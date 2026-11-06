"""Single metadata-only GET through a policy-enforcing connection backend."""
import logging
import socket
import time
from queue import Queue, Empty
from threading import Thread
import httpcore
import httpx
from httpcore._backends.sync import SyncStream
from .models import Evidence
from .cookies import observe_cookies, validate_cookie_name
from .policy import PolicyError, resolve, validate_url

# httpcore debug events contain raw response headers. Never emit them.
logging.getLogger('httpcore').disabled = True
for name in ('connection', 'connection_pool', 'http11', 'http2', 'proxy', 'socks'):
    logging.getLogger('httpcore.' + name).disabled = True
logging.getLogger('httpx').disabled = True


class DeadlineStream(httpcore.NetworkStream):
    def __init__(self, stream, deadline):
        self.stream, self.deadline = stream, deadline

    def remaining(self, timeout):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise httpcore.ReadTimeout('Request deadline exceeded.')
        return min(left, timeout) if timeout is not None else left

    def read(self, max_bytes, timeout=None):
        return self.stream.read(max_bytes, self.remaining(timeout))

    def write(self, buffer, timeout=None):
        return self.stream.write(buffer, self.remaining(timeout))

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        return DeadlineStream(self.stream.start_tls(ssl_context, server_hostname,
                                                    self.remaining(timeout)), self.deadline)

    def close(self):
        self.stream.close()

    def get_extra_info(self, info):
        return self.stream.get_extra_info(info)


class PolicyBackend(httpcore.NetworkBackend):
    def __init__(self, allow_local, deadline):
        self.allow_local, self.deadline = allow_local, deadline

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        # Resolve once; reject mixed public/private answers. Connect numerically.
        # A daemon resolver cannot hold CLI shutdown hostage after the deadline.
        # It can only return addresses; it never opens the target connection.
        result = Queue(maxsize=1)

        def lookup():
            try:
                result.put((resolve(host, port, self.allow_local), None))
            except Exception as exc:
                result.put((None, exc))

        Thread(target=lookup, daemon=True).start()
        try:
            answer, error = result.get(timeout=max(0.001, self.deadline - time.monotonic()))
        except Empty:
            raise httpcore.ConnectTimeout('DNS deadline exceeded.') from None
        if error is not None:
            raise error
        family, kind, proto, _, address = answer
        sock = socket.socket(family, kind, proto)
        try:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise httpcore.ConnectTimeout('Request deadline exceeded.')
            sock.settimeout(min(left, timeout) if timeout is not None else left)
            sock.connect(address)  # numeric sockaddr: no second hostname lookup
            return DeadlineStream(SyncStream(sock), self.deadline)
        except BaseException:
            sock.close()
            raise


class MetadataTransport(httpx.BaseTransport):
    def __init__(self, allow_local, timeout, session_cookies=()):
        self.session_cookies = session_cookies
        self.pool = httpcore.ConnectionPool(
            network_backend=PolicyBackend(allow_local, time.monotonic() + timeout),
            retries=0, max_connections=1, max_keepalive_connections=0)

    def handle_request(self, request):
        response = self.pool.handle_request(httpcore.Request(
            method='GET', url=httpcore.URL(scheme=request.url.raw_scheme,
                host=request.url.raw_host, port=request.url.port, target=request.url.raw_path),
            headers=request.headers.raw, extensions=request.extensions))
        try:
            # Do not iterate the stream or retain any raw response headers.
            headers = httpx.Headers(response.headers)
            html = headers.get('content-type', '').split(';', 1)[0].strip().lower() in {
                'text/html', 'application/xhtml+xml'}
            csp = any(value.strip() for value in headers.get_list('content-security-policy'))
            return httpx.Response(response.status, extensions={
                'evidence': Evidence(status_code=response.status, is_html=html, csp_present=csp,
                    is_https=request.url.scheme == 'https',
                    hsts_present=any(v.strip() for v in headers.get_list('strict-transport-security')),
                    cookies=observe_cookies(headers.get_list('set-cookie'), self.session_cookies))})
        finally:
            response.close()

    def close(self):
        self.pool.close()


def collect(target_url: str, *, allow_local=False, timeout=5.0, session_cookies=()):
    target_url = validate_url(target_url)
    session_cookies = tuple(dict.fromkeys(validate_cookie_name(n) for n in session_cookies))
    try:
        with httpx.Client(transport=MetadataTransport(allow_local, timeout, session_cookies),
                          trust_env=False, follow_redirects=False, timeout=timeout) as client:
            with client.stream('GET', target_url, headers={'User-Agent': 'PatchProof/0.1'}) as response:
                return response.extensions['evidence'], None
    except PolicyError:
        return Evidence(), 'Destination blocked by address policy; --allow-local permits loopback only.'
    except (httpcore.TimeoutException, httpx.TimeoutException, TimeoutError):
        return Evidence(), 'Request timed out.'
    except (httpcore.NetworkError, httpcore.ProtocolError, httpx.HTTPError, OSError):
        return Evidence(), 'Request failed; no evaluable response metadata.'
