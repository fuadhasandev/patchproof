import socket
import time
import httpcore
import pytest
from patchproof.collector import PolicyBackend, collect, DeadlineStream
from patchproof.policy import PolicyError


def answer(ip):
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (ip, 80))


def test_dns_rebinding_cannot_change_connection(monkeypatch):
    resolutions, connections = [], []

    def dns(*args, **kwargs):
        resolutions.append(args)
        return [answer('93.184.216.34' if len(resolutions) == 1 else '127.0.0.1')]

    class Socket:
        def settimeout(self, _):
            pass
        def connect(self, addr):
            connections.append(addr)
        def close(self):
            pass

    monkeypatch.setattr(socket, 'getaddrinfo', dns)
    monkeypatch.setattr(socket, 'socket', lambda *args: Socket())
    stream = PolicyBackend(False, time.monotonic() + 5).connect_tcp('example.com', 80)
    stream.close()
    assert len(resolutions) == 1
    assert connections == [('93.184.216.34', 80)]


@pytest.mark.parametrize('answers', [[answer('127.0.0.1')], [answer('93.184.216.34'), answer('10.0.0.1')]])
def test_blocked_dns_never_connects(monkeypatch, answers):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: answers)
    monkeypatch.setattr(socket, 'socket', lambda *a: pytest.fail('Blocked address reached connection'))
    with pytest.raises(PolicyError):
        PolicyBackend(False, time.monotonic() + 5).connect_tcp('example.com', 80)


def test_tls_keeps_hostname():
    seen = []
    class Stream:
        def start_tls(self, context, hostname, timeout):
            seen.append((context, hostname))
            return self
    context = object()
    DeadlineStream(Stream(), time.monotonic() + 5).start_tls(context, 'example.com')
    assert seen == [(context, 'example.com')]


def test_timeout_is_sanitized(monkeypatch):
    def fail(*a, **kw):
        raise httpcore.ReadTimeout('SECRET')
    monkeypatch.setattr(PolicyBackend, 'connect_tcp', fail)
    evidence, reason = collect('https://example.com')
    assert evidence.status_code is None
    assert reason == 'Request timed out.'


def test_metadata_does_not_consume_body(monkeypatch):
    class Response:
        status = 200
        headers = [(b'content-type', b'text/html'), (b'set-cookie', b'SECRET')]
        closed = False
        def close(self):
            self.closed = True
        @property
        def stream(self):
            pytest.fail('Body stream must not be accessed')
    response = Response()
    monkeypatch.setattr(httpcore.ConnectionPool, 'handle_request', lambda *a: response)
    evidence, reason = collect('https://example.com')
    assert reason is None
    assert evidence.is_html
    assert response.closed
    assert 'SECRET' not in evidence.model_dump_json()


def test_proxies_ignored(fixture_site, monkeypatch):
    url, state = fixture_site
    for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
        monkeypatch.setenv(name, 'http://127.0.0.1:1')
    evidence, reason = collect(url, allow_local=True)
    assert evidence.status_code == 200
    assert reason is None


def test_dns_timeout_is_bounded(monkeypatch):
    def slow(*a, **kw):
        time.sleep(0.1)
        return [answer('127.0.0.1')]
    monkeypatch.setattr(socket, 'getaddrinfo', slow)
    monkeypatch.setattr(socket, 'socket', lambda *a: pytest.fail('Timed-out DNS connected'))
    evidence, reason = collect('http://example.com', timeout=0.01)
    assert reason == 'Request timed out.'
    time.sleep(0.15)  # resolver finishes without opening a connection


def test_total_deadline():
    class Stream:
        def read(self, *a):
            pytest.fail('Read after deadline')
    with pytest.raises(httpcore.ReadTimeout):
        DeadlineStream(Stream(), time.monotonic() - 1).read(1)
