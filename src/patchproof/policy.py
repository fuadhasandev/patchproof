"""Operator scope and address policy; never trusts imported authorization."""
import ipaddress
import socket
import re
from urllib.parse import urlsplit
import httpx


class PolicyError(ValueError):
    pass


def validate_url(value: str) -> str:
    try:
        if any(ord(c) <= 32 or ord(c) == 127 for c in value) or '\\' in value:
            raise ValueError
        parts = urlsplit(value)
        if (parts.scheme not in {'http', 'https'} or not parts.hostname
                or parts.username is not None or parts.password is not None
                or '?' in value or '#' in value or '%' in parts.netloc
                or parts.netloc.endswith(':')):
            raise ValueError
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError
        url = httpx.URL(value)
        if not url.host:
            raise ValueError
        try:
            ipaddress.ip_address(url.host)
        except ValueError:
            hostname = url.raw_host.decode('ascii').removesuffix('.')
            if len(hostname) > 253 or any(
                not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                for label in hostname.split('.')
            ):
                raise ValueError
    except (ValueError, httpx.InvalidURL):
        raise PolicyError('Invalid target: use an HTTP(S) URL without credentials, query, or fragment.') from None
    return str(url)


def allowed(address: str, allow_local: bool) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (ip.is_global and not ip.is_multicast and not ip.is_reserved) or (allow_local and ip.is_loopback)


def resolve(host: str, port: int, allow_local: bool):
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not answers or any(not allowed(a[4][0], allow_local) for a in answers):
        raise PolicyError('Destination blocked by address policy; --allow-local permits loopback only.')
    return answers[0]
