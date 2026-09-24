import socket
from ipaddress import ip_address


def resolve(host, overrides=None):
    overrides = overrides or {}
    if host in overrides:
        return overrides[host]
    for pattern, value in overrides.items():
        if pattern.startswith("*.") and host.endswith(pattern[1:]):
            return value
    try:
        ip_address(host)
        return host
    except ValueError:
        pass
    try:
        values = socket.getaddrinfo(host, None, socket.AF_INET)
        return values[0][4][0]
    except OSError as exc:
        raise RuntimeError("DNS: не удалось разрешить имя") from exc
