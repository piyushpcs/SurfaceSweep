"""
Network-target safety for outbound scan fetches.

Two related SSRF weaknesses are closed here and shared by every HTTP path:

1. **Redirect hops** — validating only the first URL is bypassable: a target
   can answer ``302 Location: http://169.254.169.254/...`` and the client
   follows it. Callers must validate *every* hop (see
   :func:`modules.extraction.http.follow_redirects`).

2. **DNS names** — a hostname *string* check misses names that resolve to a
   link-local/metadata address (``169.254.169.254.nip.io`` and friends).
   :func:`resolve_fetch_ips` resolves and IP-checks the host, and
   :func:`pin_dns` forces the connect to the validated addresses so a
   second, attacker-controlled lookup (DNS rebinding) cannot swap them.

Private and loopback ranges stay allowed: local testbeds and authorized
internal assessments must keep working. Only link-local / cloud-metadata /
multicast / unspecified targets are refused.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
import threading
from urllib.parse import urlparse

__all__ = [
    "BlockedTarget",
    "METADATA_HOSTS",
    "install_dns_guard",
    "is_blocked_fetch_target",
    "is_blocked_ip",
    "pin_dns",
    "resolve_fetch_ips",
]

# Cloud-metadata service hostnames that must never be fetched from a scan.
METADATA_HOSTS = frozenset({
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "metadata",
})

# Metadata endpoints that sit inside otherwise-allowed ranges (so a plain
# link-local / private check would miss them).
_METADATA_IPS = frozenset({
    "169.254.169.254",   # AWS / Azure / DigitalOcean / OpenStack IMDS
    "100.100.100.200",   # Alibaba Cloud metadata
    "fd00:ec2::254",     # AWS IPv6 metadata
})


class BlockedTarget(Exception):
    """Raised when a fetch target is (or resolves to) a blocked address."""


def is_blocked_fetch_target(url: str) -> bool:
    """
    True for cloud-metadata / link-local targets that must never be fetched.

    This is the fast, name-based half of the guard (no DNS). It catches
    literal metadata IPs and well-known metadata hostnames; the IP-based half
    lives in :func:`resolve_fetch_ips` and catches DNS aliases.
    """
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return True
    if not host:
        return False
    if host in METADATA_HOSTS:
        return True
    if host.startswith("169.254."):
        return True
    if host == "100.100.100.200":  # Alibaba Cloud metadata
        return True
    if host == "fd00:ec2::254":  # AWS IPv6 metadata
        return True
    return False


def is_blocked_ip(value) -> bool:
    """
    True for link-local / metadata / multicast / unspecified addresses.

    IPv4-mapped IPv6 addresses (``::ffff:169.254.169.254``) are unwrapped so
    they cannot slip past the IPv4 checks. Unparseable input is treated as
    blocked (fail closed).
    """
    text = str(value)
    if "%" in text:  # strip IPv6 zone id (fe80::1%en0)
        text = text.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if str(ip) in _METADATA_IPS:
        return True
    return bool(ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def resolve_fetch_ips(host):
    """
    Resolve ``host`` for a scan fetch.

    Returns the de-duplicated list of resolved IP strings, or ``None`` when
    resolution fails (the caller proceeds and lets the request fail
    naturally — a resolution failure is not evidence of an SSRF target).

    Raises :class:`BlockedTarget` when the host resolves to *any* blocked
    address (fail closed): a name that mixes a public and a link-local answer
    must not be trusted.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    if not infos:
        return None
    ips = []
    seen = set()
    for info in infos:
        addr = info[4][0]
        if is_blocked_ip(addr):
            raise BlockedTarget(
                f"{host!r} resolves to a blocked link-local/metadata address"
            )
        ip = str(addr).split("%", 1)[0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips or None


# --- DNS pinning -----------------------------------------------------------
#
# The guard resolves a host once, then the connection must use exactly those
# addresses. A process-wide wrapper consults a *thread-local* pin map, so
# concurrent crawler threads never see each other's pins (unlike a global
# swap, which would serialize every request).

_dns_pins = threading.local()
_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def _pinned_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    pins = getattr(_dns_pins, "pins", None)
    if pins and isinstance(host, str):
        ips = pins.get(host.lower())
        if ips:
            out = []
            for ip in ips:
                try:
                    out.extend(
                        _ORIGINAL_GETADDRINFO(ip, port, family, type, proto, flags)
                    )
                except (socket.gaierror, OSError):
                    continue
            if out:
                return out
    return _ORIGINAL_GETADDRINFO(host, port, family, type, proto, flags)


def install_dns_guard() -> None:
    """Ensure the pin-aware ``getaddrinfo`` wrapper is active (idempotent)."""
    if socket.getaddrinfo is not _pinned_getaddrinfo:
        socket.getaddrinfo = _pinned_getaddrinfo


@contextlib.contextmanager
def pin_dns(host, ips):
    """
    Force ``host`` to connect to the already-validated ``ips`` for this block.

    Closes the DNS-rebinding TOCTOU window: the guard resolves the host once,
    and the HTTP stack is prevented from doing a second (attacker-controlled)
    lookup that could return an internal address. Thread-local, so parallel
    fetches to different hosts do not interfere.
    """
    if not host or not ips:
        yield
        return
    install_dns_guard()
    pins = getattr(_dns_pins, "pins", None)
    if pins is None:
        pins = {}
        _dns_pins.pins = pins
    key = host.lower()
    previous = pins.get(key)
    pins[key] = list(ips)
    try:
        yield
    finally:
        if previous is None:
            pins.pop(key, None)
        else:
            pins[key] = previous
        if not pins:
            _dns_pins.pins = None


# Installed at import so the pin is honoured by the HTTP stack before any
# fetch happens; pin_dns() re-asserts it if something replaced it.
install_dns_guard()
