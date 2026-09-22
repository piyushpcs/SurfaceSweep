"""
CORS origin construction, normalization, and comparison.
"""

import ipaddress
from urllib.parse import urlparse

DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_origin(origin):
    """
    Normalize an Origin / ACAO value for comparison.

    Handles: case, default ports, trailing slashes, missing scheme edge cases.
    Returns "null" / "*" unchanged. Empty → "".
    """
    if not origin:
        return ""
    value = origin.strip()
    if value in ("null", "*"):
        return value

    if "://" not in value:
        if value.startswith("//"):
            value = "https:" + value
        else:
            value = "https://" + value

    parsed = urlparse(value)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if not scheme or not host:
        return origin.strip()

    port = parsed.port
    netloc = host
    if port and port != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"

    return f"{scheme}://{netloc}"


def origins_equal(a, b):
    """True when two Origin/ACAO values match after normalization."""
    return normalize_origin(a) == normalize_origin(b)


def origin_host(origin):
    """Hostname from a normalized origin ("" for null/*/invalid)."""
    norm = normalize_origin(origin)
    if norm in ("", "null", "*"):
        return ""
    return urlparse(norm).hostname or ""


def is_ip_host(host):
    """True when host is an IPv4/IPv6 literal (not a domain)."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_related_host(origin, target_origin, registrable_domain=None):
    """
    True when origin's host is the target host, a subdomain of the target,
    or shares the target's registrable domain (e.g. evil.example.com vs example.com).
    """
    oh = origin_host(origin)
    th = origin_host(target_origin)
    if not oh or not th:
        return False
    if oh == th:
        return True
    if oh.endswith("." + th) or th.endswith("." + oh):
        return True
    if registrable_domain:
        reg = registrable_domain.lower()
        if oh == reg or oh.endswith("." + reg):
            return True
    return False


def is_host_suffix_match(origin_host_a, origin_host_b):
    """
    Suffix trust boundary: a.evil.com vs evil.com (dot-boundary only).
    Used for partial-match detection without naive endswith FPs (evilevil.com).
    """
    a = (origin_host_a or "").lower().rstrip(".")
    b = (origin_host_b or "").lower().rstrip(".")
    if not a or not b or a == b:
        return False
    return a.endswith("." + b) or b.endswith("." + a)


def build_test_origins(target_url, custom_origin=None):
    """
    Build list of Origin values to probe.

    For IP / localhost targets, skips domain-derived lookalikes
    (they produce nonsense like sub.0.1).
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or "example.com"
    scheme = parsed.scheme or "https"
    port = parsed.port

    origins = ["https://evil.com", "https://attacker.example", "null"]

    if is_ip_host(host) or host == "localhost":
        # Same host, different scheme / port — useful against local testbeds
        origins.extend([
            f"http://{host}" + (f":{port}" if port and scheme == "https" else ""),
            f"https://{host}" + (f":{port}" if port and scheme == "http" else ""),
            f"https://{host}:9999" if not (port == 9999) else f"https://{host}",
        ])
        if port and port not in (80, 443):
            origins.append(f"{scheme}://{host}:{port}")
    else:
        parts = host.split(".")
        registrable = ".".join(parts[-2:]) if len(parts) >= 2 else host
        origins.extend([
            f"https://sub.{registrable}",
            f"https://{registrable}.evil.com",
            f"https://{registrable}",
            f"http://{registrable}",
        ])
        if port and port not in (80, 443):
            origins.append(f"https://{registrable}:{port}")

    if custom_origin:
        origins.insert(0, custom_origin)

    seen = set()
    ordered = []
    for o in origins:
        if o not in seen:
            seen.add(o)
            ordered.append(o)
    return ordered
