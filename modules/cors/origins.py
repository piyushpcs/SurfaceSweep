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

    try:
        port = parsed.port
    except ValueError:
        # Malformed port (e.g. "5555, https:" from a multi-value ACAO)
        return value.rstrip("/") if "://" in value else value

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


def _dedupe(origins):
    seen = set()
    ordered = []
    for o in origins:
        if o and o not in seen:
            seen.add(o)
            ordered.append(o)
    return ordered


def build_test_origins(target_url, custom_origin=None):
    """
    Build list of Origin values to probe.

    Matrix covers: attacker hosts, null, path-bearing Origins (naive
    substring matchers), same host with scheme/port flips, and domain
    lookalikes. IP / localhost targets skip domain-derived lookalikes
    (they produce nonsense like sub.0.1).
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or "example.com"
    scheme = parsed.scheme or "https"
    port = parsed.port

    origins = [
        "https://evil.com",
        "https://attacker.example",
        # Path-bearing Origin — browsers never send this; catches contains()/regex FPs
        "https://evil.com/path",
        "https://evil.com.evil",
        "null",
    ]

    # Scheme + port flips on the real target host
    if port and port not in (80, 443):
        origins.extend([
            f"{scheme}://{host}:{port}",
            f"http://{host}:{port}",
            f"https://{host}:{port}",
            f"http://{host}",
            f"https://{host}",
            f"{scheme}://{host}",
        ])
    else:
        origins.extend([
            f"https://{host}",
            f"http://{host}",
        ])
        # Explicit non-default port probe (scheme-relative style)
        if scheme == "https":
            origins.append(f"http://{host}:8080")
        else:
            origins.append(f"https://{host}:8443")

    if is_ip_host(host) or host == "localhost":
        if port and port not in (80, 443):
            origins.append(f"https://{host}:9999")
        origins.append(f"{scheme}://{host}/path")  # path-bearing on target host
    else:
        parts = host.split(".")
        registrable = ".".join(parts[-2:]) if len(parts) >= 2 else host
        origins.extend([
            f"https://sub.{registrable}",
            f"https://{registrable}.evil.com",
            f"https://{registrable}",
            f"http://{registrable}",
            f"https://{registrable}/path",
            f"https://evil.{registrable}",
        ])
        if port and port not in (80, 443):
            origins.append(f"https://{registrable}:{port}")

    if custom_origin:
        origins.insert(0, custom_origin)

    return _dedupe(origins)
