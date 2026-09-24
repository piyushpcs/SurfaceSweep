"""
CORS origin construction, normalization, and comparison.
"""

import ipaddress
from urllib.parse import urlparse

from modules.extraction.scope import get_registrable_domain

DEFAULT_PORTS = {"http": 80, "https": 443}

# Probe-cost budget: origins × endpoints × methods stays manageable.
MAX_TEST_ORIGINS = 25

# Third-party free-host suffixes (CORScanner-style) probed last before the cap.
THIRD_PARTY_SUFFIXES = (
    "github.io",
    "gitlab.io",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "web.app",
)


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
    if ":" in host and not host.startswith("["):
        # urlparse.hostname strips IPv6 brackets — restore for netloc
        netloc = f"[{host}]"
    if port and port != DEFAULT_PORTS.get(scheme):
        netloc = f"{netloc}:{port}"

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


def _format_origin_host(host):
    """Bracket IPv6 literals so Origin URLs stay parseable (http://[::1])."""
    if host and ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _registrable_domain(host, scheme="https"):
    """
    Registrable domain via tldextract (correct for co.uk etc.).
    Empty for IP literals and localhost; last-label fallback on failure.
    """
    if not host or is_ip_host(host) or host == "localhost":
        return ""
    try:
        return get_registrable_domain(f"{scheme}://{host}")
    except Exception:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host


# Cap for one trusted-seed expansion (per-scan second pass budget)
MAX_SEED_LOOKALIKES = 5
MAX_TRUSTED_SEEDS = 3


def build_seed_lookalikes(seed_origin, limit=MAX_SEED_LOOKALIKES):
    """
    Lookalike Origins for a trusted/static ACAO seed (not the scan target).

    Covers suffix trust, path-bearing contains(), and subdomain confusion
    against the *allowed third-party* host seen in ACAO.
    """
    seed_n = normalize_origin(seed_origin)
    if seed_n in ("", "null", "*"):
        return []
    host = origin_host(seed_n)
    if not host or is_ip_host(host) or host == "localhost":
        return []
    scheme = urlparse(seed_n).scheme or "https"
    registrable = _registrable_domain(host, scheme)
    base = registrable or host

    candidates = [
        f"https://sub.{base}",
        f"https://{base}.evil.com",
        f"https://evil.{base}",
        f"https://{base}/path",
        f"https://{host}/path",
    ]
    return _dedupe(candidates)[: max(0, int(limit))]


def build_test_origins(target_url, custom_origin=None):
    """
    Build list of Origin values to probe (capped at MAX_TEST_ORIGINS).

    Priority (first kept under the cap): custom origin, attacker/null/special
    hosts, local-origin probes, target scheme/port flips, domain lookalikes
    (tldextract registrable), then third-party free-host suffixes.

    IP / localhost targets skip domain-derived lookalikes (they produce
    nonsense like sub.0.1) and gain alternate loopback forms instead.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or "example.com"
    scheme = parsed.scheme or "https"
    port = parsed.port
    origin_host_lit = _format_origin_host(host)
    ip_target = is_ip_host(host) or host == "localhost"

    origins = [
        "https://evil.com",
        "https://attacker.example",
        # Path-bearing Origin — browsers never send this; catches contains()/regex FPs
        "https://evil.com/path",
        "https://evil.com.evil",
        "null",
        # Special-character / no-dot hosts — naive contains or unescaped-dot matchers
        "https://evil_com",
        "https://evilcom",
        # Local-origin probes (servers that allow loopback Origin values)
        "http://localhost",
        "http://127.0.0.1",
    ]

    # Scheme + port flips on the real target host
    if port and port not in (80, 443):
        origins.extend([
            f"{scheme}://{origin_host_lit}:{port}",
            f"http://{origin_host_lit}:{port}",
            f"https://{origin_host_lit}:{port}",
            f"http://{origin_host_lit}",
            f"https://{origin_host_lit}",
            f"{scheme}://{origin_host_lit}",
        ])
    else:
        origins.extend([
            f"https://{origin_host_lit}",
            f"http://{origin_host_lit}",
        ])
        # Explicit non-default port probe (scheme-relative style)
        if scheme == "https":
            origins.append(f"http://{origin_host_lit}:8080")
        else:
            origins.append(f"https://{origin_host_lit}:8443")

    if ip_target:
        if port and port not in (80, 443):
            origins.append(f"https://{origin_host_lit}:9999")
        origins.append(f"{scheme}://{origin_host_lit}/path")
        # Alternate loopback spellings (short, wildcard, IPv6, decimal)
        if host in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):
            origins.extend([
                "http://127.1",
                "http://0.0.0.0",
                "http://[::1]",
                "http://2130706433",
            ])
    else:
        registrable = _registrable_domain(host, scheme)
        if registrable:
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
            for suffix in THIRD_PARTY_SUFFIXES:
                origins.append(f"https://{registrable}.{suffix}")

    if custom_origin:
        origins.insert(0, custom_origin)

    return _dedupe(origins)[:MAX_TEST_ORIGINS]
