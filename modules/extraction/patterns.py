"""
Regex patterns, constants, and filters for JS extraction.
"""

import re

# ---- Endpoint patterns ----

ENDPOINT_PATTERN = re.compile(
    r'["\'](/[a-zA-Z0-9_\-./]*(?:api|v[0-9]|admin|auth|graphql|internal|user|account|token)[a-zA-Z0-9_\-./]*)["\']',
    re.IGNORECASE
)

GENERIC_PATH_PATTERN = re.compile(r'["\'](/[a-zA-Z0-9_\-./]{2,80})["\']')

FULL_URL_PATTERN = re.compile(r'https?://[a-zA-Z0-9.\-]+(?:/[a-zA-Z0-9_\-./%?=&]*)?')

# Catches URLs passed as arguments to common HTTP call patterns —
# fetch("/api/x"), axios.get('/path'), $.ajax({url: "..."}), $.post("/x"), http.request("/x")
CALL_PATTERN = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:ajax|get|post)|http\.request)\s*\(\s*'
    r'(?:\{[^}]*url\s*:\s*)?["\']([^"\']{2,150})["\']',
    re.IGNORECASE
)

# ---- JS file discovery patterns ----

JS_REFERENCE_PATTERN = re.compile(
    r'''(?:src|import|require|from|chunk|loadScript|importScripts)\s*(?:\(|[=:]?\s*)['"]([^'"]+\.js(?:\?[^'"]*)?)['"]''',
    re.IGNORECASE
)

WEBPACK_CHUNK_PATTERN = re.compile(r'''['"]([^'"]*(?:chunk|vendor|main|app|bundle)[^'"]*\.js)['"]''', re.IGNORECASE)

# ---- Noise / static asset filters ----

NOISE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".svg", ".gif", ".css", ".woff", ".woff2", ".ttf", ".ico")

# Extensions that are static assets — not API endpoints (filtered from final reports only)
# Note: .js is intentionally NOT in NOISE_EXTENSIONS for discovery purposes (we follow JS references),
# but IS filtered from reported endpoint lists via STATIC_ASSET_EXTENSIONS.
STATIC_ASSET_EXTENSIONS = NOISE_EXTENSIONS + (
    ".js", ".mjs", ".cjs", ".map", ".html", ".htm", ".xml", ".json", ".txt",
    ".pdf", ".zip", ".tar", ".gz", ".mp3", ".mp4", ".webp", ".bmp",
)

COMMON_FALSE_POSITIVES = {"loading", "null", "undefined", "true", "false", "none", "test", "example", "placeholder"}

# ---- Private / internal network detection ----

# Hosts that indicate internal/infrastructure exposure
INTERNAL_HOST_PATTERN = re.compile(
    r'(?i)https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|'
    r'\[::1\]|'
    r'10\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|'
    r'172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})|'
    r'192\.168\.(?:\d{1,3})\.(?:\d{1,3})|'
    r'169\.254\.(?:\d{1,3})\.(?:\d{1,3})|'
    r'100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.(?:\d{1,3})\.(?:\d{1,3})'
    r')(?::\d{1,5})?(?:/[^\s"\'<>]*)?'
)

# Internal hostnames commonly leaked in JS (dev/staging/infra)
INTERNAL_NAME_PATTERN = re.compile(
    r'(?i)https?://[a-z0-9.-]*'
    r'(?:'
    r'\.internal|\.local|\.localdomain|\.corp|\.lan|\.intranet|\.private'
    r')'
    r'(?:[:/]|$)'
    r'(?:[^\s"\'<>]*)?'
)

# Bare private IPs (with optional port/path), not part of a longer URL scheme match
PRIVATE_IP_PATTERN = re.compile(
    r'(?<![\w.])('
    r'(?:10\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|'
    r'172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})|'
    r'192\.168\.(?:\d{1,3})\.(?:\d{1,3})|'
    r'127\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|'
    r'169\.254\.(?:\d{1,3})\.(?:\d{1,3})'
    r')(?::\d{1,5})?(?:/[\w./?=&%-]*)?'
    r')(?![\w.])'
)

# Common internal/dev subdomain keywords found in absolute URLs
INTERNAL_SUBDOMAIN_PATTERN = re.compile(
    r'(?i)https?://([a-z0-9-]+)\.[a-z0-9.-]+\.(?:com|net|org|io|dev|app|co|in|gov|edu|ai|sh|xyz|local|internal|corp|lan)(?:[:/]|$)'
)
INTERNAL_SUBDOMAIN_KEYWORDS = {
    "admin", "api-internal", "backend", "bastion", "ci", "cdn-internal",
    "dev", "grafana", "internal", "intranet", "jenkins", "jira", "kibana",
    "ldap", "monitor", "mysql", "nginx", "ops", "prod-internal", "redis",
    "staging", "stage", "test", "uat", "vpn", "wiki", "workflow",
}


def find_internal_hosts(content):
    """
    Find private IPs, localhost, and internal hostnames in JS/HTML content.
    Returns list of {match, kind, source} — caller adds source_label.
    """
    findings = []
    seen = set()

    for kind, pattern in (
        ("internal_url", INTERNAL_HOST_PATTERN),
        ("internal_name", INTERNAL_NAME_PATTERN),
        ("private_ip", PRIVATE_IP_PATTERN),
    ):
        for m in pattern.finditer(content):
            value = m.group(0)
            if value in seen:
                continue
            seen.add(value)
            findings.append({"match": value, "kind": kind})

    for m in INTERNAL_SUBDOMAIN_PATTERN.finditer(content):
        sub = (m.group(1) or "").lower()
        if sub in INTERNAL_SUBDOMAIN_KEYWORDS:
            value = m.group(0)
            if value not in seen:
                seen.add(value)
                findings.append({"match": value, "kind": "internal_subdomain"})

    # Dedup overlapping matches: keep the longest match for the same host
    findings.sort(key=lambda f: -len(f["match"]))
    kept = []
    for f in findings:
        overlap = False
        for k in kept:
            if f["match"] in k["match"] or k["match"] in f["match"]:
                overlap = True
                break
        if not overlap:
            kept.append(f)
    return kept

def is_noise(path):
    """True for paths ending in noise extensions (images, fonts, css)."""
    return any(path.lower().endswith(ext) for ext in NOISE_EXTENSIONS)


def is_static_asset(path):
    """True for paths that are static assets (JS, images, etc.) — not API endpoints."""
    clean = path.split("?")[0].split("#")[0]
    return any(clean.lower().endswith(ext) for ext in STATIC_ASSET_EXTENSIONS)


def is_likely_real_secret(value):
    """Filter obvious false positives from secret detection."""
    if value.lower() in COMMON_FALSE_POSITIVES:
        return False
    if len(value) < 10:
        return False
    return True
