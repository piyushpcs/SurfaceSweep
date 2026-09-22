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
