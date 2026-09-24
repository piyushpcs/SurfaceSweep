"""
Regex patterns, constants, and filters for JS extraction.
"""

import math
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

# ---- Secret false-positive filtering ----

# Vendor/format patterns whose structure alone is strong signal — skip
# placeholder-substring and entropy gates (prefix checks still apply).
HIGH_CONFIDENCE_SECRET_LABELS = frozenset({
    "AWS Access Key", "AWS Secret Key", "Google API Key",
    "Firebase URL", "Firebase Secret", "GCP Service Account",
    "DigitalOcean Token", "Linode Token",
    "Stripe Live Key", "Stripe Publishable", "Stripe Webhook Secret", "Square Access Token",
    "OpenAI API Key", "OpenAI Project Key", "Anthropic API Key", "SendGrid API Key",
    "Hugging Face Token",
    "Postman API Key", "Shopify Token", "Shopify API Key",
    "Mapbox Token", "New Relic Key",
    "Slack Token", "Slack Webhook", "Discord Webhook",
    "GitHub Token", "GitHub PAT (classic)", "GitHub PAT (fine-grained)", "GitLab Token",
    "Bitbucket App PW", "NPM Token", "PyPI Token",
    "JWT", "JWT Secret", "Private Key",
    "Database URL", "MongoDB SRV", "Redis URL", "AMQP URL",
    "Elasticsearch URL", "Elasticsearch Auth",
    "Cloudinary URL", "Heroku API Key",
})

# Bare / high-FP shapes that only count near an explicit secret-related keyword
# (minified JS often contains AC+32, long digit:base64, etc. with no meaning).
PROXIMITY_GATED_SECRET_TYPES = frozenset({
    "Twilio SID",
    "Telegram Bot Token",
    "Mailgun API Key",
    "Discord Token",
})

SECRET_CONTEXT_WINDOW = 96

_SECRET_CONTEXT_RE = re.compile(
    r"(?i)(?:"
    r"twilio|telegram|discord|mailgun|"
    r"api[_-]?key|apikey|secret|token|password|passwd|pwd|"
    r"auth|credential|sid|account[_-]?sid|bot[_-]?token|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret"
    r")"
)

_PLACEHOLDER_SUBSTRINGS = (
    "changeme", "change_me", "change-me", "replace_me", "replace-me",
    "your-key", "your_key", "your-api", "your_api", "your-secret",
    "your_secret", "your-token", "your_token", "your-password",
    "example-key", "example_key", "example-token", "example_secret",
    "placeholder", "not-a-secret", "not_a_secret", "redacted",
    "insert-here", "insert_here", "put-here", "todo", "fixme",
)

_PLACEHOLDER_PREFIXES = (
    "your-", "your_", "my-key", "my_key", "example-",
    "sample-", "sample_", "dummy-", "dummy_", "fake-",
    "changeme", "placeholder", "redacted", "todo-", "fixme-",
    "insert-", "replace-",
)

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


def shannon_entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def near_secret_context(content, start, end, window=SECRET_CONTEXT_WINDOW):
    """True when a secret-related keyword sits near [start, end) in content."""
    if not content or start is None or end is None:
        return False
    lo = max(0, start - window)
    hi = min(len(content), end + window)
    if lo >= hi:
        return False
    return bool(_SECRET_CONTEXT_RE.search(content[lo:hi]))


def _looks_like_placeholder(value):
    """Template/sample/dummy values that are never real credentials."""
    lowered = value.lower()
    if any(tok in lowered for tok in _PLACEHOLDER_SUBSTRINGS):
        return True
    if lowered.startswith(_PLACEHOLDER_PREFIXES):
        return True
    if value[:1] in ("<", "{", "$"):
        return True
    if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", value):
        return True
    return False


def _is_repeated_char(value):
    """aaaaaaaa… / 0000… style fills."""
    if len(value) < 4:
        return False
    return len(set(value)) == 1


def _is_modular_run(chars, mod):
    """True when every step is +1 or -1 modulo mod (1234567890, xyzabc…)."""
    if len(chars) < 8:
        return False
    steps = [
        (ord(chars[i]) - ord(chars[i - 1])) % mod for i in range(1, len(chars))
    ]
    return all(s == 1 for s in steps) or all(s == mod - 1 for s in steps)


def _is_sequential(value):
    """Counting runs: abcdefgh, 1234567890, 0987654321, xyzabcdefg…"""
    if len(value) < 8:
        return False
    lowered = value.lower()
    ascending = all(
        ord(lowered[i]) - ord(lowered[i - 1]) == 1 for i in range(1, len(lowered))
    )
    descending = all(
        ord(lowered[i]) - ord(lowered[i - 1]) == -1 for i in range(1, len(lowered))
    )
    if ascending or descending:
        return True
    if lowered.isdigit():
        return _is_modular_run(lowered, 10)
    if lowered.isalpha() and lowered.isascii():
        return _is_modular_run(lowered, 26)
    return False


def _is_low_entropy(value):
    """
    Reject random-looking values that are too uniform to be real secrets.
    Character-class aware: hex max entropy is 4.0, digits ~3.32.
    """
    if len(value) < 16:
        return False
    if "://" in value or value.startswith(("eyJ", "-----BEGIN")):
        return False
    entropy = shannon_entropy(value)
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return entropy < 3.0
    if re.fullmatch(r"[0-9]+", value):
        return entropy < 2.5
    if re.fullmatch(r"[a-z]+", value):
        return entropy < 3.4
    return entropy < 3.0


def is_likely_real_secret(value, label=None):
    """
    Filter obvious false positives from secret detection.

    label: optional SECRET_PATTERNS key. High-confidence vendor formats skip
    placeholder-substring and entropy gates (their prefixes carry the signal).
    """
    if not value:
        return False
    candidate = value.strip()
    if len(candidate) < 10:
        return False
    if candidate.lower() in COMMON_FALSE_POSITIVES:
        return False
    if _is_repeated_char(candidate) or _is_sequential(candidate):
        return False
    high_confidence = label is not None and label in HIGH_CONFIDENCE_SECRET_LABELS
    if not high_confidence:
        if _looks_like_placeholder(candidate):
            return False
        if _is_low_entropy(candidate):
            return False
    return True
