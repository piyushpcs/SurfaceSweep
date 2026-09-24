"""
Secret detection patterns and deduplication.
"""

import re
from modules.extraction.patterns import (
    PROXIMITY_GATED_SECRET_TYPES,
    is_likely_real_secret,
    near_secret_context,
)


# Lower rank wins when two patterns claim overlapping spans (more specific first).
_SECRET_TYPE_RANK = {
    "Generic API Key": 10,
    "Exposed Env Var": 10,
    "Access Token Env": 10,
    "Process Env Fallback": 12,
    "Authorization Header": 15,
    "X-API-Key Header": 15,
    "Client Secret Query": 15,
    "OAuth Client Secret": 18,
    "Refresh Token": 18,
    "Webhook Secret": 18,
    "JWT Secret": 18,
    "Generic Secret": 30,
    "Generic Password": 30,
    "CSRF Token": 30,
    "Bearer Token": 40,
    "Session Cookie": 40,
}


def _type_rank(label):
    """Specificity rank — lower is more specific / preferred on span collision."""
    return _SECRET_TYPE_RANK.get(label, 0)


def _overlaps_claimed(claimed, start, end):
    for c_start, c_end in claimed:
        if start < c_end and c_start < end:
            return True
    return False


SECRET_PATTERNS = {
    # ---- Cloud & infra keys ----
    "AWS Access Key":       re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS Secret Key":       re.compile(r'(?i)["\']aws[_-]?secret[_-]?(?:access[_-]?)?key["\']\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']'),
    "Google API Key":       re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
    "Firebase URL":         re.compile(r'[a-zA-Z0-9-]+\.firebaseio\.com'),
    "Firebase Secret":      re.compile(r'(?i)["\']firebase[_-]?secret["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']'),
    "Azure Storage Key":    re.compile(r'(?i)["\']account[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9+/=]{60,})["\']'),
    "GCP Service Account":  re.compile(r'(?i)["\']type["\']\s*:\s*["\']service_account["\']'),
    "Heroku API Key":       re.compile(r'(?i)["\']heroku[_-]?api[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9\-]{20,})["\']'),
    "DigitalOcean Token":   re.compile(r'(?i)dop_v1_[a-f0-9]{64}'),
    "Linode Token":         re.compile(r'(?i)linode_api_token\s*[:=]\s*["\']([a-f0-9]{64})["\']'),

    # ---- Payment / commerce ----
    # sk_live_ only — pk_live_ (publishable) is intentionally public in browsers.
    "Stripe Live Key":      re.compile(r'sk_live_[a-zA-Z0-9]{24,}'),
    "Stripe Publishable":   re.compile(r'pk_live_[a-zA-Z0-9]{24,}'),
    "PayPal Client ID":     re.compile(r'(?i)["\']paypal[_-]?client[_-]?id["\']\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),
    "PayPal Secret":        re.compile(r'(?i)["\']paypal[_-]?secret["\']\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),
    "Square Access Token":  re.compile(r'(?i)sqOatp-[A-Za-z0-9_\-]+'),
    "Braintree Token":      re.compile(r'(?i)["\']braintree[_-]?token["\']\s*[:=]\s*["\']([a-z0-9_\-]{20,})["\']'),

    # ---- SaaS / API keys ----
    "OpenAI API Key":       re.compile(r'sk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}'),
    "Anthropic API Key":    re.compile(r'sk-ant-[A-Za-z0-9_\-]{20,}'),
    "Twilio SID":           re.compile(r'(?i)AC[a-z0-9]{32}'),
    "Twilio Auth Token":    re.compile(r'(?i)["\'](?:twilio[_-]?)?(?:auth[_-]?)?token["\']\s*[:=]\s*["\']([a-f0-9]{32})["\']'),
    "SendGrid API Key":     re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
    "Mailgun API Key":      re.compile(r'(?i)key-[a-z0-9]{32}'),
    "Postman API Key":      re.compile(r'(?i)PMAK-[a-f0-9]{24,}[a-f0-9]{16,}'),
    "Shopify Token":        re.compile(r'(?i)shpat_[a-f0-9]{32}'),
    "Shopify API Key":      re.compile(r'(?i)shpss_[a-f0-9]{32}'),
    "Cloudinary URL":       re.compile(r'cloudinary://[^\s"\']+'),
    "Mapbox Token":         re.compile(r'pk\.eyJ1Ijoi[A-Za-z0-9_\-]+'),
    "Algolia API Key":      re.compile(r'(?i)["\'](?:algolia[_-]?(?:api[_-]?)?key|application[_-]?id)["\']\s*[:=]\s*["\']([a-z0-9]{10,})["\']'),
    "Elasticsearch URL":    re.compile(r'(?i)elastic(?:search)?://[^\s"\']+'),
    "Datadog API Key":      re.compile(r'(?i)["\']datadog[_-]?api[_-]?key["\']\s*[:=]\s*["\']([a-f0-9]{32})["\']'),
    "New Relic Key":        re.compile(r'(?i)NRAK-[A-Z0-9]{27}'),
    "Segment Write Key":    re.compile(r'(?i)["\']segment[_-]?write[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']'),
    "Braintree GraphQL":    re.compile(r'(?i)["\']authorization["\']\s*:\s*["\']([a-f0-9]{64})["\']'),

    # ---- Messaging / chat ----
    "Slack Token":          re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
    "Slack Webhook":        re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),
    "Discord Token":        re.compile(r'[MNO][A-Za-z\d_-]{23,28}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}'),
    "Discord Webhook":      re.compile(r'https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+'),
    "Telegram Bot Token":   re.compile(r'(?i)[0-9]{8,10}:[A-Za-z0-9_\-]{35}'),

    # ---- VCS / package managers ----
    "GitHub Token":         re.compile(r'gh[po]_[a-zA-Z0-9]{36,}'),
    "GitHub PAT (classic)": re.compile(r'ghp_[a-zA-Z0-9]{36}'),
    "GitLab Token":         re.compile(r'glpat-[a-zA-Z0-9_\-]{20}'),
    "Bitbucket App PW":     re.compile(r'(?i)bbdc_[A-Za-z0-9_\-]{20,}'),
    "NPM Token":            re.compile(r'npm_[a-zA-Z0-9]{36}'),
    "PyPI Token":           re.compile(r'pypi-[A-Za-z0-9_\-]{60,}'),

    # ---- Auth / session / crypto ----
    "Bearer Token":         re.compile(r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}'),
    "Basic Auth":           re.compile(
        r'(?i)(?:Authorization:\s*|["\']authorization["\']\s*:\s*["\'])Basic\s+([A-Za-z0-9+/=]{20,})'
    ),
    "JWT":                  re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}(?:\.[A-Za-z0-9_\-]*)?'),
    "JWT Secret":           re.compile(r'(?i)["\'](?:jwt[_-]?secret|signing[_-]?key|hmac[_-]?key|jwt[_-]?key)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.\/+=]{10,})["\']'),
    "Session Cookie":       re.compile(r'(?i)(?:sessionid|jsessionid|phpsessid|asp\.net_sessionid)\s*=\s*[a-zA-Z0-9_\-]{16,}'),
    "Private Key":          re.compile(r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP|PGP)?\s*PRIVATE KEY-----'),
    "Encryption Key":       re.compile(r'(?i)["\'](?:encryption[_-]?key|cipher[_-]?key|secret[_-]?key)["\']\s*[:=]\s*["\']([a-zA-Z0-9+/=]{16,})["\']'),
    "Authorization Header": re.compile(
        r'(?i)["\']authorization["\']\s*:\s*["\'](?!bearer\s)(?!basic\s)'
        r'([A-Za-z0-9_\-.=/+]{20,})["\']'
    ),
    "X-API-Key Header":     re.compile(r'(?i)["\']x-api-key["\']\s*:\s*["\']([^"\']{16,})["\']'),

    # ---- Database / infra connections ----
    "Database URL":         re.compile(r'(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|redis|amqp|mssql|oracle):\/\/[^\s"\'<>]{10,}', re.IGNORECASE),
    "MongoDB SRV":          re.compile(r'mongodb\+srv://[^\s"\']+'),
    "Redis URL":            re.compile(r'rediss?://[^\s"\']+'),
    "AMQP URL":             re.compile(r'amqps?://[^\s"\']+'),
    "Elasticsearch Auth":   re.compile(r'(?i)https?:\/\/[a-z0-9_\-]+:[^@\s]+@[^\s"\']*(?:elastic|opensearch|kibana)'),

    # ---- Email / SMTP ----
    "SMTP Credentials":     re.compile(r'(?i)["\'](?:smtp[_-]?pass|mail[_-]?password|email[_-]?password)["\']\s*[:=]\s*["\']([^\s"\']{6,})["\']'),
    "SendGrid SMTP Pass":   re.compile(r'(?i)["\']sendgrid[_-]?password["\']\s*[:=]\s*["\']([^\s"\']{6,})["\']'),

    # ---- Generic / env / config / structural ----
    "Generic API Key":      re.compile(r'(?i)["\']api[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,45})["\']'),
    "Generic Secret":       re.compile(r'(?i)["\'](?:secret|token|apikey)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{10,})["\']'),
    "Generic Password":     re.compile(r'(?i)["\'](?:password|passwd|pwd|pass)["\']\s*[:=]\s*["\']([^\s"\']{6,})["\']'),
    "Exposed Env Var":      re.compile(r'(NEXT_PUBLIC_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|VITE_[A-Z0-9_]+)\s*[:=]\s*["\']([^"\']{4,100})["\']'),
    "Access Token Env":     re.compile(r'(?:ACCESS_TOKEN|API_TOKEN|AUTH_TOKEN|SECRET_TOKEN)\s*[:=]\s*["\']([^\s"\']{8,})["\']'),
    "Process Env Fallback": re.compile(
        r'process\.env\.[A-Z0-9_]+\s*\|\|\s*["\']([^"\']{8,})["\']'
    ),
    "Client Secret Query":  re.compile(r'[?&]client_secret=([A-Za-z0-9_\-.]{16,})'),
    "OAuth Client Secret":  re.compile(r'(?i)["\']client[_-]?secret["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'),
    "Refresh Token":        re.compile(r'(?i)["\']refresh[_-]?token["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']'),
    "Webhook Secret":       re.compile(r'(?i)["\']webhook[_-]?(?:secret|signing[_-]?secret)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'),
    "CSRF Token":           re.compile(r'(?i)["\'](?:csrf[_-]?token|xsrf[_-]?token|authenticity[_-]?token)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'),
}


def extract_secrets(content, source_label):
    """
    Extract potential secrets from content.
    Returns list of {type, match, source}.
    Overlapping pattern hits keep the most specific type (span priority).
    """
    secrets = []
    claimed = []
    labels_sorted = sorted(
        SECRET_PATTERNS.keys(),
        key=lambda lab: (_type_rank(lab), lab),
    )
    for label in labels_sorted:
        pattern = SECRET_PATTERNS[label]
        proximity_gated = label in PROXIMITY_GATED_SECRET_TYPES
        for m in pattern.finditer(content):
            if _overlaps_claimed(claimed, m.start(), m.end()):
                continue
            value = m.group(1) if m.groups() else m.group(0)
            if not is_likely_real_secret(value, label=label):
                continue
            if proximity_gated and not near_secret_context(content, m.start(), m.end()):
                continue
            claimed.append((m.start(), m.end()))
            match_text = m.group(0)
            # JWTs must stay intact for offline analysis (header.payload.sig)
            if label != "JWT":
                match_text = match_text[:80]
            secrets.append({
                "type": label,
                "match": match_text,
                "source": source_label
            })
    return secrets


def deduplicate_secrets(all_secrets):
    """
    Same secret appearing in multiple files should be one entry with
    a list of sources, not N duplicate entries. Identical match text under
    different types collapses to the more specific type.
    """
    dedup = {}
    for s in all_secrets:
        key = s["match"]
        rank = _type_rank(s["type"])
        if key not in dedup:
            dedup[key] = {
                "type": s["type"],
                "match": s["match"],
                "sources": [],
                "_rank": rank,
            }
        elif rank < dedup[key]["_rank"]:
            dedup[key]["type"] = s["type"]
            dedup[key]["_rank"] = rank
        if s["source"] not in dedup[key]["sources"]:
            dedup[key]["sources"].append(s["source"])
    for entry in dedup.values():
        entry.pop("_rank", None)
    return list(dedup.values())
