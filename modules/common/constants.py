"""Shared constants used across SurfaceSweep modules."""

from __future__ import annotations

__all__ = [
    "CVE_SEVERITY_WEIGHTS",
    "DEFAULT_SECRET_SEVERITY",
    "DEFAULT_USER_AGENT",
    "INTERNAL_HOST_RISK_WEIGHTS",
    "RISK_THRESHOLDS",
    "SECRETS_RISK_WEIGHTS",
    "SEVERITY_ORDER",
    "SEVERITY_RANK",
    "SECRET_SEVERITY",
    "__version__",
    "internal_host_severity",
    "secret_severity",
]

__version__ = "1.0.0"

DEFAULT_USER_AGENT = "SurfaceSweep/1.0"

# Lower = worse (CORS also uses ERROR for probe failures).
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "ERROR": 5,
}

# Alias for call sites that treat the map as a rank lookup.
SEVERITY_RANK = SEVERITY_ORDER

RISK_THRESHOLDS = (
    (30, "HIGH"),
    (10, "MEDIUM"),
    (1, "LOW"),
)

CVE_SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}

# Type-aware secret severity (Phase C). Unmapped vendor keys stay HIGH —
# the historical flat rating — so only known public/structural types drop
# and known crown-jewel types rise.
DEFAULT_SECRET_SEVERITY = "HIGH"

SECRET_SEVERITY = {
    # Crown jewels — full account / infra compromise
    "Private Key": "CRITICAL",
    "AWS Secret Key": "CRITICAL",
    "GCP Service Account": "CRITICAL",
    "Azure Storage Key": "CRITICAL",
    "Database URL": "CRITICAL",
    "MongoDB SRV": "CRITICAL",
    "JWT Secret": "CRITICAL",
    "Encryption Key": "CRITICAL",
    "SMTP Credentials": "CRITICAL",
    # Live credentials worth HIGH
    "AWS Access Key": "HIGH",
    "Google API Key": "HIGH",
    "Stripe Live Key": "HIGH",
    "OpenAI API Key": "HIGH",
    "Anthropic API Key": "HIGH",
    "SendGrid API Key": "HIGH",
    "GitHub Token": "HIGH",
    "GitHub PAT (classic)": "HIGH",
    "GitLab Token": "HIGH",
    "NPM Token": "HIGH",
    "PyPI Token": "HIGH",
    "Slack Token": "HIGH",
    "Slack Webhook": "HIGH",
    "Discord Webhook": "HIGH",
    "Authorization Header": "HIGH",
    "X-API-Key Header": "HIGH",
    "OAuth Client Secret": "HIGH",
    "Refresh Token": "HIGH",
    "Bearer Token": "HIGH",
    "Heroku API Key": "HIGH",
    "DigitalOcean Token": "HIGH",
    "Shopify Token": "HIGH",
    "Shopify API Key": "HIGH",
    "PayPal Secret": "HIGH",
    "Firebase Secret": "HIGH",
    "Twilio Auth Token": "HIGH",
    "Telegram Bot Token": "HIGH",
    # Structural / generic — real but lower confidence or lower impact alone
    "Generic API Key": "MEDIUM",
    "Generic Secret": "MEDIUM",
    "Generic Password": "MEDIUM",
    "Exposed Env Var": "MEDIUM",
    "Access Token Env": "MEDIUM",
    "Process Env Fallback": "MEDIUM",
    "Client Secret Query": "MEDIUM",
    "Webhook Secret": "MEDIUM",
    "Basic Auth": "MEDIUM",
    "Session Cookie": "MEDIUM",
    "JWT": "MEDIUM",
    "Redis URL": "MEDIUM",
    "AMQP URL": "MEDIUM",
    "Elasticsearch URL": "MEDIUM",
    "Elasticsearch Auth": "MEDIUM",
    # Public-by-design / low standalone impact
    "Stripe Publishable": "INFO",
    "PayPal Client ID": "INFO",
    "Firebase URL": "INFO",
    "Mapbox Token": "INFO",
    "Cloudinary URL": "INFO",
    "CSRF Token": "LOW",
}

# Risk points contributed by one secret of each severity.
SECRETS_RISK_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}

# Internal-host severity ladder (Phase C): cloud metadata / link-local
# (169.254.x.x) is a direct credential-theft path → HIGH; other internal
# refs keep the historical MEDIUM rating.
INTERNAL_HOST_RISK_WEIGHTS = {"HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}

DEFAULT_INTERNAL_HOST_SEVERITY = "MEDIUM"


def secret_severity(secret_type: str) -> str:
    """Map a secret type label to CRITICAL/HIGH/MEDIUM/LOW/INFO."""
    return SECRET_SEVERITY.get(secret_type or "", DEFAULT_SECRET_SEVERITY)


def internal_host_severity(host: dict | None) -> str:
    """
    Severity for one internal_hosts_found entry.

    HIGH when the match hits a link-local / cloud-metadata range
    (169.254.x.x, including 169.254.169.254); otherwise MEDIUM.
    """
    if not isinstance(host, dict):
        return DEFAULT_INTERNAL_HOST_SEVERITY
    match = str(host.get("match", ""))
    kind = str(host.get("kind", ""))
    if kind == "metadata" or "169.254." in match:
        return "HIGH"
    return DEFAULT_INTERNAL_HOST_SEVERITY
