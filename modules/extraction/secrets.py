"""
Secret detection patterns and deduplication.
"""

import re
from modules.extraction.patterns import is_likely_real_secret


SECRET_PATTERNS = {
    "AWS Access Key":     re.compile(r'AKIA[0-9A-Z]{16}'),
    "Generic API Key":    re.compile(r'["\']api[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,45})["\']', re.IGNORECASE),
    "Bearer Token":       re.compile(r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}'),
    "Google API Key":     re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
    "Slack Token":        re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
    "Firebase URL":       re.compile(r'[a-zA-Z0-9-]+\.firebaseio\.com'),
    "Generic Secret":     re.compile(r'["\'](secret|token|apikey)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{10,})["\']', re.IGNORECASE),
    "GitHub Token":       re.compile(r'gh[po]_[a-zA-Z0-9]{36,}'),
    "GitLab Token":       re.compile(r'glpat-[a-zA-Z0-9_\-]{20}'),
    "Stripe Live Key":    re.compile(r'[sp]k_live_[a-zA-Z0-9]{24,}'),
    "Heroku API Key":     re.compile(r'["\']heroku[_-]?api[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9\-]{20,})["\']', re.IGNORECASE),
    "NPM Token":          re.compile(r'npm_[a-zA-Z0-9]{36}'),
    "Exposed Env Var":    re.compile(r'(NEXT_PUBLIC_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|VITE_[A-Z0-9_]+)\s*[:=]\s*["\']([^"\']{4,100})["\']'),
    "Private Key":        re.compile(r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----'),
    "JWT Secret":         re.compile(r'["\'](?:jwt[_-]?secret|signing[_-]?key|hmac[_-]?key|jwt[_-]?key)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.\/+=]{10,})["\']', re.IGNORECASE),
    "Database URL":       re.compile(r'(mysql|postgres|postgresql|mongodb|redis|amqp|mssql):\/\/[^\s"\'<>]{10,}', re.IGNORECASE),
    "SMTP Credentials":   re.compile(r'["\'](?:smtp[_-]?pass|mail[_-]?password|email[_-]?password)["\']\s*[:=]\s*["\']([^\s"\']{6,})["\']', re.IGNORECASE),
    "Basic Auth":         re.compile(r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}'),
    "Generic Password":   re.compile(r'["\'](password|passwd|pwd|pass)["\']\s*[:=]\s*["\']([^\s"\']{6,})["\']', re.IGNORECASE),
}


def extract_secrets(content, source_label):
    """
    Extract potential secrets from content.
    Returns list of {type, match, source}.
    """
    secrets = []
    for label, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(content):
            value = m.group(1) if m.groups() else m.group(0)
            if not is_likely_real_secret(value):
                continue
            secrets.append({
                "type": label,
                "match": m.group(0)[:80],
                "source": source_label
            })
    return secrets


def deduplicate_secrets(all_secrets):
    """
    Same secret appearing in multiple files should be one entry with
    a list of sources, not N duplicate entries.
    """
    dedup = {}
    for s in all_secrets:
        key = (s["type"], s["match"])
        if key not in dedup:
            dedup[key] = {"type": s["type"], "match": s["match"], "sources": []}
        if s["source"] not in dedup[key]["sources"]:
            dedup[key]["sources"].append(s["source"])
    return list(dedup.values())
