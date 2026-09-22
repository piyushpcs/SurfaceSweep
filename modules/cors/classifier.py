"""
CORS response classification (severity ladder).
"""

from modules.cors.origins import (
    is_host_suffix_match,
    is_related_host,
    normalize_origin,
    origin_host,
    origins_equal,
)

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "ERROR": 5,
}


def classify_cors(origin, acao, acac, target_origin=None, registrable_domain=None):
    """
    Classify a single CORS probe result.

    Severity ladder (highest first):
      CRITICAL: arbitrary reflected origin + credentials, or null + credentials
      HIGH:     reflected origin (no credentials), related-origin + credentials,
                wildcard + credentials (invalid combo — browsers block)
      MEDIUM:   wildcard origin (no credentials), null origin allowed
      LOW:      host suffix / partial trust match
      INFO:     origin not reflected, or legitimate target origin (expected)
    """
    if not acao:
        return "INFO", "No Access-Control-Allow-Origin header"

    acao = acao.strip()
    creds = (acac or "").strip().lower() == "true"
    origin_n = normalize_origin(origin)
    acao_n = normalize_origin(acao)
    target_n = normalize_origin(target_origin) if target_origin else ""

    is_wildcard = acao == "*"
    null_allowed = acao_n == "null" and origin_n == "null"
    # null is handled by the null ladder — not generic reflection
    reflected = (
        (not is_wildcard)
        and (not null_allowed)
        and origins_equal(origin, acao)
    )

    # Legitimate same-site origin: expected CORS, not a finding
    if reflected and target_n and origins_equal(origin, target_n):
        return "INFO", f"Legitimate target origin allowed (ACAO={acao})"

    related = bool(target_n) and is_related_host(
        origin, target_n, registrable_domain=registrable_domain
    )

    if null_allowed and creds:
        return "CRITICAL", "Null origin allowed with credentials (ACAO=null, ACAC=true)"

    if reflected and creds:
        if related:
            return (
                "HIGH",
                f"Related (same-site) origin reflected with credentials "
                f"(ACAO={acao}, ACAC=true)",
            )
        return "CRITICAL", f"Arbitrary origin reflected with credentials (ACAO={acao}, ACAC=true)"

    if reflected:
        return "HIGH", f"Origin reflected (ACAO={acao})"

    if is_wildcard and creds:
        return (
            "HIGH",
            "Wildcard ACAO with Allow-Credentials: true "
            "(invalid — browsers block this combination)",
        )

    if is_wildcard:
        return "MEDIUM", "Wildcard ACAO (*)"

    if null_allowed:
        return "MEDIUM", "Null origin allowed"

    # Partial / suffix trust: e.g. host target.com.evil.com vs evil.com
    oh, ah = origin_host(origin), origin_host(acao)
    if is_host_suffix_match(oh, ah):
        return "LOW", f"Partial host suffix match (ACAO={acao})"

    return "INFO", f"Origin not allowed (ACAO={acao})"
