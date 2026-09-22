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


def parse_acao_list(acao):
    """
    Split an ACAO header into discrete origin tokens.

    Spec allows a single origin or `*`. Comma-separated lists are invalid;
    some stacks emit them anyway. Returns ["*"], ["null"], or origin strings.
    """
    if not acao:
        return []
    raw = acao.strip()
    if raw == "*":
        return ["*"]
    # Split on comma; collapse whitespace; drop empties
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return parts or [raw]


def is_multi_origin_acao(acao):
    """True when ACAO lists more than one value (spec violation)."""
    return len(parse_acao_list(acao)) > 1


def classify_cors(origin, acao, acac, target_origin=None, registrable_domain=None):
    """
    Classify a single CORS probe result.

    Severity ladder (highest first):
      CRITICAL: arbitrary reflected origin + credentials, or null + credentials
      HIGH:     reflected origin (no credentials), related-origin + credentials,
                wildcard + credentials (invalid combo — browsers block)
      MEDIUM:   wildcard origin (no credentials), null origin allowed,
                non-singleton ACAO (comma-separated list)
      LOW:      host suffix / partial trust match
      INFO:     origin not reflected, or legitimate target origin (expected)
    """
    if not acao:
        return "INFO", "No Access-Control-Allow-Origin header"

    acao = acao.strip()
    creds = (acac or "").strip().lower() == "true"
    origin_n = normalize_origin(origin)
    acao_list = parse_acao_list(acao)
    multi = len(acao_list) > 1
    # Effective single ACAO for match tests (multi handled via list branches)
    effective_acao = acao_list[0] if acao_list else acao
    target_n = normalize_origin(target_origin) if target_origin else ""

    is_wildcard = "*" in acao_list or acao == "*"
    null_allowed = "null" in acao_list and origin_n == "null"
    # null is handled by the null ladder — not generic reflection
    reflected = (
        (not is_wildcard)
        and (not null_allowed)
        and (not multi)
        and origins_equal(origin, effective_acao)
    )
    # Multi-value ACAO that *contains* the request origin (still invalid header)
    origin_in_list = multi and any(
        origins_equal(origin, item) for item in acao_list if item not in ("*",)
    )

    # Legitimate same-site origin: expected CORS, not a finding
    if (reflected or origin_in_list) and target_n and origins_equal(origin, target_n):
        if multi:
            return (
                "MEDIUM",
                f"Non-singleton ACAO list includes legitimate origin "
                f"(ACAO={acao})",
            )
        return "INFO", f"Legitimate target origin allowed (ACAO={acao})"

    related = bool(target_n) and is_related_host(
        origin, target_n, registrable_domain=registrable_domain
    )

    if multi and not is_wildcard:
        # Spec: only one origin (or *). A list is malformed; browsers reject
        # the header — flag as MEDIUM unless it also carries credentials with
        # an arbitrary origin in the list (still not browser-usable as-is).
        if origin_in_list and creds and not related and not origins_equal(
            origin, target_n
        ):
            return (
                "MEDIUM",
                f"Non-singleton ACAO list contains arbitrary origin with "
                f"credentials (ACAO={acao}, ACAC=true; browsers reject multi-value)",
            )
        return "MEDIUM", f"Non-singleton ACAO (ACAO={acao})"

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
    oh = origin_host(origin)
    for item in acao_list:
        if is_host_suffix_match(oh, origin_host(item)):
            return "LOW", f"Partial host suffix match (ACAO={acao})"

    return "INFO", f"Origin not allowed (ACAO={acao})"
