"""
CORS response classification (severity ladder).
"""

from modules.common.constants import SEVERITY_ORDER
from modules.cors.origins import (
    is_host_suffix_match,
    is_related_host,
    normalize_origin,
    origin_host,
    origins_equal,
)

__all__ = [
    "SEVERITY_ORDER",
    "classify_cors",
    "is_multi_origin_acao",
    "is_pna_allowed",
    "parse_acao_list",
]


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


def is_pna_allowed(acpn):
    """
    True when Access-Control-Allow-Private-Network permits private-network
    access (CORS-RFC1918 / Private Network Access).
    """
    return (acpn or "").strip().lower() in ("true", "1", "yes")


def classify_cors(origin, acao, acac, target_origin=None, registrable_domain=None, acpn=None,
                  public=False):
    """
    Classify a single CORS probe result.

    Severity ladder (highest first):
      CRITICAL: arbitrary reflected origin + credentials, or null + credentials
      HIGH:     reflected origin (no credentials), related-origin + credentials,
                wildcard + credentials (invalid combo — browsers block),
                permissive ACAO with Access-Control-Allow-Private-Network
      MEDIUM:   wildcard origin (no credentials), null origin allowed,
                non-singleton ACAO (comma-separated list)
      LOW:      wildcard on demonstrably public content, host suffix / partial
                trust match
      INFO:     origin not reflected, or legitimate target origin (expected)

    ``acpn`` is the Access-Control-Allow-Private-Network response header.
    When PNA is allowed with a permissive ACAO (wildcard / reflected /
    null), severity is elevated and the detail notes private-network reach.

    ``public`` marks an endpoint that answered a bare GET with no
    Set-Cookie and no auth challenge — i.e. static/public content where
    ``Access-Control-Allow-Origin: *`` is expected and not exploitable.
    A no-credentials wildcard there is downgraded to LOW.
    """
    if not acao:
        return "INFO", "No Access-Control-Allow-Origin header"

    acao = acao.strip()
    creds = (acac or "").strip().lower() == "true"
    pna = is_pna_allowed(acpn)
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
    # ACAO grants cross-origin read: wildcard, reflected, null, or multi containing origin
    permissive = bool(is_wildcard or reflected or null_allowed or origin_in_list)

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
            return _apply_pna(
                "MEDIUM",
                f"Non-singleton ACAO list contains arbitrary origin with "
                f"credentials (ACAO={acao}, ACAC=true; browsers reject multi-value)",
                pna,
                acao_grants=True,
            )
        return _apply_pna(
            "MEDIUM", f"Non-singleton ACAO (ACAO={acao})", pna, acao_grants=permissive
        )

    if null_allowed and creds:
        return _apply_pna(
            "CRITICAL",
            "Null origin allowed with credentials (ACAO=null, ACAC=true); "
            "exploitable via sandboxed iframe / Origin: null clients",
            pna,
            acao_grants=True,
        )

    if reflected and creds:
        if related:
            return _apply_pna(
                "HIGH",
                f"Related (same-site) origin reflected with credentials "
                f"(ACAO={acao}, ACAC=true)",
                pna,
                acao_grants=True,
            )
        return _apply_pna(
            "CRITICAL",
            f"Arbitrary origin reflected with credentials "
            f"(ACAO={acao}, ACAC=true); cross-origin data theft possible",
            pna,
            acao_grants=True,
        )

    if reflected:
        return _apply_pna(
            "HIGH", f"Origin reflected (ACAO={acao})", pna, acao_grants=True
        )

    if is_wildcard and creds:
        return _apply_pna(
            "HIGH",
            "Wildcard ACAO with Allow-Credentials: true "
            "(invalid — browsers block this combination; "
            "still a misconfig for non-browser clients)",
            pna,
            acao_grants=True,
        )

    if is_wildcard:
        if public:
            return _apply_pna(
                "LOW",
                "Wildcard ACAO (*) on public unauthenticated content "
                "(no Set-Cookie / auth challenge) — typically informational",
                pna,
                acao_grants=True,
            )
        return _apply_pna(
            "MEDIUM",
            "Wildcard ACAO (*) — acceptable for public unauthenticated "
            "content, risky when cookies/auth are in play",
            pna,
            acao_grants=True,
        )

    if null_allowed:
        return _apply_pna(
            "MEDIUM",
            "Null origin allowed — sandboxed iframes and some redirects "
            "send Origin: null",
            pna,
            acao_grants=True,
        )

    # Partial / suffix trust: e.g. host target.com.evil.com vs evil.com
    oh = origin_host(origin)
    for item in acao_list:
        if is_host_suffix_match(oh, origin_host(item)):
            severity = "LOW"
            detail = f"Partial host suffix match (ACAO={acao})"
            return _apply_pna(severity, detail, pna, acao_grants=permissive)

    return _apply_pna("INFO", f"Origin not allowed (ACAO={acao})", pna, acao_grants=False)


def _pna_note():
    return (
        "Access-Control-Allow-Private-Network: true "
        "(Private Network Access / CORS-RFC1918 — public origins may reach "
        "private-network targets)"
    )


def _apply_pna(severity, detail, pna, acao_grants):
    """
    Elevate severity / annotate detail when PNA is allowed alongside a
    permissive ACAO. INFO (no grant) is left alone.
    """
    if not pna or not acao_grants or severity in ("INFO", "ERROR"):
        return severity, detail
    note = _pna_note()
    # Wildcard + PNA is no longer "acceptable public content" — browsers
    # that implement PNA will still block * + private, but non-browser
    # clients and misconfigured edge rules make this HIGH.
    if severity == "MEDIUM" and "Wildcard" in (detail or ""):
        severity = "HIGH"
    # Reflected origin already HIGH/CRITICAL — PNA only strengthens the note.
    if detail and note not in detail:
        detail = f"{detail}; {note}"
    elif not detail:
        detail = note
    return severity, detail
