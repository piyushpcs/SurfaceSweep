"""
JWT security analyzer — Phase 3.

Public API:
    analyze_jwt, analyze_result_jwts, decode_jwt, extract_jwts,
    deduplicate_jwts, collect_jwts_from_result, build_crack_candidates,
    verify_hs_signature, forge_hs256_token, try_key_confusion,
    rsa_jwk_to_pem, is_safe_jwt_fetch_url, fetch_jwks_keys,
    export_hashcat, export_jwt_findings, jwt_risk_boost, SEVERITY_ORDER
"""

from modules.jwt.checks import (
    SEVERITY_ORDER,
    analyze_jwt,
    is_high_entropy_value,
    is_placeholder_signature,
    kid_has_sqli,
    scan_jwts,
    shannon_entropy,
)
from modules.jwt.crack import (
    WEAK_SECRETS,
    build_crack_candidates,
    collect_candidate_secrets,
    export_hashcat,
    forge_hs256_token,
    load_wordlist,
    target_mutations,
    try_key_confusion,
    verify_hs_signature,
)
from modules.jwt.decode import (
    JWT_PATTERN,
    decode_jwt,
    deduplicate_jwts,
    extract_jwts,
)
from modules.jwt.keys import (
    collect_embedded_key_materials,
    collect_jku_urls,
    fetch_jwks_keys,
    is_safe_jwt_fetch_url,
    rsa_jwk_to_pem,
)
from modules.jwt.scanner import (
    analyze_result_jwts,
    collect_jwts_from_result,
    export_jwt_findings,
    jwt_risk_boost,
    jwt_summary,
)

__all__ = [
    "analyze_jwt",
    "analyze_result_jwts",
    "build_crack_candidates",
    "collect_candidate_secrets",
    "collect_embedded_key_materials",
    "collect_jku_urls",
    "collect_jwts_from_result",
    "decode_jwt",
    "deduplicate_jwts",
    "export_hashcat",
    "export_jwt_findings",
    "extract_jwts",
    "fetch_jwks_keys",
    "forge_hs256_token",
    "is_safe_jwt_fetch_url",
    "is_high_entropy_value",
    "is_placeholder_signature",
    "jwt_risk_boost",
    "jwt_summary",
    "JWT_PATTERN",
    "kid_has_sqli",
    "load_wordlist",
    "rsa_jwk_to_pem",
    "scan_jwts",
    "SEVERITY_ORDER",
    "shannon_entropy",
    "target_mutations",
    "try_key_confusion",
    "verify_hs_signature",
    "WEAK_SECRETS",
]
