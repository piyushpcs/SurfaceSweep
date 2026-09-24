"""
Risk scoring for scan results.

Base score is recomputed from result fields whenever the result changes.
Analysis boosts (CORS, JWT) are applied inside the same calculation so
every recalculation (wayback, SPA, validation) preserves them.
"""

from modules.common.constants import (
    CVE_SEVERITY_WEIGHTS,
    RISK_THRESHOLDS,
    SECRETS_RISK_WEIGHTS,
    secret_severity,
)

__all__ = [
    "CVE_SEVERITY_WEIGHTS",
    "RISK_THRESHOLDS",
    "SECRETS_RISK_WEIGHTS",
    "calculate_risk_summary",
    "risk_level_for_score",
]


def risk_level_for_score(score):
    """Map a numeric score to a risk level label."""
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return "INFO"


def _analysis_boost(result):
    """
    Boosts from optional analysis modules stored on the result.

    Imported lazily to avoid package cycles (extraction ↔ cors/jwt).
    """
    boost = 0
    try:
        from modules.cors.scanner import cors_risk_boost
        from modules.jwt import jwt_risk_boost
    except ImportError:
        return boost
    if result.get("cors"):
        boost += cors_risk_boost(result["cors"])
    if result.get("jwt"):
        boost += jwt_risk_boost(result["jwt"])
    return boost


def _cve_boost(result):
    """
    Weight CVE/OSV library vulnerabilities found by stage_cve.

    Applied inside calculate_risk_summary so later recalculations
    (SPA, validation, wayback) preserve the boost instead of wiping it.
    """
    return sum(
        CVE_SEVERITY_WEIGHTS.get(v.get("severity", ""), 5)
        for v in result.get("library_vulnerabilities") or []
    )


def _secrets_boost(result):
    """
    Weight secrets by type severity (Phase C).

    CRITICAL (private keys, AWS secret, DB URLs) count far more than
    publishable/CSRF tokens; unmapped vendor keys keep the old HIGH weight.
    """
    total = 0
    for s in result.get("secrets_found") or []:
        sev = secret_severity(s.get("type", ""))
        total += SECRETS_RISK_WEIGHTS.get(sev, SECRETS_RISK_WEIGHTS["HIGH"])
    return total


def calculate_risk_summary(result):
    """
    Calculate risk score and level from scan results.

    Score weights:
      - secrets: by type severity (CRITICAL=25, HIGH=10, MEDIUM=5, LOW=2, INFO=0)
      - HIGH sinks: 4 each, MEDIUM: 2 each, LOW: 1 each
      - internal hosts / private IPs: 3 each
      - source maps: 5 each
      - deobfuscation findings: 3 each
      - internal paths: 1 each
      - library CVEs: CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3 (default 5)
      - CORS / JWT analysis boosts (when result["cors"] / result["jwt"] set)
    """
    score = 0
    score += _secrets_boost(result)
    score += len(result.get("source_maps_found", [])) * 5
    score += len(result.get("deobfuscation_findings", [])) * 3
    score += len(result.get("internal_paths", [])) * 1
    score += len(result.get("internal_hosts_found", [])) * 3
    for s in result.get("sinks_found", []):
        score += {"HIGH": 4, "MEDIUM": 2, "LOW": 1}.get(s.get("severity", ""), 1)

    score += _cve_boost(result)
    score += _analysis_boost(result)

    return {"score": score, "level": risk_level_for_score(score)}
