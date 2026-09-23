"""
Risk scoring for scan results.

Base score is recomputed from result fields whenever the result changes.
Analysis boosts (CORS, JWT) are applied inside the same calculation so
every recalculation (wayback, SPA, validation) preserves them.
"""

RISK_THRESHOLDS = (
    (30, "HIGH"),
    (10, "MEDIUM"),
    (1, "LOW"),
)


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
        from modules.jwt_analyzer import jwt_risk_boost
    except ImportError:
        return boost
    if result.get("cors"):
        boost += cors_risk_boost(result["cors"])
    if result.get("jwt"):
        boost += jwt_risk_boost(result["jwt"])
    return boost


def calculate_risk_summary(result):
    """
    Calculate risk score and level from scan results.

    Score weights:
      - secrets: 10 each
      - HIGH sinks: 4 each, MEDIUM: 2 each, LOW: 1 each
      - internal hosts / private IPs: 3 each
      - source maps: 5 each
      - deobfuscation findings: 3 each
      - internal paths: 1 each
      - CORS / JWT analysis boosts (when result["cors"] / result["jwt"] set)
    """
    score = 0
    score += len(result.get("secrets_found", [])) * 10
    score += len(result.get("source_maps_found", [])) * 5
    score += len(result.get("deobfuscation_findings", [])) * 3
    score += len(result.get("internal_paths", [])) * 1
    score += len(result.get("internal_hosts_found", [])) * 3
    for s in result.get("sinks_found", []):
        score += {"HIGH": 4, "MEDIUM": 2, "LOW": 1}.get(s.get("severity", ""), 1)

    score += _analysis_boost(result)

    return {"score": score, "level": risk_level_for_score(score)}
