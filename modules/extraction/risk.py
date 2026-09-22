"""
Risk scoring for scan results.
"""


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
    """
    score = 0
    score += len(result.get("secrets_found", [])) * 10
    score += len(result.get("source_maps_found", [])) * 5
    score += len(result.get("deobfuscation_findings", [])) * 3
    score += len(result.get("internal_paths", [])) * 1
    score += len(result.get("internal_hosts_found", [])) * 3
    for s in result.get("sinks_found", []):
        score += {"HIGH": 4, "MEDIUM": 2, "LOW": 1}.get(s.get("severity", ""), 1)

    if score >= 30:
        level = "HIGH"
    elif score >= 10:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "INFO"

    return {"score": score, "level": level}
