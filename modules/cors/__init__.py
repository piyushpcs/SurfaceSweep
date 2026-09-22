"""
CORS misconfiguration scanner — Phase 2.

Public API:
    scan_cors, cors_risk_boost, classify_cors, build_test_origins, normalize_origin
"""

from modules.cors.classifier import SEVERITY_ORDER, classify_cors
from modules.cors.origins import build_test_origins, normalize_origin, origins_equal
from modules.cors.probe import probe_endpoint
from modules.cors.scanner import cors_risk_boost, resolve_endpoints, scan_cors

__all__ = [
    "scan_cors",
    "cors_risk_boost",
    "classify_cors",
    "build_test_origins",
    "normalize_origin",
    "origins_equal",
    "probe_endpoint",
    "resolve_endpoints",
    "SEVERITY_ORDER",
]
