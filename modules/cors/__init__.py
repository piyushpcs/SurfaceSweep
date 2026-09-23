"""
CORS misconfiguration scanner — Phase 2.

Public API:
    scan_cors, cors_risk_boost, classify_cors, build_test_origins,
    normalize_origin, parse_acao_list, is_multi_origin_acao,
    resolve_endpoints, collect_js_origins, aggregate_findings
"""

from modules.cors.classifier import (
    SEVERITY_ORDER,
    classify_cors,
    is_multi_origin_acao,
    parse_acao_list,
)
from modules.cors.origins import build_test_origins, normalize_origin, origins_equal
from modules.cors.probe import build_evidence, probe_endpoint
from modules.cors.scanner import (
    aggregate_findings,
    collect_js_origins,
    cors_risk_boost,
    endpoint_priority,
    is_api_like_path,
    resolve_endpoints,
    scan_cors,
)

__all__ = [
    "scan_cors",
    "cors_risk_boost",
    "classify_cors",
    "build_test_origins",
    "normalize_origin",
    "origins_equal",
    "parse_acao_list",
    "is_multi_origin_acao",
    "probe_endpoint",
    "build_evidence",
    "resolve_endpoints",
    "endpoint_priority",
    "collect_js_origins",
    "aggregate_findings",
    "is_api_like_path",
    "SEVERITY_ORDER",
]
