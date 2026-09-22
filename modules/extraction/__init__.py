"""
Extraction engine — orchestrates static + AST extraction of JS endpoints.

Public API:
    run_extractor, merge_results, extract_from_text, fetch_and_extract
    save_report, save_html_report (re-exported from reporting)
"""

from modules.extraction.engine import (
    run_extractor,
    merge_results,
    extract_from_text,
    fetch_and_extract,
    get_js_sources,
    check_source_map,
    discover_js_chunks,
)
from modules.extraction.patterns import (
    ENDPOINT_PATTERN,
    GENERIC_PATH_PATTERN,
    FULL_URL_PATTERN,
    CALL_PATTERN,
    is_noise,
    is_static_asset,
)
from modules.extraction.secrets import extract_secrets, deduplicate_secrets
from modules.extraction.http import RateLimiter, fetch_with_retry, get_page
from modules.extraction.scope import get_registrable_domain, is_same_scope
from modules.extraction.risk import calculate_risk_summary
from modules.extraction.deobfuscator import deobfuscate
from modules.extraction.ast import extract_endpoints_ast, ast_is_available
from modules.reporting.html import save_report, save_html_report

__all__ = [
    "run_extractor", "merge_results", "extract_from_text", "fetch_and_extract",
    "get_js_sources", "check_source_map", "discover_js_chunks",
    "ENDPOINT_PATTERN", "GENERIC_PATH_PATTERN", "FULL_URL_PATTERN", "CALL_PATTERN",
    "is_noise", "is_static_asset",
    "extract_secrets", "deduplicate_secrets",
    "RateLimiter", "fetch_with_retry", "get_page",
    "get_registrable_domain", "is_same_scope",
    "calculate_risk_summary",
    "deobfuscate",
    "extract_endpoints_ast", "ast_is_available",
    "save_report", "save_html_report",
]
