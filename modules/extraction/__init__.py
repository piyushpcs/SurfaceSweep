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
from modules.extraction.sourcemaps import (
    parse_source_mapping_url,
    resolve_source_map_url,
    decode_inline_sourcemap,
    load_source_map,
    collect_source_map_sources,
)
from modules.extraction.enrich import (
    enrich_endpoint,
    enrich_intercepted_endpoints,
    endpoint_tags,
    infer_method,
    is_likely_authed,
    is_state_changing,
    resolve_method,
)
from modules.extraction.patterns import (
    ENDPOINT_PATTERN,
    GENERIC_PATH_PATTERN,
    FULL_URL_PATTERN,
    CALL_PATTERN,
    is_noise,
    is_static_asset,
    find_internal_hosts,
)
from modules.extraction.secrets import extract_secrets, deduplicate_secrets
from modules.extraction.http import (
    HttpClient,
    RateLimiter,
    cache_text,
    clear_text_cache,
    configure_http,
    default_headers,
    fetch_text,
    fetch_with_retry,
    get_cached_text,
    get_page,
    parse_retry_after,
    request_kwargs,
    reset_http_config,
)
from modules.extraction.scope import (
    get_registrable_domain,
    is_same_scope,
    normalize_scope_filter,
)
from modules.extraction.risk import calculate_risk_summary, risk_level_for_score
from modules.extraction.deobfuscator import deobfuscate
from modules.extraction.ast import extract_endpoints_ast, ast_is_available
from modules.analysis.sinks import detect_sinks, deduplicate_sinks
from modules.analysis.pii import detect_pii, deduplicate_pii
from modules.reporting.html import save_report, save_html_report

__all__ = [
    "run_extractor", "merge_results", "extract_from_text", "fetch_and_extract",
    "get_js_sources", "check_source_map", "discover_js_chunks",
    "parse_source_mapping_url", "resolve_source_map_url",
    "decode_inline_sourcemap", "load_source_map",
    "collect_source_map_sources",
    "enrich_endpoint", "enrich_intercepted_endpoints",
    "endpoint_tags", "infer_method", "resolve_method",
    "is_likely_authed", "is_state_changing",
    "ENDPOINT_PATTERN", "GENERIC_PATH_PATTERN", "FULL_URL_PATTERN", "CALL_PATTERN",
    "is_noise", "is_static_asset", "find_internal_hosts",
    "extract_secrets", "deduplicate_secrets",
    "detect_sinks", "deduplicate_sinks",
    "detect_pii", "deduplicate_pii",
    "HttpClient", "RateLimiter", "fetch_with_retry", "get_page", "fetch_text",
    "configure_http", "reset_http_config", "request_kwargs",
    "default_headers", "parse_retry_after",
    "cache_text", "get_cached_text", "clear_text_cache",
    "get_registrable_domain", "is_same_scope", "normalize_scope_filter",
    "calculate_risk_summary",
    "risk_level_for_score",
    "deobfuscate",
    "extract_endpoints_ast", "ast_is_available",
    "save_report", "save_html_report",
]
