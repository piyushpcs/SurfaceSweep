"""Typed scan-result schema and factory (Phase B Step 3)."""

from __future__ import annotations

from typing import Any, Dict, List, NotRequired, TypedDict

__all__ = [
    "RESULT_SCHEMA_VERSION",
    "ScanResult",
    "new_scan_result",
]

RESULT_SCHEMA_VERSION = 1


class ScanResult(TypedDict, total=False):
    """Canonical shape of the mutable pipeline result dict."""

    # Core (always present after construction)
    target: str
    js_files_scanned: List[str]
    inline_scripts_scanned: int
    secrets_found: List[Dict[str, Any]]
    jwts_found: List[str]
    source_maps_found: List[str]
    deobfuscation_findings: List[Dict[str, Any]]
    sinks_found: List[Dict[str, Any]]
    internal_hosts_found: List[Dict[str, Any]]
    pii_found: List[Dict[str, Any]]
    params_found: List[Dict[str, Any]]
    errors: List[str]

    # Scan-mode / depth
    scan_mode: NotRequired[str]
    scan_depth: NotRequired[int]

    # Browser / full mode
    network_requests: NotRequired[List[Dict[str, Any]]]
    intercepted_endpoints: NotRequired[List[Dict[str, Any]]]

    # Discovery / enrichment (stages add these)
    internal_paths: NotRequired[List[str]]
    in_scope_urls: NotRequired[List[str]]
    out_of_scope_urls: NotRequired[List[str]]
    wayback_js_files: NotRequired[List[str]]
    spa_routes: NotRequired[List[str]]
    spa_routes_from: NotRequired[str]
    path_status: NotRequired[Dict[str, Any]]
    internal_paths_discovered: NotRequired[List[str]]

    # Analysis
    risk_summary: NotRequired[Dict[str, Any]]
    waf: NotRequired[Dict[str, Any]]
    libraries: NotRequired[List[Dict[str, Any]]]
    library_vulnerabilities: NotRequired[List[Dict[str, Any]]]
    osv_results: NotRequired[List[Dict[str, Any]]]
    cors: NotRequired[Dict[str, Any]]
    jwt: NotRequired[Dict[str, Any]]
    validation: NotRequired[Dict[str, Any]]

    # Finalization (runner)
    schema_version: NotRequired[int]
    findings: NotRequired[List[Dict[str, Any]]]
    executive_summary: NotRequired[Dict[str, Any]]
    meta: NotRequired[Dict[str, Any]]


def new_scan_result(
    target: str,
    *,
    scan_mode: str | None = None,
    scan_depth: int = 0,
    browser_fields: bool = False,
    **extra: Any,
) -> ScanResult:
    """
    Build a fresh result dict with the full core key set.

    browser_fields: include network_requests / intercepted_endpoints
    (browser mode and full merge). Extra keys are merged last so callers
    can override any default.
    """
    result: ScanResult = {
        "target": target,
        "js_files_scanned": [],
        "inline_scripts_scanned": 0,
        "secrets_found": [],
        "jwts_found": [],
        "source_maps_found": [],
        "deobfuscation_findings": [],
        "sinks_found": [],
        "internal_hosts_found": [],
        "pii_found": [],
        "params_found": [],
        "errors": [],
        "scan_depth": scan_depth,
    }
    if scan_mode is not None:
        result["scan_mode"] = scan_mode
    if browser_fields:
        result["network_requests"] = []
        result["intercepted_endpoints"] = []
    if extra:
        result.update(extra)
    return result
