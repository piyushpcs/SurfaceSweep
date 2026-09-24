"""
Unified report builder (Phase 4 Step 7).

Single entry point for writing scan outputs. Computes every output path
once from `-o/--output` and dispatches JSON / HTML / Burp / ZAP writers.

Replaces the four duplicated path computations that previously lived
inline in stage_export / stage_report.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from modules.reporting.export import export_burp_csv, export_zap_csv
from modules.reporting.html import save_html_report, save_report


def output_paths(output: str) -> Dict[str, str]:
    """
    Derive all sibling output paths from the primary JSON path.

    Input:  reports/surfacesweep_report.json
    Output: {
      "json":  reports/surfacesweep_report.json,
      "html":  reports/surfacesweep_report.html,
      "burp":  reports/surfacesweep_report_burp.csv,
      "zap":   reports/surfacesweep_report_zap.csv,
      "base":  reports/surfacesweep_report,
    }
    """
    output = str(output or "reports/surfacesweep_report.json")
    if output.endswith(".json"):
        base = output[: -len(".json")]
    elif output.endswith(".html"):
        base = output[: -len(".html")]
    else:
        base = output
    return {
        "base": base,
        "json": f"{base}.json",
        "html": f"{base}.html",
        "burp": f"{base}_burp.csv",
        "zap": f"{base}_zap.csv",
        "cors_poc": f"{base}_cors_poc.html",
    }


def ensure_parent_dir(path: str) -> None:
    """Create the parent directory for path if missing."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def write_reports(
    result: Dict[str, Any],
    output: str,
    *,
    write_json: bool = True,
    write_html: bool = False,
    write_burp: bool = False,
    write_zap: bool = False,
    write_cors_poc: bool = False,
    verbose: bool = True,
) -> Dict[str, Optional[str]]:
    """
    Write all requested report formats in one call.

    Args:
        result: full scan result dict (schema_version/meta/findings when finalized)
        output: primary JSON path (siblings derived from it)
        write_json / write_html / write_burp / write_zap / write_cors_poc: toggles
        verbose: print save confirmations (writers already print when they succeed)

    Returns:
        {"json", "html", "burp", "zap", "cors_poc"} → path or None
    """
    paths = output_paths(output)
    written: Dict[str, Optional[str]] = {
        "json": None, "html": None, "burp": None, "zap": None,
        "cors_poc": None,
    }

    if write_json:
        ensure_parent_dir(paths["json"])
        save_report(result, paths["json"])
        written["json"] = paths["json"]

    if write_html:
        ensure_parent_dir(paths["html"])
        save_html_report(result, paths["html"])
        written["html"] = paths["html"]

    if write_burp:
        ensure_parent_dir(paths["burp"])
        if export_burp_csv(result, paths["burp"]):
            written["burp"] = paths["burp"]

    if write_zap:
        ensure_parent_dir(paths["zap"])
        if export_zap_csv(result, paths["zap"]):
            written["zap"] = paths["zap"]

    if write_cors_poc:
        from modules.reporting.cors_poc import write_cors_pocs

        poc_path = write_cors_pocs(result, paths["cors_poc"])
        if poc_path:
            written["cors_poc"] = poc_path
            if verbose:
                print(f"[+] CORS PoC HTML saved: {poc_path}")

    return written


def build_report_plan(args) -> Dict[str, bool]:
    """Map CLI flags onto write_reports toggles (single source of truth)."""
    write_html = bool(getattr(args, "html", False) or getattr(args, "html_only", False))
    write_json = not bool(getattr(args, "html_only", False))
    return {
        "write_json": write_json,
        "write_html": write_html,
        "write_burp": bool(getattr(args, "burp", False)),
        "write_zap": bool(getattr(args, "zap", False)),
        "write_cors_poc": bool(getattr(args, "cors_poc", False)),
    }
