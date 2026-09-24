"""
Reporting — generate output formats (JSON, HTML, Burp CSV, ZAP CSV).

Unified entry point: write_reports / output_paths / build_report_plan
(single path computation for all formats — Phase 4 Step 7).
"""

from modules.reporting.html import save_report, save_html_report, build_html
from modules.reporting.findings import (
    build_executive_summary,
    build_findings_feed,
    render_executive_summary,
    render_findings_feed,
)
from modules.reporting.export import export_burp_csv, export_zap_csv, export_wordlist, build_wordlist
from modules.reporting.builder import (
    build_report_plan,
    ensure_parent_dir,
    output_paths,
    write_reports,
)
from modules.reporting.diff import diff_results, load_result, print_diff, save_diff
from modules.reporting.sarif import build_sarif, export_sarif

__all__ = [
    "save_report", "save_html_report", "build_html",
    "build_executive_summary", "build_findings_feed",
    "render_executive_summary", "render_findings_feed",
    "export_burp_csv", "export_zap_csv", "export_wordlist", "build_wordlist",
    "build_report_plan", "ensure_parent_dir", "output_paths", "write_reports",
    "diff_results", "load_result", "print_diff", "save_diff",
    "build_sarif", "export_sarif",
]
