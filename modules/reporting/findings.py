"""
Cross-module findings feed + executive summary (Phase 4 Step 6).

Normalizes findings from secrets, sinks, CVEs, CORS, JWT, internal hosts,
source maps, and validation into one severity-ordered feed, plus a compact
executive summary block for the HTML header and JSON consumers.
"""

from __future__ import annotations

from typing import Any, Dict, List

from modules.common.constants import (
    SEVERITY_ORDER,
    internal_host_severity,
    secret_severity,
)

__all__ = [
    "SEVERITY_ORDER",
    "build_executive_summary",
    "build_findings_feed",
    "render_executive_summary",
    "render_findings_feed",
]


def _finding(severity: str, module: str, title: str, detail: str = "",
             url: str = "", source: str = "") -> Dict[str, Any]:
    return {
        "severity": (severity or "INFO").upper(),
        "module": module,
        "title": str(title),
        "detail": str(detail or ""),
        "url": str(url or ""),
        "source": str(source or ""),
    }


def build_findings_feed(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flatten every analysis module into one severity-ordered findings list.

    Each entry: {severity, module, title, detail, url, source}
    """
    feed: List[Dict[str, Any]] = []

    # --- Secrets (type-aware severity: publishable ≠ AWS key) ---
    for s in result.get("secrets_found") or []:
        sources = s.get("sources") or [s.get("source", "")]
        feed.append(_finding(
            secret_severity(s.get("type", "")), "secrets",
            f"Potential secret ({s.get('type', 'unknown')})",
            str(s.get("match", ""))[:80],
            source=", ".join(str(x) for x in sources if x),
        ))

    # --- Sinks ---
    for s in result.get("sinks_found") or []:
        feed.append(_finding(
            s.get("severity", "MEDIUM"), "sinks",
            f"Dangerous sink: {s.get('sink', '')}",
            str(s.get("description", ""))[:120],
            source=", ".join(str(x) for x in (s.get("sources") or [s.get("source", "")]) if x),
        ))

    # --- Internal hosts (metadata IP → HIGH; other internals stay MEDIUM) ---
    for h in result.get("internal_hosts_found") or []:
        sev = internal_host_severity(h)
        title = (
            "Cloud metadata reference (169.254.x)"
            if sev == "HIGH"
            else f"Internal reference ({h.get('kind', 'host')})"
        )
        feed.append(_finding(
            sev, "internal_hosts",
            title,
            str(h.get("match", "")),
            source=str(h.get("source", "")),
        ))

    # --- PII quick wins (severity from detector: INFO/LOW) ---
    for p in result.get("pii_found") or []:
        sources = p.get("sources") or [p.get("source", "")]
        feed.append(_finding(
            p.get("severity", "INFO"), "pii",
            f"Potential PII ({p.get('kind', 'unknown')})",
            str(p.get("match", ""))[:80],
            source=", ".join(str(x) for x in sources if x),
        ))

    # --- Source maps ---
    for m in result.get("source_maps_found") or []:
        feed.append(_finding(
            "HIGH", "source_maps",
            "Exposed source map",
            "Source map publicly accessible",
            url=str(m),
        ))

    # --- Library CVEs ---
    for v in result.get("library_vulnerabilities") or []:
        cves = ", ".join(str(c) for c in (v.get("cves") or []))
        feed.append(_finding(
            v.get("severity", "MEDIUM"), "cve",
            f"{v.get('library', '?')} {v.get('version', '?')} vulnerable",
            f"{cves} — {str(v.get('description', ''))[:120]}",
            source=str(v.get("source_file", "")),
        ))

    # --- CORS ---
    for f in (result.get("cors") or {}).get("findings") or []:
        if f.get("severity") in ("INFO", "ERROR"):
            continue
        feed.append(_finding(
            f.get("severity", "MEDIUM"), "cors",
            f"CORS misconfiguration ({f.get('severity', '')})",
            f"ACAO={f.get('acao', '')} detail={str(f.get('detail', ''))[:100]}",
            url=str(f.get("url", "")),
            source=", ".join(str(o) for o in (f.get("origins_flagged") or [f.get("origin", "")]) if o),
        ))

    # --- JWT ---
    for a in (result.get("jwt") or {}).get("findings") or []:
        issues = a.get("findings") or []
        if not issues:
            continue
        worst = min(issues, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 9))
        titles = "; ".join(str(i.get("issue", "")) for i in issues[:3])
        feed.append(_finding(
            a.get("severity") or worst.get("severity", "INFO"),
            "jwt",
            f"JWT issue ({a.get('alg', '?')})",
            titles,
            source=str(a.get("source", "")),
        ))

    # --- Validation dead endpoints (info-level signal) ---
    for item in (result.get("validation") or {}).get("dead") or []:
        feed.append(_finding(
            "INFO", "validation",
            "Endpoint not live (404)",
            "Likely false positive",
            url=str(item.get("url", "")),
        ))

    # --- GraphQL introspection (Phase F3) ---
    for f in (result.get("graphql") or {}).get("findings") or []:
        if f.get("severity") in ("INFO", "ERROR"):
            continue
        feed.append(_finding(
            f.get("severity", "HIGH"), "graphql",
            "GraphQL introspection enabled",
            str(f.get("detail", ""))[:140],
            url=str(f.get("url", "")),
        ))

    # --- Confirmed live secrets (Phase F4) ---
    for f in (result.get("secret_verification") or {}).get("findings") or []:
        if f.get("severity") in ("INFO", "ERROR"):
            continue
        feed.append(_finding(
            f.get("severity", "HIGH"), "secrets",
            "Confirmed live secret",
            str(f.get("detail", ""))[:140],
            source=str(f.get("vendor", "")),
        ))

    feed.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                             f["module"], f["title"]))
    return feed


def build_executive_summary(result: Dict[str, Any],
                            feed: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """
    Compact executive summary for report headers / JSON consumers.

    Returns:
      {
        risk_level, risk_score, severity_counts, total_findings,
        modules_covered, top_findings (first 5), counts: {...}
      }
    """
    if feed is None:
        feed = build_findings_feed(result)

    severity_counts: Dict[str, int] = {}
    for f in feed:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    modules = sorted({f["module"] for f in feed})
    risk = result.get("risk_summary") or {}

    return {
        "risk_level": risk.get("level", "INFO"),
        "risk_score": risk.get("score", 0),
        "severity_counts": severity_counts,
        "total_findings": len(feed),
        "modules_covered": modules,
        "top_findings": feed[:5],
        "counts": {
            "internal_paths": len(result.get("internal_paths") or []),
            "in_scope_urls": len(result.get("in_scope_urls") or []),
            "secrets": len(result.get("secrets_found") or []),
            "js_files": len(result.get("js_files_scanned") or []),
            "cors": len((result.get("cors") or {}).get("findings") or []),
            "jwt_tokens": (result.get("jwt") or {}).get("tokens_analyzed", 0),
            "cves": len(result.get("library_vulnerabilities") or []),
            "spa_routes": len(result.get("spa_routes") or []),
            "pii": len(result.get("pii_found") or []),
            "params": len(result.get("params_found") or []),
            "graphql_findings": len((result.get("graphql") or {}).get("findings") or []),
            "secrets_confirmed": (result.get("secret_verification") or {}).get("confirmed", 0),
            "requests_sent": (result.get("meta") or {}).get("requests_sent", 0),
        },
    }


def render_executive_summary(summary: Dict[str, Any]) -> str:
    """HTML block for the top of the report (escaped)."""
    from html import escape as _esc

    if not summary:
        return ""

    risk_level = _esc(str(summary.get("risk_level", "INFO")))
    risk_score = summary.get("risk_score", 0)
    total = summary.get("total_findings", 0)
    counts = summary.get("severity_counts") or {}
    risk_color = {
        "HIGH": "#e74c3c",
        "MEDIUM": "#f39c12",
        "LOW": "#27ae60",
        "INFO": "#3498db",
    }.get(str(summary.get("risk_level", "")), "#999")

    sev_bits = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        if n:
            color = "#ff4d6d" if sev == "CRITICAL" else (
                "#e74c3c" if sev == "HIGH" else (
                    "#f39c12" if sev == "MEDIUM" else (
                        "#27ae60" if sev == "LOW" else "#3498db"
                    )
                )
            )
            sev_bits.append(
                f'<span class="badge badge-critical" style="color:{color};border-color:{color}55;">'
                f'{sev} × {n}</span>'
            )

    top_rows = []
    for f in summary.get("top_findings") or []:
        top_rows.append(
            f'<tr><td>{_esc(str(f.get("severity", "")))}</td>'
            f'<td>{_esc(str(f.get("module", "")))}</td>'
            f'<td>{_esc(str(f.get("title", "")))}</td></tr>'
        )
    top_html = ""
    if top_rows:
        top_html = (
            '<h3 style="margin:0.75rem 0 0.35rem;color:#8b949e;font-size:0.9rem;">Top findings</h3>'
            '<table><thead><tr><th>Severity</th><th>Module</th><th>Finding</th></tr></thead>'
            f'<tbody>{"".join(top_rows)}</tbody></table>'
        )

    modules = ", ".join(_esc(str(m)) for m in summary.get("modules_covered") or []) or "—"
    sev_line = " ".join(sev_bits) or '<span class="muted">No flagged findings</span>'
    requests_sent = (summary.get("counts") or {}).get("requests_sent", 0)
    footprint = (
        f' · {requests_sent} HTTP request(s) sent'
        if requests_sent else ""
    )

    return (
        f'<h2>Executive Summary</h2>'
        f'<p>Risk: <span class="risk" style="background:{risk_color}">{risk_level}</span> '
        f'(score {risk_score}) · {total} finding(s) · modules: {modules}{footprint}</p>'
        f'<p>{sev_line}</p>'
        f'{top_html}'
    )


def render_findings_feed(feed: List[Dict[str, Any]]) -> str:
    """HTML table for the full cross-module findings feed (escaped)."""
    from html import escape as _esc

    if not feed:
        return ""
    rows = []
    for f in feed[:200]:
        rows.append(
            f'<tr><td>{_esc(str(f.get("severity", "")))}</td>'
            f'<td>{_esc(str(f.get("module", "")))}</td>'
            f'<td>{_esc(str(f.get("title", "")))}</td>'
            f'<td class="muted">{_esc(str(f.get("detail", ""))[:120])}</td>'
            f'<td><code>{_esc(str(f.get("url") or f.get("source") or ""))}</code></td></tr>'
        )
    more = ""
    if len(feed) > 200:
        more = f'<p class="muted">Showing 200 of {len(feed)} findings</p>'
    return (
        f'<h2>All Findings ({len(feed)})</h2>'
        '<table><thead><tr><th>Severity</th><th>Module</th><th>Finding</th>'
        '<th>Detail</th><th>Source</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>{more}'
    )
