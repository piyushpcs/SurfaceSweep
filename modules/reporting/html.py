"""
HTML report generation for SurfaceSweep.

Keeps HTML/CSS templates separate from extraction logic.
All dynamic values are escaped via html.escape before interpolation.
"""

import json
from html import escape as _esc

from modules.common.console import ok, warn
from modules.common.constants import SEVERITY_ORDER as CORS_SEV_ORDER
from modules.reporting.findings import (
    build_executive_summary,
    build_findings_feed,
    render_executive_summary,
    render_findings_feed,
)

# Canonical severity rank (lower = worse); same map as modules.common.
__all__ = ["CORS_SEV_ORDER"]


CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; line-height: 1.6; }
h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
h2 { font-size: 1.15rem; margin: 1.5rem 0 0.5rem; color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 0.3rem; }
.target { color: #8b949e; font-size: 0.9rem; margin-bottom: 1.5rem; }
.risk { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: 600; color: #fff; font-size: 0.9rem; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1rem 0; }
.stat { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 1rem; text-align: center; }
.stat .num { font-size: 1.8rem; font-weight: 700; color: #58a6ff; }
.stat .label { font-size: 0.8rem; color: #8b949e; margin-top: 0.25rem; }
ul { list-style: none; padding: 0; }
li { padding: 0.25rem 0; }
code { background: #161b22; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; word-break: break-all; }
table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
th { text-align: left; padding: 0.5rem; border-bottom: 2px solid #21262d; color: #8b949e; font-size: 0.8rem; text-transform: uppercase; }
td { padding: 0.5rem; border-bottom: 1px solid #21262d; font-size: 0.85rem; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }
.badge-critical { background: #ff004022; color: #ff4d6d; border: 1px solid #ff004055; }
.badge-high { background: #e74c3c22; color: #e74c3c; border: 1px solid #e74c3c44; }
.badge-live { background: #27ae6022; color: #27ae60; border: 1px solid #27ae6044; }
.badge-restricted { background: #f39c1222; color: #f39c12; border: 1px solid #f39c1244; }
.badge-dead { background: #e74c3c22; color: #e74c3c; border: 1px solid #e74c3c44; }
.badge-error { background: #95a5a622; color: #95a5a6; border: 1px solid #95a5a644; }
.muted { color: #8b949e; }
.errors { background: #e74c3c11; border: 1px solid #e74c3c33; border-radius: 6px; padding: 1rem; margin-top: 1rem; }
.footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #21262d; color: #484f58; font-size: 0.8rem; text-align: center; }
"""


def _sev_badge(sev):
    """Severity badge with distinct CRITICAL styling."""
    sev = (sev or "").upper()
    css = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-restricted",
        "LOW": "badge-live",
        "INFO": "badge-error",
    }.get(sev, "badge-error")
    label = _esc(sev) if sev else "—"
    return f'<span class="badge {css}">{label}</span>'


def render_list(items, empty_msg="None found"):
    """Render a list of items as HTML (escaped)."""
    if not items:
        return f'<p class="muted">{_esc(empty_msg)}</p>'
    return (
        "<ul>"
        + "".join(f"<li><code>{_esc(str(item))}</code></li>" for item in items)
        + "</ul>"
    )


def render_secrets(secrets):
    """Render secrets table (escaped)."""
    if not secrets:
        return '<p class="muted">No secrets detected</p>'
    rows = []
    for s in secrets:
        sources = ", ".join(str(x) for x in s.get("sources", [s.get("source", "unknown")]))
        rows.append(
            f'<tr><td><span class="badge badge-high">{_esc(str(s.get("type", "")))}</span></td>'
            f'<td><code>{_esc(str(s.get("match", "")))}</code></td>'
            f'<td class="muted">{_esc(sources)}</td></tr>'
        )
    return (
        '<table><thead><tr><th>Type</th><th>Match</th><th>Sources</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def render_validation(validation):
    """Render validation results section (escaped)."""
    if not validation:
        return ""

    total_live = len(validation.get("live", []))
    total_restricted = len(validation.get("restricted", []))
    total_dead = len(validation.get("dead", []))
    total_error = (
        len(validation.get("server_error", [])) +
        len(validation.get("timeout", [])) +
        len(validation.get("connection_error", []))
    )

    status_badges = {
        "live": '<span class="badge badge-live">LIVE</span>',
        "restricted": '<span class="badge badge-restricted">RESTRICTED</span>',
        "dead": '<span class="badge badge-dead">DEAD</span>',
        "server_error": '<span class="badge badge-error">ERROR</span>',
    }

    rows = []
    for status in ["live", "restricted", "dead", "server_error"]:
        for item in validation.get(status, []):
            code = item.get("status_code", "ERR")
            rows.append(
                f'<tr><td>{status_badges.get(status, status)}</td>'
                f'<td>{_esc(str(code))}</td>'
                f'<td><code>{_esc(str(item.get("url", "")))}</code></td></tr>'
            )

    table = (
        '<table><thead><tr><th>Status</th><th>Code</th><th>URL</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
        if rows else '<p class="muted">No endpoints validated</p>'
    )

    return f"""
<h2>Endpoint Validation</h2>
<div class="stats">
  <div class="stat"><div class="num" style="color:#27ae60">{total_live}</div><div class="label">Live</div></div>
  <div class="stat"><div class="num" style="color:#f39c12">{total_restricted}</div><div class="label">Restricted (401/403)</div></div>
  <div class="stat"><div class="num" style="color:#e74c3c">{total_dead}</div><div class="label">Dead (404)</div></div>
  <div class="stat"><div class="num" style="color:#95a5a6">{total_error}</div><div class="label">Errors</div></div>
</div>
{table}
"""


def render_deobf(findings):
    """Render deobfuscation findings section (escaped)."""
    if not findings:
        return ""
    rows = []
    for f in findings:
        rows.append(
            f'<tr><td><span class="badge badge-live">{_esc(str(f.get("type", "")))}</span></td>'
            f'<td><code>{_esc(str(f.get("decoded", ""))[:120])}</code></td></tr>'
        )
    return (
        '<h2>Deobfuscation Findings</h2>'
        '<table><thead><tr><th>Type</th><th>Decoded</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def render_errors(errors):
    """Render errors section (escaped)."""
    if not errors:
        return ""
    return (
        '<h2>Errors</h2><div class="errors">' +
        "".join(f"<p>{_esc(str(e))}</p>" for e in errors) +
        "</div>"
    )


def render_libraries(libraries, vulnerabilities, osv_results=None):
    """Render detected libraries and their vulnerabilities (escaped)."""
    if not libraries and not vulnerabilities:
        return ""

    parts = []

    # Libraries table
    if libraries:
        rows = []
        for lib in libraries:
            rows.append(
                f'<tr><td><code>{_esc(str(lib.get("library", "")))}</code></td>'
                f'<td><code>{_esc(str(lib.get("version", "")))}</code></td>'
                f'<td class="muted">{_esc(str(lib.get("source", "")))}</td>'
                f'<td class="muted">{_esc(str(lib.get("file", ""))[:60])}</td></tr>'
            )
        parts.append(
            '<h2>Detected JavaScript Libraries</h2>'
            '<table><thead><tr><th>Library</th><th>Version</th><th>Detected From</th><th>Source File</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>'
        )

    # Vulnerabilities table
    if vulnerabilities:
        rows = []
        for v in vulnerabilities:
            sev = _sev_badge(v.get("severity", ""))
            cves = v.get("cves") or []
            cve_str = ", ".join(
                f'<a href="https://nvd.nist.gov/vuln/detail/{_esc(str(cve))}" style="color:#58a6ff">{_esc(str(cve))}</a>'
                for cve in cves
            )
            cvss = f' ({_esc(str(v["cvss"]))})' if v.get("cvss") else ""
            rows.append(
                f'<tr><td>{sev}</td>'
                f'<td><code>{_esc(str(v.get("library", "")))} {_esc(str(v.get("version", "")))}</code></td>'
                f'<td>{cve_str}{cvss}</td>'
                f'<td>{_esc(str(v.get("description", "")))}</td>'
                f'<td><code>{_esc(str(v.get("fixed_in", "unknown")))}</code></td></tr>'
            )
        parts.append(
            '<h2>Library Vulnerabilities (CVE)</h2>'
            '<table><thead><tr><th>Severity</th><th>Library</th><th>CVE</th><th>Description</th><th>Fixed In</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>'
        )

    # OSV results
    if osv_results:
        rows = []
        for lib_name, data in osv_results.items():
            version = data.get("version", "")
            for vuln in data.get("vulns", []):
                vid = str(vuln.get("id", ""))
                vid_link = f'<a href="https://osv.dev/vulnerability/{_esc(vid)}" style="color:#58a6ff">{_esc(vid)}</a>'
                rows.append(
                    f'<tr><td><code>{_esc(str(lib_name))} {_esc(str(version))}</code></td>'
                    f'<td>{vid_link}</td>'
                    f'<td>{_esc(str(vuln.get("summary", ""))[:150])}</td></tr>'
                )
        if rows:
            parts.append(
                '<h2>OSV.dev Additional Findings</h2>'
                '<table><thead><tr><th>Library</th><th>OSV ID</th><th>Summary</th></tr></thead>'
                f'<tbody>{"".join(rows)}</tbody></table>'
            )

    return "\n".join(parts) if parts else ""


def render_spa_routes(routes, routes_from=None):
    """Render SPA routes section (escaped)."""
    if not routes:
        return ""
    source_labels = {
        "static": '<span class="badge badge-live">static</span>',
        "dom": '<span class="badge badge-restricted">dom</span>',
        "vue": '<span class="badge badge-live">vue</span>',
        "react": '<span class="badge badge-live">react</span>',
        "next": '<span class="badge badge-live">next</span>',
        "history": '<span class="badge badge-restricted">history</span>',
        "crawl": '<span class="badge badge-restricted">crawl</span>',
        "probe": '<span class="badge badge-dead">probe</span>',
    }
    rows = []
    for route in routes:
        src = (routes_from or {}).get(route, "")
        badge = source_labels.get(src, f'<span class="muted">{_esc(str(src))}</span>')
        rows.append(
            f'<tr><td><code>{_esc(str(route))}</code></td><td>{badge}</td></tr>'
        )
    return (
        f'<h2>SPA Routes Discovered ({len(routes)})</h2>'
        '<table><thead><tr><th>Route</th><th>Source</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def render_sinks(sinks):
    """Render dangerous sink findings section (escaped)."""
    if not sinks:
        return ""
    rows = []
    for s in sinks:
        sources = ", ".join(str(x) for x in s.get("sources", [s.get("source", "unknown")]))
        rows.append(
            f'<tr><td>{_sev_badge(s.get("severity", ""))}</td>'
            f'<td><code>{_esc(str(s.get("sink", "")))}</code></td>'
            f'<td>{_esc(str(s.get("description", "")))}</td>'
            f'<td>{s.get("count", 1)}</td>'
            f'<td class="muted">{_esc(sources)}</td></tr>'
        )
    return (
        f'<h2>Dangerous Sinks ({len(sinks)})</h2>'
        '<table><thead><tr><th>Severity</th><th>Sink</th><th>Description</th><th>Hits</th><th>Sources</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def render_pii(items):
    """Render PII quick-win findings section (escaped)."""
    if not items:
        return ""
    kind_label = {
        "email": "Email",
        "phone_e164": "Phone (E.164)",
        "credit_card": "Payment card",
        "ssn": "SSN",
    }
    rows = []
    for p in items:
        sources = ", ".join(str(x) for x in p.get("sources", [p.get("source", "unknown")]))
        kind = str(p.get("kind", ""))
        label = kind_label.get(kind, kind)
        rows.append(
            f'<tr><td>{_sev_badge(p.get("severity", ""))}</td>'
            f'<td>{_esc(label)}</td>'
            f'<td><code>{_esc(str(p.get("match", "")))}</code></td>'
            f'<td>{_esc(str(p.get("description", "")))}</td>'
            f'<td class="muted">{_esc(sources)}</td></tr>'
        )
    return (
        f'<h2>Potential PII ({len(items)})</h2>'
        '<table><thead><tr><th>Severity</th><th>Type</th><th>Value</th><th>Description</th><th>Sources</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def render_internal_hosts(hosts):
    """Render internal/private host findings section (escaped)."""
    if not hosts:
        return ""
    kind_badge = {
        "internal_url": '<span class="badge badge-high">internal URL</span>',
        "internal_name": '<span class="badge badge-high">internal name</span>',
        "private_ip": '<span class="badge badge-restricted">private IP</span>',
        "internal_subdomain": '<span class="badge badge-restricted">internal subdomain</span>',
    }
    rows = []
    for h in hosts:
        kind = str(h.get("kind", ""))
        badge = kind_badge.get(kind, f'<span class="muted">{_esc(kind)}</span>')
        rows.append(
            f'<tr><td>{badge}</td>'
            f'<td><code>{_esc(str(h.get("match", "")))}</code></td>'
            f'<td class="muted">{_esc(str(h.get("source", "unknown")))}</td></tr>'
        )
    return (
        f'<h2>Internal / Private Hosts ({len(hosts)})</h2>'
        '<table><thead><tr><th>Kind</th><th>Match</th><th>Source</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def render_waf(waf):
    """Render WAF detection section (Step 5)."""
    if not waf:
        return ""
    detected = waf.get("detected", False)
    name = waf.get("waf_name") or "None detected"
    confidence = waf.get("confidence", "")
    adjustments = waf.get("adjustments") or {}
    recommendation = adjustments.get("recommendation", "")
    matched = waf.get("headers_matched") or []
    error = waf.get("error")

    badge = (
        '<span class="badge badge-high">DETECTED</span>'
        if detected else
        '<span class="badge badge-live">Not detected</span>'
    )
    parts = [f"<h2>WAF Detection</h2><p>{badge} <code>{_esc(str(name))}</code>"]
    if confidence:
        parts.append(f' <span class="muted">(confidence: {_esc(str(confidence))})</span>')
    parts.append("</p>")
    if recommendation:
        parts.append(
            f'<p class="muted">Scan adjustment: {_esc(str(recommendation))}</p>'
        )
    if error:
        parts.append(f'<p class="muted">Detection error: {_esc(str(error))}</p>')
    if matched:
        rows = "".join(
            f'<tr><td><code>{_esc(str(m.get("header", "")))}</code></td>'
            f'<td><code>{_esc(str(m.get("value", "")))}</code></td>'
            f'<td class="muted">{_esc(str(m.get("waf", "")))}</td></tr>'
            for m in matched
        )
        parts.append(
            '<table><thead><tr><th>Header</th><th>Value</th><th>Matched</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )
    return "".join(parts)


def render_wayback(wayback_js_files):
    """Render Wayback Machine historical JS list (Step 5)."""
    if not wayback_js_files:
        return ""
    return (
        "<h2>Wayback Machine Historical JS</h2>"
        + render_list(wayback_js_files, "No historical JS files")
    )


def render_intercepted(endpoints):
    """Render browser-intercepted API endpoints (Step 5) with enrichment tags."""
    if not endpoints:
        return ""
    rows = []
    for ep in endpoints:
        method = str(ep.get("method", "GET"))
        url = str(ep.get("url", ""))
        tags = ep.get("tags") or []
        tag_html = (
            " ".join(f'<span class="muted">{_esc(t)}</span>' for t in tags)
            if tags else '<span class="muted">—</span>'
        )
        rows.append(
            f'<tr><td><code>{_esc(method)}</code></td>'
            f'<td><code>{_esc(url)}</code></td>'
            f"<td>{tag_html}</td></tr>"
        )
    if not rows:
        return ""
    return (
        f"<h2>Intercepted API Endpoints ({len(rows)})</h2>"
        '<table><thead><tr><th>Method</th><th>URL</th><th>Tags</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _cors_sev_badge(sev):
    return _sev_badge(sev) if sev else '<span class="muted">—</span>'


def _cors_short_label(url, target_origin=""):
    """Short column label for matrix (path if same host as target)."""
    if target_origin and url.startswith(target_origin):
        path = url[len(target_origin):] or "/"
        path = path if len(path) <= 24 else path[:21] + "…"
        return _esc(path)
    # fallback: last two path segments
    parts = url.rstrip("/").split("/")
    tail = "/".join(parts[-2:]) if len(parts) >= 2 else url
    tail = tail if len(tail) <= 24 else "…" + tail[-23:]
    return _esc(tail)


def render_cors_matrix(cors):
    """
    Origin × URL severity matrix.

    Rows = origins that triggered at least one flag.
    Columns = flagged URLs (short path labels).
    Cells = worst severity for that (origin, URL) pair.
    """
    if not cors or not cors.get("findings"):
        return ""

    findings = [
        f for f in cors.get("findings", [])
        if f.get("severity") not in ("INFO", "ERROR") or f.get("acao")
    ]
    findings = [f for f in findings if f.get("severity") != "INFO"]
    if not findings:
        return ""

    target_origin = cors.get("target_origin") or ""
    urls = []
    for f in findings:
        u = f.get("url") or ""
        if u and u not in urls:
            urls.append(u)
    urls = urls[:20]  # keep matrix readable

    # origin -> url -> worst severity
    cell = {}
    origins = []
    for f in findings:
        flagged = f.get("origins_flagged") or (
            [f.get("origin")] if f.get("origin") else []
        )
        url = f.get("url") or ""
        if url not in urls:
            continue
        sev = f.get("severity") or "INFO"
        for o in flagged:
            if not o:
                continue
            if o not in origins:
                origins.append(o)
            key = (o, url)
            prev = cell.get(key)
            if prev is None or CORS_SEV_ORDER.get(sev, 9) < CORS_SEV_ORDER.get(prev, 9):
                cell[key] = sev

    if not origins:
        return ""

    origins = origins[:25]
    headers = "".join(
        f"<th title=\"{_cors_short_label(u, target_origin)}\">"
        f"{_cors_short_label(u, target_origin)}</th>"
        for u in urls
    )
    rows_html = []
    for o in origins:
        tds = []
        for u in urls:
            sev = cell.get((o, u))
            tds.append(f"<td>{_cors_sev_badge(sev)}</td>" if sev else '<td class="muted">·</td>')
        rows_html.append(
            f"<tr><td><code>{_esc(str(o))}</code></td>{''.join(tds)}</tr>"
        )

    return (
        f'<h3 style="margin:1rem 0 0.35rem;color:#8b949e;font-size:0.95rem;">'
        f'Origin × URL matrix ({len(origins)} origins × {len(urls)} URLs)</h3>'
        '<div style="overflow-x:auto;">'
        '<table><thead><tr><th>Origin</th>' + headers + "</tr></thead>"
        f"<tbody>{''.join(rows_html)}</tbody></table></div>"
    )


def render_cors_summary(cors):
    """Compact severity / coverage summary for the CORS section."""
    if not cors:
        return ""
    summary = cors.get("summary") or {}
    counts = summary.get("severity_counts") or cors.get("severity_counts") or {}
    urls = summary.get("urls_flagged", len(cors.get("findings") or []))
    tested = summary.get("endpoints_tested", cors.get("endpoints_tested", 0))
    origins_n = summary.get("origins_probed", len(cors.get("origins") or []))
    hits = summary.get("probe_hits", cors.get("probe_hits", 0))
    if not counts and not urls:
        return ""

    def _stat(n, label, color="#58a6ff"):
        style = f"color:{color}" if n else "color:#484f58"
        return (
            f'<div class="stat"><div class="num" style="{style}">{n}</div>'
            f'<div class="label">{label}</div></div>'
        )

    return (
        "<div class=\"stats\">"
        + _stat(counts.get("CRITICAL", 0), "Critical", "#e74c3c")
        + _stat(counts.get("HIGH", 0), "High", "#e74c3c")
        + _stat(counts.get("MEDIUM", 0), "Medium", "#f39c12")
        + _stat(counts.get("LOW", 0), "Low", "#27ae60")
        + _stat(urls, "URLs flagged")
        + _stat(tested, "Endpoints tested")
        + _stat(origins_n, "Origins probed")
        + _stat(hits, "Probe hits")
        + "</div>"
    )


def render_cors(cors):
    """Render CORS misconfiguration findings: summary, matrix, then table."""
    if not cors or not cors.get("findings"):
        return ""

    rows = []
    for f in cors.get("findings", []):
        if f.get("severity") in ("INFO", "ERROR") and not f.get("acao"):
            continue
        if f.get("severity") == "INFO":
            continue
        evidence = str(f.get("evidence") or "")
        flagged = f.get("origins_flagged") or ([f.get("origin", "")] if f.get("origin") else [])
        origin_cell = ", ".join(str(o) for o in flagged if o) or "—"
        methods = f.get("methods") or ([f.get("method", "")] if f.get("method") else [])
        method_cell = ", ".join(str(m) for m in methods if m) or "—"
        hits = f.get("probe_hits") or 1
        final_url = str(f.get("final_url") or "")
        final_cell = (
            f'<br><span class="muted" style="font-size:0.75rem;">→ {_esc(final_url)}</span>'
            if final_url and f.get("redirected")
            else ""
        )
        rows.append(
            f'<tr><td>{_sev_badge(f.get("severity", ""))}</td>'
            f'<td><code>{_esc(str(f.get("url", "")))}</code>{final_cell}</td>'
            f'<td><code>{_esc(origin_cell)}</code></td>'
            f'<td><code>{_esc(str(f.get("acao", "")))}</code></td>'
            f'<td>{_esc(str(f.get("acac") or "—"))}</td>'
            f'<td>{_esc(method_cell)}</td>'
            f'<td>{hits}</td>'
            f'<td class="muted">{_esc(str(f.get("detail", "")))}</td>'
            f'<td class="muted">{_esc(evidence) if evidence else "—"}</td></tr>'
        )
    if not rows:
        return ""

    tested = cors.get("endpoints_tested", 0)
    probe_hits = cors.get("probe_hits", len(cors.get("findings") or []))
    target_origin = str(cors.get("target_origin") or "")
    schema = cors.get("schema_version", "")

    matrix = render_cors_matrix(cors)
    summary = render_cors_summary(cors)
    meta = (
        f'<p class="muted" style="font-size:0.8rem;margin-top:0.35rem;">'
        f'Target origin: <code>{_esc(target_origin)}</code> · '
        f'{len(rows)} URL(s) / {tested} tested'
        + (f' · {probe_hits} probe hits' if probe_hits != len(rows) else "")
        + (f' · JSON schema v{schema}' if schema else "")
        + "</p>"
    )

    table = (
        '<table><thead><tr><th>Severity</th><th>URL</th><th>Origins flagged</th>'
        '<th>ACAO</th><th>ACAC</th><th>Methods</th><th>Hits</th><th>Detail</th>'
        '<th>Evidence</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )
    try:
        from modules.reporting.cors_poc import render_cors_pocs_inline
        pocs = render_cors_pocs_inline(cors)
    except Exception:
        pocs = ""
    return (
        f"<h2>CORS Misconfigurations</h2>"
        f"{summary}{meta}{matrix}"
        f'<h3 style="margin:1rem 0 0.35rem;color:#8b949e;font-size:0.95rem;">'
        f"Findings (one row per URL)</h3>{table}"
        f"{pocs}"
    )


def render_jwt_summary(jwt_result):
    """Severity / coverage stat cards for the JWT section (CORS parity)."""
    if not jwt_result:
        return ""
    summary = jwt_result.get("summary") or {}
    counts = summary.get("severity_counts") or jwt_result.get("severity_counts") or {}
    tokens = summary.get("tokens_analyzed", jwt_result.get("tokens_analyzed", 0))
    cracked = summary.get("cracked_secrets", 0)
    candidates = summary.get(
        "candidate_secrets_tried",
        jwt_result.get("candidate_secrets_tried", 0),
    )
    if not counts and not tokens:
        return ""

    def _stat(n, label, color="#58a6ff"):
        style = f"color:{color}" if n else "color:#484f58"
        return (
            f'<div class="stat"><div class="num" style="{style}">{n}</div>'
            f'<div class="label">{label}</div></div>'
        )

    return (
        "<div class=\"stats\">"
        + _stat(counts.get("CRITICAL", 0), "Critical", "#e74c3c")
        + _stat(counts.get("HIGH", 0), "High", "#e74c3c")
        + _stat(counts.get("MEDIUM", 0), "Medium", "#f39c12")
        + _stat(counts.get("LOW", 0), "Low", "#27ae60")
        + _stat(tokens, "Tokens analyzed")
        + _stat(cracked, "Secrets cracked", "#e74c3c" if cracked else "#484f58")
        + _stat(candidates, "Crack candidates")
        + "</div>"
    )


def render_jwt(jwt_result):
    """Render JWT security analysis section (summary cards + findings table)."""
    if not jwt_result or not jwt_result.get("findings"):
        return ""
    rows = []
    for a in jwt_result.get("findings", []):
        issues = a.get("findings", [])
        if not issues:
            continue
        issue_html = "<br>".join(
            f'{_sev_badge(f.get("severity", ""))} '
            f'<code>{_esc(str(f.get("issue", "")))}</code> {_esc(str(f.get("detail", "")))}'
            for f in issues
        )
        claims_raw = ", ".join(
            f"{k}={v}" for k, v in (a.get("payload_summary") or {}).items()
        )
        claims = _esc(claims_raw[:200])
        cracked = (
            f'<br><span class="badge badge-critical">secret: {_esc(str(a.get("cracked_secret", "")))}</span>'
            if a.get("cracked_secret") else ""
        )
        rows.append(
            f'<tr><td>{_sev_badge(a.get("severity", ""))}</td>'
            f'<td><code>{_esc(str(a.get("alg") or "?"))}</code></td>'
            f'<td>{issue_html}{cracked}</td>'
            f'<td class="muted">{claims}</td>'
            f'<td class="muted">{_esc(str(a.get("source", "")))}</td></tr>'
        )
    if not rows:
        return ""
    n = jwt_result.get("tokens_analyzed", len(rows))
    schema = jwt_result.get("schema_version", "")
    summary = render_jwt_summary(jwt_result)
    meta = (
        f'<p class="muted" style="font-size:0.8rem;margin-top:0.35rem;">'
        f'{n} token(s) analyzed'
        + (f' · JSON schema v{schema}' if schema else "")
        + "</p>"
    )
    table = (
        '<table><thead><tr><th>Severity</th><th>Alg</th><th>Findings</th>'
        '<th>Claims</th><th>Source</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )
    return (
        f'<h2>JWT Analysis ({n} token(s))</h2>'
        f'{summary}{meta}{table}'
    )


def build_html(result):
    """Build the full HTML report from scan results."""
    risk = result.get("risk_summary", {})
    risk_level = str(risk.get("level", "") or "")
    risk_color = {
        "HIGH": "#e74c3c",
        "MEDIUM": "#f39c12",
        "LOW": "#27ae60",
        "INFO": "#3498db"
    }.get(risk_level, "#999")

    target = _esc(str(result.get("target", "unknown")))
    scan_mode = _esc(str(result.get("scan_mode", result.get("meta", {}).get("scan_mode", "static"))))
    scan_depth = result.get("scan_depth", 0)
    risk_level_esc = _esc(risk_level) if risk_level else "N/A"
    risk_score = risk.get("score", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SurfaceSweep Report — {target}</title>
<style>{CSS}
.risk {{ background: {risk_color}; }}
</style>
</head>
<body>
<h1>SurfaceSweep — Attack Surface Report</h1>
<p class="target">Target: {target} | Mode: {scan_mode} | Scan depth: {scan_depth} | Risk: <span class="risk">{risk_level_esc}</span> (score: {risk_score})</p>

<div class="stats">
  <div class="stat"><div class="num">{len(result.get('js_files_scanned', []))}</div><div class="label">JS Files Scanned</div></div>
  <div class="stat"><div class="num">{result.get('inline_scripts_scanned', 0)}</div><div class="label">Inline Scripts</div></div>
  <div class="stat"><div class="num">{len(result.get('internal_paths', []))}</div><div class="label">Internal Paths</div></div>
  <div class="stat"><div class="num">{len(result.get('secrets_found', []))}</div><div class="label">Secrets Found</div></div>
  <div class="stat"><div class="num">{len(result.get('source_maps_found', []))}</div><div class="label">Exposed Source Maps</div></div>
  <div class="stat"><div class="num">{len(result.get('library_vulnerabilities', []))}</div><div class="label">Library CVEs</div></div>
  <div class="stat"><div class="num">{len(result.get('spa_routes', []))}</div><div class="label">SPA Routes</div></div>
  <div class="stat"><div class="num">{len(result.get('sinks_found', []))}</div><div class="label">Dangerous Sinks</div></div>
  <div class="stat"><div class="num">{len(result.get('internal_hosts_found', []))}</div><div class="label">Internal Hosts</div></div>
  <div class="stat"><div class="num">{len(result.get('pii_found', []))}</div><div class="label">PII Items</div></div>
  <div class="stat"><div class="num">{len((result.get('cors') or {}).get('findings', []))}</div><div class="label">CORS Findings</div></div>
  <div class="stat"><div class="num">{(result.get('jwt') or {}).get('tokens_analyzed', 0)}</div><div class="label">JWTs Analyzed</div></div>
</div>

{render_executive_summary(result.get("executive_summary") or build_executive_summary(result, result.get("findings") or build_findings_feed(result)))}

{render_waf(result.get('waf') or {})}

<h2>Internal Paths</h2>
{render_list(result.get('internal_paths', []), 'No internal paths discovered')}

<h2>In-Scope URLs</h2>
{render_list(result.get('in_scope_urls', []), 'No in-scope URLs found')}

<h2>Out-of-Scope URLs (informational)</h2>
{render_list(result.get('out_of_scope_urls', []), 'None')}

{render_wayback(result.get('wayback_js_files') or [])}

{render_intercepted(result.get('intercepted_endpoints') or [])}

<h2>Secrets / Leaked Keys</h2>
{render_secrets(result.get('secrets_found', []))}

{render_sinks(result.get('sinks_found', []))}

{render_pii(result.get('pii_found', []))}

{render_internal_hosts(result.get('internal_hosts_found', []))}

{render_cors(result.get('cors', {}))}

{render_jwt(result.get('jwt'))}

<h2>Exposed Source Maps</h2>
{render_list(result.get('source_maps_found', []), 'None found')}

<h2>JS Files Scanned</h2>
{render_list(result.get('js_files_scanned', []))}

{render_libraries(result.get('libraries', []), result.get('library_vulnerabilities', []), result.get('osv_results'))}

{render_spa_routes(result.get('spa_routes', []), result.get('spa_routes_from'))}

{render_validation(result.get('validation', {}))}

{render_deobf(result.get('deobfuscation_findings', []))}

{render_findings_feed(result.get('findings') or build_findings_feed(result))}

{render_errors(result.get('errors', []))}

<div class="footer">Generated by SurfaceSweep</div>
</body>
</html>"""


def save_report(result, filename="reports/surfacesweep_report.json"):
    """Save scan results as JSON."""
    try:
        with open(filename, "w") as f:
            json.dump(result, f, indent=2)
        ok(f" Report saved to {filename}")
    except OSError as e:
        warn(f" Failed to save report to {filename}: {e}")


def save_html_report(result, filename="reports/surfacesweep_report.html"):
    """Generate and save HTML report."""
    html = build_html(result)
    try:
        with open(filename, "w") as f:
            f.write(html)
        ok(f" HTML report saved to {filename}")
    except OSError as e:
        warn(f" Failed to save HTML report to {filename}: {e}")
