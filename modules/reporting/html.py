"""
HTML report generation for SurfaceSweep.

Keeps HTML/CSS templates separate from extraction logic.
"""

import json


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
.badge-high { background: #e74c3c22; color: #e74c3c; border: 1px solid #e74c3c44; }
.badge-live { background: #27ae6022; color: #27ae60; border: 1px solid #27ae6044; }
.badge-restricted { background: #f39c1222; color: #f39c12; border: 1px solid #f39c1244; }
.badge-dead { background: #e74c3c22; color: #e74c3c; border: 1px solid #e74c3c44; }
.badge-error { background: #95a5a622; color: #95a5a6; border: 1px solid #95a5a644; }
.muted { color: #8b949e; }
.errors { background: #e74c3c11; border: 1px solid #e74c3c33; border-radius: 6px; padding: 1rem; margin-top: 1rem; }
.footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #21262d; color: #484f58; font-size: 0.8rem; text-align: center; }
"""


def render_list(items, empty_msg="None found"):
    """Render a list of items as HTML."""
    if not items:
        return f'<p class="muted">{empty_msg}</p>'
    return "<ul>" + "".join(f"<li><code>{item}</code></li>" for item in items) + "</ul>"


def render_secrets(secrets):
    """Render secrets table."""
    if not secrets:
        return '<p class="muted">No secrets detected</p>'
    rows = []
    for s in secrets:
        sources = ", ".join(s.get("sources", [s.get("source", "unknown")]))
        rows.append(
            f'<tr><td><span class="badge badge-high">{s["type"]}</span></td>'
            f'<td><code>{s["match"]}</code></td>'
            f'<td class="muted">{sources}</td></tr>'
        )
    return (
        '<table><thead><tr><th>Type</th><th>Match</th><th>Sources</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def render_validation(validation):
    """Render validation results section."""
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
                f'<td>{code}</td>'
                f'<td><code>{item.get("url", "")}</code></td></tr>'
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
    """Render deobfuscation findings section."""
    if not findings:
        return ""
    rows = []
    for f in findings:
        rows.append(
            f'<tr><td><span class="badge badge-live">{f.get("type", "")}</span></td>'
            f'<td><code>{f.get("decoded", "")[:120]}</code></td></tr>'
        )
    return (
        '<h2>Deobfuscation Findings</h2>'
        '<table><thead><tr><th>Type</th><th>Decoded</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def render_errors(errors):
    """Render errors section."""
    if not errors:
        return ""
    return (
        '<h2>Errors</h2><div class="errors">' +
        "".join(f"<p>{e}</p>" for e in errors) +
        "</div>"
    )


def render_libraries(libraries, vulnerabilities, osv_results=None):
    """Render detected libraries and their vulnerabilities."""
    if not libraries and not vulnerabilities:
        return ""

    parts = []

    # Libraries table
    if libraries:
        rows = []
        for lib in libraries:
            rows.append(
                f'<tr><td><code>{lib["library"]}</code></td>'
                f'<td><code>{lib["version"]}</code></td>'
                f'<td class="muted">{lib["source"]}</td>'
                f'<td class="muted">{lib.get("file", "")[:60]}</td></tr>'
            )
        parts.append(
            '<h2>Detected JavaScript Libraries</h2>'
            '<table><thead><tr><th>Library</th><th>Version</th><th>Detected From</th><th>Source File</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>'
        )

    # Vulnerabilities table
    if vulnerabilities:
        sev_badge = {
            "CRITICAL": '<span class="badge badge-high">CRITICAL</span>',
            "HIGH": '<span class="badge badge-high">HIGH</span>',
            "MEDIUM": '<span class="badge badge-restricted">MEDIUM</span>',
            "LOW": '<span class="badge badge-live">LOW</span>',
        }
        rows = []
        for v in vulnerabilities:
            cve_str = ", ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" style="color:#58a6ff">{cve}</a>' for cve in v["cves"])
            cvss = f' ({v["cvss"]})' if v.get("cvss") else ""
            rows.append(
                f'<tr><td>{sev_badge.get(v["severity"], v["severity"])}</td>'
                f'<td><code>{v["library"]} {v["version"]}</code></td>'
                f'<td>{cve_str}{cvss}</td>'
                f'<td>{v["description"]}</td>'
                f'<td><code>{v["fixed_in"]}</code></td></tr>'
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
            for vuln in data.get("vulns", []):
                vid = vuln.get("id", "")
                vid_link = f'<a href="https://osv.dev/vulnerability/{vid}" style="color:#58a6ff">{vid}</a>'
                rows.append(
                    f'<tr><td><code>{lib_name} {data["version"]}</code></td>'
                    f'<td>{vid_link}</td>'
                    f'<td>{vuln.get("summary", "")[:150]}</td></tr>'
                )
        if rows:
            parts.append(
                '<h2>OSV.dev Additional Findings</h2>'
                '<table><thead><tr><th>Library</th><th>OSV ID</th><th>Summary</th></tr></thead>'
                f'<tbody>{"".join(rows)}</tbody></table>'
            )

    return "\n".join(parts) if parts else ""


def render_spa_routes(routes, routes_from=None):
    """Render SPA routes section."""
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
        badge = source_labels.get(src, f'<span class="muted">{src}</span>')
        rows.append(
            f'<tr><td><code>{route}</code></td><td>{badge}</td></tr>'
        )
    return (
        f'<h2>SPA Routes Discovered ({len(routes)})</h2>'
        '<table><thead><tr><th>Route</th><th>Source</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def build_html(result):
    """Build the full HTML report from scan results."""
    risk = result.get("risk_summary", {})
    risk_color = {
        "HIGH": "#e74c3c",
        "MEDIUM": "#f39c12",
        "LOW": "#27ae60",
        "INFO": "#3498db"
    }.get(risk.get("level", ""), "#999")

    target = result.get("target", "unknown")

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
<p class="target">Target: {result.get('target', 'N/A')} | Scan depth: {result.get('scan_depth', 0)} | Risk: <span class="risk">{risk.get('level', 'N/A')}</span> (score: {risk.get('score', 0)})</p>

<div class="stats">
  <div class="stat"><div class="num">{len(result.get('js_files_scanned', []))}</div><div class="label">JS Files Scanned</div></div>
  <div class="stat"><div class="num">{result.get('inline_scripts_scanned', 0)}</div><div class="label">Inline Scripts</div></div>
  <div class="stat"><div class="num">{len(result.get('internal_paths', []))}</div><div class="label">Internal Paths</div></div>
  <div class="stat"><div class="num">{len(result.get('secrets_found', []))}</div><div class="label">Secrets Found</div></div>
  <div class="stat"><div class="num">{len(result.get('source_maps_found', []))}</div><div class="label">Exposed Source Maps</div></div>
  <div class="stat"><div class="num">{len(result.get('library_vulnerabilities', []))}</div><div class="label">Library CVEs</div></div>
  <div class="stat"><div class="num">{len(result.get('spa_routes', []))}</div><div class="label">SPA Routes</div></div>
</div>

<h2>Internal Paths</h2>
{render_list(result.get('internal_paths', []), 'No internal paths discovered')}

<h2>In-Scope URLs</h2>
{render_list(result.get('in_scope_urls', []), 'No in-scope URLs found')}

<h2>Out-of-Scope URLs (informational)</h2>
{render_list(result.get('out_of_scope_urls', []), 'None')}

<h2>Secrets / Leaked Keys</h2>
{render_secrets(result.get('secrets_found', []))}

<h2>Exposed Source Maps</h2>
{render_list(result.get('source_maps_found', []), 'None found')}

<h2>JS Files Scanned</h2>
{render_list(result.get('js_files_scanned', []))}

{render_libraries(result.get('libraries', []), result.get('library_vulnerabilities', []), result.get('osv_results'))}

{render_spa_routes(result.get('spa_routes', []), result.get('spa_routes_from'))}

{render_validation(result.get('validation', {}))}

{render_deobf(result.get('deobfuscation_findings', []))}

{render_errors(result.get('errors', []))}

<div class="footer">Generated by SurfaceSweep</div>
</body>
</html>"""


def save_report(result, filename="reports/surfacesweep_report.json"):
    """Save scan results as JSON."""
    try:
        with open(filename, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[+] Report saved to {filename}")
    except OSError as e:
        print(f"[!] Failed to save report to {filename}: {e}")


def save_html_report(result, filename="reports/surfacesweep_report.html"):
    """Generate and save HTML report."""
    html = build_html(result)
    try:
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] HTML report saved to {filename}")
    except OSError as e:
        print(f"[!] Failed to save HTML report to {filename}: {e}")
