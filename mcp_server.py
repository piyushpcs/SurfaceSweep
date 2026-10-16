"""
SurfaceSweep MCP server.

Exposes the scanner to MCP-capable agents (Claude Desktop, Cursor, etc.) over
stdio using the Model Context Protocol (JSON-RPC 2.0, newline-delimited).

Intentionally dependency-free: no `mcp` SDK is required, so agents can connect
with just the project's existing requirements.

Run:
    python mcp_server.py
or, after an editable install:
    surfacesweep-mcp

Tools:
    scan_url     — run a static (or headless-browser) recon scan, return a summary
    check_scope  — test whether a URL is within a scope (respect authorization)

NOTE: stdout carries the JSON-RPC stream. All diagnostic output is forced to
stderr so the protocol stream stays clean.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from typing import Any, Callable, Dict, List, Optional

SERVER_NAME = "surfacesweep"
SERVER_VERSION = "1.0.0"
DEFAULT_PROTOCOL = "2024-11-05"
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18")

_MAX_LIMIT = 200


# --------------------------------------------------------------------------- #
# Tool schemas
# --------------------------------------------------------------------------- #

_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "scan_url",
        "description": (
            "Scan a web target's JavaScript for endpoints, secrets, dangerous "
            "sinks, and internal-host references. Passive/static by default; "
            "set browser=true to also render the page headlessly. Only scan "
            "targets you are authorized to test."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Absolute http(s) URL to scan.",
                },
                "scope": {
                    "type": "string",
                    "description": "Scope domain (e.g. 'app.example.com'). Defaults to the target's registrable domain.",
                },
                "depth": {
                    "type": "integer",
                    "description": "Recursive JS depth (0 = HTML only).",
                    "minimum": 0,
                    "maximum": 3,
                },
                "browser": {
                    "type": "boolean",
                    "description": "Use the headless browser for runtime API capture (requires Playwright Chromium).",
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header for authenticated scans (sent only to in-scope hosts).",
                },
                "headers": {
                    "type": "object",
                    "description": "Additional request headers for authenticated scans.",
                    "additionalProperties": {"type": "string"},
                },
                "deobfuscate": {
                    "type": "boolean",
                    "description": "Decode obfuscated strings (default true).",
                },
                "reveal_secrets": {
                    "type": "boolean",
                    "description": "Return full secret matches instead of redacted values (default false).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max items per list in the summary (default 25).",
                    "minimum": 1,
                    "maximum": _MAX_LIMIT,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "check_scope",
        "description": (
            "Return whether a URL falls within a given scope domain. Use this "
            "to confirm authorization boundaries before scanning."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to test."},
                "scope": {"type": "string", "description": "Scope domain (e.g. 'example.com')."},
            },
            "required": ["url", "scope"],
        },
    },
]


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #

def _redact(match: Any, reveal: bool) -> str:
    text = str(match or "")
    if reveal or len(text) <= 4:
        return text
    return text[:4] + "…"


def _validate_target(target: str) -> None:
    from urllib.parse import urlparse

    from modules.extraction.http import is_blocked_fetch_target

    parsed = urlparse(target or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be an absolute http(s) URL")
    if is_blocked_fetch_target(target):
        raise ValueError("target resolves to a blocked link-local/metadata address")


def _build_auth(arguments: Dict[str, Any]) -> Dict[str, str]:
    auth: Dict[str, str] = {}
    for key, value in (arguments.get("headers") or {}).items():
        auth[str(key)] = str(value)
    cookie = arguments.get("cookie")
    if cookie:
        auth["Cookie"] = str(cookie)
    return auth


def _scan_url(arguments: Dict[str, Any]) -> str:
    target = arguments.get("target")
    if not target:
        raise ValueError("'target' is required")
    _validate_target(target)

    scope = arguments.get("scope") or None
    depth = int(arguments.get("depth", 1))
    browser = bool(arguments.get("browser", False))
    deobfuscate = bool(arguments.get("deobfuscate", True))
    reveal = bool(arguments.get("reveal_secrets", False))
    limit = max(1, min(_MAX_LIMIT, int(arguments.get("limit", 25))))

    from modules.common.console import configure_console
    from modules.extraction.http import configure_auth
    from modules.extraction.scope import get_registrable_domain, normalize_scope_filter

    configure_console(quiet=True)
    auth = _build_auth(arguments)
    auth_scope = normalize_scope_filter(scope) or get_registrable_domain(target)
    configure_auth(auth, auth_scope)

    # Keep stdout pristine: any stray progress output is routed to stderr.
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        if browser:
            from modules.extraction.browser import run_browser_scan
            result = run_browser_scan(
                target, verbose=False, scope_filter=scope,
                deobfuscate_content=deobfuscate, headers=auth or None,
            )
        else:
            from modules.extraction.engine import run_extractor
            result = run_extractor(
                target, verbose=False, max_depth=depth,
                deobfuscate=deobfuscate, scope_filter=scope,
            )

    risk = result.get("risk_summary") or {}
    secrets = result.get("secrets_found") or []
    sinks = result.get("sinks_found") or []
    summary = {
        "target": target,
        "scan_mode": result.get("scan_mode"),
        "risk": risk.get("level"),
        "risk_score": risk.get("score"),
        "counts": {
            "js_files": len(result.get("js_files_scanned") or []),
            "internal_paths": len(result.get("internal_paths") or []),
            "in_scope_urls": len(result.get("in_scope_urls") or []),
            "secrets": len(secrets),
            "jwts": len(result.get("jwts_found") or []),
            "sinks": len(sinks),
            "internal_hosts": len(result.get("internal_hosts_found") or []),
        },
        "endpoints": (result.get("internal_paths") or [])[:limit],
        "in_scope_urls": (result.get("in_scope_urls") or [])[:limit],
        "secrets": [
            {
                "type": s.get("type"),
                "source": s.get("source"),
                "match": _redact(s.get("match"), reveal),
            }
            for s in secrets[:limit]
        ],
        "sinks": [
            {"sink": s.get("sink"), "severity": s.get("severity")}
            for s in sinks[:limit]
        ],
        "errors": (result.get("errors") or [])[:10],
    }
    return json.dumps(summary, indent=2, default=str)


def _check_scope(arguments: Dict[str, Any]) -> str:
    url = arguments.get("url")
    scope = arguments.get("scope")
    if not url or not scope:
        raise ValueError("'url' and 'scope' are required")

    from modules.extraction.scope import (
        get_registrable_domain,
        is_same_scope,
        normalize_scope_filter,
    )

    effective = normalize_scope_filter(scope) or scope
    return json.dumps(
        {
            "url": url,
            "scope": effective,
            "in_scope": is_same_scope(url, effective),
            "url_domain": get_registrable_domain(url),
        },
        indent=2,
    )


_TOOL_HANDLERS: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "scan_url": _scan_url,
    "check_scope": _check_scope,
}


# --------------------------------------------------------------------------- #
# JSON-RPC / MCP protocol
# --------------------------------------------------------------------------- #

def _result(msg_id, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _negotiate_protocol(requested: Optional[str]) -> str:
    if requested in SUPPORTED_PROTOCOLS:
        return requested
    return DEFAULT_PROTOCOL


def handle_message(message: Any) -> Optional[Dict[str, Any]]:
    """
    Handle one decoded JSON-RPC message.

    Returns the response dict, or None for notifications / responses.
    Pure function — no I/O — so it is unit-testable.
    """
    if not isinstance(message, dict):
        return _error(None, -32600, "Invalid Request")

    method = message.get("method")
    msg_id = message.get("id")
    if method is None:
        # A response to a request we never sent — ignore.
        return None

    if method == "initialize":
        params = message.get("params") or {}
        return _result(msg_id, {
            "protocolVersion": _negotiate_protocol(params.get("protocolVersion")),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })

    if method in ("notifications/initialized", "initialized"):
        return None  # notification — no response

    if method == "ping":
        return _result(msg_id, {})

    if method == "tools/list":
        return _result(msg_id, {"tools": _TOOLS})

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        handler = _TOOL_HANDLERS.get(name)
        if handler is None:
            return _error(msg_id, -32602, f"Unknown tool: {name}")
        try:
            text = handler(arguments)
        except Exception as exc:  # tool errors are reported in-band, not as RPC errors
            return _result(msg_id, {
                "content": [{"type": "text", "text": f"Error: {exc}"}],
                "isError": True,
            })
        return _result(msg_id, {
            "content": [{"type": "text", "text": text}],
            "isError": False,
        })

    return _error(msg_id, -32601, f"Method not found: {method}")


def serve(stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "Parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_message(message)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


def main() -> int:
    from modules.common.console import configure_console

    configure_console(quiet=True)  # never pollute the stdout protocol stream
    try:
        serve()
    except (BrokenPipeError, KeyboardInterrupt):
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
