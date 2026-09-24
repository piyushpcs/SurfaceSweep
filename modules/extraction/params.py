"""
Request parameter extraction from JS/HTML blobs (Phase F1).

Pulls query-string keys, URLSearchParams usage, axios/fetch `params: {}`
objects, FormData.append fields, searchParams.get/set access, and path
template placeholders (`:id`, `${id}`, `{id}`) so findings are more than
bare paths — matching xnLinkFinder/jsluice-style parameter discovery.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlparse

__all__ = [
    "extract_params",
    "deduplicate_params",
    "PARAM_KINDS",
]

PARAM_KINDS = (
    "query_string",
    "url_search_params",
    "request_params",
    "form_field",
    "search_params_access",
    "path_template",
)

# Query-string pairs in any absolute URL or path with ?…#…
_QUERY_PAIR = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]{0,64})=")

# new URLSearchParams({ a: "1", b: 2 }) / URLSearchParams({…})
_URLSP_OBJECT = re.compile(
    r"URLSearchParams\s*\(\s*\{([^}]{0,800})\}", re.IGNORECASE
)

# URLSearchParams("a=1&b=2")
_URLSP_STRING = re.compile(
    r"""URLSearchParams\s*\(\s*['"]([^'"]{1,400})['"]""", re.IGNORECASE
)

# axios / fetch config: { params: { id: 1, page: "2" } }
_REQUEST_PARAMS = re.compile(
    r"""\bparams\s*:\s*\{([^}]{0,800})\}""", re.IGNORECASE
)

# formData.append("name", …) / fd.append('file', …)
_FORM_APPEND = re.compile(
    r"""\.append\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_\-]{0,64})['"]""",
    re.IGNORECASE,
)

# searchParams.get("id") / .set / .has / .delete / .append
_SEARCH_ACCESS = re.compile(
    r"""searchParams\.(?:get|set|has|delete|append|getAll)\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_\-]{0,64})['"]""",
    re.IGNORECASE,
)

# Object keys inside a params/body-looking object literal (shallow)
_OBJ_KEY = re.compile(r"""(?:^|[{,])\s*([A-Za-z_][A-Za-z0-9_]{0,64})\s*:""")

# Path templates: "/users/:id", "/api/${userId}", "/items/{itemId}"
_PATH_TEMPLATE = re.compile(
    r"""['"`](/[a-zA-Z0-9_\-./]*(?::[A-Za-z_][\w]*|\$\{[^}]+\}|\{[A-Za-z_][\w]*\})[a-zA-Z0-9_\-./:]*)['"`]"""
)

_PLACEHOLDER_PARAM_RE = re.compile(
    r""":([A-Za-z_][\w]*)|\$\{([A-Za-z_][\w]*)\}|\{([A-Za-z_][\w]*)\}"""
)

_NOISE_PARAM_NAMES = frozenset({
    "true", "false", "null", "undefined", "this", "self", "window",
    "function", "return", "typeof", "constructor", "prototype",
    "length", "value", "key", "index", "type", "name", "data",
    "target", "source", "event", "error", "message", "status",
})

_MIN_NAME = 2
_MAX_NAME = 64


def _clean_name(name: str, min_len: int = _MIN_NAME) -> str | None:
    """Normalize a candidate parameter name; None when unusable."""
    if not name:
        return None
    name = name.strip().strip("'\"")
    if len(name) < min_len or len(name) > _MAX_NAME:
        return None
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\-]{0,63}", name):
        return None
    if name.lower() in _NOISE_PARAM_NAMES:
        return None
    return name


def _keys_from_object_body(body: str) -> List[str]:
    """Shallow `key:` pairs inside a JS object-literal fragment."""
    found: List[str] = []
    for m in _OBJ_KEY.finditer(body):
        name = _clean_name(m.group(1))
        if name:
            found.append(name)
    return found


def extract_params(content: str, source_label: str) -> List[Dict[str, Any]]:
    """
    Extract parameter names from a JS/HTML blob.

    Returns a list of {name, kind, source} suitable for dedup + report.
    """
    if not content:
        return []

    findings: List[Dict[str, Any]] = []
    seen: set = set()

    def _add(name: str | None, kind: str, min_len: int = _MIN_NAME) -> None:
        name = _clean_name(name, min_len=min_len) if name else None
        if not name:
            return
        key = (name, kind)
        if key in seen:
            return
        seen.add(key)
        findings.append({"name": name, "kind": kind, "source": source_label})

    # --- Query strings on absolute URLs and bare paths ---
    # Single-letter keys (q, s, p) are legitimate query params
    for m in _QUERY_PAIR.finditer(content):
        _add(m.group(1), "query_string", min_len=1)

    # Also parse full URL/query blocks more carefully when they appear
    for m in re.finditer(
        r"""['"](https?://[^'"\s]+|/[a-zA-Z0-9_\-./%?=&]{3,300})['"]""",
        content,
    ):
        raw = m.group(1)
        try:
            query = urlparse(raw).query if "?" in raw else (
                raw.split("?", 1)[1] if raw.startswith("/") and "?" in raw else ""
            )
            if not query and "?" in raw:
                query = raw.split("?", 1)[1]
            if query:
                for key, _ in parse_qsl(query, keep_blank_values=True):
                    _add(key, "query_string", min_len=1)
        except ValueError:
            pass

    # --- URLSearchParams ---
    for body in _URLSP_OBJECT.findall(content):
        for name in _keys_from_object_body(body):
            _add(name, "url_search_params")
    for qs in _URLSP_STRING.findall(content):
        for key, _ in parse_qsl(qs, keep_blank_values=True):
            _add(key, "url_search_params", min_len=1)

    # --- axios/fetch { params: { … } } ---
    for body in _REQUEST_PARAMS.findall(content):
        for name in _keys_from_object_body(body):
            _add(name, "request_params")

    # --- FormData.append ---
    for m in _FORM_APPEND.finditer(content):
        _add(m.group(1), "form_field")

    # --- searchParams.get/set/… ---
    for m in _SEARCH_ACCESS.finditer(content):
        _add(m.group(1), "search_params_access")

    # --- Path templates: :id / ${id} / {id} ---
    for m in _PATH_TEMPLATE.finditer(content):
        path = m.group(1)
        for pm in _PLACEHOLDER_PARAM_RE.finditer(path):
            name = pm.group(1) or pm.group(2) or pm.group(3)
            _add(name, "path_template")

    return findings


def deduplicate_params(params: List[Dict[str, Any]] | None) -> List[Dict[str, Any]]:
    """
    Merge duplicate {name, kind} pairs, collecting source labels.

    Output entries: {name, kind, source, sources}
    """
    if not params:
        return []
    order: List[tuple] = []
    buckets: Dict[tuple, Dict[str, Any]] = {}
    for p in params or []:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        kind = p.get("kind") or "query_string"
        if not name:
            continue
        key = (name, kind)
        if key not in buckets:
            buckets[key] = {
                "name": name,
                "kind": kind,
                "source": p.get("source", ""),
                "sources": [],
            }
            order.append(key)
        sources = buckets[key]["sources"]
        src = p.get("source", "")
        if src and src not in sources:
            sources.append(src)
    out = []
    for key in order:
        entry = buckets[key]
        if not entry["sources"]:
            entry["sources"] = [entry["source"]] if entry["source"] else []
        out.append(entry)
    return out
