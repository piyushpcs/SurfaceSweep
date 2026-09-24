"""
Source map discovery and reconstruction.

Parses //# sourceMappingURL= comments (including inline data: URIs), fetches
external maps, and yields original sources from sourcesContent for re-scanning.
"""

import base64
import json
import re
from urllib.parse import unquote, urljoin

import requests

from modules.extraction.http import fetch_with_retry

# Safety caps for hostile / huge maps on real targets.
MAX_SOURCEMAP_BYTES = 5_000_000
MAX_SOURCEMAP_SOURCES = 50
MAX_SOURCEMAP_SOURCE_BYTES = 500_000

_SOURCEMAP_COMMENT_RE = re.compile(
    r'(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*'
    r'(?:"([^"]+)"|\'([^\']+)\'|([^\s*]+))',
    re.IGNORECASE,
)


def parse_source_mapping_url(js_content):
    """
    Return the last sourceMappingURL target in JS content, or None.
    Spec: the last mapping comment in the file wins. Supports // and /* */ forms.
    """
    if not js_content:
        return None
    matches = []
    for m in _SOURCEMAP_COMMENT_RE.finditer(js_content):
        target = m.group(1) or m.group(2) or m.group(3)
        if target:
            matches.append(target.strip())
    if not matches:
        return None
    return matches[-1]


def resolve_source_map_url(mapping_url, js_url):
    """Resolve a mapping URL against the JS file URL. data: URIs pass through."""
    if not mapping_url:
        return None
    if mapping_url.startswith("data:"):
        return mapping_url
    return urljoin(js_url, mapping_url)


def decode_inline_sourcemap(data_url):
    """Decode data:application/json[;base64],payload into a dict (or None)."""
    if not data_url or not data_url.startswith("data:") or "," not in data_url:
        return None
    header, payload = data_url.split(",", 1)
    try:
        if ";base64" in header.lower():
            raw = base64.b64decode(payload, validate=False)
        else:
            raw = unquote(payload).encode("utf-8")
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def _parse_map_body(resp):
    """Validate HTTP response as a source map JSON object."""
    if resp is None or resp.status_code != 200:
        return None
    content = resp.content or b""
    if len(content) > MAX_SOURCEMAP_BYTES:
        return None
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        content_type = resp.headers.get("Content-Type", "")
        if "json" not in content_type.lower():
            return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _fetch_map_json(map_url, timeout=8, limiter=None):
    try:
        resp = fetch_with_retry(map_url, timeout=timeout, limiter=limiter)
    except requests.RequestException:
        return None
    return _parse_map_body(resp)


def load_source_map(js_url, js_content=None, timeout=8, limiter=None):
    """
    Resolve and load the source map for a JS file.

    Tries sourceMappingURL comment first, then the conventional js_url + ".map".
    Returns (map_dict, report_url) or (None, None).
    """
    refs = []
    mapping = parse_source_mapping_url(js_content)
    if mapping:
        refs.append(resolve_source_map_url(mapping, js_url))
    conventional = js_url + ".map"
    if conventional not in refs:
        refs.append(conventional)

    for ref in refs:
        if not ref:
            continue
        if ref.startswith("data:"):
            obj = decode_inline_sourcemap(ref)
            if obj is not None:
                return obj, f"{js_url}#inline-sourcemap"
            continue
        obj = _fetch_map_json(ref, timeout=timeout, limiter=limiter)
        if obj is not None:
            return obj, ref
    return None, None


def collect_source_map_sources(map_obj, js_url):
    """
    Return [(source_label, content), …] from sourcesContent (capped).
    Labels look like "{js_url}!{original/source.ts}" for report provenance.
    """
    if not isinstance(map_obj, dict):
        return []
    sources = map_obj.get("sources") or []
    contents = map_obj.get("sourcesContent") or []
    if not isinstance(contents, list):
        return []

    collected = []
    for i, content in enumerate(contents):
        if content is None:
            continue
        if not isinstance(content, str):
            content = str(content)
        if not content:
            continue
        if len(content) > MAX_SOURCEMAP_SOURCE_BYTES:
            content = content[:MAX_SOURCEMAP_SOURCE_BYTES]
        name = sources[i] if i < len(sources) and sources[i] else f"source_{i}"
        collected.append((f"{js_url}!{name}", content))
        if len(collected) >= MAX_SOURCEMAP_SOURCES:
            break
    return collected
