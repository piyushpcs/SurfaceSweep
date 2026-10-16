"""
Alternate discovery sources — import endpoints from Burp, ZAP, or HAR files.

Read-only: nothing here contacts the target. A pentest frequently starts from
proxy history already captured in Burp/ZAP or a browser HAR export; this lets
SurfaceSweep fold that traffic into a scan's endpoint pool so it can be
validated / CORS-probed alongside natively discovered endpoints.

Supported formats (auto-detected):
  - HAR      (JSON) : browser / devtools export    → log.entries[].request.url
  - Burp     (XML)  : Burp "Save items"            → //item/url
  - Burp     (CSV)  : SurfaceSweep / Burp list     → Host, Protocol, Path, Query
  - ZAP      (CSV)  : OWASP ZAP "Import URLs"      → URL, Method, Data, Payload

Every imported URL is scheme-checked (http/https only), fragment-stripped, and
deduplicated. Scope enforcement happens later when merging (imported URLs that
fall outside the target's registrable domain are ignored by the merge helper).
"""

from __future__ import annotations

import csv
import io
import json
import os
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urlunparse

__all__ = ["ImportParseError", "detect_format", "extract_urls", "load_import"]

_HTTP_SCHEMES = ("http://", "https://")


class ImportParseError(ValueError):
    """Raised when an import file cannot be parsed as a known format."""


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def detect_format(path: str, text: str | None = None) -> str | None:
    """
    Guess the import format from the file extension and/or leading bytes.

    Returns one of "har", "burp_xml", "burp_csv", "zap_csv", or None.
    """
    ext = os.path.splitext(path or "")[1].lower()
    if ext == ".har":
        return "har"
    if text is None:
        text = _read_text(path)
    stripped = text.lstrip()
    if ext == ".xml" or stripped.startswith("<"):
        return "burp_xml"
    if stripped.startswith("{") or stripped.startswith("["):
        # JSON — assume HAR; the parser validates the shape.
        return "har"
    if ext == ".csv":
        first = (text.splitlines() or [""])[0].strip().lower()
        if first.startswith("url,") or first == "url":
            return "zap_csv"
        return "burp_csv"
    return None


def _parse_har(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise ImportParseError(f"invalid HAR JSON: {exc}") from exc
    entries = (((data or {}).get("log") or {}).get("entries")) or []
    urls = []
    for entry in entries:
        request = (entry or {}).get("request") or {}
        url = request.get("url")
        if url:
            urls.append(url)
    return urls


def _parse_burp_xml(text: str) -> list[str]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ImportParseError(f"invalid Burp XML: {exc}") from exc
    urls = []
    for el in root.iter():
        tag = el.tag.split("}")[-1].lower() if isinstance(el.tag, str) else ""
        if tag == "url" and (el.text or "").strip():
            urls.append(el.text.strip())
    return urls


def _parse_burp_csv(text: str) -> list[str]:
    urls = []
    for row in csv.DictReader(io.StringIO(text)):
        lowered = {str(k).strip().lower(): (v or "") for k, v in row.items() if k}
        host = lowered.get("host", "").strip()
        if not host:
            continue
        protocol = (lowered.get("protocol") or "https").strip() or "https"
        path = (lowered.get("path") or "/").strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        url = f"{protocol}://{host}{path}"
        query = lowered.get("query", "").strip()
        if query:
            url = f"{url}?{query}"
        urls.append(url)
    return urls


def _parse_zap_csv(text: str) -> list[str]:
    urls = []
    for row in csv.DictReader(io.StringIO(text)):
        lowered = {str(k).strip().lower(): (v or "") for k, v in row.items() if k}
        url = lowered.get("url", "").strip()
        if url:
            urls.append(url)
    return urls


def _clean(urls: list[str]) -> list[str]:
    """Keep http(s) URLs only; strip fragments, normalize, dedupe, sort."""
    out: list[str] = []
    seen = set()
    for url in urls:
        if not isinstance(url, str):
            continue
        candidate = url.strip()
        if not candidate.lower().startswith(_HTTP_SCHEMES):
            continue
        try:
            parsed = urlparse(candidate)
        except ValueError:
            continue
        if not parsed.hostname:
            continue
        clean = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path or "/",
            parsed.params, parsed.query, "",
        ))
        if clean not in seen:
            seen.add(clean)
            out.append(clean)
    return sorted(out)


def extract_urls(text: str, fmt: str) -> list[str]:
    """Parse ``text`` as ``fmt`` and return the cleaned URL list."""
    parsers = {
        "har": _parse_har,
        "burp_xml": _parse_burp_xml,
        "burp_csv": _parse_burp_csv,
        "zap_csv": _parse_zap_csv,
    }
    parser = parsers.get(fmt)
    if parser is None:
        raise ImportParseError(f"unsupported import format: {fmt}")
    return _clean(parser(text))


def load_import(path: str, fmt: str | None = None) -> dict:
    """
    Load an import file and return {format, endpoints, count}.

    ``fmt`` overrides auto-detection when provided. Raises ImportParseError
    (a ValueError) for an unknown/unsupported or unparseable file, and OSError
    when the file cannot be read.
    """
    try:
        text = _read_text(path)
    except OSError:
        raise
    resolved = fmt or detect_format(path, text)
    if resolved is None:
        raise ImportParseError(f"unrecognized import format: {path}")
    endpoints = extract_urls(text, resolved)
    return {"format": resolved, "endpoints": endpoints, "count": len(endpoints)}
