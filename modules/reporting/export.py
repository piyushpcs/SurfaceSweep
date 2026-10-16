"""
Export module for SurfaceSweep.

Generates outputs compatible with Burp Suite and OWASP ZAP, plus
target-derived path/parameter wordlists for content discovery.
"""

import csv
import os
from urllib.parse import urlparse
from modules.common.console import ok, warn

# Spreadsheet apps treat cells beginning with these as formulas (CSV injection,
# OWASP). Prefix with an apostrophe so imported URLs/paths stay inert.
_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value) -> str:
    """Neutralize spreadsheet formula-injection in an exported cell."""
    text = "" if value is None else str(value)
    if text[:1] in _CSV_INJECTION_PREFIXES:
        return "'" + text
    return text


def _write_csv(filename: str, fieldnames: list, rows: list) -> bool:
    """Write a CSV, creating the parent dir only when the path has one."""
    parent = os.path.dirname(filename)
    if parent:
        os.makedirs(parent, exist_ok=True)
    safe_rows = [{k: _csv_safe(v) for k, v in row.items()} for row in rows]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(safe_rows)
    return True


def export_burp_csv(result, filename="reports/surfacesweep_burp.csv"):
    """
    Export endpoints in Burp Suite target list format.
    Import via Burp: Target > Site map > Add tab from clipboard / Import.

    CSV columns: Host, Protocol, Path, Query
    """
    target = result.get("target", "")
    protocol = "https" if target.startswith("https") else "http"

    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(target)
    host = parsed.netloc

    rows = []

    def add_url(url):
        p = urlparse(url) if url.startswith("http") else urlparse(f"{protocol}://{host}{url if url.startswith('/') else '/' + url}")
        path = p.path or "/"
        query = p.query or ""
        rows.append({
            "Host": p.netloc or host,
            "Protocol": p.scheme or protocol,
            "Path": path,
            "Query": query
        })

    for path in result.get("internal_paths", []):
        add_url(path)

    for url in result.get("in_scope_urls", []):
        add_url(url)

    for ep in result.get("intercepted_endpoints", []):
        url = ep.get("url", "")
        if url:
            add_url(url)

    seen = set()
    unique_rows = []
    for r in rows:
        key = (r["Host"], r["Protocol"], r["Path"], r["Query"])
        if key not in seen:
            seen.add(key)
            unique_rows.append(r)

    try:
        _write_csv(filename, ["Host", "Protocol", "Path", "Query"], unique_rows)
        ok(f" Burp CSV exported: {filename} ({len(unique_rows)} endpoints)")
        return True
    except OSError as e:
        warn(f" Failed to export Burp CSV: {e}")
        return False


def export_zap_csv(result, filename="reports/surfacesweep_zap.csv"):
    """
    Export endpoints in OWASP ZAP importable format.
    Import via ZAP: Import > Import URLs from file.

    CSV columns: URL, Method, Data, Payload
    """
    target = result.get("target", "")
    protocol = "https" if target.startswith("https") else "http"
    from urllib.parse import urlparse
    parsed = urlparse(target)
    host = parsed.netloc

    rows = []
    seen = set()

    def add_url(url):
        if url.startswith("http"):
            full = url
        elif url.startswith("/"):
            full = f"{protocol}://{host}{url}"
        else:
            full = f"{protocol}://{host}/{url}"

        if full not in seen:
            seen.add(full)
            rows.append({
                "URL": full,
                "Method": "GET",
                "Data": "",
                "Payload": ""
            })

    for path in result.get("internal_paths", []):
        add_url(path)

    for url in result.get("in_scope_urls", []):
        add_url(url)

    for ep in result.get("intercepted_endpoints", []):
        url = ep.get("url", "")
        method = ep.get("method", "GET")
        if url and url not in seen:
            seen.add(url)
            rows.append({
                "URL": url,
                "Method": method,
                "Data": "",
                "Payload": ""
            })

    try:
        _write_csv(filename, ["URL", "Method", "Data", "Payload"], rows)
        ok(f" ZAP CSV exported: {filename} ({len(rows)} endpoints)")
        return True
    except OSError as e:
        warn(f" Failed to export ZAP CSV: {e}")
        return False


def build_wordlist(result) -> list:
    """
    Build a target-derived path/parameter wordlist for content discovery.

    Combines:
      - path segments from discovered endpoints (api, v1, users, …)
      - full relative paths (for path fuzzing / recursion)
      - parameter names from params_found (query/body/URLSearchParams/path templates)
    Returns a sorted unique list of strings (xnLinkFinder-style output).
    """
    words = set()

    def _add_path(path: str) -> None:
        if not path or not isinstance(path, str):
            return
        clean = path.split("?", 1)[0].split("#", 1)[0]
        if not clean.startswith("/") and "://" not in clean:
            clean = "/" + clean
        if "://" in clean:
            try:
                clean = urlparse(clean).path or "/"
            except ValueError:
                return
        clean = clean.strip("/")
        if not clean:
            return
        words.add("/" + clean)
        for seg in clean.split("/"):
            seg = seg.strip()
            if 1 < len(seg) < 80 and not seg.startswith("{"):
                words.add(seg)

    for p in result.get("internal_paths") or []:
        _add_path(p)
    for u in result.get("in_scope_urls") or []:
        _add_path(u)
    for e in result.get("intercepted_endpoints") or []:
        if isinstance(e, dict) and e.get("url"):
            _add_path(e["url"])
    for r in result.get("spa_routes") or []:
        _add_path(r)

    for param in result.get("params_found") or []:
        name = param.get("name") if isinstance(param, dict) else None
        if name and 1 < len(name) < 80:
            words.add(name)

    return sorted(w for w in words if w and w != "/")


def export_wordlist(result, filename="reports/surfacesweep_wordlist.txt"):
    """Write the path/parameter wordlist to disk (one entry per line)."""
    entries = build_wordlist(result)
    try:
        parent = os.path.dirname(filename)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(filename, "w", encoding="utf-8") as fh:
            for entry in entries:
                fh.write(entry + "\n")
        ok(f" Wordlist exported: {filename} ({len(entries)} entries)")
        return True
    except OSError as e:
        warn(f" Failed to export wordlist: {e}")
        return False
