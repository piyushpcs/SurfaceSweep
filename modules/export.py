"""
Export module for SurfaceSweep.

Generates outputs compatible with Burp Suite and OWASP ZAP.
"""

import csv
import os


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
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["Host", "Protocol", "Path", "Query"])
            writer.writeheader()
            writer.writerows(unique_rows)
        print(f"[+] Burp CSV exported: {filename} ({len(unique_rows)} endpoints)")
        return True
    except OSError as e:
        print(f"[!] Failed to export Burp CSV: {e}")
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
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["URL", "Method", "Data", "Payload"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"[+] ZAP CSV exported: {filename} ({len(rows)} endpoints)")
        return True
    except OSError as e:
        print(f"[!] Failed to export ZAP CSV: {e}")
        return False
