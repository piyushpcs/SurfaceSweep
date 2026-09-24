"""
Wayback Machine integration for SurfaceSweep.

Fetches historical JS files from web.archive.org to find endpoints
that may no longer be linked in the current version of the site.
"""

import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.common.console import detail, info, ok


def get_wayback_js_urls(target_domain, limit=50, verbose=True):
    """
    Query Wayback Machine for historical JS files of a domain.

    Returns list of archived JS file URLs.
    """
    if verbose:
        info(f" Querying Wayback Machine for {target_domain} JS files...")

    # CDX API: search for all archived .js files
    cdx_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"{target_domain}/*",
        "output": "json",
        "fl": "original,mimetype,statuscode",
        "filter": "mimetype:application/javascript",
        "limit": str(limit * 2),
        "collapse": "urlkey"
    }

    try:
        resp = requests.get(cdx_url, params=params, timeout=30, headers={"User-Agent": "SurfaceSweep/1.0"})
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        if verbose:
            detail(f"[!] Wayback API error: {e}")
        return []
    except ValueError:
        if verbose:
            detail(f"[!] Wayback API returned invalid JSON")
        return []

    if not data or len(data) <= 1:
        if verbose:
            detail(f"[!] No archived JS files found")
        return []

    # First row is header
    header = data[0]
    js_urls = []
    for row in data[1:]:
        record = dict(zip(header, row))
        url = record.get("original", "")
        if url.endswith(".js") or ".js?" in url:
            js_urls.append(url)

    js_urls = js_urls[:limit]

    if verbose:
        detail(f"[+] Found {len(js_urls)} archived JS file(s)")

    return js_urls


def fetch_wayback_js(js_url, timeout=15, verbose=False):
    """Fetch a JS file from Wayback Machine."""
    # Use the most recent snapshot
    wayback_url = f"https://archive.org/wayback/available?url={js_url}"
    try:
        resp = requests.get(wayback_url, timeout=timeout, headers={"User-Agent": "SurfaceSweep/1.0"})
        data = resp.json()
        snapshot_url = data.get("archived_snapshots", {}).get("closest", {}).get("url", "")
        if not snapshot_url:
            return None

        # Force HTTPS — archive.org snapshots may return http:// URLs that are refused on port 80
        if snapshot_url.startswith("http://"):
            snapshot_url = "https://" + snapshot_url[len("http://"):]

        js_resp = requests.get(snapshot_url, timeout=timeout, headers={"User-Agent": "SurfaceSweep/1.0"})
        js_resp.raise_for_status()
        return {
            "original_url": js_url,
            "snapshot_url": snapshot_url,
            "content": js_resp.text
        }
    except requests.RequestException:
        return None


def get_wayback_endpoints(target_domain, limit=50, threads=5, verbose=True):
    """
    Fetch historical JS files from Wayback Machine and extract endpoints.
    Returns dict with wayback results.
    """
    js_urls = get_wayback_js_urls(target_domain, limit=limit, verbose=verbose)

    if not js_urls:
        return {"js_files": [], "endpoints": set(), "secrets": [], "sinks": [], "internal_hosts": [], "jwts": [], "pii": [], "errors": []}

    if verbose:
        info(f" Fetching {len(js_urls)} archived JS files...")

    results = {"js_files": [], "endpoints": set(), "secrets": [], "sinks": [], "internal_hosts": [], "jwts": [], "pii": [], "errors": []}

    from modules.extraction.engine import extract_from_text

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(fetch_wayback_js, url): url for url in js_urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                data = future.result()
            except Exception as e:
                results["errors"].append(f"{url}: {e}")
                continue
            if data is None:
                results["errors"].append(f"{url}: fetch failed")
                continue

            results["js_files"].append(data["original_url"])
            endpoints, secrets, _, sinks, internal, jwts, pii = extract_from_text(data["content"], data["original_url"])
            results["endpoints"].update(endpoints)
            results["secrets"].extend(secrets)
            results["sinks"].extend(sinks)
            results["jwts"].extend(jwts)
            results["pii"].extend(pii)
            for h in internal:
                h["source"] = data["original_url"]
            results["internal_hosts"].extend(internal)

            if verbose:
                detail(f"scanned {data['original_url'][:70]} — {len(endpoints)} endpoints")

    if verbose:
        ok(f" Wayback: {len(results['js_files'])} files scanned, {len(results['endpoints'])} endpoints found")

    return results
