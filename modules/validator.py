"""
Endpoint validator for SurfaceSweep.

Confirms discovered endpoints are live by making HTTP requests.
Filters out false positives (404s, soft-404s, redirects to homepage).

Status classification:
- 200: LIVE
- 201/202/204: LIVE (created/accepted/no content)
- 301/302/307/308: REDIRECT (follow to check final)
- 401/403: RESTRICTED (exists but needs auth — still valid)
- 404/410: DEAD
- 405/501: METHOD_NOT_ALLOWED (endpoint exists)
- 429: RATE_LIMITED (exists)
- 5xx: SERVER_ERROR (exists but broken)
"""

import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

USER_AGENT = "SurfaceSweep/1.0"

# Status codes that indicate the endpoint exists
LIVE_STATUSES = {200, 201, 202, 204, 206, 301, 302, 304, 307, 308}
RESTRICTED_STATUSES = {401, 403}
METHOD_STATUSES = {405, 501}
RATE_LIMITED_STATUSES = {429}
ERROR_STATUSES = set(range(500, 600))
DEAD_STATUSES = {404, 410}

# Noise responses that look like 200 but are actually soft-404s
SOFT_404_SIGNATURES = [
    "page not found",
    "not found",
    "404",
    "does not exist",
    "sorry, the page you visited does not exist",
]


def classify_status(status_code):
    """Classify HTTP status code into endpoint status."""
    if status_code in LIVE_STATUSES:
        return "live"
    if status_code in RESTRICTED_STATUSES:
        return "restricted"
    if status_code in METHOD_STATUSES:
        return "live"
    if status_code in RATE_LIMITED_STATUSES:
        return "live"
    if status_code in DEAD_STATUSES:
        return "dead"
    if status_code in ERROR_STATUSES:
        return "server_error"
    if 200 <= status_code < 300:
        return "live"
    if 300 <= status_code < 400:
        return "redirect"
    if 400 <= status_code < 500:
        return "dead"
    return "unknown"


def is_soft_404(response, original_url):
    """Detect soft-404s: server returns 200 but content indicates not found."""
    try:
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/json" not in content_type:
            return False

        body = response.text[:2000].lower()
        for sig in SOFT_404_SIGNATURES:
            if sig in body:
                # Check if the original path is also mentioned (sometimes in 404 pages)
                path = urlparse(original_url).path
                if path and path.lower() in body:
                    continue
                return True
    except Exception:
        pass
    return False


def validate_endpoint(url, method="GET", timeout=10, allow_redirects=False, headers=None):
    """
    Validate a single endpoint. Returns dict with validation details.
    """
    if headers is None:
        headers = {"User-Agent": USER_AGENT}

    try:
        resp = requests.request(
            method,
            url,
            timeout=timeout,
            headers=headers,
            allow_redirects=allow_redirects
        )

        status = classify_status(resp.status_code)
        soft_404 = is_soft_404(resp, url) if resp.status_code == 200 else False

        if soft_404:
            status = "dead"

        result = {
            "url": url,
            "status_code": resp.status_code,
            "status": status,
            "content_length": len(resp.content),
            "content_type": resp.headers.get("Content-Type", ""),
            "method": method
        }

        if resp.history:
            result["redirect_chain"] = [
                {"status": h.status_code, "url": h.url}
                for h in resp.history
            ]
            result["final_url"] = resp.url
        else:
            result["final_url"] = url

        return result

    except requests.Timeout:
        return {"url": url, "status_code": None, "status": "timeout", "method": method}
    except requests.ConnectionError:
        return {"url": url, "status_code": None, "status": "connection_error", "method": method}
    except requests.RequestException as e:
        return {"url": url, "status_code": None, "status": "error", "error": str(e), "method": method}


def validate_endpoints(urls, base_url, threads=10, timeout=10, verbose=True, headers=None):
    """
    Validate multiple endpoints concurrently.

    Args:
        urls: list of endpoint paths or full URLs
        base_url: base URL to resolve relative paths against
        threads: concurrent validation threads
        timeout: per-request timeout
        verbose: print progress
        headers: custom headers to include

    Returns:
        dict with validated endpoints categorized by status
    """
    resolved = []
    for url in urls:
        if url.startswith("http"):
            resolved.append(url)
        elif url.startswith("/"):
            resolved.append(urljoin(base_url, url))
        else:
            resolved.append(urljoin(base_url + "/", url))

    if verbose:
        print(f"[*] Validating {len(resolved)} endpoints...")

    results = {
        "live": [],
        "restricted": [],
        "dead": [],
        "server_error": [],
        "timeout": [],
        "connection_error": [],
        "error": [],
        "redirect": [],
        "unknown": []
    }

    all_results = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(validate_endpoint, url, timeout=timeout, headers=headers): url
            for url in resolved
        }
        for future in as_completed(futures):
            result = future.result()
            all_results.append(result)
            status = result.get("status", "unknown")
            if status in results:
                results[status].append(result)
            else:
                results["unknown"].append(result)

            if verbose:
                code = result.get("status_code", "ERR")
                marker = {"live": "+", "restricted": "!", "dead": "-"}.get(status, "?")
                print(f"    [{marker}] {code} {result['url'][:80]}")

    live_count = len(results["live"])
    dead_count = len(results["dead"])
    restricted_count = len(results["restricted"])

    if verbose:
        print(f"\n[+] Validation complete:")
        print(f"    Live: {live_count}")
        print(f"    Restricted (401/403): {restricted_count}")
        print(f"    Dead (404): {dead_count}")
        print(f"    Server errors: {len(results['server_error'])}")
        print(f"    Timeouts: {len(results['timeout'])}")

    return results


def get_live_endpoints(validation_results):
    """Extract only live/restricted endpoints from validation results."""
    live = []
    for status in ["live", "restricted", "server_error"]:
        for item in validation_results.get(status, []):
            live.append(item)
    return live
