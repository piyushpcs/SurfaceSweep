"""
Endpoint validator for SurfaceSweep.

Confirms discovered endpoints are live by making HTTP requests.
Filters out false positives (404s, soft-404s, SPA index shells, JSON
fail-in-200 bodies, redirects to homepage).

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

import json
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

# Noise responses that look like 200 but are actually soft-404s.
# Bare substrings like "404" are intentionally omitted — they match live
# pages that merely document status codes. Classification requires either
# a strong multi-word phrase or at least two distinct weak signals.
SOFT_404_SIGNATURES = [
    "page not found",
    "not found",
    "does not exist",
    "sorry, the page you visited does not exist",
    "404 not found",
    "error 404",
    "http 404",
    "status 404",
    "404 error",
]

# Phrases strong enough to classify soft-404 on their own.
STRONG_SOFT_404 = frozenset({
    "page not found",
    "does not exist",
    "sorry, the page you visited does not exist",
    "404 not found",
    "error 404",
    "http 404",
    "status 404",
    "404 error",
})

# API-ish path markers — used to decide when HTML is a false SPA shell hit
API_PATH_HINTS = (
    "/api/", "/api", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/",
    "/auth/", "/oauth/", "/rpc/", "/json/", "/gql/",
)

# Client-side app mount points (index.html served for unknown API routes)
SPA_SHELL_SIGNATURES = (
    'id="root"',
    "id='root'",
    'id="__next"',
    "id='__next'",
    'id="app"',
    "id='app'",
    "data-reactroot",
    "ng-version",
    "__NUXT__",
    "window.__NEXT_DATA__",
)

JSON_NOT_FOUND_SIGS = (
    "not found", "not_found", "notfound", "does not exist",
    "no route", "no routes", "unknown endpoint", "unknown route",
    "cannot find", "no such ", "endpoint not", "path not found",
)

JSON_AUTH_SIGS = (
    "unauthorized", "unauthenticated", "forbidden",
    "authentication required", "login required", "not authenticated",
    "invalid token", "token expired", "access denied",
)


def looks_like_api_path(url):
    """True when the path looks like an API endpoint (not a marketing page)."""
    if not url:
        return False
    if "://" in url or url.startswith("//"):
        try:
            path = urlparse(url).path.lower()
        except ValueError:
            path = url.lower()
    else:
        path = url.split("?")[0].split("#")[0].lower()
    return any(hint in path for hint in API_PATH_HINTS)


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
    """
    Detect soft-404s: server returns 200 but content indicates not found.

    Requires a strong phrase (e.g. "page not found") or at least two
    distinct weak signals so live pages that merely mention "404" or
    "not found" in docs/widgets are not misclassified as dead.
    """
    try:
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/json" not in content_type:
            return False

        body = response.text[:2000].lower()
        path = urlparse(original_url).path
        path_l = path.lower() if path else ""

        matched = []
        for sig in SOFT_404_SIGNATURES:
            if sig not in body:
                continue
            # Skip when the original path is echoed (common on branded 404s
            # that still render the requested URL for SEO/logging).
            if path_l and path_l in body:
                continue
            matched.append(sig)

        if not matched:
            return False
        if any(sig in STRONG_SOFT_404 for sig in matched):
            return True
        return len(set(matched)) >= 2
    except Exception:
        return False


def is_spa_shell(response, original_url):
    """
    200 + HTML app shell on an API-like path (client router fallback).
    The HTML index is not evidence the API route exists.
    """
    try:
        if not looks_like_api_path(original_url):
            return False
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return False
        body = (response.text or "")[:8000]
        body_l = body.lower()
        return any(sig.lower() in body_l for sig in SPA_SHELL_SIGNATURES)
    except Exception:
        return False


def _truthy_error_value(value):
    """Error field is meaningful only when non-empty (null/[]/{} are success)."""
    if value is None or value is False or value == 0:
        return False
    if value == "" or value == [] or value == {}:
        return False
    return True


def _json_body_failure(response):
    """
    Inspect a 200 body for application-level failure encoded in JSON.
    Returns 'not_found' | 'auth' | 'error' | None.
    """
    try:
        text = (response.text or "").strip()
        if not text:
            return None
        content_type = response.headers.get("Content-Type", "")
        looks_json_ct = "json" in content_type.lower()
        if not looks_json_ct and not text[:1] in ("{", "["):
            return None
        if len(text) > 200_000:
            return None
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    # Collect error-ish signals as lowercase strings for keyword search
    signals = []
    for key in ("error", "errors", "err", "message", "detail", "description"):
        if key in data and _truthy_error_value(data[key]):
            val = data[key]
            if isinstance(val, dict):
                signals.extend(str(v).lower() for v in val.values() if v)
            elif isinstance(val, list):
                signals.extend(str(v).lower() for v in val if v)
            else:
                signals.append(str(val).lower())

    for key in ("success", "ok"):
        if key in data and data[key] in (False, 0, "false", "no"):
            if not signals:
                signals.append("success false")

    status_val = data.get("status") or data.get("state") or data.get("code")
    if isinstance(status_val, str) and status_val.lower() in (
        "error", "fail", "failed", "failure", "not_found", "notfound",
    ):
        signals.append(status_val.lower())

    if not signals:
        return None
    blob = " | ".join(signals)
    if any(sig in blob for sig in JSON_NOT_FOUND_SIGS):
        return "not_found"
    if any(sig in blob for sig in JSON_AUTH_SIGS):
        return "auth"
    return "error"


def classify_200_body(response, original_url):
    """
    Refine a raw-200 classification using body content.
    Returns (status, note) where status is live|restricted|dead and
    note is None | soft_404 | spa_shell | json_not_found | json_auth | json_error.
    """
    if is_spa_shell(response, original_url):
        return "dead", "spa_shell"
    failure = _json_body_failure(response)
    if failure == "not_found":
        return "dead", "json_not_found"
    if failure == "auth":
        return "restricted", "json_auth"
    if is_soft_404(response, original_url):
        return "dead", "soft_404"
    if failure == "error":
        return "live", "json_error"
    return "live", None


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
        note = None
        if resp.status_code == 200:
            status, note = classify_200_body(resp, url)

        result = {
            "url": url,
            "status_code": resp.status_code,
            "status": status,
            "content_length": len(resp.content),
            "content_type": resp.headers.get("Content-Type", ""),
            "method": method
        }
        if note:
            result["note"] = note

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
            url = futures[future]
            try:
                result = future.result()
            except Exception as e:
                result = {"url": url, "status": "error", "error": str(e)}
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
