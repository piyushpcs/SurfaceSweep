"""
Browser-based endpoint extractor using Playwright.

Captures all network requests made during page load, including:
- XHR/fetch calls triggered by JS frameworks
- Lazy-loaded webpack chunks
- Dynamic imports
- API calls made after JS initialization
"""

import re
from urllib.parse import urlparse, urljoin
from playwright.sync_api import sync_playwright


JS_REFERENCE_PATTERN = re.compile(
    r'''(?:src|import|require|from|chunk|loadScript|importScripts)\s*(?:\(|[=:]?\s*)['"]([^'"]+\.js(?:\?[^'"]*)?)['"]''',
    re.IGNORECASE
)


def is_same_scope(url, target_domain):
    ext = __import__("tldextract").extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}" == target_domain
    return False


def extract_endpoints_from_text(content, source_label):
    """Quick extraction from JS text — reuses patterns from extractor module."""
    from modules.extractor import ENDPOINT_PATTERN, GENERIC_PATH_PATTERN, FULL_URL_PATTERN, CALL_PATTERN, is_noise

    endpoints = set()
    for pattern in [ENDPOINT_PATTERN, GENERIC_PATH_PATTERN, FULL_URL_PATTERN, CALL_PATTERN]:
        for match in pattern.findall(content):
            if isinstance(match, tuple):
                match = match[0]
            if match.startswith("//"):
                continue
            if not is_noise(match):
                endpoints.add(match)
    return endpoints


def get_registrable_domain(url):
    ext = __import__("tldextract").extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or urlparse(url).netloc


def run_browser_scan(base_url, timeout=30, verbose=True, scope_filter=None):
    """
    Load a page in a headless browser, intercept all network traffic,
    and extract endpoints from both the DOM and network requests.

    Returns a dict compatible with the extractor's output format.
    """
    target_domain = get_registrable_domain(base_url)

    result = {
        "target": base_url,
        "scan_mode": "browser",
        "js_files_scanned": [],
        "inline_scripts_scanned": 0,
        "secrets_found": [],
        "source_maps_found": [],
        "network_requests": [],
        "intercepted_endpoints": [],
        "errors": []
    }

    if verbose:
        print(f"[*] Launching headless browser for {base_url}")

    intercepted_requests = []
    js_files_found = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = context.new_page()

        def handle_request(request):
            url = request.url
            method = request.method
            if url.startswith("data:"):
                return
            intercepted_requests.append({
                "url": url,
                "method": method,
                "resource_type": request.resource_type
            })
            if url.endswith(".js") or ".js?" in url:
                js_files_found.add(url)

        def handle_response(response):
            url = response.url
            if url.endswith(".js.map"):
                content_type = response.headers.get("content-type", "")
                try:
                    body_start = response.text()[:1]
                    if "json" in content_type or body_start == "{":
                        result["source_maps_found"].append(url)
                        if verbose:
                            print(f"    [!] Source map exposed: {url}")
                except Exception:
                    pass

        page.on("request", handle_request)
        page.on("response", handle_response)

        try:
            page.goto(base_url, wait_until="networkidle", timeout=timeout * 1000)
            page.wait_for_timeout(2000)
        except Exception as e:
            result["errors"].append(f"Browser navigation error: {e}")
            if verbose:
                print(f"    [!] Navigation error: {e}")

        dom_content = page.content()

        for script in page.query_selector_all("script"):
            inner = script.inner_text()
            if inner.strip():
                result["inline_scripts_scanned"] += 1

        page.close()
        browser.close()

    if verbose:
        print(f"[+] Captured {len(intercepted_requests)} network requests")
        print(f"[+] Found {len(js_files_found)} JS files via browser")

    endpoint_urls = set()
    for req in intercepted_requests:
        url = req["url"]
        parsed = urlparse(url)
        path = parsed.path
        if path and path != "/" and not any(path.lower().endswith(ext) for ext in (".png", ".jpg", ".svg", ".gif", ".css", ".woff", ".ico", ".ttf")):
            if scope_filter is None or is_same_scope(url, scope_filter):
                endpoint_urls.add(url)

    for req in intercepted_requests:
        if req["resource_type"] in ("xhr", "fetch"):
            url = req["url"]
            if scope_filter is None or is_same_scope(url, scope_filter):
                result["intercepted_endpoints"].append({
                    "url": url,
                    "method": req["method"]
                })

    result["network_requests"] = intercepted_requests

    for js_url in js_files_found:
        if scope_filter and not is_same_scope(js_url, scope_filter):
            continue
        try:
            import requests
            resp = requests.get(js_url, timeout=10, headers={"User-Agent": "SurfaceSweep/1.0"})
            eps = extract_endpoints_from_text(resp.text, js_url)
            endpoint_urls.update(eps)
            from modules.extractor import extract_from_text, check_source_map
            _, secrets = extract_from_text(resp.text, js_url)
            result["secrets_found"].extend(secrets)
            result["js_files_scanned"].append(js_url)
        except Exception:
            pass

    inline_eps = extract_endpoints_from_text(dom_content, "browser_dom")
    endpoint_urls.update(inline_eps)

    from modules.extractor import extract_from_text, deduplicate_secrets
    _, dom_secrets = extract_from_text(dom_content, "browser_dom")
    result["secrets_found"].extend(dom_secrets)
    result["secrets_found"] = deduplicate_secrets(result["secrets_found"])

    result["internal_paths"] = sorted([
        e for e in endpoint_urls if e.startswith("/") and not e.startswith("//")
    ])
    result["in_scope_urls"] = sorted([
        e for e in endpoint_urls
        if e.startswith("http") and is_same_scope(e, target_domain)
    ])
    result["out_of_scope_urls"] = sorted([
        e for e in endpoint_urls
        if e.startswith("http") and not is_same_scope(e, target_domain)
    ])

    if verbose:
        print(f"[+] Internal paths found: {len(result['internal_paths'])}")
        print(f"[+] In-scope URLs: {len(result['in_scope_urls'])}")
        print(f"[+] Intercepted XHR/fetch: {len(result['intercepted_endpoints'])}")
        if result["secrets_found"]:
            print(f"[!] {len(result['secrets_found'])} unique secret(s) found")

    return result
