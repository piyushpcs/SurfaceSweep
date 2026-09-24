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
from modules.extraction.deobfuscator import deobfuscate
from modules.extraction.scope import (
    get_registrable_domain,
    is_same_scope,
    normalize_scope_filter,
)


JS_REFERENCE_PATTERN = re.compile(
    r'''(?:src|import|require|from|chunk|loadScript|importScripts)\s*(?:\(|[=:]?\s*)['"]([^'"]+\.js(?:\?[^'"]*)?)['"]''',
    re.IGNORECASE
)


def extract_endpoints_from_text(content, source_label):
    """Quick extraction from JS text — reuses patterns from extractor module."""
    from modules.extraction.engine import ENDPOINT_PATTERN, GENERIC_PATH_PATTERN, FULL_URL_PATTERN, CALL_PATTERN, is_noise

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


def run_browser_scan(base_url, timeout=30, verbose=True, scope_filter=None):
    """
    Load a page in a headless browser, intercept all network traffic,
    and extract endpoints from both the DOM and network requests.

    scope_filter is a raw --scope value (wildcard/URL OK); it is normalized
    once here. Absolute intercepted URLs outside scope are kept for display
    in out_of_scope_urls but excluded from the probe-oriented lists.

    Returns a dict compatible with the extractor's output format.
    """
    target_domain = get_registrable_domain(base_url)
    scope = normalize_scope_filter(scope_filter) or target_domain

    result = {
        "target": base_url,
        "scan_mode": "browser",
        "js_files_scanned": [],
        "inline_scripts_scanned": 0,
        "secrets_found": [],
        "jwts_found": [],
        "source_maps_found": [],
        "network_requests": [],
        "intercepted_endpoints": [],
        "deobfuscation_findings": [],
        "sinks_found": [],
        "internal_hosts_found": [],
        "pii_found": [],
        "errors": []
    }

    if verbose:
        print(f"[*] Launching headless browser for {base_url}")

    intercepted_requests = []
    js_files_found = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ignore_https_errors=True
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

        try:
            dom_content = page.content()
        except Exception:
            dom_content = ""

        try:
            for script in page.query_selector_all("script"):
                inner = script.inner_text()
                if inner.strip():
                    result["inline_scripts_scanned"] += 1
        except Exception:
            pass

        page.close()
        browser.close()

    if verbose:
        print(f"[+] Captured {len(intercepted_requests)} network requests")
        print(f"[+] Found {len(js_files_found)} JS files via browser")

    endpoint_urls = set()
    from modules.extraction.engine import is_static_asset
    for req in intercepted_requests:
        url = req["url"]
        parsed = urlparse(url)
        path = parsed.path
        if path and path != "/" and not is_static_asset(path):
            if url.startswith("http") and not is_same_scope(url, scope):
                continue
            endpoint_urls.add(url)

    for req in intercepted_requests:
        if req["resource_type"] in ("xhr", "fetch"):
            url = req["url"]
            if url.startswith("http") and not is_same_scope(url, scope):
                continue
            result["intercepted_endpoints"].append({
                "url": url,
                "method": req["method"]
            })

    from modules.extraction.enrich import enrich_intercepted_endpoints
    enrich_intercepted_endpoints(result["intercepted_endpoints"])

    result["network_requests"] = intercepted_requests

    for js_url in js_files_found:
        if not is_same_scope(js_url, scope):
            continue
        try:
            import requests
            resp = requests.get(js_url, timeout=10, headers={"User-Agent": "SurfaceSweep/1.0"})
            deobfed_content, deobf_findings = deobfuscate(resp.text)
            eps = extract_endpoints_from_text(deobfed_content, js_url)
            endpoint_urls.update(eps)
            from modules.extraction.engine import extract_from_text
            _, secrets, _, sinks, internal, jwts, pii = extract_from_text(deobfed_content, js_url)
            result["secrets_found"].extend(secrets)
            result["jwts_found"].extend(jwts)
            result["sinks_found"].extend(sinks)
            result["pii_found"].extend(pii)
            for h in internal:
                h["source"] = js_url
            result["internal_hosts_found"].extend(internal)
            result["deobfuscation_findings"].extend(deobf_findings)
            result["js_files_scanned"].append(js_url)
        except Exception:
            pass

    deobfed_dom, dom_deobf = deobfuscate(dom_content)
    inline_eps = extract_endpoints_from_text(deobfed_dom, "browser_dom")
    endpoint_urls.update(inline_eps)

    from modules.extraction.engine import extract_from_text, deduplicate_secrets, deduplicate_sinks, deduplicate_pii
    from modules.jwt import deduplicate_jwts
    _, dom_secrets, _, dom_sinks, dom_internal, dom_jwts, dom_pii = extract_from_text(deobfed_dom, "browser_dom")
    result["secrets_found"].extend(dom_secrets)
    result["jwts_found"].extend(dom_jwts)
    result["sinks_found"].extend(dom_sinks)
    result["pii_found"].extend(dom_pii)
    for h in dom_internal:
        h["source"] = "browser_dom"
    result["internal_hosts_found"].extend(dom_internal)
    result["deobfuscation_findings"].extend(dom_deobf)
    result["secrets_found"] = deduplicate_secrets(result["secrets_found"])
    result["jwts_found"] = deduplicate_jwts(result["jwts_found"])
    result["sinks_found"] = deduplicate_sinks(result["sinks_found"])
    result["pii_found"] = deduplicate_pii(result["pii_found"])
    seen_host = set()
    unique_hosts = []
    for h in result["internal_hosts_found"]:
        if h.get("match") not in seen_host:
            seen_host.add(h.get("match"))
            unique_hosts.append(h)
    result["internal_hosts_found"] = unique_hosts

    result["internal_paths"] = sorted([
        e for e in endpoint_urls if e.startswith("/") and not e.startswith("//") and not is_static_asset(e)
    ])
    result["in_scope_urls"] = sorted([
        e for e in endpoint_urls
        if e.startswith("http") and is_same_scope(e, scope) and not is_static_asset(e)
    ])
    result["out_of_scope_urls"] = sorted([
        e for e in endpoint_urls
        if e.startswith("http") and not is_same_scope(e, scope) and not is_static_asset(e)
    ])

    if verbose:
        print(f"[+] Internal paths found: {len(result['internal_paths'])}")
        print(f"[+] In-scope URLs: {len(result['in_scope_urls'])}")
        print(f"[+] Intercepted XHR/fetch: {len(result['intercepted_endpoints'])}")
        if result["secrets_found"]:
            print(f"[!] {len(result['secrets_found'])} unique secret(s) found")
        if result.get("jwts_found"):
            print(f"[!] {len(result['jwts_found'])} unique JWT(s) found")
        if result["deobfuscation_findings"]:
            print(f"[!] {len(result['deobfuscation_findings'])} obfuscated string(s) decoded")
        if result["sinks_found"]:
            print(f"[!] {len(result['sinks_found'])} dangerous sink pattern(s) found")
        if result["internal_hosts_found"]:
            print(f"[!] {len(result['internal_hosts_found'])} internal/private host reference(s) found")
        if result.get("pii_found"):
            print(f"[!] {len(result['pii_found'])} potential PII item(s) found")

    from modules.extraction.engine import calculate_risk_summary
    result["risk_summary"] = calculate_risk_summary(result)

    if verbose:
        print(f"[+] Risk level: {result['risk_summary']['level']} (score: {result['risk_summary']['score']})")

    return result
