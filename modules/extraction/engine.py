"""
Main extraction engine — orchestrates static + AST extraction.
"""

import re
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.extraction.patterns import (
    ENDPOINT_PATTERN, GENERIC_PATH_PATTERN, FULL_URL_PATTERN, CALL_PATTERN,
    JS_REFERENCE_PATTERN, WEBPACK_CHUNK_PATTERN,
    is_noise, is_static_asset, find_internal_hosts
)
from modules.extraction.secrets import extract_secrets, deduplicate_secrets
from modules.extraction.http import RateLimiter, fetch_with_retry, get_page
from modules.extraction.scope import get_registrable_domain, is_same_scope
from modules.extraction.risk import calculate_risk_summary
from modules.extraction.deobfuscator import deobfuscate
from modules.extraction.ast import extract_endpoints_ast, ast_is_available
from modules.extraction.sourcemaps import collect_source_map_sources, load_source_map
from modules.analysis.sinks import detect_sinks, deduplicate_sinks
from modules.jwt import extract_jwts, deduplicate_jwts


def get_js_sources(base_url, html):
    """Extract external and inline JS sources from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    external, inline = [], []

    for script in soup.find_all("script"):
        if script.get("src"):
            external.append(urljoin(base_url, script["src"]))
        elif script.string:
            inline.append(script.string)

    return external, inline


def check_source_map(js_url, timeout=8, limiter=None):
    """Check if a source map exists for a JS file (presence probe only)."""
    map_url = js_url + ".map"
    try:
        resp = fetch_with_retry(map_url, timeout=timeout, limiter=limiter)
        if resp is not None and resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "")
            body_start = resp.text.strip()[:1]
            if "json" in content_type.lower() or body_start == "{":
                return map_url
    except requests.RequestException:
        pass
    return None


def discover_js_chunks(js_content, base_js_url):
    """Find references to other JS files inside a JS file's content."""
    candidates = set()
    for match in JS_REFERENCE_PATTERN.findall(js_content):
        candidates.add(match)
    for match in WEBPACK_CHUNK_PATTERN.findall(js_content):
        candidates.add(match)

    resolved = set()
    for path in candidates:
        if path.startswith("http://") or path.startswith("https://"):
            resolved.add(path)
        elif path.startswith("//"):
            resolved.add("https:" + path)
        elif path.startswith("/"):
            parsed = urlparse(base_js_url)
            resolved.add(f"{parsed.scheme}://{parsed.netloc}{path}")
        else:
            resolved.add(urljoin(base_js_url, path))
    return resolved


def extract_from_text(content, source_label, do_deobfuscate=True, use_ast=True):
    """
    Run all extraction passes (regex + AST) over a blob of JS text.
    Returns (endpoints, secrets, deobf_findings, sinks, internal_hosts, jwts).
    """
    deobf_findings = []
    if do_deobfuscate:
        content, deobf_findings = deobfuscate(content)

    endpoints = set()

    # AST extraction (tree-sitter)
    if use_ast and ast_is_available():
        endpoints |= extract_endpoints_ast(content, source_label)

    # Regex extraction (complements AST)
    for match in ENDPOINT_PATTERN.findall(content):
        if match.startswith("//"):
            continue
        if not is_noise(match):
            endpoints.add(match)

    for match in GENERIC_PATH_PATTERN.findall(content):
        if match.startswith("//"):
            continue
        if not is_noise(match) and len(match) > 3:
            endpoints.add(match)

    for match in FULL_URL_PATTERN.findall(content):
        if not is_noise(match):
            endpoints.add(match)

    # Function-call based extraction — catches fetch()/axios()/$.ajax() etc.
    for match in CALL_PATTERN.findall(content):
        if match.startswith("//"):
            continue
        if not is_noise(match) and len(match) > 1:
            endpoints.add(match)

    secrets = extract_secrets(content, source_label)
    sinks = detect_sinks(content, source_label)
    internal = find_internal_hosts(content)
    for h in internal:
        h["source"] = source_label

    # Dedicated JWT extraction (populates jwts_found for Phase 3 analysis)
    jwts = extract_jwts(content, source_label=source_label)

    # Filter noise from combined AST + regex results
    endpoints = {e for e in endpoints if not is_noise(e) and not e.startswith("//")}

    return endpoints, secrets, deobf_findings, sinks, internal, jwts


def fetch_and_extract(js_url, timeout=10, limiter=None, use_ast=True):
    """Fetch a JS file and extract endpoints/secrets/sinks/jwts from it."""
    try:
        resp = fetch_with_retry(js_url, timeout=timeout, limiter=limiter)
        if resp is None:
            return {"source": js_url, "error": "Failed after retries", "endpoints": set(), "secrets": [], "linked_js": set(), "sinks": [], "internal_hosts": [], "jwts": []}

        content_type = resp.headers.get("Content-Type", "")
        text = resp.text if "json" not in content_type.lower() else ""
        if text:
            endpoints, secrets, deobf, sinks, internal, jwts = extract_from_text(text, js_url, use_ast=use_ast)
        else:
            endpoints, secrets, deobf, sinks, internal, jwts = set(), [], [], [], [], []

        # Source map: comment / data: URI / conventional .map — then rescan sourcesContent
        source_map = None
        map_obj, map_report = load_source_map(js_url, text or None, limiter=limiter)
        if map_obj is not None:
            source_map = map_report
            for label, original_source in collect_source_map_sources(map_obj, js_url):
                o_eps, o_secrets, o_deobf, o_sinks, o_internal, o_jwts = extract_from_text(
                    original_source, label, use_ast=use_ast
                )
                endpoints |= o_eps
                secrets.extend(o_secrets)
                deobf.extend(o_deobf)
                sinks.extend(o_sinks)
                internal.extend(o_internal)
                jwts.extend(o_jwts)

        linked_js = discover_js_chunks(text, js_url) if text else set()

        return {
            "source": js_url,
            "endpoints": endpoints,
            "secrets": secrets,
            "source_map_found": source_map,
            "linked_js": linked_js,
            "deobfuscation_findings": deobf,
            "sinks": sinks,
            "internal_hosts": internal,
            "jwts": jwts,
        }
    except requests.RequestException as e:
        return {"source": js_url, "error": str(e), "endpoints": set(), "secrets": [], "linked_js": set(), "deobfuscation_findings": [], "sinks": [], "internal_hosts": [], "jwts": []}


def run_extractor(base_url, threads=6, verbose=True, max_depth=1, deobfuscate=True, use_ast=True):
    """
    Main entry point. Returns a structured dict — ready for JSON export
    or feeding straight into a dashboard later.

    max_depth: how many hops into referenced JS files to follow (0 = base HTML only,
               1 = JS referenced from HTML, 2 = JS referenced from those JS files, etc.)
    use_ast: enable tree-sitter AST-based extraction (falls back to regex-only if unavailable)
    """
    result = {
        "target": base_url,
        "js_files_scanned": [],
        "inline_scripts_scanned": 0,
        "secrets_found": [],
        "jwts_found": [],
        "source_maps_found": [],
        "deobfuscation_findings": [],
        "sinks_found": [],
        "internal_hosts_found": [],
        "errors": [],
        "scan_depth": max_depth
    }

    target_domain = get_registrable_domain(base_url)
    limiter = RateLimiter(requests_per_second=5)

    if verbose:
        print(f"[*] Fetching {base_url}")

    try:
        html = get_page(base_url, limiter=limiter)
    except requests.RequestException as e:
        result["errors"].append(f"Failed to fetch base URL: {e}")
        return result

    external_js, inline_js = get_js_sources(base_url, html)
    if verbose:
        print(f"[+] Found {len(external_js)} external JS files, {len(inline_js)} inline scripts")

    all_endpoints = set()
    all_secrets = []
    all_sinks = []
    all_internal = []
    all_jwts = []

    for i, content in enumerate(inline_js):
        eps, secs, deobf, snks, intr, jwts = extract_from_text(content, f"inline_script_{i}", do_deobfuscate=deobfuscate, use_ast=use_ast)
        all_endpoints.update(eps)
        all_secrets.extend(secs)
        all_sinks.extend(snks)
        all_internal.extend(intr)
        all_jwts.extend(jwts)
        result["deobfuscation_findings"].extend(deobf)
    result["inline_scripts_scanned"] = len(inline_js)

    visited_js = set()

    def scan_js_urls(js_urls, depth):
        nonlocal all_endpoints, all_secrets, all_sinks, all_internal, all_jwts
        if not js_urls or depth > max_depth:
            return

        new_urls = [u for u in js_urls if u not in visited_js]
        visited_js.update(new_urls)

        if verbose and depth > 0:
            print(f"[*] Depth {depth}: scanning {len(new_urls)} additional JS files")

        linked_at_this_level = set()

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(fetch_and_extract, url, limiter=limiter, use_ast=use_ast): url for url in new_urls}
            for future in as_completed(futures):
                data = future.result()
                if "error" in data:
                    result["errors"].append(f"{data['source']}: {data['error']}")
                    if verbose:
                        print(f"    [!] failed: {data['source']} — {data['error']}")
                    continue

                result["js_files_scanned"].append(data["source"])
                all_endpoints.update(data["endpoints"])
                all_secrets.extend(data["secrets"])
                all_sinks.extend(data.get("sinks", []))
                all_internal.extend(data.get("internal_hosts", []))
                all_jwts.extend(data.get("jwts", []))
                result["deobfuscation_findings"].extend(data.get("deobfuscation_findings", []))

                if data["source_map_found"]:
                    result["source_maps_found"].append(data["source_map_found"])
                    if verbose:
                        print(f"    [!] Source map exposed: {data['source_map_found']}")

                linked_at_this_level.update(data.get("linked_js", set()))

                if verbose:
                    print(f"    scanned {data['source']} — {len(data['endpoints'])} endpoints found")

        if linked_at_this_level:
            scan_js_urls(linked_at_this_level, depth + 1)

    scan_js_urls(external_js, depth=0)

    result["internal_paths"] = sorted([
        e for e in all_endpoints
        if e.startswith("/") and not e.startswith("//") and not is_static_asset(e)
    ])
    result["in_scope_urls"] = sorted([
        e for e in all_endpoints if e.startswith("http") and is_same_scope(e, target_domain) and not is_static_asset(e)
    ])
    result["out_of_scope_urls"] = sorted([
        e for e in all_endpoints if e.startswith("http") and not is_same_scope(e, target_domain) and not is_static_asset(e)
    ])
    result["secrets_found"] = deduplicate_secrets(all_secrets)
    result["jwts_found"] = deduplicate_jwts(all_jwts)
    result["sinks_found"] = deduplicate_sinks(all_sinks)
    seen_host = set()
    for h in all_internal:
        key = h["match"]
        if key in seen_host:
            continue
        seen_host.add(key)
        result["internal_hosts_found"].append(h)
    result["risk_summary"] = calculate_risk_summary(result)

    if verbose:
        print(f"\n[+] Internal paths found: {len(result['internal_paths'])}")
        print(f"[+] In-scope external URLs: {len(result['in_scope_urls'])}")
        print(f"[+] Out-of-scope URLs (informational only): {len(result['out_of_scope_urls'])}")
        if use_ast and ast_is_available():
            print(f"[+] Extraction: AST (tree-sitter) + regex")
        else:
            print(f"[+] Extraction: regex only")
        if result["secrets_found"]:
            print(f"[!] {len(result['secrets_found'])} unique potential secret(s) found — review manually!")
        if result.get("jwts_found"):
            print(f"[!] {len(result['jwts_found'])} unique JWT(s) found — run with --jwt to analyze")
        if result["source_maps_found"]:
            print(f"[!] {len(result['source_maps_found'])} exposed source map(s)")
        if result["deobfuscation_findings"]:
            print(f"[!] {len(result['deobfuscation_findings'])} obfuscated string(s) decoded")
        if result["sinks_found"]:
            print(f"[!] {len(result['sinks_found'])} dangerous sink pattern(s) found")
        if result["internal_hosts_found"]:
            print(f"[!] {len(result['internal_hosts_found'])} internal/private host reference(s) found")
        print(f"[+] Risk level: {result['risk_summary']['level']} (score: {result['risk_summary']['score']})")

    return result


def merge_results(static_result, browser_result):
    """
    Combine results from static scan and browser scan into a single unified report.
    Deduplicates endpoints, secrets, and source maps across both modes.
    """
    merged = {
        "target": static_result.get("target", browser_result.get("target")),
        "scan_mode": "full",
        "js_files_scanned": [],
        "inline_scripts_scanned": 0,
        "secrets_found": [],
        "jwts_found": [],
        "source_maps_found": [],
        "deobfuscation_findings": [],
        "sinks_found": [],
        "internal_hosts_found": [],
        "network_requests": [],
        "intercepted_endpoints": [],
        "errors": [],
        "scan_depth": static_result.get("scan_depth", 0)
    }

    seen_js = set()
    for js in static_result.get("js_files_scanned", []) + browser_result.get("js_files_scanned", []):
        if js not in seen_js:
            merged["js_files_scanned"].append(js)
            seen_js.add(js)

    merged["inline_scripts_scanned"] = (
        static_result.get("inline_scripts_scanned", 0) +
        browser_result.get("inline_scripts_scanned", 0)
    )

    seen_maps = set()
    for m in static_result.get("source_maps_found", []) + browser_result.get("source_maps_found", []):
        if m not in seen_maps:
            merged["source_maps_found"].append(m)
            seen_maps.add(m)

    merged["network_requests"] = browser_result.get("network_requests", [])
    merged["intercepted_endpoints"] = browser_result.get("intercepted_endpoints", [])

    all_endpoints = set()
    all_endpoints.update(static_result.get("internal_paths", []))
    all_endpoints.update(static_result.get("in_scope_urls", []))
    all_endpoints.update(static_result.get("out_of_scope_urls", []))
    all_endpoints.update(browser_result.get("internal_paths", []))
    all_endpoints.update(browser_result.get("in_scope_urls", []))
    all_endpoints.update(browser_result.get("out_of_scope_urls", []))

    target_domain = get_registrable_domain(merged["target"])
    merged["internal_paths"] = sorted([
        e for e in all_endpoints
        if e.startswith("/") and not e.startswith("//") and not is_static_asset(e)
    ])
    merged["in_scope_urls"] = sorted([
        e for e in all_endpoints if e.startswith("http") and is_same_scope(e, target_domain) and not is_static_asset(e)
    ])
    merged["out_of_scope_urls"] = sorted([
        e for e in all_endpoints if e.startswith("http") and not is_same_scope(e, target_domain) and not is_static_asset(e)
    ])

    all_secrets = []
    all_secrets.extend(static_result.get("secrets_found", []))
    all_secrets.extend(browser_result.get("secrets_found", []))

    seen_deobf = set()
    for d in static_result.get("deobfuscation_findings", []) + browser_result.get("deobfuscation_findings", []):
        key = (d.get("type"), d.get("decoded"))
        if key not in seen_deobf:
            merged["deobfuscation_findings"].append(d)
            seen_deobf.add(key)
    flat_secrets = []
    for s in all_secrets:
        for src in s.get("sources", [s.get("source", "unknown")]):
            flat_secrets.append({"type": s["type"], "match": s["match"], "source": src})
    merged["secrets_found"] = deduplicate_secrets(flat_secrets)

    all_jwts = []
    all_jwts.extend(static_result.get("jwts_found", []))
    all_jwts.extend(browser_result.get("jwts_found", []))
    merged["jwts_found"] = deduplicate_jwts(all_jwts)

    # Merge sinks and internal hosts
    all_sinks = []
    for s in static_result.get("sinks_found", []) + browser_result.get("sinks_found", []):
        for src in s.get("sources", [s.get("source", "unknown")]):
            all_sinks.append({"sink": s.get("sink", ""), "severity": s.get("severity", ""),
                              "description": s.get("description", ""), "count": s.get("count", 1),
                              "source": src})
    merged["sinks_found"] = deduplicate_sinks(all_sinks)

    seen_host = set()
    for h in static_result.get("internal_hosts_found", []) + browser_result.get("internal_hosts_found", []):
        key = h.get("match")
        if key and key not in seen_host:
            seen_host.add(key)
            merged["internal_hosts_found"].append(h)

    merged["errors"] = sorted(set(
        static_result.get("errors", []) + browser_result.get("errors", [])
    ))

    merged["risk_summary"] = calculate_risk_summary(merged)

    return merged
