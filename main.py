import argparse
from urllib.parse import urlparse
from modules.extraction import (
    run_extractor, merge_results, calculate_risk_summary,
    is_static_asset, save_report, save_html_report
)
from modules.extraction.browser import run_browser_scan
from modules.analysis import validate_endpoints, get_live_endpoints, scan_for_libraries
from modules.reporting import export_burp_csv, export_zap_csv
from modules.discovery import get_wayback_endpoints, crawl_spa_routes
from modules.recon import detect_waf, get_scan_adjustments
from modules.cors import scan_cors, cors_risk_boost
from modules.jwt_analyzer import analyze_result_jwts, jwt_risk_boost


def main():
    parser = argparse.ArgumentParser(description="SurfaceSweep — JS Endpoint Extractor")
    parser.add_argument("target", help="Target URL, e.g. https://example.com")
    parser.add_argument("-o", "--output", default="reports/surfacesweep_report.json", help="Output JSON file")
    parser.add_argument("-t", "--threads", type=int, default=6, help="Concurrent fetch threads")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Recursive JS depth (0=HTML only, 1=JS from HTML, 2=JS from JS, ...)")
    parser.add_argument("-b", "--browser", action="store_true", help="Use headless browser mode (captures runtime API calls)")
    parser.add_argument("-f", "--full", action="store_true", help="Run both static + browser and merge results (best coverage)")
    parser.add_argument("--validate", action="store_true", help="Validate discovered endpoints to filter false positives")
    parser.add_argument("--vt", "--validate-threads", type=int, default=10, help="Concurrent validation threads (default: 10)")
    parser.add_argument("--vtimeout", type=int, default=5, help="Validation request timeout in seconds (default: 5)")
    parser.add_argument("--timeout", type=int, default=30, help="Browser page load timeout in seconds (default: 30)")
    parser.add_argument("--scope", default=None, help="Limit results to this domain (e.g. '*.target.com')")
    parser.add_argument("--cookie", default=None, help="Cookie header for authenticated scans (e.g. 'session=abc123')")
    parser.add_argument("--header", action="append", default=[], help="Custom header (can repeat: -H 'X-Api-Key: value')")
    parser.add_argument("--burp", action="store_true", help="Export endpoints as Burp Suite CSV")
    parser.add_argument("--zap", action="store_true", help="Export endpoints as OWASP ZAP CSV")
    parser.add_argument("--wayback", action="store_true", help="Include historical JS files from Wayback Machine")
    parser.add_argument("--waf", action="store_true", help="Detect WAF and adjust scan speed")
    parser.add_argument("--cve", action="store_true", help="Detect JS library versions and check local CVE database")
    parser.add_argument("--osv", action="store_true", help="Query OSV.dev for additional CVEs (requires network)")
    parser.add_argument("--spa", action="store_true", help="Discover SPA routes (React/Vue/Angular routers)")
    parser.add_argument("--max-routes", type=int, default=50, help="Max routes to crawl in SPA mode (default: 50)")
    parser.add_argument("--no-probe", action="store_true", help="Skip probing common admin/debug routes in SPA mode")
    parser.add_argument("--html", action="store_true", help="Also generate an HTML report")
    parser.add_argument("--html-only", action="store_true", help="Generate HTML report only (skip JSON)")
    parser.add_argument("--no-deobf", action="store_true", help="Skip JS deobfuscation")
    parser.add_argument("--regex-only", action="store_true", help="Disable AST extraction, use regex only")
    parser.add_argument("--cors", action="store_true", help="Scan discovered endpoints for CORS misconfigurations")
    parser.add_argument("--cors-origin", default=None, help="Custom Origin header to test (default: built-in test set)")
    parser.add_argument("--cors-max", type=int, default=50, help="Max endpoints to CORS-test (default: 50)")
    parser.add_argument("--cors-rps", type=float, default=5.0, help="CORS probe rate limit, requests/sec (default: 5, 0=unlimited)")
    parser.add_argument("--jwt", action="store_true", help="Analyze JWTs found in scanned content (alg/none, weak HMAC, exp, claims)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args()

    verbose = not args.quiet

    custom_headers = {}
    if args.cookie:
        custom_headers["Cookie"] = args.cookie
    for h in args.header:
        if ":" in h:
            key, value = h.split(":", 1)
            custom_headers[key.strip()] = value.strip()

    # WAF Detection (before scan)
    if args.waf:
        if verbose:
            print("[*] --- WAF Detection ---")
        waf_info = detect_waf(args.target, verbose=verbose)
        result_waf = {"waf": waf_info}
        adjustments = get_scan_adjustments(waf_info)
        if verbose and waf_info.get("detected"):
            print(f"[*] Scan adjustments: {adjustments['recommendation']}")

    # Wayback Machine integration
    if args.wayback:
        if verbose:
            print(f"\n[*] --- Wayback Machine ---")
        target_domain = urlparse(args.target).netloc
        wayback_result = get_wayback_endpoints(target_domain, limit=30, verbose=verbose)
    else:
        wayback_result = None

    # Main scan
    if args.full:
        if verbose:
            print("[*] === FULL SCAN: Static + Browser mode ===\n")

        if verbose:
            print("[*] --- Phase 1: Static scan ---")
        static_result = run_extractor(args.target, threads=args.threads, verbose=verbose, max_depth=args.depth, deobfuscate=not args.no_deobf, use_ast=not args.regex_only)

        if verbose:
            print(f"\n[*] --- Phase 2: Browser scan ---")
        browser_result = run_browser_scan(args.target, timeout=args.timeout, verbose=verbose, scope_filter=args.scope)

        result = merge_results(static_result, browser_result)

        if verbose:
            print(f"\n[*] --- Combined Results ---")
            print(f"[+] Total JS files: {len(result['js_files_scanned'])}")
            print(f"[+] Total internal paths: {len(result['internal_paths'])}")
            print(f"[+] Total intercepted endpoints: {len(result['intercepted_endpoints'])}")
            print(f"[+] Total secrets: {len(result['secrets_found'])}")
            print(f"[+] Risk: {result['risk_summary']['level']} (score: {result['risk_summary']['score']})")

    elif args.browser:
        result = run_browser_scan(
            args.target,
            timeout=args.timeout,
            verbose=verbose,
            scope_filter=args.scope
        )
        result["scan_mode"] = "browser"
    else:
        result = run_extractor(args.target, threads=args.threads, verbose=verbose, max_depth=args.depth, deobfuscate=not args.no_deobf, use_ast=not args.regex_only)
        result["scan_mode"] = "static"

    # Merge Wayback results
    if wayback_result and wayback_result.get("endpoints"):
        if verbose:
            print(f"\n[*] Merging Wayback results...")
        before = len(result.get("internal_paths", []))
        new_paths = [
            e for e in wayback_result["endpoints"]
            if e.startswith("/") and e not in result.get("internal_paths", []) and not is_static_asset(e)
        ]
        result["internal_paths"] = sorted(set(result.get("internal_paths", []) + new_paths))
        result["wayback_js_files"] = wayback_result.get("js_files", [])
        for s in wayback_result.get("secrets", []):
            result.setdefault("secrets_found", []).append(s)

        # Merge wayback sinks and internal hosts
        from modules.extraction import deduplicate_sinks
        for s in wayback_result.get("sinks", []):
            result.setdefault("sinks_found", []).append(s)
        if result.get("sinks_found"):
            result["sinks_found"] = deduplicate_sinks(result["sinks_found"])
        seen_wb_host = {h.get("match") for h in result.get("internal_hosts_found", [])}
        for h in wayback_result.get("internal_hosts", []):
            if h.get("match") not in seen_wb_host:
                seen_wb_host.add(h.get("match"))
                result.setdefault("internal_hosts_found", []).append(h)

        # Recalculate risk after adding Wayback endpoints
        result["risk_summary"] = calculate_risk_summary(result)
        if verbose:
            print(f"[+] Added {len(result['internal_paths']) - before} endpoint(s) from Wayback")

    # WAF info into result
    if args.waf:
        result["waf"] = result_waf.get("waf", {})

    # Library version detection and CVE check
    if args.cve or args.osv:
        if verbose:
            print(f"\n[*] --- Library Version & CVE Detection ---")
        js_files = result.get("js_files_scanned", [])
        if js_files:
            # Fetch contents for content-based detection
            import requests as _requests
            content_map = {}
            for js_url in js_files:
                try:
                    resp = _requests.get(js_url, timeout=10, headers={"User-Agent": "SurfaceSweep/1.0"})
                    content_map[js_url] = resp.text
                except _requests.RequestException:
                    pass

            lib_result = scan_for_libraries(
                js_files,
                content_map=content_map,
                use_osv=args.osv,
                verbose=verbose,
            )
            result["libraries"] = lib_result["libraries"]
            result["library_vulnerabilities"] = lib_result["vulnerabilities"]
            if lib_result["osv_results"]:
                result["osv_results"] = lib_result["osv_results"]

            # Boost risk score for vulnerabilities found
            if lib_result["vulnerabilities"]:
                vuln_score = sum(
                    {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}.get(v["severity"], 5)
                    for v in lib_result["vulnerabilities"]
                )
                result["risk_summary"]["score"] += vuln_score
                # Recompute level
                score = result["risk_summary"]["score"]
                if score >= 30:
                    result["risk_summary"]["level"] = "HIGH"
                elif score >= 10:
                    result["risk_summary"]["level"] = "MEDIUM"
                elif score > 0:
                    result["risk_summary"]["level"] = "LOW"
                if verbose:
                    print(f"[+] Risk boosted by {vuln_score} points from CVE findings")
        elif verbose:
            print("[*] No JS files to scan for libraries")

    # SPA Route Discovery
    if args.spa:
        if verbose:
            print(f"\n[*] --- SPA Route Discovery ---")
        spa_result = crawl_spa_routes(
            args.target,
            timeout=args.timeout,
            verbose=verbose,
            max_routes=args.max_routes,
            probe_common=not args.no_probe,
            scope_filter=args.scope,
        )
        result["spa_routes"] = spa_result["routes"]
        result["spa_routes_from"] = spa_result["routes_from"]
        if spa_result["api_endpoints"]:
            result.setdefault("intercepted_endpoints", [])
            for url in spa_result["api_endpoints"]:
                if not any(e.get("url") == url for e in result["intercepted_endpoints"]):
                    result["intercepted_endpoints"].append({"url": url, "method": "GET"})

        # Merge SPA routes into internal_paths
        before = len(result.get("internal_paths", []))
        new_routes = [
            r for r in spa_result["routes"]
            if r not in result.get("internal_paths", [])
        ]
        result["internal_paths"] = sorted(set(result.get("internal_paths", []) + new_routes))
        result["risk_summary"] = calculate_risk_summary(result)
        if verbose:
            print(f"[+] Added {len(result['internal_paths']) - before} route(s) from SPA discovery")

    # CORS misconfiguration scan
    if args.cors:
        cors_endpoints = list(set(
            result.get("internal_paths", []) +
            result.get("in_scope_urls", []) +
            [e.get("url") for e in result.get("intercepted_endpoints", []) if e.get("url")]
        ))
        if cors_endpoints:
            cors_result = scan_cors(
                cors_endpoints,
                args.target,
                custom_origin=args.cors_origin,
                max_endpoints=args.cors_max,
                verbose=verbose,
                headers=custom_headers if custom_headers else None,
                rate_limit=args.cors_rps,
            )
            result["cors"] = cors_result
            boost = cors_risk_boost(cors_result)
            if boost:
                result["risk_summary"]["score"] += boost
                score = result["risk_summary"]["score"]
                if score >= 30:
                    result["risk_summary"]["level"] = "HIGH"
                elif score >= 10:
                    result["risk_summary"]["level"] = "MEDIUM"
                elif score > 0:
                    result["risk_summary"]["level"] = "LOW"
                if verbose:
                    print(f"[+] Risk boosted by {boost} points from CORS findings")
        elif verbose:
            print("[*] No endpoints to CORS-test")

    # JWT security analysis
    if args.jwt:
        jwt_result = analyze_result_jwts(result, verbose=verbose)
        result["jwt"] = jwt_result
        boost = jwt_risk_boost(jwt_result)
        if boost:
            result["risk_summary"]["score"] += boost
            score = result["risk_summary"]["score"]
            if score >= 30:
                result["risk_summary"]["level"] = "HIGH"
            elif score >= 10:
                result["risk_summary"]["level"] = "MEDIUM"
            elif score > 0:
                result["risk_summary"]["level"] = "LOW"
            if verbose:
                print(f"[+] Risk boosted by {boost} points from JWT findings")

    # Validation
    if args.validate:
        if verbose:
            print(f"\n[*] --- Endpoint Validation ---")

        all_endpoints = list(set(
            result.get("internal_paths", []) +
            result.get("in_scope_urls", []) +
            [e.get("url") for e in result.get("intercepted_endpoints", []) if e.get("url")]
        ))

        if all_endpoints:
            validation = validate_endpoints(
                all_endpoints,
                args.target,
                threads=args.vt,
                timeout=args.vtimeout,
                verbose=verbose,
                headers=custom_headers if custom_headers else None
            )
            result["validation"] = validation

            # Filter to only live/restricted endpoints
            target_base = f"{urlparse(args.target).scheme}://{urlparse(args.target).netloc}"
            result["internal_paths"] = sorted(set(
                r["url"].replace(target_base, "").rstrip("/") or "/"
                for r in get_live_endpoints(validation)
                if r["url"].startswith(target_base) and not is_static_asset(r["url"])
            ))

            # Recalculate risk after validation filtering
            result["risk_summary"] = calculate_risk_summary(result)

            if verbose:
                dead = len(validation.get("dead", []))
                if dead:
                    print(f"[+] Filtered out {dead} false positive(s)")
        else:
            if verbose:
                print("[*] No endpoints to validate")

    # Exports
    if args.burp:
        base = args.output.replace(".json", "") if args.output.endswith(".json") else args.output
        export_burp_csv(result, f"{base}_burp.csv")

    if args.zap:
        base = args.output.replace(".json", "") if args.output.endswith(".json") else args.output
        export_zap_csv(result, f"{base}_zap.csv")

    if not args.html_only:
        save_report(result, args.output)

    if args.html or args.html_only:
        html_path = args.output.replace(".json", ".html") if args.output.endswith(".json") else args.output + ".html"
        save_html_report(result, html_path)


if __name__ == "__main__":
    main()
