import argparse
from urllib.parse import urlparse
from modules.extractor import run_extractor, save_report, save_html_report, merge_results, calculate_risk_summary, is_static_asset
from modules.browser_extractor import run_browser_scan
from modules.validator import validate_endpoints, get_live_endpoints
from modules.export import export_burp_csv, export_zap_csv
from modules.wayback import get_wayback_endpoints
from modules.waf import detect_waf, get_scan_adjustments


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
    parser.add_argument("--html", action="store_true", help="Also generate an HTML report")
    parser.add_argument("--html-only", action="store_true", help="Generate HTML report only (skip JSON)")
    parser.add_argument("--no-deobf", action="store_true", help="Skip JS deobfuscation")
    parser.add_argument("--regex-only", action="store_true", help="Disable AST extraction, use regex only")
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
        # Recalculate risk after adding Wayback endpoints
        result["risk_summary"] = calculate_risk_summary(result)
        if verbose:
            print(f"[+] Added {len(result['internal_paths']) - before} endpoint(s) from Wayback")

    # WAF info into result
    if args.waf:
        result["waf"] = result_waf.get("waf", {})

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
