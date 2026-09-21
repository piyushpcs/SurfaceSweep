import argparse
from modules.extractor import run_extractor, save_report, save_html_report, merge_results
from modules.browser_extractor import run_browser_scan


def main():
    parser = argparse.ArgumentParser(description="SurfaceSweep — JS Endpoint Extractor")
    parser.add_argument("target", help="Target URL, e.g. https://example.com")
    parser.add_argument("-o", "--output", default="reports/surfacesweep_report.json", help="Output JSON file")
    parser.add_argument("-t", "--threads", type=int, default=6, help="Concurrent fetch threads")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Recursive JS depth (0=HTML only, 1=JS from HTML, 2=JS from JS, ...)")
    parser.add_argument("-b", "--browser", action="store_true", help="Use headless browser mode (captures runtime API calls)")
    parser.add_argument("-f", "--full", action="store_true", help="Run both static + browser and merge results (best coverage)")
    parser.add_argument("--timeout", type=int, default=30, help="Browser page load timeout in seconds (default: 30)")
    parser.add_argument("--scope", default=None, help="Limit results to this domain (e.g. '*.target.com')")
    parser.add_argument("--html", action="store_true", help="Also generate an HTML report")
    parser.add_argument("--html-only", action="store_true", help="Generate HTML report only (skip JSON)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args()

    verbose = not args.quiet

    if args.full:
        if verbose:
            print("[*] === FULL SCAN: Static + Browser mode ===\n")

        if verbose:
            print("[*] --- Phase 1: Static scan ---")
        static_result = run_extractor(args.target, threads=args.threads, verbose=verbose, max_depth=args.depth)

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
        result = run_extractor(args.target, threads=args.threads, verbose=verbose, max_depth=args.depth)
        result["scan_mode"] = "static"

    if not args.html_only:
        save_report(result, args.output)

    if args.html or args.html_only:
        html_path = args.output.replace(".json", ".html") if args.output.endswith(".json") else args.output + ".html"
        save_html_report(result, html_path)


if __name__ == "__main__":
    main()
