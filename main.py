import argparse
from modules.extractor import run_extractor, save_report, save_html_report
from modules.browser_extractor import run_browser_scan


def main():
    parser = argparse.ArgumentParser(description="SurfaceSweep — JS Endpoint Extractor")
    parser.add_argument("target", help="Target URL, e.g. https://example.com")
    parser.add_argument("-o", "--output", default="reports/surfacesweep_report.json", help="Output JSON file")
    parser.add_argument("-t", "--threads", type=int, default=6, help="Concurrent fetch threads")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Recursive JS depth (0=HTML only, 1=JS from HTML, 2=JS from JS, ...)")
    parser.add_argument("-b", "--browser", action="store_true", help="Use headless browser mode (captures runtime API calls)")
    parser.add_argument("--timeout", type=int, default=30, help="Browser page load timeout in seconds (default: 30)")
    parser.add_argument("--scope", default=None, help="Limit results to this domain (e.g. '*.target.com')")
    parser.add_argument("--html", action="store_true", help="Also generate an HTML report")
    parser.add_argument("--html-only", action="store_true", help="Generate HTML report only (skip JSON)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args()

    if args.browser:
        result = run_browser_scan(
            args.target,
            timeout=args.timeout,
            verbose=not args.quiet,
            scope_filter=args.scope
        )
    else:
        result = run_extractor(args.target, threads=args.threads, verbose=not args.quiet, max_depth=args.depth)

    result["scan_mode"] = "browser" if args.browser else "static"

    if not args.html_only:
        save_report(result, args.output)

    if args.html or args.html_only:
        html_path = args.output.replace(".json", ".html") if args.output.endswith(".json") else args.output + ".html"
        save_html_report(result, html_path)


if __name__ == "__main__":
    main()
