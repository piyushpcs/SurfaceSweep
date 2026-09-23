"""
SurfaceSweep CLI entry point.

Arg parsing + header assembly live here; all scan orchestration runs
through modules.pipeline.run_pipeline (Phase 4 Step 1).
"""

import argparse

from modules.pipeline import run_pipeline


def build_parser() -> argparse.ArgumentParser:
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
    parser.add_argument("--cors-threads", type=int, default=6, help="CORS probe threads (default: 6)")
    parser.add_argument("--cors-timeout", type=float, default=5.0, help="CORS per-request timeout seconds (default: 5)")
    parser.add_argument("--jwt", action="store_true", help="Analyze JWTs found in scanned content (alg/none, weak HMAC, exp, claims)")
    parser.add_argument("--jwt-wordlist", default=None, metavar="FILE", help="Extra newline-delimited secrets for offline HS* cracking")
    parser.add_argument("--jwt-hashcat", default=None, metavar="FILE", help="Export HS* JWTs to FILE in hashcat mode 16500 format")
    parser.add_argument("--jwt-export", default=None, metavar="FILE", help="Write per-token JWT findings as NDJSON to FILE")
    parser.add_argument("--jwt-network", action="store_true", help="Fetch jku/x5u JWKS over network for RS256→HS256 key-confusion checks (SSRF-guarded)")
    parser.add_argument("--jwt-network-timeout", type=float, default=5.0, help="JWKS fetch timeout seconds when --jwt-network is set (default: 5)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    return parser


def build_headers(args: argparse.Namespace) -> dict:
    headers = {}
    if args.cookie:
        headers["Cookie"] = args.cookie
    for h in args.header:
        if ":" in h:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    verbose = not args.quiet
    headers = build_headers(args)
    return run_pipeline(args, verbose=verbose, headers=headers)


if __name__ == "__main__":
    main()
