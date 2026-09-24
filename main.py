"""
SurfaceSweep CLI entry point.

Arg parsing + header assembly live here; all scan orchestration runs
through modules.pipeline.run_pipeline (Phase 4 Step 1).
"""

import argparse
import sys

from modules import __version__
from modules.extraction.http import configure_http
from modules.pipeline import run_pipeline

# Exit codes for scripting/CI:
#   0 — success, findings below --fail-on (or --fail-on not set)
#   1 — findings at or above --fail-on severity
#   2 — usage error (argparse default)
#   3 — unexpected runtime error
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3

_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SurfaceSweep — JS Endpoint Extractor",
        epilog=(
            "Exit codes: 0 success, 1 findings at/above --fail-on, "
            "2 usage error, 3 runtime error"
        ),
    )
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
    parser.add_argument("--cors-poc", action="store_true", help="Write standalone CORS PoC HTML next to the report")
    parser.add_argument("--jwt", action="store_true", help="Analyze JWTs found in scanned content (alg/none, weak HMAC, exp, claims)")
    parser.add_argument("--jwt-wordlist", default=None, metavar="FILE", help="Extra newline-delimited secrets for offline HS* cracking")
    parser.add_argument("--jwt-hashcat", default=None, metavar="FILE", help="Export HS* JWTs to FILE in hashcat mode 16500 format")
    parser.add_argument("--jwt-export", default=None, metavar="FILE", help="Write per-token JWT findings as NDJSON to FILE")
    parser.add_argument("--jwt-network", action="store_true", help="Fetch jku/x5u JWKS over network for RS256→HS256 key-confusion checks (SSRF-guarded)")
    parser.add_argument("--jwt-network-timeout", type=float, default=5.0, help="JWKS fetch timeout seconds when --jwt-network is set (default: 5)")
    parser.add_argument("--proxy", default=None, metavar="URL", help="HTTP(S) proxy for all scan requests (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--ua", default=None, metavar="STRING", help="Custom User-Agent for HTTP requests")
    parser.add_argument(
        "--fail-on",
        dest="fail_on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="Exit 1 when any finding is at/above this severity (default: none)",
    )
    parser.add_argument("--version", action="version", version=f"SurfaceSweep {__version__}")
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
    if args.ua:
        headers["User-Agent"] = args.ua
    return headers


def exit_code_for_result(result, fail_on: str) -> int:
    """Map scan findings + --fail-on to a process exit code."""
    if not fail_on or fail_on == "none":
        return EXIT_OK
    threshold = _SEVERITY_RANK[fail_on.upper()]
    counts = (result or {}).get("risk_summary", {}).get("severity_counts") or {}
    # Prefer explicit severity buckets when present; fall back to risk level.
    if counts:
        for sev, n in counts.items():
            if n and _SEVERITY_RANK.get(sev.upper(), -1) >= threshold:
                return EXIT_FINDINGS
        return EXIT_OK
    level = (result or {}).get("risk_summary", {}).get("level", "INFO")
    if _SEVERITY_RANK.get(str(level).upper(), -1) >= threshold:
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    verbose = not args.quiet
    headers = build_headers(args)
    # Browser always tolerates bad certs by default; --insecure applies to requests.
    args.verify_tls = not args.insecure
    configure_http(proxy=args.proxy, insecure=args.insecure, user_agent=args.ua)
    try:
        result = run_pipeline(args, verbose=verbose, headers=headers)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"[!] Scan failed: {exc}", file=sys.stderr)
        if verbose:
            import traceback
            traceback.print_exc()
        return EXIT_ERROR
    return exit_code_for_result(result, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
