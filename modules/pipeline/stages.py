"""
Pipeline stages — one function per logical step of a scan.

Each stage receives a ScanContext and mutates ctx.result (and may stash
intermediates such as ctx.wayback_result). Stages are pure moves of the
code that previously lived inline in main.py — no behavior change.
"""

from urllib.parse import urlparse

from modules.analysis import (
    scan_for_libraries,
    validate_endpoints,
)
from modules.analysis.validator import build_method_map
from modules.common.console import emit, ok
from modules.cors import collect_js_origins, scan_cors
from modules.discovery import (
    crawl_spa_routes,
    discover_robots_and_sitemap,
    get_wayback_endpoints,
    probe_graphql_endpoints,
    collect_graphql_candidates,
)
from modules.extraction import (
    calculate_risk_summary,
    is_static_asset,
    merge_results,
    run_extractor,
    verify_secrets,
)
from modules.extraction.browser import run_browser_scan
from modules.extraction.scope import normalize_scope_filter
from modules.jwt import analyze_result_jwts
from modules.pipeline.context import ScanContext
from modules.pipeline.merge import (
    collect_endpoints,
    merge_endpoints,
    merge_wayback,
)
from modules.recon import detect_waf, get_scan_adjustments
from modules.reporting import build_report_plan, write_reports


def stage_waf_detect(ctx: ScanContext) -> None:
    """Detect WAF before the main scan; stash info for later injection."""
    ctx.log("[*] --- WAF Detection ---")
    ctx.waf_info = detect_waf(ctx.args.target, verbose=ctx.verbose)
    ctx.waf_adjustments = get_scan_adjustments(ctx.waf_info)
    if ctx.verbose and ctx.waf_info.get("detected"):
        ctx.log(f"[*] Scan adjustments: {ctx.waf_adjustments['recommendation']}")


def stage_wayback_fetch(ctx: ScanContext) -> None:
    """Prefetch historical JS endpoints from the Wayback Machine."""
    ctx.log("\n[*] --- Wayback Machine ---")
    host = urlparse(ctx.args.target).hostname or ""
    # Skip non-routable / local hosts — archive.org has nothing useful for them
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or host.startswith("127.") or host.startswith("192.168."):
        ctx.log(f"[*] Skipping Wayback for local/private host: {host}")
        ctx.wayback_result = {"js_files": [], "endpoints": set(), "secrets": [], "sinks": [], "internal_hosts": [], "jwts": [], "pii": [], "params": [], "errors": []}
        return
    target_domain = urlparse(ctx.args.target).netloc
    ctx.wayback_result = get_wayback_endpoints(target_domain, limit=30, verbose=ctx.verbose)


def stage_scan(ctx: ScanContext) -> None:
    """Run the core scan: static, browser, or full (static + browser merged)."""
    args = ctx.args
    verbose = ctx.verbose
    scope = normalize_scope_filter(args.scope)
    deobf = not getattr(args, "no_deobf", False)
    browser_kwargs = dict(
        scope_filter=scope,
        deobfuscate_content=deobf,
        user_agent=getattr(args, "ua", None),
        insecure=not getattr(args, "verify_tls", True),
        proxy=getattr(args, "proxy", None),
    )

    if args.full:
        if verbose:
            emit("[*] === FULL SCAN: Static + Browser mode ===\n")
            emit("[*] --- Phase 1: Static scan ---")
        static_result = run_extractor(
            args.target, threads=args.threads, verbose=verbose,
            max_depth=args.depth, deobfuscate=deobf,
            use_ast=not args.regex_only,
        )
        if verbose:
            emit("\n[*] --- Phase 2: Browser scan ---")
        browser_result = run_browser_scan(
            args.target, timeout=args.timeout, verbose=verbose,
            **browser_kwargs,
        )
        ctx.result = merge_results(static_result, browser_result)
        if verbose:
            emit("\n[*] --- Combined Results ---")
            ok(f"Total JS files: {len(ctx.result['js_files_scanned'])}")
            ok(f"Total internal paths: {len(ctx.result['internal_paths'])}")
            ok(f"Total intercepted endpoints: {len(ctx.result['intercepted_endpoints'])}")
            ok(f"Total secrets: {len(ctx.result['secrets_found'])}")
            ok(f"Risk: {ctx.result['risk_summary']['level']} (score: {ctx.result['risk_summary']['score']})")
    elif args.browser:
        ctx.result = run_browser_scan(
            args.target, timeout=args.timeout, verbose=verbose,
            **browser_kwargs,
        )
        ctx.result["scan_mode"] = "browser"
    else:
        ctx.result = run_extractor(
            args.target, threads=args.threads, verbose=verbose,
            max_depth=args.depth, deobfuscate=deobf,
            use_ast=not args.regex_only,
        )
        ctx.result["scan_mode"] = "static"

    _merge_robots_sitemap(ctx)


def _merge_robots_sitemap(ctx: ScanContext) -> None:
    """Pull paths from robots.txt / sitemap.xml into the live result."""
    if ctx.result is None:
        return
    result = ctx.require_result()
    discovery = discover_robots_and_sitemap(
        ctx.args.target,
        timeout=getattr(ctx.args, "timeout", 10) or 10,
        verbose=ctx.verbose,
    )
    endpoints = list(discovery.get("paths") or []) + list(discovery.get("urls") or [])
    if not endpoints:
        return
    before = len(result.get("internal_paths", []))
    added = merge_endpoints(result, endpoints, ctx.args.target)
    if added:
        result["risk_summary"] = calculate_risk_summary(result)
        if ctx.verbose:
            net = len(result.get("internal_paths", [])) - before
            ctx.log(f"[+] robots/sitemap: +{added} endpoint(s) (+{net} path(s))")


def stage_wayback_merge(ctx: ScanContext) -> None:
    """Merge Wayback historical findings into the live scan result."""
    wb = ctx.wayback_result
    if wb is None:
        return
    result = ctx.require_result()
    ctx.log("\n[*] Merging Wayback results...")
    before_paths = len(result.get("internal_paths", []))
    stats = merge_wayback(result, wb, ctx.args.target)
    result["risk_summary"] = calculate_risk_summary(result)
    ctx.log(
        f"[+] Wayback merge: +{stats['paths']} path(s), +{stats['urls']} URL(s), "
        f"+{stats['secrets']} secret(s) ({len(result.get('internal_paths', [])) - before_paths} net path(s))"
    )


def stage_waf_inject(ctx: ScanContext) -> None:
    """Attach stashed WAF detection result (and adjustments) to the scan result."""
    result = ctx.require_result()
    result["waf"] = dict(ctx.waf_info or {})
    if ctx.waf_adjustments:
        result["waf"]["adjustments"] = ctx.waf_adjustments


def stage_cve(ctx: ScanContext) -> None:
    """Library version detection + CVE/OSV lookup; boost risk score."""
    args = ctx.args
    result = ctx.require_result()
    ctx.log("\n[*] --- Library Version & CVE Detection ---")
    js_files = result.get("js_files_scanned", [])
    if not js_files:
        ctx.log("[*] No JS files to scan for libraries")
        return

    from modules.extraction.http import fetch_text
    content_map = {}
    for js_url in js_files:
        text = fetch_text(js_url, timeout=10)
        if text is not None:
            content_map[js_url] = text

    lib_result = scan_for_libraries(
        js_files, content_map=content_map, use_osv=args.osv, verbose=ctx.verbose,
    )
    result["libraries"] = lib_result["libraries"]
    result["library_vulnerabilities"] = lib_result["vulnerabilities"]
    if lib_result["osv_results"]:
        result["osv_results"] = lib_result["osv_results"]

    # CVE boost is applied inside calculate_risk_summary (Step 3) so later
    # recalculations (SPA/validation/wayback) no longer wipe it.
    before = result.get("risk_summary", {}).get("score", 0)
    result["risk_summary"] = calculate_risk_summary(result)
    delta = result["risk_summary"]["score"] - before
    if delta:
        ctx.log(f"[+] Risk boosted by {delta} points from CVE findings")


def stage_spa(ctx: ScanContext) -> None:
    """Discover SPA routes and merge them into the result."""
    args = ctx.args
    result = ctx.require_result()
    ctx.log("\n[*] --- SPA Route Discovery ---")
    spa_result = crawl_spa_routes(
        args.target, timeout=args.timeout, verbose=ctx.verbose,
        max_routes=args.max_routes, probe_common=not args.no_probe,
        scope_filter=normalize_scope_filter(args.scope),
    )
    result["spa_routes"] = spa_result["routes"]
    result["spa_routes_from"] = spa_result["routes_from"]
    if spa_result["api_endpoints"]:
        result.setdefault("intercepted_endpoints", [])
        for url in spa_result["api_endpoints"]:
            if not any(e.get("url") == url for e in result["intercepted_endpoints"]):
                result["intercepted_endpoints"].append({"url": url, "method": "GET"})
        from modules.extraction.enrich import enrich_intercepted_endpoints
        enrich_intercepted_endpoints(result["intercepted_endpoints"])

    # Same static-asset filter as wayback merge (parity)
    before = len(result.get("internal_paths", []))
    merge_endpoints(result, spa_result["routes"], args.target)
    result["risk_summary"] = calculate_risk_summary(result)
    ctx.log(f"[+] Added {len(result.get('internal_paths', [])) - before} route(s) from SPA discovery")


def stage_cors(ctx: ScanContext) -> None:
    """Probe discovered endpoints for CORS misconfigurations."""
    args = ctx.args
    result = ctx.require_result()
    cors_endpoints = collect_endpoints(result, target=args.target)
    if not cors_endpoints:
        ctx.log("[*] No endpoints to CORS-test")
        return
    js_origins = collect_js_origins(result, args.target)
    if ctx.verbose and js_origins:
        ctx.log(f"[*] CORS extra origins from scan: {', '.join(js_origins)}")

    rate_limit = args.cors_rps
    threads = args.cors_threads
    headers = dict(ctx.headers) if ctx.headers else None

    # Apply WAF pacing: slower RPS, fewer threads, WAF-friendly UA
    if ctx.waf_adjustments:
        delay = float(ctx.waf_adjustments.get("delay_multiplier") or 1.0)
        if delay > 1.0 and rate_limit and rate_limit > 0:
            rate_limit = max(0.2, rate_limit / delay)
        max_threads = ctx.waf_adjustments.get("max_threads")
        if max_threads:
            threads = min(int(threads), int(max_threads))
        waf_ua = ctx.waf_adjustments.get("user_agent")
        if waf_ua:
            headers = headers or {}
            headers["User-Agent"] = waf_ua
        if ctx.verbose and delay > 1.0:
            ctx.log(
                f"[*] CORS rate adjusted for WAF: {rate_limit:.2f} rps, "
                f"{threads} thread(s)"
            )

    result["cors"] = scan_cors(
        cors_endpoints, args.target,
        custom_origin=args.cors_origin, max_endpoints=args.cors_max,
        threads=threads, timeout=args.cors_timeout,
        verbose=ctx.verbose,
        headers=headers,
        rate_limit=rate_limit, extra_origins=js_origins,
    )
    result["risk_summary"] = calculate_risk_summary(result)
    if ctx.verbose and result["risk_summary"]["score"]:
        ctx.log(
            f"[+] Risk: {result['risk_summary']['level']} "
            f"(score: {result['risk_summary']['score']}) including CORS boost"
        )


def stage_jwt(ctx: ScanContext) -> None:
    """Analyze JWTs found in scan results."""
    args = ctx.args
    result = ctx.require_result()
    result["jwt"] = analyze_result_jwts(
        result, verbose=ctx.verbose,
        wordlist_path=args.jwt_wordlist, target=args.target,
        hashcat_path=args.jwt_hashcat, export_path=args.jwt_export,
        network=args.jwt_network, network_timeout=args.jwt_network_timeout,
    )
    result["risk_summary"] = calculate_risk_summary(result)
    if ctx.verbose:
        ctx.log(
            f"[+] Risk: {result['risk_summary']['level']} "
            f"(score: {result['risk_summary']['score']}) including JWT boost"
        )


def stage_validate(ctx: ScanContext) -> None:
    """
    Validate discovered endpoints and annotate results.

    Annotates path_status / internal_paths_discovered instead of
    destructively replacing internal_paths. Only confirmed-dead paths are
    removed from the active pool; timeouts and connection errors stay so
    they remain available for CORS and reporting.
    """
    args = ctx.args
    result = ctx.require_result()
    ctx.log("\n[*] --- Endpoint Validation ---")
    all_endpoints = collect_endpoints(result, target=args.target)
    if not all_endpoints:
        ctx.log("[*] No endpoints to validate")
        return

    method_map = build_method_map(
        all_endpoints, result.get("intercepted_endpoints") or []
    )
    validation = validate_endpoints(
        all_endpoints, args.target,
        threads=args.vt, timeout=args.vtimeout, verbose=ctx.verbose,
        headers=ctx.headers if ctx.headers else None,
        method_map=method_map,
    )
    result["validation"] = validation

    target_base = f"{urlparse(args.target).scheme}://{urlparse(args.target).netloc}"

    def _to_path(url: str):
        if not url:
            return None
        if url.startswith(target_base):
            rest = url[len(target_base):]
            return rest.split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"
        if url.startswith("/") and not url.startswith("//"):
            return url.split("?", 1)[0].split("#", 1)[0]
        return None

    # path -> {status, note?, status_code?} for every validated endpoint
    path_status: dict = {}
    for bucket, items in validation.items():
        for r in items:
            p = _to_path(r.get("url", ""))
            if p is None or p in path_status:
                continue
            entry = {"status": bucket}
            if r.get("note"):
                entry["note"] = r["note"]
            if r.get("status_code") is not None:
                entry["status_code"] = r["status_code"]
            path_status[p] = entry
    result["path_status"] = path_status

    discovered = list(result.get("internal_paths") or [])
    result["internal_paths_discovered"] = discovered

    dead_paths = set()
    for r in validation.get("dead", []):
        p = _to_path(r.get("url", ""))
        if p:
            dead_paths.add(p)

    result["internal_paths"] = sorted(
        p for p in discovered if p not in dead_paths
    )
    result["risk_summary"] = calculate_risk_summary(result)

    dead = len(validation.get("dead", []))
    if ctx.verbose and dead:
        unverified = sum(
            1 for p in discovered
            if path_status.get(p, {}).get("status") in ("timeout", "connection_error", "error")
        )
        msg = f"[+] Filtered out {dead} confirmed-dead endpoint(s)"
        if unverified:
            msg += f"; {unverified} unverified (timeout/error) kept in pool"
        ctx.log(msg)


def stage_graphql(ctx: ScanContext) -> None:
    """
    Probe candidate GraphQL endpoints for open introspection (Phase F3).

    Runs after validate so path_status can prefer live endpoints. Writes
    result["graphql"] and recomputes risk_summary.
    """
    args = ctx.args
    result = ctx.require_result()
    ctx.log("\n[*] --- GraphQL Introspection Probe ---")
    candidates = collect_graphql_candidates(result, args.target)
    if not candidates:
        ctx.log("[*] No GraphQL-like endpoints to probe")
        result["graphql"] = {
            "endpoints": [],
            "findings": [],
            "endpoints_tested": 0,
            "introspection_open": 0,
            "summary": {"endpoints_tested": 0, "introspection_open": 0},
        }
        result["risk_summary"] = calculate_risk_summary(result)
        return

    gql = probe_graphql_endpoints(
        candidates,
        timeout=getattr(args, "graphql_timeout", 5.0),
        verbose=ctx.verbose,
        headers=ctx.headers if ctx.headers else None,
    )
    result["graphql"] = gql
    result["risk_summary"] = calculate_risk_summary(result)
    if ctx.verbose:
        n = gql.get("introspection_open", 0)
        tested = gql.get("endpoints_tested", 0)
        if n:
            ctx.log(f"[!] {n}/{tested} endpoint(s) expose GraphQL introspection")
        else:
            ctx.log(f"[*] {tested} endpoint(s) probed — no open introspection")


def stage_verify_secrets(ctx: ScanContext) -> None:
    """
    Live-verify extracted secrets against vendor APIs (Phase F4, opt-in).

    Read-only GETs only; runs after validate (path_status not required).
    Writes result["secret_verification"] and recomputes risk_summary.
    """
    args = ctx.args
    result = ctx.require_result()
    secrets = result.get("secrets_found") or []
    ctx.log("\n[*] --- Secret Verification ---")
    if not secrets:
        ctx.log("[*] No secrets to verify")
        result["secret_verification"] = {
            "results": [], "findings": [], "secrets_checked": 0,
            "confirmed": 0, "rejected": 0, "errors": 0, "skipped": 0,
            "summary": {"secrets_checked": 0, "confirmed": 0,
                        "rejected": 0, "errors": 0, "skipped": 0},
        }
        result["risk_summary"] = calculate_risk_summary(result)
        return

    verification = verify_secrets(
        secrets,
        timeout=getattr(args, "verify_secrets_timeout", 5.0),
        verbose=ctx.verbose,
        headers=ctx.headers if ctx.headers else None,
    )
    result["secret_verification"] = verification
    result["risk_summary"] = calculate_risk_summary(result)
    if ctx.verbose:
        n = verification.get("confirmed", 0)
        checked = verification.get("secrets_checked", 0)
        if n:
            ctx.log(f"[!] {n}/{checked} secret(s) confirmed live")
        else:
            ctx.log(f"[*] {checked} secret(s) probed — none confirmed")


def stage_export(ctx: ScanContext) -> None:
    """Write Burp/ZAP CSVs and optional CORS PoC (when requested)."""
    args = ctx.args
    result = ctx.require_result()
    plan = build_report_plan(args)
    write_reports(
        result, args.output,
        write_json=False, write_html=False,
        write_burp=plan["write_burp"], write_zap=plan["write_zap"],
        write_cors_poc=plan["write_cors_poc"],
        write_sarif=False,
        write_wordlist=False,
        verbose=ctx.verbose,
    )


def stage_report(ctx: ScanContext) -> None:
    """Save JSON, HTML, SARIF, and optional wordlist via the unified report builder."""
    args = ctx.args
    result = ctx.require_result()
    plan = build_report_plan(args)
    write_reports(
        result, args.output,
        write_json=plan["write_json"], write_html=plan["write_html"],
        write_burp=False, write_zap=False,
        write_sarif=plan["write_sarif"],
        write_wordlist=plan.get("write_wordlist", False),
        wordlist_path=plan.get("wordlist_path"),
        verbose=ctx.verbose,
    )
