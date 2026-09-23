"""
Pipeline stages — one function per logical step of a scan.

Each stage receives a ScanContext and mutates ctx.result (and may stash
intermediates such as ctx.wayback_result). Stages are pure moves of the
code that previously lived inline in main.py — no behavior change.
"""

from urllib.parse import urlparse

from modules.analysis import (
    get_live_endpoints,
    scan_for_libraries,
    validate_endpoints,
)
from modules.cors import collect_js_origins, scan_cors
from modules.discovery import crawl_spa_routes, get_wayback_endpoints
from modules.extraction import (
    calculate_risk_summary,
    is_static_asset,
    merge_results,
    run_extractor,
)
from modules.extraction.browser import run_browser_scan
from modules.jwt import analyze_result_jwts, deduplicate_jwts
from modules.pipeline.context import ScanContext
from modules.recon import detect_waf, get_scan_adjustments
from modules.reporting import export_burp_csv, export_zap_csv, save_html_report, save_report


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
    target_domain = urlparse(ctx.args.target).netloc
    ctx.wayback_result = get_wayback_endpoints(target_domain, limit=30, verbose=ctx.verbose)


def stage_scan(ctx: ScanContext) -> None:
    """Run the core scan: static, browser, or full (static + browser merged)."""
    args = ctx.args
    verbose = ctx.verbose

    if args.full:
        if verbose:
            print("[*] === FULL SCAN: Static + Browser mode ===\n")
            print("[*] --- Phase 1: Static scan ---")
        static_result = run_extractor(
            args.target, threads=args.threads, verbose=verbose,
            max_depth=args.depth, deobfuscate=not args.no_deobf,
            use_ast=not args.regex_only,
        )
        if verbose:
            print("\n[*] --- Phase 2: Browser scan ---")
        browser_result = run_browser_scan(
            args.target, timeout=args.timeout, verbose=verbose,
            scope_filter=args.scope,
        )
        ctx.result = merge_results(static_result, browser_result)
        if verbose:
            print("\n[*] --- Combined Results ---")
            print(f"[+] Total JS files: {len(ctx.result['js_files_scanned'])}")
            print(f"[+] Total internal paths: {len(ctx.result['internal_paths'])}")
            print(f"[+] Total intercepted endpoints: {len(ctx.result['intercepted_endpoints'])}")
            print(f"[+] Total secrets: {len(ctx.result['secrets_found'])}")
            print(f"[+] Risk: {ctx.result['risk_summary']['level']} (score: {ctx.result['risk_summary']['score']})")
    elif args.browser:
        ctx.result = run_browser_scan(
            args.target, timeout=args.timeout, verbose=verbose,
            scope_filter=args.scope,
        )
        ctx.result["scan_mode"] = "browser"
    else:
        ctx.result = run_extractor(
            args.target, threads=args.threads, verbose=verbose,
            max_depth=args.depth, deobfuscate=not args.no_deobf,
            use_ast=not args.regex_only,
        )
        ctx.result["scan_mode"] = "static"


def stage_wayback_merge(ctx: ScanContext) -> None:
    """Merge Wayback historical findings into the live scan result."""
    wb = ctx.wayback_result
    if not (wb and wb.get("endpoints")):
        return
    result = ctx.require_result()
    ctx.log("\n[*] Merging Wayback results...")
    before = len(result.get("internal_paths", []))
    new_paths = [
        e for e in wb["endpoints"]
        if e.startswith("/") and e not in result.get("internal_paths", [])
        and not is_static_asset(e)
    ]
    result["internal_paths"] = sorted(set(result.get("internal_paths", []) + new_paths))
    result["wayback_js_files"] = wb.get("js_files", [])
    for s in wb.get("secrets", []):
        result.setdefault("secrets_found", []).append(s)

    from modules.extraction import deduplicate_sinks
    for s in wb.get("sinks", []):
        result.setdefault("sinks_found", []).append(s)
    if result.get("sinks_found"):
        result["sinks_found"] = deduplicate_sinks(result["sinks_found"])
    seen_wb_host = {h.get("match") for h in result.get("internal_hosts_found", [])}
    for h in wb.get("internal_hosts", []):
        if h.get("match") not in seen_wb_host:
            seen_wb_host.add(h.get("match"))
            result.setdefault("internal_hosts_found", []).append(h)

    for j in wb.get("jwts", []):
        result.setdefault("jwts_found", []).append(j)
    if result.get("jwts_found"):
        result["jwts_found"] = deduplicate_jwts(result["jwts_found"])

    result["risk_summary"] = calculate_risk_summary(result)
    ctx.log(f"[+] Added {len(result['internal_paths']) - before} endpoint(s) from Wayback")


def stage_waf_inject(ctx: ScanContext) -> None:
    """Attach stashed WAF detection result to the scan result."""
    result = ctx.require_result()
    result["waf"] = (ctx.waf_info or {})


def stage_cve(ctx: ScanContext) -> None:
    """Library version detection + CVE/OSV lookup; boost risk score."""
    args = ctx.args
    result = ctx.require_result()
    ctx.log("\n[*] --- Library Version & CVE Detection ---")
    js_files = result.get("js_files_scanned", [])
    if not js_files:
        ctx.log("[*] No JS files to scan for libraries")
        return

    import requests as _requests
    content_map = {}
    for js_url in js_files:
        try:
            resp = _requests.get(js_url, timeout=10, headers={"User-Agent": "SurfaceSweep/1.0"})
            content_map[js_url] = resp.text
        except _requests.RequestException:
            pass

    lib_result = scan_for_libraries(
        js_files, content_map=content_map, use_osv=args.osv, verbose=ctx.verbose,
    )
    result["libraries"] = lib_result["libraries"]
    result["library_vulnerabilities"] = lib_result["vulnerabilities"]
    if lib_result["osv_results"]:
        result["osv_results"] = lib_result["osv_results"]

    if lib_result["vulnerabilities"]:
        vuln_score = sum(
            {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}.get(v["severity"], 5)
            for v in lib_result["vulnerabilities"]
        )
        result["risk_summary"]["score"] += vuln_score
        score = result["risk_summary"]["score"]
        if score >= 30:
            result["risk_summary"]["level"] = "HIGH"
        elif score >= 10:
            result["risk_summary"]["level"] = "MEDIUM"
        elif score > 0:
            result["risk_summary"]["level"] = "LOW"
        ctx.log(f"[+] Risk boosted by {vuln_score} points from CVE findings")


def stage_spa(ctx: ScanContext) -> None:
    """Discover SPA routes and merge them into the result."""
    args = ctx.args
    result = ctx.require_result()
    ctx.log("\n[*] --- SPA Route Discovery ---")
    spa_result = crawl_spa_routes(
        args.target, timeout=args.timeout, verbose=ctx.verbose,
        max_routes=args.max_routes, probe_common=not args.no_probe,
        scope_filter=args.scope,
    )
    result["spa_routes"] = spa_result["routes"]
    result["spa_routes_from"] = spa_result["routes_from"]
    if spa_result["api_endpoints"]:
        result.setdefault("intercepted_endpoints", [])
        for url in spa_result["api_endpoints"]:
            if not any(e.get("url") == url for e in result["intercepted_endpoints"]):
                result["intercepted_endpoints"].append({"url": url, "method": "GET"})

    before = len(result.get("internal_paths", []))
    new_routes = [
        r for r in spa_result["routes"]
        if r not in result.get("internal_paths", [])
    ]
    result["internal_paths"] = sorted(set(result.get("internal_paths", []) + new_routes))
    result["risk_summary"] = calculate_risk_summary(result)
    ctx.log(f"[+] Added {len(result['internal_paths']) - before} route(s) from SPA discovery")


def stage_cors(ctx: ScanContext) -> None:
    """Probe discovered endpoints for CORS misconfigurations."""
    args = ctx.args
    result = ctx.require_result()
    cors_endpoints = list(set(
        result.get("internal_paths", []) +
        result.get("in_scope_urls", []) +
        [e.get("url") for e in result.get("intercepted_endpoints", []) if e.get("url")]
    ))
    if not cors_endpoints:
        ctx.log("[*] No endpoints to CORS-test")
        return
    js_origins = collect_js_origins(result, args.target)
    if ctx.verbose and js_origins:
        ctx.log(f"[*] CORS extra origins from scan: {', '.join(js_origins)}")
    result["cors"] = scan_cors(
        cors_endpoints, args.target,
        custom_origin=args.cors_origin, max_endpoints=args.cors_max,
        threads=args.cors_threads, timeout=args.cors_timeout,
        verbose=ctx.verbose,
        headers=ctx.headers if ctx.headers else None,
        rate_limit=args.cors_rps, extra_origins=js_origins,
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
    """Validate discovered endpoints; filter dead false positives from paths."""
    args = ctx.args
    result = ctx.require_result()
    ctx.log("\n[*] --- Endpoint Validation ---")
    all_endpoints = list(set(
        result.get("internal_paths", []) +
        result.get("in_scope_urls", []) +
        [e.get("url") for e in result.get("intercepted_endpoints", []) if e.get("url")]
    ))
    if not all_endpoints:
        ctx.log("[*] No endpoints to validate")
        return

    validation = validate_endpoints(
        all_endpoints, args.target,
        threads=args.vt, timeout=args.vtimeout, verbose=ctx.verbose,
        headers=ctx.headers if ctx.headers else None,
    )
    result["validation"] = validation

    target_base = f"{urlparse(args.target).scheme}://{urlparse(args.target).netloc}"
    result["internal_paths"] = sorted(set(
        r["url"].replace(target_base, "").rstrip("/") or "/"
        for r in get_live_endpoints(validation)
        if r["url"].startswith(target_base) and not is_static_asset(r["url"])
    ))
    result["risk_summary"] = calculate_risk_summary(result)
    dead = len(validation.get("dead", []))
    if ctx.verbose and dead:
        ctx.log(f"[+] Filtered out {dead} false positive(s)")


def stage_export(ctx: ScanContext) -> None:
    """Write Burp/ZAP CSVs (when requested)."""
    args = ctx.args
    result = ctx.require_result()
    if args.burp:
        base = args.output.replace(".json", "") if args.output.endswith(".json") else args.output
        export_burp_csv(result, f"{base}_burp.csv")
    if args.zap:
        base = args.output.replace(".json", "") if args.output.endswith(".json") else args.output
        export_zap_csv(result, f"{base}_zap.csv")


def stage_report(ctx: ScanContext) -> None:
    """Save JSON and/or HTML reports."""
    args = ctx.args
    result = ctx.require_result()
    if not args.html_only:
        save_report(result, args.output)
    if args.html or args.html_only:
        html_path = (
            args.output.replace(".json", ".html")
            if args.output.endswith(".json")
            else args.output + ".html"
        )
        save_html_report(result, html_path)
