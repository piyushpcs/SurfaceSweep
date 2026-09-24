"""
CORS scan orchestration: endpoint prioritization, aggregation, concurrency.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests

from modules.common.console import detail, info, ok, warn
from modules.cors.classifier import SEVERITY_ORDER, parse_acao_list
from modules.cors.origins import (
    MAX_TRUSTED_SEEDS,
    build_seed_lookalikes,
    build_test_origins,
    normalize_origin,
    origins_equal,
)
from modules.cors.probe import is_reflected_acao, probe_baseline, probe_endpoint
from modules.extraction.http import RateLimiter
from modules.extraction.scope import get_registrable_domain

STATIC_EXTENSIONS = (
    ".js", ".mjs", ".cjs", ".map", ".css", ".png", ".jpg", ".jpeg", ".svg",
    ".gif", ".webp", ".woff", ".woff2", ".ico", ".html", ".htm", ".txt",
    ".xml", ".pdf", ".zip",
)

# Paths where a simple GET may not surface CORS — worth a POST fallback
API_PATH_HINTS = (
    "/api/", "/api", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/",
    "/auth/", "/oauth/", "/webhook", "/rpc/", "/json/", "/post-only",
)

# Higher score = probe first when max_endpoints truncates the list
PRIORITY_HINTS = (
    ("/api/", 100),
    ("/auth", 90),
    ("/oauth", 90),
    ("/login", 85),
    ("/session", 85),
    ("/admin", 85),
    ("/graphql", 85),
    ("/webhook", 80),
    ("/rpc/", 80),
    ("/v1/", 75),
    ("/v2/", 75),
    ("/v3/", 75),
    ("/rest/", 75),
)


def is_api_like_path(url):
    """True when the path looks like an API endpoint (POST fallback candidate)."""
    path = url.split("?")[0].split("#")[0].lower()
    return any(hint in path for hint in API_PATH_HINTS)


def endpoint_priority(url, base_url=None):
    """
    Sort key score for CORS probing (higher = more interesting).
    API/auth paths rank above static/marketing pages.
    """
    path = urlparse(url).path.lower() if "://" in url else url.lower()
    score = 0
    for hint, weight in PRIORITY_HINTS:
        if hint in path:
            score = max(score, weight)
    if is_api_like_path(url):
        score = max(score, 70)
    # Same-host absolute URLs beat cross-host noise when tied
    if base_url and url.startswith("http"):
        base_host = (urlparse(base_url).hostname or "").lower()
        url_host = (urlparse(url).hostname or "").lower()
        if base_host and url_host == base_host:
            score += 5
    # Fewer path segments → broader surface, slight preference
    segments = [s for s in path.split("/") if s]
    score += max(0, 10 - len(segments))
    return score


def resolve_endpoints(endpoints, base_url, max_endpoints=50):
    """
    Resolve paths/URLs to absolute URLs, drop static assets,
    prioritize API-like endpoints, then cap at max_endpoints.
    """
    resolved = []
    seen = set()
    for ep in endpoints:
        if not ep:
            continue
        if ep.startswith("http"):
            url = ep
        elif ep.startswith("/"):
            url = urljoin(base_url, ep)
        else:
            url = urljoin(base_url + "/", ep)

        clean = url.split("?")[0].split("#")[0].lower()
        if any(clean.endswith(ext) for ext in STATIC_EXTENSIONS):
            continue
        if url not in seen:
            seen.add(url)
            resolved.append(url)

    resolved.sort(key=lambda u: (-endpoint_priority(u, base_url), u))
    return resolved[:max_endpoints]


def collect_js_origins(result, base_url, limit=8):
    """
    Origins the target's own JS/scan already references (API hosts, CDNs).
    Added to the probe matrix so overly-broad allowlists of first-party
    or partner origins are tested alongside attacker origins.
    """
    target_n = normalize_origin(base_url)
    target_host = (urlparse(target_n).hostname or "").lower()
    candidates = []

    buckets = [
        result.get("in_scope_urls") or [],
        result.get("out_of_scope_urls") or [],
        [e.get("url") for e in (result.get("intercepted_endpoints") or []) if e.get("url")],
        result.get("js_files_scanned") or [],
    ]
    for bucket in buckets:
        for raw in bucket:
            if not raw or not isinstance(raw, str) or not raw.startswith("http"):
                continue
            parsed = urlparse(raw)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                continue
            host = parsed.hostname.lower()
            if host == target_host:
                continue
            origin = f"{parsed.scheme}://{host}"
            if parsed.port and parsed.port not in (80, 443):
                origin = f"{origin}:{parsed.port}"
            if origin != target_n:
                candidates.append(origin)

    seen = set()
    ordered = []
    for o in candidates:
        if o not in seen:
            seen.add(o)
            ordered.append(o)
    return ordered[:limit]


def aggregate_findings(raw_findings):
    """
    Collapse probe rows to one finding per URL (worst severity wins).

    Keeps representative fields from the worst-severity probe and records
    every origin that triggered at least one flag on that URL.
    """
    by_url = {}
    for f in raw_findings:
        url = f.get("url") or ""
        sev = f.get("severity") or "INFO"
        if sev == "INFO" and not f.get("acao"):
            continue
        if sev == "INFO":
            continue
        current = by_url.get(url)
        if current is None:
            item = dict(f)
            item["origins_flagged"] = [f.get("origin", "")]
            item["methods"] = [f.get("method", "")]
            item["probe_hits"] = 1
            by_url[url] = item
            continue
        current["probe_hits"] = current.get("probe_hits", 1) + 1
        origin = f.get("origin", "")
        if origin and origin not in current["origins_flagged"]:
            current["origins_flagged"].append(origin)
        method = f.get("method", "")
        if method and method not in current["methods"]:
            current["methods"].append(method)
        # Worst severity wins (SEVERITY_ORDER: lower = worse)
        if SEVERITY_ORDER.get(sev, 9) < SEVERITY_ORDER.get(current["severity"], 9):
            keep_origins = current["origins_flagged"]
            keep_methods = current["methods"]
            keep_hits = current["probe_hits"]
            current.clear()
            current.update(f)
            current["origins_flagged"] = keep_origins
            current["methods"] = keep_methods
            current["probe_hits"] = keep_hits
        elif sev == current["severity"]:
            # Same severity: prefer the most specific detail/acao sample
            if not current.get("acao") and f.get("acao"):
                for key in ("acao", "acac", "detail", "evidence", "method", "origin"):
                    if f.get(key):
                        current[key] = f[key]

    aggregated = list(by_url.values())
    aggregated.sort(
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f.get("url") or "")
    )
    return aggregated


def scan_cors(
    endpoints,
    base_url,
    custom_origin=None,
    max_endpoints=50,
    threads=6,
    timeout=5,
    verbose=True,
    headers=None,
    rate_limit=5,
    extra_origins=None,
    aggregate=True,
):
    """
    Scan discovered endpoints for CORS misconfigurations.

    Args:
        endpoints: list of paths or absolute URLs to test
        base_url: base URL for resolving relative paths (also = legitimate origin)
        custom_origin: optional extra Origin to test first
        max_endpoints: cap after API-first prioritization
        threads: concurrent probe threads
        timeout: per-request timeout seconds
        verbose: print progress
        headers: extra request headers (cookies etc.)
        rate_limit: max requests/sec across probes (0 disables)
        extra_origins: additional Origins (e.g. hosts seen in scanned JS)
        aggregate: collapse findings to one row per URL (worst severity)

    Returns dict with findings, endpoints_tested, origins, severity_counts.
    """
    resolved = resolve_endpoints(endpoints, base_url, max_endpoints)
    origins = build_test_origins(base_url, custom_origin)
    if extra_origins:
        for o in extra_origins:
            if o and o not in origins and o != normalize_origin(base_url):
                origins.append(o)
    target_origin = normalize_origin(base_url)

    registrable_domain = None
    try:
        registrable_domain = get_registrable_domain(base_url)
    except Exception:
        registrable_domain = None

    limiter = RateLimiter(rate_limit) if rate_limit and rate_limit > 0 else None

    if verbose:
        info(" --- CORS Scan ---")
        info(f" Testing {len(resolved)} endpoint(s) with {len(origins)} origin(s)")
        info(f" Target origin: {target_origin}")
        info(f" Origins: {', '.join(origins)}")
        if resolved:
            top = resolved[0]
            info(f" First (highest priority): {top}")

    raw_findings = []
    error_probes = 0
    session = requests.Session()
    from modules.extraction.http import RelaxedTLSAdapter, request_kwargs
    session.mount("https://", RelaxedTLSAdapter())
    # Apply process-wide insecure/proxy config — this session bypasses
    # request_tls, so without this every probe fails on bad-cert hosts.
    cfg = request_kwargs(headers=None)
    if cfg.get("verify") is False:
        session.verify = False
    if cfg.get("proxies"):
        session.proxies.update(cfg["proxies"])
    baselines = {}
    urls_with_acao = set()
    trusted_seeds = set()

    def _record_trusted(row):
        """Collect static/third-party ACAO seeds (not reflection, not target)."""
        acao = (row.get("acao") or "").strip()
        if not acao or acao in ("*", "null"):
            return
        probe_origin = row.get("origin") or ""
        for item in parse_acao_list(acao):
            if item in ("*", "null"):
                continue
            if origins_equal(item, probe_origin):
                continue  # pure reflection — matrix already covers
            if target_origin and origins_equal(item, target_origin):
                continue  # legitimate target allowlist
            if is_reflected_acao(probe_origin, item) and origins_equal(
                item, probe_origin
            ):
                continue
            norm = normalize_origin(item)
            if norm and norm not in ("", "null", "*"):
                trusted_seeds.add(norm)

    def _probe(url, method, request_method="GET", static_acao=False, origin_list=None):
        return probe_endpoint(
            url,
            origin_list if origin_list is not None else origins,
            timeout=timeout,
            method=method,
            headers=headers,
            limiter=limiter,
            target_origin=target_origin,
            registrable_domain=registrable_domain,
            request_method=request_method,
            static_acao=static_acao,
            session=session,
        )

    def _has_finding_acao(results):
        """True when any row is a real misconfig (not INFO / bare ERROR)."""
        return any(
            r.get("acao") and r.get("severity") not in ("INFO", "ERROR")
            for r in results
        )

    def _scan_one(url):
        baseline = probe_baseline(
            url, timeout=timeout, headers=headers, limiter=limiter, session=session
        )
        baselines[url] = baseline
        static_acao = bool(baseline.get("static_acao"))

        # Escalate only when no *finding-worthy* ACAO on preflight.
        # A legitimate target-origin ACAO on OPTIONS must not suppress GET.
        opt_results = _probe(url, "OPTIONS", static_acao=static_acao)
        if _has_finding_acao(opt_results):
            return url, opt_results, baseline

        get_results = _probe(url, "GET", static_acao=static_acao)
        if _has_finding_acao(get_results):
            return url, get_results, baseline

        # API-like paths often only expose CORS on non-simple requests
        if is_api_like_path(url):
            post_results = _probe(
                url, "POST", request_method="POST", static_acao=static_acao
            )
            if _has_finding_acao(post_results):
                return url, post_results, baseline
            return url, get_results, baseline

        return url, get_results, baseline

    def _ingest(url, results):
        for r in results:
            _record_trusted(r)
            if r.get("acao"):
                urls_with_acao.add(url)
            if r["severity"] == "ERROR":
                nonlocal error_probes
                error_probes += 1
                continue
            if r["severity"] == "INFO":
                continue
            finding = dict(r)
            finding["url"] = url
            raw_findings.append(finding)

    try:
        with ThreadPoolExecutor(max_workers=max(1, int(threads))) as pool:
            futures = {pool.submit(_scan_one, url): url for url in resolved}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    scanned_url, results, _baseline = future.result()
                except Exception:
                    error_probes += 1
                    continue
                _ingest(scanned_url, results)

        # --- Trusted-seed second pass -------------------------------------
        seed_origins = []
        for seed in sorted(trusted_seeds)[:MAX_TRUSTED_SEEDS]:
            for look in build_seed_lookalikes(seed):
                if look not in origins and look not in seed_origins:
                    seed_origins.append(look)
        seed_urls = sorted(urls_with_acao)
        if seed_origins and seed_urls:
            if verbose:
                info(
                    f"Trusted-seed re-probe: {len(seed_origins)} origin(s) "
                    f"on {len(seed_urls)} URL(s)"
                )

            def _scan_seeds(url):
                static_acao = bool((baselines.get(url) or {}).get("static_acao"))
                opt_results = _probe(
                    url, "OPTIONS", static_acao=static_acao, origin_list=seed_origins
                )
                if _has_finding_acao(opt_results):
                    return url, opt_results
                get_results = _probe(
                    url, "GET", static_acao=static_acao, origin_list=seed_origins
                )
                return url, get_results

            with ThreadPoolExecutor(max_workers=max(1, int(threads))) as pool:
                futures = {pool.submit(_scan_seeds, url): url for url in seed_urls}
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        scanned_url, results = future.result()
                    except Exception:
                        error_probes += 1
                        continue
                    _ingest(scanned_url, results)
    finally:
        session.close()

    if aggregate:
        findings = aggregate_findings(raw_findings)
        if verbose:
            for f in findings:
                origins_list = ", ".join(f.get("origins_flagged") or [f.get("origin", "")])
                detail(
                    f"[!] {f['severity']:8s} {f['url'][:70]} "
                    f"origins={origins_list[:80]} ACAO={f.get('acao', '')}"
                )
    else:
        findings = sorted(
            raw_findings,
            key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f.get("url") or ""),
        )
        if verbose:
            for f in findings:
                detail(
                    f"[!] {f['severity']:8s} {f['url'][:70]} "
                    f"origin={f.get('origin', '')} ACAO={f.get('acao', '')}"
                )

    severity_counts = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
    if error_probes:
        severity_counts["ERROR"] = error_probes

    if verbose:
        crit = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)
        med = severity_counts.get("MEDIUM", 0)
        err = severity_counts.get("ERROR", 0)
        ok(
            f"CORS findings: {crit} critical, {high} high, {med} medium "
            f"({len(findings)} URL(s) flagged"
            + (f", {len(raw_findings)} probe hits" if aggregate else "")
            + (f", {err} probe errors" if err else "")
            + ")"
        )
        if crit:
            warn("CRITICAL: reflected origin + credentials — data theft possible")

    summary = {
        "urls_flagged": len(findings),
        "endpoints_tested": len(resolved),
        "origins_probed": len(origins),
        "probe_hits": len(raw_findings),
        "severity_counts": dict(severity_counts),
        "aggregated": bool(aggregate),
    }
    if error_probes:
        summary["error_probes"] = error_probes

    return {
        "schema_version": 1,
        "findings": findings,
        "probe_hits": len(raw_findings),
        "endpoints_tested": len(resolved),
        "target_origin": target_origin,
        "origins": origins,
        "severity_counts": severity_counts,
        "summary": summary,
    }


def cors_risk_boost(cors_result):
    """Return risk points to add based on CORS findings severity."""
    counts = (cors_result or {}).get("severity_counts", {})
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    return sum(counts.get(sev, 0) * w for sev, w in weights.items())
