"""
CORS scan orchestration: endpoint resolution, concurrency, risk boost.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from modules.cors.classifier import SEVERITY_ORDER
from modules.cors.origins import build_test_origins, normalize_origin
from modules.cors.probe import probe_endpoint
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


def is_api_like_path(url):
    """True when the path looks like an API endpoint (POST fallback candidate)."""
    path = url.split("?")[0].split("#")[0].lower()
    return any(hint in path for hint in API_PATH_HINTS)


def resolve_endpoints(endpoints, base_url, max_endpoints=50):
    """Resolve paths/URLs to absolute URLs, drop static assets, cap count."""
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
    return resolved[:max_endpoints]


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
):
    """
    Scan discovered endpoints for CORS misconfigurations.

    Args:
        endpoints: list of paths or absolute URLs to test
        base_url: base URL for resolving relative paths (also = legitimate origin)
        custom_origin: optional extra Origin to test
        max_endpoints: cap on number of endpoints probed
        threads: concurrent probe threads
        timeout: per-request timeout
        verbose: print progress
        headers: extra request headers (cookies etc.)
        rate_limit: max requests/sec across probes (0 disables)

    Returns dict with findings, endpoints_tested, origins, severity_counts.
    """
    resolved = resolve_endpoints(endpoints, base_url, max_endpoints)
    origins = build_test_origins(base_url, custom_origin)
    target_origin = normalize_origin(base_url)

    registrable_domain = None
    try:
        registrable_domain = get_registrable_domain(base_url)
    except Exception:
        registrable_domain = None

    limiter = RateLimiter(rate_limit) if rate_limit and rate_limit > 0 else None

    if verbose:
        print("[*] --- CORS Scan ---")
        print(f"[*] Testing {len(resolved)} endpoint(s) with {len(origins)} origin(s)")
        print(f"[*] Target origin: {target_origin}")
        print(f"[*] Origins: {', '.join(origins)}")

    findings = []

    def _probe(url, method, request_method="GET"):
        return probe_endpoint(
            url,
            origins,
            timeout=timeout,
            method=method,
            headers=headers,
            limiter=limiter,
            target_origin=target_origin,
            registrable_domain=registrable_domain,
            request_method=request_method,
        )

    def _scan_one(url):
        opt_results = _probe(url, "OPTIONS")
        if any(r["acao"] for r in opt_results):
            return url, opt_results

        get_results = _probe(url, "GET")
        if any(r["acao"] for r in get_results):
            return url, get_results

        # API-like paths often only expose CORS on non-simple requests
        if is_api_like_path(url):
            post_results = _probe(url, "POST", request_method="POST")
            if any(r["acao"] for r in post_results):
                return url, post_results
            # Merge POST errors into GET noise only if GET had nothing
            return url, get_results

        return url, get_results

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_one, url): url for url in resolved}
        for future in as_completed(futures):
            url, results = future.result()
            for r in results:
                if r["severity"] in ("INFO", "ERROR") and not r["acao"]:
                    continue
                if r["severity"] == "INFO":
                    continue  # expected / not-allowed — not a finding
                finding = dict(r)
                finding["url"] = url
                findings.append(finding)
                if verbose:
                    print(
                        f"    [!] {r['severity']:8s} {url[:70]} "
                        f"origin={r['origin']} ACAO={r['acao']}"
                    )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["url"]))

    severity_counts = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    if verbose:
        crit = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)
        med = severity_counts.get("MEDIUM", 0)
        print(
            f"[+] CORS findings: {crit} critical, {high} high, {med} medium "
            f"({len(findings)} total flagged)"
        )
        if crit:
            print("[!] CRITICAL: reflected origin + credentials — data theft possible")

    return {
        "findings": findings,
        "endpoints_tested": len(resolved),
        "target_origin": target_origin,
        "origins": origins,
        "severity_counts": severity_counts,
    }


def cors_risk_boost(cors_result):
    """Return risk points to add based on CORS findings severity."""
    counts = (cors_result or {}).get("severity_counts", {})
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    return sum(counts.get(sev, 0) * w for sev, w in weights.items())
