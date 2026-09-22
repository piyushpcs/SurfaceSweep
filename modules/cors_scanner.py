"""
CORS misconfiguration scanner for SurfaceSweep.

Sends spoofed Origin headers to discovered endpoints (OPTIONS + GET)
and classifies responses by severity based on reflected/wildcard origins
and Access-Control-Allow-Credentials.
"""

import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

USER_AGENT = "SurfaceSweep/1.0"

# Test origins (evil.com is never a real target origin)
def build_test_origins(target_url, custom_origin=None):
    """Build list of Origin values to probe."""
    parsed = urlparse(target_url)
    host = parsed.hostname or "example.com"
    parts = host.split(".")
    registrable = ".".join(parts[-2:]) if len(parts) >= 2 else host

    origins = [
        "https://evil.com",
        "https://attacker.example",
        f"https://sub.{registrable}",
        f"https://{registrable}.evil.com",
        f"https://{registrable}",
        "null",
    ]
    if custom_origin:
        # Put custom origin first so it's always tested
        origins.insert(0, custom_origin)
    # de-dupe preserving order
    seen = set()
    ordered = []
    for o in origins:
        if o not in seen:
            seen.add(o)
            ordered.append(o)
    return ordered


def classify_cors(origin, acao, acac, target_origin):
    """
    Classify a single CORS probe result.

    Severity ladder (highest first):
      CRITICAL: reflected origin + Allow-Credentials: true
      HIGH:     reflected origin (no credentials) OR wildcard + credentials
      MEDIUM:   wildcard origin (no credentials) OR null origin allowed
      LOW:      origin prefix/suffix match (partial trust)
      INFO:     origin not reflected / properly restricted
    """
    if not acao:
        return "INFO", "No Access-Control-Allow-Origin header"

    acao = acao.strip()
    reflected = acao == origin or acao == "*"
    is_wildcard = acao == "*"
    creds = (acac or "").strip().lower() == "true"
    null_allowed = acao == "null" and origin == "null"

    # Subdomain / suffix tricks: evil.com vs registrable.com
    partial = False
    if not reflected and not is_wildcard:
        # e.g. acao=https://target.com.evil.com when origin=https://evil.com
        if origin.endswith(acao.replace("https://", "")) or acao.replace("https://", "").endswith(
            origin.replace("https://", "")
        ):
            partial = True

    if (acao == origin or null_allowed) and creds:
        return "CRITICAL", f"Reflected origin with credentials (ACAO={acao}, ACAC=true)"
    if acao == origin:
        return "HIGH", f"Origin reflected (ACAO={acao})"
    if is_wildcard and creds:
        return "HIGH", "Wildcard ACAO with Allow-Credentials: true"
    if is_wildcard:
        return "MEDIUM", "Wildcard ACAO (*)"
    if null_allowed:
        return "MEDIUM", "Null origin allowed"
    if partial:
        return "LOW", f"Partial origin match (ACAO={acao})"
    return "INFO", f"Origin not allowed (ACAO={acao})"


def probe_endpoint(url, origins, timeout=8, method="OPTIONS", headers=None, limiter=None):
    """
    Send one request with each test Origin and collect CORS headers.
    Returns list of {origin, acao, acac, status, severity, detail}.
    """
    results = []
    base_headers = {"User-Agent": USER_AGENT}
    if headers:
        base_headers.update(headers)

    for origin in origins:
        if limiter:
            limiter.wait()
        req_headers = dict(base_headers)
        req_headers["Origin"] = origin
        try:
            resp = requests.request(
                method,
                url,
                timeout=timeout,
                headers=req_headers,
                allow_redirects=False,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            severity, detail = classify_cors(origin, acao, acac, origin)
            results.append({
                "origin": origin,
                "method": method,
                "status": resp.status_code,
                "acao": acao,
                "acac": acac,
                "severity": severity,
                "detail": detail,
            })
        except requests.RequestException as e:
            results.append({
                "origin": origin,
                "method": method,
                "status": None,
                "acao": "",
                "acac": "",
                "severity": "ERROR",
                "detail": str(e),
            })
    return results


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "ERROR": 5}


def scan_cors(endpoints, base_url, custom_origin=None, max_endpoints=50,
              threads=6, timeout=8, verbose=True, headers=None):
    """
    Scan discovered endpoints for CORS misconfigurations.

    Args:
        endpoints: list of paths or absolute URLs to test
        base_url: base URL for resolving relative paths
        custom_origin: optional extra Origin to test
        max_endpoints: cap on number of endpoints probed (default 50)
        threads: concurrent probe threads
        timeout: per-request timeout
        verbose: print progress
        headers: extra request headers (cookies etc.)

    Returns dict:
        {
          "findings": [ {url, origin, method, status, acao, acac, severity, detail}, ... ],
          "endpoints_tested": int,
          "severity_counts": {CRITICAL: n, ...},
        }
    """
    # Resolve endpoints to absolute URLs
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
        # skip static assets
        clean = url.split("?")[0].split("#")[0].lower()
        if any(clean.endswith(ext) for ext in (
            ".js", ".mjs", ".cjs", ".map", ".css", ".png", ".jpg", ".svg",
            ".gif", ".woff", ".woff2", ".ico", ".html", ".htm",
        )):
            continue
        if url not in seen:
            seen.add(url)
            resolved.append(url)

    resolved = resolved[:max_endpoints]
    origins = build_test_origins(base_url, custom_origin)

    if verbose:
        print(f"[*] --- CORS Scan ---")
        print(f"[*] Testing {len(resolved)} endpoint(s) with {len(origins)} origin(s)")
        print(f"[*] Origins: {', '.join(origins)}")

    findings = []

    def _scan_one(url):
        # Prefer OPTIONS (preflight), fall back to GET for endpoints that reject OPTIONS
        opt_results = probe_endpoint(url, origins, timeout=timeout,
                                     method="OPTIONS", headers=headers)
        # If OPTIONS returned no ACAO at all for any origin, also try GET
        if not any(r["acao"] for r in opt_results):
            get_results = probe_endpoint(url, origins, timeout=timeout,
                                         method="GET", headers=headers)
            # Keep whichever produced ACAO headers; if both empty keep OPTIONS
            if any(r["acao"] for r in get_results):
                return url, get_results
        return url, opt_results

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_one, url): url for url in resolved}
        for future in as_completed(futures):
            url, results = future.result()
            for r in results:
                if r["severity"] in ("INFO", "ERROR") and not r["acao"]:
                    continue  # skip boring no-header noise unless it's a finding
                finding = dict(r)
                finding["url"] = url
                findings.append(finding)
                if verbose and r["severity"] not in ("INFO", "ERROR"):
                    print(f"    [!] {r['severity']:8s} {url[:70]} origin={r['origin']} ACAO={r['acao']}")

    # Sort by severity
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["url"]))

    severity_counts = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    if verbose:
        crit = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)
        med = severity_counts.get("MEDIUM", 0)
        print(f"[+] CORS findings: {crit} critical, {high} high, {med} medium "
              f"({len(findings)} total flagged)")
        if crit:
            print(f"[!] CRITICAL: reflected origin + credentials — data theft possible")

    return {
        "findings": findings,
        "endpoints_tested": len(resolved),
        "origins": origins,
        "severity_counts": severity_counts,
    }


def cors_risk_boost(cors_result):
    """Return risk points to add based on CORS findings severity."""
    counts = (cors_result or {}).get("severity_counts", {})
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    return sum(counts.get(sev, 0) * w for sev, w in weights.items())
