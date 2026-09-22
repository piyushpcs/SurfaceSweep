"""
HTTP probing for CORS misconfigurations (preflight + simple requests).
"""

import requests

from modules.cors.classifier import classify_cors

USER_AGENT = "SurfaceSweep/1.0"

# Realistic browser preflight headers
PREFLIGHT_ACRM = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
PREFLIGHT_ACRH = "content-type, authorization, x-requested-with"


def build_probe_headers(origin, base_headers=None, preflight=False, request_method="GET"):
    """Build request headers for one Origin probe."""
    headers = {"User-Agent": USER_AGENT}
    if base_headers:
        headers.update(base_headers)
    headers["Origin"] = origin
    if preflight:
        headers["Access-Control-Request-Method"] = request_method
        headers["Access-Control-Request-Headers"] = PREFLIGHT_ACRH
    return headers


def extract_cors_headers(resp):
    """
    Pull CORS-related headers from a response.

    `requests` joins duplicate headers with ", " — multi-value ACAO
    surfaces here as a comma-separated string for the classifier.
    """
    h = resp.headers
    return {
        "acao": h.get("Access-Control-Allow-Origin", ""),
        "acac": h.get("Access-Control-Allow-Credentials", ""),
        "acah": h.get("Access-Control-Allow-Headers", ""),
        "acam": h.get("Access-Control-Allow-Methods", ""),
        "acma": h.get("Access-Control-Max-Age", ""),
        "vary": h.get("Vary", ""),
        "acrq": h.get("Access-Control-Request-Private-Network", ""),
    }


def build_evidence(cors):
    """Compact evidence string for reports (empty when nothing notable)."""
    bits = []
    for key, label in (
        ("vary", "Vary"),
        ("acam", "Methods"),
        ("acah", "Headers"),
        ("acma", "Max-Age"),
    ):
        val = (cors.get(key) or "").strip()
        if val:
            bits.append(f"{label}: {val}")
    return "; ".join(bits)


def probe_endpoint(
    url,
    origins,
    timeout=8,
    method="OPTIONS",
    headers=None,
    limiter=None,
    target_origin=None,
    registrable_domain=None,
    request_method="GET",
):
    """
    Send one request per Origin and collect CORS headers.

    OPTIONS probes include Access-Control-Request-Method/Headers (real preflight).
    Returns list of finding dicts.
    """
    results = []
    is_preflight = method.upper() == "OPTIONS"

    for origin in origins:
        if limiter:
            limiter.wait()
        req_headers = build_probe_headers(
            origin,
            base_headers=headers,
            preflight=is_preflight,
            request_method=request_method,
        )
        try:
            # Browsers follow redirects for CORS checks; ACAO is read from
            # the final response (e.g. apex → www often carries the headers).
            resp = requests.request(
                method,
                url,
                timeout=timeout,
                headers=req_headers,
                allow_redirects=True,
            )
            cors = extract_cors_headers(resp)
            severity, detail = classify_cors(
                origin,
                cors["acao"],
                cors["acac"],
                target_origin=target_origin,
                registrable_domain=registrable_domain,
            )
            results.append(
                {
                    "origin": origin,
                    "method": method,
                    "status": resp.status_code,
                    "final_url": str(resp.url),
                    "redirected": str(resp.url).rstrip("/") != url.rstrip("/"),
                    "severity": severity,
                    "detail": detail,
                    "evidence": build_evidence(cors),
                    **cors,
                }
            )
        except requests.RequestException as e:
            results.append(
                {
                    "origin": origin,
                    "method": method,
                    "status": None,
                    "acao": "",
                    "acac": "",
                    "acah": "",
                    "acam": "",
                    "acma": "",
                    "vary": "",
                    "acrq": "",
                    "evidence": "",
                    "severity": "ERROR",
                    "detail": str(e),
                }
            )
    return results
