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
    """Pull CORS-related headers from a response."""
    h = resp.headers
    return {
        "acao": h.get("Access-Control-Allow-Origin", ""),
        "acac": h.get("Access-Control-Allow-Credentials", ""),
        "acah": h.get("Access-Control-Allow-Headers", ""),
        "acam": h.get("Access-Control-Allow-Methods", ""),
        "acma": h.get("Access-Control-Max-Age", ""),
        "vary": h.get("Vary", ""),
    }


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
            resp = requests.request(
                method,
                url,
                timeout=timeout,
                headers=req_headers,
                allow_redirects=False,
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
                    "severity": severity,
                    "detail": detail,
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
                    "severity": "ERROR",
                    "detail": str(e),
                }
            )
    return results
