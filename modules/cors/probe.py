"""
HTTP probing for CORS misconfigurations (preflight + simple requests).
"""

from urllib.parse import urlparse

import requests

from modules.cors.classifier import classify_cors, parse_acao_list
from modules.cors.origins import origins_equal

USER_AGENT = "SurfaceSweep/1.0"

# Realistic browser preflight request-header list
PREFLIGHT_ACRH = "content-type, authorization, x-requested-with"


def build_probe_headers(origin, base_headers=None, preflight=False, request_method="GET"):
    """Build request headers for one Origin probe."""
    headers = {"User-Agent": USER_AGENT}
    if base_headers:
        headers.update(base_headers)
    headers["Origin"] = origin
    if preflight:
        # Browsers send the single method under test (not a full list)
        headers["Access-Control-Request-Method"] = request_method
        headers["Access-Control-Request-Headers"] = PREFLIGHT_ACRH
    return headers


def extract_cors_headers(resp):
    """
    Pull CORS-related headers from a response.

    `requests` joins duplicate headers with ", " — multi-value ACAO
    surfaces here as a comma-separated string for the classifier.

    PNA: the response header is Access-Control-Allow-Private-Network
    (the Request-* form is what clients send on the preflight).
    """
    h = resp.headers
    return {
        "acao": h.get("Access-Control-Allow-Origin", ""),
        "acac": h.get("Access-Control-Allow-Credentials", ""),
        "acah": h.get("Access-Control-Allow-Headers", ""),
        "acam": h.get("Access-Control-Allow-Methods", ""),
        "acma": h.get("Access-Control-Max-Age", ""),
        "vary": h.get("Vary", ""),
        "acpn": h.get("Access-Control-Allow-Private-Network", ""),
    }


def build_evidence(cors):
    """Compact evidence string for reports (empty when nothing notable)."""
    bits = []
    for key, label in (
        ("vary", "Vary"),
        ("acam", "Methods"),
        ("acah", "Headers"),
        ("acma", "Max-Age"),
        ("acpn", "Allow-Private-Network"),
    ):
        val = (cors.get(key) or "").strip()
        if val:
            bits.append(f"{label}: {val}")
    return "; ".join(bits)


def is_cross_domain_redirect(url, final_url):
    """True when the request landed on a different host than it started on."""
    start = (urlparse(url).hostname or "").lower()
    final = (urlparse(final_url or "").hostname or "").lower()
    return bool(start and final and start != final)


def is_reflected_acao(origin, acao):
    """True when ACAO echoes the probe Origin (proves Origin-dependent reply)."""
    if not acao or not origin:
        return False
    if acao.strip() == "*":
        return False
    if origins_equal(origin, acao):
        return True
    return any(origins_equal(origin, item) for item in parse_acao_list(acao))


def _vary_missing(vary):
    """True when Vary does not mention Origin (case-insensitive)."""
    if not vary:
        return True
    return "origin" not in vary.lower()


def probe_baseline(url, timeout=8, headers=None, limiter=None):
    """
    One GET without an Origin header — detects a static ACAO.

    Returns dict with status/final_url/acao/acac/vary/acpn/error/static_acao.
    Cross-domain redirects yield empty ACAO (result belongs to another host).
    """
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req_headers.pop("Origin", None)

    if limiter:
        limiter.wait()
    try:
        resp = requests.request(
            "GET", url, timeout=timeout, headers=req_headers, allow_redirects=True
        )
        final_url = str(resp.url)
        if is_cross_domain_redirect(url, final_url):
            return {
                "status": resp.status_code,
                "final_url": final_url,
                "acao": "",
                "acac": "",
                "vary": "",
                "acpn": "",
                "error": "cross-domain redirect",
                "static_acao": False,
            }
        cors = extract_cors_headers(resp)
        return {
            "status": resp.status_code,
            "final_url": final_url,
            **cors,
            "error": None,
            "static_acao": bool(cors["acao"]),
        }
    except requests.RequestException as e:
        return {
            "status": None,
            "final_url": url,
            "acao": "",
            "acac": "",
            "vary": "",
            "acpn": "",
            "error": str(e),
            "static_acao": False,
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
    static_acao=False,
):
    """
    Send one request per Origin and collect CORS headers.

    OPTIONS probes include Access-Control-Request-Method/Headers (real preflight).
    Cross-domain redirects are skipped (CORScanner-style FP filter).
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
            final_url = str(resp.url)
            if is_cross_domain_redirect(url, final_url):
                # Headers belong to the final host — not a finding for this URL
                continue

            cors = extract_cors_headers(resp)
            severity, detail = classify_cors(
                origin,
                cors["acao"],
                cors["acac"],
                target_origin=target_origin,
                registrable_domain=registrable_domain,
            )

            # Dynamic ACAO (reflected) without Vary: Origin → cache-poisoning signal
            dynamic = is_reflected_acao(origin, cors["acao"]) and not static_acao
            if dynamic and severity != "INFO" and _vary_missing(cors["vary"]):
                note = "missing Vary: Origin (cache poisoning risk)"
                if note not in (detail or ""):
                    detail = f"{detail}; {note}" if detail else note

            results.append(
                {
                    "origin": origin,
                    "method": method,
                    "status": resp.status_code,
                    "final_url": final_url,
                    "redirected": final_url.rstrip("/") != url.rstrip("/"),
                    "severity": severity,
                    "detail": detail,
                    "evidence": build_evidence(cors),
                    "static_acao": bool(static_acao),
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
                    "acpn": "",
                    "evidence": "",
                    "severity": "ERROR",
                    "detail": str(e),
                    "static_acao": bool(static_acao),
                }
            )
    return results
