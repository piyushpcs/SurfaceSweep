"""
WAF detection for SurfaceSweep.

Identifies Web Application Firewalls (Cloudflare, Akamai, AWS WAF, etc.)
so the scanner can adjust speed and headers to avoid being blocked.
"""

import requests
from modules.common.console import detail, ok, warn


# WAF signatures: header name -> list of (value_pattern, waf_name)
WAF_SIGNATURES = {
    "server": [
        ("cloudflare", "Cloudflare"),
        ("akamai", "Akamai"),
        ("incapsula", "Incapsula"),
        ("sucuri", "Sucuri"),
        ("varnish", "Varnish"),
        ("bigip", "F5 BigIP"),
        ("bigsip", "F5 BigIP"),
        ("netscaler", "Citrix NetScaler"),
    ],
    "x-powered-by": [
        ("sucuri", "Sucuri"),
        ("asp.net", "ASP.NET"),
    ],
    "x-cdn": [
        ("cloudflare", "Cloudflare"),
        ("akamai", "Akamai"),
        ("fastly", "Fastly"),
        ("cloudfront", "AWS CloudFront"),
    ],
    "cf-ray": [
        ("", "Cloudflare"),
    ],
    "x-sucuri-id": [
        ("", "Sucuri"),
    ],
    "x-iinfo": [
        ("", "Incapsula"),
    ],
    "x-akamai-transformed": [
        ("", "Akamai"),
    ],
    "x-amz-cf-id": [
        ("", "AWS CloudFront"),
    ],
    "x-amz-request-id": [
        ("", "AWS"),
    ],
    "x-aws-waf": [
        ("", "AWS WAF"),
    ],
}

# WAF detection via response to malicious probe
WAF_ERROR_SIGNATURES = [
    ("access denied", "Generic WAF"),
    ("blocked by security", "Generic WAF"),
    ("request rejected", "Generic WAF"),
    ("web application firewall", "Generic WAF"),
    ("sql injection", "Generic WAF"),
    ("cross-site scripting", "Generic WAF"),
    ("cf-ray", "Cloudflare"),
    ("cloudflare", "Cloudflare"),
    ("akamai", "Akamai"),
    ("incapsula", "Incapsula"),
    ("sucuri", "Sucuri"),
    ("access to this page has been denied", "Imperva/Incapsula"),
]


def detect_waf(url, timeout=10, verbose=True):
    """
    Detect WAF by analyzing response headers.
    Returns dict with WAF info.
    """
    result = {
        "detected": False,
        "waf_name": None,
        "headers_matched": [],
        "confidence": "low"
    }

    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "SurfaceSweep/1.0"}, allow_redirects=True)
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

        matches = []
        for header_name, signatures in WAF_SIGNATURES.items():
            header_value = headers.get(header_name, "")
            if not header_value:
                continue
            for pattern, waf_name in signatures:
                if pattern == "" or pattern in header_value:
                    matches.append({"header": header_name, "value": header_value[:100], "waf": waf_name})

        if matches:
            waf_names = list(set(m["waf"] for m in matches))
            result["detected"] = True
            result["waf_name"] = ", ".join(waf_names)
            result["headers_matched"] = matches
            result["confidence"] = "high" if len(matches) >= 2 else "medium"

            if verbose:
                warn(f" WAF detected: {result['waf_name']} (confidence: {result['confidence']})")
                for m in matches:
                    detail(f"{m['header']}: {m['value']}")
        else:
            if verbose:
                ok(" No WAF detected from headers")

    except requests.RequestException as e:
        result["error"] = str(e)
        if verbose:
            warn(f" WAF detection failed: {e}")

    return result


def get_scan_adjustments(waf_info):
    """
    Return scan adjustments based on detected WAF.
    """
    waf_name = (waf_info.get("waf_name") or "").lower()

    adjustments = {
        "delay_multiplier": 1.0,
        "max_threads": 10,
        "user_agent": "SurfaceSweep/1.0",
        "recommendation": "Normal scanning"
    }

    if "cloudflare" in waf_name:
        adjustments.update({
            "delay_multiplier": 3.0,
            "max_threads": 3,
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "recommendation": "Cloudflare detected — use browser mode and slower rate"
        })
    elif "akamai" in waf_name:
        adjustments.update({
            "delay_multiplier": 2.5,
            "max_threads": 4,
            "recommendation": "Akamai detected — reduce thread count and add delays"
        })
    elif "aws" in waf_name or "cloudfront" in waf_name:
        adjustments.update({
            "delay_multiplier": 2.0,
            "max_threads": 5,
            "recommendation": "AWS WAF detected — moderate scan speed"
        })
    elif "incapsula" in waf_name or "imperva" in waf_name:
        adjustments.update({
            "delay_multiplier": 3.0,
            "max_threads": 2,
            "recommendation": "Imperva/Incapsula detected — expect JavaScript challenges"
        })
    elif "sucuri" in waf_name:
        adjustments.update({
            "delay_multiplier": 2.5,
            "max_threads": 3,
            "recommendation": "Sucuri detected — use browser mode for JS challenges"
        })

    return adjustments
