"""
Single-token analysis: algorithm issues, header injection sinks, signature
quality, time claims, sensitive claims. Returns one findings dict per token.
"""

import json
import math
import re
import time
from collections import Counter
from urllib.parse import urlparse

from modules.common.constants import SEVERITY_ORDER
from modules.jwt.crack import _try_crack_hs, try_key_confusion
from modules.jwt.decode import b64url_decode, decode_jwt
from modules.jwt.keys import collect_embedded_key_materials

__all__ = ["SEVERITY_ORDER"]

SENSITIVE_CLAIM_KEYS = {
    "admin", "role", "roles", "is_admin", "isAdmin", "permissions",
    "scope", "scp", "privilege", "user_type", "userType",
}

# Registered/standard claims skipped by high-entropy payload scanning
STANDARD_CLAIM_KEYS = {
    "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "auth_time",
    "nonce", "sid", "azp", "acr", "amr", "at_hash", "c_hash",
}

_PLACEHOLDER_SIGS = {
    "sig", "signature", "test", "changeme", "secret", "none", "null",
    "xxx", "abc", "placeholder",
}

_KID_SQLI_RE = re.compile(
    r"\b(union|select|insert|update|delete|drop|alter|exec|truncate)\b",
    re.IGNORECASE,
)


def shannon_entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def kid_has_sqli(kid):
    """True when kid contains SQL injection metacharacters or keywords."""
    if any(ch in kid for ch in ("'", '"', ";", "--", "/*", "%00")):
        return True
    return bool(_KID_SQLI_RE.search(kid))


def is_placeholder_signature(signature):
    """True for empty-ish / low-entropy signatures that cannot be real HMACs."""
    if not signature:
        return False
    try:
        raw = b64url_decode(signature)
        text = raw.decode("utf-8", "ignore").lower().strip()
    except Exception:
        text = ""
    if text in _PLACEHOLDER_SIGS:
        return True
    if len(signature) < 8:
        return True
    return len(signature) < 16 and shannon_entropy(signature) < 3.0


def is_high_entropy_value(v):
    """String claim values that look like embedded secrets (high entropy)."""
    if not isinstance(v, str) or len(v) < 16:
        return False
    if v.startswith(("http://", "https://", "/", "eyJ")):
        return False
    return shannon_entropy(v) >= 3.2


def _is_sensitive_claim(key, value):
    if key in SENSITIVE_CLAIM_KEYS:
        if value in (True, 1, "1", "true", "admin", "root", "superuser"):
            return True
        if isinstance(value, str) and value.lower() in ("admin", "root", "superadmin"):
            return True
        if isinstance(value, list) and any(
            str(v).lower() in ("admin", "root", "write", "*") for v in value
        ):
            return True
    if key.lower() in ("user", "username", "email", "sub", "uid") and value:
        return "identity"
    return False


def analyze_jwt(token, source="unknown", candidate_secrets=None, now=None,
                key_materials=None):
    """
    Analyze a single JWT. Returns:
      {
        token, source, alg, header, payload_summary,
        findings: [{severity, issue, detail}, ...],
        severity: max severity of findings,
        cracked_secret: str|None,
      }
    key_materials: optional extra PEM/raw secrets for RS256→HS256 confusion PoC
      (e.g. fetched from jku/x5u when --jwt-network is set).
    """
    now = now if now is not None else time.time()
    decoded = decode_jwt(token)
    findings = []

    if decoded.get("error"):
        return {
            "token": token,
            "source": source,
            "alg": "",
            "header": {},
            "payload_summary": {},
            "findings": [{"severity": "LOW", "issue": "malformed_jwt", "detail": decoded["error"]}],
            "severity": "LOW",
            "cracked_secret": None,
        }

    header = decoded["header"]
    payload = decoded["payload"]
    alg = decoded.get("alg", "")
    alg_l = alg.lower()
    kid = header.get("kid")
    cracked = None
    forged_token = None

    # --- Algorithm issues ---
    if alg_l in ("none", ""):
        findings.append({
            "severity": "CRITICAL",
            "issue": "alg_none",
            "detail": f"Algorithm '{alg or 'none'}' allows signature bypass (unsecured JWT)",
        })
    elif alg_l in ("hs256", "hs384", "hs512"):
        cracked = _try_crack_hs(token, candidate_secrets)
        if cracked is not None:
            findings.append({
                "severity": "CRITICAL",
                "issue": "weak_hmac_secret",
                "detail": f"HMAC secret cracked: '{cracked[:40]}' (offline forgery possible)",
            })
        elif candidate_secrets:
            findings.append({
                "severity": "MEDIUM",
                "issue": "hs_algorithm",
                "detail": f"{alg} symmetric signature — secret not cracked from wordlist/scan secrets",
            })
        else:
            findings.append({
                "severity": "LOW",
                "issue": "hs_algorithm",
                "detail": f"{alg} symmetric signature (no candidate secrets provided)",
            })
    elif alg_l in ("rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "ps384", "ps512"):
        findings.append({
            "severity": "INFO",
            "issue": "asymmetric_alg",
            "detail": f"{alg} asymmetric signature (public key required for verification)",
        })
        # --- RS256→HS256 key-confusion PoC (Step 6) ---
        materials = list(key_materials or [])
        materials.extend(collect_embedded_key_materials(header))
        seen_mat = set()
        uniq = []
        for m in materials:
            mid = m if isinstance(m, str) else id(m)
            if mid not in seen_mat:
                seen_mat.add(mid)
                uniq.append(m)
        forged, used = try_key_confusion(decoded, uniq)
        if forged is not None:
            forged_token = forged
            if isinstance(used, bytes):
                used_desc = f"<bytes, {len(used)}>"
            elif isinstance(used, str) and len(used) <= 60:
                used_desc = used
            else:
                used_desc = str(used)[:60] + "…" if used is not None else "?"
            findings.append({
                "severity": "CRITICAL",
                "issue": "rs256_hs256_confusion",
                "detail": (
                    "RS256→HS256 key-confusion forgery constructed offline "
                    f"using public key material ({used_desc}) — server may accept "
                    "if it does not pin the algorithm"
                ),
                "forged_token": forged,
            })
    elif alg:
        findings.append({
            "severity": "MEDIUM",
            "issue": "unusual_alg",
            "detail": f"Unusual algorithm '{alg}'",
        })

    # --- Header injection sinks ---
    if isinstance(kid, str) and ("../" in kid or kid.startswith("/") or "\\" in kid):
        findings.append({
            "severity": "HIGH",
            "issue": "kid_path_traversal",
            "detail": f"kid looks like a path ('{kid[:80]}') — possible key-selection traversal",
        })
    for url_key in ("jku", "x5u", "jwk"):
        val = header.get(url_key)
        if isinstance(val, str) and val:
            findings.append({
                "severity": "HIGH",
                "issue": f"{url_key}_header_url",
                "detail": f"Header '{url_key}' points at '{val[:100]}' — possible key URL injection",
            })

    # --- Embedded key material / critical header extensions (Step 2) ---
    jwk_val = header.get("jwk")
    if isinstance(jwk_val, dict) and jwk_val:
        findings.append({
            "severity": "HIGH",
            "issue": "embedded_jwk",
            "detail": "Header embeds a full JWK object — server may trust attacker-controlled keys",
        })
    x5c_val = header.get("x5c")
    if isinstance(x5c_val, list) and x5c_val:
        findings.append({
            "severity": "HIGH",
            "issue": "x5c_header_chain",
            "detail": f"x5c certificate chain ({len(x5c_val)} cert(s)) — possible certificate/key confusion",
        })
    if "crit" in header:
        findings.append({
            "severity": "MEDIUM",
            "issue": "crit_header",
            "detail": f"crit={header['crit']!r} — critical extensions must be understood; "
                      "misconfigured parsers may ignore them",
        })
    if isinstance(kid, str) and kid_has_sqli(kid):
        findings.append({
            "severity": "HIGH",
            "issue": "kid_sqli",
            "detail": f"kid contains SQL metacharacters/keywords ('{kid[:80]}') — possible key-store injection",
        })

    # --- Signature quality: null / placeholder / alg=none with leftover sig ---
    signature = decoded.get("signature", "")
    if alg_l not in ("none", "") and not signature:
        findings.append({
            "severity": "CRITICAL",
            "issue": "empty_signature",
            "detail": f"alg='{alg}' claims a signature but signature is empty (signature bypass)",
        })
    elif alg_l in ("none", "") and signature:
        findings.append({
            "severity": "MEDIUM",
            "issue": "alg_none_with_signature",
            "detail": "alg=none token still carries a signature segment (tampering / strip attempt)",
        })
    elif signature and is_placeholder_signature(signature):
        findings.append({
            "severity": "MEDIUM",
            "issue": "low_entropy_signature",
            "detail": f"Signature segment looks like a placeholder (len={len(signature)}, "
                      f"entropy={shannon_entropy(signature):.1f} bits/char)",
        })

    # --- Payload / time claims ---
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    iat = payload.get("iat")
    if exp is None:
        findings.append({
            "severity": "MEDIUM",
            "issue": "missing_exp",
            "detail": "No exp claim — token may never expire",
        })
    else:
        try:
            exp_f = float(exp)
            if exp_f < now:
                findings.append({
                    "severity": "INFO",
                    "issue": "expired",
                    "detail": f"Token expired at {int(exp_f)}",
                })
            elif exp_f - now > 10 * 365 * 24 * 3600:
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "long_lived_exp",
                    "detail": f"exp more than 10 years in the future (iat={iat})",
                })
        except (TypeError, ValueError):
            findings.append({
                "severity": "LOW",
                "issue": "bad_exp",
                "detail": f"Non-numeric exp: {exp!r}",
            })
    try:
        if nbf is not None and float(nbf) > now + 60:
            findings.append({
                "severity": "LOW",
                "issue": "future_nbf",
                "detail": f"nbf is in the future: {nbf}",
            })
    except (TypeError, ValueError):
        pass

    # --- Missing issuer / audience binding (Step 2) ---
    if "iss" not in payload and "aud" not in payload:
        findings.append({
            "severity": "LOW",
            "issue": "missing_iss_aud",
            "detail": "No iss/aud claims — token is not bound to an issuer or audience",
        })

    # --- High-entropy payload claims (possible embedded secrets, Step 2) ---
    high_entropy = [
        f"{k}={str(v)[:40]}"
        for k, v in payload.items()
        if k not in STANDARD_CLAIM_KEYS and is_high_entropy_value(v)
    ]
    if high_entropy:
        findings.append({
            "severity": "MEDIUM",
            "issue": "high_entropy_claim",
            "detail": "High-entropy value(s) in payload (possible embedded secret): "
                      + "; ".join(high_entropy[:5]),
        })

    # --- Sensitive claims ---
    sensitive = []
    identity = []
    for k, v in payload.items():
        if k in ("iat", "nbf", "exp", "jti", "iss", "aud", "sub"):
            if k == "sub":
                identity.append(str(v)[:60])
            continue
        res = _is_sensitive_claim(k, v)
        if res is True:
            sensitive.append(f"{k}={v!r}"[:80])
        elif res == "identity":
            identity.append(f"{k}={v}"[:60])

    if sensitive:
        findings.append({
            "severity": "HIGH",
            "issue": "sensitive_claims",
            "detail": "Privileged claims present: " + "; ".join(sensitive[:5]),
        })

    payload_summary = {}
    for k, v in list(payload.items())[:20]:
        s = json.dumps(v) if not isinstance(v, str) else v
        payload_summary[k] = s[:80]

    if not findings:
        findings.append({
            "severity": "INFO",
            "issue": "ok",
            "detail": "No obvious JWT misconfiguration detected",
        })

    top = min((f["severity"] for f in findings), key=lambda s: SEVERITY_ORDER.get(s, 9))

    return {
        "token": token if len(token) <= 500 else token[:500] + "…",
        "source": source,
        "alg": alg,
        "header": {
            k: header.get(k)
            for k in ("alg", "typ", "kid", "jku", "x5u", "crit")
            if k in header
        },
        "payload_summary": payload_summary,
        "identity": identity,
        "findings": findings,
        "severity": top,
        "cracked_secret": cracked,
        "forged_token": forged_token,
    }


def scan_jwts(content, source="unknown", candidate_secrets=None):
    """Extract + analyze all JWTs in a content blob."""
    from modules.jwt.decode import extract_jwts
    return [
        analyze_jwt(item["token"], source=item["source"], candidate_secrets=candidate_secrets)
        for item in extract_jwts(content, source)
    ]
