"""
JWT security analyzer for SurfaceSweep.

Extracts JWTs from scan results, decodes header/payload (no network),
flags alg=none / weak HMAC secrets / missing-exp / admin claims / kid+jku
injection risks, and optionally verifies HS* signatures against weak or
in-scan secrets.
"""

import base64
import hashlib
import hmac
import json
import re
import time
from urllib.parse import urlparse

# Full compact JWT (signature may be empty for alg=none)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]*)?"
)

# Secrets worth trying for offline HS* verification
WEAK_SECRETS = [
    "secret", "password", "Password1", "123456", "12345678", "qwerty",
    "admin", "test", "changeme", "jwtsecret", "jwt-secret", "jwt_secret",
    "supersecret", "your-256-bit-secret", "your-secret-key", "mysecret",
    "dev", "development", "production", "private", "keyboard cat",
    "HS256", "abcdef", "secretkey", "secret_key", "app_secret",
    "please-change-me", "insecure", "default", "token", "auth",
]

SENSITIVE_CLAIM_KEYS = {
    "admin", "role", "roles", "is_admin", "isAdmin", "permissions",
    "scope", "scp", "privilege", "user_type", "userType",
}


def _b64url_decode(segment):
    """Decode a base64url segment (adds padding if needed)."""
    if not segment:
        return b""
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def extract_jwts(content, source_label=None):
    """
    Find JWT-like tokens in free text.
    Returns list of {token, source}.
    """
    found = []
    seen = set()
    for m in JWT_PATTERN.finditer(content or ""):
        token = m.group(0)
        # Require at least header.payload (sig optional for none-alg)
        if token.count(".") < 2 and not token.endswith("."):
            # JWT_PATTERN always has 2 dots; empty sig ends with '.'
            pass
        if token in seen:
            continue
        seen.add(token)
        found.append({"token": token, "source": source_label or "unknown"})
    return found


def decode_jwt(token):
    """
    Decode a compact JWT without verifying the signature.
    Returns dict with header, payload, signature, or error.
    """
    parts = (token or "").split(".")
    if len(parts) not in (2, 3):
        return {"error": "not a compact JWT (expected 2-3 dot-separated parts)"}

    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception as e:
        return {"error": f"invalid header segment: {e}"}
    if not isinstance(header, dict):
        return {"error": "header is not a JSON object"}

    # Payload may be missing for malformed tokens
    payload = {}
    if len(parts) == 2 or parts[1]:
        try:
            raw_payload = _b64url_decode(parts[1])
            payload = json.loads(raw_payload) if raw_payload else {}
            if not isinstance(payload, dict):
                payload = {"_raw": payload}
        except Exception as e:
            payload = {"_decode_error": str(e)}
    signature = parts[2] if len(parts) == 3 else ""

    return {
        "header": header,
        "payload": payload,
        "signature": signature,
        "alg": str(header.get("alg", "")),
        "typ": str(header.get("typ", header.get("type", ""))),
        "kid": header.get("kid"),
        "parts": len(parts),
    }


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


def verify_hs_signature(token, secret):
    """Constant-time HMAC verify for HS256/384/512. Returns bool or None if unsupported."""
    decoded = decode_jwt(token)
    if decoded.get("error"):
        return None
    alg = decoded.get("alg", "").upper()
    hashes = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg not in hashes:
        return None
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return False
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        expected = hmac.new(
            str(secret).encode("utf-8"), signing_input, hashes[alg]
        ).digest()
        actual = _b64url_decode(parts[2])
    except Exception:
        return None
    return hmac.compare_digest(expected, actual)


def _try_crack_hs(token, candidate_secrets=None):
    """Try weak + scan-derived secrets against an HS* JWT. Returns cracked secret or None."""
    candidates = []
    for s in WEAK_SECRETS:
        candidates.append(s)
    for s in candidate_secrets or []:
        if s and s not in candidates:
            candidates.append(s)
    for secret in candidates:
        if verify_hs_signature(token, secret) is True:
            return secret
    return None


def analyze_jwt(token, source="unknown", candidate_secrets=None, now=None):
    """
    Analyze a single JWT. Returns:
      {
        token, source, alg, header, payload_summary,
        findings: [{severity, issue, detail}, ...],
        severity: max severity of findings,
        cracked_secret: str|None,
      }
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

    # --- Algorithm issues ---
    if alg_l in ("none", ""):
        findings.append({
            "severity": "CRITICAL",
            "issue": "alg_none",
            "detail": f"Algorithm '{alg or 'none'}' allows signature bypass (unsecured JWT)",
        })
    elif alg_l.startswith("hs") and alg_l in ("hs256", "hs384", "hs512"):
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
            host = urlparse(val if "//" in val else f"https://{val}").hostname
            findings.append({
                "severity": "HIGH",
                "issue": f"{url_key}_header_url",
                "detail": f"Header '{url_key}' points at '{val[:100]}' — possible key URL injection",
            })
            if host:
                pass

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

    # Payload summary for report (truncate long values)
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

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    top = min((f["severity"] for f in findings), key=lambda s: sev_rank.get(s, 9))

    return {
        "token": token if len(token) <= 500 else token[:500] + "…",
        "source": source,
        "alg": alg,
        "header": {k: header.get(k) for k in ("alg", "typ", "kid", "jku", "x5u") if k in header},
        "payload_summary": payload_summary,
        "identity": identity,
        "findings": findings,
        "severity": top,
        "cracked_secret": cracked,
    }


def collect_candidate_secrets(result):
    """Pull secret-looking string values from a scan result for HS* cracking."""
    candidates = []
    for s in result.get("secrets_found", []):
        match = s.get("match", "")
        typ = s.get("type", "")
        # Prefer things that look like configured secrets, skip obvious JWTs/URLs
        if typ == "JWT" or match.startswith("eyJ"):
            continue
        if match.startswith("http") or "://" in match:
            # strip scheme-only noise for db URLs is not useful as HMAC key usually
            continue
        if len(match) >= 6 and len(match) <= 200:
            candidates.append(match)
        # Also try the raw value if pattern kept quotes-ish
    # JWT Secret / Generic Secret style entries already have the value in match
    return list(dict.fromkeys(candidates))


def collect_jwts_from_result(result):
    """
    Gather unique JWTs from secrets_found (type JWT) and any raw jwt fields.
    Secrets module stores match truncated to 80 — re-extract from sources if needed.
    """
    tokens = []
    seen = set()
    for s in result.get("secrets_found", []):
        if s.get("type") != "JWT":
            continue
        for src in s.get("sources", [s.get("source", "unknown")]):
            tok = s.get("match", "")
            # Truncated match may be incomplete; only keep if it looks complete enough
            if tok.count(".") >= 2 and tok not in seen:
                # Prefer re-parse: header+payload must decode
                dec = decode_jwt(tok)
                if not dec.get("error") and tok not in seen:
                    seen.add(tok)
                    tokens.append({"token": tok, "source": src})
    # Also scan pre-collected raw list if present
    for item in result.get("jwts_found", []) or []:
        tok = item.get("token", "")
        if tok and tok not in seen:
            dec = decode_jwt(tok)
            if not dec.get("error"):
                seen.add(tok)
                tokens.append({"token": tok, "source": item.get("source", "unknown")})
    return tokens


def scan_jwts(content, source="unknown", candidate_secrets=None):
    """Extract + analyze all JWTs in a content blob."""
    return [
        analyze_jwt(item["token"], source=item["source"], candidate_secrets=candidate_secrets)
        for item in extract_jwts(content, source)
    ]


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def analyze_result_jwts(result, verbose=True):
    """
    Run JWT analysis over a full scan result.
    Returns:
      {
        "tokens_analyzed": n,
        "findings": [analyze_jwt dicts...],
        "severity_counts": {...},
      }
    """
    if verbose:
        print("[*] --- JWT Analysis ---")

    candidates = collect_candidate_secrets(result)
    tokens = collect_jwts_from_result(result)

    # Also re-extract from deobfuscation outputs and raw path strings if present
    # (full tokens often truncated in secrets.match — jwts_found preferred)
    if not tokens:
        if verbose:
            print("[*] No complete JWTs found in scan results")
        return {
            "tokens_analyzed": 0,
            "findings": [],
            "severity_counts": {},
            "candidate_secrets_tried": len(candidates),
        }

    analyses = []
    for item in tokens:
        # Re-expand truncated secret matches by re-scanning is not possible;
        # analyze what we have (full tokens come from extract_jwts on content).
        a = analyze_jwt(
            item["token"],
            source=item.get("source", "unknown"),
            candidate_secrets=candidates,
        )
        analyses.append(a)

    # Prefer longest/full tokens: if a truncated token analyzed as malformed,
    # drop LOW malformed duplicates when a sibling decoded cleanly
    analyses = [a for a in analyses if not (
        a["findings"] and a["findings"][0].get("issue") == "malformed_jwt"
        and any(x["findings"] and x["findings"][0].get("issue") != "malformed_jwt"
                for x in analyses)
    )]

    analyses.sort(key=lambda a: (SEVERITY_ORDER.get(a["severity"], 9), a.get("alg", "")))

    severity_counts = {}
    for a in analyses:
        for f in a["findings"]:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if verbose:
        crit = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)
        med = severity_counts.get("MEDIUM", 0)
        print(f"[+] JWT findings: {crit} critical, {high} high, {med} medium "
              f"({len(analyses)} token(s) analyzed)")
        for a in analyses:
            if a["severity"] in ("CRITICAL", "HIGH"):
                top = a["findings"][0]
                print(f"    [!] {a['severity']:8s} {a['alg'] or '?':6s} {top['issue']}: {top['detail'][:90]}")

    return {
        "tokens_analyzed": len(analyses),
        "findings": analyses,
        "severity_counts": severity_counts,
        "candidate_secrets_tried": len(candidates),
    }


def jwt_risk_boost(jwt_result):
    """Risk points from JWT findings (by severity count across all findings)."""
    counts = (jwt_result or {}).get("severity_counts", {})
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    return sum(counts.get(sev, 0) * w for sev, w in weights.items())
