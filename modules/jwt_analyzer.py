"""
JWT security analyzer for SurfaceSweep.

Extracts JWTs from scan results, decodes header/payload (no network),
flags alg=none / weak HMAC secrets / missing-exp / admin claims / kid+jku
injection risks, and optionally verifies HS* signatures against weak or
in-scan secrets.

Step 2 offline hardening: embedded jwk objects, x5c chains, crit headers,
null/placeholder signatures, kid SQLi characters, missing iss/aud, and
high-entropy payload claims (possible embedded secrets).
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import math
import re
import socket
import time
from collections import Counter
from urllib.parse import urlparse

# Full compact JWT (signature may be empty for alg=none)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]*)?"
)

# Secrets worth trying for offline HS* verification (common JWT defaults +
# jwt_tool/SecLists-style common secrets)
WEAK_SECRETS = [
    # Core defaults
    "secret", "password", "Password1", "123456", "12345678", "qwerty",
    "admin", "test", "changeme", "jwtsecret", "jwt-secret", "jwt_secret",
    "supersecret", "your-256-bit-secret", "your-secret-key", "mysecret",
    "dev", "development", "production", "private", "keyboard cat",
    "HS256", "abcdef", "secretkey", "secret_key", "app_secret",
    "please-change-me", "insecure", "default", "token", "auth",
    # Common password / JWT wordlist entries
    "password123", "admin123", "root", "qwerty123", "letmein", "welcome",
    "monkey", "dragon", "master", "shadow", "login", "pass", "abc123",
    "111111", "123123", "654321", "iloveyou", "princess", "football",
    "baseball", "trustno1", "sunshine", "starwars", "whatever", "freedom",
    "secret123", "key", "hmac", "changeme123", "Password1!", "P@ssw0rd",
    "admin1", "test123", "demo", "sample", "example", "temp", "tmp",
    "SECRET", "Secret", "SECRET_KEY", "JWT_SECRET", "APP_SECRET",
    "AUTH_SECRET", "SESSION_SECRET", "SIGNING_KEY", "HMAC_KEY",
    "devsecret", "prodsecret", "stage", "staging", "localhost",
    "super-secret", "my-secret", "the-secret", "a-secret",
    "123456789", "1234567890", "000000", "1111", "passw0rd",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1q2w3e4r", "1qaz2wsx",
    "hunter2", "correcthorsebatterystaple", "you-shall-not-pass",
]

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


def _shannon_entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _kid_has_sqli(kid):
    """True when kid contains SQL injection metacharacters or keywords."""
    if any(ch in kid for ch in ("'", '"', ";", "--", "/*", "%00")):
        return True
    return bool(_KID_SQLI_RE.search(kid))


def _is_placeholder_signature(signature):
    """True for empty-ish / low-entropy signatures that cannot be real HMACs."""
    if not signature:
        return False
    try:
        raw = _b64url_decode(signature)
        text = raw.decode("utf-8", "ignore").lower().strip()
    except Exception:
        text = ""
    if text in _PLACEHOLDER_SIGS:
        return True
    if len(signature) < 8:
        return True
    return len(signature) < 16 and _shannon_entropy(signature) < 3.0


def _is_high_entropy_value(v):
    """String claim values that look like embedded secrets (high entropy)."""
    if not isinstance(v, str) or len(v) < 16:
        return False
    if v.startswith(("http://", "https://", "/", "eyJ")):
        return False
    return _shannon_entropy(v) >= 3.2


def load_wordlist(path):
    """Load newline-delimited secrets from a wordlist file (skips blanks/#)."""
    candidates = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    candidates.append(s)
    except OSError:
        return []
    return candidates


def target_mutations(target):
    """
    Derive likely HMAC secrets from a target URL's host labels.
    e.g. https://app.example.com → example, app, appexample, examplesecret, ...
    """
    if not target:
        return []
    try:
        host = urlparse(target if "//" in target else f"https://{target}").hostname or ""
    except Exception:
        return []
    if not host:
        return []
    labels = [p for p in host.lower().replace("-", "").split(".") if p and p != "www"]
    if not labels:
        return []

    bases = []
    for lab in labels:
        if lab not in ("com", "org", "net", "io", "co", "in", "gov", "edu"):
            bases.append(lab)
    if len(labels) >= 2:
        bases.append(labels[0] + labels[1])
    # unique, preserve order
    bases = list(dict.fromkeys(bases))[:6]

    suffixes = ["", "secret", "key", "123", "2024", "2025", "2026", "jwt", "auth"]
    mutations = []
    for b in bases:
        for suf in suffixes:
            mutations.append(f"{b}{suf}")
        mutations.append(b.capitalize())
        mutations.append(f"{b}-secret")
        mutations.append(f"{b}_secret")
    return list(dict.fromkeys(mutations))


def export_hashcat(tokens, path):
    """
    Write JWTs in hashcat mode 16500 format (one full compact JWT per line).
    Only HS* tokens are crackable in 16500 — filter to those.
    Returns count written.
    """
    written = 0
    try:
        with open(path, "w", encoding="utf-8") as fh:
            for t in tokens or []:
                d = decode_jwt(t)
                if d.get("error"):
                    continue
                alg = (d.get("alg") or "").upper()
                if alg not in ("HS256", "HS384", "HS512"):
                    continue
                fh.write(t.rstrip("\n") + "\n")
                written += 1
    except OSError:
        return 0
    return written


def is_safe_jwt_fetch_url(url):
    """
    SSRF guard for optional jku/x5u/JWKS fetches: http(s) only,
    no loopback/private/link-local/reserved/multicast targets.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def _der_length(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_int(value):
    length_bytes = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if length_bytes[0] & 0x80:
        length_bytes = b"\x00" + length_bytes
    return b"\x02" + _der_length(len(length_bytes)) + length_bytes


def rsa_jwk_to_pem(jwk):
    """Build a PEM SubjectPublicKeyInfo from an RSA JWK ({n, e}). Returns str or None."""
    if not isinstance(jwk, dict) or jwk.get("kty") not in (None, "RSA"):
        return None
    try:
        if "n" not in jwk or "e" not in jwk:
            return None
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        if n <= 0 or e <= 0:
            return None
        pk_seq = _der_int(n) + _der_int(e)
        pk = b"\x30" + _der_length(len(pk_seq)) + pk_seq
        # rsaEncryption AlgorithmIdentifier
        oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
        null = b"\x05\x00"
        alg = b"\x30" + _der_length(len(oid) + len(null)) + oid + null
        spki_body = alg + pk
        spki = b"\x30" + _der_length(len(spki_body)) + spki_body
        b64 = base64.b64encode(spki).decode("ascii")
        lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
        return (
            "-----BEGIN PUBLIC KEY-----\n"
            + "\n".join(lines)
            + "\n-----END PUBLIC KEY-----"
        )
    except Exception:
        return None


def forge_hs256_token(header, payload, secret):
    """Construct an HS256 compact JWT signed with `secret` (key-confusion PoC helper)."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(
        str(secret).encode("utf-8"), f"{h}.{p}".encode("ascii"), hashlib.sha256
    ).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def try_key_confusion(decoded, key_materials):
    """
    RS256→HS256 key-confusion PoC: re-sign the same payload as HS256 using
    each public-key material as the HMAC secret. Returns (forged_token, material)
    or (None, None). Offline — proves forgeability when public key material is known.
    """
    if not key_materials:
        return None, None
    header = dict(decoded.get("header") or {})
    if (header.get("alg") or "").upper() not in ("RS256", "RS384", "RS512"):
        return None, None
    header["alg"] = "HS256"
    for drop in ("jwk", "jku", "x5u", "x5c", "crit"):
        header.pop(drop, None)
    payload = decoded.get("payload") or {}
    for mat in key_materials:
        if not mat:
            continue
        forged = forge_hs256_token(header, payload, mat)
        if verify_hs_signature(forged, mat) is True:
            return forged, mat
    return None, None


def collect_embedded_key_materials(header):
    """RSA PEM candidates from an embedded jwk header (offline)."""
    jwk = header.get("jwk") if isinstance(header, dict) else None
    if not isinstance(jwk, dict):
        return []
    pem = rsa_jwk_to_pem(jwk)
    materials = []
    if pem:
        materials.append(pem)
        # Also try raw modulus bytes (some naive HMAC implementations)
        try:
            materials.append(_b64url_decode(jwk["n"]))
        except Exception:
            pass
    return materials


def fetch_jwks_keys(url, timeout=5.0):
    """
    Fetch a JWKS document (network — behind --jwt-network).
    Returns list of PEM strings for RSA keys. SSRF-guarded; empty on any failure.
    """
    if not is_safe_jwt_fetch_url(url):
        return []
    try:
        import requests
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "SurfaceSweep/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, list):
        # Some endpoints return a bare JWK
        keys = [data] if isinstance(data, dict) and data.get("kty") else []
    materials = []
    for jwk in keys:
        if isinstance(jwk, dict) and jwk.get("kty") == "RSA":
            pem = rsa_jwk_to_pem(jwk)
            if pem:
                materials.append(pem)
    return materials


def collect_jku_urls(tokens):
    """Unique jku/x5u URLs from decoded tokens (for optional network fetch)."""
    urls = []
    seen = set()
    for item in tokens or []:
        d = decode_jwt(item.get("token", ""))
        if d.get("error"):
            continue
        header = d.get("header") or {}
        for key in ("jku", "x5u"):
            val = header.get(key)
            if isinstance(val, str) and val and val not in seen:
                seen.add(val)
                urls.append(val)
    return urls


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


def deduplicate_jwts(all_jwts):
    """
    Dedupe JWTs by token value (first source wins).
    Same token across multiple files → one entry.
    """
    seen = {}
    for j in all_jwts or []:
        tok = j.get("token")
        if tok and tok not in seen:
            seen[tok] = {"token": tok, "source": j.get("source", "unknown")}
    return list(seen.values())


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


def build_crack_candidates(result, wordlist_path=None, target=None):
    """
    Assemble the full offline crack candidate list:
    built-in WEAK_SECRETS + in-scan secrets + optional wordlist file + target mutations.
    Returns (candidates, meta) where meta records counts for reporting.
    """
    scan_secrets = collect_candidate_secrets(result)
    wordlist = load_wordlist(wordlist_path) if wordlist_path else []
    mutations = target_mutations(target)

    seen = set()
    candidates = []
    for s in list(WEAK_SECRETS) + scan_secrets + wordlist + mutations:
        if s and s not in seen:
            seen.add(s)
            candidates.append(s)

    meta = {
        "builtin": len(WEAK_SECRETS),
        "scan_secrets": len(scan_secrets),
        "wordlist": len(wordlist),
        "target_mutations": len(mutations),
        "total": len(candidates),
    }
    return candidates, meta


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
        # --- RS256→HS256 key-confusion PoC (Step 6) ---
        materials = list(key_materials or [])
        materials.extend(collect_embedded_key_materials(header))
        # de-dupe, keep order
        seen_mat = set()
        uniq = []
        for m in materials:
            mid = m if isinstance(m, str) else id(m)
            if mid not in seen_mat:
                seen_mat.add(mid)
                uniq.append(m)
        forged, used = try_key_confusion(decoded, uniq)
        if forged is not None:
            used_desc = (
                used if isinstance(used, str) and len(used) <= 60
                else (f"<{type(used).__name__}, {len(used)} bytes>" if not isinstance(used, str) else used[:60] + "…")
            )
            findings.append({
                "severity": "CRITICAL",
                "issue": "rs256_hs256_confusion",
                "detail": (
                    "RS256→HS256 key-confusion forgery constructed offline "
                    f"using public key material ({used_desc}) — server may accept "
                    "if it does not pin the algorithm"
                ),
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
    if isinstance(kid, str) and _kid_has_sqli(kid):
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
    elif signature and _is_placeholder_signature(signature):
        findings.append({
            "severity": "MEDIUM",
            "issue": "low_entropy_signature",
            "detail": f"Signature segment looks like a placeholder (len={len(signature)}, "
                      f"entropy={_shannon_entropy(signature):.1f} bits/char)",
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
        if k not in STANDARD_CLAIM_KEYS and _is_high_entropy_value(v)
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


def export_jwt_findings(jwt_result, path):
    """
    Write one JSON object per analyzed token (NDJSON) for tooling.
    Returns count of lines written.
    """
    written = 0
    try:
        with open(path, "w", encoding="utf-8") as fh:
            for a in (jwt_result or {}).get("findings", []):
                fh.write(json.dumps(a, ensure_ascii=False, default=str) + "\n")
                written += 1
    except OSError:
        return 0
    return written


def _jwt_summary(analyses, severity_counts, candidates_meta, exported=0):
    """Compact summary block for JSON consumers (parity with CORS schema)."""
    cracked = sum(1 for a in analyses if a.get("cracked_secret"))
    issue_counts = {}
    for a in analyses:
        for f in a.get("findings", []):
            issue = f.get("issue", "unknown")
            issue_counts[issue] = issue_counts.get(issue, 0) + 1
    summary = {
        "tokens_analyzed": len(analyses),
        "severity_counts": severity_counts,
        "cracked_secrets": cracked,
        "candidate_secrets_tried": (candidates_meta or {}).get("total", 0),
        "issue_counts": dict(sorted(issue_counts.items(), key=lambda kv: -kv[1])),
    }
    if exported:
        summary["hashcat_exported"] = exported
    return summary


def analyze_result_jwts(result, verbose=True, wordlist_path=None, target=None,
                        hashcat_path=None, export_path=None, network=False,
                        network_timeout=5.0):
    """
    Run JWT analysis over a full scan result.
    Args:
        wordlist_path: optional extra newline-delimited secret wordlist
        target: target URL — derive host-based HMAC mutations
        hashcat_path: if set, export HS* tokens in hashcat mode 16500 format
        export_path: if set, write per-token findings as NDJSON
        network: fetch jku/x5u JWKS over the network (SSRF-guarded) for
                 RS256→HS256 key-confusion checks (CLI: --jwt-network)
        network_timeout: seconds for each JWKS fetch when network=True
    Returns:
      {
        "schema_version": 1,
        "tokens_analyzed": n,
        "findings": [analyze_jwt dicts...],
        "severity_counts": {...},
        "summary": {...},
        "candidate_secrets_tried": n,
        "crack_meta": {...},
        "hashcat_exported": n,
        "findings_exported": n,
        "jku_fetches": n,          # when network=True
        "network_key_materials": n # when network=True
      }
    """
    if verbose:
        print("[*] --- JWT Analysis ---")

    candidates, crack_meta = build_crack_candidates(
        result, wordlist_path=wordlist_path, target=target
    )

    tokens = collect_jwts_from_result(result)

    hashcat_n = 0
    if hashcat_path and tokens:
        hashcat_n = export_hashcat([t["token"] for t in tokens], hashcat_path)
        if verbose and hashcat_n:
            print(f"[+] Exported {hashcat_n} HS* JWT(s) for hashcat (-m 16500): {hashcat_path}")

    # Optional network: fetch jku/x5u JWKS → PEM key materials for confusion PoC
    network_materials = []
    jku_fetches = 0
    if network and tokens:
        jku_urls = collect_jku_urls(tokens)
        for u in jku_urls:
            jku_fetches += 1
            network_materials.extend(fetch_jwks_keys(u, timeout=network_timeout))
        # de-dupe PEMs
        network_materials = list(dict.fromkeys(network_materials))
        if verbose and jku_urls:
            print(f"[*] Network JWKS: {jku_fetches} jku/x5u URL(s), "
                  f"{len(network_materials)} RSA key(s) retrieved")
        if verbose and jku_urls and not network_materials:
            print("[*] Network JWKS: no usable RSA keys (SSRF guard, fetch error, or non-RSA)")

    if not tokens:
        if verbose:
            print("[*] No complete JWTs found in scan results")
        empty = {
            "schema_version": 1,
            "tokens_analyzed": 0,
            "findings": [],
            "severity_counts": {},
            "summary": _jwt_summary([], {}, crack_meta),
            "candidate_secrets_tried": len(candidates),
            "crack_meta": crack_meta,
        }
        if hashcat_n:
            empty["hashcat_exported"] = hashcat_n
        if network:
            empty["jku_fetches"] = jku_fetches
            empty["network_key_materials"] = len(network_materials)
        if export_path:
            empty["findings_exported"] = export_jwt_findings(empty, export_path)
        return empty

    analyses = []
    for item in tokens:
        a = analyze_jwt(
            item["token"],
            source=item.get("source", "unknown"),
            candidate_secrets=candidates,
            key_materials=network_materials,
        )
        analyses.append(a)

    # Prefer longest/full tokens: drop LOW malformed duplicates when a sibling decoded cleanly
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
        if crack_meta.get("total"):
            print(f"[*] Crack candidates: {crack_meta['total']} "
                  f"(builtin={crack_meta['builtin']}, scan={crack_meta['scan_secrets']}, "
                  f"wordlist={crack_meta['wordlist']}, mutations={crack_meta['target_mutations']})")
        for a in analyses:
            if a["severity"] in ("CRITICAL", "HIGH"):
                top = a["findings"][0]
                print(f"    [!] {a['severity']:8s} {a['alg'] or '?':6s} {top['issue']}: {top['detail'][:90]}")

    out = {
        "schema_version": 1,
        "tokens_analyzed": len(analyses),
        "findings": analyses,
        "severity_counts": severity_counts,
        "summary": _jwt_summary(analyses, severity_counts, crack_meta, exported=hashcat_n),
        "candidate_secrets_tried": len(candidates),
        "crack_meta": crack_meta,
    }
    if hashcat_n:
        out["hashcat_exported"] = hashcat_n
    if network:
        out["jku_fetches"] = jku_fetches
        out["network_key_materials"] = len(network_materials)
        out["summary"]["jku_fetches"] = jku_fetches
        out["summary"]["network_key_materials"] = len(network_materials)
    if export_path:
        out["findings_exported"] = export_jwt_findings(out, export_path)
        if verbose and out["findings_exported"]:
            print(f"[+] Wrote {out['findings_exported']} per-token finding(s) (NDJSON): {export_path}")
    return out


def jwt_risk_boost(jwt_result):
    """Risk points from JWT findings (by severity count across all findings)."""
    counts = (jwt_result or {}).get("severity_counts", {})
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    return sum(counts.get(sev, 0) * w for sev, w in weights.items())
