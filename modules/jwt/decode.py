"""
JWT token parsing: base64url helpers, pattern extraction, decode, dedupe.
"""

import base64
import json
import re

# Full compact JWT (signature may be empty for alg=none)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]*)?"
)


def b64url_decode(segment):
    """Decode a base64url segment (adds padding if needed)."""
    if not segment:
        return b""
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def b64url_encode(data):
    """Encode bytes as base64url without padding."""
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
        header = json.loads(b64url_decode(parts[0]))
    except Exception as e:
        return {"error": f"invalid header segment: {e}"}
    if not isinstance(header, dict):
        return {"error": "header is not a JSON object"}

    payload = {}
    if len(parts) == 2 or parts[1]:
        try:
            raw_payload = b64url_decode(parts[1])
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
