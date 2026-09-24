"""
Key material: SSRF-guarded JWKS fetch, RSA JWK→PEM, embedded jwk extraction.
"""

import base64
import ipaddress
import socket
from urllib.parse import urlparse

from modules.jwt.decode import b64url_decode, decode_jwt


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
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
        if n <= 0 or e <= 0:
            return None
        pk_seq = _der_int(n) + _der_int(e)
        pk = b"\x30" + _der_length(len(pk_seq)) + pk_seq
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


def collect_embedded_key_materials(header):
    """RSA PEM candidates from an embedded jwk header (offline)."""
    jwk = header.get("jwk") if isinstance(header, dict) else None
    if not isinstance(jwk, dict):
        return []
    pem = rsa_jwk_to_pem(jwk)
    materials = []
    if pem:
        materials.append(pem)
        try:
            materials.append(b64url_decode(jwk["n"]))
        except Exception:
            pass
    return materials


def _get_with_safe_redirects(url, timeout=5.0, max_redirects=3):
    """
    GET with redirects re-validated against the SSRF guard on every hop.
    Returns a requests.Response or None. Never follows a redirect to an
    unsafe host (initial URL validation alone is bypassable via 302).
    """
    try:
        import requests
    except ImportError:
        return None

    current = url
    for _ in range(max_redirects + 1):
        if not is_safe_jwt_fetch_url(current):
            return None
        try:
            resp = requests.get(
                current,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "SurfaceSweep/1.0"},
            )
        except Exception:
            return None
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                return None
            try:
                from urllib.parse import urljoin
                current = urljoin(current, location)
            except ValueError:
                return None
            continue
        try:
            resp.raise_for_status()
        except Exception:
            return None
        return resp
    return None  # too many redirects


def fetch_jwks_keys(url, timeout=5.0):
    """
    Fetch a JWKS document (network — behind --jwt-network).
    Returns list of PEM strings for RSA keys. SSRF-guarded on every
    redirect hop; empty on any failure.
    """
    if not is_safe_jwt_fetch_url(url):
        return []
    resp = _get_with_safe_redirects(url, timeout=timeout)
    if resp is None:
        return []
    try:
        data = resp.json()
    except Exception:
        return []
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, list):
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
