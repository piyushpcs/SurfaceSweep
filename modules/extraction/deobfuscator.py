"""
JS Deobfuscation module for SurfaceSweep.

Decodes common obfuscation techniques found in real-world JS:
- Base64 / atob() encoded strings
- Hex escape sequences (\x41\x42)
- Unicode escape sequences (\u0041\u0042)
- eval() wrapped payloads
- String.fromCharCode() calls
"""

import re
import base64
import codecs


def decode_base64_strings(content):
    """Find and decode base64 encoded strings in JS."""
    decoded = []
    pattern = re.compile(r'''(?:atob|btoa)\s*\(\s*['"]([A-Za-z0-9+/=]{8,})['"]''')
    for match in pattern.finditer(content):
        encoded = match.group(1)
        try:
            result = base64.b64decode(encoded).decode("utf-8", errors="ignore")
            if result.isprintable() and len(result) > 2:
                decoded.append({"encoded": match.group(0), "decoded": result, "type": "base64"})
        except Exception:
            pass

    pattern2 = re.compile(r'''(?:window\.)?location\s*=\s*['"]([A-Za-z0-9+/=]{20,})['"]''')
    for match in pattern2.finditer(content):
        encoded = match.group(1)
        try:
            result = base64.b64decode(encoded).decode("utf-8", errors="ignore")
            if result.startswith("http") or "/" in result:
                decoded.append({"encoded": match.group(0), "decoded": result, "type": "base64_redirect"})
        except Exception:
            pass

    return decoded


def decode_hex_strings(content):
    """Decode hex escape sequences like \\x41\\x42 -> AB."""
    decoded = []
    pattern = re.compile(r'''(?:['"])(\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){2,})(?:['"])''')
    for match in pattern.finditer(content):
        hex_str = match.group(1)
        try:
            result = codecs.decode(hex_str, "unicode_escape")
            if result.isprintable():
                decoded.append({"encoded": match.group(0), "decoded": result, "type": "hex"})
        except Exception:
            pass
    return decoded


def decode_unicode_strings(content):
    """Decode unicode escape sequences like \\u0041\\u0042 -> AB."""
    decoded = []
    pattern = re.compile(r'''(?:['"])(\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){2,})(?:['"])''')
    for match in pattern.finditer(content):
        uni_str = match.group(1)
        try:
            result = codecs.decode(uni_str, "unicode_escape")
            if result.isprintable():
                decoded.append({"encoded": match.group(0), "decoded": result, "type": "unicode"})
        except Exception:
            pass
    return decoded


def extract_eval_payloads(content):
    """Extract content from eval() calls — often contains obfuscated code."""
    decoded = []
    pattern = re.compile(r'''eval\s*\(\s*(?:atob\s*\(\s*)?['"]([^'"]{10,})['"]''')
    for match in pattern.finditer(content):
        payload = match.group(1)
        if "\\x" in payload or "\\u" in payload:
            try:
                result = codecs.decode(payload, "unicode_escape")
                decoded.append({"encoded": match.group(0), "decoded": result, "type": "eval_payload"})
            except Exception:
                decoded.append({"encoded": match.group(0), "decoded": payload, "type": "eval_raw"})
        elif re.match(r'^[A-Za-z0-9+/=]+$', payload) and len(payload) > 12:
            try:
                result = base64.b64decode(payload).decode("utf-8", errors="ignore")
                if result.isprintable():
                    decoded.append({"encoded": match.group(0), "decoded": result, "type": "eval_base64"})
            except Exception:
                pass
    return decoded


def decode_from_char_code(content):
    """Decode String.fromCharCode(72,101,108) -> Hello."""
    decoded = []
    pattern = re.compile(r'String\.fromCharCode\s*\(([\d,\s]+)\)')
    for match in pattern.finditer(content):
        codes_str = match.group(1)
        try:
            codes = [int(c.strip()) for c in codes_str.split(",") if c.strip()]
            result = "".join(chr(c) for c in codes if 0 <= c <= 0x10FFFF)
            if result.isprintable():
                decoded.append({"encoded": match.group(0), "decoded": result, "type": "fromCharCode"})
        except Exception:
            pass
    return decoded


def decode_char_comparisons(content):
    """Decode patterns like '\\x68\\x74\\x74\\x70' built via char concatenation."""
    decoded = []
    full_chain = re.compile(r'''(?:['"])(?:\\x[0-9a-fA-F]{2}(?:\s*\+\s*['"]\\x[0-9a-fA-F]{2}['"])+)(?:['"])''')
    for match in full_chain.finditer(content):
        hex_chars = re.findall(r'\\x([0-9a-fA-F]{2})', match.group(0))
        try:
            result = "".join(chr(int(h, 16)) for h in hex_chars)
            if result.isprintable():
                decoded.append({"encoded": match.group(0), "decoded": result, "type": "char_chain"})
        except Exception:
            pass
    return decoded


def deobfuscate(content):
    """
    Run all deobfuscation passes on JS content.
    Returns the content with decoded strings appended as comments,
    plus a list of all findings.
    """
    findings = []

    findings.extend(decode_base64_strings(content))
    findings.extend(decode_hex_strings(content))
    findings.extend(decode_unicode_strings(content))
    findings.extend(extract_eval_payloads(content))
    findings.extend(decode_from_char_code(content))
    findings.extend(decode_char_comparisons(content))

    enriched = content
    for f in findings:
        if f["decoded"] not in enriched:
            enriched += f"\n/* DEOBFUSCATED [{f['type']}]: {f['decoded']} */"

    return enriched, findings
