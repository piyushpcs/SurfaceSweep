"""
Scope and domain utilities.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

import tldextract


def get_registrable_domain(url: str) -> str:
    """Extract the registered domain (e.g. 'example.com' from 'sub.example.com')."""
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or urlparse(url).netloc


def normalize_scope_filter(raw: Optional[str]) -> Optional[str]:
    """
    Normalize a --scope CLI value to a registrable domain for is_same_scope().

    Accepts hostnames, URLs, and wildcard forms:
      '*.target.com'  -> 'target.com'
      'target.com'    -> 'target.com'
      'https://a.target.com/path' -> 'target.com'
      'localhost' / bare IPs are kept as-is (no public-suffix reduction).

    Returns None when the input is empty/absent (no scope restriction).
    """
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    if "://" in s:
        s = urlparse(s).netloc or s
    if s.startswith("*."):
        s = s[2:]
    if "/" in s:
        s = s.split("/", 1)[0]
    if s.startswith("[") and "]" in s:
        s = s[1:s.index("]")]
    elif s.count(":") == 1:
        # host:port — keep host only for comparison against registrable domains
        host, port = s.rsplit(":", 1)
        if port.isdigit():
            s = host
    if not s:
        return None
    ext = tldextract.extract(s)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return s


def is_same_scope(url: str, target_domain: str) -> bool:
    """
    Check if a URL belongs to the target's scope.

    target_domain should be a registrable domain (use normalize_scope_filter
    on raw --scope values). Wildcards are normalized defensively so a raw
    '*.example.com' still matches.
    """
    if not target_domain:
        return True
    normalized = normalize_scope_filter(target_domain) or target_domain
    return get_registrable_domain(url) == normalized
