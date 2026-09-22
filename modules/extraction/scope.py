"""
Scope and domain utilities.
"""

import tldextract
from urllib.parse import urlparse


def get_registrable_domain(url):
    """Extract the registered domain (e.g. 'example.com' from 'sub.example.com')."""
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or urlparse(url).netloc


def is_same_scope(url, target_domain):
    """Check if a URL belongs to the target's registrable domain."""
    return get_registrable_domain(url) == target_domain
