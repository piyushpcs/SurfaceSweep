"""
robots.txt and sitemap.xml discovery for SurfaceSweep.

Reads standard crawler manifests on the target origin and extracts
literal paths/URLs that often surface admin areas, API prefixes, and
content trees not linked from the HTML/JS crawl.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse

from modules.common.console import detail, info, ok
from modules.extraction.http import fetch_text

__all__ = [
    "discover_robots_and_sitemap",
    "parse_robots",
    "parse_sitemap_locs",
]

# Nested sitemap indexes / sibling maps we are willing to follow.
_MAX_SITEMAPS = 3
_LOC_RE = re.compile(r"<loc>\s*([^<\s][^<]*?)\s*</loc>", re.IGNORECASE)


def _normalize_path(value: str) -> Optional[str]:
    """Normalize a robots Allow/Disallow value to a clean absolute path."""
    if not value:
        return None
    path = value.strip()
    if not path.startswith("/") or path.startswith("//"):
        return None
    # Prefix rules like /admin/* → /admin ; bare /* or / is useless as a route
    if path.endswith("*"):
        path = path.rstrip("*")
    if not path or path == "/":
        return None
    # Drop query/fragment noise and collapse duplicate slashes (keep leading /)
    path = path.split("#", 1)[0].split("?", 1)[0]
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    if not path or path == "/":
        return None
    return path


def parse_robots(text: str) -> Dict[str, List[str]]:
    """
    Parse robots.txt into literal paths and Sitemap URLs.

    Wildcard-only or site-root rules are skipped; ``Sitemap:`` entries are
    returned as absolute URLs for the caller to fetch.
    """
    paths: List[str] = []
    sitemaps: List[str] = []
    seen_paths = set()
    seen_maps = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "sitemap":
            if value.startswith("http") and value not in seen_maps:
                seen_maps.add(value)
                sitemaps.append(value)
        elif key in ("allow", "disallow"):
            path = _normalize_path(value)
            if path and path not in seen_paths:
                seen_paths.add(path)
                paths.append(path)
    return {"paths": paths, "sitemaps": sitemaps}


def parse_sitemap_locs(text: str) -> List[str]:
    """Extract ``<loc>`` URLs from sitemap XML (urlset or sitemapindex)."""
    if not text:
        return []
    locs: List[str] = []
    seen = set()
    for match in _LOC_RE.findall(text):
        url = match.strip()
        if url and url not in seen:
            seen.add(url)
            locs.append(url)
    return locs


def _path_from_url(url: str, base_netloc: str) -> Optional[str]:
    """Same-host absolute URL → path, or None if cross-host/non-path."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    if parsed.netloc.lower() != base_netloc.lower():
        return None
    path = parsed.path or "/"
    if not path.startswith("/"):
        return None
    if path == "/":
        return None
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path or None


def discover_robots_and_sitemap(
    base_url: str,
    timeout: int = 10,
    verbose: bool = True,
    fetch=fetch_text,
) -> Dict[str, List[str]]:
    """
    Fetch ``/robots.txt`` and sitemaps from the target origin.

    Returns ``{"paths": [...], "urls": [...]}`` — relative paths for
    ``internal_paths`` and same-origin absolute URLs (usually sitemap locs
    that already include useful paths). Never raises; network failures are
    treated as "nothing found".
    """
    base = (base_url or "").rstrip("/")
    if not base.startswith("http"):
        return {"paths": [], "urls": []}
    netloc = urlparse(base).netloc
    if not netloc:
        return {"paths": [], "urls": []}

    if verbose:
        info(" Checking robots.txt / sitemap.xml...")

    paths: List[str] = []
    urls: List[str] = []
    seen_paths = set()
    seen_urls = set()

    def _add_path(path: Optional[str]) -> None:
        if path and path not in seen_paths:
            seen_paths.add(path)
            paths.append(path)

    def _add_url(url: str) -> None:
        if url and url not in seen_urls:
            seen_urls.add(url)
            urls.append(url)

    robots_text = fetch(f"{base}/robots.txt", timeout=timeout)
    sitemaps: List[str] = []
    if robots_text:
        parsed = parse_robots(robots_text)
        for path in parsed["paths"]:
            _add_path(path)
        sitemaps.extend(parsed["sitemaps"])
        if verbose and parsed["paths"]:
            detail(f"[+] robots.txt: {len(parsed['paths'])} path(s)")

    # Always probe the conventional sitemap location when robots omits it.
    default_sitemap = f"{base}/sitemap.xml"
    if default_sitemap not in sitemaps:
        sitemaps.append(default_sitemap)

    fetched_sitemaps = set()
    for sm_url in sitemaps[:_MAX_SITEMAPS]:
        if sm_url in fetched_sitemaps:
            continue
        fetched_sitemaps.add(sm_url)
        sm_text = fetch(sm_url, timeout=timeout)
        if not sm_text:
            continue
        locs = parse_sitemap_locs(sm_text)
        # sitemapindex: follow a few nested maps (same host only)
        nested = [
            u for u in locs
            if u.lower().endswith(".xml")
            and urlparse(u).netloc.lower() == netloc.lower()
        ]
        for nested_url in nested[:_MAX_SITEMAPS]:
            if nested_url in fetched_sitemaps:
                continue
            fetched_sitemaps.add(nested_url)
            nested_text = fetch(nested_url, timeout=timeout)
            if nested_text:
                locs.extend(parse_sitemap_locs(nested_text))

        for loc in locs:
            path = _path_from_url(loc, netloc)
            if path:
                _add_path(path)
                _add_url(loc)
            elif loc.lower().endswith(".xml") is False and loc.startswith("http"):
                # Cross-host or root — keep only same-host absolute URLs
                pass

        if verbose and locs:
            detail(f"[+] sitemap: {len(locs)} loc(s) from {sm_url}")

    if verbose:
        ok(f" robots/sitemap: {len(paths)} path(s), {len(urls)} URL(s)")

    return {"paths": paths, "urls": urls}
