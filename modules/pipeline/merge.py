"""
Shared merge helpers for pipeline stages (Phase 4 Step 2).

One dialect for combining fragment findings (wayback, SPA) into the
primary scan result, and one collector for the endpoint pool used by
CORS / validation.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from modules.extraction import deduplicate_secrets, deduplicate_sinks, deduplicate_pii, is_static_asset
from modules.extraction.params import deduplicate_params
from modules.extraction.scope import is_same_scope, get_registrable_domain
from modules.jwt import deduplicate_jwts


def flatten_secrets(secrets: Sequence[dict]) -> List[dict]:
    """Normalize secrets to {type, match, source} (accepts sources[] or source)."""
    flat = []
    for s in secrets or []:
        if "sources" in s:
            for src in s["sources"]:
                flat.append({"type": s["type"], "match": s["match"], "source": src})
        else:
            flat.append({
                "type": s.get("type", ""),
                "match": s.get("match", ""),
                "source": s.get("source", "unknown"),
            })
    return flat


def merge_secrets(result: dict, new_secrets: Optional[Sequence[dict]]) -> None:
    """Append fragment secrets into result['secrets_found'] and dedupe."""
    if not new_secrets:
        return
    combined = list(result.get("secrets_found") or []) + list(new_secrets)
    result["secrets_found"] = deduplicate_secrets(flatten_secrets(combined))


def merge_sinks(result: dict, new_sinks: Optional[Sequence[dict]]) -> None:
    """Append fragment sinks and dedupe (sources list + total count)."""
    if not new_sinks:
        return
    combined = list(result.get("sinks_found") or []) + list(new_sinks)
    # Flatten sources→source so deduplicate_sinks sees one source per row
    flat = []
    for s in combined:
        if "sources" in s:
            for src in s["sources"]:
                flat.append({**s, "source": src, "count": 1})
        else:
            flat.append(s)
    result["sinks_found"] = deduplicate_sinks(flat)


def merge_jwts(result: dict, new_jwts: Optional[Sequence[dict]]) -> None:
    """Append fragment JWTs and dedupe by token value."""
    if not new_jwts:
        return
    result["jwts_found"] = deduplicate_jwts(
        list(result.get("jwts_found") or []) + list(new_jwts)
    )


def merge_pii(result: dict, new_pii: Optional[Sequence[dict]]) -> None:
    """Append fragment PII findings and dedupe by (kind, match)."""
    if not new_pii:
        return
    combined = list(result.get("pii_found") or []) + list(new_pii)
    flat = []
    for p in combined:
        if "sources" in p:
            for src in p["sources"]:
                flat.append({**p, "source": src})
        else:
            flat.append(p)
    result["pii_found"] = deduplicate_pii(flat)


def merge_params(result: dict, new_params: Optional[Sequence[dict]]) -> None:
    """Append fragment parameter findings and dedupe by (name, kind)."""
    if not new_params:
        return
    combined = list(result.get("params_found") or []) + list(new_params)
    flat = []
    for p in combined:
        if "sources" in p and "source" not in p:
            for src in p["sources"]:
                flat.append({"name": p.get("name"), "kind": p.get("kind"), "source": src})
        else:
            flat.append(p)
    result["params_found"] = deduplicate_params(flat)


def merge_internal_hosts(result: dict, new_hosts: Optional[Sequence[dict]]) -> None:
    """Append fragment internal hosts; first-seen wins per match value."""
    if not new_hosts:
        return
    seen = {h.get("match") for h in result.get("internal_hosts_found", [])}
    for h in new_hosts:
        key = h.get("match")
        if key and key not in seen:
            seen.add(key)
            result.setdefault("internal_hosts_found", []).append(h)


def merge_errors(result: dict, new_errors: Optional[Iterable[str]]) -> None:
    """Union error strings into result['errors'] (sorted for determinism)."""
    if not new_errors:
        return
    result["errors"] = sorted(set(
        list(result.get("errors") or []) + [str(e) for e in new_errors]
    ))


def merge_paths(result: dict, new_paths: Iterable[str]) -> int:
    """
    Add relative paths into internal_paths (static-asset filtered, sorted).
    Returns count of paths actually added.
    """
    existing = set(result.get("internal_paths") or [])
    added = [
        p for p in new_paths
        if p.startswith("/") and not p.startswith("//")
        and p not in existing and not is_static_asset(p)
    ]
    if not added:
        return 0
    result["internal_paths"] = sorted(existing | set(added))
    return len(added)


def merge_in_scope_urls(result: dict, new_urls: Iterable[str], target: str) -> int:
    """
    Add absolute URLs into in_scope_urls when same registrable domain.
    Returns count of URLs actually added.
    """
    if not new_urls:
        return 0
    domain = get_registrable_domain(target)
    existing = set(result.get("in_scope_urls") or [])
    added = [
        u for u in new_urls
        if u.startswith("http") and u not in existing
        and not is_static_asset(u) and is_same_scope(u, domain)
    ]
    if not added:
        return 0
    result["in_scope_urls"] = sorted(existing | set(added))
    return len(added)


def merge_endpoints(result: dict, endpoints: Iterable[str], target: str) -> int:
    """
    Split a mixed endpoint collection into internal_paths vs in_scope_urls.
    Returns total number of entries added across both lists.
    """
    endpoints = list(endpoints or [])
    paths = [e for e in endpoints if e.startswith("/") and not e.startswith("//")]
    urls = [e for e in endpoints if e.startswith("http")]
    return merge_paths(result, paths) + merge_in_scope_urls(result, urls, target)


def collect_endpoints(result: dict, target: Optional[str] = None) -> List[str]:
    """
    Canonical endpoint pool for CORS / validation:
    internal_paths + in_scope_urls + intercepted endpoint URLs (deduped, sorted).

    When target is provided, absolute intercepted URLs outside the target's
    registrable domain are excluded so third-party analytics/CDN calls are
    never probed. Relative paths and same-scope absolute URLs are kept.
    """
    pool = set(result.get("internal_paths") or [])
    pool.update(result.get("in_scope_urls") or [])
    scope_domain = get_registrable_domain(target) if target else None
    for e in result.get("intercepted_endpoints") or []:
        url = e.get("url") if isinstance(e, dict) else None
        if not url:
            continue
        if scope_domain and url.startswith("http") and not is_same_scope(url, scope_domain):
            continue
        pool.add(url)
    return sorted(pool)


def merge_wayback(result: dict, wb: dict, target: str) -> dict:
    """
    Merge a wayback fragment into result.

    Fixes vs the old inline block:
      - not gated on non-empty endpoints (js_files/secrets/errors still merge)
      - absolute same-scope URLs go to in_scope_urls (previously dropped)
      - secrets deduped
      - errors merged
    Returns stats: {paths, urls, secrets, errors}.
    """
    stats = {"paths": 0, "urls": 0, "secrets": 0, "errors": 0}

    endpoints = wb.get("endpoints") or []
    # endpoints may be a set from wayback.py
    if isinstance(endpoints, set):
        endpoints = sorted(endpoints)
    stats["paths"] = merge_paths(result, endpoints)
    stats["urls"] = merge_in_scope_urls(result, endpoints, target)

    result["wayback_js_files"] = list(wb.get("js_files") or [])

    before_secrets = len(result.get("secrets_found") or [])
    merge_secrets(result, wb.get("secrets"))
    stats["secrets"] = len(result.get("secrets_found") or []) - before_secrets

    merge_sinks(result, wb.get("sinks"))
    merge_internal_hosts(result, wb.get("internal_hosts"))
    merge_jwts(result, wb.get("jwts"))
    merge_pii(result, wb.get("pii"))
    merge_params(result, wb.get("params"))

    before_errors = len(result.get("errors") or [])
    merge_errors(result, wb.get("errors"))
    stats["errors"] = len(result.get("errors") or []) - before_errors
    return stats
