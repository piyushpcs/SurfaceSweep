"""
GraphQL endpoint probing — introspection query to detect open schema exposure.

Phase F3: POST a minimal introspection query to candidate /graphql URLs and
report whether the full schema is publicly readable (often HIGH severity).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from modules.common.console import warn

__all__ = [
    "INTROSPECTION_QUERY",
    "probe_introspection",
    "probe_graphql_endpoints",
    "collect_graphql_candidates",
]


# Minimal introspection: query/mutation root names + type list (name/kind).
INTROSPECTION_QUERY = (
    "{__schema{queryType{name}mutationType{name}"
    "types{name kind}}}"
)


def _is_graphql_path(url: str) -> bool:
    if not url:
        return False
    path = urlparse(url).path.lower() if "://" in url else url.lower()
    return (
        "graphql" in path
        or path.rstrip("/").endswith("/gql")
        or path.rstrip("/").endswith("/graphiql")
        or path.rstrip("/").endswith("/playground")
    )


def collect_graphql_candidates(result: Dict[str, Any], target: str) -> List[str]:
    """
    Gather GraphQL-like endpoint URLs from a scan result.

    Sources: collect_endpoints-style pools already in the result
    (internal_paths / in_scope_urls / intercepted_endpoints), plus common
    fallback paths on the target origin when nothing graphql-tagged is found.
    """
    from modules.pipeline.merge import collect_endpoints

    seen: set = set()
    candidates: List[str] = []

    def _add(url: Optional[str]) -> None:
        if not url or url in seen:
            return
        if not _is_graphql_path(url):
            return
        seen.add(url)
        candidates.append(url)

    for url in collect_endpoints(result, target=target):
        _add(url)

    for ep in result.get("intercepted_endpoints") or []:
        tags = ep.get("tags") or []
        if "graphql" in tags:
            _add(ep.get("url"))

    # Fallback: probe standard paths when the scan found none (still opt-in via --graphql).
    if not candidates and target:
        origin = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        for path in ("/graphql", "/api/graphql", "/gql"):
            _add(origin + path)

    return candidates


def probe_introspection(
    url: str,
    timeout: float = 5.0,
    session=None,
    headers: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    POST an introspection query to `url`.

    Returns a dict:
      {url, status, introspection_enabled, query_type, mutation_type,
       type_count, types, error}
    """
    import requests as _requests

    from modules.extraction.http import request_kwargs

    http = session if session is not None else _requests
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    # Merge proxy/TLS/UA from process-wide HttpClient config when not injecting a session.
    kwargs: Dict[str, Any] = {}
    if session is None:
        kwargs = request_kwargs(headers=req_headers)
        # request_kwargs already sets headers; keep Content-Type + caller headers
        merged = dict(kwargs.get("headers") or {})
        merged.update(req_headers)
        kwargs["headers"] = merged
    else:
        kwargs = {"headers": req_headers}

    result: Dict[str, Any] = {
        "url": url,
        "status": None,
        "introspection_enabled": False,
        "query_type": None,
        "mutation_type": None,
        "type_count": 0,
        "types": [],
        "error": None,
    }

    try:
        resp = http.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            timeout=timeout,
            **kwargs,
        )
    except _requests.RequestException as exc:
        result["error"] = str(exc) or exc.__class__.__name__
        return result

    result["status"] = getattr(resp, "status_code", None)
    try:
        data = resp.json()
    except Exception:
        result["error"] = "non-JSON response"
        return result

    if not isinstance(data, dict):
        result["error"] = "unexpected JSON shape"
        return result

    schema = ((data.get("data") or {}).get("__schema")) or data.get("__schema")
    if not isinstance(schema, dict):
        # GraphQL may exist but introspection is disabled/blocked
        errors = data.get("errors")
        if errors:
            result["error"] = "introspection blocked or query rejected"
        else:
            result["error"] = "no __schema in response"
        return result

    result["introspection_enabled"] = True
    query_type = schema.get("queryType") or {}
    mutation_type = schema.get("mutationType") or {}
    result["query_type"] = query_type.get("name") if isinstance(query_type, dict) else None
    result["mutation_type"] = (
        mutation_type.get("name") if isinstance(mutation_type, dict) else None
    )
    types = schema.get("types") or []
    if isinstance(types, list):
        # Keep a bounded sample for reporting; count is the full length.
        result["type_count"] = len(types)
        result["types"] = [
            t.get("name")
            for t in types[:40]
            if isinstance(t, dict) and t.get("name")
        ]
    return result


def probe_graphql_endpoints(
    urls: List[str],
    timeout: float = 5.0,
    verbose: bool = True,
    headers: Optional[dict] = None,
    session=None,
) -> Dict[str, Any]:
    """
    Probe each candidate URL for open introspection.

    Returns {endpoints, findings, endpoints_tested, introspection_open, summary}.
    """
    endpoints: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    for url in urls:
        ep = probe_introspection(
            url, timeout=timeout, session=session, headers=headers
        )
        endpoints.append(ep)
        if ep.get("introspection_enabled"):
            n_types = ep.get("type_count", 0)
            findings.append({
                "severity": "HIGH",
                "url": url,
                "detail": (
                    f"GraphQL introspection enabled — {n_types} type(s) exposed; "
                    f"query={ep.get('query_type') or '?'} "
                    f"mutation={ep.get('mutation_type') or 'n/a'}"
                ),
                "type_count": n_types,
                "query_type": ep.get("query_type"),
            })
            if verbose:
                warn(f"GraphQL introspection open at {url} ({n_types} types)")

    open_count = sum(1 for e in endpoints if e.get("introspection_enabled"))
    summary = {
        "endpoints_tested": len(endpoints),
        "introspection_open": open_count,
        "graphql_confirmed": sum(
            1
            for e in endpoints
            if e.get("introspection_enabled")
            or (e.get("status") and not e.get("error", "").startswith("non-JSON"))
        ),
    }
    return {
        "endpoints": endpoints,
        "findings": findings,
        "endpoints_tested": len(endpoints),
        "introspection_open": open_count,
        "summary": summary,
    }
