"""
Endpoint enrichment: method inference, protocol tags, auth/state hints.

Works on intercepted/SPA endpoint dicts ({url, method, …}). Bare-string
pools (internal_paths / in_scope_urls) stay unchanged for compatibility.
"""

from urllib.parse import urlparse

# Path segment → method when no real HTTP verb was observed (or only a
# weak SPA-default GET was recorded).
_METHOD_SEGMENT_HINTS = {
    "create": "POST",
    "register": "POST",
    "signup": "POST",
    "login": "POST",
    "logout": "POST",
    "upload": "POST",
    "submit": "POST",
    "store": "POST",
    "save": "POST",
    "authenticate": "POST",
    "delete": "DELETE",
    "remove": "DELETE",
    "destroy": "DELETE",
    "update": "PUT",
    "edit": "PUT",
    "replace": "PUT",
    "patch": "PATCH",
}

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Paths that usually sit behind auth (admin consoles, personal data, …)
AUTH_PATH_HINTS = (
    "/admin", "/account", "/profile", "/dashboard", "/settings",
    "/user/", "/users/", "/me", "/private", "/internal", "/staff",
    "/console", "/manage", "/manager", "/billing", "/payment",
)


def _path_of(url):
    """Path portion of a URL or a bare path string (query/fragment stripped)."""
    if not url:
        return ""
    if "://" in url or url.startswith("//"):
        try:
            return urlparse(url).path or ""
        except ValueError:
            return url.split("?")[0].split("#")[0]
    return url.split("?")[0].split("#")[0]


def infer_method(url):
    """
    Guess HTTP method from path segments (create/delete/…).
    Returns an uppercase method or None when no signal.
    """
    path = _path_of(url)
    for segment in path.split("/"):
        hint = _METHOD_SEGMENT_HINTS.get(segment.lower())
        if hint:
            return hint
    return None


def resolve_method(url, observed=None):
    """
    Combine an observed method with path inference.

    Returns (method, source) where source is:
      observed — real browser/network method (non-GET)
      inferred — path keyword overrode a weak/missing GET default
      default  — GET with no signal
    """
    observed_u = (observed or "").strip().upper() or None
    inferred = infer_method(url)

    if observed_u and observed_u != "GET":
        return observed_u, "observed"
    if observed_u == "GET":
        if inferred and inferred != "GET":
            return inferred, "inferred"
        return "GET", "observed"
    if inferred:
        return inferred, "inferred"
    return "GET", "default"


def endpoint_tags(url):
    """Protocol / surface tags: graphql, trpc, websocket, auth, api, spa."""
    tags = []
    if not url:
        return tags
    low = url.lower()
    path = _path_of(url).lower()

    if "graphql" in path or path.rstrip("/").endswith("/gql"):
        tags.append("graphql")
    if "/trpc" in path or path.startswith("trpc") or ".trpc." in low:
        tags.append("trpc")
    if (
        low.startswith("ws://")
        or low.startswith("wss://")
        or "/socket.io" in path
        or path.rstrip("/").endswith("/ws")
        or "/websocket" in path
        or "/sockjs" in path
        or "/eventsource" in path
    ):
        tags.append("websocket")
    if any(
        h in path
        for h in ("/auth", "/login", "/logout", "/oauth", "/session", "/token", "/sso", "/signin")
    ):
        tags.append("auth")
    if (
        "/api" in path
        or path.startswith("/v1/")
        or path.startswith("/v2/")
        or path.startswith("/v3/")
        or path.rstrip("/") in ("/api", "/v1", "/v2", "/v3")
        or "/rest" in path
        or "/rpc" in path
    ):
        tags.append("api")
    if any(h in path for h in ("/admin", "/wp-admin", "/wp-login")):
        tags.append("admin")
    return tags


def is_state_changing(method, url=None):
    """True for verbs that mutate server state (POST/PUT/PATCH/DELETE)."""
    del url  # signature kept for call-site clarity
    return (method or "GET").upper() in STATE_CHANGING_METHODS


def is_likely_authed(url, method=None):
    """
    Heuristic: endpoint likely requires credentials (jsrip-style).
    Auth-ish path OR state-changing verb OR GraphQL.
    """
    path = _path_of(url)
    if any(hint in path for hint in AUTH_PATH_HINTS):
        return True
    if is_state_changing(method, url):
        return True
    if "graphql" in path.lower():
        return True
    return False


def enrich_endpoint(endpoint):
    """
    Annotate one {url, method, …} dict in place:
    method, method_source, tags, state_changing, likely_authed.
    Non-dict / missing url entries are returned unchanged.
    """
    if not isinstance(endpoint, dict):
        return endpoint
    url = endpoint.get("url") or ""
    if not url:
        return endpoint

    method, source = resolve_method(url, endpoint.get("method"))
    endpoint["method"] = method
    endpoint["method_source"] = source
    endpoint["tags"] = endpoint_tags(url)
    endpoint["state_changing"] = is_state_changing(method, url)
    endpoint["likely_authed"] = is_likely_authed(url, method)
    return endpoint


def enrich_intercepted_endpoints(endpoints):
    """Enrich every dict endpoint in a list (returns the same list)."""
    for ep in endpoints or []:
        enrich_endpoint(ep)
    return endpoints
