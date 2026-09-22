"""
AST-based endpoint extraction using tree-sitter.

Complements regex extraction by parsing JS into an Abstract Syntax Tree
and walking it to find:
  - call expressions: fetch(), axios.get(), $.ajax(), XMLHttpRequest.open()
  - URL/path string literals (including template literal static parts)
  - URL-ish property assignments: { url: "/api/x" }, path = "/api/x"
  - string literals inside comments (catches deobfuscator output)

Advantages over regex:
  - No false positives from strings that merely contain keywords
  - Catches endpoints built via template literals (partial static parts)
  - Survives minified/broken code via tree-sitter error recovery
  - Understands actual call-site structure, not just text adjacency
"""

try:
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser, Query, QueryCursor
    _JS_LANG = Language(tsjs.language())
    _PARSER = Parser(_JS_LANG)
    AST_AVAILABLE = True
except ImportError:
    AST_AVAILABLE = False
    _JS_LANG = None
    _PARSER = None


# HTTP client call targets we care about (function name → arg index that holds URL)
HTTP_CALLS = {
    "fetch": 0,
    "axios": 0,
    "request": 0,
}

# Member-expression method names (axios.get, axios.post, $.ajax, $.get, ...)
HTTP_METHODS = {
    "get", "post", "put", "delete", "patch", "head", "options",
    "ajax", "request", "getJSON", "postJSON",
}

# Property keys that typically hold a URL/path value
URL_PROPERTY_KEYS = {
    "url", "uri", "href", "path", "endpoint", "baseurl", "base_url",
    "apiurl", "api_url", "apiroot", "api_root", "route", "resource",
}

# String prefixes that mark a value as a URL/path candidate
PATH_PREFIXES = ("/", "http://", "https://", "//")


def _node_text(node, src):
    """Extract text for a node as a Python string."""
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _unwrap_string(text):
    """Strip quotes from a string literal, handling both quote types."""
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        return text[1:-1]
    return text


def _is_endpoint_candidate(value):
    """Quick filter: does this string look like it could be an endpoint?"""
    if not value or len(value) < 3 or len(value) > 300:
        return False
    if not value.startswith(PATH_PREFIXES):
        return False
    # Skip pure anchors / fragments
    if value.startswith("#"):
        return False
    # Skip CSS/HTML selector fragments that happen to start with /
    # e.g. '/wp-content"],meta[name="generator"]...'
    if any(c in value for c in ('"', "'", "]", "}", ";", "{", "<", ">", "\n", "\t")):
        return False
    # Skip paths with spaces (likely prose or selector text)
    if " " in value:
        return False
    # Path portion (after leading /) must be at least 2 chars to avoid
    # single-letter noise from minified code (/a, /d, /g, etc.)
    path_part = value.lstrip("/").split("?")[0].split("#")[0]
    if len(path_part) < 2:
        return False
    return True


def _extract_template_static_parts(text):
    """
    From a template literal like `/api/v1/${id}/users`, extract the
    static prefix `/api/v1/` (and any fully static segments).
    Returns a list of static substrings that look like paths.
    """
    import re as _re
    # Remove ${...} interpolations, keep static parts
    parts = _re.split(r"\$\{[^}]*\}", text)
    results = []
    for part in parts:
        part = part.strip()
        if part and part.startswith("/") and len(part) >= 2:
            results.append(part)
    return results


def _get_function_name(node, src):
    """
    Resolve the callee of a call_expression to a dotted name string.
    e.g. 'axios.get', '$.ajax', 'fetch', 'window.fetch'
    """
    fn = node.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type == "identifier":
        return _node_text(fn, src)
    if fn.type == "member_expression":
        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        if obj and prop:
            obj_name = _node_text(obj, src)
            prop_name = _node_text(prop, src)
            # Handle chains: axios.default.get → axios.default.get
            # We only need the last two segments for matching
            return f"{obj_name}.{prop_name}"
        return _node_text(fn, src)
    if fn.type == "subscript_expression":
        # e.g. client['get'](...) — fall back to raw text
        return _node_text(fn, src)
    return _node_text(fn, src)


def _matches_http_call(func_name):
    """
    Check if a resolved callee name matches a known HTTP client call.
    Handles: fetch, axios, axios.get, axios.post, $.ajax, $.get, $.post,
    window.fetch, http.request, XMLHttpRequest.prototype.open, etc.
    """
    if not func_name:
        return False
    name = func_name.lower()

    # Exact matches
    if name in ("fetch", "axios", "request"):
        return True
    if name.endswith(".ajax") or name.endswith("$.ajax"):
        return True

    # Member method matches: axios.get, $.post, http.request, etc.
    parts = name.split(".")
    if len(parts) >= 2:
        method = parts[-1]
        obj = parts[-2]
        if method in HTTP_METHODS:
            # axios.*, $.ajax, http.request, superagent, etc.
            if obj in ("axios", "$", "jquery", "http", "https", "request",
                       "superagent", "got", "ky", "node-fetch", "ofetch",
                       "window", "global", "self", "client", "api", "httpclient"):
                return True
            # Generic: anyObj.method where method is a known HTTP verb
            # (catches minified aliases like n.get(...))
            if method in ("get", "post", "put", "delete", "patch"):
                # Only match if object name hints at HTTP (too risky otherwise)
                if any(h in obj for h in ("api", "http", "client", "rest", "ajax", "request", "axios", "fetch")):
                    return True

    # XMLHttpRequest open
    if "xmlhttprequest" in name and name.endswith(".open"):
        return True

    return False


def _extract_url_from_args(args_node, src, func_name):
    """
    Extract URL candidates from a call_expression's arguments node.
    Returns list of string values.
    """
    results = []

    if args_node is None:
        return results

    children = args_node.named_children
    if not children:
        return results

    # fetch(url, init) / axios(url, config) — first positional arg
    # axios.get(url, config) — first positional arg
    # $.ajax({ url: "...", ... }) — object with url property
    # XMLHttpRequest.open(method, url, ...) — second positional arg

    first = children[0]

    if first.type == "string":
        val = _unwrap_string(_node_text(first, src))
        results.append(val)

    elif first.type == "template_string":
        raw = _node_text(first, src)
        # Strip backticks
        inner = raw[1:-1] if raw.startswith("`") and raw.endswith("`") else raw
        # Extract static parts
        static_parts = _extract_template_static_parts(inner)
        results.extend(static_parts)
        # Also: if no interpolation at all, the whole thing is the URL
        if "${" not in inner:
            results.append(inner)

    elif first.type == "object":
        # Object literal — look for url/path/endpooint properties
        for prop in first.named_children:
            if prop.type != "pair":
                continue
            key_node = prop.child_by_field_name("key")
            val_node = prop.child_by_field_name("value")
            if key_node is None or val_node is None:
                continue
            key = _unwrap_string(_node_text(key_node, src)).lower()
            if key in URL_PROPERTY_KEYS:
                if val_node.type == "string":
                    results.append(_unwrap_string(_node_text(val_node, src)))
                elif val_node.type == "template_string":
                    raw = _node_text(val_node, src)
                    inner = raw[1:-1] if raw.startswith("`") and raw.endswith("`") else raw
                    static_parts = _extract_template_static_parts(inner)
                    results.extend(static_parts)
                    if "${" not in inner:
                        results.append(inner)

    elif first.type in ("identifier", "member_expression", "subscript_expression"):
        # Variable reference — can't resolve statically, skip
        pass

    # XMLHttpRequest.open(method, url, ...) — url is second arg
    if func_name and "xmlhttprequest" in func_name.lower() and len(children) >= 2:
        second = children[1]
        if second.type == "string":
            results.append(_unwrap_string(_node_text(second, src)))

    return results


def _walk(node):
    """Iterative pre-order walk of the AST (avoids recursion limits)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        # Push children in reverse so they're processed left-to-right
        stack.extend(reversed(current.children))


def extract_endpoints_ast(content, source_label=""):
    """
    Parse JS content and extract endpoint candidates via AST walk.

    Returns a set of endpoint strings (same shape as regex extraction).
    Never raises — on parse failure returns empty set.
    """
    if not AST_AVAILABLE or not content:
        return set()

    # tree-sitter works on bytes
    src_bytes = content.encode("utf-8", errors="replace")

    try:
        tree = _PARSER.parse(src_bytes)
    except Exception:
        return set()

    endpoints = set()

    # Convert to str once for text extraction
    src = src_bytes

    for node in _walk(tree.root_node):

        # --- 1. Call expressions: fetch(), axios.get(), $.ajax(), etc. ---
        if node.type == "call_expression":
            func_name = _get_function_name(node, src)
            if _matches_http_call(func_name):
                args_node = node.child_by_field_name("arguments")
                for url in _extract_url_from_args(args_node, src, func_name):
                    if _is_endpoint_candidate(url):
                        endpoints.add(url)

        # --- 2. String literals that look like endpoints ---
        elif node.type == "string":
            val = _unwrap_string(_node_text(node, src))
            if _is_endpoint_candidate(val):
                endpoints.add(val)

        # --- 3. Template literals: extract static path parts ---
        elif node.type == "template_string":
            raw = _node_text(node, src)
            inner = raw[1:-1] if raw.startswith("`") and raw.endswith("`") else raw
            for part in _extract_template_static_parts(inner):
                if _is_endpoint_candidate(part):
                    endpoints.add(part)
            # Fully static template = plain string
            if "${" not in inner and _is_endpoint_candidate(inner):
                endpoints.add(inner)

        # --- 4. Property assignments: { url: "/api/x" } or path = "/api/x" ---
        elif node.type == "pair":
            key_node = node.child_by_field_name("key")
            val_node = node.child_by_field_name("value")
            if key_node and val_node:
                key = _unwrap_string(_node_text(key_node, src)).lower()
                if key in URL_PROPERTY_KEYS and val_node.type == "string":
                    val = _unwrap_string(_node_text(val_node, src))
                    if _is_endpoint_candidate(val):
                        endpoints.add(val)

        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right:
                left_text = _node_text(left, src).lower()
                # path = "/api/x" or url = '...'
                if any(k in left_text for k in ("url", "path", "endpoint", "uri", "route")):
                    if right.type == "string":
                        val = _unwrap_string(_node_text(right, src))
                        if _is_endpoint_candidate(val):
                            endpoints.add(val)

        # --- 5. Comments (catches deobfuscator output which appends as comments) ---
        elif node.type == "comment":
            comment_text = _node_text(node, src)
            import re as _re

            # Deobfuscator format: /* DEOBFUSCATED [type]: decoded_value */
            # decoded_value may be a bare path, URL, or other string — extract it
            deobf_match = _re.search(r"DEOBFUSCATED\s*\[[^\]]+\]:\s*(.+?)\s*\*/", comment_text, _re.IGNORECASE)
            if deobf_match:
                decoded = deobf_match.group(1).strip()
                # decoded may itself contain quoted strings or be a bare path/URL
                for qm in _re.finditer(r'["\']([^"\']{2,300})["\']', decoded):
                    val = qm.group(1)
                    if _is_endpoint_candidate(val):
                        endpoints.add(val)
                if _is_endpoint_candidate(decoded):
                    endpoints.add(decoded)

            # Quoted paths in any comment
            for m in _re.finditer(r'["\'](/[a-zA-Z0-9_\-./]{2,150})["\']', comment_text):
                val = m.group(1)
                if _is_endpoint_candidate(val):
                    endpoints.add(val)

            # Full URLs in any comment
            for m in _re.finditer(r'https?://[a-zA-Z0-9.\-]+(?:/[a-zA-Z0-9_\-./%?=&]*)?', comment_text):
                val = m.group(0)
                if _is_endpoint_candidate(val):
                    endpoints.add(val)

            # Bare paths in DEOBFUSCATED comments (unquoted, e.g. "/api/x" without quotes)
            if "DEOBFUSCATED" in comment_text.upper():
                for m in _re.finditer(r'(?<=:\s)(/[a-zA-Z0-9_\-./]{2,150})(?=\s|$)', comment_text):
                    val = m.group(1)
                    if _is_endpoint_candidate(val):
                        endpoints.add(val)

    return endpoints


def ast_is_available():
    """Check if tree-sitter AST extraction is usable."""
    return AST_AVAILABLE
