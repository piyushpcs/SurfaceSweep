"""
SPA route discovery for SurfaceSweep.

Extracts hidden routes from React/Vue/Angular SPAs via:
  1. Static regex on JS bundles (path: "/..." patterns survive minification)
  2. Runtime DOM inspection (anchors, routerlink, [to])
  3. Framework router introspection (Vue $router, React fiber, Next.js manifest)
  4. History API instrumentation (catches client-side navigation)
  5. BFS crawl to unfold lazy-loaded routes
  6. Common admin/debug route probing
"""

import re
import time
from urllib.parse import urlparse, urljoin
from playwright.sync_api import sync_playwright
from modules.common.console import detail, info, ok


# ---- Static route patterns (survive minification) ----

# Generic: path: "/..." or path: '/...' (React, Vue, Angular all use this)
ROUTE_PATH_PATTERN = re.compile(
    r'\bpath\s*:\s*(["\'])([^"\']{1,300})\1',
    re.IGNORECASE
)

# Co-occurrence keys that confirm it's a route object (within ±150 chars)
ROUTE_CONTEXT_PATTERN = re.compile(
    r'\b(?:element|component|components|children|loader|action|redirect|'
    r'beforeEnter|canActivate|loadChildren|loadComponent|index|exact|'
    r'errorElement|pathMatch|meta|props|caseSensitive)\s*:',
    re.IGNORECASE
)

# Navigation calls: navigate("/x"), push("/x"), $router.push("/x")
NAVIGATION_PATTERN = re.compile(
    r'\b(?:navigate|push|replace|assign|href|to|router\.push|router\.replace|'
    r'\$router\.push|\$router\.replace|location\.href)\s*(?:\(|\s*=\s*)'
    r'\s*(["\'])(/[A-Za-z0-9._~%/?=&-][^"\']{0,300})\1',
    re.IGNORECASE
)

# Redirect targets (Angular uses redirectTo, Vue uses redirect)
REDIRECT_PATTERN = re.compile(
    r'\b(?:redirectTo|redirect)\s*:\s*(["\'])([^"\']{1,300})\1',
    re.IGNORECASE
)

# Hash routes: "#/dashboard"
HASH_ROUTE_PATTERN = re.compile(
    r'(["\'])#(/[A-Za-z0-9._~%/?=&-][^"\']{0,300})\1',
    re.IGNORECASE
)

# Angular forRoot anchor (property access survives minification)
ANGULAR_ANCHOR = re.compile(r'\.forRoot\s*\(\s*\[|\.forChild\s*\(\s*\[', re.IGNORECASE)

# Next.js build manifest
NEXT_MANIFEST_PATTERN = re.compile(
    r'self\.__BUILD_MANIFEST[^=]*=\s*(\{[\s\S]*?\});'
)

# Next.js chunk filenames leak routes: pages/admin-users-abc.js
NEXT_CHUNK_PATTERN = re.compile(
    r'/_next/static/chunks/pages(?:/|%2F)([A-Za-z0-9/_.\[\]-]+?)(?:-[0-9a-f]+)?\.js'
)

# File-based routing hints: src/pages/users/[id].vue → /users/:id
FILE_ROUTE_PATTERN = re.compile(
    r'(?:src|app)/(?:pages|routes)/([^"\'\\]+?)\.(?:vue|svelte|tsx?|jsx?)'
)


# ---- Common admin/debug/hidden routes to probe ----

COMMON_ROUTES = [
    # Admin panels
    "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/administrator",
    "/panel", "/dashboard", "/manage", "/console", "/backoffice",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-json/",
    # API docs (high value)
    "/api", "/api/", "/api/v1", "/api/v2", "/graphql",
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
    "/openapi.json", "/api-docs", "/redoc", "/docs", "/docs/",
    "/v2/api-docs", "/v3/api-docs", "/graphiql", "/playground",
    # Health/debug
    "/health", "/healthz", "/status", "/ping", "/metrics", "/info", "/version",
    "/debug", "/debug/", "/actuator", "/actuator/health", "/actuator/env",
    # Config/secrets
    "/.env", "/.git/HEAD", "/package.json", "/robots.txt", "/sitemap.xml",
    "/.well-known/security.txt",
    # Auth
    "/login", "/logout", "/register", "/signup", "/reset-password", "/forgot-password",
    "/auth", "/auth/login", "/oauth/token",
    # Server
    "/server-status", "/phpinfo.php", "/info.php",
]


def _normalize_route(route):
    """Normalize a route path for deduplication."""
    route = route.strip()
    if not route:
        return None
    # Ensure leading slash
    if not route.startswith("/") and not route.startswith("#/"):
        route = "/" + route
    # Collapse multiple slashes (but keep protocol-relative //)
    if not route.startswith("//"):
        route = re.sub(r"/{2,}", "/", route)
    # Remove trailing slash (except root)
    if len(route) > 1 and route.endswith("/") and not route.endswith("//"):
        route = route.rstrip("/")
    return route


def _is_valid_route(route):
    """Filter out obvious non-routes."""
    if not route or len(route) > 300:
        return False
    # Must start with / or #/
    if not (route.startswith("/") or route.startswith("#/")):
        return False
    # Skip protocol-relative, full URLs, data URIs
    if route.startswith("//") or route.startswith("/http") or route.startswith("/data:"):
        return False
    # Skip static assets
    from modules.extraction.engine import is_static_asset
    if is_static_asset(route):
        return False
    # Skip routes with template placeholders (we'll instantiate them separately)
    # But keep them for now — caller can decide
    # Skip routes that are just a file with query (already handled by is_static_asset)
    # Skip pure anchors
    if route.startswith("/#") and len(route) <= 3:
        return False
    return True


def extract_routes_from_js(content):
    """
    Extract route paths from JS content via static regex.
    Returns set of route strings.
    """
    routes = set()

    # Pattern 1: path: "/..." with route context nearby
    for match in ROUTE_PATH_PATTERN.finditer(content):
        route = match.group(2)
        if not route:
            continue
        # Check context window for route-identifying keys
        start = max(0, match.start() - 150)
        end = min(len(content), match.end() + 150)
        context = content[start:end]
        if ROUTE_CONTEXT_PATTERN.search(context) or ANGULAR_ANCHOR.search(context):
            normalized = _normalize_route(route)
            if normalized and _is_valid_route(normalized):
                routes.add(normalized)

    # Pattern 2: Navigation calls
    for match in NAVIGATION_PATTERN.finditer(content):
        route = match.group(2)
        normalized = _normalize_route(route)
        if normalized and _is_valid_route(normalized):
            routes.add(normalized)

    # Pattern 3: Redirect targets
    for match in REDIRECT_PATTERN.finditer(content):
        route = match.group(2)
        normalized = _normalize_route(route)
        if normalized and _is_valid_route(normalized):
            routes.add(normalized)

    # Pattern 4: Hash routes
    for match in HASH_ROUTE_PATTERN.finditer(content):
        route = match.group(2)
        normalized = _normalize_route(route)
        if normalized and _is_valid_route(normalized):
            routes.add(normalized)

    # Pattern 5: Next.js build manifest
    for match in NEXT_MANIFEST_PATTERN.finditer(content):
        try:
            import json
            manifest = json.loads(match.group(1).replace(",}", "}").replace(",]", "]"))
            for key in manifest.keys():
                if key.startswith("/"):
                    normalized = _normalize_route(key)
                    if normalized and _is_valid_route(normalized):
                        routes.add(normalized)
        except (json.JSONDecodeError, ValueError):
            pass

    # Pattern 6: Next.js chunk filenames
    for match in NEXT_CHUNK_PATTERN.finditer(content):
        route = "/" + match.group(1)
        normalized = _normalize_route(route)
        if normalized and _is_valid_route(normalized):
            routes.add(normalized)

    return routes


def instantiate_route_params(route):
    """
    Replace route params with fixture values for crawling.
    /users/:id → /users/1
    /posts/[slug] → /posts/test
    /files/[...path] → /files/a/b/c
    """
    result = route
    # React/Vue/Angular params: :id, :id?, :id*
    result = re.sub(r':\w+\([^)]*\)[*+?]?', '1', result)
    result = re.sub(r':\w+[*+?]?', '1', result)
    # Next.js/SvelteKit bracket params
    result = re.sub(r'\[\[\.\.\.\w+\]\]|\[\.\.\.\w+\]', 'a/b/c', result)
    result = re.sub(r'\[\[\w+\]\]|\[\w+\]', 'test', result)
    # Wildcards
    result = result.replace('**', 'x').replace('*', 'x')
    # Clean up any remaining empty segments
    result = re.sub(r'/{2,}', '/', result)
    return result


def _get_dom_routes(page):
    """Extract routes from DOM anchors and router directives."""
    return page.evaluate("""() => {
        const out = new Set();
        const base = location.origin;
        const abs = (u) => {
            try {
                const x = new URL(u, location.href);
                if (x.origin === base) out.add(x.pathname + x.search);
            } catch(e) {}
        };
        // Standard anchors
        document.querySelectorAll('a[href],area[href]').forEach(a => abs(a.getAttribute('href')));
        // Angular routerlink
        document.querySelectorAll('[routerlink]').forEach(el => {
            const v = el.getAttribute('routerlink');
            if (v) abs(v);
        });
        // Vue/React custom directives
        document.querySelectorAll('[to],[data-href],[data-route]').forEach(el => {
            const v = el.getAttribute('to') || el.getAttribute('data-href') || el.getAttribute('data-route');
            if (v) abs(v);
        });
        return [...out];
    }""")


def _get_vue_routes(page):
    """Extract routes from Vue Router instance."""
    return page.evaluate("""() => {
        const out = [];
        try {
            // Vue 3
            const app = document.querySelector('#app,#__nuxt')?.__vue_app__;
            const router = app?.config?.globalProperties?.$router;
            if (router && router.getRoutes) {
                router.getRoutes().forEach(r => { if (r.path) out.push(r.path); });
            }
            // Vue 2
            const el = document.querySelector('#app');
            if (el && el.__vue__ && el.__vue__.$router) {
                const walk = (recs, base='') => {
                    recs.forEach(rec => {
                        const full = rec.path.startsWith('/') ? rec.path
                            : (base.replace(/\\/$/,'') + '/' + rec.path).replace(/\\/+/g,'/');
                        out.push(full);
                        if (rec.children) walk(rec.children, full);
                    });
                };
                walk(el.__vue__.$router.options.routes || []);
            }
        } catch(e) {}
        return out;
    }""")


def _get_react_routes(page):
    """Extract routes from React fiber tree."""
    return page.evaluate("""() => {
        const out = new Set();
        try {
            const root = document.querySelector('#root,#__next,#__next_root,[data-reactroot]');
            if (!root) return [];
            const key = Object.keys(root).find(k =>
                k.startsWith('__reactContainer') || k.startsWith('_reactRootContainer'));
            let fiber = root[key] || root._reactRootContainer?._internalRoot?.current;
            if (!fiber && key) fiber = root[key];
            const seen = new Set();
            const walk = (f, d) => {
                if (!f || d > 500 || seen.has(f)) return;
                seen.add(f);
                const p = f.memoizedProps;
                if (p) {
                    if (typeof p.path === 'string') out.add(p.path);
                    if (typeof p.to === 'string') out.add(p.to);
                    if (typeof p.route === 'string') out.add(p.route);
                }
                walk(f.child, d + 1);
                walk(f.sibling, d + 1);
            };
            walk(fiber, 0);
        } catch(e) {}
        return [...out];
    }""")


def _get_next_routes(page):
    """Extract routes from Next.js manifests and RSC payload."""
    return page.evaluate("""() => {
        const out = [];
        try {
            // Pages Router: __NEXT_DATA__
            const nd = window.__NEXT_DATA__;
            if (nd && nd.page) out.push(nd.page);

            // App Router: __next_f RSC payload
            (window.__next_f || []).forEach(a => {
                if (a && typeof a[1] === 'string') {
                    for (const m of a[1].matchAll(/"app\\/([^"]+?)\\/(?:page|layout|route)"/g)) {
                        out.push('/' + m[1]);
                    }
                    for (const m of a[1].matchAll(/"pages\\/([^"]+?)"(?:\\s|,|\\])/g)) {
                        out.push('/' + m[1].replace(/\\/(index)?$/, '') || '/');
                    }
                }
            });
        } catch(e) {}
        return out;
    }""")


def _probe_common_routes(base_url, existing_routes, verbose=True, timeout=5):
    """Filter common routes that aren't already discovered."""
    discovered = set(existing_routes)
    candidates = []
    for route in COMMON_ROUTES:
        normalized = _normalize_route(route)
        if normalized and normalized not in discovered:
            candidates.append(normalized)
    return candidates


# Statuses that mean the path exists (auth walls count as existence)
_PROBE_EXISTS_STATUSES = (200, 301, 302, 401, 403, 405)


def probe_route(url, timeout=5, session=None, headers=None):
    """
    Existence probe for a candidate route: HEAD first, GET fallback.

    Many stacks reject or mis-handle HEAD (405/501/empty) while GET works.
    Falling back avoids false negatives on admin/API paths. Returns the
    confirming status code, or None when the path does not look live.
    """
    import requests as _requests
    from modules.extraction.http import request_tls

    req_headers = dict(headers) if headers else {"User-Agent": "SurfaceSweep/1.0"}
    # HEAD first (some stacks reject it with RST — fall through to GET)
    try:
        if session is not None:
            r = session.head(url, timeout=timeout, allow_redirects=True, headers=req_headers)
        else:
            r = request_tls("HEAD", url, timeout=timeout, allow_redirects=True, headers=req_headers)
        status = r.status_code
        if status in _PROBE_EXISTS_STATUSES and status not in (405, 501):
            return status
    except _requests.RequestException:
        pass
    try:
        if session is not None:
            r = session.get(url, timeout=timeout, allow_redirects=True, headers=req_headers)
        else:
            r = request_tls("GET", url, timeout=timeout, allow_redirects=True, headers=req_headers)
        status = r.status_code
        if status in _PROBE_EXISTS_STATUSES:
            return status
    except _requests.RequestException:
        return None
    return None


def crawl_spa_routes(base_url, timeout=30, verbose=True, max_routes=50,
                     probe_common=True, scope_filter=None, headers=None):
    """
    Discover SPA routes using static + runtime analysis.

    headers: auth headers (Cookie / -H) applied to bundle fetches, runtime
             browsing, and route probes so authenticated SPAs are covered.

    Returns dict with:
      - routes: list of discovered route paths
      - routes_from: dict mapping route -> source (static/dom/vue/react/next/probe)
      - api_endpoints: API endpoints discovered during crawl
      - errors: list of errors
    """
    from modules.extraction.engine import get_registrable_domain, is_static_asset, is_same_scope
    from modules.extraction.scope import normalize_scope_filter
    scope = normalize_scope_filter(scope_filter)

    req_headers = {"User-Agent": "SurfaceSweep/1.0"}
    if headers:
        req_headers.update(headers)

    target_domain = get_registrable_domain(base_url)
    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    result = {
        "routes": [],
        "routes_from": {},
        "api_endpoints": [],
        "errors": [],
    }

    all_routes = {}  # route -> source

    def add_route(route, source):
        normalized = _normalize_route(route)
        if normalized and _is_valid_route(normalized):
            if normalized not in all_routes:
                all_routes[normalized] = source
                return True
        return False

    # ---- Phase 1: Static extraction from JS bundles ----
    if verbose:
        info(f" Phase 1: Static analysis of JS bundles...")

    import requests as _requests
    js_urls = set()

    # Get JS files from the page
    try:
        from modules.extraction.http import request_tls as _request_tls
        resp = _request_tls("GET", base_url, timeout=10, headers=req_headers)
        # Find script src
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE):
            js_url = urljoin(base_url, m.group(1))
            js_urls.add(js_url)
    except _requests.RequestException as e:
        result["errors"].append(f"Failed to fetch HTML: {e}")

    # Fetch and analyze each JS file
    static_count = 0
    for js_url in js_urls:
        if scope and not is_same_scope(js_url, scope):
            continue
        try:
            from modules.extraction.http import request_tls as _request_tls
            js_resp = _request_tls("GET", js_url, timeout=10, headers=req_headers)
            routes = extract_routes_from_js(js_resp.text)
            for route in routes:
                if add_route(route, "static"):
                    static_count += 1
        except _requests.RequestException:
            pass

    if verbose and static_count:
        detail(f"[+] Found {static_count} route(s) in JS bundles")

    # ---- Phase 2: Runtime analysis via Playwright ----
    if verbose:
        info(f" Phase 2: Runtime analysis (Playwright)...")

    api_endpoints = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        cookie_header = ""
        extra_headers = {}
        for key, value in (headers or {}).items():
            if key.lower() == "cookie":
                cookie_header = value
            else:
                extra_headers[key] = value

        context = browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ignore_https_errors=True,
            service_workers="block",
            extra_http_headers=extra_headers or None,
        )
        if cookie_header:
            from modules.extraction.browser import _parse_cookie_header
            cookies = _parse_cookie_header(cookie_header, base_url)
            if cookies:
                context.add_cookies(cookies)

        # Instrument History API before page loads
        context.add_init_script("""
            window.__ss_nav = new Set();
            for (const m of ['pushState', 'replaceState']) {
                const o = history[m];
                history[m] = function(st, t, url) {
                    if (url != null) window.__ss_nav.add(String(url));
                    return o.apply(this, arguments);
                };
            }
            addEventListener('popstate', () => window.__ss_nav.add(location.pathname + location.search));
            addEventListener('hashchange', () => window.__ss_nav.add(location.hash));
        """)

        try:
            page = context.new_page()
            spa_api_endpoints = set()

            def handle_request(request):
                url = request.url
                if url.startswith("data:"):
                    return
                if request.resource_type in ("xhr", "fetch"):
                    path = urlparse(url).path
                    if path and not is_static_asset(path):
                        spa_api_endpoints.add(url)

            page.on("request", handle_request)

            try:
                # domcontentloaded: networkidle never settles on long-poll/SSE
                # apps and was observed hanging the initial SPA load too.
                page.goto(base_url, wait_until="domcontentloaded", timeout=timeout * 1000)
                page.wait_for_timeout(2000)
            except Exception as e:
                result["errors"].append(f"Navigation error: {e}")
                if verbose:
                    detail(f"[!] Navigation error: {e}")

            # DOM routes
            dom_routes = _get_dom_routes(page)
            dom_count = 0
            for route in dom_routes:
                if add_route(route, "dom"):
                    dom_count += 1
            if verbose and dom_count:
                detail(f"[+] Found {dom_count} route(s) from DOM anchors")

            # Vue routes
            vue_routes = _get_vue_routes(page)
            vue_count = 0
            for route in vue_routes:
                if add_route(route, "vue"):
                    vue_count += 1
            if verbose and vue_count:
                detail(f"[+] Found {vue_count} route(s) from Vue Router")

            # React routes
            react_routes = _get_react_routes(page)
            react_count = 0
            for route in react_routes:
                if add_route(route, "react"):
                    react_count += 1
            if verbose and react_count:
                detail(f"[+] Found {react_count} route(s) from React fiber")

            # Next.js routes
            next_routes = _get_next_routes(page)
            next_count = 0
            for route in next_routes:
                if add_route(route, "next"):
                    next_count += 1
            if verbose and next_count:
                detail(f"[+] Found {next_count} route(s) from Next.js manifest")

            # History API captured navigation
            hist_nav = page.evaluate("() => [...window.__ss_nav]")
            hist_count = 0
            for nav in hist_nav:
                path = urlparse(nav).path if nav.startswith("http") else nav.split("?")[0]
                if path and add_route(path, "history"):
                    hist_count += 1
            if verbose and hist_count:
                detail(f"[+] Found {hist_count} route(s) from History API")

            # ---- Phase 3: BFS crawl to unfold lazy routes ----
            if verbose:
                info(f" Phase 3: BFS crawl ({len(all_routes)} candidate route(s))...")

            # Seed queue with discovered routes
            queue = list(all_routes.keys())
            visited = set()
            crawled = 0
            # Hard wall-clock budget so a chatty site cannot hang the crawl.
            # (timeout * max_routes * 0.5 defaulted to 750s with stock flags.)
            import time as _time
            crawl_deadline = _time.monotonic() + min(60.0, max(15.0, float(timeout)))

            while queue and crawled < max_routes and _time.monotonic() < crawl_deadline:
                route = queue.pop(0)
                if route in visited:
                    continue
                visited.add(route)

                concrete = instantiate_route_params(route)
                crawl_url = base_origin + concrete

                try:
                    # domcontentloaded: networkidle never settles on long-poll/SSE apps
                    # and was observed hanging multi-minute BFS crawls in live tests.
                    page.goto(crawl_url, wait_until="domcontentloaded", timeout=5000)
                    page.wait_for_timeout(300)
                    crawled += 1

                    # Harvest more routes from this page state
                    new_dom = _get_dom_routes(page)
                    for r in new_dom:
                        if add_route(r, "crawl") and r not in visited:
                            queue.append(r)

                    new_vue = _get_vue_routes(page)
                    for r in new_vue:
                        if add_route(r, "crawl") and r not in visited:
                            queue.append(r)

                    new_react = _get_react_routes(page)
                    for r in new_react:
                        if add_route(r, "crawl") and r not in visited:
                            queue.append(r)

                    # Capture API endpoints from this page
                    # (already captured by handle_request)

                except Exception:
                    pass

            if verbose and crawled:
                detail(f"[+] Crawled {crawled} route(s)")

            # Collect API endpoints
            api_endpoints.update(spa_api_endpoints)

            page.close()
            browser.close()
        finally:
            # Always release Playwright resources, even on an unexpected error.
            for _closer in (page.close, browser.close):
                try:
                    _closer()
                except Exception:
                    pass

    # ---- Phase 4: Probe common routes ----
    if probe_common:
        if verbose:
            info(f" Phase 4: Probing common admin/debug routes...")
        probe_candidates = _probe_common_routes(base_url, all_routes.keys())
        if verbose:
            detail(f"[*] {len(probe_candidates)} candidate(s) to probe (not yet discovered)")

        # Quick HTTP probe (HEAD, GET fallback for method-not-allowed)
        import concurrent.futures
        probed = []

        def probe(route):
            url = base_origin + route
            status = probe_route(url, timeout=5, headers=req_headers)
            if status is not None:
                return (route, status)
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(probe, r): r for r in probe_candidates}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result_data = future.result()
                except Exception:
                    continue
                if result_data:
                    route, status = result_data
                    if add_route(route, "probe"):
                        probed.append((route, status))

        if verbose and probed:
            detail(f"[+] Found {len(probed)} additional route(s) via probing:")
            for route, status in sorted(probed):
                detail(f"    [{status}] {route}")

    # ---- Final results ----
    result["routes"] = sorted(all_routes.keys())
    result["routes_from"] = dict(all_routes)
    result["api_endpoints"] = sorted(api_endpoints)

    if verbose:
        ok(f" Total SPA routes discovered: {len(result['routes'])}")
        if result["api_endpoints"]:
            ok(f" API endpoints during crawl: {len(result['api_endpoints'])}")

    return result
