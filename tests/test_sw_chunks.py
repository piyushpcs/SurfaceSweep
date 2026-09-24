"""E3 — Vite/webpack chunk manifests + service-worker route discovery."""

import unittest

from modules.extraction.engine import (
    discover_js_chunks,
    extract_from_text,
    extract_sw_routes,
)


class TestViteWebpackChunks(unittest.TestCase):
    def test_vite_hashed_asset_chunk(self):
        js = 'const m = () => import("./assets/index-B7xK9mQ2.js");'
        found = discover_js_chunks(js, "https://app.test/index-ROOT.js")
        self.assertIn("https://app.test/assets/index-B7xK9mQ2.js", found)

    def test_vite_relative_from_assets_dir(self):
        js = 'import("./about-a1b2c3d4.js");'
        found = discover_js_chunks(js, "https://app.test/assets/main.js")
        self.assertIn("https://app.test/assets/about-a1b2c3d4.js", found)

    def test_vite_absolute_asset_chunk(self):
        js = 'import("/assets/about-a1b2c3d4.js");'
        found = discover_js_chunks(js, "https://app.test/assets/main.js")
        self.assertIn("https://app.test/assets/about-a1b2c3d4.js", found)

    def test_dynamic_import_extensionless_ignored(self):
        # Non-JS dynamic imports (JSON etc.) must not become linked_js
        js = 'import("./locales/en.json");'
        found = discover_js_chunks(js, "https://app.test/assets/main.js")
        self.assertEqual(found, set())

    def test_webpack_runtime_u_call(self):
        js = '__webpack_require__.u = (id) => "chunk-" + id + ".js"; __webpack_require__.u("vendor");'
        # .u("vendor") alone isn't .js — runtime map may not yield URL;
        # classic string still caught by WEBPACK pattern when it ends in .js
        js2 = 'webpackChunk.push([[0],{0:(e,t,a)=>{a.u("chunk-abc123.js")}}]);'
        found = discover_js_chunks(js2, "https://app.test/static/runtime.js")
        self.assertTrue(any("chunk-abc123.js" in u for u in found), found)

    def test_existing_import_still_works(self):
        js = 'import("./chunk-abc123.js");'
        found = discover_js_chunks(js, "http://127.0.0.1:5555/static/app.js")
        self.assertIn("http://127.0.0.1:5555/static/chunk-abc123.js", found)


class TestServiceWorkerRoutes(unittest.TestCase):
    SW = """
    self.addEventListener('install', (e) => {
      caches.open('v1').then((cache) =>
        cache.addAll(['/offline', '/api/v2/offline-data', '/api/v1/cache-me'])
      );
    });
    workbox.routing.registerRoute(({url}) => url.pathname === '/api/v2/wb-route', workbox.strategies.cacheFirst());
    workbox.routing.navigateFallback('/index.html');
    const api = '/api/v2/sw-api-path';
    """

    def test_extract_sw_routes_cache_list(self):
        routes = extract_sw_routes(self.SW, "sw.js")
        matches = {r["match"] for r in routes}
        self.assertIn("/offline", matches)
        self.assertIn("/api/v2/offline-data", matches)
        self.assertIn("/api/v1/cache-me", matches)

    def test_extract_sw_routes_register_route(self):
        routes = extract_sw_routes(self.SW, "sw.js")
        matches = {r["match"] for r in routes}
        self.assertIn("/api/v2/wb-route", matches)
        self.assertIn("/index.html", matches)

    def test_extract_sw_routes_api_path(self):
        routes = extract_sw_routes(self.SW, "sw.js")
        matches = {r["match"] for r in routes}
        self.assertIn("/api/v2/sw-api-path", matches)

    def test_sw_routes_flow_into_endpoints(self):
        eps, *_ = extract_from_text(self.SW, "sw.js", use_ast=False)
        self.assertIn("/api/v2/offline-data", eps)
        self.assertIn("/api/v2/wb-route", eps)
        self.assertIn("/api/v2/sw-api-path", eps)

    def test_star_patterns_skipped(self):
        routes = extract_sw_routes(
            "cache.addAll(['/api/*', '/static/*']);", "sw.js"
        )
        self.assertEqual(routes, [])

    def test_kind_recorded(self):
        routes = extract_sw_routes(self.SW, "sw.js")
        kinds = {r["kind"] for r in routes}
        self.assertIn("sw_cache_list", kinds)
        self.assertTrue(kinds & {"sw_register_route", "sw_api_path"})
        self.assertTrue(all(r["source"] == "sw.js" for r in routes))


if __name__ == "__main__":
    unittest.main()
