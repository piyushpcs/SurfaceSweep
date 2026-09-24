"""Unit tests for scope normalization and endpoint-pool filtering (Phase A Step 1)."""

import unittest

from modules.extraction.scope import (
    get_registrable_domain,
    is_same_scope,
    normalize_scope_filter,
)
from modules.pipeline.merge import collect_endpoints


class TestNormalizeScopeFilter(unittest.TestCase):
    def test_none_and_empty(self):
        self.assertIsNone(normalize_scope_filter(None))
        self.assertIsNone(normalize_scope_filter(""))
        self.assertIsNone(normalize_scope_filter("   "))

    def test_wildcard_stripped_and_reduced(self):
        self.assertEqual(normalize_scope_filter("*.target.com"), "target.com")
        self.assertEqual(normalize_scope_filter("*.api.target.com"), "target.com")

    def test_bare_domain(self):
        self.assertEqual(normalize_scope_filter("target.com"), "target.com")

    def test_url_input(self):
        self.assertEqual(
            normalize_scope_filter("https://a.target.com/path?x=1"),
            "target.com",
        )
        self.assertEqual(normalize_scope_filter("https://target.com"), "target.com")

    def test_host_port_stripped(self):
        self.assertEqual(normalize_scope_filter("localhost:5555"), "localhost")
        self.assertEqual(normalize_scope_filter("127.0.0.1:8080"), "127.0.0.1")

    def test_localhost_kept(self):
        self.assertEqual(normalize_scope_filter("localhost"), "localhost")
        self.assertEqual(normalize_scope_filter("http://localhost:5555/"), "localhost")

    def test_ip_kept(self):
        self.assertEqual(normalize_scope_filter("192.168.1.10"), "192.168.1.10")

    def test_public_suffix_reduced(self):
        self.assertEqual(normalize_scope_filter("shop.example.co.uk"), "example.co.uk")


class TestIsSameScope(unittest.TestCase):
    def test_registrable_domain_match(self):
        self.assertTrue(is_same_scope("https://api.target.com/v1", "target.com"))
        self.assertTrue(is_same_scope("https://target.com/", "target.com"))

    def test_cross_domain_rejected(self):
        self.assertFalse(is_same_scope("https://evil.com/x", "target.com"))
        self.assertFalse(is_same_scope("https://target.com.evil.com/x", "target.com"))
        self.assertFalse(is_same_scope("https://target.net/", "target.com"))

    def test_raw_wildcard_target_normalized_defensively(self):
        self.assertTrue(is_same_scope("https://api.target.com/v1", "*.target.com"))
        self.assertTrue(is_same_scope("https://target.com/", "*.target.com"))

    def test_empty_target_means_unrestricted(self):
        self.assertTrue(is_same_scope("https://anything.com/", ""))
        self.assertTrue(is_same_scope("https://anything.com/", None))

    def test_localhost(self):
        self.assertTrue(is_same_scope("http://localhost:5555/api", "localhost"))
        self.assertFalse(is_same_scope("http://127.0.0.1:5555/api", "localhost"))


class TestGetRegistrableDomain(unittest.TestCase):
    def test_subdomain(self):
        self.assertEqual(get_registrable_domain("https://a.b.example.com/x"), "example.com")

    def test_co_uk(self):
        self.assertEqual(get_registrable_domain("https://shop.example.co.uk/"), "example.co.uk")

    def test_localhost_fallback(self):
        self.assertIn("localhost", get_registrable_domain("http://localhost:5555/"))


class TestCollectEndpointsScopeFilter(unittest.TestCase):
    def _result(self, **overrides):
        base = {
            "internal_paths": [],
            "in_scope_urls": [],
            "intercepted_endpoints": [],
        }
        base.update(overrides)
        return base

    def test_without_target_keeps_all_intercepted(self):
        """Backward compatible: no target → no extra filtering."""
        r = self._result(intercepted_endpoints=[
            {"url": "https://third-party.com/analytics"},
            {"url": "https://example.com/api"},
        ])
        pool = collect_endpoints(r)
        self.assertIn("https://third-party.com/analytics", pool)
        self.assertIn("https://example.com/api", pool)

    def test_with_target_excludes_third_party(self):
        r = self._result(intercepted_endpoints=[
            {"url": "https://third-party.com/analytics"},
            {"url": "https://cdn.example.com/app"},
            {"url": "https://api.example.com/v1/users"},
            {"url": "https://evil.com/steal"},
        ])
        pool = collect_endpoints(r, target="https://example.com")
        self.assertNotIn("https://third-party.com/analytics", pool)
        self.assertNotIn("https://evil.com/steal", pool)
        self.assertIn("https://cdn.example.com/app", pool)
        self.assertIn("https://api.example.com/v1/users", pool)

    def test_relative_paths_always_kept(self):
        r = self._result(
            internal_paths=["/api/users"],
            intercepted_endpoints=[{"url": "/relative/path"}],
        )
        pool = collect_endpoints(r, target="https://example.com")
        self.assertIn("/api/users", pool)
        self.assertIn("/relative/path", pool)

    def test_target_with_wildcard_scope_style_url(self):
        r = self._result(intercepted_endpoints=[
            {"url": "https://api.example.com/x"},
            {"url": "https://other.com/y"},
        ])
        pool = collect_endpoints(r, target="https://www.example.com/app")
        self.assertIn("https://api.example.com/x", pool)
        self.assertNotIn("https://other.com/y", pool)

    def test_entries_without_url_skipped(self):
        r = self._result(intercepted_endpoints=[{"method": "GET"}])
        self.assertEqual(collect_endpoints(r, target="https://example.com"), [])


class TestBrowserUsesSharedScope(unittest.TestCase):
    def test_browser_module_has_no_local_is_same_scope(self):
        """browser.py must import scope helpers, not re-implement them."""
        import inspect
        import modules.extraction.browser as browser_mod
        src = inspect.getsource(browser_mod)
        # Local duplicate definition would look like "def is_same_scope"
        self.assertNotIn("def is_same_scope", src)
        self.assertNotIn("def get_registrable_domain", src)
        self.assertIn("normalize_scope_filter", src)


if __name__ == "__main__":
    unittest.main()
