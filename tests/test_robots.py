"""Unit tests for robots.txt / sitemap.xml discovery (Phase C — C8)."""

import unittest
from unittest import mock

from modules.discovery.robots import (
    discover_robots_and_sitemap,
    parse_robots,
    parse_sitemap_locs,
)


class TestParseRobots(unittest.TestCase):
    def test_disallow_and_allow_paths(self):
        text = """
User-agent: *
Disallow: /admin/
Disallow: /api/v2/private
Allow: /admin/public
Disallow: /
# comment
"""
        parsed = parse_robots(text)
        self.assertIn("/admin", parsed["paths"])
        self.assertIn("/api/v2/private", parsed["paths"])
        self.assertIn("/admin/public", parsed["paths"])
        self.assertNotIn("/", parsed["paths"])

    def test_sitemap_urls(self):
        text = "Sitemap: https://x.test/sitemap.xml\nSitemap: https://x.test/sitemap-news.xml\n"
        parsed = parse_robots(text)
        self.assertEqual(
            parsed["sitemaps"],
            ["https://x.test/sitemap.xml", "https://x.test/sitemap-news.xml"],
        )

    def test_wildcard_prefix_normalized(self):
        parsed = parse_robots("Disallow: /private/*\n")
        self.assertEqual(parsed["paths"], ["/private"])

    def test_empty_and_junk(self):
        self.assertEqual(parse_robots(""), {"paths": [], "sitemaps": []})
        self.assertEqual(parse_robots("???\n*"), {"paths": [], "sitemaps": []})

    def test_query_string_stripped(self):
        parsed = parse_robots("Disallow: /search?q=1\n")
        self.assertEqual(parsed["paths"], ["/search"])


class TestParseSitemap(unittest.TestCase):
    def test_urlset_locs(self):
        xml = """<?xml version="1.0"?>
<urlset>
  <url><loc>https://x.test/login</loc></url>
  <url><loc>https://x.test/api/users</loc></url>
</urlset>
"""
        locs = parse_sitemap_locs(xml)
        self.assertEqual(locs, ["https://x.test/login", "https://x.test/api/users"])

    def test_sitemapindex_and_empty(self):
        xml = "<sitemapindex><sitemap><loc>https://x.test/sm.xml</loc></sitemap></sitemapindex>"
        self.assertEqual(parse_sitemap_locs(xml), ["https://x.test/sm.xml"])
        self.assertEqual(parse_sitemap_locs(""), [])


class TestDiscover(unittest.TestCase):
    def test_paths_from_robots_and_sitemap(self):
        robots = "Disallow: /admin\nSitemap: https://x.test/sitemap.xml\n"
        sitemap = (
            "<urlset><url><loc>https://x.test/login</loc></url>"
            "<url><loc>https://other.test/x</loc></url>"
            "<url><loc>https://x.test/static/app.js</loc></url></urlset>"
        )

        def fake_fetch(url, timeout=10):
            if url.endswith("/robots.txt"):
                return robots
            if url.endswith("/sitemap.xml"):
                return sitemap
            return None

        out = discover_robots_and_sitemap(
            "https://x.test", verbose=False, fetch=fake_fetch,
        )
        self.assertIn("/admin", out["paths"])
        self.assertIn("/login", out["paths"])
        self.assertIn("/static/app.js", out["paths"])  # merge_paths drops assets later
        self.assertNotIn("/x", out["paths"])  # cross-host
        self.assertIn("https://x.test/login", out["urls"])

    def test_network_failure_returns_empty(self):
        def boom(url, timeout=10):
            raise RuntimeError("offline")

        with self.assertRaises(RuntimeError):
            discover_robots_and_sitemap("https://x.test", verbose=False, fetch=boom)

    def test_missing_robots_still_probes_default_sitemap(self):
        calls = []

        def fake_fetch(url, timeout=10):
            calls.append(url)
            if url.endswith("/sitemap.xml"):
                return "<urlset><url><loc>https://x.test/home</loc></url></urlset>"
            return None

        out = discover_robots_and_sitemap("https://x.test", verbose=False, fetch=fake_fetch)
        self.assertTrue(any(u.endswith("/robots.txt") for u in calls))
        self.assertTrue(any(u.endswith("/sitemap.xml") for u in calls))
        self.assertIn("/home", out["paths"])

    def test_invalid_base_url(self):
        self.assertEqual(
            discover_robots_and_sitemap("not-a-url", verbose=False, fetch=lambda *a, **k: None),
            {"paths": [], "urls": []},
        )


if __name__ == "__main__":
    unittest.main()
