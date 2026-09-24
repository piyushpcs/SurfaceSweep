"""Unit tests for Wayback Machine CDX query and fetch (Phase C3)."""

import unittest
from unittest import mock

from modules.discovery.wayback import (
    fetch_wayback_js,
    get_wayback_endpoints,
    get_wayback_js_urls,
)


class TestGetWaybackJsUrls(unittest.TestCase):
    def _cdx_response(self, rows):
        resp = mock.Mock()
        resp.raise_for_status = mock.Mock()
        resp.json.return_value = rows
        return resp

    def test_uses_match_type_domain_and_both_js_mimetypes(self):
        resp = self._cdx_response([
            ["original", "mimetype", "statuscode"],
            ["https://example.com/app.js", "application/javascript", "200"],
        ])
        with mock.patch("modules.discovery.wayback.requests.get", return_value=resp) as get:
            urls = get_wayback_js_urls("example.com", limit=10, verbose=False)

        self.assertEqual(urls, ["https://example.com/app.js"])
        _, kwargs = get.call_args
        params = kwargs["params"]
        # params is a list of (key, value) pairs so repeated filter keys work
        self.assertIn(("matchType", "domain"), params)
        self.assertIn(("url", "example.com"), params)
        filters = [v for k, v in params if k == "filter"]
        self.assertIn("mimetype:application/javascript", filters)
        self.assertIn("mimetype:text/javascript", filters)
        # Domain-scoped URL (no /* required when matchType=domain)
        self.assertNotIn(("url", "example.com/*"), params)

    def test_accepts_text_javascript_rows(self):
        resp = self._cdx_response([
            ["original", "mimetype", "statuscode"],
            ["https://example.com/lib.js", "text/javascript", "200"],
            ["https://example.com/style.css", "text/css", "200"],
        ])
        with mock.patch("modules.discovery.wayback.requests.get", return_value=resp):
            urls = get_wayback_js_urls("example.com", verbose=False)
        self.assertEqual(urls, ["https://example.com/lib.js"])

    def test_respects_limit(self):
        rows = [["original", "mimetype", "statuscode"]]
        for i in range(20):
            rows.append([f"https://example.com/f{i}.js", "application/javascript", "200"])
        resp = self._cdx_response(rows)
        with mock.patch("modules.discovery.wayback.requests.get", return_value=resp):
            urls = get_wayback_js_urls("example.com", limit=5, verbose=False)
        self.assertEqual(len(urls), 5)

    def test_http_error_returns_empty(self):
        import requests
        resp = mock.Mock()
        resp.raise_for_status.side_effect = requests.RequestException("boom")
        with mock.patch("modules.discovery.wayback.requests.get", return_value=resp):
            self.assertEqual(get_wayback_js_urls("example.com", verbose=False), [])

    def test_invalid_json_returns_empty(self):
        resp = mock.Mock()
        resp.raise_for_status = mock.Mock()
        resp.json.side_effect = ValueError("nope")
        with mock.patch("modules.discovery.wayback.requests.get", return_value=resp):
            self.assertEqual(get_wayback_js_urls("example.com", verbose=False), [])

    def test_header_only_returns_empty(self):
        resp = self._cdx_response([["original", "mimetype", "statuscode"]])
        with mock.patch("modules.discovery.wayback.requests.get", return_value=resp):
            self.assertEqual(get_wayback_js_urls("example.com", verbose=False), [])

    def test_query_string_js_urls_kept(self):
        resp = self._cdx_response([
            ["original", "mimetype", "statuscode"],
            ["https://example.com/app.js?v=2", "application/javascript", "200"],
        ])
        with mock.patch("modules.discovery.wayback.requests.get", return_value=resp):
            urls = get_wayback_js_urls("example.com", verbose=False)
        self.assertEqual(urls, ["https://example.com/app.js?v=2"])


class TestFetchWaybackJs(unittest.TestCase):
    def test_returns_none_when_no_snapshot(self):
        resp = mock.Mock()
        resp.raise_for_status = mock.Mock()
        resp.json.return_value = {"archived_snapshots": {}}
        with mock.patch("modules.discovery.wayback.requests.get", return_value=resp):
            self.assertIsNone(fetch_wayback_js("https://example.com/a.js"))

    def test_upgrades_http_snapshot_to_https(self):
        avail = mock.Mock()
        avail.raise_for_status = mock.Mock()
        avail.json.return_value = {
            "archived_snapshots": {
                "closest": {"url": "http://web.archive.org/web/2020/https://example.com/a.js"}
            }
        }
        snap = mock.Mock()
        snap.raise_for_status = mock.Mock()
        snap.text = 'fetch("/api/users");'

        def _get(url, **kwargs):
            return avail if "archive.org/wayback/available" in url else snap

        with mock.patch("modules.discovery.wayback.requests.get", side_effect=_get) as get:
            out = fetch_wayback_js("https://example.com/a.js")

        self.assertIsNotNone(out)
        self.assertTrue(out["snapshot_url"].startswith("https://"))
        self.assertIn("/api/users", out["content"])
        # Second call must hit the upgraded HTTPS snapshot URL
        self.assertTrue(get.call_args_list[1][0][0].startswith("https://"))

    def test_network_error_returns_none(self):
        import requests
        with mock.patch(
            "modules.discovery.wayback.requests.get",
            side_effect=requests.RequestException("down"),
        ):
            self.assertIsNone(fetch_wayback_js("https://example.com/a.js"))


class TestGetWaybackEndpoints(unittest.TestCase):
    def test_empty_js_list_returns_empty_shape(self):
        with mock.patch("modules.discovery.wayback.get_wayback_js_urls", return_value=[]):
            out = get_wayback_endpoints("example.com", verbose=False)
        self.assertEqual(out["js_files"], [])
        self.assertEqual(out["endpoints"], set())
        self.assertEqual(out["errors"], [])

    def test_scans_fetched_files(self):
        with mock.patch(
            "modules.discovery.wayback.get_wayback_js_urls",
            return_value=["https://example.com/a.js"],
        ), mock.patch(
            "modules.discovery.wayback.fetch_wayback_js",
            return_value={
                "original_url": "https://example.com/a.js",
                "snapshot_url": "https://web.archive.org/web/x",
                "content": 'fetch("/api/v1/users");',
            },
        ):
            out = get_wayback_endpoints("example.com", verbose=False)

        self.assertEqual(out["js_files"], ["https://example.com/a.js"])
        self.assertIn("/api/v1/users", out["endpoints"])
        self.assertEqual(out["errors"], [])

    def test_fetch_failure_recorded_in_errors(self):
        with mock.patch(
            "modules.discovery.wayback.get_wayback_js_urls",
            return_value=["https://example.com/missing.js"],
        ), mock.patch("modules.discovery.wayback.fetch_wayback_js", return_value=None):
            out = get_wayback_endpoints("example.com", verbose=False)

        self.assertEqual(out["js_files"], [])
        self.assertEqual(out["errors"], ["https://example.com/missing.js: fetch failed"])


if __name__ == "__main__":
    unittest.main()
