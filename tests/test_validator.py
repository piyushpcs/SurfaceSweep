"""Unit tests for Phase 1.1 Step 5 — validation hardening (SPA shell, JSON fail-in-200)."""

import json
import unittest
from unittest import mock

from modules.analysis.validator import (
    build_method_map,
    classify_200_body,
    classify_status,
    is_soft_404,
    is_spa_shell,
    looks_like_api_path,
    resolve_validation_method,
    validate_endpoint,
    validate_endpoints,
)


def _resp(text="", content_type="text/html", status_code=200, content=None):
    """Minimal requests-like response double."""
    body = content if content is not None else text.encode("utf-8")
    return mock.Mock(
        status_code=status_code,
        text=text if content is None else body.decode("utf-8", errors="replace"),
        content=body,
        headers={"Content-Type": content_type},
        history=[],
        url="https://x.test/",
    )


class TestLooksLikeApiPath(unittest.TestCase):
    def test_api_paths(self):
        self.assertTrue(looks_like_api_path("https://x.test/api/v1/users"))
        self.assertTrue(looks_like_api_path("/api/users"))
        self.assertTrue(looks_like_api_path("https://x.test/graphql"))

    def test_page_paths(self):
        self.assertFalse(looks_like_api_path("https://x.test/about"))
        self.assertFalse(looks_like_api_path("/blog/post"))


class TestSpaShell(unittest.TestCase):
    def test_api_path_with_root_shell(self):
        html = '<!doctype html><html><body><div id="root"></div></body></html>'
        resp = _resp(html, "text/html")
        self.assertTrue(is_spa_shell(resp, "https://x.test/api/v1/users"))

    def test_next_shell(self):
        html = '<div id="__next"></div><script src="/_next/static/chunk.js"></script>'
        resp = _resp(html, "text/html")
        self.assertTrue(is_spa_shell(resp, "https://x.test/api/v2/items"))

    def test_non_api_html_not_shell_killed(self):
        # Real marketing HTML page should stay live (no false dead)
        html = '<html><body><div id="root"><h1>Welcome</h1></div></body></html>'
        resp = _resp(html, "text/html")
        self.assertFalse(is_spa_shell(resp, "https://x.test/landing"))
        status, note = classify_200_body(resp, "https://x.test/landing")
        self.assertEqual(status, "live")
        self.assertIsNone(note)

    def test_api_path_html_without_shell_markers_stays_live(self):
        html = '<html><body><p>custom api docs</p></body></html>'
        resp = _resp(html, "text/html")
        self.assertFalse(is_spa_shell(resp, "https://x.test/api/docs"))
        status, note = classify_200_body(resp, "https://x.test/api/docs")
        self.assertEqual(status, "live")

    def test_api_path_shell_classified_dead(self):
        html = '<div id="root"></div>'
        resp = _resp(html, "text/html")
        status, note = classify_200_body(resp, "https://x.test/api/v1/secret")
        self.assertEqual(status, "dead")
        self.assertEqual(note, "spa_shell")

    def test_json_content_type_not_shell(self):
        resp = _resp('{"ok":true}', "application/json")
        self.assertFalse(is_spa_shell(resp, "https://x.test/api/v1/users"))


class TestJsonFailIn200(unittest.TestCase):
    def test_not_found_json_dead(self):
        resp = _resp('{"error":"resource not found"}', "application/json")
        status, note = classify_200_body(resp, "https://x.test/api/v1/users")
        self.assertEqual(status, "dead")
        self.assertEqual(note, "json_not_found")

    def test_success_false_with_not_found(self):
        body = json.dumps({"success": False, "message": "User does not exist"})
        resp = _resp(body, "application/json")
        status, note = classify_200_body(resp, "https://x.test/api/users/1")
        self.assertEqual(status, "dead")
        self.assertEqual(note, "json_not_found")

    def test_auth_error_restricted(self):
        resp = _resp('{"error":"unauthorized"}', "application/json")
        status, note = classify_200_body(resp, "https://x.test/api/admin")
        self.assertEqual(status, "restricted")
        self.assertEqual(note, "json_auth")

    def test_generic_error_stays_live(self):
        # Endpoint exists; app-level failure is still a finding surface
        resp = _resp('{"error":"database timeout"}', "application/json")
        status, note = classify_200_body(resp, "https://x.test/api/v1/jobs")
        self.assertEqual(status, "live")
        self.assertEqual(note, "json_error")

    def test_null_error_is_success(self):
        resp = _resp('{"error":null,"data":[1,2]}', "application/json")
        status, note = classify_200_body(resp, "https://x.test/api/v1/jobs")
        self.assertEqual(status, "live")
        self.assertIsNone(note)

    def test_empty_errors_list_success(self):
        resp = _resp('{"errors":[],"data":{"ok":1}}', "application/json")
        status, note = classify_200_body(resp, "https://x.test/api/v1/jobs")
        self.assertEqual(status, "live")
        self.assertIsNone(note)

    def test_non_json_html_success_untouched(self):
        resp = _resp("<html><body>docs</body></html>", "text/html")
        status, note = classify_200_body(resp, "https://x.test/api/docs")
        self.assertEqual((status, note), ("live", None))


class TestSoft404StillWorks(unittest.TestCase):
    def test_classic_soft_404(self):
        resp = _resp("<html><body>Page not found</body></html>", "text/html")
        self.assertTrue(is_soft_404(resp, "https://x.test/api/v1/nope"))
        status, note = classify_200_body(resp, "https://x.test/api/v1/nope")
        self.assertEqual(status, "dead")
        self.assertEqual(note, "soft_404")

    def test_bare_404_alone_not_soft_404(self):
        """Docs pages that mention status code 404 must stay live."""
        resp = _resp(
            "<html><body><p>API returns 404 when missing</p></body></html>",
            "text/html",
        )
        self.assertFalse(is_soft_404(resp, "https://x.test/api/docs"))

    def test_single_weak_not_found_alone_not_enough(self):
        resp = _resp("<html><body>entry not found in cache</body></html>", "text/html")
        self.assertFalse(is_soft_404(resp, "https://x.test/api/v1/items"))

    def test_two_weak_signals_are_enough(self):
        resp = _resp(
            "<html><body>sorry not found — resource does not exist</body></html>",
            "text/html",
        )
        self.assertTrue(is_soft_404(resp, "https://x.test/api/v1/items"))

    def test_error_404_phrase_is_strong(self):
        resp = _resp("<html><body>Error 404</body></html>", "text/html")
        self.assertTrue(is_soft_404(resp, "https://x.test/missing"))

    def test_does_not_exist_is_strong(self):
        resp = _resp("<html><body>The record does not exist</body></html>", "text/html")
        self.assertTrue(is_soft_404(resp, "https://x.test/api/v1/rec"))

    def test_path_echo_suppresses_weak_match(self):
        resp = _resp(
            "<html><body>You wanted /api/v1/nope not found</body></html>",
            "text/html",
        )
        # path is echoed — weak "not found" should not kill alone via path skip
        # but "not found" is weak and only one signal after path skip of path itself
        # path "/api/v1/nope" appears in body → all sigs skipped → not soft-404
        self.assertFalse(is_soft_404(resp, "https://x.test/api/v1/nope"))


class TestValidateEndpointUsesBodyNotes(unittest.TestCase):
    @mock.patch("modules.analysis.validator.request_tls")
    def test_spa_shell_downgrades_to_dead(self, request_mock):
        request_mock.return_value = _resp(
            '<!doctype html><div id="root"></div>', "text/html"
        )
        result = validate_endpoint("https://x.test/api/v1/users")
        self.assertEqual(result["status"], "dead")
        self.assertEqual(result.get("note"), "spa_shell")

    @mock.patch("modules.analysis.validator.request_tls")
    def test_json_auth_downgrades_to_restricted(self, request_mock):
        request_mock.return_value = _resp(
            '{"error":"invalid token"}', "application/json"
        )
        result = validate_endpoint("https://x.test/api/v1/me")
        self.assertEqual(result["status"], "restricted")
        self.assertEqual(result.get("note"), "json_auth")

    @mock.patch("modules.analysis.validator.request_tls")
    def test_non_200_ignores_body(self, request_mock):
        request_mock.return_value = _resp(
            '{"error":"not found"}', "application/json", status_code=404
        )
        result = validate_endpoint("https://x.test/api/v1/gone")
        self.assertEqual(result["status"], "dead")
        self.assertNotIn("note", result)

    @mock.patch("modules.analysis.validator.request_tls")
    def test_plain_200_no_note(self, request_mock):
        request_mock.return_value = _resp('{"ok":true}', "application/json")
        result = validate_endpoint("https://x.test/api/v1/health")
        self.assertEqual(result["status"], "live")
        self.assertNotIn("note", result)


class TestClassifyStatusUnchanged(unittest.TestCase):
    def test_core_codes(self):
        self.assertEqual(classify_status(200), "live")
        self.assertEqual(classify_status(401), "restricted")
        self.assertEqual(classify_status(404), "dead")
        self.assertEqual(classify_status(500), "server_error")


class TestMethodAwareValidation(unittest.TestCase):
    def test_observed_post_wins(self):
        method, source = resolve_validation_method(
            "https://x.test/api/orders", observed="POST"
        )
        self.assertEqual(method, "POST")
        self.assertEqual(source, "observed")

    def test_path_inferred_post(self):
        method, source = resolve_validation_method("https://x.test/api/users/create")
        self.assertEqual(method, "POST")
        self.assertEqual(source, "inferred")

    def test_inferred_delete_downgraded_to_options(self):
        method, source = resolve_validation_method("https://x.test/api/items/1/delete")
        self.assertEqual(method, "OPTIONS")
        self.assertEqual(source, "inferred")

    def test_observed_delete_kept(self):
        method, source = resolve_validation_method(
            "https://x.test/api/items/1", observed="DELETE"
        )
        self.assertEqual(method, "DELETE")
        self.assertEqual(source, "observed")

    def test_default_get(self):
        method, source = resolve_validation_method("https://x.test/health")
        self.assertEqual(method, "GET")
        self.assertEqual(source, "default")

    def test_build_method_map(self):
        mm = build_method_map(
            ["/api/orders", "/api/users/create", "/health", "/api/items/9/delete"],
            intercepted=[{"url": "/api/orders", "method": "POST"}],
        )
        self.assertEqual(mm["/api/orders"], "POST")
        self.assertEqual(mm["/api/users/create"], "POST")
        self.assertEqual(mm["/health"], "GET")
        self.assertEqual(mm["/api/items/9/delete"], "OPTIONS")  # inferred DELETE → OPTIONS

    @mock.patch("modules.analysis.validator.request_tls")
    def test_validate_endpoints_uses_method_map(self, request_mock):
        request_mock.return_value = _resp('{"ok":true}', "application/json")
        validate_endpoints(
            ["/api/orders"],
            "https://x.test",
            verbose=False,
            method_map={"/api/orders": "POST"},
        )
        args, kwargs = request_mock.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], "https://x.test/api/orders")

    @mock.patch("modules.analysis.validator.request_tls")
    def test_ws_urls_skipped(self, request_mock):
        request_mock.return_value = _resp('{"ok":true}', "application/json")
        validate_endpoints(
            ["wss://ws.example.com/socket", "/health"],
            "https://x.test",
            verbose=False,
        )
        request_mock.assert_called_once()
        called_url = request_mock.call_args[0][1]
        self.assertNotIn("wss://", called_url)
        self.assertEqual(called_url, "https://x.test/health")


class TestValidationSummaryBuckets(unittest.TestCase):
    @mock.patch("modules.analysis.validator.emit")
    @mock.patch("modules.analysis.validator.detail")
    @mock.patch("modules.analysis.validator.request_tls")
    def test_summary_reports_connection_errors(self, request_mock, detail_mock, emit_mock):
        request_mock.side_effect = __import__("requests").ConnectionError("down")
        results = validate_endpoints(["/a", "/b"], "https://x.test", verbose=True)
        self.assertEqual(len(results["connection_error"]), 2)
        printed = " ".join(str(c.args[0]) for c in detail_mock.call_args_list)
        self.assertIn("Connection errors: 2", printed)
        self.assertIn("Other errors: 0", printed)

    @mock.patch("modules.analysis.validator.emit")
    @mock.patch("modules.analysis.validator.detail")
    @mock.patch("modules.analysis.validator.request_tls")
    def test_summary_reports_other_errors(self, request_mock, detail_mock, emit_mock):
        request_mock.side_effect = __import__("requests").RequestException("boom")
        results = validate_endpoints(["/a"], "https://x.test", verbose=True)
        self.assertEqual(len(results["error"]), 1)
        printed = " ".join(str(c.args[0]) for c in detail_mock.call_args_list)
        self.assertIn("Other errors: 1", printed)


if __name__ == "__main__":
    unittest.main()
