"""Unit tests for Phase 1.1 Step 4 — endpoint enrichment (method/tags/auth)."""

import unittest

from modules.extraction.enrich import (
    enrich_endpoint,
    enrich_intercepted_endpoints,
    endpoint_tags,
    infer_method,
    is_likely_authed,
    is_state_changing,
    resolve_method,
)


class TestInferMethod(unittest.TestCase):
    def test_create_post(self):
        self.assertEqual(infer_method("/api/v1/users/create"), "POST")

    def test_delete(self):
        self.assertEqual(infer_method("https://x.test/api/items/delete/42"), "DELETE")

    def test_update_put(self):
        self.assertEqual(infer_method("/api/profile/edit"), "PUT")

    def test_patch_segment(self):
        self.assertEqual(infer_method("/api/v2/patch"), "PATCH")

    def test_no_signal(self):
        self.assertIsNone(infer_method("/api/v1/users"))
        self.assertIsNone(infer_method("https://x.test/about"))

    def test_query_string_ignored(self):
        self.assertEqual(infer_method("/api/login?next=/"), "POST")


class TestResolveMethod(unittest.TestCase):
    def test_observed_post_wins(self):
        self.assertEqual(
            resolve_method("/api/users/create", "POST"),
            ("POST", "observed"),
        )

    def test_observed_get_with_create_hint(self):
        # SPA hardcodes GET — path hint upgrades and marks inferred
        self.assertEqual(
            resolve_method("/api/v1/resources/create", "GET"),
            ("POST", "inferred"),
        )

    def test_observed_get_plain_path_stays_get(self):
        self.assertEqual(
            resolve_method("/api/v1/users", "GET"),
            ("GET", "observed"),
        )

    def test_missing_observed_infers(self):
        self.assertEqual(
            resolve_method("/auth/login", None),
            ("POST", "inferred"),
        )

    def test_missing_observed_default_get(self):
        self.assertEqual(
            resolve_method("/about", None),
            ("GET", "default"),
        )


class TestEndpointTags(unittest.TestCase):
    def test_graphql(self):
        self.assertIn("graphql", endpoint_tags("https://x.test/api/graphql"))

    def test_trpc(self):
        self.assertIn("trpc", endpoint_tags("https://x.test/api/trpc/user.byId"))

    def test_websocket(self):
        self.assertIn("websocket", endpoint_tags("wss://x.test/socket.io/?EIO=4"))
        self.assertIn("websocket", endpoint_tags("https://x.test/ws"))

    def test_auth_and_api(self):
        tags = endpoint_tags("https://x.test/api/oauth/token")
        self.assertIn("auth", tags)
        self.assertIn("api", tags)

    def test_admin(self):
        self.assertIn("admin", endpoint_tags("/wp-admin/admin-ajax.php"))

    def test_plain_page_minimal(self):
        self.assertEqual(endpoint_tags("https://x.test/about"), [])


class TestStateAndAuth(unittest.TestCase):
    def test_state_changing(self):
        self.assertTrue(is_state_changing("POST"))
        self.assertTrue(is_state_changing("DELETE"))
        self.assertFalse(is_state_changing("GET"))

    def test_auth_path(self):
        self.assertTrue(is_likely_authed("/admin/users", "GET"))
        self.assertTrue(is_likely_authed("/account/settings", "GET"))

    def test_state_changing_implies_authed(self):
        self.assertTrue(is_likely_authed("/api/v1/orders", "POST"))

    def test_graphql_implies_authed(self):
        self.assertTrue(is_likely_authed("/graphql", "GET"))

    def test_public_get_not_authed(self):
        self.assertFalse(is_likely_authed("/api/v1/public/status", "GET"))


class TestEnrichEndpoint(unittest.TestCase):
    def test_enrich_graphql_spa_default(self):
        ep = {"url": "https://x.test/api/graphql", "method": "GET"}
        enrich_endpoint(ep)
        self.assertEqual(ep["method"], "GET")
        self.assertEqual(ep["method_source"], "observed")
        self.assertIn("graphql", ep["tags"])
        self.assertTrue(ep["likely_authed"])
        self.assertFalse(ep["state_changing"])

    def test_enrich_infers_post_for_create(self):
        ep = {"url": "https://x.test/api/items/create", "method": "GET"}
        enrich_endpoint(ep)
        self.assertEqual(ep["method"], "POST")
        self.assertEqual(ep["method_source"], "inferred")
        self.assertTrue(ep["state_changing"])
        self.assertTrue(ep["likely_authed"])

    def test_observed_delete_preserved(self):
        ep = {"url": "https://x.test/api/items", "method": "DELETE"}
        enrich_endpoint(ep)
        self.assertEqual(ep["method"], "DELETE")
        self.assertEqual(ep["method_source"], "observed")

    def test_skips_invalid(self):
        self.assertEqual(enrich_endpoint(None), None)
        self.assertEqual(enrich_endpoint("https://x.test"), "https://x.test")
        self.assertEqual(enrich_endpoint({}), {})

    def test_enrich_list_in_place(self):
        eps = [
            {"url": "https://x.test/api/trpc/x", "method": "GET"},
            {"url": "https://x.test/login", "method": "GET"},
        ]
        out = enrich_intercepted_endpoints(eps)
        self.assertIs(out, eps)
        self.assertIn("trpc", eps[0]["tags"])
        self.assertEqual(eps[1]["method"], "POST")
        self.assertIn("auth", eps[1]["tags"])


if __name__ == "__main__":
    unittest.main()
