"""Unit tests for Phase 2 CORS Step 1 (origins + classifier)."""

import unittest

from modules.cors import build_test_origins, classify_cors, normalize_origin, origins_equal
from modules.cors.classifier import classify_cors as classify
from modules.cors.scanner import cors_risk_boost, resolve_endpoints


TARGET = "https://example.com"
EVIL = "https://evil.com"


class TestNormalizeOrigin(unittest.TestCase):
    def test_lowercase_scheme_host(self):
        self.assertEqual(normalize_origin("HTTPS://Example.COM"), "https://example.com")

    def test_default_port_https_stripped(self):
        self.assertEqual(normalize_origin("https://example.com:443"), "https://example.com")

    def test_default_port_http_stripped(self):
        self.assertEqual(normalize_origin("http://example.com:80"), "http://example.com")

    def test_nondefault_port_kept(self):
        self.assertEqual(normalize_origin("https://example.com:8443"), "https://example.com:8443")

    def test_trailing_slash_stripped(self):
        self.assertEqual(normalize_origin("https://example.com/"), "https://example.com")

    def test_null_and_star_passthrough(self):
        self.assertEqual(normalize_origin("null"), "null")
        self.assertEqual(normalize_origin("*"), "*")

    def test_origins_equal_ignores_case_and_port(self):
        self.assertTrue(origins_equal("https://Example.com:443", "https://example.com"))


class TestBuildTestOrigins(unittest.TestCase):
    def test_custom_origin_first(self):
        origins = build_test_origins(TARGET, custom_origin="https://my.origin")
        self.assertEqual(origins[0], "https://my.origin")

    def test_ip_target_skips_domain_lookalikes(self):
        origins = build_test_origins("http://127.0.0.1:5555")
        self.assertNotIn("https://sub.0.1", origins)
        self.assertTrue(any(o == "null" for o in origins))

    def test_domain_target_includes_lookalikes(self):
        origins = build_test_origins(TARGET)
        self.assertIn("https://sub.example.com", origins)
        self.assertIn("https://example.com.evil.com", origins)
        self.assertIn("null", origins)


class TestClassifyCors(unittest.TestCase):
    def test_no_header_info(self):
        sev, _ = classify(EVIL, "", "")
        self.assertEqual(sev, "INFO")

    def test_arbitrary_reflect_with_creds_critical(self):
        sev, _ = classify(EVIL, EVIL, "true", target_origin=TARGET)
        self.assertEqual(sev, "CRITICAL")

    def test_arbitrary_reflect_no_creds_high(self):
        sev, _ = classify(EVIL, EVIL, "", target_origin=TARGET)
        self.assertEqual(sev, "HIGH")

    def test_null_with_creds_critical(self):
        sev, _ = classify("null", "null", "true", target_origin=TARGET)
        self.assertEqual(sev, "CRITICAL")

    def test_null_without_creds_medium(self):
        sev, _ = classify("null", "null", "", target_origin=TARGET)
        self.assertEqual(sev, "MEDIUM")

    def test_wildcard_no_creds_medium(self):
        sev, _ = classify(EVIL, "*", "", target_origin=TARGET)
        self.assertEqual(sev, "MEDIUM")

    def test_wildcard_with_creds_high_invalid_combo(self):
        sev, detail = classify(EVIL, "*", "true", target_origin=TARGET)
        self.assertEqual(sev, "HIGH")
        self.assertIn("browsers block", detail)

    def test_legitimate_target_origin_info(self):
        sev, _ = classify(
            "https://example.com", "https://example.com", "true", target_origin=TARGET
        )
        self.assertEqual(sev, "INFO")

    def test_legitimate_with_default_port_info(self):
        sev, _ = classify(
            "https://example.com:443", "https://example.com", "true", target_origin=TARGET
        )
        self.assertEqual(sev, "INFO")

    def test_related_subdomain_with_creds_high_not_critical(self):
        sev, _ = classify(
            "https://api.example.com",
            "https://api.example.com",
            "true",
            target_origin=TARGET,
            registrable_domain="example.com",
        )
        self.assertEqual(sev, "HIGH")

    def test_normalized_reflection_case_insensitive(self):
        sev, _ = classify(
            "https://evil.com", "https://EVIL.com", "true", target_origin=TARGET
        )
        self.assertEqual(sev, "CRITICAL")

    def test_partial_suffix_match_low(self):
        # acao host is suffix-related to origin host (dot boundary)
        sev, _ = classify(
            "https://foo.evil.com", "https://evil.com", "", target_origin=TARGET
        )
        # equal after normalize? no — different hosts; suffix → LOW
        # Wait: origin foo.evil.com, acao evil.com — not equal, suffix match
        self.assertEqual(sev, "LOW")

    def test_not_allowed_info(self):
        sev, _ = classify(EVIL, "https://other.com", "", target_origin=TARGET)
        self.assertEqual(sev, "INFO")

    def test_naive_endswith_not_partial(self):
        # evilevil.com vs evil.com should NOT be suffix partial (dot boundary)
        sev, _ = classify(
            "https://evilevil.com", "https://evil.com", "", target_origin=TARGET
        )
        self.assertEqual(sev, "INFO")


class TestScannerHelpers(unittest.TestCase):
    def test_resolve_skips_static_assets(self):
        urls = resolve_endpoints(
            ["/api/users", "/app.js", "/style.css", "https://x.test/api"],
            "https://example.com",
        )
        self.assertEqual(
            urls,
            ["https://example.com/api/users", "https://x.test/api"],
        )

    def test_risk_boost_weights(self):
        boost = cors_risk_boost(
            {"severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1}}
        )
        self.assertEqual(boost, 25 + 15 + 8 + 3)


if __name__ == "__main__":
    unittest.main()
