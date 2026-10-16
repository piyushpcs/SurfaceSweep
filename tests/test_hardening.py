"""
Regression tests for the Phase 0 safety/correctness hardening pass.

Covers: SSRF/metadata fetch guard, scope-limited JS crawl, non-mutating
validation methods, secret-extraction fixes, CSV export hardening, sink-count
merge, SARIF severity, and per-stage error isolation.
"""

import os
import tempfile
import unittest
from argparse import Namespace
from unittest import mock

import requests

from modules.analysis.validator import resolve_validation_method
from modules.common.constants import secret_severity
from modules.extraction.http import fetch_with_retry, is_blocked_fetch_target
from modules.extraction.secrets import extract_secrets
from modules.extraction.verify import VERIFIERS
from modules.pipeline.merge import merge_sinks
from modules.reporting.export import _csv_safe, export_burp_csv
from modules.reporting.sarif import build_sarif


# ---------------------------------------------------------------- SSRF guard

class TestFetchSafety(unittest.TestCase):
    def test_metadata_targets_blocked(self):
        for url in (
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.0.10/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
        ):
            self.assertTrue(is_blocked_fetch_target(url), url)

    def test_normal_hosts_allowed(self):
        # Private / loopback stay allowed (local testbeds, internal tests).
        for url in (
            "https://example.com/app.js",
            "http://127.0.0.1:5555/x",
            "http://10.0.0.5/x",
            "http://192.168.1.5/x",
        ):
            self.assertFalse(is_blocked_fetch_target(url), url)

    def test_fetch_refuses_metadata(self):
        with self.assertRaises(requests.ConnectionError):
            fetch_with_retry("http://169.254.169.254/latest/meta-data/")


# ------------------------------------------------------- crawler scope guard

class TestCrawlerScope(unittest.TestCase):
    @mock.patch("modules.extraction.engine.fetch_and_extract")
    @mock.patch("modules.extraction.engine.get_page")
    def test_off_scope_linked_js_not_fetched(self, get_page, fetch_extract):
        get_page.return_value = (
            '<html><script src="https://evil.example.net/track.js"></script>'
            '<script src="/app.js"></script></html>'
        )
        fetch_extract.return_value = {
            "source": "/app.js", "error": None, "endpoints": set(),
            "secrets": [], "linked_js": set(), "deobfuscation_findings": [],
            "sinks": [], "internal_hosts": [], "jwts": [], "pii": [],
            "params": [], "source_map_found": None,
        }
        from modules.extraction.engine import run_extractor

        run_extractor("https://app.example.com", verbose=False, max_depth=1)
        fetched = [c.args[0] for c in fetch_extract.call_args_list]
        self.assertFalse(
            any("evil.example.net" in str(u) for u in fetched),
            f"off-scope JS was fetched: {fetched}",
        )


# ------------------------------------------------- non-mutating validation

class TestValidationNeverMutates(unittest.TestCase):
    def test_inferred_mutation_verbs_become_options(self):
        # create→POST, update→PUT, patch→PATCH, delete→DELETE (enrich hints).
        for path in ("/api/users/create", "/api/users/update",
                     "/api/users/patch", "/api/users/delete/1"):
            method, source = resolve_validation_method(f"https://x.test{path}")
            self.assertEqual(method, "OPTIONS", path)
            self.assertEqual(source, "inferred")

    def test_plain_path_stays_get(self):
        method, source = resolve_validation_method("https://x.test/api/v1/items")
        self.assertEqual((method, source), ("GET", "default"))

    def test_observed_verbs_are_kept(self):
        method, source = resolve_validation_method(
            "https://x.test/api/orders", observed="POST"
        )
        self.assertEqual((method, source), ("POST", "observed"))


# ------------------------------------------------------- secret extraction

class TestSecretExtractionFixes(unittest.TestCase):
    def test_bare_pkcs8_private_key_detected(self):
        content = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n"
        types = {s["type"] for s in extract_secrets(content, "x.js")}
        self.assertIn("Private Key", types)

    def test_rsa_private_key_detected(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n"
        types = {s["type"] for s in extract_secrets(content, "x.js")}
        self.assertIn("Private Key", types)

    def test_exposed_env_var_gates_on_value_not_name(self):
        # Short env name (VITE_KEY, 8 chars) with a long high-entropy value:
        # the old code gated on the name and dropped the finding.
        content = 'VITE_KEY: "aB3xY9mN2pQ7rS5tU8vW1xY4zA6bC9dE"'
        types = {s["type"] for s in extract_secrets(content, "x.js")}
        self.assertIn("Exposed Env Var", types)

    def test_github_pat_not_truncated(self):
        token = "ghp_" + "aB3xY9mN2pQ7rS5tU8vW1xY4zA6bC9dEfGh1"  # 40 chars payload
        content = f'const t = "{token}";'
        matches = [s["match"] for s in extract_secrets(content, "x.js")
                   if "GitHub" in s["type"]]
        self.assertTrue(any(token in m for m in matches), matches)

    def test_npm_verifier_registered_under_correct_label(self):
        self.assertIn("NPM Token", VERIFIERS)
        self.assertEqual(secret_severity("NPM Token"), "HIGH")


# ------------------------------------------------------------- CSV export

class TestExportHardening(unittest.TestCase):
    def test_csv_safe_prefixes_formula_cells(self):
        self.assertEqual(_csv_safe("=SUM(A1)"), "'=SUM(A1)")
        self.assertEqual(_csv_safe("@cmd"), "'@cmd")
        self.assertEqual(_csv_safe("+1"), "'+1")
        self.assertEqual(_csv_safe("normal/path"), "normal/path")
        self.assertEqual(_csv_safe(None), "")

    def test_burp_export_bare_filename_succeeds(self):
        result = {"target": "https://x.test", "internal_paths": ["/api/users"]}
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                ok = export_burp_csv(result, "burp.csv")
                self.assertTrue(ok)
                self.assertTrue(os.path.exists("burp.csv"))
            finally:
                os.chdir(cwd)

    def test_burp_export_neutralizes_injection(self):
        result = {"target": "https://x.test",
                  "internal_paths": ["/x?@SUM(1)"]}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "burp.csv")
            self.assertTrue(export_burp_csv(result, path))
            with open(path, encoding="utf-8") as fh:
                contents = fh.read()
        self.assertIn("'@SUM(1)", contents)


# ------------------------------------------------------------- sink merge

class TestSinkMerge(unittest.TestCase):
    def test_merge_preserves_counts_and_sources(self):
        result = {
            "sinks_found": [{
                "sink": "eval", "severity": "HIGH", "description": "d",
                "sources": ["a.js", "b.js"], "count": 5,
            }]
        }
        merge_sinks(result, [{
            "sink": "eval", "severity": "HIGH", "description": "d",
            "source": "c.js", "count": 2,
        }])
        entry = result["sinks_found"][0]
        self.assertEqual(entry["count"], 7)
        self.assertEqual(sorted(entry["sources"]), ["a.js", "b.js", "c.js"])


# ------------------------------------------------------------- SARIF

class TestSarifSeverity(unittest.TestCase):
    def test_secret_severity_is_type_aware(self):
        for typ in ("Stripe Publishable", "Private Key", "CSRF Token"):
            result = {
                "target": "https://x.test",
                "secrets_found": [{"type": typ, "match": "x", "source": "a.js"}],
            }
            sarif = build_sarif(result)
            sec = [r for r in sarif["runs"][0]["results"]
                   if r["ruleId"] == "secret-leak"][0]
            self.assertEqual(sec["properties"]["severity"], secret_severity(typ))


# ------------------------------------------------- stage error isolation

def _base_args():
    return Namespace(
        full=False, browser=False, waf=False, wayback=False, cve=False,
        osv=False, spa=False, cors=False, jwt=False, validate=False,
        graphql=False, verify_secrets=False, burp=False, zap=False,
        html=False, html_only=False,
    )


class TestStageIsolation(unittest.TestCase):
    def test_failing_stage_does_not_abort_pipeline(self):
        from modules.common.result import new_scan_result
        from modules.pipeline import runner

        def make_result(ctx):
            ctx.result = new_scan_result("https://x.test")

        def boom(ctx):
            raise RuntimeError("kaboom")

        stages = [("scan", make_result), ("bad", boom), ("report", lambda ctx: None)]
        with mock.patch.object(runner, "build_stages", return_value=stages):
            result = runner.run_pipeline(_base_args(), verbose=False)

        self.assertIn("bad", result["meta"]["stages_run"])
        self.assertTrue(any("bad" in e for e in result["errors"]), result["errors"])


# ---------------------------------------------------------- scoped auth

class TestScopedAuth(unittest.TestCase):
    def tearDown(self):
        from modules.extraction.http import reset_http_config
        reset_http_config()

    def test_auth_only_attached_in_scope(self):
        from modules.extraction.http import configure_auth, _client
        configure_auth({"Cookie": "session=secret"}, "example.com")
        in_scope = _client._merge_headers("https://app.example.com/x", None)
        off_scope = _client._merge_headers("https://evil.example.net/x", None)
        self.assertEqual(in_scope.get("Cookie"), "session=secret")
        self.assertNotIn("Cookie", off_scope)

    def test_caller_headers_win(self):
        from modules.extraction.http import configure_auth, _client
        configure_auth({"X-Api-Key": "scoped"}, "example.com")
        merged = _client._merge_headers(
            "https://example.com/x", {"X-Api-Key": "override"}
        )
        self.assertEqual(merged["X-Api-Key"], "override")

    def test_reset_clears_auth(self):
        from modules.extraction.http import configure_auth, reset_http_config, _client
        configure_auth({"Cookie": "s=1"}, "example.com")
        reset_http_config()
        self.assertNotIn("Cookie", _client._merge_headers("https://example.com/x", None))


class TestBrowserCookieParse(unittest.TestCase):
    def test_parse_cookie_header(self):
        from modules.extraction.browser import _parse_cookie_header
        cookies = _parse_cookie_header(
            "a=b; session=abc==;  ; broken", "https://x.test"
        )
        self.assertEqual(cookies, [
            {"name": "a", "value": "b", "url": "https://x.test"},
            {"name": "session", "value": "abc==", "url": "https://x.test"},
        ])


class TestNoCredentialLeakToVendors(unittest.TestCase):
    def test_verify_stage_does_not_forward_target_headers(self):
        from modules.common.result import new_scan_result
        from modules.pipeline import stages
        from modules.pipeline.context import ScanContext

        args = _base_args()
        args.target = "https://x.test"
        args.verify_secrets_timeout = 5.0
        ctx = ScanContext(args, verbose=False, headers={"Cookie": "session=secret"})
        ctx.result = new_scan_result("https://x.test")
        ctx.result["secrets_found"] = [
            {"type": "Generic API Key", "match": "x", "source": "a.js"}
        ]
        empty = {"results": [], "findings": [], "secrets_checked": 1,
                 "confirmed": 0, "rejected": 0, "errors": 0, "skipped": 0,
                 "summary": {}}
        with mock.patch.object(stages, "verify_secrets", return_value=empty) as vs:
            stages.stage_verify_secrets(ctx)
        self.assertIsNone(vs.call_args.kwargs.get("headers"))


# ---------------------------------------------------------- OSV mapping

class TestOsvIndexMapping(unittest.TestCase):
    @mock.patch("modules.extraction.http.request_tls")
    def test_results_map_to_correct_library(self, request_tls):
        # First lib has no npm mapping (not queried); only jQuery is queried.
        libs = [
            {"library": "TotallyUnknown", "version": "1.0"},
            {"library": "jQuery", "version": "3.4.1"},
        ]
        resp = mock.Mock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {
            "results": [{"vulns": [{"id": "GHSA-1", "summary": "xss"}]}]
        }
        request_tls.return_value = resp

        from modules.analysis.libraries import query_osv
        out = query_osv(libs)
        self.assertIn("jQuery", out)
        self.assertEqual(out["jQuery"]["vulns"][0]["id"], "GHSA-1")
        self.assertNotIn("TotallyUnknown", out)


# ---------------------------------------------------------- DNS pinning

class TestDnsPinning(unittest.TestCase):
    def test_resolve_safe_ips_rejects_private(self):
        from modules.jwt.keys import _resolve_safe_ips
        self.assertIsNone(_resolve_safe_ips("127.0.0.1"))
        self.assertIsNone(_resolve_safe_ips("10.0.0.1"))
        self.assertIsNone(_resolve_safe_ips("169.254.169.254"))

    def test_pin_dns_forces_validated_address_and_restores(self):
        import socket
        from modules.jwt.keys import _pin_dns
        real = socket.getaddrinfo
        with _pin_dns("example.com", ["93.184.216.34"]):
            infos = socket.getaddrinfo("example.com", 443)
        self.assertIs(socket.getaddrinfo, real)
        self.assertTrue(any(i[4][0] == "93.184.216.34" for i in infos))


# ---------------------------------------------------------- probe TLS fallback

class TestProbeTlsFallback(unittest.TestCase):
    def test_falls_back_only_on_policy_error(self):
        from modules.cors import probe
        session = mock.Mock()
        session.request.side_effect = requests.ConnectionError(
            "connection reset by peer"
        )
        with mock.patch.object(probe, "relaxed_session") as relaxed:
            relaxed.return_value.request.return_value = "ok"
            out = probe._do_request(session, "GET", "https://x.test")
        self.assertEqual(out, "ok")
        relaxed.return_value.request.assert_called_once()

    def test_other_errors_propagate_without_downgrade(self):
        from modules.cors import probe
        session = mock.Mock()
        session.request.side_effect = requests.ConnectionError("connection refused")
        with mock.patch.object(probe, "relaxed_session") as relaxed:
            with self.assertRaises(requests.ConnectionError):
                probe._do_request(session, "GET", "https://x.test")
        relaxed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
