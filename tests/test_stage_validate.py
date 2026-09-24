"""Unit tests for stage_validate annotation behavior (Phase A Step 3)."""

import unittest
from argparse import Namespace
from unittest import mock

from modules.pipeline import ScanContext
from modules.pipeline.stages import stage_validate


def _args(**overrides):
    base = dict(
        target="https://example.com",
        output="reports/out.json",
        threads=6,
        depth=1,
        browser=False,
        full=False,
        validate=True,
        vt=10,
        vtimeout=5,
        timeout=30,
        scope=None,
        cookie=None,
        header=[],
        burp=False,
        zap=False,
        wayback=False,
        waf=False,
        cve=False,
        osv=False,
        spa=False,
        max_routes=50,
        no_probe=False,
        html=False,
        html_only=False,
        no_deobf=False,
        proxy=None,
        insecure=False,
        ua=None,
        fail_on="none",
        verify_tls=True,
        regex_only=False,
        cors=False,
        cors_origin=None,
        cors_max=50,
        cors_rps=5.0,
        cors_threads=6,
        cors_timeout=5.0,
        cors_poc=False,
        jwt=False,
        jwt_wordlist=None,
        jwt_hashcat=None,
        jwt_export=None,
        jwt_network=False,
        jwt_network_timeout=5.0,
        graphql=False,
        graphql_timeout=5.0,
        quiet=False,
    )
    base.update(overrides)
    return Namespace(**base)


def _validation_result(url, status, note=None, status_code=200):
    r = {"url": url, "status": status, "status_code": status_code, "method": "GET"}
    if note:
        r["note"] = note
    return r


class TestStageValidateAnnotates(unittest.TestCase):
    def _ctx(self, paths):
        ctx = ScanContext(_args(), verbose=False)
        ctx.result = {
            "target": "https://example.com",
            "internal_paths": list(paths),
            "in_scope_urls": [],
            "intercepted_endpoints": [],
            "secrets_found": [],
        }
        return ctx

    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.validate_endpoints")
    def test_preserves_discovered_and_removes_only_dead(self, ve_mock, risk_mock):
        risk_mock.return_value = {"level": "INFO", "score": 0}
        ve_mock.return_value = {
            "live": [_validation_result("https://example.com/api/live", "live")],
            "restricted": [],
            "dead": [_validation_result("https://example.com/api/gone", "dead", "soft_404")],
            "server_error": [],
            "timeout": [_validation_result("https://example.com/api/slow", "timeout", status_code=None)],
            "connection_error": [],
            "error": [],
            "redirect": [],
            "unknown": [],
        }
        ctx = self._ctx(["/api/live", "/api/gone", "/api/slow"])
        stage_validate(ctx)
        r = ctx.result

        # Full discovery preserved
        self.assertEqual(
            r["internal_paths_discovered"],
            ["/api/live", "/api/gone", "/api/slow"],
        )
        # Confirmed dead removed from active pool; timeout kept
        self.assertEqual(r["internal_paths"], ["/api/live", "/api/slow"])
        # Annotations present
        self.assertEqual(r["path_status"]["/api/live"]["status"], "live")
        self.assertEqual(r["path_status"]["/api/gone"]["status"], "dead")
        self.assertEqual(r["path_status"]["/api/gone"]["note"], "soft_404")
        self.assertEqual(r["path_status"]["/api/slow"]["status"], "timeout")
        self.assertIn("validation", r)

    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.validate_endpoints")
    def test_connection_error_not_erased(self, ve_mock, risk_mock):
        risk_mock.return_value = {"level": "INFO", "score": 0}
        ve_mock.return_value = {
            "live": [],
            "restricted": [],
            "dead": [],
            "server_error": [],
            "timeout": [],
            "connection_error": [_validation_result(
                "https://example.com/api/x", "connection_error", status_code=None
            )],
            "error": [],
            "redirect": [],
            "unknown": [],
        }
        ctx = self._ctx(["/api/x"])
        stage_validate(ctx)
        self.assertEqual(ctx.result["internal_paths"], ["/api/x"])
        self.assertEqual(ctx.result["path_status"]["/api/x"]["status"], "connection_error")

    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.validate_endpoints")
    def test_empty_validation_keeps_all_paths(self, ve_mock, risk_mock):
        risk_mock.return_value = {"level": "INFO", "score": 0}
        ve_mock.return_value = {
            "live": [], "restricted": [], "dead": [], "server_error": [],
            "timeout": [], "connection_error": [], "error": [],
            "redirect": [], "unknown": [],
        }
        ctx = self._ctx(["/a", "/b"])
        stage_validate(ctx)
        self.assertEqual(ctx.result["internal_paths"], ["/a", "/b"])
        self.assertEqual(ctx.result["internal_paths_discovered"], ["/a", "/b"])

    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.validate_endpoints")
    def test_no_endpoints_skips_validation(self, ve_mock, risk_mock):
        ctx = ScanContext(_args(), verbose=False)
        ctx.result = {
            "target": "https://example.com",
            "internal_paths": [],
            "in_scope_urls": [],
            "intercepted_endpoints": [],
        }
        stage_validate(ctx)
        ve_mock.assert_not_called()
        self.assertNotIn("validation", ctx.result)


if __name__ == "__main__":
    unittest.main()
