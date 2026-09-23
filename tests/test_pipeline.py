"""Unit tests for Phase 4 Step 1 — pipeline stage list and ordering."""

import unittest
from argparse import Namespace

from modules.pipeline import ScanContext, build_stages, stage_names


def _args(**overrides):
    """Minimal Namespace with every flag the stage predicates read."""
    base = dict(
        target="https://example.com",
        output="reports/out.json",
        threads=6,
        depth=1,
        browser=False,
        full=False,
        validate=False,
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
        regex_only=False,
        cors=False,
        cors_origin=None,
        cors_max=50,
        cors_rps=5.0,
        cors_threads=6,
        cors_timeout=5.0,
        jwt=False,
        jwt_wordlist=None,
        jwt_hashcat=None,
        jwt_export=None,
        jwt_network=False,
        jwt_network_timeout=5.0,
        quiet=False,
    )
    base.update(overrides)
    return Namespace(**base)


class TestStageList(unittest.TestCase):
    def test_default_stages(self):
        names = stage_names(_args())
        self.assertEqual(names, ["scan", "report"])

    def test_all_flags_enabled_order(self):
        names = stage_names(_args(
            waf=True, wayback=True, full=True, cve=True, spa=True,
            cors=True, jwt=True, validate=True, burp=True, zap=True,
        ))
        self.assertEqual(names, [
            "waf_detect", "wayback_fetch", "scan", "wayback_merge",
            "waf_inject", "cve", "spa", "cors", "jwt", "validate",
            "export", "report",
        ])

    def test_cve_or_osv_enables_cve_stage(self):
        self.assertIn("cve", stage_names(_args(cve=True)))
        self.assertIn("cve", stage_names(_args(osv=True)))
        self.assertNotIn("cve", stage_names(_args()))

    def test_export_only_when_burp_or_zap(self):
        self.assertNotIn("export", stage_names(_args()))
        self.assertIn("export", stage_names(_args(burp=True)))
        self.assertIn("export", stage_names(_args(zap=True)))

    def test_scan_always_present(self):
        self.assertIn("scan", stage_names(_args()))
        self.assertIn("report", stage_names(_args()))

    def test_wayback_pair(self):
        names = stage_names(_args(wayback=True))
        self.assertEqual(names, ["wayback_fetch", "scan", "wayback_merge", "report"])

    def test_build_stages_returns_callables(self):
        for name, fn in build_stages(_args(waf=True, wayback=True, cors=True)):
            self.assertTrue(callable(fn), name)


class TestScanContext(unittest.TestCase):
    def test_require_result_before_scan_raises(self):
        ctx = ScanContext(_args(), verbose=False)
        with self.assertRaises(RuntimeError):
            ctx.require_result()

    def test_require_result_after_init(self):
        ctx = ScanContext(_args(), verbose=False)
        ctx.result = {"target": "x"}
        self.assertEqual(ctx.require_result()["target"], "x")

    def test_log_respects_verbose(self):
        ctx = ScanContext(_args(), verbose=False)
        ctx.log("should not print")  # must not raise


if __name__ == "__main__":
    unittest.main()
