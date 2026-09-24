"""Tier-1 tests for modules.common shared constants."""

import unittest
from unittest import mock

from modules import __version__ as modules_version
from modules.common import (
    CVE_SEVERITY_WEIGHTS,
    DEFAULT_USER_AGENT,
    RISK_THRESHOLDS,
    SEVERITY_ORDER,
    SEVERITY_RANK,
)
from modules.common import __version__ as common_version
from modules.common.constants import __version__ as constants_version


class TestVersion(unittest.TestCase):
    def test_versions_match(self):
        self.assertEqual(modules_version, common_version)
        self.assertEqual(common_version, constants_version)

    def test_version_format(self):
        parts = common_version.split(".")
        self.assertEqual(len(parts), 3)
        for p in parts:
            self.assertTrue(p.isdigit())


class TestSeverityOrder(unittest.TestCase):
    def test_rank_is_alias(self):
        self.assertIs(SEVERITY_RANK, SEVERITY_ORDER)

    def test_lower_is_worse(self):
        ranks = [SEVERITY_ORDER[s] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ERROR")]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(ranks[0], 0)

    def test_unknown_severity_not_in_map(self):
        self.assertNotIn("FATAL", SEVERITY_ORDER)

    def test_cors_severity_matches_common(self):
        from modules.cors.classifier import SEVERITY_ORDER as cors_order

        self.assertEqual(cors_order, SEVERITY_ORDER)

    def test_jwt_severity_matches_common(self):
        from modules.jwt.checks import SEVERITY_ORDER as jwt_order

        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertEqual(jwt_order[key], SEVERITY_ORDER[key])

    def test_findings_severity_matches_common(self):
        from modules.reporting.findings import SEVERITY_ORDER as findings_order

        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertEqual(findings_order[key], SEVERITY_ORDER[key])

    def test_html_cors_sev_order_matches_common(self):
        from modules.reporting.html import CORS_SEV_ORDER

        self.assertEqual(CORS_SEV_ORDER, SEVERITY_ORDER)


class TestRiskConstants(unittest.TestCase):
    def test_thresholds_descending(self):
        scores = [t for t, _ in RISK_THRESHOLDS]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_risk_levels_upper(self):
        for _, level in RISK_THRESHOLDS:
            self.assertEqual(level, level.upper())

    def test_cve_weights_cover_standard_severities(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            self.assertIn(sev, CVE_SEVERITY_WEIGHTS)
            self.assertIsInstance(CVE_SEVERITY_WEIGHTS[sev], int)
            self.assertGreater(CVE_SEVERITY_WEIGHTS[sev], 0)

    def test_cve_weights_monotonic(self):
        self.assertGreater(CVE_SEVERITY_WEIGHTS["CRITICAL"], CVE_SEVERITY_WEIGHTS["HIGH"])
        self.assertGreater(CVE_SEVERITY_WEIGHTS["HIGH"], CVE_SEVERITY_WEIGHTS["MEDIUM"])
        self.assertGreater(CVE_SEVERITY_WEIGHTS["MEDIUM"], CVE_SEVERITY_WEIGHTS["LOW"])

    def test_risk_module_reexports(self):
        from modules.extraction.risk import CVE_SEVERITY_WEIGHTS as risk_cve, RISK_THRESHOLDS as risk_rt

        self.assertEqual(risk_rt, RISK_THRESHOLDS)
        self.assertEqual(risk_cve, CVE_SEVERITY_WEIGHTS)


class TestUserAgent(unittest.TestCase):
    def test_default_ua_format(self):
        self.assertTrue(DEFAULT_USER_AGENT.startswith("SurfaceSweep/"))
        self.assertNotIn(" ", DEFAULT_USER_AGENT)

    def test_http_module_reexports(self):
        from modules.extraction.http import DEFAULT_USER_AGENT as http_ua

        self.assertEqual(http_ua, DEFAULT_USER_AGENT)


class TestScanResultSchema(unittest.TestCase):
    CORE_KEYS = (
        "target", "js_files_scanned", "inline_scripts_scanned",
        "secrets_found", "jwts_found", "source_maps_found",
        "deobfuscation_findings", "sinks_found", "internal_hosts_found",
        "pii_found", "errors",
    )

    def test_schema_version(self):
        from modules.common.result import RESULT_SCHEMA_VERSION

        self.assertEqual(RESULT_SCHEMA_VERSION, 1)

    def test_new_scan_result_core_keys(self):
        from modules.common.result import new_scan_result

        r = new_scan_result("https://x.test")
        for key in self.CORE_KEYS:
            self.assertIn(key, r)
        self.assertEqual(r["target"], "https://x.test")
        self.assertEqual(r["js_files_scanned"], [])
        self.assertEqual(r["inline_scripts_scanned"], 0)
        self.assertNotIn("scan_mode", r)
        self.assertNotIn("network_requests", r)

    def test_new_scan_result_browser_fields(self):
        from modules.common.result import new_scan_result

        r = new_scan_result("https://x.test", scan_mode="browser", browser_fields=True)
        self.assertEqual(r["scan_mode"], "browser")
        self.assertEqual(r["network_requests"], [])
        self.assertEqual(r["intercepted_endpoints"], [])

    def test_new_scan_result_extra_overrides(self):
        from modules.common.result import new_scan_result

        r = new_scan_result("https://x.test", scan_depth=2, errors=["boom"])
        self.assertEqual(r["scan_depth"], 2)
        self.assertEqual(r["errors"], ["boom"])

    def test_extractor_uses_factory(self):
        import inspect
        from modules.extraction import engine

        src = inspect.getsource(engine.run_extractor)
        self.assertIn("new_scan_result", src)
        self.assertNotIn('"secrets_found": []', src)

    def test_extractor_sets_risk_on_fetch_failure(self):
        """Failed base URL must still produce risk_summary (HTML/fail-on need it)."""
        import requests
        from modules.extraction import engine

        with mock.patch(
            "modules.extraction.engine.get_page",
            side_effect=requests.ConnectionError("proxy down"),
        ):
            r = engine.run_extractor("http://127.0.0.1:9/", verbose=False)
        self.assertTrue(any("Failed to fetch" in e for e in r["errors"]))
        self.assertIn("risk_summary", r)
        self.assertIn("level", r["risk_summary"])

    def test_extractor_pulls_paths_from_html_body(self):
        """Server-rendered pages with no JS must still yield href paths."""
        from modules.extraction import engine

        html = (
            '<html><body>'
            '<a href="/index.jsp?content=login">login</a>'
            '<a href="/admin/panel.jsp">admin</a>'
            '<link rel="stylesheet" href="/style.css">'
            '</body></html>'
        )
        with mock.patch("modules.extraction.engine.get_page", return_value=html):
            r = engine.run_extractor("https://demo.testfire.net/", verbose=False, max_depth=0)
        self.assertIn("/index.jsp?content=login", r["internal_paths"])
        self.assertIn("/admin/panel.jsp", r["internal_paths"])
        self.assertNotIn("/style.css", r["internal_paths"])

    def test_extractor_source_label_is_html_body(self):
        import inspect
        from modules.extraction import engine

        src = inspect.getsource(engine.run_extractor)
        self.assertIn('"html_body"', src)

    def test_browser_uses_factory(self):
        import inspect
        from modules.extraction import browser

        src = inspect.getsource(browser.run_browser_scan)
        self.assertIn("new_scan_result", src)

    def test_merge_uses_factory(self):
        import inspect
        from modules.extraction import engine

        src = inspect.getsource(engine.merge_results)
        self.assertIn("new_scan_result", src)

    def test_runner_stamps_schema_version_constant(self):
        import inspect
        from modules.pipeline import runner

        src = inspect.getsource(runner._stamp_meta)
        self.assertIn("RESULT_SCHEMA_VERSION", src)


class TestConsole(unittest.TestCase):
    def setUp(self):
        from modules.common.console import configure_console

        configure_console(quiet=False)

    def tearDown(self):
        from modules.common.console import configure_console

        configure_console(quiet=False)

    def test_info_ok_warn_prefixes(self):
        import io
        from contextlib import redirect_stdout
        from modules.common.console import detail, info, ok, warn

        buf = io.StringIO()
        with redirect_stdout(buf):
            info("progress")
            ok("done")
            warn("careful")
            detail("sub")
        lines = buf.getvalue().splitlines()
        self.assertEqual(lines[0], "[*] progress")
        self.assertEqual(lines[1], "[+] done")
        self.assertEqual(lines[2], "[!] careful")
        self.assertEqual(lines[3], "    sub")

    def test_leading_space_trimmed(self):
        import io
        from contextlib import redirect_stdout
        from modules.common.console import info

        buf = io.StringIO()
        with redirect_stdout(buf):
            info(" spaced")
        self.assertEqual(buf.getvalue(), "[*] spaced\n")

    def test_quiet_suppresses_stdout(self):
        import io
        from contextlib import redirect_stdout
        from modules.common.console import configure_console, info, is_quiet, ok

        configure_console(quiet=True)
        self.assertTrue(is_quiet())
        buf = io.StringIO()
        with redirect_stdout(buf):
            info("hidden")
            ok("hidden")
        self.assertEqual(buf.getvalue(), "")

    def test_error_always_to_stderr(self):
        import io
        from contextlib import redirect_stderr
        from modules.common.console import configure_console, error

        configure_console(quiet=True)
        buf = io.StringIO()
        with redirect_stderr(buf):
            error("[!] fatal")
        self.assertIn("fatal", buf.getvalue())
        configure_console(quiet=False)

    def test_main_wires_quiet(self):
        import inspect
        import main as main_mod

        src = inspect.getsource(main_mod.main)
        self.assertIn("configure_console", src)

    def test_emit_respects_quiet_and_file(self):
        import io
        from contextlib import redirect_stdout
        from modules.common.console import configure_console, emit

        configure_console(quiet=False)
        buf = io.StringIO()
        with redirect_stdout(buf):
            emit("[*] raw line")
        self.assertEqual(buf.getvalue(), "[*] raw line\n")

        configure_console(quiet=True)
        buf2 = io.StringIO()
        with redirect_stdout(buf2):
            emit("[*] hidden")
        self.assertEqual(buf2.getvalue(), "")
        configure_console(quiet=False)

    def test_emit_explicit_file_bypasses_stdout(self):
        import io
        from modules.common.console import configure_console, emit

        configure_console(quiet=False)
        buf = io.StringIO()
        emit("[+] to-file", file=buf)
        self.assertEqual(buf.getvalue(), "[+] to-file\n")


class TestScanContextResult(unittest.TestCase):
    def test_require_result_raises_before_scan(self):
        from argparse import Namespace
        from modules.pipeline.context import ScanContext

        ctx = ScanContext(Namespace(), verbose=False)
        with self.assertRaises(RuntimeError):
            ctx.require_result()

    def test_require_result_returns_scan_result(self):
        from argparse import Namespace
        from modules.common.result import new_scan_result
        from modules.pipeline.context import ScanContext

        ctx = ScanContext(Namespace(), verbose=False)
        ctx.result = new_scan_result("https://x.test")
        out = ctx.require_result()
        self.assertEqual(out["target"], "https://x.test")
        self.assertIn("secrets_found", out)

    def test_log_respects_verbose(self):
        import io
        from argparse import Namespace
        from contextlib import redirect_stdout
        from modules.pipeline.context import ScanContext

        quiet_ctx = ScanContext(Namespace(), verbose=False)
        loud_ctx = ScanContext(Namespace(), verbose=True)
        buf = io.StringIO()
        with redirect_stdout(buf):
            quiet_ctx.log("[*] nope")
            loud_ctx.log("[*] yes")
        self.assertEqual(buf.getvalue(), "[*] yes\n")


class TestFoundationContracts(unittest.TestCase):
    def test_no_bare_print_in_modules(self):
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parents[1] / "modules"
        offenders = []
        for path in root.rglob("*.py"):
            if path.name == "console.py":
                continue
            text = path.read_text(encoding="utf-8")
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(r"\bprint\s*\(", line) and "file=" not in line:
                    offenders.append(f"{path.relative_to(root.parent)}:{i}")
        self.assertEqual(offenders, [], f"bare print() found: {offenders}")

    def test_common_package_exports(self):
        import modules.common as common

        for name in (
            "SEVERITY_ORDER", "RISK_THRESHOLDS", "CVE_SEVERITY_WEIGHTS",
            "DEFAULT_USER_AGENT", "__version__", "ScanResult", "new_scan_result",
            "RESULT_SCHEMA_VERSION", "configure_console", "info", "ok", "warn",
            "HttpClient" if hasattr(common, "HttpClient") else "detail",
        ):
            self.assertTrue(hasattr(common, name), f"missing export: {name}")

    def test_new_scan_result_lists_not_shared(self):
        from modules.common.result import new_scan_result

        a = new_scan_result("https://a.test")
        b = new_scan_result("https://b.test")
        a["secrets_found"].append({"type": "x"})
        self.assertEqual(b["secrets_found"], [])
        self.assertIsNot(a["errors"], b["errors"])


class TestSecretSeverity(unittest.TestCase):
    def test_critical_crown_jewels(self):
        from modules.common.constants import secret_severity

        for t in ("Private Key", "AWS Secret Key", "GCP Service Account", "Database URL"):
            self.assertEqual(secret_severity(t), "CRITICAL", t)

    def test_publishable_and_public_info(self):
        from modules.common.constants import secret_severity

        for t in ("Stripe Publishable", "PayPal Client ID", "Firebase URL", "Mapbox Token"):
            self.assertEqual(secret_severity(t), "INFO", t)

    def test_csrf_is_low(self):
        from modules.common.constants import secret_severity

        self.assertEqual(secret_severity("CSRF Token"), "LOW")

    def test_unknown_defaults_high(self):
        from modules.common.constants import DEFAULT_SECRET_SEVERITY, secret_severity

        self.assertEqual(secret_severity("Some Vendor Key"), DEFAULT_SECRET_SEVERITY)
        self.assertEqual(secret_severity(""), "HIGH")
        self.assertEqual(secret_severity(None), "HIGH")

    def test_generic_secret_is_medium(self):
        from modules.common.constants import secret_severity

        self.assertEqual(secret_severity("Generic Secret"), "MEDIUM")

    def test_findings_use_type_severity(self):
        from modules.reporting.findings import build_findings_feed

        result = {
            "secrets_found": [
                {"type": "AWS Access Key", "match": "AKIA...", "sources": ["a"]},
                {"type": "Stripe Publishable", "match": "pk_live...", "sources": ["b"]},
                {"type": "Private Key", "match": "-----BEGIN...", "sources": ["c"]},
            ],
        }
        feed = build_findings_feed(result)
        by_type = {f["title"]: f["severity"] for f in feed if f["module"] == "secrets"}
        self.assertEqual(by_type["Potential secret (AWS Access Key)"], "HIGH")
        self.assertEqual(by_type["Potential secret (Stripe Publishable)"], "INFO")
        self.assertEqual(by_type["Potential secret (Private Key)"], "CRITICAL")

    def test_risk_weights_by_type(self):
        from modules.extraction.risk import calculate_risk_summary

        base = calculate_risk_summary({"secrets_found": []})["score"]
        crit = calculate_risk_summary(
            {"secrets_found": [{"type": "Private Key", "match": "x"}]}
        )["score"]
        info = calculate_risk_summary(
            {"secrets_found": [{"type": "Stripe Publishable", "match": "pk_live_x"}]}
        )["score"]
        high = calculate_risk_summary(
            {"secrets_found": [{"type": "AWS Access Key", "match": "AKIA..."}]}
        )["score"]
        self.assertEqual(crit - base, 25)
        self.assertEqual(high - base, 10)
        self.assertEqual(info - base, 0)

    def test_secret_severity_exported_from_common(self):
        from modules.common import secret_severity as exported

        self.assertEqual(exported("Private Key"), "CRITICAL")

    def test_metadata_ip_is_high(self):
        from modules.common.constants import internal_host_severity

        self.assertEqual(
            internal_host_severity(
                {"match": "http://169.254.169.254/latest/meta-data", "kind": "internal_url"}
            ),
            "HIGH",
        )
        self.assertEqual(internal_host_severity({"match": "169.254.1.1"}), "HIGH")
        self.assertEqual(internal_host_severity({"match": "10.0.0.1", "kind": "private_ip"}), "MEDIUM")
        self.assertEqual(internal_host_severity(None), "MEDIUM")

    def test_findings_metadata_high_vs_private_medium(self):
        from modules.reporting.findings import build_findings_feed

        result = {
            "internal_hosts_found": [
                {"kind": "internal_url", "match": "http://169.254.169.254/latest/meta-data", "source": "a.js"},
                {"kind": "private_ip", "match": "10.0.0.5", "source": "b.js"},
            ],
        }
        feed = build_findings_feed(result)
        by_title = {f["title"]: f for f in feed if f["module"] == "internal_hosts"}
        self.assertEqual(by_title["Cloud metadata reference (169.254.x)"]["severity"], "HIGH")
        self.assertEqual(by_title["Internal reference (private_ip)"]["severity"], "MEDIUM")

    def test_internal_host_risk_weights(self):
        from modules.extraction.risk import calculate_risk_summary

        base = calculate_risk_summary({"internal_hosts_found": []})["score"]
        meta = calculate_risk_summary(
            {"internal_hosts_found": [{"match": "http://169.254.169.254/", "kind": "internal_url"}]}
        )["score"]
        priv = calculate_risk_summary(
            {"internal_hosts_found": [{"match": "10.0.0.5", "kind": "private_ip"}]}
        )["score"]
        self.assertEqual(meta - base, 6)
        self.assertEqual(priv - base, 3)


if __name__ == "__main__":
    unittest.main()
