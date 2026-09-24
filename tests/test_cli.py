"""Unit tests for Phase A Step 6 — CLI flags, HTTP config, exit codes."""

import subprocess
import sys
import os
import unittest
from argparse import Namespace

from main import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    build_headers,
    build_parser,
    exit_code_for_result,
)
from modules import __version__
from modules.extraction.http import (
    DEFAULT_USER_AGENT,
    configure_http,
    default_headers,
    request_kwargs,
    reset_http_config,
)


class TestCliFlags(unittest.TestCase):
    def setUp(self):
        reset_http_config()

    def tearDown(self):
        reset_http_config()

    def test_parser_has_new_flags(self):
        parser = build_parser()
        args = parser.parse_args(
            ["https://x.test",
             "--proxy", "http://127.0.0.1:8080",
             "--insecure",
             "--ua", "MyUA/1.0",
             "--fail-on", "high",
             "--no-deobf",
            ]
        )
        self.assertEqual(args.proxy, "http://127.0.0.1:8080")
        self.assertTrue(args.insecure)
        self.assertEqual(args.ua, "MyUA/1.0")
        self.assertEqual(args.fail_on, "high")
        self.assertTrue(args.no_deobf)

    def test_fail_on_choices(self):
        parser = build_parser()
        for level in ("none", "low", "medium", "high", "critical"):
            args = parser.parse_args(["https://x.test", "--fail-on", level])
            self.assertEqual(args.fail_on, level)
        with self.assertRaises(SystemExit):
            parser.parse_args(["https://x.test", "--fail-on", "bogus"])

    def test_default_fail_on_is_none(self):
        args = build_parser().parse_args(["https://x.test"])
        self.assertEqual(args.fail_on, "none")
        self.assertFalse(args.insecure)
        self.assertIsNone(args.proxy)
        self.assertIsNone(args.ua)

    def test_build_headers_ua(self):
        args = build_parser().parse_args(
            ["https://x.test", "--ua", "Custom/2.0", "--cookie", "a=b"]
        )
        headers = build_headers(args)
        self.assertEqual(headers["User-Agent"], "Custom/2.0")
        self.assertEqual(headers["Cookie"], "a=b")

    def test_build_headers_without_ua(self):
        args = build_parser().parse_args(["https://x.test"])
        self.assertNotIn("User-Agent", build_headers(args))

    def test_version_flag(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = os.environ.copy()
        env["PYTHONPATH"] = root
        proc = subprocess.run(
            [sys.executable, "main.py", "--version"],
            capture_output=True, text=True, cwd=root, env=env,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn(__version__, proc.stdout + proc.stderr)

    def test_help_lists_exit_codes_and_new_flags(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = os.environ.copy()
        env["PYTHONPATH"] = root
        proc = subprocess.run(
            [sys.executable, "main.py", "--help"],
            capture_output=True, text=True, cwd=root, env=env,
        )
        self.assertEqual(proc.returncode, 0)
        for needle in ("--proxy", "--insecure", "--ua", "--fail-on", "Exit codes"):
            self.assertIn(needle, proc.stdout)


class TestHttpConfig(unittest.TestCase):
    def setUp(self):
        reset_http_config()

    def tearDown(self):
        reset_http_config()

    def test_defaults(self):
        self.assertEqual(default_headers(), {"User-Agent": DEFAULT_USER_AGENT})
        kwargs = request_kwargs()
        self.assertNotIn("proxies", kwargs)
        self.assertNotIn("verify", kwargs)

    def test_configure_proxy_and_insecure_and_ua(self):
        configure_http(
            proxy="http://127.0.0.1:8080",
            insecure=True,
            user_agent="UA-Test/9",
        )
        kwargs = request_kwargs()
        self.assertEqual(kwargs["headers"]["User-Agent"], "UA-Test/9")
        self.assertEqual(kwargs["proxies"]["http"], "http://127.0.0.1:8080")
        self.assertEqual(kwargs["proxies"]["https"], "http://127.0.0.1:8080")
        self.assertIs(kwargs["verify"], False)

    def test_explicit_headers_win(self):
        configure_http(user_agent="Ignored")
        kwargs = request_kwargs(headers={"User-Agent": "Explicit"})
        self.assertEqual(kwargs["headers"]["User-Agent"], "Explicit")

    def test_reset(self):
        configure_http(proxy="http://p:1", insecure=True, user_agent="X")
        reset_http_config()
        kwargs = request_kwargs()
        self.assertNotIn("proxies", kwargs)
        self.assertNotIn("verify", kwargs)
        self.assertEqual(default_headers()["User-Agent"], DEFAULT_USER_AGENT)


class TestExitCodes(unittest.TestCase):
    def _result(self, severity_counts=None, level="INFO"):
        return {
            "risk_summary": {
                "score": 0,
                "level": level,
                "severity_counts": severity_counts or {},
            }
        }

    def test_fail_on_none_always_ok(self):
        r = self._result({"CRITICAL": 5}, level="CRITICAL")
        self.assertEqual(exit_code_for_result(r, "none"), EXIT_OK)
        self.assertEqual(exit_code_for_result(r, ""), EXIT_OK)
        self.assertEqual(exit_code_for_result(None, "none"), EXIT_OK)

    def test_fail_on_critical_with_critical(self):
        r = self._result({"CRITICAL": 1})
        self.assertEqual(exit_code_for_result(r, "critical"), EXIT_FINDINGS)

    def test_fail_on_critical_without_critical(self):
        r = self._result({"HIGH": 3, "MEDIUM": 1})
        self.assertEqual(exit_code_for_result(r, "critical"), EXIT_OK)

    def test_fail_on_high_with_high(self):
        r = self._result({"HIGH": 1})
        self.assertEqual(exit_code_for_result(r, "high"), EXIT_FINDINGS)

    def test_fail_on_high_with_only_medium(self):
        r = self._result({"MEDIUM": 9})
        self.assertEqual(exit_code_for_result(r, "high"), EXIT_OK)

    def test_fail_on_medium_with_high_counts_as_at_or_above(self):
        r = self._result({"HIGH": 1})
        self.assertEqual(exit_code_for_result(r, "medium"), EXIT_FINDINGS)

    def test_fallback_to_risk_level_when_no_severity_counts(self):
        r = {"risk_summary": {"score": 40, "level": "HIGH"}}
        self.assertEqual(exit_code_for_result(r, "high"), EXIT_FINDINGS)
        self.assertEqual(exit_code_for_result(r, "critical"), EXIT_OK)

    def test_empty_result(self):
        self.assertEqual(exit_code_for_result({}, "high"), EXIT_OK)
        self.assertEqual(exit_code_for_result(None, "high"), EXIT_OK)

    def test_error_code_is_distinct(self):
        self.assertNotEqual(EXIT_ERROR, EXIT_OK)
        self.assertNotEqual(EXIT_ERROR, EXIT_FINDINGS)
        self.assertNotEqual(EXIT_FINDINGS, EXIT_OK)


class TestNoDeobfThreading(unittest.TestCase):
    def test_stage_scan_passes_deobfuscate_flag(self):
        from modules.pipeline import stages as stages_mod
        from modules.pipeline.context import ScanContext

        captured = {}

        def fake_run_extractor(target, **kwargs):
            captured["static"] = kwargs
            return {"target": target, "scan_mode": "static", "internal_paths": [],
                    "js_files_scanned": [], "secrets_found": [],
                    "risk_summary": {"score": 0, "level": "INFO"},
                    "intercepted_endpoints": [], "errors": [],
                    "deobfuscation_findings": [], "sinks_found": [],
                    "internal_hosts_found": [], "jwts_found": [],
                    "pii_found": [], "in_scope_urls": [], "out_of_scope_urls": [],
                    "source_maps_found": [], "network_requests": []}

        args = Namespace(
            target="https://x.test", threads=2, depth=1, full=False,
            browser=False, no_deobf=True, regex_only=False, scope=None,
            timeout=5, ua=None, proxy=None, verify_tls=True,
        )
        ctx = ScanContext(args, verbose=False)
        orig = stages_mod.run_extractor
        stages_mod.run_extractor = fake_run_extractor
        try:
            stages_mod.stage_scan(ctx)
        finally:
            stages_mod.run_extractor = orig
        self.assertIn("static", captured)
        self.assertIs(captured["static"]["deobfuscate"], False)

    def test_browser_scan_accepts_deobfuscate_content_param(self):
        import inspect
        from modules.extraction.browser import run_browser_scan
        sig = inspect.signature(run_browser_scan)
        self.assertIn("deobfuscate_content", sig.parameters)
        self.assertIs(sig.parameters["deobfuscate_content"].default, True)
        self.assertIn("user_agent", sig.parameters)
        self.assertIn("proxy", sig.parameters)


if __name__ == "__main__":
    unittest.main()
