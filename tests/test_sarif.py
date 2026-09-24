"""Unit tests for SARIF export (Phase D — D2)."""

import json
import os
import tempfile
import unittest

from modules.reporting.builder import build_report_plan, output_paths, write_reports
from modules.reporting.sarif import build_sarif, export_sarif


def _result(**overrides):
    base = {
        "target": "https://example.com",
        "internal_paths": ["/login"],
        "secrets_found": [
            {"type": "AWS Access Key", "match": "AKIAEXAMPLE", "severity": "HIGH",
             "sources": ["app.js"]},
        ],
        "library_vulnerabilities": [
            {"library": "jquery", "version": "1.11.0", "cve": "CVE-2020-11022",
             "severity": "MEDIUM", "title": "XSS in html()"},
        ],
        "sinks_found": [
            {"sink": "eval", "severity": "HIGH", "description": "eval()",
             "source": "bundle.js"},
        ],
        "cors": {
            "findings": [
                {"url": "https://example.com/api", "severity": "CRITICAL",
                 "acao": "https://evil.com", "detail": "Arbitrary origin reflected"},
                {"url": "https://example.com/x", "severity": "INFO", "acao": ""},
            ],
        },
        "jwt": {
            "findings": [
                {"findings": [{"title": "alg=none accepted", "severity": "HIGH"}]},
            ],
        },
        "risk_summary": {"score": 40, "level": "HIGH"},
        "meta": {"finished_at": "2026-01-01T00:00:00+00:00"},
    }
    base.update(overrides)
    return base


class TestBuildSarif(unittest.TestCase):
    def test_envelope(self):
        log = build_sarif(_result())
        self.assertEqual(log["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0", log["$schema"])
        self.assertEqual(len(log["runs"]), 1)
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "SurfaceSweep")
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertLessEqual(
            {"secret-leak", "vulnerable-library", "dangerous-sink",
             "cors-misconfig", "jwt-issue"},
            rule_ids,
        )

    def test_results_from_all_surfaces(self):
        results = build_sarif(_result())["runs"][0]["results"]
        by_rule = {}
        for r in results:
            by_rule.setdefault(r["ruleId"], []).append(r)
        self.assertEqual(len(by_rule["secret-leak"]), 1)
        self.assertEqual(len(by_rule["vulnerable-library"]), 1)
        self.assertEqual(len(by_rule["dangerous-sink"]), 1)
        self.assertEqual(len(by_rule["cors-misconfig"]), 1)  # INFO skipped
        self.assertEqual(len(by_rule["jwt-issue"]), 1)

    def test_levels(self):
        results = build_sarif(_result())["runs"][0]["results"]
        levels = {(r["ruleId"], r["level"]) for r in results}
        self.assertIn(("secret-leak", "error"), levels)
        self.assertIn(("vulnerable-library", "warning"), levels)
        self.assertIn(("dangerous-sink", "error"), levels)
        self.assertIn(("cors-misconfig", "error"), levels)
        self.assertIn(("jwt-issue", "error"), levels)

    def test_locations_use_source(self):
        results = build_sarif(_result())["runs"][0]["results"]
        secret = next(r for r in results if r["ruleId"] == "secret-leak")
        uri = secret["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "app.js")

    def test_empty_result_valid_envelope(self):
        log = build_sarif({})
        self.assertEqual(log["runs"][0]["results"], [])
        self.assertEqual(log["version"], "2.1.0")

    def test_cve_in_message(self):
        results = build_sarif(_result())["runs"][0]["results"]
        lib = next(r for r in results if r["ruleId"] == "vulnerable-library")
        self.assertIn("CVE-2020-11022", lib["message"]["text"])
        self.assertIn("jquery", lib["message"]["text"])


class TestExportSarif(unittest.TestCase):
    def test_export_writes_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.sarif")
            self.assertTrue(export_sarif(_result(), path))
            with open(path) as fh:
                data = json.load(fh)
            self.assertEqual(data["version"], "2.1.0")
            self.assertTrue(data["runs"][0]["results"])

    def test_export_failure_returns_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Directory as file path → OSError
            bad = os.path.join(tmp, "adir")
            os.makedirs(bad)
            self.assertFalse(export_sarif(_result(), bad))


class TestBuilderWiring(unittest.TestCase):
    def test_output_paths_include_sarif(self):
        p = output_paths("reports/scan.json")
        self.assertEqual(p["sarif"], "reports/scan.sarif")

    def test_build_report_plan_sarif_flag(self):
        from argparse import Namespace
        plan = build_report_plan(Namespace(sarif=True, html=False, html_only=False,
                                           burp=False, zap=False, cors_poc=False))
        self.assertTrue(plan["write_sarif"])

    def test_build_report_plan_sarif_off(self):
        from argparse import Namespace
        plan = build_report_plan(Namespace(sarif=False, html=False, html_only=False,
                                           burp=False, zap=False, cors_poc=False))
        self.assertFalse(plan["write_sarif"])

    def test_write_reports_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "scan.json")
            written = write_reports(
                _result(), out,
                write_json=True, write_sarif=True, verbose=False,
            )
            self.assertTrue(written["json"])
            self.assertTrue(written["sarif"])
            self.assertTrue(os.path.isfile(written["sarif"]))


class TestCliFlag(unittest.TestCase):
    def test_parser_has_sarif(self):
        from main import build_parser
        args = build_parser().parse_args(["https://x.test", "--sarif"])
        self.assertTrue(args.sarif)

    def test_default_off(self):
        from main import build_parser
        args = build_parser().parse_args(["https://x.test"])
        self.assertFalse(args.sarif)


if __name__ == "__main__":
    unittest.main()
