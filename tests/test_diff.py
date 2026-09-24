"""Unit tests for scan diff mode (Phase D — D1)."""

import json
import os
import tempfile
import unittest

from modules.reporting.diff import (
    diff_results,
    load_result,
    print_diff,
    run_diff_cli,
    save_diff,
)


def _result(**overrides):
    base = {
        "target": "https://example.com",
        "internal_paths": ["/login", "/api/users"],
        "in_scope_urls": [],
        "intercepted_endpoints": [],
        "secrets_found": [
            {"type": "AWS Access Key", "match": "AKIAEXAMPLEKEY123"},
        ],
        "library_vulnerabilities": [
            {"library": "jquery", "cve": "CVE-2020-11022", "severity": "MEDIUM"},
        ],
        "risk_summary": {"score": 10, "level": "LOW", "severity_counts": {"LOW": 1}},
        "sinks_found": [],
    }
    base.update(overrides)
    return base


class TestDiffResults(unittest.TestCase):
    def test_added_and_removed_endpoints(self):
        old = _result(internal_paths=["/login", "/old"])
        new = _result(internal_paths=["/login", "/new"])
        d = diff_results(old, new)
        self.assertEqual(d["endpoints"]["added"], ["/new"])
        self.assertEqual(d["endpoints"]["removed"], ["/old"])
        self.assertEqual(d["endpoints"]["unchanged"], 1)

    def test_identical_results_no_change(self):
        d = diff_results(_result(), _result())
        self.assertEqual(d["endpoints"]["added"], [])
        self.assertEqual(d["endpoints"]["removed"], [])
        self.assertEqual(d["secrets"]["added"], [])
        self.assertEqual(d["risk"]["score_delta"], 0)
        self.assertFalse(d["regression"])

    def test_secret_added_triggers_regression_via_high_severity(self):
        old = _result(secrets_found=[])
        new = _result(
            secrets_found=[{"type": "AWS Access Key", "match": "AKIAEXAMPLEKEY123"}],
            risk_summary={"score": 35, "level": "HIGH", "severity_counts": {"HIGH": 1}},
        )
        d = diff_results(old, new)
        self.assertEqual(len(d["secrets"]["added"]), 1)
        self.assertTrue(d["regression"])
        self.assertEqual(d["risk"]["score_delta"], 25)

    def test_targets_recorded(self):
        d = diff_results(_result(target="https://a.test"), _result(target="https://b.test"))
        self.assertEqual(d["old_target"], "https://a.test")
        self.assertEqual(d["new_target"], "https://b.test")
        self.assertEqual(d["schema_version"], 1)

    def test_intercepted_endpoints_counted(self):
        old = _result(intercepted_endpoints=[])
        new = _result(intercepted_endpoints=[{"url": "https://example.com/api/x", "method": "GET"}])
        d = diff_results(old, new)
        self.assertIn("https://example.com/api/x", d["endpoints"]["added"])

    def test_library_vuln_diff(self):
        old = _result(library_vulnerabilities=[])
        new = _result(library_vulnerabilities=[
            {"library": "jquery", "cve": "CVE-2020-11022", "severity": "MEDIUM"},
        ])
        d = diff_results(old, new)
        self.assertEqual(d["library_vulnerabilities"]["added"], ["jquery:CVE-2020-11022"])


class TestDiffIO(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        d = diff_results(_result(), _result(internal_paths=["/login", "/api/users", "/x"]))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "diff.json")
            self.assertTrue(save_diff(d, path))
            loaded = load_result(path)
            self.assertEqual(loaded["endpoints"]["added"], ["/x"])
            self.assertEqual(loaded["schema_version"], 1)

    def test_load_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w") as fh:
                json.dump([1, 2], fh)
            with self.assertRaises(ValueError):
                load_result(path)

    def test_print_diff_does_not_raise(self):
        d = diff_results(_result(), _result(internal_paths=["/login", "/new"]))
        print_diff(d, verbose=True)
        print_diff(d, verbose=False)

    def test_run_diff_cli_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_p = os.path.join(tmp, "old.json")
            new_p = os.path.join(tmp, "new.json")
            out_p = os.path.join(tmp, "diff.json")
            with open(old_p, "w") as fh:
                json.dump(_result(), fh)
            with open(new_p, "w") as fh:
                json.dump(_result(internal_paths=["/login", "/api/users", "/extra"]), fh)
            d = run_diff_cli(old_p, new_p, output=out_p, verbose=False)
            self.assertEqual(d["endpoints"]["added"], ["/extra"])
            self.assertTrue(os.path.isfile(out_p))


class TestDiffCliFlag(unittest.TestCase):
    def test_parser_has_diff_flag(self):
        from main import build_parser

        args = build_parser().parse_args(["https://x.test", "--diff", "base.json"])
        self.assertEqual(args.diff, "base.json")

    def test_diff_flag_default_none(self):
        from main import build_parser

        args = build_parser().parse_args(["https://x.test"])
        self.assertIsNone(args.diff)


if __name__ == "__main__":
    unittest.main()
