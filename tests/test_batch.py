"""Unit tests for multi-target batch scans (Phase D — D3)."""

import os
import tempfile
import unittest
from argparse import Namespace
from unittest import mock

from main import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    batch_output_path,
    build_parser,
    load_targets_file,
    main,
    resolve_targets,
)


class TestLoadTargetsFile(unittest.TestCase):
    def test_skips_comments_and_blanks_dedupes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "targets.txt")
            with open(path, "w") as fh:
                fh.write(
                    "# production\n"
                    "https://a.test\n"
                    "\n"
                    "https://b.test\n"
                    "https://a.test\n"
                    "  https://c.test  \n"
                )
            self.assertEqual(
                load_targets_file(path),
                ["https://a.test", "https://b.test", "https://c.test"],
            )

    def test_missing_file_raises(self):
        with self.assertRaises(OSError):
            load_targets_file("/nonexistent/targets.txt")


class TestResolveTargets(unittest.TestCase):
    def _parser(self):
        return build_parser()

    def test_positional_only(self):
        parser = self._parser()
        args = parser.parse_args(["https://a.test"])
        self.assertEqual(resolve_targets(args, parser), ["https://a.test"])

    def test_targets_file_only(self):
        parser = self._parser()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.txt")
            with open(path, "w") as fh:
                fh.write("https://a.test\nhttps://b.test\n")
            args = parser.parse_args(["--targets", path])
            self.assertEqual(
                resolve_targets(args, parser),
                ["https://a.test", "https://b.test"],
            )

    def test_positional_plus_file_deduped(self):
        parser = self._parser()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.txt")
            with open(path, "w") as fh:
                fh.write("https://a.test\nhttps://b.test\n")
            args = parser.parse_args(["https://a.test", "--targets", path])
            self.assertEqual(
                resolve_targets(args, parser),
                ["https://a.test", "https://b.test"],
            )

    def test_neither_errors(self):
        parser = self._parser()
        args = parser.parse_args([])
        with self.assertRaises(SystemExit):
            resolve_targets(args, parser)


class TestBatchOutputPath(unittest.TestCase):
    def test_derives_host_suffix(self):
        p = batch_output_path("reports/out.json", "https://app.example.com/path")
        self.assertEqual(p, "reports/out_app.example.com.json")

    def test_sanitizes_special_chars(self):
        p = batch_output_path("reports/out.json", "https://a_b.example.com:8443")
        self.assertIn("out_", p)
        self.assertTrue(p.endswith(".json"))
        # colon becomes underscore via sanitizer
        self.assertNotIn(":", os.path.basename(p))

    def test_non_http_target(self):
        p = batch_output_path("reports/out.json", "not-a-url")
        self.assertTrue(p.endswith(".json"))


class TestMainBatch(unittest.TestCase):
    def test_batch_runs_each_target_with_own_output(self):
        seen = []
        results = {}

        def fake_pipeline(args, verbose=True, headers=None):
            seen.append((args.target, args.output))
            results[args.target] = {
                "target": args.target,
                "risk_summary": {"score": 0, "level": "INFO"},
            }
            return results[args.target]

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "targets.txt")
            with open(path, "w") as fh:
                fh.write("https://a.test\nhttps://b.test\n")
            with mock.patch("main.run_pipeline", side_effect=fake_pipeline):
                code = main([
                    "--targets", path,
                    "-o", os.path.join(tmp, "out.json"),
                    "-q",
                ])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0][0], "https://a.test")
        self.assertEqual(seen[1][0], "https://b.test")
        self.assertNotEqual(seen[0][1], seen[1][1])
        self.assertTrue(all(s[1].endswith(".json") for s in seen))

    def test_batch_exit_findings_if_any(self):
        def fake_pipeline(args, verbose=True, headers=None):
            if args.target == "https://bad.test":
                return {"risk_summary": {"score": 50, "level": "HIGH",
                                         "severity_counts": {"HIGH": 1}}}
            return {"risk_summary": {"score": 0, "level": "INFO"}}

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.txt")
            with open(path, "w") as fh:
                fh.write("https://good.test\nhttps://bad.test\n")
            with mock.patch("main.run_pipeline", side_effect=fake_pipeline):
                code = main([
                    "--targets", path,
                    "-o", os.path.join(tmp, "out.json"),
                    "-q",
                    "--fail-on", "high",
                ])
        self.assertEqual(code, EXIT_FINDINGS)

    def test_batch_exit_error_dominates(self):
        def fake_pipeline(args, verbose=True, headers=None):
            if args.target == "https://boom.test":
                raise RuntimeError("network down")
            return {"risk_summary": {"score": 50, "level": "HIGH",
                                     "severity_counts": {"HIGH": 1}}}

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.txt")
            with open(path, "w") as fh:
                fh.write("https://boom.test\nhttps://ok.test\n")
            with mock.patch("main.run_pipeline", side_effect=fake_pipeline):
                code = main([
                    "--targets", path,
                    "-o", os.path.join(tmp, "out.json"),
                    "-q",
                    "--fail-on", "high",
                ])
        self.assertEqual(code, EXIT_ERROR)

    def test_single_target_unchanged_output(self):
        seen = {}

        def fake_pipeline(args, verbose=True, headers=None):
            seen["target"] = args.target
            seen["output"] = args.output
            return {"risk_summary": {"score": 0, "level": "INFO"}}

        with mock.patch("main.run_pipeline", side_effect=fake_pipeline):
            code = main([
                "https://solo.test",
                "-o", "reports/solo.json",
                "-q",
            ])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(seen["target"], "https://solo.test")
        self.assertEqual(seen["output"], "reports/solo.json")


class TestParserTargets(unittest.TestCase):
    def test_target_is_optional(self):
        args = build_parser().parse_args(["--targets", "list.txt"])
        self.assertIsNone(args.target)
        self.assertEqual(args.targets, "list.txt")

    def test_targets_default_none(self):
        args = build_parser().parse_args(["https://x.test"])
        self.assertIsNone(args.targets)


if __name__ == "__main__":
    unittest.main()
