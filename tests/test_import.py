"""Alternate discovery sources — Burp / ZAP / HAR import."""

import json
import os
import tempfile
import unittest

from argparse import Namespace

from modules.discovery.importers import (
    ImportParseError,
    detect_format,
    extract_urls,
    load_import,
)
from modules.pipeline import ScanContext
from modules.pipeline.stages import stage_import
from modules.reporting.export import export_burp_csv, export_zap_csv

TARGET = "https://example.com"

_HAR = {
    "log": {
        "entries": [
            {"request": {"url": "https://example.com/api/v1/users?page=1#frag"}},
            {"request": {"url": "https://cdn.third-party.test/lib.js"}},
            {"request": {"url": "ftp://example.com/skip-me"}},
            {"request": {"url": "https://example.com/api/v1/users?page=1#frag"}},
        ]
    }
}

_BURP_XML = """<?xml version="1.0"?>
<items>
  <item><url><![CDATA[https://example.com/admin/panel]]></url></item>
  <item><url><![CDATA[https://example.com/api/graphql]]></url></item>
</items>
"""


def _write(suffix, text):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class TestDetectFormat(unittest.TestCase):
    def test_har_extension(self):
        self.assertEqual(detect_format("x.har", "{}"), "har")

    def test_json_content_is_har(self):
        self.assertEqual(detect_format("capture.json", '{"log": {}}'), "har")

    def test_xml_extension(self):
        self.assertEqual(detect_format("items.xml", "<items/>"), "burp_xml")

    def test_xml_content(self):
        self.assertEqual(detect_format("blob", "<?xml version='1.0'?><items/>"), "burp_xml")

    def test_zap_csv_by_header(self):
        self.assertEqual(detect_format("z.csv", "URL,Method,Data,Payload\n"), "zap_csv")

    def test_burp_csv_by_header(self):
        self.assertEqual(detect_format("b.csv", "Host,Protocol,Path,Query\n"), "burp_csv")

    def test_unknown_returns_none(self):
        self.assertIsNone(detect_format("notes.txt", "hello world"))


class TestHarParsing(unittest.TestCase):
    def test_extracts_and_cleans(self):
        urls = extract_urls(json.dumps(_HAR), "har")
        self.assertEqual(
            urls,
            [
                "https://cdn.third-party.test/lib.js",
                "https://example.com/api/v1/users?page=1",
            ],
        )

    def test_fragment_stripped_and_deduped(self):
        urls = extract_urls(json.dumps(_HAR), "har")
        # "#frag" dropped, duplicate collapsed
        self.assertEqual(sum(1 for u in urls if "page=1" in u), 1)
        self.assertFalse(any("#" in u for u in urls))

    def test_invalid_json_raises_parse_error(self):
        with self.assertRaises(ImportParseError):
            extract_urls("{not json", "har")


class TestBurpXmlParsing(unittest.TestCase):
    def test_extracts_urls(self):
        self.assertEqual(
            extract_urls(_BURP_XML, "burp_xml"),
            ["https://example.com/admin/panel", "https://example.com/api/graphql"],
        )

    def test_invalid_xml_raises_parse_error(self):
        with self.assertRaises(ImportParseError):
            extract_urls("<items><item>", "burp_xml")


class TestZapCsvParsing(unittest.TestCase):
    def test_extracts_url_column(self):
        text = "URL,Method,Data,Payload\nhttps://example.com/api,a,,\n"
        self.assertEqual(extract_urls(text, "zap_csv"), ["https://example.com/api"])


class TestBurpCsvRoundTrip(unittest.TestCase):
    def test_export_then_import(self):
        result = {"target": TARGET, "internal_paths": ["/api/login"], "in_scope_urls": []}
        out = tempfile.mkdtemp()
        path = os.path.join(out, "burp.csv")
        export_burp_csv(result, path)
        urls = load_import(path)["endpoints"]
        self.assertIn("https://example.com/api/login", urls)


class TestZapCsvRoundTrip(unittest.TestCase):
    def test_export_then_import(self):
        result = {"target": TARGET, "internal_paths": ["/api/v2/items"], "in_scope_urls": []}
        out = tempfile.mkdtemp()
        path = os.path.join(out, "zap.csv")
        export_zap_csv(result, path)
        urls = load_import(path)["endpoints"]
        self.assertIn("https://example.com/api/v2/items", urls)


class TestLoadImport(unittest.TestCase):
    def test_load_har_file(self):
        path = _write(".har", json.dumps(_HAR))
        try:
            loaded = load_import(path)
        finally:
            os.unlink(path)
        self.assertEqual(loaded["format"], "har")
        self.assertEqual(loaded["count"], len(loaded["endpoints"]))

    def test_unknown_format_raises(self):
        path = _write(".txt", "no urls here")
        try:
            with self.assertRaises(ImportParseError):
                load_import(path)
        finally:
            os.unlink(path)


class TestStageImport(unittest.TestCase):
    def _ctx(self, files):
        args = Namespace(target=TARGET, import_files=files)
        ctx = ScanContext(args, verbose=False)
        ctx.result = {
            "target": TARGET,
            "internal_paths": [],
            "in_scope_urls": [],
            "intercepted_endpoints": [],
            "secrets_found": [],
        }
        return ctx

    def test_merges_only_in_scope(self):
        path = _write(".har", json.dumps(_HAR))
        try:
            ctx = self._ctx([path])
            stage_import(ctx)
        finally:
            os.unlink(path)
        urls = ctx.result["in_scope_urls"]
        self.assertIn("https://example.com/api/v1/users?page=1", urls)
        # Third-party and static URLs must not widen the scan
        self.assertFalse(any("third-party" in u for u in urls))
        self.assertFalse(any(u.endswith(".js") for u in urls))
        self.assertEqual(ctx.result["imported_sources"], ["har"])

    def test_missing_file_recorded_as_error(self):
        ctx = self._ctx(["/does/not/exist.har"])
        stage_import(ctx)
        self.assertTrue(any("import" in e for e in ctx.result.get("errors", [])))

    def test_no_files_is_noop(self):
        ctx = self._ctx([])
        stage_import(ctx)
        self.assertNotIn("imported_sources", ctx.result)

    def test_multiple_files(self):
        har = _write(".har", json.dumps(_HAR))
        xml = _write(".xml", _BURP_XML)
        try:
            ctx = self._ctx([har, xml])
            stage_import(ctx)
        finally:
            os.unlink(har)
            os.unlink(xml)
        self.assertEqual(ctx.result["imported_sources"], ["har", "burp_xml"])
        self.assertIn("https://example.com/api/graphql", ctx.result["in_scope_urls"])


class TestCliImportFlag(unittest.TestCase):
    def test_repeatable_import_flag(self):
        from main import build_parser

        args = build_parser().parse_args(
            [TARGET, "--import", "a.har", "--import", "b.xml"]
        )
        self.assertEqual(args.import_files, ["a.har", "b.xml"])

    def test_default_is_none(self):
        from main import build_parser

        args = build_parser().parse_args([TARGET])
        self.assertIsNone(args.import_files)


if __name__ == "__main__":
    unittest.main()
