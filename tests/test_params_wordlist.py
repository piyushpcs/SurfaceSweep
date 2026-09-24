"""Phase F1 — parameter extraction and path/parameter wordlist export."""

import os
import tempfile
import unittest
from argparse import Namespace

from main import build_parser
from modules.extraction.params import (
    deduplicate_params,
    extract_params,
)
from modules.reporting.builder import build_report_plan, output_paths, write_reports
from modules.reporting.export import build_wordlist, export_wordlist


class TestQueryParamExtraction(unittest.TestCase):
    def test_query_string_on_path(self):
        found = extract_params('fetch("/api/users?id=1&role=admin");', "app.js")
        names = {(p["name"], p["kind"]) for p in found}
        self.assertIn(("id", "query_string"), names)
        self.assertIn(("role", "query_string"), names)

    def test_query_string_on_absolute_url(self):
        found = extract_params(
            'const u = "https://api.test/v1/items?page=2&limit=50";', "app.js"
        )
        names = {p["name"] for p in found if p["kind"] == "query_string"}
        self.assertIn("page", names)
        self.assertIn("limit", names)

    def test_source_label_recorded(self):
        found = extract_params('x = "/a?foo=bar";', "inline_0")
        self.assertTrue(all(p["source"] == "inline_0" for p in found))


class TestUrlSearchParamsExtraction(unittest.TestCase):
    def test_urlsearchparams_object_keys(self):
        js = 'const p = new URLSearchParams({ userId: 42, tab: "posts" });'
        found = extract_params(js, "app.js")
        names = {p["name"] for p in found if p["kind"] == "url_search_params"}
        self.assertIn("userId", names)
        self.assertIn("tab", names)

    def test_urlsearchparams_string(self):
        js = "const p = new URLSearchParams('q=surface&page=1');"
        found = extract_params(js, "app.js")
        names = {p["name"] for p in found if p["kind"] == "url_search_params"}
        self.assertIn("q", names)
        self.assertIn("page", names)

    def test_search_params_access(self):
        js = 'const id = searchParams.get("sessionId"); searchParams.set("debug", "1");'
        found = extract_params(js, "app.js")
        names = {p["name"] for p in found if p["kind"] == "search_params_access"}
        self.assertIn("sessionId", names)
        self.assertIn("debug", names)


class TestRequestBodyAndFormExtraction(unittest.TestCase):
    def test_axios_params_object(self):
        js = 'axios.get("/api/search", { params: { query: "x", filters: true } });'
        found = extract_params(js, "app.js")
        names = {p["name"] for p in found if p["kind"] == "request_params"}
        self.assertIn("query", names)
        self.assertIn("filters", names)

    def test_formdata_append(self):
        js = 'formData.append("avatar", file); fd.append("displayName", name);'
        found = extract_params(js, "app.js")
        names = {p["name"] for p in found if p["kind"] == "form_field"}
        self.assertIn("avatar", names)
        self.assertIn("displayName", names)


class TestPathTemplateExtraction(unittest.TestCase):
    def test_colon_param(self):
        found = extract_params('get("/api/users/:userId/profile");', "app.js")
        names = {p["name"] for p in found if p["kind"] == "path_template"}
        self.assertIn("userId", names)

    def test_template_literal_param(self):
        found = extract_params("fetch(`/api/orders/${orderId}`);", "app.js")
        names = {p["name"] for p in found if p["kind"] == "path_template"}
        self.assertIn("orderId", names)

    def test_brace_param(self):
        found = extract_params('path = "/items/{itemId}/edit";', "app.js")
        names = {p["name"] for p in found if p["kind"] == "path_template"}
        self.assertIn("itemId", names)


class TestNoiseAndDedup(unittest.TestCase):
    def test_noise_names_skipped(self):
        found = extract_params('x = { type: "a", name: "b", id: 1 };', "app.js")
        names = {p["name"] for p in found}
        self.assertNotIn("type", names)
        self.assertNotIn("name", names)

    def test_single_char_names_skipped(self):
        found = extract_params('params: { a: 1 }', "app.js")
        self.assertEqual([p for p in found if p["name"] == "a"], [])

    def test_empty_content(self):
        self.assertEqual(extract_params("", "x.js"), [])

    def test_dedup_merges_sources(self):
        raw = [
            {"name": "id", "kind": "query_string", "source": "a.js"},
            {"name": "id", "kind": "query_string", "source": "b.js"},
            {"name": "id", "kind": "path_template", "source": "a.js"},
        ]
        out = deduplicate_params(raw)
        self.assertEqual(len(out), 2)
        by_kind = {p["kind"]: p for p in out}
        self.assertEqual(by_kind["query_string"]["sources"], ["a.js", "b.js"])
        self.assertEqual(by_kind["path_template"]["sources"], ["a.js"])

    def test_dedup_empty(self):
        self.assertEqual(deduplicate_params(None), [])
        self.assertEqual(deduplicate_params([]), [])


class TestWordlistExport(unittest.TestCase):
    def _result(self):
        return {
            "target": "https://app.example.com",
            "internal_paths": ["/api/v1/users", "/api/v1/orders", "/login"],
            "in_scope_urls": ["https://app.example.com/api/v2/search"],
            "intercepted_endpoints": [
                {"url": "https://app.example.com/graphql", "method": "POST"},
            ],
            "params_found": [
                {"name": "userId", "kind": "path_template", "source": "a.js",
                 "sources": ["a.js"]},
                {"name": "page", "kind": "query_string", "source": "a.js",
                 "sources": ["a.js"]},
            ],
        }

    def test_build_wordlist_includes_paths_segments_and_params(self):
        words = build_wordlist(self._result())
        self.assertIn("/api/v1/users", words)
        self.assertIn("api", words)
        self.assertIn("users", words)
        self.assertIn("userId", words)
        self.assertIn("page", words)
        self.assertIn("graphql", words)
        self.assertEqual(words, sorted(set(words)))

    def test_export_wordlist_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wl.txt")
            self.assertTrue(export_wordlist(self._result(), path))
            with open(path) as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
            self.assertIn("/login", lines)
            self.assertIn("userId", lines)

    def test_output_paths_include_wordlist(self):
        self.assertEqual(
            output_paths("reports/scan.json")["wordlist"],
            "reports/scan_wordlist.txt",
        )


class TestReportPlanAndCli(unittest.TestCase):
    def _ns(self, **kw):
        base = dict(
            html=False, html_only=False, burp=False, zap=False,
            cors_poc=False, sarif=False, wordlist=None,
        )
        base.update(kw)
        return Namespace(**base)

    def test_wordlist_off_by_default(self):
        plan = build_report_plan(self._ns())
        self.assertFalse(plan["write_wordlist"])
        self.assertIsNone(plan["wordlist_path"])

    def test_bare_wordlist_uses_sibling_path(self):
        plan = build_report_plan(self._ns(wordlist="__default__"))
        self.assertTrue(plan["write_wordlist"])
        self.assertIsNone(plan["wordlist_path"])

    def test_explicit_wordlist_path(self):
        plan = build_report_plan(self._ns(wordlist="/tmp/wl.txt"))
        self.assertTrue(plan["write_wordlist"])
        self.assertEqual(plan["wordlist_path"], "/tmp/wl.txt")

    def test_parser_wordlist_flag(self):
        args = build_parser().parse_args(["https://x.test", "--wordlist"])
        self.assertEqual(args.wordlist, "__default__")

    def test_parser_wordlist_with_path(self):
        args = build_parser().parse_args(
            ["https://x.test", "--wordlist", "/tmp/out.txt"]
        )
        self.assertEqual(args.wordlist, "/tmp/out.txt")

    def test_parser_wordlist_default_none(self):
        args = build_parser().parse_args(["https://x.test"])
        self.assertIsNone(args.wordlist)

    def test_write_reports_wordlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "scan.json")
            written = write_reports(
                self._result_for_write(), out,
                write_json=False, write_wordlist=True, verbose=False,
            )
            self.assertTrue(written["wordlist"])
            self.assertTrue(os.path.isfile(written["wordlist"]))

    @staticmethod
    def _result_for_write():
        return {
            "target": "https://example.com",
            "internal_paths": ["/api/test"],
            "params_found": [],
        }


if __name__ == "__main__":
    unittest.main()
