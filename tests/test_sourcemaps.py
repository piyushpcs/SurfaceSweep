"""Unit tests for Phase 1.1 Step 3 — source map deep parsing and reconstruction."""

import base64
import json
import unittest
from unittest import mock

from modules.extraction.sourcemaps import (
    MAX_SOURCEMAP_SOURCES,
    MAX_SOURCEMAP_SOURCE_BYTES,
    collect_source_map_sources,
    decode_inline_sourcemap,
    load_source_map,
    parse_source_mapping_url,
    resolve_source_map_url,
)


_JS_URL = "https://cdn.example.com/static/app.js"
_MAP_OBJ = {
    "version": 3,
    "sources": ["webpack:///src/api.ts", "webpack:///src/util.ts"],
    "sourcesContent": [
        'fetch("/api/v1/users");\nconst api_key = "aB3xY9mN2pQ7rS5tU8vW1xY4zA6bC9dE";',
        'export const helper = () => axios.get("/api/v1/health");',
    ],
}


def _inline_map_data_url(map_obj):
    raw = json.dumps(map_obj).encode("utf-8")
    return "data:application/json;base64," + base64.b64encode(raw).decode("ascii")


class TestParseSourceMappingUrl(unittest.TestCase):
    def test_absent_returns_none(self):
        self.assertIsNone(parse_source_mapping_url("var a = 1;"))
        self.assertIsNone(parse_source_mapping_url(""))
        self.assertIsNone(parse_source_mapping_url(None))

    def test_simple_comment(self):
        js = "var a=1;\n//# sourceMappingURL=app.js.map"
        self.assertEqual(parse_source_mapping_url(js), "app.js.map")

    def test_quoted_and_alt_syntax(self):
        js = '/*@ sourceMappingURL="static/js/main.chunk.js.map" */'
        self.assertEqual(parse_source_mapping_url(js), "static/js/main.chunk.js.map")

    def test_last_comment_wins(self):
        js = (
            "//# sourceMappingURL=first.map\n"
            "var x=1;\n"
            "//# sourceMappingURL=second.map"
        )
        self.assertEqual(parse_source_mapping_url(js), "second.map")

    def test_inline_data_uri(self):
        data = _inline_map_data_url(_MAP_OBJ)
        js = f"//# sourceMappingURL={data}"
        self.assertEqual(parse_source_mapping_url(js), data)


class TestResolveAndDecode(unittest.TestCase):
    def test_relative_resolves_against_js(self):
        self.assertEqual(
            resolve_source_map_url("app.js.map", _JS_URL),
            "https://cdn.example.com/static/app.js.map",
        )

    def test_absolute_unchanged(self):
        url = "https://maps.example.com/app.js.map"
        self.assertEqual(resolve_source_map_url(url, _JS_URL), url)

    def test_data_uri_passthrough(self):
        data = "data:application/json;base64,e30="
        self.assertEqual(resolve_source_map_url(data, _JS_URL), data)

    def test_decode_base64_inline(self):
        data = _inline_map_data_url(_MAP_OBJ)
        obj = decode_inline_sourcemap(data)
        self.assertIsNotNone(obj)
        self.assertEqual(obj["sources"], _MAP_OBJ["sources"])

    def test_decode_urlencoded_inline(self):
        payload = json.dumps({"version": 3, "sources": [], "sourcesContent": []})
        from urllib.parse import quote
        data = "data:application/json," + quote(payload, safe="")
        obj = decode_inline_sourcemap(data)
        self.assertIsNotNone(obj)
        self.assertEqual(obj["version"], 3)

    def test_decode_invalid_returns_none(self):
        self.assertIsNone(decode_inline_sourcemap("data:application/json;base64,!!!"))
        self.assertIsNone(decode_inline_sourcemap("not-a-data-uri"))
        self.assertIsNone(decode_inline_sourcemap(None))


class TestCollectSources(unittest.TestCase):
    def test_pairs_sources_with_content(self):
        out = collect_source_map_sources(_MAP_OBJ, _JS_URL)
        self.assertEqual(len(out), 2)
        label, content = out[0]
        self.assertTrue(label.startswith(_JS_URL + "!"))
        self.assertIn("api_key", content)

    def test_null_content_skipped(self):
        obj = {"sources": ["a.ts", "b.ts"], "sourcesContent": [None, "code()"]}
        out = collect_source_map_sources(obj, _JS_URL)
        self.assertEqual(len(out), 1)
        self.assertIn("b.ts", out[0][0])

    def test_source_count_cap(self):
        obj = {
            "sources": [f"s{i}.ts" for i in range(MAX_SOURCEMAP_SOURCES + 10)],
            "sourcesContent": ["x" * 10 for _ in range(MAX_SOURCEMAP_SOURCES + 10)],
        }
        out = collect_source_map_sources(obj, _JS_URL)
        self.assertEqual(len(out), MAX_SOURCEMAP_SOURCES)

    def test_per_source_byte_cap(self):
        huge = "A" * (MAX_SOURCEMAP_SOURCE_BYTES + 100)
        obj = {"sources": ["big.ts"], "sourcesContent": [huge]}
        out = collect_source_map_sources(obj, _JS_URL)
        self.assertEqual(len(out[0][1]), MAX_SOURCEMAP_SOURCE_BYTES)

    def test_invalid_map(self):
        self.assertEqual(collect_source_map_sources(None, _JS_URL), [])
        self.assertEqual(collect_source_map_sources({}, _JS_URL), [])
        self.assertEqual(
            collect_source_map_sources({"sourcesContent": "nope"}, _JS_URL),
            [],
        )


class TestLoadSourceMap(unittest.TestCase):
    def test_inline_from_comment(self):
        data = _inline_map_data_url(_MAP_OBJ)
        js = f"var x=1;\n//# sourceMappingURL={data}"
        obj, report = load_source_map(_JS_URL, js)
        self.assertIsNotNone(obj)
        self.assertEqual(report, f"{_JS_URL}#inline-sourcemap")
        self.assertEqual(obj["version"], 3)

    @mock.patch("modules.extraction.sourcemaps.fetch_with_retry")
    def test_external_from_comment(self, fetch_mock):
        resp = mock.Mock(status_code=200, content=json.dumps(_MAP_OBJ).encode("utf-8"),
                         headers={"Content-Type": "application/json"})
        fetch_mock.return_value = resp
        js = "//# sourceMappingURL=../maps/app.js.map"
        obj, report = load_source_map(_JS_URL, js)
        self.assertIsNotNone(obj)
        self.assertEqual(report, "https://cdn.example.com/maps/app.js.map")
        fetch_mock.assert_called_once()
        self.assertEqual(
            fetch_mock.call_args.args[0],
            "https://cdn.example.com/maps/app.js.map",
        )

    @mock.patch("modules.extraction.sourcemaps.fetch_with_retry")
    def test_conventional_map_fallback(self, fetch_mock):
        resp = mock.Mock(status_code=200, content=json.dumps(_MAP_OBJ).encode("utf-8"),
                         headers={"Content-Type": "application/json"})
        fetch_mock.return_value = resp
        obj, report = load_source_map(_JS_URL, "var x=1;")
        self.assertIsNotNone(obj)
        self.assertEqual(report, _JS_URL + ".map")
        fetch_mock.assert_called_once_with(_JS_URL + ".map", timeout=8, limiter=None)

    @mock.patch("modules.extraction.sourcemaps.fetch_with_retry")
    def test_missing_map_returns_none(self, fetch_mock):
        fetch_mock.return_value = None
        obj, report = load_source_map(_JS_URL, "var x=1;")
        self.assertIsNone(obj)
        self.assertIsNone(report)

    @mock.patch("modules.extraction.sourcemaps.fetch_with_retry")
    def test_non_json_body_rejected(self, fetch_mock):
        resp = mock.Mock(
            status_code=200,
            content=b"<html>nope</html>",
            headers={"Content-Type": "text/html"},
        )
        fetch_mock.return_value = resp
        obj, _ = load_source_map(_JS_URL, None)
        self.assertIsNone(obj)

    @mock.patch("modules.extraction.sourcemaps.fetch_with_retry")
    def test_oversized_map_rejected(self, fetch_mock):
        from modules.extraction.sourcemaps import MAX_SOURCEMAP_BYTES
        resp = mock.Mock(
            status_code=200,
            content=b"{" + b"a" * MAX_SOURCEMAP_BYTES,
            headers={"Content-Type": "application/json"},
        )
        fetch_mock.return_value = resp
        obj, _ = load_source_map(_JS_URL, None)
        self.assertIsNone(obj)


class TestFetchAndExtractUsesSourceMap(unittest.TestCase):
    """fetch_and_extract rescans sourcesContent and reports the map URL."""

    @mock.patch("modules.extraction.engine.load_source_map")
    @mock.patch("modules.extraction.engine.fetch_with_retry")
    def test_original_source_secrets_and_endpoints(self, fetch_mock, load_mock):
        from modules.extraction.engine import fetch_and_extract

        js_body = 'fetch("/api/bundle-only");\n//# sourceMappingURL=app.js.map'
        resp = mock.Mock(
            status_code=200,
            text=js_body,
            headers={"Content-Type": "application/javascript"},
        )
        fetch_mock.return_value = resp
        map_obj = {
            "version": 3,
            "sources": ["webpack:///src/api.ts", "webpack:///src/util.ts"],
            "sourcesContent": [
                'fetch("/api/v1/users");\nconst cfg = { "api_key": "aB3xY9mN2pQ7rS5tU8vW1xY4zA6bC9dE" };',
                'export const helper = () => axios.get("/api/v1/health");',
            ],
        }
        load_mock.return_value = (
            map_obj,
            "https://cdn.example.com/static/app.js.map",
        )

        data = fetch_and_extract(_JS_URL, use_ast=False)
        self.assertEqual(data["source_map_found"], "https://cdn.example.com/static/app.js.map")
        self.assertIn("/api/bundle-only", data["endpoints"])
        self.assertIn("/api/v1/users", data["endpoints"])
        self.assertIn("/api/v1/health", data["endpoints"])
        self.assertTrue(any(s["type"] == "Generic API Key" for s in data["secrets"]))


if __name__ == "__main__":
    unittest.main()
