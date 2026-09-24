"""Unit tests for endpoint URL patterns (Phase C6)."""

import unittest

from modules.extraction.engine import extract_from_text
from modules.extraction.patterns import (
    FULL_URL_PATTERN,
    PROTOCOL_RELATIVE_URL_PATTERN,
    WS_URL_PATTERN,
)


class TestWsPatterns(unittest.TestCase):
    def test_wss_matched(self):
        self.assertEqual(
            WS_URL_PATTERN.findall('var u = "wss://ws.example.com/socket.io/?EIO=4";'),
            ["wss://ws.example.com/socket.io/?EIO=4"],
        )

    def test_ws_matched(self):
        self.assertEqual(
            WS_URL_PATTERN.findall("connect('ws://127.0.0.1:8080/ws')"),
            ["ws://127.0.0.1:8080/ws"],
        )

    def test_http_not_matched_by_ws_pattern(self):
        self.assertEqual(WS_URL_PATTERN.findall('https://example.com/api'), [])


class TestProtocolRelative(unittest.TestCase):
    def test_quoted_protocol_relative(self):
        self.assertEqual(
            PROTOCOL_RELATIVE_URL_PATTERN.findall('cdn = "//cdn.example.com/lib.js"'),
            ["//cdn.example.com/lib.js"],
        )

    def test_js_comment_not_matched(self):
        # Line comments must not be treated as protocol-relative URLs
        self.assertEqual(
            PROTOCOL_RELATIVE_URL_PATTERN.findall("// just a comment\nvar x = 1;"),
            [],
        )

    def test_single_quotes(self):
        self.assertEqual(
            PROTOCOL_RELATIVE_URL_PATTERN.findall("base = '//api.example.com/v1'"),
            ["//api.example.com/v1"],
        )


class TestExtractFromText(unittest.TestCase):
    def test_wss_endpoint_extracted(self):
        endpoints, *_ = extract_from_text(
            'const sock = new WebSocket("wss://ws.example.com/live");',
            "unit.js",
            do_deobfuscate=False,
            use_ast=False,
        )
        self.assertIn("wss://ws.example.com/live", endpoints)

    def test_protocol_relative_normalized_to_https(self):
        endpoints, *_ = extract_from_text(
            'const u = "//api.example.com/v1/users";',
            "unit.js",
            do_deobfuscate=False,
            use_ast=False,
        )
        self.assertIn("https://api.example.com/v1/users", endpoints)
        self.assertNotIn("//api.example.com/v1/users", endpoints)

    def test_full_https_still_extracted(self):
        endpoints, *_ = extract_from_text(
            'fetch("https://api.example.com/health");',
            "unit.js",
            do_deobfuscate=False,
            use_ast=False,
        )
        self.assertTrue(any("https://api.example.com/health" in e for e in endpoints))

    def test_ws_tagged_websocket_via_enrich(self):
        from modules.extraction.enrich import endpoint_tags

        self.assertIn("websocket", endpoint_tags("wss://ws.example.com/socket.io/?EIO=4"))


if __name__ == "__main__":
    unittest.main()
