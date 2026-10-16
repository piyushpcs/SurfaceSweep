"""
Tests for the MCP stdio server wrapper (mcp_server.py).

Exercises the pure JSON-RPC dispatcher and the tool implementations, and
covers the critical invariant that stdout carries *only* protocol JSON
(progress output is redirected away).
"""

import io
import json
import unittest
from unittest import mock

import mcp_server


def _rpc(method, params=None, msg_id=1):
    msg = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _fake_result():
    return {
        "scan_mode": "static",
        "risk_summary": {"level": "medium", "score": 42},
        "js_files_scanned": ["https://example.com/a.js"],
        "internal_paths": ["/api/v1/users", "/admin"],
        "in_scope_urls": ["https://example.com/api/v1/users"],
        "secrets_found": [
            {"type": "AWS Access Key", "source": "a.js", "match": "AKIAIOSFODNN7EXAMPLE"},
        ],
        "jwts_found": [{"token": "x.y.z"}],
        "sinks_found": [{"sink": "eval", "severity": "high"}],
        "internal_hosts_found": ["internal.corp"],
        "errors": [],
    }


class TestProtocol(unittest.TestCase):
    def test_initialize(self):
        resp = mcp_server.handle_message(
            _rpc("initialize", {"protocolVersion": "2024-11-05"})
        )
        self.assertEqual(resp["id"], 1)
        self.assertEqual(resp["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(resp["result"]["serverInfo"]["name"], "surfacesweep")
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_initialize_negotiates_supported_protocol(self):
        for version in mcp_server.SUPPORTED_PROTOCOLS:
            resp = mcp_server.handle_message(
                _rpc("initialize", {"protocolVersion": version})
            )
            self.assertEqual(resp["result"]["protocolVersion"], version)

    def test_initialize_unknown_protocol_falls_back(self):
        resp = mcp_server.handle_message(
            _rpc("initialize", {"protocolVersion": "1999-01-01"})
        )
        self.assertEqual(resp["result"]["protocolVersion"], mcp_server.DEFAULT_PROTOCOL)

    def test_initialized_notification_has_no_response(self):
        self.assertIsNone(
            mcp_server.handle_message(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )
        )

    def test_ping(self):
        resp = mcp_server.handle_message(_rpc("ping"))
        self.assertEqual(resp["result"], {})

    def test_tools_list(self):
        resp = mcp_server.handle_message(_rpc("tools/list"))
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        self.assertIn("scan_url", tools)
        self.assertIn("check_scope", tools)
        for tool in tools.values():
            self.assertEqual(tool["inputSchema"]["type"], "object")
            self.assertTrue(tool["description"])
        self.assertEqual(tools["scan_url"]["inputSchema"]["required"], ["target"])

    def test_unknown_method(self):
        resp = mcp_server.handle_message(_rpc("does/not/exist"))
        self.assertEqual(resp["error"]["code"], -32601)

    def test_unknown_tool(self):
        resp = mcp_server.handle_message(
            _rpc("tools/call", {"name": "bogus", "arguments": {}})
        )
        self.assertEqual(resp["error"]["code"], -32602)

    def test_invalid_request(self):
        resp = mcp_server.handle_message("not a dict")
        self.assertEqual(resp["error"]["code"], -32600)

    def test_response_message_ignored(self):
        self.assertIsNone(
            mcp_server.handle_message({"jsonrpc": "2.0", "id": 1, "result": {}})
        )


class TestCheckScope(unittest.TestCase):
    def _call(self, arguments):
        return mcp_server.handle_message(
            _rpc("tools/call", {"name": "check_scope", "arguments": arguments})
        )

    def test_in_scope(self):
        resp = self._call({"url": "https://app.example.com/x", "scope": "example.com"})
        self.assertFalse(resp["result"]["isError"])
        data = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(data["in_scope"])
        self.assertEqual(data["url_domain"], "example.com")

    def test_out_of_scope(self):
        resp = self._call({"url": "https://evil.test/x", "scope": "example.com"})
        data = json.loads(resp["result"]["content"][0]["text"])
        self.assertFalse(data["in_scope"])

    def test_missing_args_is_error(self):
        resp = self._call({})
        self.assertTrue(resp["result"]["isError"])


class TestScanUrl(unittest.TestCase):
    def _call(self, arguments):
        return mcp_server.handle_message(
            _rpc("tools/call", {"name": "scan_url", "arguments": arguments})
        )

    def _summary(self, arguments, fake=None, side_effect=None):
        fake = fake or _fake_result()
        with mock.patch(
            "modules.extraction.engine.run_extractor",
            side_effect=side_effect or (lambda *a, **k: fake),
        ):
            resp = self._call(arguments)
        return resp, json.loads(resp["result"]["content"][0]["text"])

    def test_summary_shape(self):
        resp, data = self._summary({"target": "https://example.com"})
        self.assertFalse(resp["result"]["isError"])
        self.assertEqual(data["scan_mode"], "static")
        self.assertEqual(data["risk"], "medium")
        self.assertEqual(data["risk_score"], 42)
        self.assertEqual(
            data["counts"],
            {
                "js_files": 1,
                "internal_paths": 2,
                "in_scope_urls": 1,
                "secrets": 1,
                "jwts": 1,
                "sinks": 1,
                "internal_hosts": 1,
            },
        )

    def test_secrets_redacted_by_default(self):
        _, data = self._summary({"target": "https://example.com"})
        self.assertEqual(data["secrets"][0]["match"], "AKIA…")

    def test_secrets_revealed_on_request(self):
        _, data = self._summary({"target": "https://example.com", "reveal_secrets": True})
        self.assertEqual(data["secrets"][0]["match"], "AKIAIOSFODNN7EXAMPLE")

    def test_limit_truncates_lists(self):
        fake = _fake_result()
        fake["internal_paths"] = [f"/p/{i}" for i in range(50)]
        _, data = self._summary({"target": "https://example.com", "limit": 5}, fake=fake)
        self.assertEqual(len(data["endpoints"]), 5)

    def test_non_http_target_rejected(self):
        resp = self._call({"target": "ftp://example.com/x"})
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("http", resp["result"]["content"][0]["text"])

    def test_missing_target_rejected(self):
        resp = self._call({})
        self.assertTrue(resp["result"]["isError"])

    def test_metadata_target_rejected(self):
        resp = self._call({"target": "http://169.254.169.254/latest/meta-data/"})
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("blocked", resp["result"]["content"][0]["text"])

    def test_stdout_noise_does_not_corrupt_json(self):
        # A scanner that prints to stdout must not break the JSON payload.
        def noisy(*a, **k):
            print("progress: crawling...")  # noqa: T201 - intentional noise
            return _fake_result()

        _, data = self._summary({"target": "https://example.com"}, side_effect=noisy)
        self.assertEqual(data["target"], "https://example.com")


class TestServe(unittest.TestCase):
    def test_streams_responses(self):
        stdin = io.StringIO(
            json.dumps(_rpc("initialize", {"protocolVersion": "2024-11-05"}))
            + "\n"
            + "\n"  # blank line ignored
            + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
            + "\n"
            + json.dumps(_rpc("tools/list", msg_id=2))
            + "\n"
        )
        stdout = io.StringIO()
        mcp_server.serve(stdin=stdin, stdout=stdout)

        lines = [ln for ln in stdout.getvalue().splitlines() if ln.strip()]
        # initialize + tools/list responses; the notification yields nothing.
        self.assertEqual(len(lines), 2)
        for line in lines:
            payload = json.loads(line)  # every line must be valid JSON
            self.assertEqual(payload["jsonrpc"], "2.0")

    def test_parse_error_is_reported(self):
        stdin = io.StringIO("{ not json }\n")
        stdout = io.StringIO()
        mcp_server.serve(stdin=stdin, stdout=stdout)
        payload = json.loads(stdout.getvalue().strip())
        self.assertEqual(payload["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()
