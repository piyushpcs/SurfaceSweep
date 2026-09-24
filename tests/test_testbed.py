"""E1 — offline end-to-end validation of Phase C–D extraction against testbed fixtures.

Mirrors testbed/vuln_api.py (port 5555) without requiring the Flask app to run.
"""

import json
import os
import tempfile
import unittest
from argparse import Namespace
from unittest.mock import MagicMock

from modules.extraction.engine import discover_js_chunks, extract_from_text
from modules.extraction.secrets import extract_secrets
from modules.pipeline.context import ScanContext
from modules.pipeline.stages import stage_export, stage_report
from modules.reporting.builder import output_paths


# --- fixtures lifted from testbed/vuln_api.py ---

INDEX_HTML = """
    <script src="/static/app.js"></script>
    <script>
    fetch("/api/v2/users");
    fetch("/api/v2/admin/settings");
    axios.get("/api/v2/products");
    fetch("/api/v1/public");
    fetch("/api/v2/null-cred");
    fetch("/api/v2/legit");
    fetch("/api/v2/multi-acao");
    fetch("/api/v2/path-origin");
    fetch("/rpc/post-only");
    </script>
"""

APP_JS = r'''
    var BASE_URL = "https://api.testapp.local";
    fetch(BASE_URL + "/api/v2/auth/login");
    axios.post("/api/v2/orders", {item: "test"});
    $.ajax({url: "/api/v2/search"});
    $.get("/api/v2/health");
    var adminPath = "/admin/debug/config";
    var token = "ghp_FAKE_GITHUB_TOKEN_for_testing_12345";
    var NEXT_PUBLIC_API_URL = "https://api.testapp.local/v3";
    var REACT_APP_SECRET_KEY = "value123456789";
    import("./chunk-abc123.js");
    import("./vendor.def456.js");

    var decoded = atob("L2FwaS92Mi9vYnVzY2VkL3VzZXJz");
    fetch(decoded);

    var hexPath = "\x2f\x61\x70\x69\x2f\x76\x32\x2f\x73\x65\x63\x72\x65\x74\x2d\x65\x6e\x64\x70\x6f\x69\x6e\x74";
    fetch(hexPath);

    var uniPath = "\u002f\u0061\u0070\u0069\u002f\u0076\u0032\u002f\u0075\u0073\u0065\u0072\u002d\u0070\u0072\u006f\u0066\u0069\u006c\u0065";
    fetch(uniPath);

    var ccPath = String.fromCharCode(47,97,112,105,47,118,50,47,102,114,111,109,45,99,111,117,110,116);
    fetch(ccPath);

    eval("\x66\x65\x74\x63\x68\x28\x22\x2f\x61\x70\x69\x2f\x76\x32\x2f\x65\x76\x61\x6c\x2d\x65\x6e\x64\x70\x6f\x69\x6e\x74\x22\x29");
    eval(atob("ZmV0Y2goIi9hcGkvdjIvYmFzZTY0LWVuZHBvaW50Iik="));

    var DB_URL = "postgres://admin:password123@db.internal.com:5432/myapp";
    var mail_config = { password: "smtp_secret_pass_123" };

    document.getElementById("out").innerHTML = userInput;
    setTimeout("doSomething()", 100);
    var url = "https://" + location.hash.substring(1);
    window.location.href = url;

    var devApi = "http://localhost:3000/api";
    var stage = "https://staging.testapp.local/admin";
    var backup = "https://192.168.1.50:8443/backup";
    var grafana = "http://grafana.internal.corp:3000/d/abc";

    var jwtNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.";
    var jwtWeak = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJhZG1pbiIsImV4cCI6NDEwMjQ0NDgwMH0.37v4b22djkCt_PFJq-b2KgRj-bTLlT_X5vcxZ85rVPE";
    var jwtNoExp = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0Iiwic2NvcGUiOiJhZG1pbiB3cml0ZSJ9.c2lnbmF0dXJl";
'''

CHUNK_JS = '''
    fetch("/api/v2/chunk-data");
    axios.get("/api/v2/analytics");
'''

VENDOR_JS = '''
    fetch("/api/v2/vendor-endpoint");
'''


class TestTestbedExtraction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js_eps, cls.js_secrets, cls.js_deobf, cls.js_sinks, cls.js_hosts, cls.js_jwts, cls.js_pii = (
            extract_from_text(APP_JS, "app.js")
        )
        cls.html_eps, *_ = extract_from_text(INDEX_HTML, "index.html")

    def test_inline_html_endpoints(self):
        for path in (
            "/api/v2/users", "/api/v2/admin/settings", "/api/v2/products",
            "/api/v1/public", "/api/v2/null-cred", "/api/v2/legit",
            "/api/v2/multi-acao", "/api/v2/path-origin", "/rpc/post-only",
        ):
            self.assertIn(path, self.html_eps, path)

    def test_js_endpoints_from_calls(self):
        for path in (
            "/api/v2/auth/login", "/api/v2/orders", "/api/v2/search",
            "/api/v2/health", "/admin/debug/config",
        ):
            self.assertIn(path, self.js_eps, path)

    def test_deobfuscated_endpoints(self):
        # atob / hex / unicode / fromCharCode / eval payloads decode into paths
        for path in (
            "/api/v2/obusced/users",
            "/api/v2/secret-endpoint",
            "/api/v2/user-profile",
            "/api/v2/from-count",
            "/api/v2/base64-endpoint",
            "/api/v2/eval-endpoint",
        ):
            self.assertIn(path, self.js_eps, f"missing deobf path {path}")

    def test_chunk_discovery(self):
        chunks = discover_js_chunks(APP_JS, "http://127.0.0.1:5555/static/app.js")
        self.assertIn("http://127.0.0.1:5555/static/chunk-abc123.js", chunks)
        self.assertIn("http://127.0.0.1:5555/static/vendor.def456.js", chunks)

    def test_chunk_endpoints(self):
        chunk_eps, *_ = extract_from_text(CHUNK_JS, "chunk.js")
        self.assertIn("/api/v2/chunk-data", chunk_eps)
        self.assertIn("/api/v2/analytics", chunk_eps)
        vendor_eps, *_ = extract_from_text(VENDOR_JS, "vendor.js")
        self.assertIn("/api/v2/vendor-endpoint", vendor_eps)

    def test_secrets_database_and_env(self):
        types = {s["type"] for s in self.js_secrets}
        self.assertIn("Database URL", types)
        self.assertIn("Exposed Env Var", types)

    def test_unquoted_password_bare_key(self):
        found = extract_secrets(APP_JS, "app.js")
        passwords = [s for s in found if s["type"] == "Generic Password"]
        self.assertTrue(any("smtp_secret_pass_123" in s["match"] for s in passwords),
                        f"bare password key missed: {passwords}")

    def test_sinks(self):
        sink_names = {s["sink"] for s in self.js_sinks}
        self.assertIn("innerHTML", sink_names)
        self.assertIn("eval", sink_names)
        self.assertIn("setTimeout string", sink_names)
        self.assertIn("location.hash sink", sink_names)

    def test_internal_hosts(self):
        matches = {h["match"] for h in self.js_hosts}
        self.assertIn("http://localhost:3000/api", matches)
        self.assertIn("https://192.168.1.50:8443/backup", matches)
        self.assertIn("http://grafana.internal.corp:3000/d/abc", matches)

    def test_jwts_found(self):
        self.assertEqual(len(self.js_jwts), 3)


def _minimal_result(target="http://127.0.0.1:5555"):
    return {
        "target": target,
        "internal_paths": ["/api/v2/users"],
        "secrets_found": [
            {"type": "Generic Password", "match": 'password: "smtp_secret_pass_123"',
             "severity": "MEDIUM", "sources": ["app.js"]},
        ],
        "sinks_found": [
            {"sink": "eval", "severity": "HIGH", "description": "eval()",
             "source": "app.js", "count": 1},
        ],
        "risk_summary": {"score": 40, "level": "HIGH"},
        "meta": {"finished_at": "2026-01-01T00:00:00+00:00"},
    }


def _ctx(result, args):
    ctx = MagicMock(spec=ScanContext)
    ctx.args = args
    ctx.require_result.return_value = result
    ctx.verbose = False
    ctx.log = lambda *_a, **_k: None
    return ctx


class TestSarifStageWiring(unittest.TestCase):
    """stage_report must honor --sarif; stage_export must not double-write it."""

    def _args(self, out, **flags):
        base = dict(
            output=out, html=False, html_only=False,
            burp=False, zap=False, cors_poc=False, sarif=False,
        )
        base.update(flags)
        return Namespace(**base)

    def test_stage_export_does_not_write_sarif(self):
        """SARIF is a report-stage artifact — export must not duplicate it."""
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "scan.json")
            stage_export(_ctx(_minimal_result(), self._args(out, sarif=True)))
            self.assertFalse(
                os.path.isfile(output_paths(out)["sarif"]),
                "stage_export wrote SARIF (double-export bug)",
            )

    def test_stage_report_writes_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "scan.json")
            stage_report(_ctx(_minimal_result(), self._args(out, sarif=True)))
            sarif_path = output_paths(out)["sarif"]
            self.assertTrue(os.path.isfile(sarif_path), "stage_report ignored --sarif")

    def test_sarif_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "scan.json")
            stage_report(_ctx(_minimal_result(), self._args(out)))
            self.assertFalse(os.path.isfile(output_paths(out)["sarif"]))


if __name__ == "__main__":
    unittest.main()
