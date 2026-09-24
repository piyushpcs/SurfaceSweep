"""
Phase 4 Step 8 — integration tests.

Runs the full pipeline offline by mocking network leaf functions
(run_extractor, detect_waf, scan_cors, ...). Stage functions themselves
stay real so merge/risk/meta/report wiring is exercised end-to-end.
"""

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

import requests

from modules.pipeline import build_stages, run_pipeline, stage_names
from modules.pipeline import stages as stages_mod


def _args(**overrides):
    base = dict(
        target="https://example.com",
        output="reports/out.json",
        threads=6,
        depth=1,
        browser=False,
        full=False,
        validate=False,
        vt=10,
        vtimeout=5,
        timeout=30,
        scope=None,
        cookie=None,
        header=[],
        burp=False,
        zap=False,
        wayback=False,
        waf=False,
        cve=False,
        osv=False,
        spa=False,
        max_routes=50,
        no_probe=False,
        html=False,
        html_only=False,
        no_deobf=False,
        regex_only=False,
        cors=False,
        cors_origin=None,
        cors_max=50,
        cors_rps=5.0,
        cors_threads=6,
        cors_timeout=5.0,
        jwt=False,
        jwt_wordlist=None,
        jwt_hashcat=None,
        jwt_export=None,
        jwt_network=False,
        jwt_network_timeout=5.0,
        quiet=True,
    )
    base.update(overrides)
    return Namespace(**base)


def _fixture_result(**overrides):
    """Synthetic scan result exercising every findings module."""
    result = {
        "target": "https://example.com",
        "scan_mode": "static",
        "scan_depth": 1,
        "js_files_scanned": ["https://example.com/app.js"],
        "inline_scripts_scanned": 2,
        "internal_paths": ["/api/users", "/login"],
        "in_scope_urls": ["https://example.com/api/v2"],
        "out_of_scope_urls": [],
        "secrets_found": [
            {"type": "aws_key", "match": "AKIAEXAMPLE", "sources": ["app.js"]},
        ],
        "jwts_found": [],
        "source_maps_found": ["https://example.com/app.js.map"],
        "deobfuscation_findings": [],
        "sinks_found": [
            {"sink": "innerHTML", "severity": "HIGH", "description": "XSS",
             "count": 3, "sources": ["app.js"]},
        ],
        "internal_hosts_found": [
            {"kind": "private_ip", "match": "10.0.0.5", "source": "app.js"},
        ],
        "errors": [],
        "library_vulnerabilities": [
            {"library": "jQuery", "version": "1.6.3", "cves": ["CVE-2011-4969"],
             "severity": "CRITICAL", "description": "XSS", "source_file": "app.js"},
        ],
        "libraries": [
            {"library": "jQuery", "version": "1.6.3", "source": "filename",
             "file": "app.js"},
        ],
        "intercepted_endpoints": [
            {"url": "https://example.com/api/xhr", "method": "POST"},
        ],
    }
    result.update(overrides)
    result.setdefault("risk_summary", {"level": "HIGH", "score": 0})
    return result


_CORS_RESULT = {
    "schema_version": 1,
    "findings": [{
        "severity": "CRITICAL",
        "url": "https://example.com/api/users",
        "origin": "https://evil.com",
        "origins_flagged": ["https://evil.com"],
        "acao": "*",
        "acac": "true",
        "method": "GET",
        "detail": "arbitrary origin reflected with credentials",
        "evidence": "ACAO: *; ACAC: true",
    }],
    "severity_counts": {"CRITICAL": 1},
    "endpoints_tested": 5,
    "target_origin": "https://example.com",
    "summary": {"urls_flagged": 1, "severity_counts": {"CRITICAL": 1}},
}

_JWT_RESULT = {
    "schema_version": 1,
    "tokens_analyzed": 1,
    "findings": [{
        "severity": "CRITICAL",
        "alg": "none",
        "source": "app.js",
        "payload_summary": {"sub": "admin"},
        "findings": [{"severity": "CRITICAL", "issue": "alg none",
                      "detail": "unsigned token accepted"}],
    }],
    "severity_counts": {"CRITICAL": 1},
    "summary": {"tokens_analyzed": 1, "severity_counts": {"CRITICAL": 1}},
}

_WAYBACK_RESULT = {
    "js_files": ["https://example.com/old.js"],
    "endpoints": {"/api/historical", "https://example.com/api/abs",
                  "https://evil.com/x", "/style.css"},
    "secrets": [{"type": "generic_key", "match": "WBKEY1234567890",
                 "source": "old.js"}],
    "sinks": [],
    "internal_hosts": [],
    "jwts": [],
    "errors": ["wayback snapshot missing"],
}


def _fake_waf(url, **kwargs):
    return {
        "detected": True,
        "waf_name": "Cloudflare",
        "headers_matched": [{"header": "server", "value": "cloudflare",
                             "waf": "Cloudflare"}],
        "confidence": "high",
    }


def _fake_wayback(domain, **kwargs):
    return dict(_WAYBACK_RESULT, endpoints=set(_WAYBACK_RESULT["endpoints"]))


def _fake_libs(js_files, **kwargs):
    return {
        "libraries": [{"library": "jQuery", "version": "1.6.3",
                       "source": "filename", "file": "app.js"}],
        "vulnerabilities": [{
            "library": "jQuery", "version": "1.6.3",
            "cves": ["CVE-2011-4969"], "severity": "CRITICAL",
            "description": "XSS", "source_file": "app.js",
        }],
        "osv_results": [],
    }


def _fake_spa(base_url, **kwargs):
    return {
        "routes": ["/dashboard"],
        "routes_from": {"/dashboard": "static"},
        "api_endpoints": ["https://example.com/api/spa"],
    }


def _fake_validate(urls, base_url, **kwargs):
    base = "https://example.com"
    live, dead = [], []
    for u in urls:
        full = f"{base}{u}" if u.startswith("/") else u
        if not full.startswith(base) or "style" in full:
            continue
        if u == "/login":
            dead.append({"url": full, "status_code": 404, "status": "dead"})
        else:
            live.append({"url": full, "status_code": 200, "status": "live"})
    return {
        "live": live,
        "restricted": [],
        "dead": dead,
        "server_error": [],
        "timeout": [],
        "connection_error": [],
        "error": [],
        "redirect": [],
        "unknown": [],
    }


def _offline_patches():
    """Leaf functions stages call — patch these, keep stages real."""
    return {
        "run_extractor": lambda *a, **k: _fixture_result(),
        "run_browser_scan": lambda *a, **k: _fixture_result(scan_mode="browser"),
        "detect_waf": _fake_waf,
        "get_wayback_endpoints": _fake_wayback,
        "scan_for_libraries": _fake_libs,
        "crawl_spa_routes": _fake_spa,
        "scan_cors": lambda *a, **k: dict(_CORS_RESULT),
        "analyze_result_jwts": lambda *a, **k: dict(_JWT_RESULT),
        "validate_endpoints": _fake_validate,
    }


def _run_offline(args, headers=None, extra_patches=None):
    """Run run_pipeline fully offline (network leaves mocked)."""
    patches = _offline_patches()
    if extra_patches:
        patches.update(extra_patches)
    with mock.patch.multiple(stages_mod, **patches), \
         mock.patch("requests.get",
                    side_effect=requests.exceptions.ConnectionError("offline")):
        return run_pipeline(args, verbose=False, headers=headers)


class TestPipelineEndToEnd(unittest.TestCase):
    """Full offline pipeline: stage order + schema contract on returned dict."""

    def test_minimal_scan_returns_schema(self):
        result = _run_offline(_args(output="reports/it_min.json"))
        self.assertEqual(result["schema_version"], 1)
        meta = result["meta"]
        self.assertEqual(meta["tool"], "SurfaceSweep")
        self.assertEqual(meta["scan_mode"], "static")
        self.assertIn("scan", meta["stages_run"])
        self.assertIn("report", meta["stages_run"])
        self.assertIn("scan", meta["stage_timings"])
        self.assertIsInstance(meta["duration_seconds"], float)
        self.assertIsInstance(result["findings"], list)
        self.assertIn("executive_summary", result)

    def test_all_flags_stage_order(self):
        result = _run_offline(_args(
            output="reports/it_all.json",
            waf=True, wayback=True, full=True, cve=True, spa=True,
            cors=True, jwt=True, validate=True, burp=True, zap=True, html=True,
        ))
        expected = [
            "waf_detect", "wayback_fetch", "scan", "wayback_merge",
            "waf_inject", "cve", "spa", "jwt", "validate", "cors",
            "export", "report",
        ]
        self.assertEqual(result["meta"]["stages_run"], expected)
        self.assertEqual(sorted(result["meta"]["stage_timings"]), sorted(expected))

    def test_flags_recorded_in_meta(self):
        result = _run_offline(_args(
            cors=True, jwt=True, waf=True, wayback=True, burp=True,
        ))
        flags = result["meta"]["flags"]
        for f in ("cors", "jwt", "waf", "wayback", "burp"):
            self.assertIn(f, flags)

    def test_wayback_merge_applied(self):
        result = _run_offline(_args(wayback=True))
        self.assertIn("/api/historical", result["internal_paths"])
        self.assertIn("https://example.com/api/abs", result["in_scope_urls"])
        self.assertNotIn("https://evil.com/x", result["in_scope_urls"])
        self.assertNotIn("/style.css", result["internal_paths"])
        self.assertEqual(result["wayback_js_files"],
                         ["https://example.com/old.js"])
        self.assertIn("wayback snapshot missing", result["errors"])
        matches = {s.get("match") for s in result["secrets_found"]}
        self.assertIn("WBKEY1234567890", matches)

    def test_waf_inject_stored_with_adjustments(self):
        result = _run_offline(_args(waf=True))
        waf = result["waf"]
        self.assertTrue(waf["detected"])
        self.assertEqual(waf["waf_name"], "Cloudflare")
        self.assertIn("adjustments", waf)
        self.assertIn("recommendation", waf["adjustments"])

    def test_findings_feed_cross_module(self):
        result = _run_offline(_args(cors=True, jwt=True, waf=True, cve=True))
        feed = result["findings"]
        modules = {f["module"] for f in feed}
        for m in ("secrets", "sinks", "cve", "cors", "jwt", "source_maps"):
            self.assertIn(m, modules, f"missing {m} in findings feed")
        self.assertEqual(feed[0]["severity"], "CRITICAL")

    def test_executive_summary_counts(self):
        result = _run_offline(_args(cors=True, jwt=True))
        s = result["executive_summary"]
        self.assertGreaterEqual(s["total_findings"], 3)
        self.assertIn("CRITICAL", s["severity_counts"])
        self.assertEqual(s["risk_level"], result["risk_summary"]["level"])
        self.assertTrue(s["top_findings"])
        self.assertLessEqual(len(s["top_findings"]), 5)

    def test_cve_boost_preserved_after_validate_recalc(self):
        """CVE boost must survive stage_validate's calculate_risk_summary."""
        result = _run_offline(_args(cve=True, validate=True))
        from modules.extraction.risk import calculate_risk_summary
        expected = calculate_risk_summary(result)["score"]
        self.assertEqual(result["risk_summary"]["score"], expected)
        # CRITICAL CVE alone is +25
        self.assertGreaterEqual(result["risk_summary"]["score"], 25)

    def test_validate_filters_dead_paths(self):
        result = _run_offline(_args(validate=True))
        self.assertNotIn("/login", result["internal_paths"])
        self.assertIn("/api/users", result["internal_paths"])
        dead_urls = [d["url"] for d in result["validation"]["dead"]]
        self.assertIn("https://example.com/login", dead_urls)

    def test_spa_routes_merged(self):
        result = _run_offline(_args(spa=True))
        self.assertIn("/dashboard", result["internal_paths"])
        self.assertEqual(result["spa_routes"], ["/dashboard"])
        intercepted = {e.get("url") for e in result["intercepted_endpoints"]}
        self.assertIn("https://example.com/api/spa", intercepted)

    def test_cors_and_jwt_stages_populate_result(self):
        result = _run_offline(_args(cors=True, jwt=True))
        self.assertEqual(result["cors"]["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(result["jwt"]["tokens_analyzed"], 1)


class TestReportOutputsOnDisk(unittest.TestCase):
    """write_reports + pipeline report stage produce valid on-disk artifacts."""

    def test_json_contains_full_contract(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "scan.json")
            _run_offline(_args(output=out, html=True, burp=True, zap=True))
            path = Path(out)
            self.assertTrue(path.is_file())
            data = json.loads(path.read_text())
            self.assertEqual(data["schema_version"], 1)
            self.assertIn("meta", data)
            self.assertIn("findings", data)
            self.assertIn("executive_summary", data)
            self.assertEqual(data["meta"]["tool"], "SurfaceSweep")
            self.assertTrue((Path(td) / "scan.html").is_file())
            self.assertTrue((Path(td) / "scan_burp.csv").is_file())
            self.assertTrue((Path(td) / "scan_zap.csv").is_file())

    def test_html_contains_required_sections(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "scan.json")
            _run_offline(_args(
                output=out, html=True,
                waf=True, wayback=True, cors=True, jwt=True,
            ))
            html = (Path(td) / "scan.html").read_text()
            for section in (
                "Executive Summary",
                "All Findings",
                "WAF Detection",
                "Wayback Machine Historical JS",
                "CORS Misconfigurations",
                "JWT Analysis",
                "Internal Paths",
                "Secrets / Leaked Keys",
                "badge-critical",
                "Mode: static",
            ):
                self.assertIn(section, html, f"missing: {section}")
            self.assertNotIn("<script>alert", html)

    def test_burp_csv_headers(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "scan.json")
            _run_offline(_args(output=out, burp=True))
            csv_text = (Path(td) / "scan_burp.csv").read_text()
            lines = csv_text.strip().splitlines()
            self.assertEqual(lines[0], "Host,Protocol,Path,Query")
            self.assertGreater(len(lines), 1)

    def test_zap_csv_headers(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "scan.json")
            _run_offline(_args(output=out, zap=True))
            csv_text = (Path(td) / "scan_zap.csv").read_text()
            lines = csv_text.strip().splitlines()
            self.assertEqual(lines[0], "URL,Method,Data,Payload")
            self.assertGreater(len(lines), 1)

    def test_html_only_skips_json(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "scan.json")
            _run_offline(_args(output=out, html_only=True))
            self.assertFalse((Path(td) / "scan.json").exists())
            self.assertTrue((Path(td) / "scan.html").is_file())

    def test_nested_output_dir_created(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "a" / "b" / "scan.json")
            _run_offline(_args(output=out, html=True))
            self.assertTrue((Path(td) / "a" / "b" / "scan.json").is_file())
            self.assertTrue((Path(td) / "a" / "b" / "scan.html").is_file())


class TestStageListConsistency(unittest.TestCase):
    """stage_names / build_stages stay in sync with _STAGE_SPECS."""

    def test_every_spec_has_callable(self):
        for name, fn in build_stages(_args(
            waf=True, wayback=True, cve=True, spa=True, cors=True,
            jwt=True, validate=True, burp=True, zap=True,
        )):
            self.assertTrue(callable(fn), name)

    def test_default_is_scan_then_report(self):
        self.assertEqual(stage_names(_args()), ["scan", "report"])

    def test_export_requires_burp_or_zap(self):
        self.assertNotIn("export", stage_names(_args()))
        self.assertIn("export", stage_names(_args(burp=True)))
        self.assertIn("export", stage_names(_args(zap=True)))


if __name__ == "__main__":
    unittest.main()
