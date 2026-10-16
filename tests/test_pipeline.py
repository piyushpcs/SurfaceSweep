"""Unit tests for Phase 4 Steps 1–2 — pipeline stages and merge helpers."""

import unittest
from argparse import Namespace
from unittest import mock

from datetime import datetime, timezone

from modules.extraction.risk import calculate_risk_summary
from modules.pipeline import (
    ScanContext,
    build_stages,
    collect_endpoints,
    flatten_secrets,
    merge_endpoints,
    merge_errors,
    merge_in_scope_urls,
    merge_internal_hosts,
    merge_jwts,
    merge_paths,
    merge_pii,
    merge_secrets,
    merge_sinks,
    merge_wayback,
    stage_names,
)
from modules.pipeline.runner import _stamp_meta


def _args(**overrides):
    """Minimal Namespace with every flag the stage predicates read."""
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
        cors_poc=False,
        jwt=False,
        jwt_wordlist=None,
        jwt_hashcat=None,
        jwt_export=None,
        jwt_network=False,
        jwt_network_timeout=5.0,
        graphql=False,
        graphql_timeout=5.0,
        verify_secrets=False,
        verify_secrets_timeout=5.0,
        quiet=False,
        proxy=None,
        insecure=False,
        ua=None,
        fail_on="none",
        verify_tls=True,
        wordlist=None,
        sarif=False,
    )
    base.update(overrides)
    return Namespace(**base)


class TestStageList(unittest.TestCase):
    def test_default_stages(self):
        names = stage_names(_args())
        self.assertEqual(names, ["scan", "report"])

    def test_all_flags_enabled_order(self):
        names = stage_names(_args(
            waf=True, wayback=True, full=True, cve=True, spa=True,
            cors=True, jwt=True, validate=True, burp=True, zap=True,
            graphql=True, verify_secrets=True,
        ))
        self.assertEqual(names, [
            "waf_detect", "wayback_fetch", "scan", "wayback_merge",
            "waf_inject", "cve", "spa", "jwt", "validate", "graphql",
            "verify_secrets", "cors", "export", "report",
        ])

    def test_graphql_runs_after_validate_before_cors(self):
        names = stage_names(_args(graphql=True, validate=True, cors=True))
        self.assertLess(names.index("validate"), names.index("graphql"))
        self.assertLess(names.index("graphql"), names.index("cors"))

    def test_graphql_off_by_default(self):
        self.assertNotIn("graphql", stage_names(_args()))

    def test_verify_secrets_runs_after_graphql_before_cors(self):
        names = stage_names(_args(
            verify_secrets=True, graphql=True, validate=True, cors=True,
        ))
        self.assertLess(names.index("graphql"), names.index("verify_secrets"))
        self.assertLess(names.index("verify_secrets"), names.index("cors"))

    def test_verify_secrets_off_by_default(self):
        self.assertNotIn("verify_secrets", stage_names(_args()))

    def test_cors_runs_after_validate(self):
        """Phase 2.2: CORS must probe post-validation (live endpoints only)."""
        names = stage_names(_args(cors=True, validate=True, jwt=True))
        self.assertLess(names.index("validate"), names.index("cors"))

    def test_cors_without_validate_still_after_jwt(self):
        names = stage_names(_args(cors=True, jwt=True))
        self.assertLess(names.index("jwt"), names.index("cors"))
        self.assertNotIn("validate", names)

    def test_cve_or_osv_enables_cve_stage(self):
        self.assertIn("cve", stage_names(_args(cve=True)))
        self.assertIn("cve", stage_names(_args(osv=True)))
        self.assertNotIn("cve", stage_names(_args()))

    def test_export_only_when_burp_or_zap_or_cors_poc(self):
        self.assertNotIn("export", stage_names(_args()))
        self.assertIn("export", stage_names(_args(burp=True)))
        self.assertIn("export", stage_names(_args(zap=True)))
        self.assertIn("export", stage_names(_args(cors_poc=True)))
        # SARIF/wordlist are report-stage artifacts — no separate export stage
        self.assertNotIn("export", stage_names(_args(sarif=True)))
        self.assertNotIn("export", stage_names(_args(wordlist="__default__")))

    def test_cors_poc_implies_cors_stage(self):
        """--cors-poc without --cors must still scan CORS (else no PoC data)."""
        names = stage_names(_args(cors_poc=True))
        self.assertIn("cors", names)
        self.assertIn("export", names)

    def test_scan_always_present(self):
        self.assertIn("scan", stage_names(_args()))
        self.assertIn("report", stage_names(_args()))

    def test_wayback_pair(self):
        names = stage_names(_args(wayback=True))
        self.assertEqual(names, ["wayback_fetch", "scan", "wayback_merge", "report"])

    def test_build_stages_returns_callables(self):
        for name, fn in build_stages(_args(waf=True, wayback=True, cors=True)):
            self.assertTrue(callable(fn), name)


class TestWaybackLocalSkip(unittest.TestCase):
    """stage_wayback_fetch must skip local/private hosts (archive.org is useless for them)."""

    def _ctx(self, target):
        args = _args(target=target, wayback=True)
        ctx = ScanContext(args, verbose=False)
        return ctx

    @mock.patch("modules.pipeline.stages.get_wayback_endpoints")
    def test_skips_localhost(self, wb_mock):
        from modules.pipeline.stages import stage_wayback_fetch

        ctx = self._ctx("http://127.0.0.1:5555/")
        stage_wayback_fetch(ctx)
        wb_mock.assert_not_called()
        self.assertEqual(ctx.wayback_result["js_files"], [])

    @mock.patch("modules.pipeline.stages.get_wayback_endpoints")
    def test_skips_localhost_name(self, wb_mock):
        from modules.pipeline.stages import stage_wayback_fetch

        ctx = self._ctx("http://localhost:3000/")
        stage_wayback_fetch(ctx)
        wb_mock.assert_not_called()

    @mock.patch("modules.pipeline.stages.get_wayback_endpoints")
    def test_queries_public_domain(self, wb_mock):
        from modules.pipeline.stages import stage_wayback_fetch

        wb_mock.return_value = {"js_files": [], "endpoints": set(), "secrets": [],
                                "sinks": [], "internal_hosts": [], "jwts": [],
                                "pii": [], "params": [], "errors": []}
        ctx = self._ctx("https://example.com/")
        stage_wayback_fetch(ctx)
        wb_mock.assert_called_once()
        self.assertEqual(wb_mock.call_args[0][0], "example.com")


class TestScanContext(unittest.TestCase):
    def test_require_result_before_scan_raises(self):
        ctx = ScanContext(_args(), verbose=False)
        with self.assertRaises(RuntimeError):
            ctx.require_result()

    def test_require_result_after_init(self):
        ctx = ScanContext(_args(), verbose=False)
        ctx.result = {"target": "x"}
        self.assertEqual(ctx.require_result()["target"], "x")

    def test_log_respects_verbose(self):
        ctx = ScanContext(_args(), verbose=False)
        ctx.log("should not print")  # must not raise


def _result(**overrides):
    base = {
        "target": "https://example.com",
        "internal_paths": [],
        "in_scope_urls": [],
        "secrets_found": [],
        "sinks_found": [],
        "jwts_found": [],
        "internal_hosts_found": [],
        "pii_found": [],
        "errors": [],
        "intercepted_endpoints": [],
    }
    base.update(overrides)
    return base


class TestFlattenSecrets(unittest.TestCase):
    def test_sources_list_flattened(self):
        flat = flatten_secrets([
            {"type": "aws_key", "match": "AKIA...", "sources": ["a.js", "b.js"]},
        ])
        self.assertEqual(len(flat), 2)
        self.assertEqual({s["source"] for s in flat}, {"a.js", "b.js"})

    def test_source_scalar_passthrough(self):
        flat = flatten_secrets([
            {"type": "aws_key", "match": "AKIA...", "source": "a.js"},
        ])
        self.assertEqual(flat, [{"type": "aws_key", "match": "AKIA...", "source": "a.js"}])

    def test_empty(self):
        self.assertEqual(flatten_secrets(None), [])


class TestMergeSecrets(unittest.TestCase):
    def test_dedupes_across_sources(self):
        r = _result(secrets_found=[
            {"type": "jwt_hs", "match": "tok", "sources": ["live.js"]},
        ])
        merge_secrets(r, [{"type": "jwt_hs", "match": "tok", "source": "wb.js"}])
        self.assertEqual(len(r["secrets_found"]), 1)
        self.assertEqual(r["secrets_found"][0]["sources"], ["live.js", "wb.js"])

    def test_new_secret_appended(self):
        r = _result()
        merge_secrets(r, [{"type": "aws_key", "match": "AKIA1", "source": "wb.js"}])
        self.assertEqual(len(r["secrets_found"]), 1)
        self.assertEqual(r["secrets_found"][0]["sources"], ["wb.js"])

    def test_noop_when_empty(self):
        r = _result(secrets_found=[])
        merge_secrets(r, [])
        merge_secrets(r, None)
        self.assertEqual(r["secrets_found"], [])


class TestMergeSinks(unittest.TestCase):
    def test_merges_sources_and_counts(self):
        r = _result(sinks_found=[
            {"sink": "innerHTML", "severity": "HIGH", "description": "d", "count": 2, "sources": ["a.js"]},
        ])
        merge_sinks(r, [
            {"sink": "innerHTML", "severity": "HIGH", "description": "d", "source": "wb.js"},
        ])
        self.assertEqual(len(r["sinks_found"]), 1)
        self.assertIn("a.js", r["sinks_found"][0]["sources"])
        self.assertIn("wb.js", r["sinks_found"][0]["sources"])
        self.assertGreaterEqual(r["sinks_found"][0]["count"], 2)


class TestMergeJwts(unittest.TestCase):
    def test_dedupes_by_token(self):
        r = _result(jwts_found=[{"token": "a.b.c", "source": "live.js"}])
        merge_jwts(r, [{"token": "a.b.c", "source": "wb.js"}, {"token": "d.e.f", "source": "wb.js"}])
        self.assertEqual(len(r["jwts_found"]), 2)
        tokens = {j["token"] for j in r["jwts_found"]}
        self.assertEqual(tokens, {"a.b.c", "d.e.f"})


class TestMergePii(unittest.TestCase):
    def test_dedupes_by_kind_and_match(self):
        r = _result(pii_found=[
            {"kind": "email", "match": "alice@corp-target.io",
             "severity": "INFO", "description": "d", "sources": ["live.js"]},
        ])
        merge_pii(r, [
            {"kind": "email", "match": "alice@corp-target.io",
             "severity": "INFO", "description": "d", "source": "wb.js"},
            {"kind": "phone_e164", "match": "+14155552671",
             "severity": "INFO", "description": "d", "source": "wb.js"},
        ])
        self.assertEqual(len(r["pii_found"]), 2)
        email = next(p for p in r["pii_found"] if p["kind"] == "email")
        self.assertIn("live.js", email["sources"])
        self.assertIn("wb.js", email["sources"])

    def test_noop_when_empty(self):
        r = _result(pii_found=[])
        merge_pii(r, [])
        merge_pii(r, None)
        self.assertEqual(r["pii_found"], [])


class TestMergeInternalHosts(unittest.TestCase):
    def test_first_seen_wins(self):
        r = _result(internal_hosts_found=[{"match": "10.0.0.1", "source": "a.js"}])
        merge_internal_hosts(r, [
            {"match": "10.0.0.1", "source": "wb.js"},
            {"match": "192.168.1.1", "source": "wb.js"},
        ])
        hosts = {h["match"]: h["source"] for h in r["internal_hosts_found"]}
        self.assertEqual(hosts["10.0.0.1"], "a.js")
        self.assertEqual(hosts["192.168.1.1"], "wb.js")

    def test_skips_missing_match(self):
        r = _result(internal_hosts_found=[])
        merge_internal_hosts(r, [{"source": "wb.js"}])
        self.assertEqual(r["internal_hosts_found"], [])


class TestMergeErrors(unittest.TestCase):
    def test_sorted_union(self):
        r = _result(errors=["b failed"])
        merge_errors(r, ["a failed", "b failed"])
        self.assertEqual(r["errors"], ["a failed", "b failed"])

    def test_noop(self):
        r = _result(errors=["x"])
        merge_errors(r, None)
        merge_errors(r, [])
        self.assertEqual(r["errors"], ["x"])


class TestMergePaths(unittest.TestCase):
    def test_adds_relative_paths(self):
        r = _result(internal_paths=["/a"])
        added = merge_paths(r, ["/a", "/b", "/c"])
        self.assertEqual(added, 2)
        self.assertEqual(r["internal_paths"], ["/a", "/b", "/c"])

    def test_filters_static_assets(self):
        r = _result()
        merge_paths(r, ["/app.js", "/style.css", "/api/users"])
        self.assertEqual(r["internal_paths"], ["/api/users"])

    def test_skips_protocol_relative(self):
        r = _result()
        merge_paths(r, ["//evil.com/x"])
        self.assertEqual(r["internal_paths"], [])


class TestMergeInScopeUrls(unittest.TestCase):
    def test_same_scope_only(self):
        r = _result()
        added = merge_in_scope_urls(
            r,
            [
                "https://api.example.com/users",
                "https://evil.com/steal",
                "https://other.com/x",
            ],
            "https://example.com",
        )
        self.assertEqual(added, 1)
        self.assertEqual(r["in_scope_urls"], ["https://api.example.com/users"])

    def test_static_assets_filtered(self):
        r = _result()
        merge_in_scope_urls(r, ["https://example.com/bundle.js"], "https://example.com")
        self.assertEqual(r["in_scope_urls"], [])


class TestMergeEndpoints(unittest.TestCase):
    def test_splits_paths_and_urls(self):
        r = _result()
        added = merge_endpoints(
            r,
            ["/api/a", "https://example.com/api/b", "https://evil.com/x"],
            "https://example.com",
        )
        self.assertEqual(added, 2)
        self.assertEqual(r["internal_paths"], ["/api/a"])
        self.assertEqual(r["in_scope_urls"], ["https://example.com/api/b"])


class TestCollectEndpoints(unittest.TestCase):
    def test_unions_and_sorts(self):
        r = _result(
            internal_paths=["/b", "/a"],
            in_scope_urls=["https://example.com/c"],
            intercepted_endpoints=[
                {"url": "https://example.com/d"},
                {"method": "GET"},
            ],
        )
        pool = collect_endpoints(r)
        self.assertEqual(pool, [
            "/a", "/b",
            "https://example.com/c", "https://example.com/d",
        ])

    def test_dedupes_overlap(self):
        r = _result(
            internal_paths=["/a"],
            in_scope_urls=["https://example.com/x"],
            intercepted_endpoints=[{"url": "https://example.com/x"}],
        )
        pool = collect_endpoints(r)
        self.assertEqual(len(pool), 2)


class TestMergeWayback(unittest.TestCase):
    def test_merges_paths_urls_and_js_files(self):
        r = _result(internal_paths=["/existing"])
        wb = {
            "js_files": ["https://example.com/a.js"],
            "endpoints": {"/api/new", "https://example.com/api/abs", "https://evil.com/x"},
            "secrets": [],
            "sinks": [],
            "internal_hosts": [],
            "jwts": [],
            "errors": [],
        }
        stats = merge_wayback(r, wb, "https://example.com")
        self.assertIn("/api/new", r["internal_paths"])
        self.assertIn("https://example.com/api/abs", r["in_scope_urls"])
        self.assertNotIn("https://evil.com/x", r["in_scope_urls"])
        self.assertEqual(r["wayback_js_files"], ["https://example.com/a.js"])
        self.assertEqual(stats["paths"], 1)
        self.assertEqual(stats["urls"], 1)

    def test_not_gated_on_endpoints(self):
        """js_files / secrets / errors merge even when endpoints is empty."""
        r = _result()
        wb = {
            "js_files": ["https://example.com/only.js"],
            "endpoints": set(),
            "secrets": [{"type": "aws_key", "match": "AKIA1", "source": "wb.js"}],
            "sinks": [],
            "internal_hosts": [],
            "jwts": [],
            "errors": ["wayback fetch failed"],
        }
        merge_wayback(r, wb, "https://example.com")
        self.assertEqual(r["wayback_js_files"], ["https://example.com/only.js"])
        self.assertEqual(len(r["secrets_found"]), 1)
        self.assertIn("wayback fetch failed", r["errors"])

    def test_dedupes_secrets_against_live(self):
        r = _result(secrets_found=[
            {"type": "aws_key", "match": "AKIA1", "sources": ["live.js"]},
        ])
        wb = {
            "js_files": [],
            "endpoints": set(),
            "secrets": [{"type": "aws_key", "match": "AKIA1", "source": "wb.js"}],
            "sinks": [],
            "internal_hosts": [],
            "jwts": [],
            "errors": [],
        }
        stats = merge_wayback(r, wb, "https://example.com")
        self.assertEqual(len(r["secrets_found"]), 1)
        self.assertEqual(r["secrets_found"][0]["sources"], ["live.js", "wb.js"])
        # Net secret count unchanged (dup), so stats['secrets'] is 0 after dedupe
        self.assertEqual(stats["secrets"], 0)

    def test_merges_errors(self):
        r = _result(errors=["live error"])
        wb = {
            "js_files": [],
            "endpoints": set(),
            "secrets": [],
            "sinks": [],
            "internal_hosts": [],
            "jwts": [],
            "errors": ["wb error", "live error"],
        }
        merge_wayback(r, wb, "https://example.com")
        self.assertEqual(r["errors"], ["live error", "wb error"])

    def test_empty_wayback_fragment(self):
        r = _result(internal_paths=["/keep"])
        wb = {
            "js_files": [],
            "endpoints": set(),
            "secrets": [],
            "sinks": [],
            "internal_hosts": [],
            "jwts": [],
            "errors": [],
        }
        merge_wayback(r, wb, "https://example.com")
        self.assertEqual(r["internal_paths"], ["/keep"])
        self.assertEqual(r["wayback_js_files"], [])


class TestCveBoost(unittest.TestCase):
    """CVE boost must live inside calculate_risk_summary (Step 3)."""

    def test_cve_boost_weights(self):
        r = _result(internal_paths=["/a"])
        r["library_vulnerabilities"] = [{"severity": "CRITICAL"}, {"severity": "HIGH"}]
        # path(1) + 25 + 15
        self.assertEqual(calculate_risk_summary(r)["score"], 41)
        self.assertEqual(calculate_risk_summary(r)["level"], "HIGH")

    def test_cve_boost_preserved_on_recalc(self):
        """SPA/validation recalculation must not wipe the CVE boost."""
        r = _result(internal_paths=["/a"])
        r["library_vulnerabilities"] = [{"severity": "CRITICAL"}]
        first = calculate_risk_summary(r)
        self.assertEqual(first["score"], 26)
        r["spa_routes"] = ["/b"]
        second = calculate_risk_summary(r)
        self.assertEqual(second["score"], first["score"])

    def test_unknown_severity_defaults_to_5(self):
        r = _result()
        r["library_vulnerabilities"] = [{"severity": "WAT"}]
        self.assertEqual(calculate_risk_summary(r)["score"], 5)

    def test_no_vulns_zero_boost(self):
        r = _result(internal_paths=["/a"])
        self.assertEqual(calculate_risk_summary(r)["score"], 1)


class TestSchemaMeta(unittest.TestCase):
    """Result schema contract (Step 4): schema_version + meta block."""

    def _stamp(self, **arg_overrides):
        args = _args(**arg_overrides)
        ctx = ScanContext(args, verbose=False)
        ctx.stages_run = ["scan", "report"]
        ctx.stage_timings = {"scan": 0.1, "report": 0.0}
        ctx.result = {"target": args.target, "internal_paths": ["/a"]}
        _stamp_meta(ctx, datetime.now(timezone.utc))
        return ctx.result

    def test_schema_version_is_1(self):
        r = self._stamp()
        self.assertEqual(r["schema_version"], 1)

    def test_meta_required_keys(self):
        r = self._stamp()
        meta = r["meta"]
        for key in (
            "tool", "finished_at", "duration_seconds", "scan_mode",
            "stages_run", "stage_timings", "flags", "requests_sent",
        ):
            self.assertIn(key, meta)
        self.assertEqual(meta["tool"], "SurfaceSweep")
        self.assertIsInstance(meta["requests_sent"], int)
        self.assertEqual(meta["scan_mode"], "static")
        self.assertEqual(meta["stages_run"], ["scan", "report"])
        self.assertEqual(meta["stage_timings"], {"scan": 0.1, "report": 0.0})
        self.assertIsInstance(meta["duration_seconds"], float)
        self.assertTrue(meta["finished_at"].endswith("+00:00") or "T" in meta["finished_at"])

    def test_meta_flags_sorted_enabled_only(self):
        r = self._stamp(cors=True, jwt=True, waf=False, wayback=True)
        flags = r["meta"]["flags"]
        self.assertEqual(flags, sorted(flags))
        self.assertIn("cors", flags)
        self.assertIn("jwt", flags)
        self.assertIn("wayback", flags)
        self.assertNotIn("waf", flags)

    def test_scan_mode_respected(self):
        r = self._stamp(full=True)
        self.assertEqual(r["meta"]["scan_mode"], "full")
        r = self._stamp(browser=True)
        self.assertEqual(r["meta"]["scan_mode"], "browser")

    def test_result_scan_mode_wins(self):
        """result["scan_mode"] set by stage_scan overrides flag-derived mode."""
        ctx = ScanContext(_args(), verbose=False)
        ctx.result = {"scan_mode": "full", "target": "x"}
        _stamp_meta(ctx, datetime.now(timezone.utc))
        self.assertEqual(ctx.result["meta"]["scan_mode"], "full")

    def test_stamp_without_result_is_noop(self):
        ctx = ScanContext(_args(), verbose=False)
        _stamp_meta(ctx, datetime.now(timezone.utc))  # must not raise
        self.assertIsNone(ctx.result)


class TestHtmlHardening(unittest.TestCase):
    """HTML report escaping + missing sections (Step 5)."""

    def test_list_escapes(self):
        from modules.reporting.html import render_list
        html = render_list(["<script>alert(1)</script>"])
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_secrets_escape(self):
        from modules.reporting.html import render_secrets
        html = render_secrets([{
            "type": "<b>x</b>",
            "match": "\"><img src=x>",
            "source": "<i>src</i>",
        }])
        self.assertNotIn("<b>x</b>", html)
        self.assertNotIn("<img src=x>", html)
        self.assertIn("&lt;b&gt;", html)

    def test_errors_escape(self):
        from modules.reporting.html import render_errors
        html = render_errors(["<svg onload=alert(1)>"])
        self.assertNotIn("<svg", html)
        self.assertIn("&lt;svg", html)

    def test_build_html_escapes_target(self):
        from modules.reporting.html import build_html
        html = build_html({"target": '"><script>alert(1)</script>'})
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_critical_badge_distinct(self):
        from modules.reporting.html import render_sinks, CSS
        self.assertIn("badge-critical", CSS)
        html = render_sinks([{
            "sink": "innerHTML", "severity": "CRITICAL",
            "description": "d", "count": 1, "source": "a",
        }])
        self.assertIn("badge-critical", html)

    def test_render_pii_section(self):
        from modules.reporting.html import render_pii
        html = render_pii([{
            "kind": "email", "match": "alice@corp-target.io",
            "severity": "INFO", "description": "Email",
            "sources": ["a.js"],
        }])
        self.assertIn("Potential PII", html)
        self.assertIn("alice@corp-target.io", html)
        self.assertIn("a.js", html)

    def test_render_pii_escapes_match(self):
        from modules.reporting.html import render_pii
        html = render_pii([{
            "kind": "email", "match": "<script>alert(1)</script>@x.io",
            "severity": "INFO", "description": "Email", "source": "a.js",
        }])
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_render_pii_empty(self):
        from modules.reporting.html import render_pii
        self.assertEqual(render_pii([]), "")
        self.assertEqual(render_pii(None), "")

    def test_build_html_has_pii_stat_and_section(self):
        from modules.reporting.html import build_html
        html = build_html({
            "target": "https://example.com",
            "pii_found": [{
                "kind": "credit_card", "match": "4532015112830366",
                "severity": "LOW", "description": "Payment card",
                "source": "a.js",
            }],
        })
        self.assertIn("PII Items", html)
        self.assertIn("Potential PII", html)
        self.assertIn("Payment card", html)

    def test_waf_section_present(self):
        from modules.reporting.html import build_html
        html = build_html({
            "target": "https://example.com",
            "waf": {
                "detected": True,
                "waf_name": "Cloudflare",
                "confidence": "high",
                "headers_matched": [{"header": "server", "value": "cloudflare", "waf": "Cloudflare"}],
                "adjustments": {"recommendation": "slow down"},
            },
        })
        self.assertIn("WAF Detection", html)
        self.assertIn("Cloudflare", html)
        self.assertIn("slow down", html)

    def test_wayback_section_present(self):
        from modules.reporting.html import build_html
        html = build_html({
            "target": "https://example.com",
            "wayback_js_files": ["https://example.com/old.js"],
        })
        self.assertIn("Wayback Machine Historical JS", html)
        self.assertIn("old.js", html)

    def test_intercepted_section_present(self):
        from modules.reporting.html import build_html
        html = build_html({
            "target": "https://example.com",
            "intercepted_endpoints": [{"url": "https://example.com/api", "method": "POST"}],
        })
        self.assertIn("Intercepted API Endpoints", html)
        self.assertIn("POST", html)

    def test_scan_mode_in_header(self):
        from modules.reporting.html import build_html
        html = build_html({"target": "https://example.com", "scan_mode": "full"})
        self.assertIn("Mode: full", html)

    def test_cors_table_escapes(self):
        from modules.reporting.html import render_cors
        html = render_cors({
            "findings": [{
                "severity": "HIGH",
                "url": "https://example.com/<script>",
                "origin": "https://evil.com",
                "acao": "*",
                "acac": "true",
                "method": "GET",
                "detail": "<svg/onload=1>",
                "evidence": "<b>e</b>",
            }],
        })
        self.assertNotIn("<script>", html)
        self.assertNotIn("<svg/onload=1>", html)
        self.assertIn("&lt;script&gt;", html)


class TestFindingsFeed(unittest.TestCase):
    """Cross-module findings feed + executive summary (Step 6)."""

    def _result(self):
        return {
            "target": "https://example.com",
            "risk_summary": {"level": "HIGH", "score": 42},
            "internal_paths": ["/a"],
            "secrets_found": [{"type": "aws_key", "match": "AKIA...", "sources": ["a.js"]}],
            "sinks_found": [{"sink": "innerHTML", "severity": "HIGH", "description": "d",
                             "count": 1, "source": "a"}],
            "library_vulnerabilities": [{
                "library": "jQuery", "version": "1.6.3", "cves": ["CVE-2011-4969"],
                "severity": "CRITICAL", "description": "XSS", "source_file": "x.js",
            }],
            "cors": {"findings": [{
                "severity": "CRITICAL", "url": "https://example.com/api",
                "acao": "*", "origins_flagged": ["https://evil.com"], "detail": "reflected",
            }]},
            "jwt": {
                "tokens_analyzed": 1,
                "findings": [{
                    "severity": "HIGH", "alg": "none", "source": "a",
                    "findings": [{"severity": "HIGH", "issue": "alg none", "detail": "x"}],
                }],
            },
            "internal_hosts_found": [],
            "source_maps_found": [],
            "pii_found": [{
                "kind": "credit_card", "match": "4532015112830366",
                "severity": "LOW", "description": "Payment card",
                "sources": ["a.js"],
            }],
        }

    def test_feed_sorted_by_severity(self):
        from modules.reporting.findings import build_findings_feed, SEVERITY_ORDER
        feed = build_findings_feed(self._result())
        self.assertTrue(feed)
        keys = [(SEVERITY_ORDER.get(f["severity"], 9), f["module"], f["title"]) for f in feed]
        self.assertEqual(keys, sorted(keys))

    def test_feed_includes_modules(self):
        from modules.reporting.findings import build_findings_feed
        feed = build_findings_feed(self._result())
        modules = {f["module"] for f in feed}
        self.assertLessEqual({"secrets", "sinks", "cve", "cors", "jwt", "pii"}, modules)

    def test_feed_includes_pii_entry(self):
        from modules.reporting.findings import build_findings_feed
        feed = build_findings_feed(self._result())
        pii = [f for f in feed if f["module"] == "pii"]
        self.assertEqual(len(pii), 1)
        self.assertEqual(pii[0]["severity"], "LOW")
        self.assertIn("credit_card", pii[0]["title"])

    def test_executive_summary_shape(self):
        from modules.reporting.findings import build_executive_summary, build_findings_feed
        r = self._result()
        feed = build_findings_feed(r)
        s = build_executive_summary(r, feed)
        self.assertEqual(s["risk_level"], "HIGH")
        self.assertEqual(s["risk_score"], 42)
        self.assertEqual(s["total_findings"], len(feed))
        self.assertIn("CRITICAL", s["severity_counts"])
        self.assertTrue(s["top_findings"])
        self.assertIn("cors", s["modules_covered"])
        self.assertEqual(s["counts"]["secrets"], 1)

    def test_html_has_executive_and_feed(self):
        from modules.reporting.html import build_html
        html = build_html(self._result())
        self.assertIn("Executive Summary", html)
        self.assertIn("All Findings", html)
        self.assertIn("Top findings", html)

    def test_html_escapes_feed_content(self):
        from modules.reporting.html import build_html
        r = self._result()
        r["secrets_found"] = [{"type": "<script>", "match": "<img>", "source": "x"}]
        html = build_html(r)
        self.assertNotIn("<script>", html.replace("<script>alert", ""))
        # secret type appears escaped in feed
        self.assertIn("&lt;script&gt;", html)

    def test_finalize_attaches_fields(self):
        from datetime import datetime, timezone
        from modules.pipeline.runner import _finalize_result
        ctx = ScanContext(_args(cors=True, jwt=True), verbose=False)
        ctx.stages_run = ["scan"]
        ctx.result = self._result()
        _finalize_result(ctx, datetime.now(timezone.utc))
        self.assertEqual(ctx.result["schema_version"], 1)
        self.assertIn("findings", ctx.result)
        self.assertIn("executive_summary", ctx.result)
        self.assertIn("meta", ctx.result)
        self.assertTrue(ctx.result["findings"])


class TestReportBuilder(unittest.TestCase):
    """Unified report builder (Step 7): path derivation + toggles."""

    def test_output_paths_from_json(self):
        from modules.reporting.builder import output_paths
        p = output_paths("reports/scan.json")
        self.assertEqual(p["base"], "reports/scan")
        self.assertEqual(p["json"], "reports/scan.json")
        self.assertEqual(p["html"], "reports/scan.html")
        self.assertEqual(p["burp"], "reports/scan_burp.csv")
        self.assertEqual(p["zap"], "reports/scan_zap.csv")

    def test_output_paths_from_non_json(self):
        from modules.reporting.builder import output_paths
        p = output_paths("reports/out")
        self.assertEqual(p["json"], "reports/out.json")
        self.assertEqual(p["html"], "reports/out.html")
        p2 = output_paths("reports/old.html")
        self.assertEqual(p2["base"], "reports/old")
        self.assertEqual(p2["json"], "reports/old.json")

    def test_report_plan_flags(self):
        from modules.reporting.builder import build_report_plan
        plan = build_report_plan(_args())
        self.assertTrue(plan["write_json"])
        self.assertFalse(plan["write_html"])
        self.assertFalse(plan["write_burp"])
        self.assertFalse(plan["write_cors_poc"])

        plan = build_report_plan(_args(html=True, burp=True, zap=True, cors_poc=True))
        self.assertTrue(plan["write_json"])
        self.assertTrue(plan["write_html"])
        self.assertTrue(plan["write_burp"])
        self.assertTrue(plan["write_zap"])
        self.assertTrue(plan["write_cors_poc"])

        plan = build_report_plan(_args(html_only=True))
        self.assertFalse(plan["write_json"])
        self.assertTrue(plan["write_html"])

    def test_write_reports_creates_files(self):
        import tempfile
        import json as _json
        from pathlib import Path
        from modules.reporting.builder import write_reports

        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "nested" / "scan.json")
            result = {"target": "https://example.com", "internal_paths": ["/a"],
                      "schema_version": 1, "meta": {}, "findings": []}
            written = write_reports(
                result, out,
                write_json=True, write_html=True, write_burp=True, write_zap=True,
                verbose=False,
            )
            self.assertTrue(Path(written["json"]).is_file())
            self.assertTrue(Path(written["html"]).is_file())
            self.assertTrue(Path(written["burp"]).is_file())
            self.assertTrue(Path(written["zap"]).is_file())
            with open(written["json"]) as f:
                data = _json.load(f)
            self.assertEqual(data["schema_version"], 1)

    def test_write_reports_respects_toggles(self):
        import tempfile
        from pathlib import Path
        from modules.reporting.builder import write_reports

        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "scan.json")
            written = write_reports(
                {"target": "https://x.com"}, out,
                write_json=True, write_html=False,
                write_burp=False, write_zap=False, write_cors_poc=False,
                verbose=False,
            )
            self.assertIsNotNone(written["json"])
            self.assertIsNone(written["html"])
            self.assertIsNone(written["burp"])
            self.assertIsNone(written["zap"])
            self.assertIsNone(written["cors_poc"])

    def test_write_cors_poc_document(self):
        import tempfile
        from pathlib import Path
        from modules.reporting.builder import write_reports

        result = {
            "target": "https://example.com",
            "cors": {
                "target_origin": "https://example.com",
                "findings": [{
                    "url": "https://example.com/api",
                    "severity": "CRITICAL",
                    "origin": "https://evil.com",
                    "acao": "https://evil.com",
                    "acac": "true",
                }],
            },
        }
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "scan.json")
            written = write_reports(
                result, out,
                write_json=False, write_html=False,
                write_burp=False, write_zap=False, write_cors_poc=True,
                verbose=False,
            )
            self.assertIsNotNone(written["cors_poc"])
            text = Path(written["cors_poc"]).read_text()
            self.assertIn("credentials:", text)
            self.assertIn("include", text)
            self.assertIn("https://example.com/api", text)

    def test_write_cors_poc_skips_when_no_findings(self):
        import tempfile
        from pathlib import Path
        from modules.reporting.builder import write_reports

        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "scan.json")
            written = write_reports(
                {"target": "https://example.com", "cors": {"findings": []}},
                out,
                write_json=False, write_html=False,
                write_burp=False, write_zap=False, write_cors_poc=True,
                verbose=False,
            )
            self.assertIsNone(written["cors_poc"])

    def test_html_report_embeds_poc_for_critical(self):
        from modules.reporting.html import build_html
        result = {
            "target": "https://example.com",
            "risk_summary": {"level": "CRITICAL", "score": 25},
            "cors": {
                "schema_version": 1,
                "target_origin": "https://example.com",
                "endpoints_tested": 1,
                "probe_hits": 1,
                "severity_counts": {"CRITICAL": 1},
                "summary": {"urls_flagged": 1, "severity_counts": {"CRITICAL": 1}},
                "findings": [{
                    "url": "https://example.com/api",
                    "severity": "CRITICAL",
                    "origin": "https://evil.com",
                    "origins_flagged": ["https://evil.com"],
                    "acao": "https://evil.com",
                    "acac": "true",
                    "method": "GET",
                    "methods": ["GET"],
                    "detail": "reflected",
                }],
            },
        }
        html = build_html(result)
        self.assertIn("Proof of concept", html)
        self.assertIn("credentials:", html)
        self.assertIn("credentialed", html)

    def test_no_inline_path_duplication_in_stages(self):
        """stage_export / stage_report must not re-derive paths inline."""
        import inspect
        from modules.pipeline import stages
        src = inspect.getsource(stages)
        self.assertNotIn('args.output.replace(".json"', src)


class TestStageCorsWafPacing(unittest.TestCase):
    """Phase 2.1 Step 3: stage_cors applies WAF adjustments to scan_cors."""

    def _ctx(self, waf_adjustments=None, **arg_overrides):
        args = _args(cors=True, **arg_overrides)
        ctx = ScanContext(args, verbose=False, headers={"Cookie": "a=b"})
        ctx.result = _result(
            in_scope_urls=["https://example.com/api/users"],
        )
        ctx.waf_adjustments = waf_adjustments
        return ctx

    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.scan_cors")
    def test_no_waf_uses_cli_settings(self, scan_mock, risk_mock):
        from modules.pipeline.stages import stage_cors
        scan_mock.return_value = {"severity_counts": {}, "findings": []}
        risk_mock.return_value = {"level": "INFO", "score": 0}
        ctx = self._ctx()
        stage_cors(ctx)
        kwargs = scan_mock.call_args.kwargs
        self.assertEqual(kwargs["rate_limit"], 5.0)
        self.assertEqual(kwargs["threads"], 6)
        self.assertEqual(kwargs["headers"], {"Cookie": "a=b"})

    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.scan_cors")
    def test_waf_slows_rate_caps_threads_sets_ua(self, scan_mock, risk_mock):
        from modules.pipeline.stages import stage_cors
        scan_mock.return_value = {"severity_counts": {}, "findings": []}
        risk_mock.return_value = {"level": "INFO", "score": 0}
        ctx = self._ctx(waf_adjustments={
            "delay_multiplier": 3.0,
            "max_threads": 2,
            "user_agent": "WAF-UA/1.0",
        })
        stage_cors(ctx)
        kwargs = scan_mock.call_args.kwargs
        self.assertAlmostEqual(kwargs["rate_limit"], 5.0 / 3.0)
        self.assertEqual(kwargs["threads"], 2)
        self.assertEqual(kwargs["headers"]["User-Agent"], "WAF-UA/1.0")
        self.assertEqual(kwargs["headers"]["Cookie"], "a=b")

    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.scan_cors")
    def test_waf_thread_cap_never_raises(self, scan_mock, risk_mock):
        from modules.pipeline.stages import stage_cors
        scan_mock.return_value = {"severity_counts": {}, "findings": []}
        risk_mock.return_value = {"level": "INFO", "score": 0}
        ctx = self._ctx(
            waf_adjustments={"delay_multiplier": 1.0, "max_threads": 20},
            cors_threads=6,
        )
        stage_cors(ctx)
        # min(6, 20) — WAF cap is an upper bound, not a floor
        self.assertEqual(scan_mock.call_args.kwargs["threads"], 6)


if __name__ == "__main__":
    unittest.main()
