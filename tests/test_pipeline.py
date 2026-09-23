"""Unit tests for Phase 4 Steps 1–2 — pipeline stages and merge helpers."""

import unittest
from argparse import Namespace

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
    merge_secrets,
    merge_sinks,
    merge_wayback,
    stage_names,
)


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
        jwt=False,
        jwt_wordlist=None,
        jwt_hashcat=None,
        jwt_export=None,
        jwt_network=False,
        jwt_network_timeout=5.0,
        quiet=False,
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
        ))
        self.assertEqual(names, [
            "waf_detect", "wayback_fetch", "scan", "wayback_merge",
            "waf_inject", "cve", "spa", "cors", "jwt", "validate",
            "export", "report",
        ])

    def test_cve_or_osv_enables_cve_stage(self):
        self.assertIn("cve", stage_names(_args(cve=True)))
        self.assertIn("cve", stage_names(_args(osv=True)))
        self.assertNotIn("cve", stage_names(_args()))

    def test_export_only_when_burp_or_zap(self):
        self.assertNotIn("export", stage_names(_args()))
        self.assertIn("export", stage_names(_args(burp=True)))
        self.assertIn("export", stage_names(_args(zap=True)))

    def test_scan_always_present(self):
        self.assertIn("scan", stage_names(_args()))
        self.assertIn("report", stage_names(_args()))

    def test_wayback_pair(self):
        names = stage_names(_args(wayback=True))
        self.assertEqual(names, ["wayback_fetch", "scan", "wayback_merge", "report"])

    def test_build_stages_returns_callables(self):
        for name, fn in build_stages(_args(waf=True, wayback=True, cors=True)):
            self.assertTrue(callable(fn), name)


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


if __name__ == "__main__":
    unittest.main()
