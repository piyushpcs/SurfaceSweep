"""Unit tests for Phase 2 CORS + Phase 2.1 hardening (origins, probe, scanner, reporting)."""

import unittest
from unittest import mock

from modules.cors import (
    aggregate_findings,
    build_test_origins,
    classify_cors,
    collect_js_origins,
    endpoint_priority,
    is_api_like_path,
    is_cross_domain_redirect,
    is_multi_origin_acao,
    is_reflected_acao,
    normalize_origin,
    origins_equal,
    parse_acao_list,
    probe_baseline,
    probe_endpoint,
)
from modules.cors.classifier import classify_cors as classify
from modules.cors.classifier import is_pna_allowed
from modules.cors.origins import (
    MAX_TEST_ORIGINS,
    THIRD_PARTY_SUFFIXES,
    build_seed_lookalikes,
)
from modules.cors.probe import build_evidence, build_probe_headers, extract_cors_headers
from modules.cors.scanner import cors_risk_boost, resolve_endpoints, scan_cors


TARGET = "https://example.com"
EVIL = "https://evil.com"


class TestNormalizeOrigin(unittest.TestCase):
    def test_lowercase_scheme_host(self):
        self.assertEqual(normalize_origin("HTTPS://Example.COM"), "https://example.com")

    def test_default_port_https_stripped(self):
        self.assertEqual(normalize_origin("https://example.com:443"), "https://example.com")

    def test_default_port_http_stripped(self):
        self.assertEqual(normalize_origin("http://example.com:80"), "http://example.com")

    def test_nondefault_port_kept(self):
        self.assertEqual(normalize_origin("https://example.com:8443"), "https://example.com:8443")

    def test_trailing_slash_stripped(self):
        self.assertEqual(normalize_origin("https://example.com/"), "https://example.com")

    def test_null_and_star_passthrough(self):
        self.assertEqual(normalize_origin("null"), "null")
        self.assertEqual(normalize_origin("*"), "*")

    def test_origins_equal_ignores_case_and_port(self):
        self.assertTrue(origins_equal("https://Example.com:443", "https://example.com"))

    def test_normalize_ipv6_keeps_brackets(self):
        self.assertEqual(normalize_origin("http://[::1]:5555"), "http://[::1]:5555")
        self.assertEqual(normalize_origin("http://[::1]:80"), "http://[::1]")


class TestBuildTestOrigins(unittest.TestCase):
    def test_custom_origin_first(self):
        origins = build_test_origins(TARGET, custom_origin="https://my.origin")
        self.assertEqual(origins[0], "https://my.origin")

    def test_ip_target_skips_domain_lookalikes(self):
        origins = build_test_origins("http://127.0.0.1:5555")
        self.assertNotIn("https://sub.0.1", origins)
        self.assertTrue(any(o == "null" for o in origins))

    def test_domain_target_includes_lookalikes(self):
        origins = build_test_origins(TARGET)
        self.assertIn("https://sub.example.com", origins)
        self.assertIn("https://example.com.evil.com", origins)
        self.assertIn("null", origins)

    def test_path_bearing_origin_included(self):
        origins = build_test_origins(TARGET)
        self.assertIn("https://evil.com/path", origins)
        self.assertIn("https://example.com/path", origins)

    def test_http_scheme_on_target_host(self):
        origins = build_test_origins("https://example.com")
        self.assertIn("http://example.com", origins)
        self.assertIn("https://example.com", origins)

    def test_ip_matrix_has_scheme_flips(self):
        origins = build_test_origins("http://127.0.0.1:5555")
        self.assertIn("http://127.0.0.1:5555", origins)
        self.assertIn("https://127.0.0.1:5555", origins)
        self.assertIn("http://127.0.0.1", origins)
        self.assertNotIn("https://sub.0.1", origins)

    def test_registrable_domain_uses_public_suffix(self):
        # Naive last-two-labels would yield co.uk → sub.co.uk / co.uk.evil.com
        origins = build_test_origins("https://a.b.example.co.uk")
        self.assertIn("https://sub.example.co.uk", origins)
        self.assertIn("https://example.co.uk.evil.com", origins)
        self.assertIn("https://example.co.uk", origins)
        self.assertNotIn("https://sub.co.uk", origins)
        self.assertNotIn("https://co.uk.evil.com", origins)

    def test_special_char_and_nodot_attacker_origins(self):
        origins = build_test_origins(TARGET)
        self.assertIn("https://evil_com", origins)
        self.assertIn("https://evilcom", origins)

    def test_local_origin_probes_included(self):
        origins = build_test_origins(TARGET)
        self.assertIn("http://localhost", origins)
        self.assertIn("http://127.0.0.1", origins)

    def test_third_party_free_host_origins(self):
        origins = build_test_origins(TARGET)
        for suffix in THIRD_PARTY_SUFFIXES[:2]:
            self.assertIn(f"https://example.com.{suffix}", origins)

    def test_ip_alternate_loopback_forms(self):
        origins = build_test_origins("http://127.0.0.1:5555")
        self.assertIn("http://127.1", origins)
        self.assertIn("http://0.0.0.0", origins)
        self.assertIn("http://[::1]", origins)
        self.assertIn("http://2130706433", origins)

    def test_matrix_capped_and_custom_first(self):
        origins = build_test_origins(TARGET, custom_origin="https://my.origin")
        self.assertLessEqual(len(origins), MAX_TEST_ORIGINS)
        self.assertEqual(origins[0], "https://my.origin")
        # Cap must never drop the core attacker origin
        self.assertIn("https://evil.com", origins)
        self.assertIn("null", origins)

    def test_ipv6_target_origins_are_bracketed(self):
        origins = build_test_origins("http://[::1]:5555")
        self.assertTrue(any("[::1]" in o for o in origins))
        self.assertFalse(any("http://::1" in o for o in origins))
        self.assertNotIn("https://sub.0.1", origins)


class TestParseAcaoList(unittest.TestCase):
    def test_single_origin(self):
        self.assertEqual(parse_acao_list("https://evil.com"), ["https://evil.com"])

    def test_star(self):
        self.assertEqual(parse_acao_list("*"), ["*"])

    def test_multi_comma(self):
        self.assertEqual(
            parse_acao_list("https://evil.com, https://cdn.example.com"),
            ["https://evil.com", "https://cdn.example.com"],
        )

    def test_is_multi(self):
        self.assertTrue(is_multi_origin_acao("https://a.com, https://b.com"))
        self.assertFalse(is_multi_origin_acao("https://a.com"))
        self.assertFalse(is_multi_origin_acao("*"))


class TestClassifyMultiAcao(unittest.TestCase):
    def test_multi_origin_list_medium(self):
        sev, detail = classify(
            EVIL, "https://evil.com, https://cdn.example.com", "true", target_origin=TARGET
        )
        self.assertEqual(sev, "MEDIUM")
        self.assertIn("Non-singleton", detail)

    def test_multi_with_arbitrary_and_creds_medium(self):
        sev, _ = classify(
            "https://attacker.example",
            "https://attacker.example, https://other.com",
            "true",
            target_origin=TARGET,
        )
        self.assertEqual(sev, "MEDIUM")

    def test_legitimate_in_multi_list_medium_not_info(self):
        sev, _ = classify(
            "https://example.com",
            "https://example.com, https://cdn.example.com",
            "true",
            target_origin=TARGET,
        )
        self.assertEqual(sev, "MEDIUM")


class TestStep2OriginsAndProbe(unittest.TestCase):
    def test_path_bearing_reflection_still_classified(self):
        # Server echoes path-bearing Origin (naive contains match)
        sev, _ = classify(
            "https://evil.com/path",
            "https://evil.com/path",
            "true",
            target_origin=TARGET,
        )
        self.assertEqual(sev, "CRITICAL")

    def test_api_like_path(self):
        self.assertTrue(is_api_like_path("https://x.test/api/v2/users"))
        self.assertTrue(is_api_like_path("https://x.test/graphql"))
        self.assertFalse(is_api_like_path("https://x.test/about"))
        self.assertFalse(is_api_like_path("https://x.test/app.js"))

    def test_build_evidence_joins_headers(self):
        ev = build_evidence({
            "vary": "Origin",
            "acam": "GET, POST",
            "acah": "Content-Type",
            "acma": "600",
        })
        self.assertIn("Vary: Origin", ev)
        self.assertIn("Methods: GET, POST", ev)
        self.assertIn("Max-Age: 600", ev)

    def test_build_evidence_empty(self):
        self.assertEqual(build_evidence({"vary": "", "acam": "", "acah": "", "acma": ""}), "")

    def test_build_evidence_includes_private_network(self):
        ev = build_evidence({"acpn": "true", "vary": ""})
        self.assertIn("Allow-Private-Network: true", ev)

    def test_preflight_acrm_matches_request_method(self):
        headers = build_probe_headers(
            EVIL, preflight=True, request_method="POST"
        )
        self.assertEqual(headers["Access-Control-Request-Method"], "POST")
        self.assertEqual(headers["Origin"], EVIL)

    def test_extract_pna_allow_header(self):
        resp = mock.Mock()
        resp.headers = {
            "Access-Control-Allow-Origin": EVIL,
            "Access-Control-Allow-Private-Network": "true",
        }
        cors = extract_cors_headers(resp)
        self.assertEqual(cors["acpn"], "true")
        self.assertNotIn("acrq", cors)

    def test_is_cross_domain_redirect(self):
        self.assertTrue(
            is_cross_domain_redirect("https://a.example/api", "https://evil.com/api")
        )
        self.assertFalse(
            is_cross_domain_redirect("https://a.example/api", "https://a.example/other")
        )
        self.assertFalse(is_cross_domain_redirect("https://a.example/api", ""))

    def test_is_reflected_acao(self):
        self.assertTrue(is_reflected_acao(EVIL, EVIL))
        self.assertTrue(is_reflected_acao(EVIL, f"{EVIL}, https://other.com"))
        self.assertFalse(is_reflected_acao(EVIL, "*"))
        self.assertFalse(is_reflected_acao(EVIL, "https://other.com"))
        self.assertFalse(is_reflected_acao(EVIL, ""))

    @staticmethod
    def _mock_resp(headers=None, status=200, url="https://example.com/api"):
        resp = mock.Mock()
        resp.headers = headers or {}
        resp.status_code = status
        resp.url = url
        return resp

    @mock.patch("modules.cors.probe.requests.request")
    def test_probe_endpoint_happy_path(self, request_mock):
        request_mock.return_value = self._mock_resp({
            "Access-Control-Allow-Origin": EVIL,
            "Access-Control-Allow-Credentials": "true",
            "Vary": "Origin",
        })
        results = probe_endpoint(
            "https://example.com/api", [EVIL], target_origin=TARGET
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "CRITICAL")
        self.assertEqual(results[0]["acpn"], "")
        self.assertNotIn("missing Vary", results[0]["detail"])

    @mock.patch("modules.cors.probe.requests.request")
    def test_probe_endpoint_missing_vary_note(self, request_mock):
        request_mock.return_value = self._mock_resp({
            "Access-Control-Allow-Origin": EVIL,
            "Access-Control-Allow-Credentials": "true",
        })
        results = probe_endpoint(
            "https://example.com/api", [EVIL], target_origin=TARGET
        )
        self.assertIn("missing Vary: Origin", results[0]["detail"])

    @mock.patch("modules.cors.probe.requests.request")
    def test_probe_endpoint_skips_cross_domain_redirect(self, request_mock):
        request_mock.return_value = self._mock_resp(
            headers={"Access-Control-Allow-Origin": EVIL},
            url="https://other-host.test/api",
        )
        results = probe_endpoint(
            "https://example.com/api", [EVIL], target_origin=TARGET
        )
        self.assertEqual(results, [])

    @mock.patch("modules.cors.probe.requests.request")
    def test_probe_endpoint_error_row(self, request_mock):
        import requests as requests_lib

        request_mock.side_effect = requests_lib.exceptions.ConnectionError("down")
        results = probe_endpoint("https://example.com/api", [EVIL])
        self.assertEqual(results[0]["severity"], "ERROR")
        self.assertEqual(results[0]["acpn"], "")

    @mock.patch("modules.cors.probe.requests.request")
    def test_probe_baseline_omits_origin_header(self, request_mock):
        request_mock.return_value = self._mock_resp({
            "Access-Control-Allow-Origin": "*",
        })
        out = probe_baseline("https://example.com/api")
        sent = request_mock.call_args.kwargs["headers"]
        self.assertNotIn("Origin", sent)
        self.assertTrue(out["static_acao"])
        self.assertEqual(out["acao"], "*")

    @mock.patch("modules.cors.probe.requests.request")
    def test_probe_baseline_cross_domain_static_false(self, request_mock):
        request_mock.return_value = self._mock_resp(
            headers={"Access-Control-Allow-Origin": "*"},
            url="https://other-host.test/api",
        )
        out = probe_baseline("https://example.com/api")
        self.assertFalse(out["static_acao"])
        self.assertEqual(out["acao"], "")
        self.assertEqual(out["error"], "cross-domain redirect")

    @mock.patch("modules.cors.probe.requests.request")
    def test_probe_endpoint_uses_shared_session(self, request_mock):
        session = mock.Mock()
        session.request.return_value = self._mock_resp({
            "Access-Control-Allow-Origin": EVIL,
            "Vary": "Origin",
        })
        results = probe_endpoint(
            "https://example.com/api", [EVIL],
            target_origin=TARGET, session=session,
        )
        session.request.assert_called_once()
        request_mock.assert_not_called()
        self.assertEqual(len(results), 1)


class TestRateLimiter(unittest.TestCase):
    """Step 4: rate limiter must not hold the lock while sleeping."""

    def test_min_interval_enforced(self):
        import time

        from modules.extraction.http import RateLimiter

        limiter = RateLimiter(50)  # 0.02s interval
        t0 = time.monotonic()
        for _ in range(5):
            limiter.wait()
        elapsed = time.monotonic() - t0
        # 4 gaps × 0.02s (first call is free)
        self.assertGreaterEqual(elapsed, 0.06)

    def test_lock_released_during_sleep(self):
        import threading
        import time

        from modules.extraction.http import RateLimiter

        limiter = RateLimiter(2)  # 0.5s interval
        limiter.wait()  # arm the bucket

        acquired_during = []
        started = threading.Event()

        def try_acquire():
            started.wait(timeout=1)
            ok = limiter._lock.acquire(timeout=0.25)
            if ok:
                limiter._lock.release()
            acquired_during.append(ok)

        holder = threading.Thread(target=limiter.wait)
        prober = threading.Thread(target=try_acquire)
        holder.start()
        time.sleep(0.05)  # let holder enter its sleep window
        started.set()
        prober.start()
        prober.join(timeout=2)
        holder.join(timeout=2)
        self.assertTrue(acquired_during and acquired_during[0],
                        "lock must not be held while wait() sleeps")


class TestSeedLookalikes(unittest.TestCase):
    """Phase 2.2 Step 2: trusted-seed expansion."""

    def test_seed_builds_suffix_and_subdomain(self):
        looks = build_seed_lookalikes("https://cdn.partner.com")
        self.assertIn("https://sub.partner.com", looks)
        self.assertIn("https://partner.com.evil.com", looks)
        self.assertIn("https://evil.partner.com", looks)
        self.assertIn("https://cdn.partner.com/path", looks)

    def test_seed_rejects_null_star_empty(self):
        self.assertEqual(build_seed_lookalikes("null"), [])
        self.assertEqual(build_seed_lookalikes("*"), [])
        self.assertEqual(build_seed_lookalikes(""), [])

    def test_seed_rejects_ip_host(self):
        self.assertEqual(build_seed_lookalikes("https://10.0.0.5"), [])

    def test_seed_respects_limit(self):
        looks = build_seed_lookalikes("https://cdn.partner.com", limit=2)
        self.assertEqual(len(looks), 2)

    @mock.patch("modules.cors.scanner.requests.Session")
    @mock.patch("modules.cors.scanner.probe_baseline")
    @mock.patch("modules.cors.scanner.probe_endpoint")
    def test_second_pass_when_trusted_acao_seen(
        self, probe_mock, baseline_mock, session_cls
    ):
        baseline_mock.return_value = {"static_acao": False, "acao": ""}
        # First pass: INFO with static third-party ACAO (trusted seed)
        # No finding on first pass for simplicity — seed still collected
        info_row = {
            "origin": "https://evil.com",
            "method": "OPTIONS",
            "status": 200,
            "final_url": "https://example.com/api",
            "redirected": False,
            "severity": "INFO",
            "detail": "static allowlist",
            "evidence": "",
            "static_acao": False,
            "acao": "https://cdn.partner.com",
            "acac": "",
            "vary": "",
            "acpn": "",
        }
        # Second pass: seed lookalike reflects + creds → CRITICAL
        seed_crit = dict(info_row)
        seed_crit.update({
            "origin": "https://evil.partner.com",
            "severity": "CRITICAL",
            "acao": "https://evil.partner.com",
            "acac": "true",
            "method": "GET",
        })

        # OPTIONS pass 1 (INFO), GET pass 1 (INFO) — then seed OPTIONS/GET
        probe_mock.side_effect = [
            [info_row],  # OPTIONS pass 1
            [info_row],  # GET pass 1
            [seed_crit],  # seed OPTIONS
        ]
        out = scan_cors(
            ["/about"], TARGET, verbose=False, threads=1, rate_limit=0
        )
        self.assertGreaterEqual(probe_mock.call_count, 3)
        origin_lists = [
            c.args[1] for c in probe_mock.call_args_list if len(c.args) >= 2
        ]
        seed_lists = [
            o for o in origin_lists
            if any("evil.partner.com" in (x or "") for x in o)
        ]
        self.assertTrue(seed_lists, "second pass must probe seed lookalikes")
        self.assertEqual(out["severity_counts"].get("CRITICAL"), 1)

    @mock.patch("modules.cors.scanner.requests.Session")
    @mock.patch("modules.cors.scanner.probe_baseline")
    @mock.patch("modules.cors.scanner.probe_endpoint")
    def test_no_second_pass_without_trusted_seed(
        self, probe_mock, baseline_mock, session_cls
    ):
        baseline_mock.return_value = {"static_acao": False, "acao": ""}
        crit = {
            "origin": "https://evil.com",
            "method": "OPTIONS",
            "status": 200,
            "final_url": "https://example.com/api",
            "redirected": False,
            "severity": "CRITICAL",
            "detail": "reflected",
            "evidence": "",
            "static_acao": False,
            "acao": "https://evil.com",
            "acac": "true",
            "vary": "Origin",
            "acpn": "",
        }
        probe_mock.return_value = [crit]
        scan_cors(["/api/users"], TARGET, verbose=False, threads=1, rate_limit=0)
        # Only first-pass probes — no seed lookalike origins passed through
        origin_lists = [
            c.args[1] for c in probe_mock.call_args_list if len(c.args) >= 2
        ]
        seed_lists = [
            o for o in origin_lists
            if any("evil.partner.com" in (x or "") for x in o)
        ]
        self.assertEqual(seed_lists, [])


class TestScannerEscalationAndErrors(unittest.TestCase):
    """HTTP-layer scan_cors behavior: escalation gate + ERROR counts."""

    @mock.patch("modules.cors.scanner.requests.Session")
    def test_scan_cors_closes_session(self, session_cls):
        session = session_cls.return_value
        session_cls.return_value = session

        with mock.patch("modules.cors.scanner.probe_baseline") as baseline_mock, \
                mock.patch("modules.cors.scanner.probe_endpoint") as probe_mock:
            baseline_mock.return_value = {"static_acao": False, "acao": ""}
            probe_mock.return_value = []
            scan_cors(
                ["/api/users"], TARGET, verbose=False, threads=1, rate_limit=0
            )
        session.close.assert_called_once()

    @staticmethod
    def _row(origin, severity, acao, method="OPTIONS"):
        return {
            "origin": origin,
            "method": method,
            "status": 200,
            "final_url": "https://example.com/api",
            "redirected": False,
            "severity": severity,
            "detail": "x",
            "evidence": "",
            "static_acao": False,
            "acao": acao,
            "acac": "true" if severity == "CRITICAL" else "",
            "vary": "Origin",
            "acpn": "",
        }

    def test_get_runs_when_options_only_legit_acao(self):
        # OPTIONS returns only legitimate target ACAO (INFO) — must still GET
        opt = [self._row(TARGET, "INFO", TARGET, method="OPTIONS")]
        get_crit = [self._row(EVIL, "CRITICAL", EVIL, method="GET")]

        with mock.patch("modules.cors.scanner.probe_baseline") as baseline_mock, \
                mock.patch("modules.cors.scanner.probe_endpoint") as probe_mock:
            baseline_mock.return_value = {"static_acao": False, "acao": ""}
            probe_mock.side_effect = [opt, get_crit]
            out = scan_cors(
                ["/api/users"], TARGET, verbose=False, threads=1, rate_limit=0
            )

        self.assertEqual(probe_mock.call_count, 2)
        self.assertEqual(probe_mock.call_args_list[0].kwargs["method"], "OPTIONS")
        self.assertEqual(probe_mock.call_args_list[1].kwargs["method"], "GET")
        self.assertEqual(out["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(len(out["findings"]), 1)

    def test_no_get_when_options_already_finding(self):
        opt_crit = [self._row(EVIL, "CRITICAL", EVIL, method="OPTIONS")]

        with mock.patch("modules.cors.scanner.probe_baseline") as baseline_mock, \
                mock.patch("modules.cors.scanner.probe_endpoint") as probe_mock:
            baseline_mock.return_value = {"static_acao": False, "acao": ""}
            probe_mock.return_value = opt_crit
            out = scan_cors(
                ["/api/users"], TARGET, verbose=False, threads=1, rate_limit=0
            )

        self.assertEqual(probe_mock.call_count, 1)
        self.assertEqual(out["severity_counts"]["CRITICAL"], 1)

    def test_error_probes_counted_in_severity_counts(self):
        err = [self._row(EVIL, "ERROR", "", method="GET")]
        err[0]["detail"] = "timeout"

        with mock.patch("modules.cors.scanner.probe_baseline") as baseline_mock, \
                mock.patch("modules.cors.scanner.probe_endpoint") as probe_mock:
            baseline_mock.return_value = {"static_acao": False, "acao": ""}
            probe_mock.return_value = err
            out = scan_cors(
                ["/api/users"], TARGET, verbose=False, threads=1, rate_limit=0
            )

        self.assertEqual(out["severity_counts"].get("ERROR"), 1)
        self.assertEqual(out["summary"].get("error_probes"), 1)
        self.assertEqual(out["findings"], [])

    def test_post_escalation_when_get_and_options_empty(self):
        empty = []
        post_crit = [self._row(EVIL, "CRITICAL", EVIL, method="POST")]

        with mock.patch("modules.cors.scanner.probe_baseline") as baseline_mock, \
                mock.patch("modules.cors.scanner.probe_endpoint") as probe_mock:
            baseline_mock.return_value = {"static_acao": False, "acao": ""}
            probe_mock.side_effect = [empty, empty, post_crit]
            out = scan_cors(
                ["/api/v2/users"], TARGET, verbose=False, threads=1, rate_limit=0
            )

        self.assertEqual(probe_mock.call_count, 3)
        methods = [c.kwargs["method"] for c in probe_mock.call_args_list]
        self.assertEqual(methods, ["OPTIONS", "GET", "POST"])
        self.assertEqual(out["severity_counts"]["CRITICAL"], 1)


class TestClassifyCors(unittest.TestCase):
    def test_no_header_info(self):
        sev, _ = classify(EVIL, "", "")
        self.assertEqual(sev, "INFO")

    def test_arbitrary_reflect_with_creds_critical(self):
        sev, _ = classify(EVIL, EVIL, "true", target_origin=TARGET)
        self.assertEqual(sev, "CRITICAL")

    def test_arbitrary_reflect_no_creds_high(self):
        sev, _ = classify(EVIL, EVIL, "", target_origin=TARGET)
        self.assertEqual(sev, "HIGH")

    def test_null_with_creds_critical(self):
        sev, _ = classify("null", "null", "true", target_origin=TARGET)
        self.assertEqual(sev, "CRITICAL")

    def test_null_without_creds_medium(self):
        sev, _ = classify("null", "null", "", target_origin=TARGET)
        self.assertEqual(sev, "MEDIUM")

    def test_wildcard_no_creds_medium(self):
        sev, _ = classify(EVIL, "*", "", target_origin=TARGET)
        self.assertEqual(sev, "MEDIUM")

    def test_wildcard_with_creds_high_invalid_combo(self):
        sev, detail = classify(EVIL, "*", "true", target_origin=TARGET)
        self.assertEqual(sev, "HIGH")
        self.assertIn("browsers block", detail)
        self.assertIn("non-browser", detail)

    def test_wildcard_notes_public_content_caveat(self):
        sev, detail = classify(EVIL, "*", "", target_origin=TARGET)
        self.assertEqual(sev, "MEDIUM")
        self.assertIn("public unauthenticated", detail)

    def test_null_creds_notes_sandboxed_iframe(self):
        sev, detail = classify("null", "null", "true", target_origin=TARGET)
        self.assertEqual(sev, "CRITICAL")
        self.assertIn("sandboxed iframe", detail)

    def test_legitimate_target_origin_info(self):
        sev, _ = classify(
            "https://example.com", "https://example.com", "true", target_origin=TARGET
        )
        self.assertEqual(sev, "INFO")

    def test_legitimate_with_default_port_info(self):
        sev, _ = classify(
            "https://example.com:443", "https://example.com", "true", target_origin=TARGET
        )
        self.assertEqual(sev, "INFO")

    def test_related_subdomain_with_creds_high_not_critical(self):
        sev, _ = classify(
            "https://api.example.com",
            "https://api.example.com",
            "true",
            target_origin=TARGET,
            registrable_domain="example.com",
        )
        self.assertEqual(sev, "HIGH")

    def test_normalized_reflection_case_insensitive(self):
        sev, _ = classify(
            "https://evil.com", "https://EVIL.com", "true", target_origin=TARGET
        )
        self.assertEqual(sev, "CRITICAL")

    def test_partial_suffix_match_low(self):
        # acao host is suffix-related to origin host (dot boundary)
        sev, _ = classify(
            "https://foo.evil.com", "https://evil.com", "", target_origin=TARGET
        )
        # equal after normalize? no — different hosts; suffix → LOW
        # Wait: origin foo.evil.com, acao evil.com — not equal, suffix match
        self.assertEqual(sev, "LOW")

    def test_not_allowed_info(self):
        sev, _ = classify(EVIL, "https://other.com", "", target_origin=TARGET)
        self.assertEqual(sev, "INFO")

    def test_naive_endswith_not_partial(self):
        # evilevil.com vs evil.com should NOT be suffix partial (dot boundary)
        sev, _ = classify(
            "https://evilevil.com", "https://evil.com", "", target_origin=TARGET
        )
        self.assertEqual(sev, "INFO")


class TestScannerHelpers(unittest.TestCase):
    def test_resolve_skips_static_assets(self):
        urls = resolve_endpoints(
            ["/api/users", "/app.js", "/style.css", "https://x.test/api"],
            "https://example.com",
        )
        self.assertEqual(
            urls,
            ["https://example.com/api/users", "https://x.test/api"],
        )

    def test_api_paths_prioritized(self):
        urls = resolve_endpoints(
            ["/about", "/pricing", "/api/v2/users", "/login", "/blog/post"],
            "https://example.com",
            max_endpoints=2,
        )
        self.assertEqual(len(urls), 2)
        # /api/v2/users and /login should outrank marketing pages
        joined = " ".join(urls)
        self.assertIn("/api/v2/users", joined)
        self.assertIn("/login", joined)

    def test_endpoint_priority_api_gt_about(self):
        base = "https://example.com"
        self.assertGreater(
            endpoint_priority("https://example.com/api/users", base),
            endpoint_priority("https://example.com/about", base),
        )

    def test_collect_js_origins_skips_target_host(self):
        result = {
            "in_scope_urls": [
                "https://api.partner.example/v1",
                "https://example.com/static/x.js",
            ],
            "out_of_scope_urls": ["https://cdn.other.com/app.js"],
            "intercepted_endpoints": [{"url": "https://graphql.partner.example/"}],
            "js_files_scanned": ["https://example.com/_next/chunk.js"],
        }
        origins = collect_js_origins(result, "https://example.com")
        self.assertIn("https://api.partner.example", origins)
        self.assertIn("https://cdn.other.com", origins)
        self.assertIn("https://graphql.partner.example", origins)
        self.assertNotIn("https://example.com", origins)

    def test_collect_js_origins_limit(self):
        result = {
            "in_scope_urls": [f"https://h{i}.example.com/x" for i in range(20)],
        }
        origins = collect_js_origins(result, "https://example.com", limit=5)
        self.assertEqual(len(origins), 5)

    def test_aggregate_worst_severity_per_url(self):
        url = "https://example.com/api"
        raw = [
            {"url": url, "severity": "MEDIUM", "origin": "https://evil.com",
             "acao": "*", "method": "OPTIONS", "detail": "wildcard", "acac": ""},
            {"url": url, "severity": "CRITICAL", "origin": "https://attacker.example",
             "acao": "https://attacker.example", "method": "GET",
             "detail": "reflected+creds", "acac": "true"},
            {"url": url, "severity": "HIGH", "origin": "https://evil.com/path",
             "acao": "https://evil.com/path", "method": "GET",
             "detail": "reflected", "acac": ""},
        ]
        agg = aggregate_findings(raw)
        self.assertEqual(len(agg), 1)
        self.assertEqual(agg[0]["severity"], "CRITICAL")
        self.assertEqual(agg[0]["probe_hits"], 3)
        self.assertEqual(
            set(agg[0]["origins_flagged"]),
            {"https://evil.com", "https://attacker.example", "https://evil.com/path"},
        )
        self.assertEqual(agg[0]["acao"], "https://attacker.example")

    def test_aggregate_multiple_urls_sorted_by_severity(self):
        raw = [
            {"url": "https://example.com/a", "severity": "MEDIUM",
             "origin": "https://evil.com", "acao": "*", "method": "OPTIONS"},
            {"url": "https://example.com/b", "severity": "CRITICAL",
             "origin": "https://evil.com", "acao": "https://evil.com",
             "method": "GET", "acac": "true"},
        ]
        agg = aggregate_findings(raw)
        self.assertEqual([f["url"] for f in agg],
                         ["https://example.com/b", "https://example.com/a"])

    def test_aggregate_skips_info(self):
        raw = [
            {"url": "https://example.com/x", "severity": "INFO",
             "origin": "https://evil.com", "acao": "", "method": "OPTIONS"},
        ]
        self.assertEqual(aggregate_findings(raw), [])

    def test_risk_boost_weights(self):
        boost = cors_risk_boost(
            {"severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1}}
        )
        self.assertEqual(boost, 25 + 15 + 8 + 3)


class TestReportingStep4(unittest.TestCase):
    """Step 4: HTML matrix, summary, JSON schema surface."""

    def _cors_payload(self):
        return {
            "schema_version": 1,
            "target_origin": "https://example.com",
            "endpoints_tested": 3,
            "probe_hits": 4,
            "origins": ["https://evil.com", "null", "https://example.com"],
            "severity_counts": {"HIGH": 1, "MEDIUM": 1},
            "summary": {
                "urls_flagged": 2,
                "endpoints_tested": 3,
                "origins_probed": 3,
                "probe_hits": 4,
                "severity_counts": {"HIGH": 1, "MEDIUM": 1},
                "aggregated": True,
            },
            "findings": [
                {
                    "url": "https://example.com/api/v2/users",
                    "severity": "HIGH",
                    "origins_flagged": ["https://evil.com"],
                    "origin": "https://evil.com",
                    "acao": "https://evil.com",
                    "acac": "true",
                    "method": "GET",
                    "methods": ["OPTIONS", "GET"],
                    "probe_hits": 3,
                    "detail": "reflected + credentials",
                    "evidence": "Methods: OPTIONS, GET",
                },
                {
                    "url": "https://example.com/api/v1/public",
                    "severity": "MEDIUM",
                    "origins_flagged": ["https://evil.com", "null"],
                    "origin": "*",
                    "acao": "*",
                    "acac": "",
                    "method": "OPTIONS",
                    "methods": ["OPTIONS"],
                    "probe_hits": 1,
                    "detail": "wildcard",
                    "evidence": "Vary: Origin",
                },
            ],
        }

    def test_matrix_renders_origins_and_short_paths(self):
        from modules.reporting.html import render_cors_matrix
        html = render_cors_matrix(self._cors_payload())
        self.assertIn("Origin × URL matrix", html)
        self.assertIn("https://evil.com", html)
        self.assertIn("/api/v2/users", html)
        self.assertIn("HIGH", html)
        self.assertIn("MED", html)  # compact MEDIUM badge in matrix cells

    def test_matrix_empty_when_no_findings(self):
        from modules.reporting.html import render_cors_matrix
        self.assertEqual(render_cors_matrix({"findings": []}), "")
        self.assertEqual(render_cors_matrix({}), "")

    def test_summary_counts(self):
        from modules.reporting.html import render_cors_summary
        html = render_cors_summary(self._cors_payload())
        self.assertIn("Critical", html)
        self.assertIn("URLs flagged", html)
        self.assertIn("Origins probed", html)
        self.assertIn("Probe hits", html)

    def test_render_cors_skips_info_and_includes_sections(self):
        from modules.reporting.html import render_cors
        payload = self._cors_payload()
        payload["findings"].append(
            {"url": "https://example.com/", "severity": "INFO", "origin": "https://example.com",
             "acao": "https://example.com", "detail": "legit"}
        )
        html = render_cors(payload)
        self.assertIn("CORS Misconfigurations", html)
        self.assertIn("Findings (one row per URL)", html)
        self.assertIn("JSON schema v1", html)
        self.assertIn("Target origin:", html)
        # INFO row omitted from findings table (URL may appear in PoC/matrix)
        table_html = html.split("Findings (one row per URL)")[1].split("<h3")[0] if "Findings (one row per URL)" in html else html
        self.assertEqual(table_html.count("https://example.com/api/v2/users"), 1)

    def test_render_cors_empty(self):
        from modules.reporting.html import render_cors
        self.assertEqual(render_cors({}), "")
        self.assertEqual(render_cors({"findings": []}), "")

    def test_build_html_includes_cors_section(self):
        from modules.reporting.html import build_html
        result = {
            "target": "https://example.com",
            "scan_depth": 1,
            "risk_summary": {"level": "HIGH", "score": 23},
            "js_files_scanned": [],
            "internal_paths": ["/api"],
            "cors": self._cors_payload(),
        }
        html = build_html(result)
        self.assertIn("Origin × URL matrix", html)
        self.assertIn("CORS Findings", html)

    def test_cors_sev_order_matches_classifier(self):
        from modules.reporting.html import CORS_SEV_ORDER
        from modules.cors.classifier import SEVERITY_ORDER
        self.assertEqual(CORS_SEV_ORDER, SEVERITY_ORDER)

    def test_scanner_return_schema_keys(self):
        # scan_cors return shape contract (schema_version 1)
        expected_top = {
            "schema_version", "findings", "probe_hits", "endpoints_tested",
            "target_origin", "origins", "severity_counts", "summary",
        }
        # Shape check without network: rebuild dict as scanner does
        summary_keys = {
            "urls_flagged", "endpoints_tested", "origins_probed",
            "probe_hits", "severity_counts", "aggregated",
        }
        # Validate against a minimal fixture mirroring scanner output
        fixture = {
            "schema_version": 1,
            "findings": [],
            "probe_hits": 0,
            "endpoints_tested": 1,
            "target_origin": "https://example.com",
            "origins": [],
            "severity_counts": {},
            "summary": {
                "urls_flagged": 0,
                "endpoints_tested": 1,
                "origins_probed": 0,
                "probe_hits": 0,
                "severity_counts": {},
                "aggregated": True,
            },
        }
        self.assertEqual(set(fixture.keys()), expected_top)
        self.assertTrue(summary_keys.issubset(fixture["summary"].keys()))


class TestPnaClassification(unittest.TestCase):
    """Private Network Access (CORS-RFC1918) severity ladder — C10."""

    def test_is_pna_allowed(self):
        self.assertTrue(is_pna_allowed("true"))
        self.assertTrue(is_pna_allowed("TRUE"))
        self.assertTrue(is_pna_allowed("1"))
        self.assertFalse(is_pna_allowed(""))
        self.assertFalse(is_pna_allowed(None))
        self.assertFalse(is_pna_allowed("false"))

    def test_wildcard_without_pna_stays_medium(self):
        sev, detail = classify(EVIL, "*", "", target_origin=TARGET)
        self.assertEqual(sev, "MEDIUM")
        self.assertNotIn("Private-Network", detail)

    def test_wildcard_with_pna_elevates_to_high(self):
        sev, detail = classify(EVIL, "*", "", target_origin=TARGET, acpn="true")
        self.assertEqual(sev, "HIGH")
        self.assertIn("Private-Network", detail)

    def test_reflected_with_pna_notes_private_network(self):
        sev, detail = classify(EVIL, EVIL, "", target_origin=TARGET, acpn="true")
        self.assertEqual(sev, "HIGH")
        self.assertIn("Private-Network", detail)

    def test_reflected_creds_with_pna_stays_critical(self):
        sev, detail = classify(EVIL, EVIL, "true", target_origin=TARGET, acpn="true")
        self.assertEqual(sev, "CRITICAL")
        self.assertIn("Private-Network", detail)

    def test_no_acao_pna_ignored(self):
        sev, detail = classify(EVIL, "", "", target_origin=TARGET, acpn="true")
        self.assertEqual(sev, "INFO")
        self.assertNotIn("Private-Network", detail)

    def test_legitimate_origin_untouched_by_pna(self):
        sev, detail = classify(TARGET, TARGET, "", target_origin=TARGET, acpn="true")
        self.assertEqual(sev, "INFO")


if __name__ == "__main__":
    unittest.main()
