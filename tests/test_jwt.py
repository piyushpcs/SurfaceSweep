"""Unit tests for Phase 3 JWT (Steps 1–5: decode, crack, analysis, offline
hardening, pipeline wiring, cracking, reporting parity, risk boost)."""

import base64
import json
import time
import unittest

from modules.extraction.risk import calculate_risk_summary, risk_level_for_score
from modules.jwt_analyzer import (
    analyze_jwt,
    analyze_result_jwts,
    build_crack_candidates,
    collect_candidate_secrets,
    collect_jwts_from_result,
    decode_jwt,
    deduplicate_jwts,
    export_hashcat,
    export_jwt_findings,
    extract_jwts,
    jwt_risk_boost,
    load_wordlist,
    target_mutations,
    verify_hs_signature,
)

# alg=none (unsecured) — CRITICAL
JWT_NONE = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0."
)

# HS256 signed with secret "secret" — cracked CRITICAL
# header: {"alg":"HS256","typ":"JWT"}
# payload: {"sub":"user1","role":"admin","exp":4102444800}
# Generated offline: HMAC-SHA256(header.payload, key=b"secret")
JWT_HS256_SECRET = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJhZG1pbiIsImV4cCI6NDEwMjQ0NDgwMH0."
    "6d6jBoiv2f2mca1EaibKvh0xhMjOdVXD7cB0jgbEfeI"
)

# HS256 with kid path traversal + weak secret "secret"
JWT_KID_TRAVERSAL = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ."
    "eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJhZG1pbiIsImV4cCI6NDEwMjQ0NDgwMH0."
    "37v4b22djkCt_PFJq-b2KgRj-bTLlT_X5vcxZ85rVPE"
)

# RS256 missing exp — INFO + MEDIUM
JWT_RS256_NO_EXP = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ0ZXN0Iiwic2NvcGUiOiJhZG1pbiB3cml0ZSJ9."
    "c2lnbmF0dXJl"
)

# RS256 with jku URL header
JWT_JKU = (
    "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZXZpbC5jb20vandrcy5qc29uIn0."
    "eyJzdWIiOiJ0ZXN0IiwiZXhwIjo0MTAyNDQ0ODAwfQ."
    "c2ln"
)


def _b64url(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_jwt(header_obj, payload_obj, signature="c2ln"):
    """Build a compact JWT for fixture purposes (signature need not verify)."""
    h = _b64url(json.dumps(header_obj, separators=(",", ":")))
    p = _b64url(json.dumps(payload_obj, separators=(",", ":")))
    return f"{h}.{p}.{signature}"


def _now():
    return time.time()


class TestDecodeJwt(unittest.TestCase):
    def test_decode_header_and_payload(self):
        d = decode_jwt(JWT_HS256_SECRET)
        self.assertNotIn("error", d)
        self.assertEqual(d["alg"], "HS256")
        self.assertEqual(d["payload"]["sub"], "user1")
        self.assertEqual(d["parts"], 3)

    def test_decode_alg_none_empty_signature(self):
        d = decode_jwt(JWT_NONE)
        self.assertNotIn("error", d)
        self.assertEqual(d["alg"].lower(), "none")
        self.assertEqual(d["signature"], "")
        self.assertEqual(d["parts"], 3)

    def test_error_not_compact(self):
        self.assertIn("error", decode_jwt("not-a-jwt"))
        self.assertIn("error", decode_jwt(""))

    def test_error_invalid_header(self):
        self.assertIn("error", decode_jwt("!!!.payload.sig"))


class TestExtractJwts(unittest.TestCase):
    def test_finds_token_in_free_text(self):
        content = f'var t = "{JWT_HS256_SECRET}";'
        found = extract_jwts(content, source_label="app.js")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["token"], JWT_HS256_SECRET)
        self.assertEqual(found[0]["source"], "app.js")

    def test_dedupes(self):
        content = f"{JWT_HS256_SECRET} {JWT_HS256_SECRET}"
        self.assertEqual(len(extract_jwts(content)), 1)

    def test_empty_content(self):
        self.assertEqual(extract_jwts(""), [])
        self.assertEqual(extract_jwts(None), [])


class TestVerifyHsSignature(unittest.TestCase):
    def test_correct_secret(self):
        self.assertTrue(verify_hs_signature(JWT_HS256_SECRET, "secret"))

    def test_wrong_secret(self):
        self.assertFalse(verify_hs_signature(JWT_HS256_SECRET, "wrong"))

    def test_rs256_unsupported_returns_none(self):
        self.assertIsNone(verify_hs_signature(JWT_RS256_NO_EXP, "secret"))

    def test_malformed_returns_none(self):
        self.assertIsNone(verify_hs_signature("bad", "secret"))


class TestAnalyzeJwt(unittest.TestCase):
    def test_alg_none_critical(self):
        a = analyze_jwt(JWT_NONE, source="testbed")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("alg_none", issues)
        self.assertEqual(a["severity"], "CRITICAL")
        self.assertEqual(a["alg"].lower(), "none")

    def test_weak_hmac_cracked(self):
        a = analyze_jwt(JWT_HS256_SECRET, source="testbed")
        self.assertEqual(a["cracked_secret"], "secret")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("weak_hmac_secret", issues)
        self.assertEqual(a["severity"], "CRITICAL")

    def test_kid_path_traversal_high(self):
        a = analyze_jwt(JWT_KID_TRAVERSAL, source="testbed")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("kid_path_traversal", issues)
        self.assertEqual(a["cracked_secret"], "secret")
        self.assertEqual(a["severity"], "CRITICAL")

    def test_rs256_asymmetric_info_plus_missing_exp(self):
        a = analyze_jwt(JWT_RS256_NO_EXP, source="testbed")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("asymmetric_alg", issues)
        self.assertIn("missing_exp", issues)
        self.assertEqual(a["severity"], "MEDIUM")

    def test_jku_url_flagged_high(self):
        a = analyze_jwt(JWT_JKU, source="testbed")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("jku_header_url", issues)

    def test_sensitive_claims_admin(self):
        a = analyze_jwt(JWT_HS256_SECRET, source="t", candidate_secrets=["nope"])
        issues = [f["issue"] for f in a["findings"]]
        self.assertIn("sensitive_claims", issues)

    def test_expired_info(self):
        # exp in the past
        past = analyze_jwt(
            "eyJhbGciOiJub25lIn0.eyJleHAiOjF9.",
            source="t",
            now=_now(),
        )
        issues = {f["issue"] for f in past["findings"]}
        self.assertIn("alg_none", issues)
        self.assertIn("expired", issues)

    def test_malformed_low(self):
        a = analyze_jwt("garbage", source="t")
        self.assertEqual(a["severity"], "LOW")
        self.assertEqual(a["findings"][0]["issue"], "malformed_jwt")

    def test_long_token_truncated_in_output(self):
        long_tok = JWT_HS256_SECRET + "A" * 600
        a = analyze_jwt(long_tok, source="t")
        self.assertTrue(a["token"].endswith("…"))
        self.assertLessEqual(len(a["token"]), 501)


class TestOfflineHardening(unittest.TestCase):
    """Step 2: stronger offline checks."""

    def test_embedded_jwk_object_high(self):
        tok = _make_jwt(
            {"alg": "RS256", "typ": "JWT", "jwk": {"kty": "RSA", "n": "x", "e": "AQAB"}},
            {"sub": "t", "exp": 4102444800},
        )
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("embedded_jwk", issues)
        self.assertEqual(a["severity"], "HIGH")

    def test_jwk_string_still_url_finding(self):
        tok = _make_jwt(
            {"alg": "RS256", "jwk": "https://evil.example/jwk.json"},
            {"sub": "t", "exp": 4102444800},
        )
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("jwk_header_url", issues)
        self.assertNotIn("embedded_jwk", issues)

    def test_x5c_header_chain_high(self):
        tok = _make_jwt(
            {"alg": "RS256", "x5c": ["MIIDdzCCAl8gAwIBAgIEb0..."]},
            {"sub": "t", "exp": 4102444800},
        )
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("x5c_header_chain", issues)
        self.assertEqual(a["severity"], "HIGH")

    def test_crit_header_medium(self):
        tok = _make_jwt(
            {"alg": "RS256", "crit": ["exp"], "exp": True},
            {"sub": "t", "exp": 4102444800},
        )
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("crit_header", issues)
        finding = next(f for f in a["findings"] if f["issue"] == "crit_header")
        self.assertEqual(finding["severity"], "MEDIUM")

    def test_empty_signature_critical(self):
        # HS256 header + payload, no signature segment content
        tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "t", "exp": 4102444800}, signature="")
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("empty_signature", issues)
        self.assertEqual(a["severity"], "CRITICAL")

    def test_alg_none_empty_signature_not_flagged_as_empty(self):
        a = analyze_jwt(JWT_NONE, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertNotIn("empty_signature", issues)
        self.assertNotIn("alg_none_with_signature", issues)

    def test_alg_none_with_leftover_signature(self):
        tok = _make_jwt(
            {"alg": "none", "typ": "JWT"},
            {"sub": "t", "exp": 4102444800},
            signature="c2ln",
        )
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("alg_none_with_signature", issues)
        self.assertIn("alg_none", issues)

    def test_kid_sqli_high(self):
        tok = _make_jwt(
            {"alg": "HS256", "kid": "admin'--"},
            {"sub": "t", "exp": 4102444800},
            signature="c2ln",
        )
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("kid_sqli", issues)
        self.assertIn("low_entropy_signature", issues)
        self.assertEqual(a["severity"], "HIGH")

    def test_kid_union_keyword(self):
        tok = _make_jwt(
            {"alg": "HS256", "kid": "1 UNION SELECT password FROM users"},
            {"sub": "t", "exp": 4102444800},
            signature="c2ln",
        )
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("kid_sqli", issues)

    def test_missing_iss_aud_low(self):
        a = analyze_jwt(JWT_HS256_SECRET, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("missing_iss_aud", issues)

    def test_present_iss_aud_no_finding(self):
        tok = _make_jwt(
            {"alg": "RS256"},
            {"sub": "t", "iss": "https://auth.example", "aud": "api", "exp": 4102444800},
            signature="c2ln",
        )
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertNotIn("missing_iss_aud", issues)

    def test_low_entropy_signature_medium(self):
        # "c2ln" decodes to "sig" — placeholder
        a = analyze_jwt(JWT_RS256_NO_EXP, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("low_entropy_signature", issues)

    def test_real_hmac_signature_not_placeholder(self):
        a = analyze_jwt(JWT_HS256_SECRET, source="t", candidate_secrets=[])
        issues = {f["issue"] for f in a["findings"]}
        self.assertNotIn("low_entropy_signature", issues)

    def test_high_entropy_claim_medium(self):
        secret_val = "a3f9c8e2b1d4f6a7c9e0b2d4f6a8c1e3A3F9C8E2"
        tok = _make_jwt(
            {"alg": "RS256"},
            {"sub": "t", "api_key": secret_val, "exp": 4102444800},
            signature="c2ln",
        )
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertIn("high_entropy_claim", issues)
        finding = next(f for f in a["findings"] if f["issue"] == "high_entropy_claim")
        self.assertIn("api_key", finding["detail"])

    def test_standard_claims_not_flagged_as_high_entropy(self):
        tok = _make_jwt(
            {"alg": "RS256"},
            {
                "sub": "a3f9c8e2b1d4f6a7c9e0b2d4f6a8c1e3",
                "jti": "a3f9c8e2b1d4-f6a7-c9e0-b2d4f6a8c1e3",
                "iss": "https://auth.example",
                "aud": "api",
                "exp": 4102444800,
            },
            signature="c2ln",
        )
        a = analyze_jwt(tok, source="t")
        issues = {f["issue"] for f in a["findings"]}
        self.assertNotIn("high_entropy_claim", issues)


class TestExtractionWiring(unittest.TestCase):
    """Step 3: extract_from_text / merge_results populate jwts_found."""

    def test_extract_from_text_returns_jwts(self):
        from modules.extraction.engine import extract_from_text
        content = f'var t = "{JWT_HS256_SECRET}"; fetch("/api/v1/users");'
        eps, secrets, _, sinks, internal, jwts = extract_from_text(
            content, "app.js", do_deobfuscate=False, use_ast=False
        )
        self.assertEqual(len(jwts), 1)
        self.assertEqual(jwts[0]["token"], JWT_HS256_SECRET)
        self.assertEqual(jwts[0]["source"], "app.js")
        # JWT also present in secrets (type JWT)
        self.assertTrue(any(s["type"] == "JWT" for s in secrets))

    def test_extract_from_text_no_jwt(self):
        from modules.extraction.engine import extract_from_text
        eps, _, _, _, _, jwts = extract_from_text(
            'fetch("/api");', "x.js", do_deobfuscate=False, use_ast=False
        )
        self.assertEqual(jwts, [])

    def test_deduplicate_jwts_first_source_wins(self):
        out = deduplicate_jwts([
            {"token": "aaa.bbb.ccc", "source": "a.js"},
            {"token": "aaa.bbb.ccc", "source": "b.js"},
            {"token": "ddd.eee.fff", "source": "c.js"},
        ])
        self.assertEqual(len(out), 2)
        by_token = {j["token"]: j for j in out}
        self.assertEqual(by_token["aaa.bbb.ccc"]["source"], "a.js")
        self.assertEqual(by_token["ddd.eee.fff"]["source"], "c.js")

    def test_deduplicate_jwts_empty(self):
        self.assertEqual(deduplicate_jwts([]), [])
        self.assertEqual(deduplicate_jwts(None), [])

    def test_merge_results_merges_jwts(self):
        from modules.extraction.engine import merge_results
        static = {
            "target": "https://example.com",
            "jwts_found": [{"token": JWT_NONE, "source": "a.js"}],
        }
        browser = {
            "target": "https://example.com",
            "jwts_found": [
                {"token": JWT_NONE, "source": "b.js"},  # duplicate token
                {"token": JWT_HS256_SECRET, "source": "c.js"},
            ],
        }
        merged = merge_results(static, browser)
        tokens = {j["token"] for j in merged["jwts_found"]}
        self.assertEqual(len(merged["jwts_found"]), 2)
        self.assertIn(JWT_NONE, tokens)
        self.assertIn(JWT_HS256_SECRET, tokens)
        # first source wins for the duplicate
        none_entry = next(j for j in merged["jwts_found"] if j["token"] == JWT_NONE)
        self.assertEqual(none_entry["source"], "a.js")

    def test_collect_prefers_jwts_found_over_truncated_secret(self):
        # jwts_found holds the full token; secrets may be truncated elsewhere
        result = {
            "secrets_found": [],
            "jwts_found": [{"token": JWT_KID_TRAVERSAL, "source": "inline"}],
        }
        tokens = collect_jwts_from_result(result)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0]["token"], JWT_KID_TRAVERSAL)
        out = analyze_result_jwts(result, verbose=False)
        self.assertEqual(out["tokens_analyzed"], 1)
        self.assertEqual(out["findings"][0]["cracked_secret"], "secret")


class TestCrackingStep4(unittest.TestCase):
    """Step 4: wordlist, target mutations, hashcat export."""

    def test_load_wordlist_skips_blanks_and_comments(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# comment\n\nsecret1\n  secret2  \n")
            path = fh.name
        try:
            out = load_wordlist(path)
            self.assertEqual(out, ["secret1", "secret2"])
        finally:
            os.unlink(path)

    def test_load_wordlist_missing_file(self):
        self.assertEqual(load_wordlist("/nonexistent/wordlist.txt"), [])

    def test_target_mutations_from_host(self):
        muts = target_mutations("https://app.example.com/login")
        self.assertIn("example", muts)
        self.assertIn("app", muts)
        self.assertIn("examplesecret", muts)
        self.assertIn("appexample", muts)

    def test_target_mutations_empty(self):
        self.assertEqual(target_mutations(""), [])
        self.assertEqual(target_mutations(None), [])

    def test_build_crack_candidates_combines_sources(self):
        result = {"secrets_found": [{"type": "Generic Secret", "match": "scansecret99"}]}
        cands, meta = build_crack_candidates(
            result, wordlist_path=None, target="https://foo.example.com"
        )
        self.assertIn("secret", cands)          # builtin
        self.assertIn("scansecret99", cands)     # scan
        self.assertIn("example", cands)          # mutation
        # total is after dedup — may be < sum of parts if sources overlap
        self.assertLessEqual(meta["total"], meta["builtin"] + meta["scan_secrets"] + meta["target_mutations"])
        self.assertGreaterEqual(meta["total"], meta["builtin"])
        self.assertEqual(len(cands), len(set(cands)))

    def test_analyze_with_target_mutations_cracks(self):
        # Sign with a target-derived secret not in the builtin list
        import base64, hashlib, hmac, json as _json
        header = base64.urlsafe_b64encode(
            _json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            _json.dumps({"sub": "u", "exp": 4102444800}, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        sig = hmac.new(b"examplesecret", f"{header}.{payload}".encode(), hashlib.sha256).digest()
        tok = f"{header}.{payload}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

        a = analyze_jwt(tok, source="t", candidate_secrets=target_mutations("https://x.example.com"))
        self.assertEqual(a["cracked_secret"], "examplesecret")

    def test_export_hashcat_hs_only(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("r", suffix=".txt", delete=False) as fh:
            path = fh.name
        try:
            n = export_hashcat([JWT_HS256_SECRET, JWT_RS256_NO_EXP, "garbage"], path)
            self.assertEqual(n, 1)  # only HS256 written
            with open(path) as fh2:
                lines = [l.strip() for l in fh2 if l.strip()]
            self.assertEqual(lines, [JWT_HS256_SECRET])
        finally:
            os.unlink(path)

    def test_analyze_result_jwts_hashcat_export(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("r", suffix=".txt", delete=False) as fh:
            path = fh.name
        try:
            result = {
                "secrets_found": [
                    {"type": "JWT", "match": JWT_HS256_SECRET, "sources": ["a"]},
                ]
            }
            out = analyze_result_jwts(
                result, verbose=False,
                wordlist_path=None,
                target="https://example.com",
                hashcat_path=path,
            )
            self.assertEqual(out["hashcat_exported"], 1)
            self.assertIn("crack_meta", out)
            self.assertIn("total", out["crack_meta"])
        finally:
            os.unlink(path)


class TestReportingStep5(unittest.TestCase):
    """Step 5: schema/summary, HTML escaping, severity cards, per-token export."""

    def test_empty_result_has_schema_and_summary(self):
        out = analyze_result_jwts({"secrets_found": []}, verbose=False)
        self.assertEqual(out["schema_version"], 1)
        self.assertIn("summary", out)
        self.assertEqual(out["summary"]["tokens_analyzed"], 0)
        self.assertIn("severity_counts", out["summary"])
        self.assertIn("issue_counts", out["summary"])

    def test_full_result_schema_and_summary(self):
        result = {
            "secrets_found": [
                {"type": "JWT", "match": JWT_NONE, "sources": ["a"]},
                {"type": "JWT", "match": JWT_HS256_SECRET, "sources": ["b"]},
            ]
        }
        out = analyze_result_jwts(result, verbose=False, target="https://example.com")
        self.assertEqual(out["schema_version"], 1)
        s = out["summary"]
        self.assertEqual(s["tokens_analyzed"], 2)
        self.assertEqual(s["severity_counts"], out["severity_counts"])
        self.assertGreaterEqual(s["cracked_secrets"], 1)  # "secret"
        self.assertGreaterEqual(s["candidate_secrets_tried"], 100)
        self.assertIn("alg_none", s["issue_counts"])

    def test_html_escapes_payload_and_detail(self):
        from modules.reporting.html import render_jwt
        evil = {
            "schema_version": 1,
            "tokens_analyzed": 1,
            "severity_counts": {"HIGH": 1},
            "summary": {"tokens_analyzed": 1, "severity_counts": {"HIGH": 1}},
            "findings": [{
                "severity": "HIGH",
                "alg": "RS256",
                "source": '<img src=x onerror=alert(1)>',
                "payload_summary": {"x": "<script>alert(1)</script>"},
                "cracked_secret": "</code><script>alert(2)</script>",
                "findings": [{
                    "severity": "HIGH",
                    "issue": "sensitive_claims",
                    "detail": 'role=<script>alert("xss")</script>',
                }],
            }],
        }
        html = render_jwt(evil)
        self.assertNotIn('<script>alert("xss")</script>', html)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("</code><script>alert(2)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_html_severity_cards(self):
        from modules.reporting.html import render_jwt
        result = {
            "schema_version": 1,
            "tokens_analyzed": 2,
            "severity_counts": {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 3},
            "summary": {
                "tokens_analyzed": 2,
                "severity_counts": {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 3},
                "cracked_secrets": 1,
                "candidate_secrets_tried": 134,
            },
            "findings": [{
                "severity": "CRITICAL",
                "alg": "HS256",
                "source": "a.js",
                "payload_summary": {},
                "cracked_secret": "secret",
                "findings": [{"severity": "CRITICAL", "issue": "alg_none", "detail": "x"}],
            }],
        }
        html = render_jwt(result)
        self.assertIn("Critical", html)
        self.assertIn("Tokens analyzed", html)
        self.assertIn("Secrets cracked", html)
        self.assertIn("Crack candidates", html)
        self.assertIn("JSON schema v1", html)

    def test_export_jwt_findings_ndjson(self):
        import tempfile, os
        result = {
            "secrets_found": [
                {"type": "JWT", "match": JWT_NONE, "sources": ["a"]},
                {"type": "JWT", "match": JWT_HS256_SECRET, "sources": ["b"]},
            ]
        }
        out = analyze_result_jwts(result, verbose=False)
        with tempfile.NamedTemporaryFile("r", suffix=".ndjson", delete=False) as fh:
            path = fh.name
        try:
            n = export_jwt_findings(out, path)
            self.assertEqual(n, 2)
            with open(path) as fh2:
                lines = [json.loads(l) for l in fh2 if l.strip()]
            self.assertEqual(len(lines), 2)
            self.assertTrue(all("findings" in l and "severity" in l for l in lines))
        finally:
            os.unlink(path)

    def test_analyze_result_jwts_export_path(self):
        import tempfile, os
        result = {
            "secrets_found": [{"type": "JWT", "match": JWT_NONE, "sources": ["a"]}],
        }
        with tempfile.NamedTemporaryFile("r", suffix=".ndjson", delete=False) as fh:
            path = fh.name
        try:
            out = analyze_result_jwts(result, verbose=False, export_path=path)
            self.assertEqual(out["findings_exported"], 1)
            self.assertEqual(out["summary"]["tokens_analyzed"], 1)
        finally:
            os.unlink(path)


class TestCollectHelpers(unittest.TestCase):
    def test_collect_candidate_secrets_skips_jwts_and_urls(self):
        result = {
            "secrets_found": [
                {"type": "JWT", "match": JWT_HS256_SECRET},
                {"type": "Generic Secret", "match": "s3cr3tvalue"},
                {"type": "URL", "match": "https://api.example.com/v1"},
                {"type": "Short", "match": "abc"},
            ]
        }
        cands = collect_candidate_secrets(result)
        self.assertIn("s3cr3tvalue", cands)
        self.assertNotIn(JWT_HS256_SECRET, cands)
        self.assertNotIn("https://api.example.com/v1", cands)
        self.assertNotIn("abc", cands)

    def test_collect_jwts_from_secrets_found(self):
        result = {
            "secrets_found": [
                {"type": "JWT", "match": JWT_HS256_SECRET, "sources": ["app.js"]},
                {"type": "Generic Secret", "match": "x"},
            ]
        }
        tokens = collect_jwts_from_result(result)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0]["token"], JWT_HS256_SECRET)
        self.assertEqual(tokens[0]["source"], "app.js")

    def test_collect_jwts_from_jwts_found(self):
        result = {"jwts_found": [{"token": JWT_NONE, "source": "inline"}]}
        tokens = collect_jwts_from_result(result)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0]["source"], "inline")


class TestAnalyzeResultJwts(unittest.TestCase):
    def test_empty_result_shape(self):
        out = analyze_result_jwts({"secrets_found": []}, verbose=False)
        self.assertEqual(out["tokens_analyzed"], 0)
        self.assertEqual(out["findings"], [])
        self.assertEqual(out["severity_counts"], {})
        self.assertIn("candidate_secrets_tried", out)

    def test_analyzes_jwt_secrets_and_sorts(self):
        result = {
            "secrets_found": [
                {"type": "JWT", "match": JWT_RS256_NO_EXP, "sources": ["a.js"]},
                {"type": "JWT", "match": JWT_NONE, "sources": ["a.js"]},
                {"type": "JWT", "match": JWT_HS256_SECRET, "sources": ["b.js"]},
            ]
        }
        out = analyze_result_jwts(result, verbose=False)
        self.assertEqual(out["tokens_analyzed"], 3)
        # Worst first: alg_none and weak_hmac are CRITICAL
        self.assertEqual(out["findings"][0]["severity"], "CRITICAL")
        self.assertIn("CRITICAL", out["severity_counts"])

    def test_cracks_with_scan_secret_candidate(self):
        result = {
            "secrets_found": [
                {"type": "JWT", "match": JWT_HS256_SECRET, "sources": ["a"]},
                {"type": "JWT Secret", "match": "not-the-secret-xx"},
            ]
        }
        # Built-in wordlist already has "secret"; ensure candidates path works
        out = analyze_result_jwts(result, verbose=False)
        self.assertEqual(out["findings"][0]["cracked_secret"], "secret")


class TestJwtRiskBoost(unittest.TestCase):
    def test_weights(self):
        boost = jwt_risk_boost(
            {"severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1}}
        )
        self.assertEqual(boost, 25 + 15 + 8 + 3)

    def test_info_zero(self):
        self.assertEqual(jwt_risk_boost({"severity_counts": {"INFO": 5}}), 0)

    def test_none_result(self):
        self.assertEqual(jwt_risk_boost(None), 0)
        self.assertEqual(jwt_risk_boost({}), 0)


class TestRiskBoostPreservation(unittest.TestCase):
    """Step 1: recalculation must not wipe CORS/JWT boosts."""

    def test_risk_level_for_score(self):
        self.assertEqual(risk_level_for_score(0), "INFO")
        self.assertEqual(risk_level_for_score(1), "LOW")
        self.assertEqual(risk_level_for_score(10), "MEDIUM")
        self.assertEqual(risk_level_for_score(30), "HIGH")

    def test_base_score_without_analysis(self):
        r = calculate_risk_summary({"internal_paths": ["/a", "/b"]})
        self.assertEqual(r["score"], 2)
        self.assertEqual(r["level"], "LOW")

    def test_jwt_boost_included_in_recalc(self):
        result = {
            "internal_paths": ["/api"],
            "jwt": {
                "severity_counts": {"CRITICAL": 1},
                "findings": [],
                "tokens_analyzed": 1,
            },
        }
        first = calculate_risk_summary(result)
        # base path (1) + CRITICAL jwt boost (25) = 26 → MEDIUM (>=10, <30)
        self.assertEqual(first["score"], 1 + 25)
        # Simulate validate/wayback full recalculation — boost must remain
        second = calculate_risk_summary(result)
        self.assertEqual(second["score"], first["score"])
        self.assertEqual(second["level"], "MEDIUM")

    def test_cors_boost_included_in_recalc(self):
        result = {
            "internal_paths": [],
            "cors": {
                "severity_counts": {"CRITICAL": 1, "MEDIUM": 1},
                "findings": [],
            },
        }
        r = calculate_risk_summary(result)
        self.assertEqual(r["score"], 25 + 8)
        self.assertEqual(r["level"], "HIGH")

    def test_validate_style_recalc_keeps_both_boosts(self):
        result = {
            "internal_paths": ["/a"],
            "cors": {"severity_counts": {"HIGH": 1}},
            "jwt": {"severity_counts": {"CRITICAL": 1}},
        }
        before = calculate_risk_summary(result)
        # Validation filters paths then recalculates
        result["internal_paths"] = []
        after = calculate_risk_summary(result)
        # Base path score dropped by 1; boosts retained
        self.assertEqual(after["score"], before["score"] - 1)
        self.assertEqual(after["score"], 15 + 25)
        self.assertEqual(after["level"], "HIGH")

    def test_empty_result_info(self):
        self.assertEqual(
            calculate_risk_summary({}),
            {"score": 0, "level": "INFO"},
        )


if __name__ == "__main__":
    unittest.main()
