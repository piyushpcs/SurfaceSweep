"""Unit tests for live secret verification (Phase F4)."""

import unittest
from argparse import Namespace
from unittest import mock

import requests

from modules.extraction.verify import (
    SKIP_TYPES,
    VERIFIERS,
    extract_credential,
    verify_secret,
    verify_secrets,
)
from modules.pipeline import ScanContext
from modules.pipeline.stages import stage_verify_secrets


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def _args(**kw):
    base = dict(
        target="https://example.com",
        verify_secrets=True,
        verify_secrets_timeout=5.0,
    )
    base.update(kw)
    return Namespace(**base)


class TestExtractCredential(unittest.TestCase):
    def test_strips_quotes(self):
        self.assertEqual(extract_credential('"ghp_abc123def"'), "ghp_abc123def")

    def test_strips_bearer_prefix(self):
        self.assertEqual(extract_credential("Bearer sk-test"), "sk-test")

    def test_passthrough(self):
        self.assertEqual(extract_credential("sk_live_xxx"), "sk_live_xxx")


class TestVerifySecret(unittest.TestCase):
    def test_skip_types_return_none(self):
        for t in SKIP_TYPES:
            r = verify_secret({"type": t, "match": "x" * 20})
            self.assertIsNone(r, t)

    def test_unknown_type_returns_none(self):
        self.assertIsNone(verify_secret({"type": "Not A Vendor", "match": "abcdefghij"}))

    def test_short_token_skipped(self):
        r = verify_secret({"type": "OpenAI API Key", "match": "short"})
        self.assertIsNone(r)

    def test_confirmed_github(self):
        session = mock.Mock()
        session.get.return_value = _Resp(200, {"login": "u"})
        r = verify_secret(
            {"type": "GitHub Token", "match": "ghp_" + "A" * 36},
            session=session,
        )
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["vendor"], "GitHub")
        self.assertEqual(r["http_status"], 200)
        args, kwargs = session.get.call_args
        self.assertEqual(args[0], "https://api.github.com/user")
        self.assertIn("Bearer", kwargs["headers"]["Authorization"])

    def test_rejected_stripe(self):
        session = mock.Mock()
        session.get.return_value = _Resp(401, {"error": "invalid"})
        r = verify_secret(
            {"type": "Stripe Live Key", "match": "sk_live_" + "a" * 24},
            session=session,
        )
        self.assertEqual(r["status"], "rejected")
        self.assertEqual(r["http_status"], 401)

    def test_slack_ok_false_rejected(self):
        session = mock.Mock()
        session.get.return_value = _Resp(200, {"ok": False, "error": "invalid_auth"})
        r = verify_secret(
            {"type": "Slack Token", "match": "xoxb-" + "a" * 20},
            session=session,
        )
        self.assertEqual(r["status"], "rejected")
        self.assertIn("invalid_auth", r["detail"])

    def test_slack_ok_true_confirmed(self):
        session = mock.Mock()
        session.get.return_value = _Resp(200, {"ok": True})
        r = verify_secret(
            {"type": "Slack Token", "match": "xoxb-" + "a" * 20},
            session=session,
        )
        self.assertEqual(r["status"], "confirmed")

    def test_connection_error_is_error_status(self):
        session = mock.Mock()
        session.get.side_effect = requests.ConnectionError("down")
        r = verify_secret(
            {"type": "OpenAI API Key", "match": "dummy-openai-key-for-error-test"},
            session=session,
        )
        self.assertEqual(r["status"], "error")
        self.assertIn("down", r["detail"])

    def test_unexpected_status_is_error(self):
        session = mock.Mock()
        session.get.return_value = _Resp(500)
        r = verify_secret(
            {"type": "DigitalOcean Token", "match": "dop_v1_" + "a" * 64},
            session=session,
        )
        self.assertEqual(r["status"], "error")
        self.assertIn("500", r["detail"])


class TestVerifySecretsBatch(unittest.TestCase):
    @mock.patch("modules.extraction.verify.verify_secret")
    def test_batch_counts_and_findings(self, vs_mock):
        vs_mock.side_effect = [
            {"type": "GitHub Token", "match": "ghp_…", "vendor": "GitHub",
             "status": "confirmed", "http_status": 200, "detail": "ok", "url": "u"},
            {"type": "Stripe Live Key", "match": "sk_live_…", "vendor": "Stripe",
             "status": "rejected", "http_status": 401, "detail": "no", "url": "u"},
        ]
        secrets = [
            {"type": "GitHub Token", "match": "ghp_" + "A" * 36},
            {"type": "Stripe Live Key", "match": "sk_live_" + "a" * 24},
            {"type": "High-Entropy String", "match": "x" * 40},
        ]
        out = verify_secrets(secrets, verbose=False)
        self.assertEqual(out["secrets_checked"], 2)
        self.assertEqual(out["confirmed"], 1)
        self.assertEqual(out["rejected"], 1)
        self.assertEqual(out["skipped"], 1)
        self.assertEqual(len(out["findings"]), 1)
        self.assertEqual(out["findings"][0]["severity"], "HIGH")
        self.assertIn("Confirmed live", out["findings"][0]["detail"])

    @mock.patch("modules.extraction.verify.verify_secret")
    def test_batch_cap(self, vs_mock):
        vs_mock.return_value = {
            "type": "GitHub Token", "match": "ghp_…", "vendor": "GitHub",
            "status": "confirmed", "http_status": 200, "detail": "ok", "url": "u",
        }
        secrets = [
            {"type": "GitHub Token", "match": f"ghp_{i:036d}"} for i in range(30)
        ]
        out = verify_secrets(secrets, verbose=False)
        self.assertEqual(out["secrets_checked"], 25)
        self.assertEqual(vs_mock.call_count, 25)

    def test_verifier_table_readonly_gets(self):
        # Every builder must produce an https URL (no mutations / cleartext).
        for typ, (builder, *_rest) in VERIFIERS.items():
            # builders that need a token arg
            url, headers = builder("TESTTOKENVALUE123")
            self.assertTrue(url.startswith("https://"), typ)
            self.assertTrue(headers, typ)


class TestStageVerifySecrets(unittest.TestCase):
    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.verify_secrets")
    def test_stage_writes_result(self, vs_mock, risk_mock):
        vs_mock.return_value = {
            "results": [{
                "type": "GitHub Token", "match": "ghp_…", "vendor": "GitHub",
                "status": "confirmed", "http_status": 200,
                "detail": "credential accepted", "url": "https://api.github.com/user",
            }],
            "findings": [{
                "severity": "HIGH", "url": "",
                "detail": "Confirmed live GitHub Token via GitHub (HTTP 200)",
                "type": "GitHub Token", "vendor": "GitHub",
                "match": "ghp_…", "http_status": 200,
            }],
            "secrets_checked": 1, "confirmed": 1, "rejected": 0,
            "errors": 0, "skipped": 0,
            "summary": {"secrets_checked": 1, "confirmed": 1,
                        "rejected": 0, "errors": 0, "skipped": 0},
        }
        risk_mock.return_value = {"level": "HIGH", "score": 40}
        ctx = ScanContext(_args(), verbose=False)
        ctx.result = {
            "target": "https://example.com",
            "secrets_found": [
                {"type": "GitHub Token", "match": "ghp_" + "A" * 36},
            ],
        }
        stage_verify_secrets(ctx)
        self.assertEqual(ctx.result["secret_verification"]["confirmed"], 1)
        vs_mock.assert_called_once()
        risk_mock.assert_called_once()

    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.verify_secrets")
    def test_stage_no_secrets(self, vs_mock, risk_mock):
        risk_mock.return_value = {"level": "INFO", "score": 0}
        ctx = ScanContext(_args(), verbose=False)
        ctx.result = {"target": "https://example.com", "secrets_found": []}
        stage_verify_secrets(ctx)
        self.assertEqual(ctx.result["secret_verification"]["secrets_checked"], 0)
        vs_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
