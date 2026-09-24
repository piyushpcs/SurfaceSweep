"""Unit tests for Phase 1.1 Step 1 — secret FP stack (entropy + proximity)."""

import unittest

from modules.extraction.patterns import (
    HIGH_CONFIDENCE_SECRET_LABELS,
    PROXIMITY_GATED_SECRET_TYPES,
    is_likely_real_secret,
    near_secret_context,
    shannon_entropy,
)
from modules.extraction.secrets import deduplicate_secrets, extract_secrets


# High-entropy-shaped fixtures (structure + randomness real keys exhibit).
_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
_GOOGLE_KEY = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
_GENERIC_HIGH_ENTROPY = "aB3xY9mN2pQ7rS5tU8vW1xY4zA6bC9dE"
_TWILIO_SID = "AC" + "0123456789abcdef0123456789abcdef"
# Telegram pattern requires 35 chars after "digits:"
_TELEGRAM_TOKEN = "1234567890:" + "aB3xY9mN2pQ7rS5tU8vW1xY4zA6bC9dEfGh"


class TestShannonEntropy(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_uniform_is_zero(self):
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_high_entropy_above_three(self):
        self.assertGreater(shannon_entropy(_GENERIC_HIGH_ENTROPY), 3.5)

    def test_hex_ceiling(self):
        self.assertLessEqual(shannon_entropy("deadbeef"), 3.0)


class TestIsLikelyRealSecret(unittest.TestCase):
    def test_short_rejected(self):
        self.assertFalse(is_likely_real_secret("short"))

    def test_common_false_positive_exact(self):
        self.assertFalse(is_likely_real_secret("placeholder"))
        self.assertFalse(is_likely_real_secret("undefined"))

    def test_placeholder_substring_rejected(self):
        self.assertFalse(is_likely_real_secret("your-secret-key-here"))
        self.assertFalse(is_likely_real_secret("changeme-please-1"))

    def test_template_braces_rejected(self):
        self.assertFalse(is_likely_real_secret("<api-key-goes-here>"))
        self.assertFalse(is_likely_real_secret("{{API_KEY_VALUE}}"))

    def test_repeated_char_rejected(self):
        self.assertFalse(is_likely_real_secret("aaaaaaaaaaaaaaaa"))

    def test_zero_fill_rejected(self):
        self.assertFalse(is_likely_real_secret("0000000000000000"))

    def test_sequential_rejected(self):
        self.assertFalse(is_likely_real_secret("abcdefghijklmno"))
        self.assertFalse(is_likely_real_secret("123456789012345"))

    def test_low_entropy_mixed_rejected(self):
        self.assertFalse(is_likely_real_secret("passwordpassword"))

    def test_high_entropy_generic_accepted(self):
        self.assertTrue(is_likely_real_secret(_GENERIC_HIGH_ENTROPY))

    def test_high_confidence_skips_placeholder_gate(self):
        # Integration fixtures use AKIAEXAMPLE — vendor prefix wins.
        self.assertTrue(is_likely_real_secret("AKIAEXAMPLE", label="AWS Access Key"))
        self.assertIn("AWS Access Key", HIGH_CONFIDENCE_SECRET_LABELS)

    def test_label_does_not_bypass_length(self):
        self.assertFalse(is_likely_real_secret("AKIA", label="AWS Access Key"))


class TestNearSecretContext(unittest.TestCase):
    def test_keyword_before_match(self):
        content = 'const sid = twilio.accountSid = "%s";' % _TWILIO_SID
        start = content.index(_TWILIO_SID)
        self.assertTrue(near_secret_context(content, start, start + len(_TWILIO_SID)))

    def test_keyword_in_assignment(self):
        content = 'bot_token: "%s",' % _TELEGRAM_TOKEN
        start = content.index(_TELEGRAM_TOKEN)
        self.assertTrue(near_secret_context(content, start, start + len(_TELEGRAM_TOKEN)))

    def test_no_keyword_far_away(self):
        pad = "x" * 200
        content = pad + _TWILIO_SID + pad
        start = content.index(_TWILIO_SID)
        self.assertFalse(near_secret_context(content, start, start + len(_TWILIO_SID)))

    def test_empty_content(self):
        self.assertFalse(near_secret_context("", 0, 5))


class TestExtractSecrets(unittest.TestCase):
    def test_gated_types_declared(self):
        self.assertIn("Twilio SID", PROXIMITY_GATED_SECRET_TYPES)
        self.assertIn("Telegram Bot Token", PROXIMITY_GATED_SECRET_TYPES)

    def test_aws_key_extracted(self):
        content = 'const key = "%s";' % _AWS_KEY
        found = extract_secrets(content, "unit.js")
        types = [s["type"] for s in found]
        self.assertIn("AWS Access Key", types)

    def test_high_entropy_generic_extracted(self):
        content = '"api_key": "%s",' % _GENERIC_HIGH_ENTROPY
        found = extract_secrets(content, "unit.js")
        self.assertTrue(any(s["type"] == "Generic API Key" for s in found))

    def test_placeholder_generic_rejected(self):
        content = '"secret": "your-secret-key-here",'
        self.assertEqual(extract_secrets(content, "unit.js"), [])

    def test_low_entropy_generic_rejected(self):
        content = '"password": "passwordpassword",'
        self.assertEqual(extract_secrets(content, "unit.js"), [])

    def test_twilio_sid_without_context_rejected(self):
        content = 'var blob = "%s";' % _TWILIO_SID
        found = [s for s in extract_secrets(content, "unit.js") if s["type"] == "Twilio SID"]
        self.assertEqual(found, [])

    def test_twilio_sid_with_context_accepted(self):
        content = 'accountSid: "%s",' % _TWILIO_SID
        found = [s for s in extract_secrets(content, "unit.js") if s["type"] == "Twilio SID"]
        self.assertEqual(len(found), 1)

    def test_telegram_without_context_rejected(self):
        content = 'var blob = "%s";' % _TELEGRAM_TOKEN
        found = [
            s for s in extract_secrets(content, "unit.js")
            if s["type"] == "Telegram Bot Token"
        ]
        self.assertEqual(found, [])

    def test_telegram_with_context_accepted(self):
        content = 'telegram_bot_token: "%s",' % _TELEGRAM_TOKEN
        found = [
            s for s in extract_secrets(content, "unit.js")
            if s["type"] == "Telegram Bot Token"
        ]
        self.assertEqual(len(found), 1)

    def test_jwt_not_truncated(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )
        content = 'token = "%s";' % jwt
        found = [s for s in extract_secrets(content, "unit.js") if s["type"] == "JWT"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["match"], jwt)

    def test_source_label_recorded(self):
        found = extract_secrets('"api_key": "%s",' % _GENERIC_HIGH_ENTROPY, "app.js")
        self.assertTrue(found)
        self.assertEqual(found[0]["source"], "app.js")


class TestDeduplicateSecrets(unittest.TestCase):
    def test_merges_sources(self):
        a = {"type": "AWS Access Key", "match": _AWS_KEY, "source": "a.js"}
        b = {"type": "AWS Access Key", "match": _AWS_KEY, "source": "b.js"}
        merged = deduplicate_secrets([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["sources"], ["a.js", "b.js"])


if __name__ == "__main__":
    unittest.main()
