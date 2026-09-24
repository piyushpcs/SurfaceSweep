"""Unit tests for Phase 1.1 Steps 1–2 — secret FP stack + structural patterns."""

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
_SECOND_HIGH_ENTROPY = "Zq7Wn4Kp2Xr8Vt5Yc1Bm6Hd3Lf9Gj0Sa"
_TWILIO_SID = "AC" + "0123456789abcdef0123456789abcdef"
# Telegram pattern requires 35 chars after "digits:"
_TELEGRAM_TOKEN = "1234567890:" + "aB3xY9mN2pQ7rS5tU8vW1xY4zA6bC9dEfGh"
_STRIPE_SECRET = "sk_live_" + "aB3xY9mN2pQ7rS5tU8vW1xY4"
_STRIPE_PUBLISHABLE = "pk_live_" + "Zq7Wn4Kp2Xr8Vt5Yc1Bm6Hd3"


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

    def test_same_match_prefers_specific_type(self):
        match = '"apikey": "%s"' % _GENERIC_HIGH_ENTROPY
        a = {"type": "Generic Secret", "match": match, "source": "a.js"}
        b = {"type": "Generic API Key", "match": match, "source": "b.js"}
        merged = deduplicate_secrets([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["type"], "Generic API Key")
        self.assertEqual(merged[0]["sources"], ["a.js", "b.js"])


class TestStructuralPatterns(unittest.TestCase):
    def test_process_env_fallback(self):
        content = 'const k = process.env.API_SECRET || "%s";' % _GENERIC_HIGH_ENTROPY
        found = extract_secrets(content, "unit.js")
        self.assertTrue(any(s["type"] == "Process Env Fallback" for s in found))

    def test_authorization_header_object(self):
        content = 'headers: { "Authorization": "%s" },' % _SECOND_HIGH_ENTROPY
        found = extract_secrets(content, "unit.js")
        self.assertTrue(any(s["type"] == "Authorization Header" for s in found))

    def test_authorization_bearer_stays_bearer_type(self):
        content = '"Authorization": "Bearer %s",' % _GENERIC_HIGH_ENTROPY
        found = extract_secrets(content, "unit.js")
        types = [s["type"] for s in found]
        self.assertIn("Bearer Token", types)
        self.assertNotIn("Authorization Header", types)

    def test_x_api_key_header(self):
        content = '"X-API-Key": "%s",' % _SECOND_HIGH_ENTROPY
        found = extract_secrets(content, "unit.js")
        self.assertTrue(any(s["type"] == "X-API-Key Header" for s in found))

    def test_client_secret_query_param(self):
        content = 'fetch("/oauth?client_secret=%s&redirect=1")' % _GENERIC_HIGH_ENTROPY
        found = extract_secrets(content, "unit.js")
        self.assertTrue(any(s["type"] == "Client Secret Query" for s in found))

    def test_basic_auth_object_form(self):
        b64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
        content = '"Authorization": "Basic %s",' % b64
        found = extract_secrets(content, "unit.js")
        self.assertTrue(any(s["type"] == "Basic Auth" for s in found))


class TestStripeAndOverlap(unittest.TestCase):
    def test_stripe_secret_not_publishable(self):
        content = 'const k = "%s";' % _STRIPE_SECRET
        found = extract_secrets(content, "unit.js")
        types = [s["type"] for s in found]
        self.assertIn("Stripe Live Key", types)
        self.assertNotIn("Stripe Publishable", types)

    def test_stripe_publishable_not_secret(self):
        content = 'const k = "%s";' % _STRIPE_PUBLISHABLE
        found = extract_secrets(content, "unit.js")
        types = [s["type"] for s in found]
        self.assertIn("Stripe Publishable", types)
        self.assertNotIn("Stripe Live Key", types)

    def test_apikey_claimed_once_by_specific_type(self):
        content = '"apikey": "%s",' % _GENERIC_HIGH_ENTROPY
        found = extract_secrets(content, "unit.js")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["type"], "Generic API Key")


class TestModernSecretPatterns(unittest.TestCase):
    """Phase C4 — high-signal modern vendor formats."""

    def test_github_fine_grained_pat(self):
        token = "github_pat_" + "11ABCDEFGHijklmnopqrstuv_" + "Q" * 40
        found = extract_secrets(f'const t = "{token}";', "unit.js")
        types = [s["type"] for s in found]
        self.assertIn("GitHub PAT (fine-grained)", types)

    def test_stripe_webhook_secret(self):
        whsec = "whsec_" + "a" * 32
        found = extract_secrets(f'const k = "{whsec}";', "unit.js")
        types = [s["type"] for s in found]
        self.assertIn("Stripe Webhook Secret", types)
        self.assertNotIn("Stripe Live Key", types)

    def test_hugging_face_token(self):
        hf = "hf_" + "A" * 40
        found = extract_secrets(f'token: "{hf}",', "unit.js")
        types = [s["type"] for s in found]
        self.assertIn("Hugging Face Token", types)

    def test_openai_project_key_without_marker(self):
        sk = "sk-proj-" + "aB3xY9mN2pQ7rS5tU8vW1xY4zA6bC9dE"
        found = extract_secrets(f'key = "{sk}";', "unit.js")
        types = [s["type"] for s in found]
        self.assertIn("OpenAI Project Key", types)

    def test_openai_classic_marker_still_classic_type(self):
        sk = "sk-" + "aB3xY9mN2pQ7rS5tU8vW" + "T3BlbkFJ" + "Zq7Wn4Kp2Xr8Vt5Yc1Bm6Hd3"
        found = extract_secrets(f'key = "{sk}";', "unit.js")
        types = [s["type"] for s in found]
        self.assertIn("OpenAI API Key", types)

    def test_anthropic_not_swallowed_by_project_key(self):
        sk = "sk-ant-api03-" + "aB3xY9mN2pQ7rS5tU8vW1xY4zA6bC9dE"
        found = extract_secrets(f'key = "{sk}";', "unit.js")
        types = [s["type"] for s in found]
        self.assertIn("Anthropic API Key", types)
        self.assertNotIn("OpenAI Project Key", types)

    def test_new_labels_are_high_confidence(self):
        for label in (
            "GitHub PAT (fine-grained)",
            "Stripe Webhook Secret",
            "Hugging Face Token",
            "OpenAI Project Key",
        ):
            self.assertIn(label, HIGH_CONFIDENCE_SECRET_LABELS)

    def test_pattern_catalog_size_above_readme_claim(self):
        from modules.extraction.secrets import SECRET_PATTERNS

        # README claims "60+ patterns" — keep the claim true.
        self.assertGreaterEqual(len(SECRET_PATTERNS), 60)


class TestFpGateHardening(unittest.TestCase):
    """E2 — structural FP shapes + expanded placeholder vocabulary."""

    def test_uuid_rejected(self):
        self.assertFalse(is_likely_real_secret("550e8400-e29b-41d4-a716-446655440000"))

    def test_email_rejected(self):
        self.assertFalse(is_likely_real_secret("user@example-company.com"))

    def test_relative_path_rejected(self):
        self.assertFalse(is_likely_real_secret("/static/assets/config.json"))

    def test_common_sample_tokens_rejected(self):
        for sample in (
            "deadbeefdeadbeefcafe",
            "xxxxxxxxxxxxxxxxxxxx",
            "foobarfoobarbazquux1",
            "password1password1aa",
            "your_api_key_here_xx",
        ):
            self.assertFalse(is_likely_real_secret(sample), sample)

    def test_vendor_prefix_still_accepted_despite_uuidish_body(self):
        # high-confidence prefixes are exempt from structural gates
        self.assertTrue(is_likely_real_secret("AKIAEXAMPLE", label="AWS Access Key"))

    def test_random_high_entropy_still_accepted(self):
        self.assertTrue(is_likely_real_secret(_GENERIC_HIGH_ENTROPY))
        self.assertTrue(is_likely_real_secret(_SECOND_HIGH_ENTROPY))

    def test_bare_object_password_still_extracted(self):
        found = extract_secrets('{ password: "smtp_secret_pass_123" }', "unit.js")
        self.assertTrue(any(s["type"] == "Generic Password" for s in found))

    def test_uuid_as_password_value_rejected(self):
        found = extract_secrets(
            '{ password: "550e8400-e29b-41d4-a716-446655440000" }', "unit.js"
        )
        self.assertFalse(any(s["type"] == "Generic Password" for s in found))


if __name__ == "__main__":
    unittest.main()
