"""Unit tests for PII quick-win detection."""

import unittest

from modules.analysis.pii import (
    PII_PATTERNS,
    deduplicate_pii,
    detect_pii,
    luhn_valid,
)


class TestLuhn(unittest.TestCase):
    def test_known_good_pans(self):
        for pan in (
            "4111111111111111",
            "5555555555554444",
            "378282246310005",
            "6011111111111117",
        ):
            self.assertTrue(luhn_valid(pan), pan)

    def test_bad_checksum(self):
        self.assertFalse(luhn_valid("4111111111111112"))

    def test_short_or_non_numeric(self):
        self.assertFalse(luhn_valid("1234"))
        self.assertFalse(luhn_valid("abcdefghijklmn"))


class TestEmail(unittest.TestCase):
    def test_real_looking_email(self):
        found = detect_pii('contact: "alice.smith@corp-target.io"', "a.js")
        emails = [f for f in found if f["kind"] == "email"]
        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0]["match"], "alice.smith@corp-target.io")
        self.assertEqual(emails[0]["severity"], "INFO")

    def test_sentry_boilerplate_rejected(self):
        found = detect_pii('from: "alerts@sentry.io"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "email"], [])

    def test_noreply_local_rejected(self):
        found = detect_pii('"email": "noreply@corp-target.io"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "email"], [])

    def test_example_com_rejected(self):
        found = detect_pii('"admin@example.com"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "email"], [])

    def test_numeric_local_rejected(self):
        found = detect_pii('"12345@corp-target.io"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "email"], [])


class TestPhoneE164(unittest.TestCase):
    def test_plus_number_accepted(self):
        found = detect_pii('sms: "+14155552671"', "a.js")
        phones = [f for f in found if f["kind"] == "phone_e164"]
        self.assertEqual(len(phones), 1)
        self.assertEqual(phones[0]["match"], "+14155552671")

    def test_bare_digits_rejected(self):
        found = detect_pii('phone: "4155552671"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "phone_e164"], [])

    def test_too_short_rejected(self):
        found = detect_pii('"+1234567"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "phone_e164"], [])


class TestCreditCard(unittest.TestCase):
    def test_luhn_pass_reported(self):
        # 4111… is a classic test PAN — must be denylisted
        found = detect_pii('card: "4111111111111111"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "credit_card"], [])

    def test_non_test_luhn_pan_reported(self):
        # 4532015112830366 — Luhn-valid Visa-shaped, not on test denylist
        found = detect_pii('pan: "4532015112830366"', "a.js")
        cards = [f for f in found if f["kind"] == "credit_card"]
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["match"], "4532015112830366")
        self.assertEqual(cards[0]["severity"], "LOW")

    def test_separated_pan_normalized(self):
        found = detect_pii('pan: "4532 0151 1283 0366"', "a.js")
        cards = [f for f in found if f["kind"] == "credit_card"]
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["match"], "4532015112830366")

    def test_luhn_fail_rejected(self):
        found = detect_pii('pan: "4532015112830367"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "credit_card"], [])

    def test_timestamp_rejected(self):
        found = detect_pii('ts: 1727045612345', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "credit_card"], [])


class TestSsn(unittest.TestCase):
    def test_dashed_ssn_reported(self):
        found = detect_pii('ssn: "456-78-9012"', "a.js")
        ssns = [f for f in found if f["kind"] == "ssn"]
        self.assertEqual(len(ssns), 1)
        self.assertEqual(ssns[0]["match"], "456-78-9012")
        self.assertEqual(ssns[0]["severity"], "LOW")

    def test_sample_ssn_rejected(self):
        for sample in ("219-09-9999", "123-45-6789", "078-05-1120"):
            found = detect_pii('"%s"' % sample, "a.js")
            self.assertEqual(
                [f for f in found if f["kind"] == "ssn"],
                [],
                sample,
            )

    def test_invalid_area_rejected(self):
        found = detect_pii('"000-12-3456"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "ssn"], [])
        found = detect_pii('"666-12-3456"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "ssn"], [])

    def test_undashed_nine_digits_not_ssn(self):
        found = detect_pii('"987654320"', "a.js")
        self.assertEqual([f for f in found if f["kind"] == "ssn"], [])


class TestLineSkipAndDedup(unittest.TestCase):
    def test_source_map_line_skipped(self):
        line = '//# sourceMappingURL=data:application/json;base64,eyJ2IjozfQ== 456-78-9012'
        found = detect_pii(line, "a.js")
        self.assertEqual([f for f in found if f["kind"] == "ssn"], [])

    def test_dedup_merges_sources(self):
        a = {
            "kind": "email", "match": "alice@corp-target.io",
            "severity": "INFO", "description": "d", "source": "a.js",
        }
        b = dict(a, source="b.js")
        merged = deduplicate_pii([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["sources"], ["a.js", "b.js"])
        self.assertNotIn("source", merged[0])

    def test_different_matches_stay_separate(self):
        a = {"kind": "email", "match": "a@b.co", "severity": "INFO", "description": "d", "source": "x"}
        b = {"kind": "email", "match": "c@d.co", "severity": "INFO", "description": "d", "source": "x"}
        self.assertEqual(len(deduplicate_pii([a, b])), 2)

    def test_patterns_declared(self):
        self.assertEqual(
            set(PII_PATTERNS),
            {"email", "phone_e164", "credit_card", "ssn"},
        )


if __name__ == "__main__":
    unittest.main()
