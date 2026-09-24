"""
PII quick-win detection for recon (emails, phones, PANs, SSNs).

Checksum-gated where possible (Luhn for cards; dashed SSA form + sample
denylist for SSN). Severity is informational/low — PII shape alone is rarely
a bounty on H1/BB unless combined with authz issues or bulk cross-user data.
"""

import re

# kind -> (pattern, severity, description)
PII_PATTERNS = {
    "email": (
        re.compile(
            r'(?<![\w.+-])[A-Za-z0-9._%+-]+@'
            r'(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}'
            r'(?![\w.-])'
        ),
        "INFO",
        "Email address in client-side content",
    ),
    "phone_e164": (
        # Strict E.164: + and 8–15 digits, first digit 1–9 (near-zero FP)
        re.compile(r'(?<![\w+])\+[1-9]\d{7,14}(?![\d\w])'),
        "INFO",
        "International phone number (E.164)",
    ),
    "credit_card": (
        # Digit runs of PAN length with optional separators; Luhn applied later
        re.compile(r'(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])'),
        "LOW",
        "Payment card number shape (Luhn-validated)",
    ),
    "ssn": (
        # Dashed SSN only (bare 9-digit runs are IDs/hashes); SSA area rules
        re.compile(r'(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)'),
        "LOW",
        "US Social Security Number (dashed form)",
    ),
}

# Analytics / boilerplate hosts that dominate minified bundles
EMAIL_DENY_DOMAINS = frozenset({
    "example.com", "example.org", "example.net", "example.edu",
    "test.com", "test.org", "localhost", "local", "invalid",
    "sentry.io", "getsentry.net", "bugsnag.com", "airbrake.io",
    "segment.com", "segment.io", "mixpanel.com", "fullstory.com",
    "hotjar.com", "google-analytics.com", "analytics.google.com",
    "doubleclick.net", "cookielaw.org", "onetrust.com", "cookiebot.com",
    "datadoghq.com", "newrelic.com", "nr-data.net", "amplitude.com",
    "heap.io", "heapanalytics.com", "intercom.io", "intercomcdn.com",
    "zendesk.com", "helpscout.net", "mailchimp.com", "sendgrid.net",
    "webpack.js.org", "example.invalid",
})

_EMAIL_LOCAL_STOPWORDS = (
    "noreply", "no-reply", "donotreply", "do-not-reply",
    "example", "sample", "placeholder", "sentry", "bugsnag",
    "webpack", "localhost", "redacted", "test",
)

# Fictional / docs / gitleaks-allowlisted SSNs
_SSN_SAMPLE_DENY = frozenset({
    "219-09-9999", "078-05-1120", "123-45-6789", "999-99-9999",
    "111-11-1111", "222-22-2222", "333-33-3333", "444-44-4444",
    "555-55-5555", "666-66-6666", "777-77-7777", "888-88-8888",
    "000-00-0000",
})

# Stripe / Brick / docs test PANs
_TEST_PAN_DENY = frozenset({
    "4111111111111111", "4242424242424242", "4000056655665556",
    "5555555555554444", "5454545454545454", "2223003122003222",
    "378282246310005", "371449635398431", "6011111111111117",
    "6011000990139424", "30569309025904", "3566002020360505",
})

_LINE_SKIP_RE = re.compile(
    r'(?i)(sourceMappingURL|webpackChunk|__webpack_require__|'
    r'base64,|data:application/json|node_modules|\.min\.js)'
)

_CONTEXT_PHONE_RE = re.compile(
    r'(?i)(?:phone|tel(?:ephone)?|mobile|cell|sms|fax|contact|call us|whatsapp)'
)


def luhn_valid(digits):
    """True when the digit string passes the Luhn checksum."""
    if not digits or not digits.isdigit() or len(digits) < 12:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _email_is_boilerplate(email):
    lowered = email.lower()
    local, _, domain = lowered.partition("@")
    domain = domain.rstrip(".")
    if domain in EMAIL_DENY_DOMAINS:
        return True
    # Multi-label deny (e.g. foo.sentry.io)
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        if ".".join(labels[i:]) in EMAIL_DENY_DOMAINS:
            return True
    if any(word in local for word in _EMAIL_LOCAL_STOPWORDS):
        return True
    if local.isdigit():
        return True
    return False


def _normalize_pan(candidate):
    return re.sub(r"[ -]", "", candidate)


def _credit_card_valid(candidate):
    pan = _normalize_pan(candidate)
    if len(pan) < 13 or len(pan) > 19:
        return False
    if pan in _TEST_PAN_DENY:
        return False
    # Require plausible IIN prefix (rejects random long digit runs that pass Luhn rarely but helps)
    if not re.match(
        r'^(?:4|5[1-5]|2[2-7]|3[47]|3(?:0[0-5]|[68])|6(?:011|5|4[4-9]|22))',
        pan,
    ):
        # Still accept if Luhn passes and length is 15–16 (covers less common brands)
        if not (luhn_valid(pan) and len(pan) in (15, 16)):
            return False
    return luhn_valid(pan)


def _ssn_valid(match_text):
    if match_text in _SSN_SAMPLE_DENY:
        return False
    # Group/serial non-zero already in regex; reject repeated groups like 123-45-6789 handled by deny
    area, group, serial = match_text.split("-")
    if area == group == serial:
        return False
    return True


def detect_pii(content, source_label):
    """
    Detect PII quick-wins in content.
    Returns list of {kind, match, severity, description, source}.
    """
    if not content:
        return []

    findings = []
    seen = set()

    # Cheap line-level skip for source-map / minified noise regions
    scan_content = content

    for kind, (pattern, severity, description) in PII_PATTERNS.items():
        for m in pattern.finditer(scan_content):
            raw = m.group(0)
            # Context-line skip: don't invent PII from map/base64 blobs
            line_start = scan_content.rfind("\n", 0, m.start()) + 1
            line_end = scan_content.find("\n", m.end())
            if line_end == -1:
                line_end = len(scan_content)
            line = scan_content[line_start:line_end]
            if _LINE_SKIP_RE.search(line):
                continue

            match_text = raw
            if kind == "email":
                if _email_is_boilerplate(raw):
                    continue
            elif kind == "credit_card":
                if not _credit_card_valid(raw):
                    continue
                match_text = _normalize_pan(raw)
            elif kind == "ssn":
                if not _ssn_valid(raw):
                    continue
            elif kind == "phone_e164":
                # Reject if glued to a longer digit/word run (already in regex)
                # Optional: require nearby phone keyword only for borderline — E.164 is strict enough
                pass

            dedup_key = (kind, match_text)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append({
                "kind": kind,
                "match": match_text[:120],
                "severity": severity,
                "description": description,
                "source": source_label,
            })
    return findings


def deduplicate_pii(all_findings):
    """Merge duplicate PII findings across sources; keep sources list."""
    dedup = {}
    for f in all_findings:
        key = (f.get("kind"), f.get("match"))
        if key not in dedup:
            row = dict(f)
            row["sources"] = [f["source"]] if f.get("source") else []
            row.pop("source", None)
            dedup[key] = row
        else:
            src = f.get("source")
            if src and src not in dedup[key]["sources"]:
                dedup[key]["sources"].append(src)
    return list(dedup.values())
