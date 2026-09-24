"""Unit tests for library version detection and CVE matching (Phase A Step 4)."""

import unittest

from modules.analysis.libraries import (
    _matches_vulnerability,
    _parse_version,
    _version_gte,
    _version_lt,
    check_vulnerabilities,
    detect_libraries_from_content,
)


class TestVersionCompare(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(_parse_version("3.4.1"), (3, 4, 1))
        self.assertEqual(_parse_version("4.17.21"), (4, 17, 21))
        self.assertEqual(_parse_version("10.0.0"), (10, 0, 0))

    def test_numeric_not_lexicographic(self):
        """3.10.0 must be GREATER than 3.4.1 (lexicographic would invert)."""
        self.assertTrue(_version_lt("3.4.1", "3.10.0"))
        self.assertFalse(_version_lt("3.10.0", "3.4.1"))
        self.assertTrue(_version_gte("3.10.0", "3.4.1"))

    def test_padding(self):
        self.assertTrue(_version_lt("3.4", "3.4.1"))
        self.assertFalse(_version_lt("3.4.1", "3.4"))


class TestMatchesVulnerability(unittest.TestCase):
    def test_bootstrap_fixed_3_4_1_not_matched(self):
        vuln = next(v for v in __import__(
            "modules.analysis.libraries", fromlist=["VULNERABILITIES"]
        ).VULNERABILITIES if v["library"] == "Bootstrap")
        self.assertFalse(_matches_vulnerability("3.4.1", vuln))
        self.assertFalse(_matches_vulnerability("3.17.0", vuln))
        self.assertTrue(_matches_vulnerability("3.4.0", vuln))
        self.assertTrue(_matches_vulnerability("4.3.0", vuln))
        self.assertFalse(_matches_vulnerability("4.3.1", vuln))
        self.assertTrue(_matches_vulnerability("2.3.2", vuln))

    def test_vulnerable_below(self):
        vuln = {"library": "X", "vulnerable_below": "3.5.0"}
        self.assertTrue(_matches_vulnerability("3.4.9", vuln))
        self.assertFalse(_matches_vulnerability("3.5.0", vuln))
        self.assertFalse(_matches_vulnerability("3.10.0", vuln))

    def test_from_and_max(self):
        vuln = {"library": "X", "vulnerable_from": "2.18.0", "max_version": "2.29.3"}
        self.assertFalse(_matches_vulnerability("2.17.0", vuln))
        self.assertTrue(_matches_vulnerability("2.29.3", vuln))
        self.assertFalse(_matches_vulnerability("2.29.4", vuln))


class TestDetectLibraries(unittest.TestCase):
    def test_jquery_content_banner(self):
        content = "/*! jQuery v3.4.1 | (c) OpenJS Foundation */"
        libs = detect_libraries_from_content(content, "https://x.test/app.js")
        jquery = next(l for l in libs if l["library"] == "jQuery")
        self.assertEqual(jquery["version"], "3.4.1")
        self.assertEqual(jquery["source"], "content")

    def test_jquery_filename(self):
        libs = detect_libraries_from_content("", "https://cdn.test/jquery-1.12.4.min.js")
        jquery = next(l for l in libs if l["library"] == "jQuery")
        self.assertEqual(jquery["version"], "1.12.4")
        self.assertEqual(jquery["source"], "filename")

    def test_bootstrap_filename(self):
        libs = detect_libraries_from_content("", "/static/bootstrap-4.3.1.min.js")
        boot = next(l for l in libs if l["library"] == "Bootstrap")
        self.assertEqual(boot["version"], "4.3.1")

    def test_unknown_library_no_match(self):
        libs = detect_libraries_from_content("var x = 1;", "https://x.test/app.js")
        self.assertEqual(libs, [])


class TestCheckVulnerabilities(unittest.TestCase):
    def test_jquery_old_vulnerable(self):
        findings = check_vulnerabilities([
            {"library": "jQuery", "version": "1.6.3", "file": "jquery.js"},
        ])
        self.assertTrue(findings)
        cves = set(findings[0]["cves"])
        self.assertIn("CVE-2020-11022", cves)

    def test_jquery_current_not_flagged(self):
        findings = check_vulnerabilities([
            {"library": "jQuery", "version": "3.7.1", "file": "jquery.js"},
        ])
        self.assertEqual(findings, [])

    def test_bootstrap_fixed_versions_not_flagged(self):
        for ver in ("3.4.1", "4.3.1", "5.3.3"):
            findings = check_vulnerabilities([
                {"library": "Bootstrap", "version": ver, "file": "b.js"},
            ])
            self.assertEqual(findings, [], f"Bootstrap {ver} should not be flagged")

    def test_bootstrap_vulnerable_versions_flagged(self):
        for ver in ("3.4.0", "4.0.0", "4.3.0", "2.3.2"):
            findings = check_vulnerabilities([
                {"library": "Bootstrap", "version": ver, "file": "b.js"},
            ])
            self.assertTrue(findings, f"Bootstrap {ver} should be flagged")

    def test_bootstrap_3_10_not_lexicographic_fp(self):
        """3.10.0 > 3.4.1 numerically — must not be treated as < 3.4.1."""
        # Bootstrap never shipped 3.10, but the comparator must be numeric
        findings = check_vulnerabilities([
            {"library": "Bootstrap", "version": "3.10.0", "file": "b.js"},
        ])
        self.assertEqual(findings, [])

    def test_lodash_findings_merged_single_row(self):
        findings = check_vulnerabilities([
            {"library": "Lodash", "version": "4.17.18", "file": "lodash.js"},
        ])
        self.assertEqual(len(findings), 1)
        cves = set(findings[0]["cves"])
        self.assertEqual(cves, {"CVE-2021-23337", "CVE-2020-8203"})

    def test_lodash_cve_not_double_counted(self):
        """Risk scoring sums per finding — one row per library+version only."""
        findings = check_vulnerabilities([
            {"library": "Lodash", "version": "4.17.15", "file": "a.js"},
            {"library": "Lodash", "version": "4.17.15", "file": "b.js"},
        ])
        self.assertEqual(len(findings), 1)
        # file from first seen
        self.assertEqual(findings[0]["source_file"], "a.js")

    def test_empty_libraries(self):
        self.assertEqual(check_vulnerabilities([]), [])

    def test_unknown_library_no_findings(self):
        self.assertEqual(
            check_vulnerabilities([{"library": "MysteryLib", "version": "1.0.0"}]),
            [],
        )

    def test_no_also_affects_lexicographic_lambda(self):
        """Regression: lexicographic also_affects lambda must be gone."""
        import inspect
        from modules.analysis import libraries
        src = inspect.getsource(libraries)
        self.assertNotIn("also_affects", src)
        self.assertNotIn('v < "3.4.1"', src)


class TestModernLibraryCoverage(unittest.TestCase):
    """Phase C5 — DOMPurify / jQuery UI / axios / Bootstrap detectors + CVEs."""

    def test_dompurify_content_banner(self):
        content = 'var DOMPurify = { version: "2.4.1" };'
        libs = detect_libraries_from_content(content, "https://x.test/app.js")
        dp = next(l for l in libs if l["library"] == "DOMPurify")
        self.assertEqual(dp["version"], "2.4.1")

    def test_dompurify_filename(self):
        libs = detect_libraries_from_content("", "/static/purify-3.1.0.min.js")
        dp = next(l for l in libs if l["library"] == "DOMPurify")
        self.assertEqual(dp["version"], "3.1.0")
        self.assertEqual(dp["source"], "filename")

    def test_dompurify_vulnerable_ranges(self):
        for ver, vulnerable in (("2.4.1", True), ("2.5.3", True), ("2.5.4", False),
                                ("3.1.0", True), ("3.1.3", False), ("3.2.0", False)):
            findings = check_vulnerabilities([
                {"library": "DOMPurify", "version": ver, "file": "dp.js"},
            ])
            if vulnerable:
                self.assertTrue(findings, f"DOMPurify {ver} should be flagged")
                self.assertIn("CVE-2024-45801", findings[0]["cves"])
            else:
                self.assertEqual(findings, [], f"DOMPurify {ver} should not be flagged")

    def test_jquery_ui_filename_and_content(self):
        libs = detect_libraries_from_content("", "https://cdn.test/jquery-ui-1.12.1.min.js")
        ui = next(l for l in libs if l["library"] == "jQuery UI")
        self.assertEqual(ui["version"], "1.12.1")

        content = "/*! jQuery UI v1.11.4 */"
        libs = detect_libraries_from_content(content, "https://x.test/bundle.js")
        ui = next(l for l in libs if l["library"] == "jQuery UI")
        self.assertEqual(ui["version"], "1.11.4")

    def test_jquery_ui_vulnerable_and_fixed(self):
        old = check_vulnerabilities([
            {"library": "jQuery UI", "version": "1.11.4", "file": "ui.js"},
        ])
        self.assertTrue(old)
        cves = set(old[0]["cves"])
        self.assertIn("CVE-2016-7103", cves)
        self.assertIn("CVE-2021-41182", cves)

        mid = check_vulnerabilities([
            {"library": "jQuery UI", "version": "1.12.1", "file": "ui.js"},
        ])
        self.assertTrue(mid)
        cves = set(mid[0]["cves"])
        self.assertNotIn("CVE-2016-7103", cves)
        self.assertIn("CVE-2021-41182", cves)

        fixed = check_vulnerabilities([
            {"library": "jQuery UI", "version": "1.13.2", "file": "ui.js"},
        ])
        self.assertEqual(fixed, [])

    def test_axios_cve_2025_27152(self):
        findings = check_vulnerabilities([
            {"library": "axios", "version": "1.7.9", "file": "a.js"},
        ])
        self.assertTrue(findings)
        cves = set(findings[0]["cves"])
        self.assertIn("CVE-2025-27152", cves)

        fixed = check_vulnerabilities([
            {"library": "axios", "version": "1.8.2", "file": "a.js"},
        ])
        self.assertEqual(fixed, [])

    def test_bootstrap_5_carousel_cve(self):
        findings = check_vulnerabilities([
            {"library": "Bootstrap", "version": "5.3.2", "file": "b.js"},
        ])
        self.assertTrue(findings)
        self.assertIn("CVE-2024-6531", findings[0]["cves"])

        fixed = check_vulnerabilities([
            {"library": "Bootstrap", "version": "5.3.3", "file": "b.js"},
        ])
        self.assertEqual(fixed, [])


if __name__ == "__main__":
    unittest.main()
