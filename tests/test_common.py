"""Tier-1 tests for modules.common shared constants."""

import unittest

from modules import __version__ as modules_version
from modules.common import (
    CVE_SEVERITY_WEIGHTS,
    DEFAULT_USER_AGENT,
    RISK_THRESHOLDS,
    SEVERITY_ORDER,
    SEVERITY_RANK,
)
from modules.common import __version__ as common_version
from modules.common.constants import __version__ as constants_version


class TestVersion(unittest.TestCase):
    def test_versions_match(self):
        self.assertEqual(modules_version, common_version)
        self.assertEqual(common_version, constants_version)

    def test_version_format(self):
        parts = common_version.split(".")
        self.assertEqual(len(parts), 3)
        for p in parts:
            self.assertTrue(p.isdigit())


class TestSeverityOrder(unittest.TestCase):
    def test_rank_is_alias(self):
        self.assertIs(SEVERITY_RANK, SEVERITY_ORDER)

    def test_lower_is_worse(self):
        ranks = [SEVERITY_ORDER[s] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ERROR")]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(ranks[0], 0)

    def test_unknown_severity_not_in_map(self):
        self.assertNotIn("FATAL", SEVERITY_ORDER)

    def test_cors_severity_matches_common(self):
        from modules.cors.classifier import SEVERITY_ORDER as cors_order

        self.assertEqual(cors_order, SEVERITY_ORDER)

    def test_jwt_severity_matches_common(self):
        from modules.jwt.checks import SEVERITY_ORDER as jwt_order

        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertEqual(jwt_order[key], SEVERITY_ORDER[key])

    def test_findings_severity_matches_common(self):
        from modules.reporting.findings import SEVERITY_ORDER as findings_order

        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertEqual(findings_order[key], SEVERITY_ORDER[key])

    def test_html_cors_sev_order_matches_common(self):
        from modules.reporting.html import CORS_SEV_ORDER

        self.assertEqual(CORS_SEV_ORDER, SEVERITY_ORDER)


class TestRiskConstants(unittest.TestCase):
    def test_thresholds_descending(self):
        scores = [t for t, _ in RISK_THRESHOLDS]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_risk_levels_upper(self):
        for _, level in RISK_THRESHOLDS:
            self.assertEqual(level, level.upper())

    def test_cve_weights_cover_standard_severities(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            self.assertIn(sev, CVE_SEVERITY_WEIGHTS)
            self.assertIsInstance(CVE_SEVERITY_WEIGHTS[sev], int)
            self.assertGreater(CVE_SEVERITY_WEIGHTS[sev], 0)

    def test_cve_weights_monotonic(self):
        self.assertGreater(CVE_SEVERITY_WEIGHTS["CRITICAL"], CVE_SEVERITY_WEIGHTS["HIGH"])
        self.assertGreater(CVE_SEVERITY_WEIGHTS["HIGH"], CVE_SEVERITY_WEIGHTS["MEDIUM"])
        self.assertGreater(CVE_SEVERITY_WEIGHTS["MEDIUM"], CVE_SEVERITY_WEIGHTS["LOW"])

    def test_risk_module_reexports(self):
        from modules.extraction.risk import CVE_SEVERITY_WEIGHTS as risk_cve, RISK_THRESHOLDS as risk_rt

        self.assertEqual(risk_rt, RISK_THRESHOLDS)
        self.assertEqual(risk_cve, CVE_SEVERITY_WEIGHTS)


class TestUserAgent(unittest.TestCase):
    def test_default_ua_format(self):
        self.assertTrue(DEFAULT_USER_AGENT.startswith("SurfaceSweep/"))
        self.assertNotIn(" ", DEFAULT_USER_AGENT)

    def test_http_module_reexports(self):
        from modules.extraction.http import DEFAULT_USER_AGENT as http_ua

        self.assertEqual(http_ua, DEFAULT_USER_AGENT)


if __name__ == "__main__":
    unittest.main()
