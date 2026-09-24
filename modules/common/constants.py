"""Shared constants used across SurfaceSweep modules."""

from __future__ import annotations

__all__ = [
    "CVE_SEVERITY_WEIGHTS",
    "DEFAULT_USER_AGENT",
    "RISK_THRESHOLDS",
    "SEVERITY_ORDER",
    "SEVERITY_RANK",
    "__version__",
]

__version__ = "1.0.0"

DEFAULT_USER_AGENT = "SurfaceSweep/1.0"

# Lower = worse (CORS also uses ERROR for probe failures).
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "ERROR": 5,
}

# Alias for call sites that treat the map as a rank lookup.
SEVERITY_RANK = SEVERITY_ORDER

RISK_THRESHOLDS = (
    (30, "HIGH"),
    (10, "MEDIUM"),
    (1, "LOW"),
)

CVE_SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
