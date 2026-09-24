"""Cross-cutting shared utilities (constants, HTTP client, result schema)."""

from modules.common.constants import (
    CVE_SEVERITY_WEIGHTS,
    DEFAULT_USER_AGENT,
    RISK_THRESHOLDS,
    SEVERITY_ORDER,
    SEVERITY_RANK,
    __version__,
)

__all__ = [
    "CVE_SEVERITY_WEIGHTS",
    "DEFAULT_USER_AGENT",
    "RISK_THRESHOLDS",
    "SEVERITY_ORDER",
    "SEVERITY_RANK",
    "__version__",
]
