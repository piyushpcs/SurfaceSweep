"""Cross-cutting shared utilities (constants, HTTP client, result schema)."""

from modules.common.constants import (
    CVE_SEVERITY_WEIGHTS,
    DEFAULT_USER_AGENT,
    RISK_THRESHOLDS,
    SEVERITY_ORDER,
    SEVERITY_RANK,
    __version__,
)
from modules.common.result import (
    RESULT_SCHEMA_VERSION,
    ScanResult,
    new_scan_result,
)

__all__ = [
    "CVE_SEVERITY_WEIGHTS",
    "DEFAULT_USER_AGENT",
    "RISK_THRESHOLDS",
    "RESULT_SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "SEVERITY_RANK",
    "ScanResult",
    "__version__",
    "new_scan_result",
]
