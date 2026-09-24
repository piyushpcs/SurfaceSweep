"""Cross-cutting shared utilities (constants, HTTP client, result schema)."""

from modules.common.constants import (
    CVE_SEVERITY_WEIGHTS,
    DEFAULT_SECRET_SEVERITY,
    DEFAULT_USER_AGENT,
    INTERNAL_HOST_RISK_WEIGHTS,
    RISK_THRESHOLDS,
    SECRETS_RISK_WEIGHTS,
    SEVERITY_ORDER,
    SEVERITY_RANK,
    SECRET_SEVERITY,
    __version__,
    internal_host_severity,
    secret_severity,
)
from modules.common.console import (
    configure_console,
    detail,
    emit,
    error,
    info,
    is_quiet,
    ok,
    warn,
)
from modules.common.result import (
    RESULT_SCHEMA_VERSION,
    ScanResult,
    new_scan_result,
)

__all__ = [
    "CVE_SEVERITY_WEIGHTS",
    "DEFAULT_SECRET_SEVERITY",
    "DEFAULT_USER_AGENT",
    "INTERNAL_HOST_RISK_WEIGHTS",
    "RISK_THRESHOLDS",
    "RESULT_SCHEMA_VERSION",
    "SECRETS_RISK_WEIGHTS",
    "SEVERITY_ORDER",
    "SEVERITY_RANK",
    "SECRET_SEVERITY",
    "ScanResult",
    "__version__",
    "configure_console",
    "detail",
    "emit",
    "error",
    "info",
    "internal_host_severity",
    "is_quiet",
    "new_scan_result",
    "ok",
    "secret_severity",
    "warn",
]
