"""
Analysis — validate endpoints, detect libraries/CVEs, detect sinks/PII, calculate risk.
"""

from modules.analysis.validator import (
    validate_endpoints,
    get_live_endpoints,
    validate_endpoint,
    build_method_map,
    resolve_validation_method,
)
from modules.analysis.libraries import scan_for_libraries, detect_libraries_from_content, check_vulnerabilities
from modules.analysis.sinks import detect_sinks, deduplicate_sinks
from modules.analysis.pii import detect_pii, deduplicate_pii

__all__ = [
    "validate_endpoints", "get_live_endpoints", "validate_endpoint",
    "build_method_map", "resolve_validation_method",
    "scan_for_libraries", "detect_libraries_from_content", "check_vulnerabilities",
    "detect_sinks", "deduplicate_sinks",
    "detect_pii", "deduplicate_pii",
]
