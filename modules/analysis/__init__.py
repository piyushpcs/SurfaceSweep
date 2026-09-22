"""
Analysis — validate endpoints, detect libraries/CVEs, calculate risk.
"""

from modules.analysis.validator import validate_endpoints, get_live_endpoints, validate_endpoint
from modules.analysis.libraries import scan_for_libraries, detect_libraries_from_content, check_vulnerabilities

__all__ = [
    "validate_endpoints", "get_live_endpoints", "validate_endpoint",
    "scan_for_libraries", "detect_libraries_from_content", "check_vulnerabilities",
]
