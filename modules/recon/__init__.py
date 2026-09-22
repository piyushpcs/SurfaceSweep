"""
Recon — target reconnaissance (WAF detection).
"""

from modules.recon.waf import detect_waf, get_scan_adjustments

__all__ = ["detect_waf", "get_scan_adjustments"]
