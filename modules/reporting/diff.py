"""
Scan diff — compare two SurfaceSweep JSON reports of the same target.

Used by ``--diff BASELINE.json`` after a live scan, and by the offline
entry point ``python -m modules.reporting.diff OLD.json NEW.json``.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Set

from modules.common.console import detail, info, ok, warn

__all__ = [
    "diff_results",
    "load_result",
    "print_diff",
    "save_diff",
]


def load_result(path: str) -> Dict[str, Any]:
    """Load a scan result JSON file. Raises OSError / ValueError on failure."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object scan result")
    return data


def _endpoints(result: Dict[str, Any]) -> Set[str]:
    """Normalized endpoint keys: relative paths + absolute in-scope URLs."""
    out: Set[str] = set()
    for p in result.get("internal_paths") or []:
        if isinstance(p, str) and p:
            out.add(p)
    for u in result.get("in_scope_urls") or []:
        if isinstance(u, str) and u:
            out.add(u)
    for ep in result.get("intercepted_endpoints") or []:
        if isinstance(ep, dict):
            url = ep.get("url") or ""
            if url:
                out.add(url)
    return out


def _secret_keys(result: Dict[str, Any]) -> Set[str]:
    """Stable keys for secrets: type + first 12 chars of match."""
    out: Set[str] = set()
    for s in result.get("secrets_found") or []:
        if not isinstance(s, dict):
            continue
        typ = str(s.get("type") or "unknown")
        match = str(s.get("match") or "")
        out.add(f"{typ}:{match[:12]}")
    return out


def _library_vuln_keys(result: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for v in result.get("library_vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        cve = v.get("cve") or v.get("id") or ""
        name = v.get("library") or v.get("package") or ""
        out.add(f"{name}:{cve}")
    return out


def _risk(result: Dict[str, Any]) -> Dict[str, Any]:
    rs = result.get("risk_summary") or {}
    return {
        "score": int(rs.get("score") or 0),
        "level": str(rs.get("level") or "INFO"),
    }


def _severity_counts(result: Dict[str, Any]) -> Dict[str, int]:
    """Best-effort aggregate of severity counts (mirrors CLI fail-on helper)."""
    counts: Dict[str, int] = {}

    def bump(sev, n=1):
        if not sev:
            return
        key = str(sev).upper()
        counts[key] = counts.get(key, 0) + int(n or 0)

    rs = result.get("risk_summary") or {}
    for sev, n in (rs.get("severity_counts") or {}).items():
        bump(sev, n)
    for key in ("cors", "jwt"):
        block = result.get(key) or {}
        for sev, n in (block.get("severity_counts") or {}).items():
            bump(sev, n)
    for v in result.get("library_vulnerabilities") or []:
        if isinstance(v, dict):
            bump(v.get("severity"))
    for s in result.get("sinks_found") or []:
        if isinstance(s, dict):
            bump(s.get("severity"))
    return counts


def diff_results(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two scan results.

    Returns a dict:
      {
        "old_target": str, "new_target": str,
        "endpoints": {"added": [...], "removed": [...], "unchanged": n},
        "secrets":   {"added": [...], "removed": [...], "unchanged": n},
        "library_vulnerabilities": {"added": [...], "removed": [...], "unchanged": n},
        "risk": {"old": {...}, "new": {...}, "score_delta": int},
        "severity_counts": {"old": {...}, "new": {...}},
        "regression": bool,   # risk score increased or new high-sev findings
      }
    """
    old = old or {}
    new = new or {}

    ep_old, ep_new = _endpoints(old), _endpoints(new)
    sec_old, sec_new = _secret_keys(old), _secret_keys(new)
    vul_old, vul_new = _library_vuln_keys(old), _library_vuln_keys(new)

    def pack(old_set: Set[str], new_set: Set[str]) -> Dict[str, Any]:
        return {
            "added": sorted(new_set - old_set),
            "removed": sorted(old_set - new_set),
            "unchanged": len(old_set & new_set),
        }

    risk_old, risk_new = _risk(old), _risk(new)
    score_delta = risk_new["score"] - risk_old["score"]
    sev_old, sev_new = _severity_counts(old), _severity_counts(new)

    # Regression: risk score rose, or new HIGH/CRITICAL severity items appeared
    def high_count(c: Dict[str, int]) -> int:
        return int(c.get("HIGH", 0)) + int(c.get("CRITICAL", 0))

    regression = score_delta > 0 or high_count(sev_new) > high_count(sev_old)

    return {
        "old_target": old.get("target") or "",
        "new_target": new.get("target") or "",
        "endpoints": pack(ep_old, ep_new),
        "secrets": pack(sec_old, sec_new),
        "library_vulnerabilities": pack(vul_old, vul_new),
        "risk": {
            "old": risk_old,
            "new": risk_new,
            "score_delta": score_delta,
        },
        "severity_counts": {"old": sev_old, "new": sev_new},
        "regression": bool(regression),
        "schema_version": 1,
        "diff_kind": "scan",
    }


def print_diff(diff: Dict[str, Any], verbose: bool = True) -> None:
    """Console summary matching SurfaceSweep prefix format."""
    if not verbose:
        return
    info(" --- Scan Diff ---")
    old_t = diff.get("old_target") or "?"
    new_t = diff.get("new_target") or "?"
    detail(f"[*] Baseline: {old_t}")
    detail(f"[*] Current:  {new_t}")

    for section, label in (
        ("endpoints", "Endpoints"),
        ("secrets", "Secrets"),
        ("library_vulnerabilities", "Library vulns"),
    ):
        block = diff.get(section) or {}
        added = len(block.get("added") or [])
        removed = len(block.get("removed") or [])
        unchanged = block.get("unchanged", 0)
        if added or removed:
            ok(f" {label}: +{added} added, -{removed} removed ({unchanged} unchanged)")
            for item in (block.get("added") or [])[:20]:
                detail(f"    + {item}")
            for item in (block.get("removed") or [])[:20]:
                detail(f"    - {item}")
            extra = added + removed - min(added, 20) - min(removed, 20)
            if added + removed > 40:
                detail(f"    … {max(0, extra)} more not shown")
        else:
            detail(f"[*] {label}: no change ({unchanged} unchanged)")

    risk = diff.get("risk") or {}
    delta = risk.get("score_delta", 0)
    old_score = (risk.get("old") or {}).get("score", 0)
    new_score = (risk.get("new") or {}).get("score", 0)
    if delta:
        sign = "+" if delta > 0 else ""
        warn(f" Risk: {old_score} → {new_score} ({sign}{delta})")
    else:
        detail(f"[*] Risk: {new_score} (unchanged)")

    if diff.get("regression"):
        warn(" REGRESSION: risk increased or new HIGH/CRITICAL findings appeared")
    else:
        ok(" No regression detected")


def save_diff(diff: Dict[str, Any], path: str) -> bool:
    """Write diff JSON to path. Returns True on success."""
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(diff, fh, indent=2, sort_keys=True)
            fh.write("\n")
        ok(f" Diff JSON saved: {path}")
        return True
    except OSError as e:
        warn(f" Failed to save diff: {e}")
        return False


def run_diff_cli(baseline_path: str, current_path: str, output: Optional[str] = None,
                 verbose: bool = True) -> Dict[str, Any]:
    """Offline entry: load two reports, print + optionally save the diff."""
    old = load_result(baseline_path)
    new = load_result(current_path)
    diff = diff_results(old, new)
    print_diff(diff, verbose=verbose)
    if output:
        save_diff(diff, output)
    return diff


def _main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Diff two SurfaceSweep JSON scan reports",
    )
    parser.add_argument("baseline", help="Older / baseline scan JSON")
    parser.add_argument("current", help="Newer / current scan JSON")
    parser.add_argument("-o", "--output", default=None, help="Write diff JSON to FILE")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress summary")
    args = parser.parse_args(argv)
    try:
        run_diff_cli(args.baseline, args.current, output=args.output,
                     verbose=not args.quiet)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
