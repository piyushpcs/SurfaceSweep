"""
Pipeline runner — builds the ordered stage list from CLI flags and executes it.

Stage order matches the original main.py sequence exactly:
  waf_detect → wayback_fetch → scan → wayback_merge → waf_inject →
  cve → spa → cors → jwt → validate → export → report
"""

from __future__ import annotations

from argparse import Namespace
from typing import Callable, List, Tuple

from modules.pipeline.context import ScanContext
from modules.pipeline.stages import (
    stage_cors,
    stage_cve,
    stage_export,
    stage_jwt,
    stage_report,
    stage_scan,
    stage_spa,
    stage_validate,
    stage_waf_detect,
    stage_waf_inject,
    stage_wayback_fetch,
    stage_wayback_merge,
)

StageFn = Callable[[ScanContext], None]

# (name, stage_fn, enabled predicate on args)
_STAGE_SPECS: List[Tuple[str, StageFn, Callable[[Namespace], bool]]] = [
    ("waf_detect", stage_waf_detect, lambda a: bool(a.waf)),
    ("wayback_fetch", stage_wayback_fetch, lambda a: bool(a.wayback)),
    ("scan", stage_scan, lambda a: True),
    ("wayback_merge", stage_wayback_merge, lambda a: bool(a.wayback)),
    ("waf_inject", stage_waf_inject, lambda a: bool(a.waf)),
    ("cve", stage_cve, lambda a: bool(a.cve or a.osv)),
    ("spa", stage_spa, lambda a: bool(a.spa)),
    ("cors", stage_cors, lambda a: bool(a.cors)),
    ("jwt", stage_jwt, lambda a: bool(a.jwt)),
    ("validate", stage_validate, lambda a: bool(a.validate)),
    ("export", stage_export, lambda a: bool(a.burp or a.zap)),
    ("report", stage_report, lambda a: True),
]


def build_stages(args: Namespace) -> List[Tuple[str, StageFn]]:
    """Return the enabled (name, fn) stages for this arg set, in run order."""
    return [(name, fn) for name, fn, enabled in _STAGE_SPECS if enabled(args)]


def stage_names(args: Namespace) -> List[str]:
    """Names of stages that would run for these args (for tests / meta)."""
    return [name for name, _ in build_stages(args)]


def run_pipeline(args: Namespace, verbose: bool = True,
                 headers: dict | None = None) -> dict:
    """
    Execute all enabled stages against a fresh ScanContext.
    Stamps schema_version + meta + findings before the report stage so
    JSON/HTML on disk include the full contract (Step 4 + Step 6).
    """
    from datetime import datetime, timezone
    from time import monotonic

    ctx = ScanContext(args, verbose=verbose, headers=headers)
    for name, fn in build_stages(args):
        # Stamp before report so saved JSON/HTML include meta + findings
        if name == "report" and ctx.result is not None and "schema_version" not in ctx.result:
            _finalize_result(ctx, datetime.now(timezone.utc))
        started = monotonic()
        ctx.stages_run.append(name)
        fn(ctx)
        ctx.stage_timings[name] = round(monotonic() - started, 3)

    if ctx.result is not None:
        if "schema_version" not in ctx.result:
            _finalize_result(ctx, datetime.now(timezone.utc))
        else:
            # Refresh meta so stages_run/stage_timings include report
            _stamp_meta(ctx, datetime.now(timezone.utc))
    return ctx.require_result()


def _finalize_result(ctx: ScanContext, finished_at) -> None:
    """Attach findings feed, executive summary, schema_version, and meta."""
    if ctx.result is None:
        return

    # Stage timings known so far (report stage still pending when called early)
    from modules.reporting.findings import build_executive_summary, build_findings_feed
    feed = build_findings_feed(ctx.result)
    ctx.result["findings"] = feed
    ctx.result["executive_summary"] = build_executive_summary(ctx.result, feed)
    _stamp_meta(ctx, finished_at)


def _stamp_meta(ctx: ScanContext, finished_at) -> None:
    """Attach schema_version + meta block to the final result (Step 4)."""
    if ctx.result is None:
        return
    args = ctx.args
    scan_mode = "static"
    if getattr(args, "full", False):
        scan_mode = "full"
    elif getattr(args, "browser", False):
        scan_mode = "browser"
    if ctx.result.get("scan_mode"):
        scan_mode = ctx.result["scan_mode"]

    flags = sorted(
        name for name in (
            "waf", "wayback", "cve", "osv", "spa", "cors", "jwt",
            "validate", "burp", "zap", "html", "html_only", "full", "browser",
        )
        if getattr(args, name, False)
    )

    ctx.result["schema_version"] = 1
    ctx.result["meta"] = {
        "tool": "SurfaceSweep",
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round(ctx.elapsed(), 3),
        "scan_mode": scan_mode,
        "stages_run": list(ctx.stages_run),
        "stage_timings": dict(ctx.stage_timings),
        "flags": flags,
    }
