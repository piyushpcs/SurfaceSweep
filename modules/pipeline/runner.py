"""
Pipeline runner — builds the ordered stage list from CLI flags and executes it.

Stage order (Phase 2.2: CORS runs after validate so probes hit live endpoints;
Phase F3: graphql runs after validate, before cors;
Phase F4: verify_secrets after graphql, before cors):
  waf_detect → wayback_fetch → scan → import → wayback_merge → waf_inject →
  cve → spa → jwt → validate → graphql → verify_secrets → cors → export → report
"""

from __future__ import annotations

from argparse import Namespace
from typing import Callable, List, Tuple

from modules.common.result import RESULT_SCHEMA_VERSION, ScanResult
from modules.common.console import warn
from modules.pipeline.context import ScanContext
from modules.pipeline.stages import (
    stage_cors,
    stage_cve,
    stage_export,
    stage_graphql,
    stage_import,
    stage_jwt,
    stage_report,
    stage_scan,
    stage_spa,
    stage_validate,
    stage_verify_secrets,
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
    ("import", stage_import, lambda a: bool(getattr(a, "import_files", None))),
    ("wayback_merge", stage_wayback_merge, lambda a: bool(a.wayback)),
    ("waf_inject", stage_waf_inject, lambda a: bool(a.waf)),
    ("cve", stage_cve, lambda a: bool(a.cve or a.osv)),
    ("spa", stage_spa, lambda a: bool(a.spa)),
    ("jwt", stage_jwt, lambda a: bool(a.jwt)),
    ("validate", stage_validate, lambda a: bool(a.validate)),
    ("graphql", stage_graphql, lambda a: bool(getattr(a, "graphql", False))),
    ("verify_secrets", stage_verify_secrets, lambda a: bool(getattr(a, "verify_secrets", False))),
    ("cors", stage_cors, lambda a: bool(a.cors or getattr(a, "cors_poc", False))),
    ("export", stage_export, lambda a: bool(a.burp or a.zap or getattr(a, "cors_poc", False))),
    ("report", stage_report, lambda a: True),
]


def build_stages(args: Namespace) -> List[Tuple[str, StageFn]]:
    """Return the enabled (name, fn) stages for this arg set, in run order."""
    return [(name, fn) for name, fn, enabled in _STAGE_SPECS if enabled(args)]


def stage_names(args: Namespace) -> List[str]:
    """Names of stages that would run for these args (for tests / meta)."""
    return [name for name, _ in build_stages(args)]


def run_pipeline(args: Namespace, verbose: bool = True,
                 headers: dict | None = None) -> ScanResult:
    """
    Execute all enabled stages against a fresh ScanContext.
    Stamps schema_version + meta + findings before the report stage so
    JSON/HTML on disk include the full contract (Step 4 + Step 6).
    """
    from datetime import datetime, timezone
    from time import monotonic
    from modules.extraction.http import request_count, reset_request_count

    reset_request_count()
    ctx = ScanContext(args, verbose=verbose, headers=headers)
    for name, fn in build_stages(args):
        # Record the stage before it runs so the report written *during* the
        # report stage lists itself, then stamp findings/meta before that stage
        # serializes the result.
        ctx.stages_run.append(name)
        if name == "report" and ctx.result is not None and "schema_version" not in ctx.result:
            _finalize_result(ctx, datetime.now(timezone.utc))
        started = monotonic()
        try:
            fn(ctx)
        except Exception as exc:
            # One stage failing must not abort the whole scan / lose the report.
            ctx.stage_errors.append(f"{name}: {exc}")
            warn(f"[!] Stage '{name}' failed: {exc}")
            if ctx.result is not None:
                ctx.result.setdefault("errors", [])
                ctx.result["errors"].append(f"stage {name} failed: {exc}")
        ctx.stage_timings[name] = round(monotonic() - started, 3)

    if ctx.result is not None:
        if "schema_version" not in ctx.result:
            _finalize_result(ctx, datetime.now(timezone.utc))
        else:
            # Refresh meta so stages_run/stage_timings include report
            _stamp_meta(ctx, datetime.now(timezone.utc))
        # Scan footprint — evidence of a bounded, paced scan for VDP notes.
        ctx.log(f"[*] Total HTTP requests sent: {request_count()}")
    return ctx.require_result()


def _finalize_result(ctx: ScanContext, finished_at) -> None:
    """Attach findings feed, executive summary, schema_version, and meta."""
    if ctx.result is None:
        return

    # Stamp meta first so the executive summary can report the request
    # footprint (it reads meta.requests_sent).
    _stamp_meta(ctx, finished_at)
    from modules.reporting.findings import build_executive_summary, build_findings_feed
    feed = build_findings_feed(ctx.result)
    ctx.result["findings"] = feed
    ctx.result["executive_summary"] = build_executive_summary(ctx.result, feed)


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
            "validate", "graphql", "verify_secrets", "burp", "zap", "html", "html_only",
            "full", "browser",
        )
        if getattr(args, name, False)
    )
    if getattr(args, "import_files", None):
        flags.append("import")
        flags.sort()

    ctx.result["schema_version"] = RESULT_SCHEMA_VERSION
    from modules.extraction.http import request_count
    ctx.result["meta"] = {
        "tool": "SurfaceSweep",
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round(ctx.elapsed(), 3),
        "scan_mode": scan_mode,
        "stages_run": list(ctx.stages_run),
        "stage_timings": dict(ctx.stage_timings),
        "flags": flags,
        "requests_sent": request_count(),
    }
