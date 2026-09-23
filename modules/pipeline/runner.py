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
    Returns the final result dict.
    """
    ctx = ScanContext(args, verbose=verbose, headers=headers)
    for name, fn in build_stages(args):
        ctx.stages_run.append(name)
        fn(ctx)
    return ctx.require_result()
