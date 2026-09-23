"""
Pipeline — ordered scan stages and merge helpers (Phase 4 Steps 1–2).

Public API:
    run_pipeline, build_stages, stage_names, ScanContext,
    collect_endpoints, merge_wayback, merge_endpoints, merge_secrets, ...
"""

from modules.pipeline.context import ScanContext
from modules.pipeline.merge import (
    collect_endpoints,
    flatten_secrets,
    merge_endpoints,
    merge_errors,
    merge_in_scope_urls,
    merge_internal_hosts,
    merge_jwts,
    merge_paths,
    merge_secrets,
    merge_sinks,
    merge_wayback,
)
from modules.pipeline.runner import build_stages, run_pipeline, stage_names

__all__ = [
    "ScanContext",
    "build_stages",
    "run_pipeline",
    "stage_names",
    "collect_endpoints",
    "flatten_secrets",
    "merge_endpoints",
    "merge_errors",
    "merge_in_scope_urls",
    "merge_internal_hosts",
    "merge_jwts",
    "merge_paths",
    "merge_secrets",
    "merge_sinks",
    "merge_wayback",
]
