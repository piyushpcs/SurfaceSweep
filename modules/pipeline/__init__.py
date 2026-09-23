"""
Pipeline — ordered scan stages (Phase 4 Step 1).

Public API:
    run_pipeline, build_stages, stage_names, ScanContext
"""

from modules.pipeline.context import ScanContext
from modules.pipeline.runner import build_stages, run_pipeline, stage_names

__all__ = [
    "ScanContext",
    "build_stages",
    "run_pipeline",
    "stage_names",
]
