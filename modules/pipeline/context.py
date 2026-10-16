"""
Scan context shared across pipeline stages.

Holds CLI args, verbosity, auth headers, and the mutable result dict
that each stage enriches. Also tracks stage timing for the result meta block.
"""

from __future__ import annotations

from argparse import Namespace
from time import monotonic
from typing import Optional

from modules.common.console import emit
from modules.common.result import ScanResult


class ScanContext:
    """Mutable state passed through every pipeline stage."""

    __slots__ = ("args", "verbose", "headers", "result", "wayback_result",
                 "waf_info", "waf_adjustments", "stages_run", "_t0",
                 "stage_timings", "stage_errors")

    def __init__(self, args: Namespace, verbose: bool = True,
                 headers: Optional[dict] = None):
        self.args = args
        self.verbose = verbose
        self.headers = headers or {}
        self.result: Optional[ScanResult] = None
        self.wayback_result: Optional[dict] = None
        self.waf_info: Optional[dict] = None
        self.waf_adjustments: Optional[dict] = None
        self.stages_run: list[str] = []
        self.stage_timings: dict[str, float] = {}
        self.stage_errors: list[str] = []
        self._t0 = monotonic()

    def log(self, msg: str) -> None:
        if self.verbose:
            emit(msg)

    def require_result(self) -> ScanResult:
        if self.result is None:
            raise RuntimeError("pipeline: result not initialized (scan stage must run first)")
        return self.result

    def elapsed(self) -> float:
        """Total seconds since the context was created."""
        return monotonic() - self._t0
