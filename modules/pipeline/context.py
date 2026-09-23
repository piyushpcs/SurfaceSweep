"""
Scan context shared across pipeline stages.

Holds CLI args, verbosity, auth headers, and the mutable result dict
that each stage enriches.
"""

from __future__ import annotations

from argparse import Namespace
from typing import Any, Optional


class ScanContext:
    """Mutable state passed through every pipeline stage."""

    __slots__ = ("args", "verbose", "headers", "result", "wayback_result",
                 "waf_info", "waf_adjustments", "stages_run")

    def __init__(self, args: Namespace, verbose: bool = True,
                 headers: Optional[dict] = None):
        self.args = args
        self.verbose = verbose
        self.headers = headers or {}
        self.result: Optional[dict] = None
        self.wayback_result: Optional[dict] = None
        self.waf_info: Optional[dict] = None
        self.waf_adjustments: Optional[dict] = None
        self.stages_run: list[str] = []

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def require_result(self) -> dict:
        if self.result is None:
            raise RuntimeError("pipeline: result not initialized (scan stage must run first)")
        return self.result
