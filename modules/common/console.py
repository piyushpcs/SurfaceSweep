"""
Console output helpers with the SurfaceSweep CLI prefix format.

Replaces bare ``print()`` so quiet mode, future log sinks, and tests can
control progress output from one place. Format matches historical output:

    [*] progress / info
    [+] success / results
    [!] warnings / findings
        indented detail lines
"""

from __future__ import annotations

import sys
from typing import Optional, TextIO

__all__ = [
    "configure_console",
    "detail",
    "emit",
    "error",
    "info",
    "is_quiet",
    "ok",
    "warn",
]

_config = {"quiet": False}


def configure_console(quiet: bool = False) -> None:
    """Set process-wide quiet mode (CLI --quiet / tests)."""
    _config["quiet"] = bool(quiet)


def is_quiet() -> bool:
    return bool(_config["quiet"])


def _write(msg: str, file: Optional[TextIO] = None) -> None:
    if not _config["quiet"]:
        print(msg, file=file if file is not None else sys.stdout)


def _trim(msg: str) -> str:
    """Drop one leading space left after stripping a CLI prefix."""
    return msg[1:] if msg.startswith(" ") else msg


def emit(msg: str, file: Optional[TextIO] = None) -> None:
    """Print a pre-formatted line (already includes prefixes/indent) unless quiet."""
    _write(msg, file)


def info(msg: str) -> None:
    """Progress / informational line: ``[*] msg``."""
    _write(f"[*] {_trim(msg)}")


def ok(msg: str) -> None:
    """Success / result line: ``[+] msg``."""
    _write(f"[+] {_trim(msg)}")


def warn(msg: str) -> None:
    """Warning / finding line: ``[!] msg`` (stdout, matches historical CLI)."""
    _write(f"[!] {_trim(msg)}")


def error(msg: str) -> None:
    """Error line to stderr (always shown, even in quiet — fatal path)."""
    print(msg, file=sys.stderr)


def detail(msg: str) -> None:
    """Indented detail under a parent line: four spaces + msg."""
    _write(f"    {msg}")
