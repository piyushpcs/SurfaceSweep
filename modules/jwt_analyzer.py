"""
Legacy import path — Phase 3 JWT analyzer now lives in modules.jwt.

Kept so older imports (`from modules.jwt_analyzer import ...`) keep working.
Prefer: `from modules.jwt import ...`
"""

from modules.jwt import *  # noqa: F401,F403 — re-export public API
from modules.jwt import __all__  # noqa: F401
