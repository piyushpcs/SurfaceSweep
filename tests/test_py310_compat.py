"""
Guard the declared Python floor (requires-python >= 3.10).

Static AST scan for imports of symbols that only exist on newer Pythons, so a
3.11+/3.12+ import can't slip in and break the 3.10 CI leg (which is exactly
how ``typing.NotRequired`` went unnoticed: the code ran fine on 3.12 locally but
failed to import on 3.10).
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# module -> names that require a Python newer than 3.10
_TOO_NEW = {
    "typing": {
        "NotRequired",  # 3.11
        "Required",  # 3.11
        "Self",  # 3.11
        "LiteralString",  # 3.11
        "Never",  # 3.11
        "TypeVarTuple",  # 3.11
        "Unpack",  # 3.11
        "assert_never",  # 3.11
        "assert_type",  # 3.11
        "reveal_type",  # 3.11
        "dataclass_transform",  # 3.11
    },
    "tomllib": {"*"},  # stdlib added in 3.11
}

# modules whose presence alone implies a newer interpreter
_TOO_NEW_MODULES = {"tomllib"}  # 3.11

_SCAN_DIRS = ("modules",)
_SCAN_FILES = ("main.py", "mcp_server.py")


def _iter_sources():
    for directory in _SCAN_DIRS:
        base = os.path.join(ROOT, directory)
        for dirpath, _dirnames, filenames in os.walk(base):
            if "__pycache__" in dirpath:
                continue
            for name in filenames:
                if name.endswith(".py"):
                    yield os.path.join(dirpath, name)
    for name in _SCAN_FILES:
        path = os.path.join(ROOT, name)
        if os.path.exists(path):
            yield path


def _find_too_new(path):
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in _TOO_NEW:
            banned = _TOO_NEW[node.module]
            for alias in node.names:
                if "*" in banned or alias.name in banned:
                    found.append(f"{node.module}.{alias.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _TOO_NEW_MODULES:
                    found.append(alias.name)
    return found


class TestPython310Compatibility(unittest.TestCase):
    def test_no_newer_than_310_imports(self):
        offenders = {}
        for path in _iter_sources():
            hits = _find_too_new(path)
            if hits:
                offenders[os.path.relpath(path, ROOT)] = hits
        self.assertEqual(
            offenders,
            {},
            f"imports require Python > 3.10: {offenders}",
        )


if __name__ == "__main__":
    unittest.main()
