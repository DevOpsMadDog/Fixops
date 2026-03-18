"""
sitecustomize.py - Automatic sys.path configuration for FixOps suite structure.

This module is automatically loaded by Python at startup. It prepends the suite
directories to sys.path so that cross-suite imports work seamlessly.

Example:
    - `import apps.api.app` works even though apps/ is now in suite-api/
    - `import core` works even though core/ is now in suite-core/
    - `import risk` works even though risk/ is now in suite-evidence-risk/
    - `import backend` works even though backend/ is now in suite-api/

This enables backward compatibility with existing scripts, imports, and uvicorn commands.
"""

import sys
from pathlib import Path

# ── Python 3.14 dataclasses bug workaround (cpython#142214) ──
# dataclasses._add_slots crashes: 'wrapper_descriptor' has no '__annotate__'
# when @dataclass(init=False, slots=True) is used (e.g. networkx).
# NOTE: This sitecustomize.py may not be loaded if a system-level one exists.
# The same patch is also applied in tests/conftest.py for pytest.
if sys.version_info[:2] == (3, 14):
    import dataclasses as _dc

    _orig_add_slots = _dc._add_slots  # type: ignore[attr-defined]

    def _safe_add_slots(cls, is_frozen, weakref_slot, fields):  # type: ignore[no-untyped-def]
        try:
            return _orig_add_slots(cls, is_frozen, weakref_slot, fields)
        except AttributeError as exc:
            if "__annotate__" in str(exc):
                return cls  # fall back to non-slots
            raise

    _dc._add_slots = _safe_add_slots  # type: ignore[attr-defined]
# ── End Python 3.14 workaround ──

# Determine the project root (same directory as this file)
_PROJECT_ROOT = Path(__file__).parent.resolve()

# Suite directories to add to sys.path (order matters for import priority)
_SUITE_PATHS = [
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-integrations",
    "suite-evidence-risk",
]

# Prepend suite paths to sys.path if they exist
for suite in _SUITE_PATHS:
    suite_path = _PROJECT_ROOT / suite
    if suite_path.is_dir():
        suite_str = str(suite_path)
        if suite_str not in sys.path:
            sys.path.insert(0, suite_str)
