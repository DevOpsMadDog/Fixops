"""
sitecustomize.py - Automatic sys.path configuration for FixOps suite structure.

This module is automatically loaded by Python at startup. It prepends the suite
directories to sys.path so that legacy imports continue to work after restructure.

Example:
    - `import apps.api.app` works even though apps/ is now in suite-api/
    - `import core` works even though core/ is now in suite-core/
    - `import risk` works even though risk/ is now in suite-evidence-risk/
    - `import backend` works even though backend/ is now in suite-api/

This enables backward compatibility with existing scripts, imports, and uvicorn commands.
"""

import sys
from pathlib import Path

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
    # Legacy code paths (still imported by some modules)
    "archive/legacy",
    "archive/enterprise_legacy",
]

# Prepend suite paths to sys.path if they exist
for suite in _SUITE_PATHS:
    suite_path = _PROJECT_ROOT / suite
    if suite_path.is_dir():
        suite_str = str(suite_path)
        if suite_str not in sys.path:
            sys.path.insert(0, suite_str)
