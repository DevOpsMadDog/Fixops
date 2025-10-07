"""Pytest configuration for FixOps tests."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PACKAGE_ROOT = PROJECT_ROOT / "fixops-blended-enterprise"
SRC_PATH = SRC_PACKAGE_ROOT / "src"

for path in (SRC_PACKAGE_ROOT, SRC_PATH):
    if str(path) not in sys.path:
        sys.path.append(str(path))
