"""Minimal SARIF model stub for tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class SarifLog:
    runs: List[Any]
    version: str
    schema_uri: Optional[str] = None
    properties: Optional[dict[str, Any]] = field(default=None)
