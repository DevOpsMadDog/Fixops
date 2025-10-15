"""Filesystem helpers with guardrails for evidence storage."""

from __future__ import annotations

from pathlib import Path


def resolve_within_root(root: Path, name: str) -> Path:
    """Return *name* resolved beneath *root* or raise when escaping."""

    resolved_root = root.resolve()
    safe_name = Path(str(name))
    candidate = (resolved_root / safe_name).resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError("refusing to write outside evidence root")
    return candidate


__all__ = ["resolve_within_root"]
