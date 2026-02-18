"""Utilities for safely resolving evidence file paths."""

from __future__ import annotations

from pathlib import Path


def resolve_within_root(root: Path, name: str) -> Path:
    """Resolve *name* beneath *root* ensuring the result remains inside *root*.

    The helper normalises the provided ``name`` to its final path component and
    rejects attempts to traverse outside the ``root`` directory. Callers receive
    the resolved path suitable for IO operations.
    """

    resolved_root = root.resolve()
    provided = Path(str(name))
    if provided.is_absolute() or any(part == ".." for part in provided.parts):
        raise ValueError("refusing to write outside evidence root")
    safe_name = provided.name
    candidate = (resolved_root / safe_name).resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError("refusing to write outside evidence root")
    return candidate


__all__ = ["resolve_within_root"]
