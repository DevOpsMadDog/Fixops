"""Path utilities for enforcing secure data directories."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable, Tuple


def _current_uid() -> int | None:
    try:
        return os.getuid()
    except AttributeError:  # pragma: no cover - not available on Windows
        return None


def _validate_directory_security(path: Path, expected_uid: int | None) -> None:
    if not path.exists():
        raise PermissionError(
            f"Allowlisted directory '{path}' does not exist; create it with secure permissions"
        )
    stats = path.stat()
    if stats.st_mode & stat.S_IWOTH:
        raise PermissionError(
            f"Directory '{path}' must not be world-writable for regulated storage"
        )
    if expected_uid is not None and hasattr(stats, "st_uid"):
        if stats.st_uid not in {expected_uid, 0}:
            raise PermissionError(
                f"Directory '{path}' is owned by unexpected UID {stats.st_uid}; "
                "ensure the FixOps process or root owns data roots"
            )


def ensure_secure_directory(path: Path, mode: int = 0o750) -> Path:
    """Create *path* if needed and enforce restrictive permissions.

    Directories are created with the provided ``mode`` (default ``0o750``). If the
    resulting directory is world-writable the function raises ``PermissionError`` to
    prevent unsafe evidence or artefact storage locations from being used. The
    caller receives the resolved ``Path`` object for further operations.
    """

    resolved = path.resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(resolved, mode)
    except PermissionError:
        # Windows systems may not support chmod in the same way; continue after best effort.
        pass

    stats = resolved.stat()
    # Deny directories that allow writes for "others" to avoid accidental leakage.
    if stats.st_mode & stat.S_IWOTH:
        raise PermissionError(
            f"Directory '{resolved}' must not be world-writable for regulated storage"
        )
    return resolved


def verify_allowlisted_path(path: Path, allowlist: Iterable[Path]) -> Path:
    """Resolve *path* and ensure it resides inside a secure allowlisted root."""

    resolved_allowlist: Tuple[Path, ...] = tuple(root.resolve() for root in allowlist)
    if not resolved_allowlist:
        raise PermissionError("No data directory allowlist configured")

    resolved = path.expanduser().resolve()
    matched_root: Path | None = None
    for root in resolved_allowlist:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        else:
            matched_root = root
            break

    if matched_root is None:
        raise PermissionError(
            f"Directory '{resolved}' is not within the configured allowlist: {resolved_allowlist}"
        )

    uid = _current_uid()
    ancestor = matched_root
    _validate_directory_security(ancestor, uid)
    for parent in resolved.parents:
        if matched_root in {parent, parent.resolve()}:
            break
        if parent.exists():
            _validate_directory_security(parent, uid)
    if resolved.exists():
        _validate_directory_security(resolved, uid)

    return resolved


__all__ = ["ensure_secure_directory", "verify_allowlisted_path"]
