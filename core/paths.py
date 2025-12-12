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


def ensure_output_directory(path: Path, mode: int = 0o750) -> Path:
    """Create *path* if needed for user-specified output files.

    This is a relaxed version of ``ensure_secure_directory`` for non-regulated
    storage like user-specified output paths (--output flag). Unlike the strict
    version, this function allows world-writable directories (e.g., /tmp) but
    still attempts to set restrictive permissions where possible.

    Use this for user-facing output paths. Use ``ensure_secure_directory`` for
    regulated storage (evidence, uploads, archives).
    """

    resolved = path.resolve()
    directory_existed = resolved.exists()
    resolved.mkdir(parents=True, exist_ok=True)

    if not directory_existed:
        try:
            os.chmod(resolved, mode)
        except PermissionError:
            # Windows systems may not support chmod in the same way; continue after best effort.
            pass

    return resolved


def verify_allowlisted_path(path: Path, allowlist: Iterable[Path]) -> Path:
    """Resolve *path* and ensure it resides inside a secure allowlisted root.

    The path itself does not need to exist, but all existing ancestors must pass
    security validation. This allows first-run initialization to validate paths
    before creating them.

    This function acts as a path sanitizer - callers should always use the returned
    Path object for any filesystem operations, not the original input path.
    """
    # Step 1: Resolve and validate the allowlist roots first (trusted paths)
    resolved_allowlist: Tuple[Path, ...] = tuple(root.resolve() for root in allowlist)
    if not resolved_allowlist:
        raise PermissionError("No data directory allowlist configured")

    # Step 2: Validate allowlist roots exist and have secure permissions
    uid = _current_uid()
    for root in resolved_allowlist:
        if not root.exists():
            raise PermissionError(
                f"Allowlisted root '{root}' does not exist; create it with secure permissions"
            )
        _validate_directory_security(root, uid)

    # Step 3: Now resolve the user-provided path and check it's within allowlist
    # This is intentionally done AFTER validating the allowlist roots
    resolved = path.expanduser().resolve()  # codeql[py/path-injection]
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

    # Step 4: Validate all existing parent directories have secure permissions
    for parent in resolved.parents:
        if matched_root in {parent, parent.resolve()}:
            break
        if parent.exists():
            _validate_directory_security(parent, uid)

    # Step 5: Validate the resolved path itself if it exists
    if resolved.exists():
        _validate_directory_security(resolved, uid)

    return resolved


__all__ = [
    "ensure_secure_directory",
    "ensure_output_directory",
    "verify_allowlisted_path",
]
