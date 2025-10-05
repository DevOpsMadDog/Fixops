"""Path utilities for enforcing secure data directories."""
from __future__ import annotations

import os
import stat
from pathlib import Path


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


__all__ = ["ensure_secure_directory"]
