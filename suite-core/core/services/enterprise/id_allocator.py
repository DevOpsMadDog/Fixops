"""Enterprise ID allocator — assigns APP-IDs and run-IDs to stage artefacts."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict

_COUNTER: int = 0


def _stable_hash(name: str) -> int:
    """Return a deterministic hash for *name* that is stable across processes.

    Python's built-in ``hash()`` is randomised per-process (since 3.3+) which
    means the same app_name produces different APP-IDs in different sub-process
    invocations.  We use MD5 (not for security — just for stability) to derive
    a deterministic integer.
    """
    digest = hashlib.md5(name.encode("utf-8"), usedforsecurity=False).hexdigest()
    return int(digest[:8], 16)


def _next_app_id() -> str:
    """Generate a new APP-ID in the canonical format."""
    global _COUNTER
    _COUNTER += 1
    return f"APP-{10000 + _COUNTER}"


def ensure_ids(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure the payload has ``app_id`` and ``run_id`` fields.

    If they are missing or empty, deterministic IDs are allocated based on
    ``app_name`` or a UUID fallback.
    """
    result = dict(payload)

    if not result.get("app_id"):
        app_name = result.get("app_name", "")
        if app_name:
            # Deterministic ID based on app name (stable across processes)
            hash_suffix = _stable_hash(app_name) % 90000 + 10000
            result["app_id"] = f"APP-{hash_suffix}"
        else:
            result["app_id"] = _next_app_id()

    if not result.get("run_id"):
        result["run_id"] = uuid.uuid4().hex[:12]

    return result


def allocate_run_id() -> str:
    """Allocate a fresh run ID."""
    return uuid.uuid4().hex[:12]


def allocate_app_id(app_name: str | None = None) -> str:
    """Allocate a fresh APP-ID, optionally seeded from the application name."""
    if app_name:
        hash_suffix = _stable_hash(app_name) % 90000 + 10000
        return f"APP-{hash_suffix}"
    return _next_app_id()
