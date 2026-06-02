"""Enterprise ID allocator — assigns APP-IDs and run-IDs to stage artefacts."""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from typing import Any, Dict, MutableMapping

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


def _mint_component_id(name: str) -> str:
    """Mint a deterministic ``C-<stem>`` component id from a component name.

    ``login-ui`` -> ``C-login``, ``claims-core`` -> ``C-claims``. The stem is
    the first alphanumeric token of the slugified name.
    """
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in name)
    token = cleaned.strip("-") or "component"
    stem = token.split("-")[0] or "component"
    return f"C-{stem}"


def _deterministic_run_id(result: Dict[str, Any]) -> str:
    """Derive a reproducible run id from the document's stable identity.

    Hashing app_id + the ordered component ids means an identical design
    document always yields the same run_id (honours this module's documented
    deterministic contract), while distinct documents diverge.
    """
    components = result.get("components")
    component_ids = (
        [c.get("component_id") for c in components if isinstance(c, MutableMapping)]
        if isinstance(components, list)
        else []
    )
    seed = json.dumps(
        {"app_id": result.get("app_id"), "components": component_ids},
        sort_keys=True,
        default=str,
    )
    return hashlib.md5(seed.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def ensure_ids(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of *payload* with guaranteed deterministic identifiers.

    Mints, when missing: ``app_id`` (from ``app_name``), a ``component_id`` for
    each entry in ``components`` (``C-<stem>``), and a content-derived
    ``run_id``. The input is never mutated and identical documents always
    produce identical output.
    """
    result = copy.deepcopy(dict(payload))

    if not result.get("app_id"):
        app_name = result.get("app_name", "")
        if app_name:
            # Deterministic ID based on app name (stable across processes)
            hash_suffix = _stable_hash(app_name) % 90000 + 10000
            result["app_id"] = f"APP-{hash_suffix}"
        else:
            result["app_id"] = _next_app_id()

    components = result.get("components")
    if isinstance(components, list):
        for component in components:
            if isinstance(component, MutableMapping) and not component.get(
                "component_id"
            ):
                component["component_id"] = _mint_component_id(
                    str(component.get("name") or "component")
                )

    if not result.get("run_id"):
        result["run_id"] = _deterministic_run_id(result)

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
