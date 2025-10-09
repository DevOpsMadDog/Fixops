"""Helpers for minting deterministic application and component identifiers."""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict, Mapping, MutableMapping

_APP_MIN = 1000
_APP_RANGE = 9000


def ensure_ids(design_document: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a copy of the design document with guaranteed identifiers."""

    normalized = copy.deepcopy(dict(design_document))
    app_name = str(normalized.get("app_name") or "app")
    app_id = str(normalized.get("app_id") or _mint_app_id(app_name))
    normalized["app_id"] = app_id

    components = normalized.get("components")
    if isinstance(components, list):
        for component in components:
            if isinstance(component, MutableMapping):
                name = str(component.get("name") or "component")
                component.setdefault("component_id", _mint_component_id(name))
    return normalized


def _mint_app_id(app_name: str) -> str:
    digest = hashlib.sha1(app_name.encode("utf-8")).hexdigest()
    number = int(digest, 16) % _APP_RANGE + _APP_MIN
    return f"APP-{number:04d}"


def _mint_component_id(name: str) -> str:
    cleaned = [ch.lower() if ch.isalnum() else "-" for ch in name]
    token = "".join(cleaned).strip("-") or "component"
    stem = token.split("-")[0] or "component"
    return f"C-{stem.lower()}"


__all__ = ["ensure_ids"]
