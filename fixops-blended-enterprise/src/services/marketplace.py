"""Marketplace helper utilities for demo remediation packs."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping

_PACK_ROOT = Path(__file__).resolve().parents[3] / "marketplace" / "packs"

# Map control identifiers to pack directories and filenames
_CONTROL_MAP: dict[str, tuple[str, str, str]] = {
    "ISO27001:AC-2": ("iso", "ac-2", "least-privilege.json"),
    "ISO27001:AC-1": ("iso", "ac-1", "network-segmentation.json"),
    "PCI:8.3": ("pci", "8.3", "mfa.json"),
}


def get_recommendations(control_ids: Iterable[str]) -> list[dict[str, Any]]:
    """Return remediation pack recommendations for failing controls."""

    recommendations = []
    for control in control_ids or []:
        pack = _load_pack(control)
        if not pack:
            continue
        recommendations.append(
            {
                "control_id": control,
                "pack_id": pack.get("pack_id"),
                "title": pack.get("title"),
                "link": pack.get("link"),
            }
        )
    return recommendations


def get_pack(framework: str, control: str) -> Mapping[str, Any]:
    """Return the pack metadata for the requested framework/control pair."""

    lookup_key = f"{framework}:{control}".upper()
    pack = _load_pack(lookup_key)
    if pack:
        return pack
    # Attempt to resolve partial matches (framework may already be normalized)
    for control_id in _CONTROL_MAP:
        if control_id.upper().startswith(f"{framework.upper()}:{control.upper()}"):
            pack = _load_pack(control_id)
            if pack:
                return pack
    raise FileNotFoundError(f"Pack {framework}/{control} not found")


@lru_cache(maxsize=None)
def _load_pack(control_id: str) -> Mapping[str, Any] | None:
    mapping = _CONTROL_MAP.get(control_id)
    if not mapping:
        return None
    framework, control, filename = mapping
    path = _PACK_ROOT / framework / control / filename
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    data.setdefault("pack_id", path.stem)
    data.setdefault("link", f"/api/v1/marketplace/packs/{framework}/{control}")
    return data


__all__ = ["get_recommendations", "get_pack"]
