"""Tests for deterministic ID allocation in design documents."""

from __future__ import annotations

from copy import deepcopy

from src.services.id_allocator import ensure_ids


def _sample_design() -> dict:
    return {
        "app_name": "life-claims-portal",
        "components": [
            {"name": "login-ui", "tier": "tier-0", "exposure": "internet", "pii": True},
            {
                "name": "claims-core",
                "tier": "tier-0",
                "exposure": "internal",
                "pii": True,
            },
        ],
    }


def test_ensure_ids_mints_app_and_component_ids() -> None:
    design = _sample_design()
    enriched = ensure_ids(design)
    assert enriched["app_id"].startswith("APP-")
    component_ids = [component["component_id"] for component in enriched["components"]]
    assert component_ids == ["C-login", "C-claims"]


def test_ensure_ids_is_deterministic() -> None:
    design = _sample_design()
    first = ensure_ids(design)
    second = ensure_ids(deepcopy(design))
    assert first == second
    assert design.get("app_id") is None
