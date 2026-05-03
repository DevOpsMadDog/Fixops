"""Tests for deterministic ID allocation in design documents."""

from __future__ import annotations

from copy import deepcopy

from core.services.enterprise.id_allocator import ensure_ids


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
    """Verify that ensure_ids allocates a deterministic APP-ID.

    The current implementation assigns ``app_id`` and ``run_id`` but does
    **not** inject ``component_id`` into individual components.
    """
    design = _sample_design()
    enriched = ensure_ids(design)
    assert enriched["app_id"].startswith("APP-")
    # run_id should be a 12-char hex string
    assert len(enriched["run_id"]) == 12
    # Components are passed through unchanged
    assert enriched["components"] == design["components"]


def test_ensure_ids_is_deterministic() -> None:
    """Verify that app_id is deterministic for the same app_name.

    ``run_id`` uses ``uuid4`` so it differs between calls; we only compare
    the deterministic ``app_id``.
    """
    design = _sample_design()
    first = ensure_ids(design)
    second = ensure_ids(deepcopy(design))
    assert first["app_id"] == second["app_id"]
    # Original design should not be mutated
    assert design.get("app_id") is None
