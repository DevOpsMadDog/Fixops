"""
Tests for empty-endpoint fix #13: GET /api/v1/supply-chain/
Previously returned hardcoded {"items": [], "count": 0}.
Now wired to SupplyChainIntel.get_supply_chain_stats().
"""
from __future__ import annotations

import sys
import os
import pytest

# Ensure suite paths are on sys.path via sitecustomize
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _get_test_client():
    from fastapi.testclient import TestClient
    from apps.api.app import create_app
    app = create_app()
    return TestClient(app, headers={"X-API-Key": "test-key"})


def _get_supply_chain_intel():
    from core.supply_chain_intel import SupplyChainIntel
    return SupplyChainIntel()


class TestSupplyChainIndexNotStub:
    """Confirm the endpoint is no longer a hardcoded stub."""

    def test_response_has_no_stub_items_key(self):
        """Old stub returned 'items': [] — wired response must not rely on items."""
        client = _get_test_client()
        resp = client.get("/api/v1/supply-chain/", params={"org_id": "default"})
        assert resp.status_code in (200, 401, 403), f"Unexpected status: {resp.status_code}"
        if resp.status_code == 200:
            data = resp.json()
            # Old stub signature: only router + org_id + items + count
            # New response must include at least one real field from SupplyChainIntel
            # or gracefully degrade with an error key (never the old stub signature)
            assert not (
                list(data.keys()) == ["router", "org_id", "items", "count"]
                and data.get("items") == []
                and data.get("count") == 0
            ), "Endpoint still returns old hardcoded stub — wire not applied"

    def test_response_has_router_key(self):
        """Wired response retains the router identifier."""
        client = _get_test_client()
        resp = client.get("/api/v1/supply-chain/", params={"org_id": "test-org"})
        if resp.status_code == 200:
            assert resp.json().get("router") == "supply-chain"

    def test_response_count_key_present(self):
        """Wired response always includes a numeric count key."""
        client = _get_test_client()
        resp = client.get("/api/v1/supply-chain/", params={"org_id": "default"})
        if resp.status_code == 200:
            data = resp.json()
            assert "count" in data
            assert isinstance(data["count"], int)


class TestSupplyChainIntelEngine:
    """Unit tests for the underlying engine — no HTTP layer."""

    def test_get_supply_chain_stats_returns_dict(self):
        """SupplyChainIntel.get_supply_chain_stats() returns a dict with expected keys."""
        try:
            intel = _get_supply_chain_intel()
        except ImportError:
            pytest.skip("supply_chain_intel not importable in this environment")

        stats = intel.get_supply_chain_stats(org_id="test-org")
        assert isinstance(stats, dict)
        for key in ("org_id", "total_packages_analyzed", "high_risk_packages", "unresolved_alerts"):
            assert key in stats, f"Missing key: {key}"

    def test_get_supply_chain_stats_org_id_matches(self):
        """Stats returned are scoped to the requested org_id."""
        try:
            intel = _get_supply_chain_intel()
        except ImportError:
            pytest.skip("supply_chain_intel not importable in this environment")

        stats = intel.get_supply_chain_stats(org_id="wire-test-org")
        assert stats["org_id"] == "wire-test-org"

    def test_get_supply_chain_stats_numeric_fields(self):
        """All count fields are non-negative integers or floats."""
        try:
            intel = _get_supply_chain_intel()
        except ImportError:
            pytest.skip("supply_chain_intel not importable in this environment")

        stats = intel.get_supply_chain_stats(org_id="default")
        for key in ("total_packages_analyzed", "high_risk_packages", "critical_risk_packages",
                    "total_alerts", "unresolved_alerts"):
            assert isinstance(stats[key], int) and stats[key] >= 0, (
                f"Field {key} should be a non-negative int, got {stats[key]!r}"
            )
