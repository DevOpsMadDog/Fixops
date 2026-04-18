"""Tests for the Platform Health Dashboard endpoint.

GET /api/v1/platform/health

5 tests covering:
1. Response shape — all required top-level keys present
2. engines block — total/healthy/degraded present and consistent
3. routers block — total == mounted (fully mounted platform)
4. data block — all 5 data keys present with numeric values
5. intelligence_mesh block — all 5 mesh components reported active
"""

from __future__ import annotations

import os
import time
import pytest

# ---------------------------------------------------------------------------
# We test the router logic directly (no live HTTP server needed).
# Import the module and call platform_health() as a coroutine.
# ---------------------------------------------------------------------------

os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_VERSION", "1.0.0-wave47-test")


@pytest.fixture()
def health_response(monkeypatch):
    """Return the platform_health dict with all live DB calls stubbed out."""
    import apps.api.platform_router as pr

    monkeypatch.setattr(pr, "_query_brain_nodes", lambda: 7250)
    monkeypatch.setattr(pr, "_query_alert_count", lambda org_id="default": 50)
    monkeypatch.setattr(pr, "_query_vulnerability_count", lambda org_id="default": 100)
    monkeypatch.setattr(pr, "_query_asset_count", lambda org_id="default": 200)
    monkeypatch.setattr(pr, "_query_compliance_frameworks", lambda org_id="default": 7)
    monkeypatch.setattr(
        pr, "_query_feed_counts", lambda: {"active": 9, "configured": 5}
    )

    import asyncio
    return asyncio.get_event_loop().run_until_complete(pr.platform_health())


# ===========================================================================
# 1. Top-level response shape
# ===========================================================================

def test_platform_health_top_level_keys(health_response):
    required = {
        "status", "version", "timestamp", "uptime_seconds",
        "engines", "routers", "frontend", "tests",
        "data", "feeds", "trustgraph", "intelligence_mesh",
    }
    assert required.issubset(health_response.keys()), (
        f"Missing keys: {required - health_response.keys()}"
    )


# ===========================================================================
# 2. engines block consistency
# ===========================================================================

def test_platform_health_engines_block(health_response):
    eng = health_response["engines"]
    assert eng["total"] > 0
    assert eng["healthy"] > 0
    assert eng["degraded"] >= 0
    assert eng["healthy"] + eng["degraded"] <= eng["total"]


# ===========================================================================
# 3. routers block — mounted equals total
# ===========================================================================

def test_platform_health_routers_fully_mounted(health_response):
    rtr = health_response["routers"]
    assert rtr["total"] == rtr["mounted"], (
        f"Unmounted routers detected: total={rtr['total']} mounted={rtr['mounted']}"
    )


# ===========================================================================
# 4. data block — stubbed values flow through correctly
# ===========================================================================

def test_platform_health_data_block(health_response):
    data = health_response["data"]
    required_keys = {"brain_nodes", "alerts", "vulnerabilities", "assets", "compliance_frameworks"}
    assert required_keys.issubset(data.keys())
    # All values must be non-negative integers
    for key in required_keys:
        assert isinstance(data[key], int), f"{key} should be int, got {type(data[key])}"
        assert data[key] >= 0, f"{key} should be >= 0"
    # Verify stubbed values are reflected
    assert data["brain_nodes"] == 7250
    assert data["alerts"] == 50
    assert data["vulnerabilities"] == 100
    assert data["assets"] == 200
    assert data["compliance_frameworks"] == 7


# ===========================================================================
# 5. intelligence_mesh — all components active
# ===========================================================================

def test_platform_health_intelligence_mesh(health_response):
    mesh = health_response["intelligence_mesh"]
    expected_components = {
        "brain_graph", "event_bus", "subscribers", "risk_sync", "supply_chain_sync"
    }
    assert expected_components.issubset(mesh.keys())
    for component, status in mesh.items():
        assert status == "active", f"Expected '{component}' to be 'active', got '{status}'"
