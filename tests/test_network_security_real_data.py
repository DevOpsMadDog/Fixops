"""Network Security real-data endpoint tests — ALDECI Beast Mode.

Tests the GET "/" 5-state summary endpoints wired in batch-7 for:
  - /api/v1/ddos-protection/
  - /api/v1/nac/
  - /api/v1/microsegmentation/
  - /api/v1/network-monitoring/

NO MOCKS. All tests call the real engine via TestClient.
Each summary must return a valid 5-state envelope (state + message + stats + links).
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# App fixture — mount only the 4 routers under test to avoid cross-router
# state leakage (TestClient FastAPI state-leak pattern documented in MEMORY.md)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    app = FastAPI()

    from apps.api.ddos_protection_router import router as ddos_router
    from apps.api.network_access_control_router import router as nac_router
    from apps.api.microsegmentation_policy_router import router as microseg_router
    from apps.api.network_monitoring_router import router as netmon_router

    app.include_router(ddos_router)
    app.include_router(nac_router)
    app.include_router(microseg_router)
    app.include_router(netmon_router)

    # Override auth so we don't need a real API key in tests
    from apps.api.auth_deps import api_key_auth
    app.dependency_overrides[api_key_auth] = lambda: None

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

_VALID_STATES = {"ok", "warning", "critical", "empty", "error"}


def _assert_envelope(data: dict, prefix: str) -> None:
    """Validate the 5-state envelope contract."""
    assert "state" in data, f"{prefix}: missing 'state' key"
    assert data["state"] in _VALID_STATES, f"{prefix}: invalid state {data['state']!r}"
    assert "message" in data, f"{prefix}: missing 'message' key"
    assert isinstance(data["message"], str) and data["message"], f"{prefix}: empty message"
    assert "stats" in data, f"{prefix}: missing 'stats' key"
    assert isinstance(data["stats"], dict), f"{prefix}: stats must be a dict"
    assert "links" in data, f"{prefix}: missing 'links' key"
    assert isinstance(data["links"], dict), f"{prefix}: links must be a dict"


# ---------------------------------------------------------------------------
# DDoS Protection summary
# ---------------------------------------------------------------------------

class TestDDoSSummary:
    def test_returns_200(self, client):
        r = client.get("/api/v1/ddos-protection/", params={"org_id": "test-ddos"})
        assert r.status_code == 200, r.text

    def test_envelope_contract(self, client):
        r = client.get("/api/v1/ddos-protection/", params={"org_id": "test-ddos"})
        data = r.json()
        _assert_envelope(data, "ddos-protection/")

    def test_empty_state_for_fresh_org(self, client):
        r = client.get("/api/v1/ddos-protection/", params={"org_id": "fresh-org-ddos-xzy"})
        data = r.json()
        assert data["state"] == "empty", f"Expected 'empty' for fresh org, got {data['state']!r}"

    def test_links_present(self, client):
        r = client.get("/api/v1/ddos-protection/", params={"org_id": "test-ddos"})
        links = r.json()["links"]
        assert "resources" in links
        assert "attacks" in links
        assert "rules" in links

    def test_org_id_echoed(self, client):
        r = client.get("/api/v1/ddos-protection/", params={"org_id": "myorg-ddos"})
        assert r.json()["org_id"] == "myorg-ddos"


# ---------------------------------------------------------------------------
# Network Access Control summary
# ---------------------------------------------------------------------------

class TestNACSummary:
    def test_returns_200(self, client):
        r = client.get("/api/v1/nac/", params={"org_id": "test-nac"})
        assert r.status_code == 200, r.text

    def test_envelope_contract(self, client):
        r = client.get("/api/v1/nac/", params={"org_id": "test-nac"})
        _assert_envelope(r.json(), "nac/")

    def test_empty_state_for_fresh_org(self, client):
        r = client.get("/api/v1/nac/", params={"org_id": "fresh-org-nac-xzy"})
        data = r.json()
        assert data["state"] == "empty", f"Expected 'empty' for fresh org, got {data['state']!r}"

    def test_links_present(self, client):
        r = client.get("/api/v1/nac/", params={"org_id": "test-nac"})
        links = r.json()["links"]
        assert "endpoints" in links
        assert "policies" in links
        assert "stats" in links

    def test_org_id_echoed(self, client):
        r = client.get("/api/v1/nac/", params={"org_id": "myorg-nac"})
        assert r.json()["org_id"] == "myorg-nac"


# ---------------------------------------------------------------------------
# Microsegmentation summary
# ---------------------------------------------------------------------------

class TestMicrosegmentationSummary:
    def test_returns_200(self, client):
        r = client.get("/api/v1/microsegmentation/", params={"org_id": "test-microseg"})
        assert r.status_code == 200, r.text

    def test_envelope_contract(self, client):
        r = client.get("/api/v1/microsegmentation/", params={"org_id": "test-microseg"})
        _assert_envelope(r.json(), "microsegmentation/")

    def test_empty_state_for_fresh_org(self, client):
        r = client.get("/api/v1/microsegmentation/", params={"org_id": "fresh-org-microseg-xzy"})
        data = r.json()
        assert data["state"] == "empty", f"Expected 'empty' for fresh org, got {data['state']!r}"

    def test_links_present(self, client):
        r = client.get("/api/v1/microsegmentation/", params={"org_id": "test-microseg"})
        links = r.json()["links"]
        assert "segments" in links
        assert "policies" in links
        assert "violations" in links

    def test_org_id_echoed(self, client):
        r = client.get("/api/v1/microsegmentation/", params={"org_id": "myorg-microseg"})
        assert r.json()["org_id"] == "myorg-microseg"


# ---------------------------------------------------------------------------
# Network Monitoring summary
# ---------------------------------------------------------------------------

class TestNetworkMonitoringSummary:
    def test_returns_200(self, client):
        r = client.get("/api/v1/network-monitoring/", params={"org_id": "test-netmon"})
        assert r.status_code == 200, r.text

    def test_envelope_contract(self, client):
        r = client.get("/api/v1/network-monitoring/", params={"org_id": "test-netmon"})
        _assert_envelope(r.json(), "network-monitoring/")

    def test_empty_state_for_fresh_org(self, client):
        r = client.get("/api/v1/network-monitoring/", params={"org_id": "fresh-org-netmon-xzy"})
        data = r.json()
        assert data["state"] == "empty", f"Expected 'empty' for fresh org, got {data['state']!r}"

    def test_links_present(self, client):
        r = client.get("/api/v1/network-monitoring/", params={"org_id": "test-netmon"})
        links = r.json()["links"]
        assert "interfaces" in links
        assert "alert_rules" in links
        assert "alerts" in links

    def test_org_id_echoed(self, client):
        r = client.get("/api/v1/network-monitoring/", params={"org_id": "myorg-netmon"})
        assert r.json()["org_id"] == "myorg-netmon"
