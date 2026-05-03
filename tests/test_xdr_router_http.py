"""HTTP-level tests for /api/v1/xdr router — XDR Correlation Engine.

Mounts the xdr_router directly via TestClient (no full create_app cost).
Covers: signal ingest, signal list, incident create/get, status patch,
signal-link, correlation rules, and stats.
"""
from __future__ import annotations

import os

os.environ["FIXOPS_MODE"] = "enterprise"
os.environ["FIXOPS_API_TOKEN"] = "test-key"
os.environ["FIXOPS_JWT_SECRET"] = "test-secret-that-is-at-least-32chars!"
os.environ["FIXOPS_DISABLE_TELEMETRY"] = "1"
os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Mount only the xdr_router to avoid full create_app() cost."""
    from apps.api.xdr_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


AUTH = {"X-API-Key": "test-key"}
ORG = "test-xdr-http-org"


# ---------------------------------------------------------------------------
# GET /api/v1/xdr/stats — empty org
# ---------------------------------------------------------------------------

def test_stats_empty_org_returns_200(client):
    resp = client.get("/api/v1/xdr/stats", params={"org_id": ORG}, headers=AUTH)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_signals"] == 0
    assert data["new_incidents"] == 0
    assert data["active_incidents"] == 0
    assert data["critical_incidents"] == 0


# ---------------------------------------------------------------------------
# POST /api/v1/xdr/signals — ingest
# ---------------------------------------------------------------------------

def test_ingest_signal_returns_201_shape(client):
    payload = {
        "source_type": "endpoint",
        "signal_type": "malware",
        "severity": "high",
        "entity_id": "host-router-01",
        "entity_type": "host",
        "confidence": 0.92,
    }
    resp = client.post("/api/v1/xdr/signals", json=payload, params={"org_id": ORG}, headers=AUTH)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "signal_id" in data
    assert data["signal_type"] == "malware"
    assert data["severity"] == "high"
    assert data["org_id"] == ORG


# ---------------------------------------------------------------------------
# GET /api/v1/xdr/signals — list after ingest
# ---------------------------------------------------------------------------

def test_list_signals_returns_ingested(client):
    entity = "host-list-check-01"
    client.post(
        "/api/v1/xdr/signals",
        json={"source_type": "network", "entity_id": entity, "severity": "medium"},
        params={"org_id": ORG},
        headers=AUTH,
    )
    resp = client.get("/api/v1/xdr/signals", params={"org_id": ORG}, headers=AUTH)
    assert resp.status_code == 200, resp.text
    ids = [s["entity_id"] for s in resp.json()]
    assert entity in ids


# ---------------------------------------------------------------------------
# POST /api/v1/xdr/incidents — create manually
# ---------------------------------------------------------------------------

def test_create_incident_returns_incident_id(client):
    payload = {
        "title": "HTTP-Test Ransomware Campaign",
        "description": "Detected via router test",
        "attack_stage": "impact",
        "severity": "critical",
        "affected_entities": ["host-target-01"],
    }
    resp = client.post("/api/v1/xdr/incidents", json=payload, params={"org_id": ORG}, headers=AUTH)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "incident_id" in data
    assert data["severity"] == "critical"
    assert data["attack_stage"] == "impact"


# ---------------------------------------------------------------------------
# GET /api/v1/xdr/incidents/{incident_id} — get with signals
# ---------------------------------------------------------------------------

def test_get_incident_with_linked_signal(client):
    # Create incident
    inc_resp = client.post(
        "/api/v1/xdr/incidents",
        json={"title": "Link-test incident", "severity": "high"},
        params={"org_id": ORG},
        headers=AUTH,
    )
    assert inc_resp.status_code == 200
    incident_id = inc_resp.json()["incident_id"]

    # Ingest a signal
    sig_resp = client.post(
        "/api/v1/xdr/signals",
        json={"entity_id": "host-link-99", "severity": "high"},
        params={"org_id": ORG},
        headers=AUTH,
    )
    assert sig_resp.status_code == 200
    signal_id = sig_resp.json()["signal_id"]

    # Link signal to incident
    link_resp = client.post(
        f"/api/v1/xdr/incidents/{incident_id}/signals",
        json={"signal_id": signal_id},
        params={"org_id": ORG},
        headers=AUTH,
    )
    assert link_resp.status_code == 200, link_resp.text
    assert link_resp.json()["linked"] is True

    # Fetch full incident — should include linked signal
    get_resp = client.get(
        f"/api/v1/xdr/incidents/{incident_id}",
        params={"org_id": ORG},
        headers=AUTH,
    )
    assert get_resp.status_code == 200, get_resp.text
    full = get_resp.json()
    assert full["incident_id"] == incident_id
    sids = [s["signal_id"] for s in full.get("signals", [])]
    assert signal_id in sids


# ---------------------------------------------------------------------------
# PATCH /api/v1/xdr/incidents/{incident_id}/status
# ---------------------------------------------------------------------------

def test_update_incident_status(client):
    inc_resp = client.post(
        "/api/v1/xdr/incidents",
        json={"title": "Status-patch test", "severity": "medium"},
        params={"org_id": ORG},
        headers=AUTH,
    )
    incident_id = inc_resp.json()["incident_id"]

    patch_resp = client.patch(
        f"/api/v1/xdr/incidents/{incident_id}/status",
        json={"status": "investigating", "assigned_to": "analyst@example.com"},
        params={"org_id": ORG},
        headers=AUTH,
    )
    assert patch_resp.status_code == 200, patch_resp.text
    assert patch_resp.json()["status"] == "investigating"


def test_update_incident_status_invalid_returns_422(client):
    inc_resp = client.post(
        "/api/v1/xdr/incidents",
        json={"title": "Bad status test"},
        params={"org_id": ORG},
        headers=AUTH,
    )
    incident_id = inc_resp.json()["incident_id"]

    patch_resp = client.patch(
        f"/api/v1/xdr/incidents/{incident_id}/status",
        json={"status": "snoozed"},
        params={"org_id": ORG},
        headers=AUTH,
    )
    assert patch_resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /api/v1/xdr/incidents/{id} — 404 for missing
# ---------------------------------------------------------------------------

def test_get_incident_not_found_returns_404(client):
    resp = client.get(
        "/api/v1/xdr/incidents/nonexistent-uuid-xyz",
        params={"org_id": ORG},
        headers=AUTH,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/xdr/rules — correlation rule
# ---------------------------------------------------------------------------

def test_create_correlation_rule(client):
    payload = {
        "name": "Lateral + C2 combo",
        "description": "Detect combined lateral movement and C2",
        "conditions": {"signal_types": ["lateral_movement", "c2"], "min_signals": 2},
        "incident_severity": "critical",
        "mitre_tactic": "TA0011",
    }
    resp = client.post("/api/v1/xdr/rules", json=payload, params={"org_id": ORG}, headers=AUTH)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "rule_id" in data
    assert data["name"] == "Lateral + C2 combo"
    assert data["mitre_tactic"] == "TA0011"


# ---------------------------------------------------------------------------
# GET /api/v1/xdr/stats — populated
# ---------------------------------------------------------------------------

def test_stats_reflects_ingested_data(client):
    stat_org = "test-xdr-stats-populated"
    client.post(
        "/api/v1/xdr/signals",
        json={"source_type": "cloud", "severity": "critical", "entity_id": "vm-001"},
        params={"org_id": stat_org},
        headers=AUTH,
    )
    client.post(
        "/api/v1/xdr/signals",
        json={"source_type": "identity", "severity": "high", "entity_id": "vm-001"},
        params={"org_id": stat_org},
        headers=AUTH,
    )
    resp = client.get("/api/v1/xdr/stats", params={"org_id": stat_org}, headers=AUTH)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_signals"] >= 2
    assert "cloud" in data["by_source"]
    assert data["signals_last_24h"] >= 2
