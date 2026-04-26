"""Smoke tests for privilege_escalation_detector_router."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Force a fresh DB so tests don't pollute the repo .fixops_data
    from core import privilege_escalation_detector_engine as engine_mod

    engine_mod._engine_instance = None
    monkeypatch.setattr(
        engine_mod, "_DEFAULT_DB", str(tmp_path / "pe_test.db")
    )
    # Reset singleton so it picks up the new path
    engine_mod._engine_instance = engine_mod.PrivilegeEscalationDetectorEngine(
        db_path=str(tmp_path / "pe_test.db")
    )

    from apps.api.privilege_escalation_detector_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app)


def test_health(client):
    r = client.get("/api/v1/privilege-escalation-detector/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_status(client):
    r = client.get("/api/v1/privilege-escalation-detector/status")
    assert r.status_code == 200
    assert r.json()["ready"] is True


def test_record_event_then_analyze(client):
    body = {
        "org_id": "test-org",
        "user_id": "alice",
        "from_role": "user",
        "to_role": "root",
        "method": "sudo",
        "source_ip": "10.0.0.1",
    }
    r = client.post("/api/v1/privilege-escalation-detector/events", json=body)
    assert r.status_code == 200, r.text
    event = r.json()
    assert event["risk_level"] in ("low", "medium", "high", "critical")
    assert event["org_id"] == "test-org"

    # Analyze it back
    r2 = client.get(
        f"/api/v1/privilege-escalation-detector/events/{event['id']}/analyze",
        params={"org_id": "test-org"},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["event_id"] == event["id"]


def test_stats_for_empty_org(client):
    r = client.get(
        "/api/v1/privilege-escalation-detector/stats",
        params={"org_id": "empty-org"},
    )
    assert r.status_code == 200
    assert r.json()["org_id"] == "empty-org"


def test_invalid_method_rejected(client):
    body = {
        "org_id": "test-org",
        "user_id": "bob",
        "from_role": "user",
        "to_role": "root",
        "method": "telepathy",
    }
    r = client.post("/api/v1/privilege-escalation-detector/events", json=body)
    assert r.status_code == 422
