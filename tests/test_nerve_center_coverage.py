"""Comprehensive tests for suite-core/api/nerve_center.py — Nerve Center APIs."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create a test client with the nerve center router mounted."""
    app = FastAPI()
    from api.nerve_center import router
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ─── Model Imports ──────────────────────────────────────────────────────


class TestModelImports:
    def test_import_models(self):
        from api.nerve_center import ThreatPulse, SuiteStatus
        pulse = ThreatPulse(level="medium", score=45.0)
        assert pulse.level == "medium"
        assert pulse.score == 45.0
        assert pulse.active_incidents == 0

        status = SuiteStatus(
            suite="core", status="healthy", endpoints=50,
            latency_ms=12.5, last_heartbeat="2026-03-08T00:00:00Z",
        )
        assert status.suite == "core"
        assert status.latency_ms == 12.5

    def test_more_models(self):
        from api.nerve_center import IntelligenceLink
        link = IntelligenceLink(
            source_suite="core", target_suite="attack",
            data_flow="findings", events_per_min=10.0,
        )
        assert link.source_suite == "core"
        assert link.status == "active"

    def test_lazy_helpers(self):
        from api.nerve_center import _brain, _ml_store, _event_bus
        _brain()
        _ml_store()
        _event_bus()


# ─── Nerve Center Endpoints ────────────────────────────────────────────


class TestNerveCenterEndpoints:
    def test_get_pulse(self, client):
        resp = client.get("/api/v1/nerve-center/pulse")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_get_state(self, client):
        resp = client.get("/api/v1/nerve-center/state")
        assert resp.status_code == 200

    def test_auto_remediate(self, client):
        resp = client.post(
            "/api/v1/nerve-center/auto-remediate",
            json={"finding_id": "f-1", "action": "patch"},
        )
        assert resp.status_code in (200, 422)

    def test_intelligence_map(self, client):
        resp = client.get("/api/v1/nerve-center/intelligence-map")
        assert resp.status_code == 200

    def test_playbooks_list(self, client):
        resp = client.get("/api/v1/nerve-center/playbooks")
        assert resp.status_code == 200

    def test_playbooks_validate(self, client):
        resp = client.post(
            "/api/v1/nerve-center/playbooks/validate",
            json={"name": "test-playbook", "steps": []},
        )
        assert resp.status_code in (200, 422)

    def test_playbook_execute(self, client):
        resp = client.post("/api/v1/nerve-center/playbooks/execute/playbook-1")
        assert resp.status_code in (200, 404, 422)

    def test_overlay_get(self, client):
        resp = client.get("/api/v1/nerve-center/overlay")
        assert resp.status_code == 200

    def test_overlay_put(self, client):
        resp = client.put(
            "/api/v1/nerve-center/overlay",
            json={"mode": "enhanced"},
        )
        assert resp.status_code in (200, 422)
