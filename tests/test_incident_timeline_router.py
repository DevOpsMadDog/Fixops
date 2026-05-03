"""HTTP-layer tests for incident_timeline_router — MTTR/MTTD analytics endpoint.

Focuses on POST /{timeline_id}/metrics (calculate_metrics) plus the
supporting CRUD endpoints needed to build a real timeline before calculating.

Uses FastAPI TestClient with a tmp-path-scoped engine so no real DB is touched.
Auth: X-API-Key header override via dependency_overrides.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path):
    """Isolated TestClient with tmp-scoped IncidentTimelineEngine."""
    from core.incident_timeline_engine import IncidentTimelineEngine
    import apps.api.incident_timeline_router as _router_module
    from apps.api.auth_deps import api_key_auth

    # Swap engine singleton for this test scope
    test_engine = IncidentTimelineEngine(db_path=str(tmp_path / "test_timeline.db"))
    original_engine = _router_module._engine
    _router_module._engine = test_engine

    from apps.api.incident_timeline_router import router

    app = FastAPI()
    app.include_router(router)

    # Bypass auth
    app.dependency_overrides[api_key_auth] = lambda: None

    yield TestClient(app)

    # Teardown: restore original engine singleton
    _router_module._engine = original_engine
    app.dependency_overrides.clear()


ORG = "org-router-test"


def _create_timeline(client: TestClient, **kwargs) -> dict:
    payload = {"title": "Test Incident", "incident_type": "breach", "severity": "high"}
    payload.update(kwargs)
    # Drop None values so optional fields don't trigger NOT NULL constraints
    payload = {k: v for k, v in payload.items() if v is not None}
    resp = client.post("/api/v1/incident-timeline", params={"org_id": ORG}, json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _add_event(client: TestClient, timeline_id: str, **kwargs) -> dict:
    payload = {"event_type": "action", "title": "Event"}
    payload.update(kwargs)
    payload = {k: v for k, v in payload.items() if v is not None}
    resp = client.post(
        f"/api/v1/incident-timeline/{timeline_id}/events",
        params={"org_id": ORG},
        json=payload,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Test 1: GET / returns 200 with empty list on fresh org
# ---------------------------------------------------------------------------

def test_list_timelines_empty(client):
    resp = client.get("/api/v1/incident-timeline", params={"org_id": ORG})
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# Test 2: POST / creates timeline, GET /{id} retrieves it
# ---------------------------------------------------------------------------

def test_create_and_get_timeline(client):
    tl = _create_timeline(client, title="Ransomware Hit", incident_type="ransomware", severity="critical")
    assert tl["timeline_id"]
    assert tl["status"] == "active"

    resp = client.get(f"/api/v1/incident-timeline/{tl['timeline_id']}", params={"org_id": ORG})
    assert resp.status_code == 200
    fetched = resp.json()
    assert fetched["title"] == "Ransomware Hit"
    assert fetched["severity"] == "critical"


# ---------------------------------------------------------------------------
# Test 3: POST /{id}/metrics returns MTTD when detection event present
# ---------------------------------------------------------------------------

def test_calculate_metrics_with_detection_event(client):
    started = "2026-01-01T00:00:00"
    tl = _create_timeline(client, started_at=started, title="MTTR Test")
    tid = tl["timeline_id"]

    # Detection event fires 90 minutes after start
    _add_event(client, tid, event_type="detection", title="IDS alert",
               event_time="2026-01-01T01:30:00")
    _add_event(client, tid, event_type="action", title="Remediation step")

    # Mark resolved so MTTR can be computed
    client.patch(
        f"/api/v1/incident-timeline/{tid}/status",
        params={"org_id": ORG},
        json={"status": "resolved"},
    )

    resp = client.post(f"/api/v1/incident-timeline/{tid}/metrics", params={"org_id": ORG})
    assert resp.status_code == 201
    m = resp.json()
    assert m["metric_id"]
    assert m["timeline_id"] == tid
    assert m["total_events"] == 2
    assert m["mttd_minutes"] == pytest.approx(90.0, abs=1.0)
    assert m["mttr_minutes"] is not None
    assert m["mttc_minutes"] is None  # not yet contained


# ---------------------------------------------------------------------------
# Test 4: POST /{id}/metrics with no detection event yields mttd_minutes=null
# ---------------------------------------------------------------------------

def test_calculate_metrics_no_detection_event(client):
    tl = _create_timeline(client, title="No Detection")
    tid = tl["timeline_id"]
    _add_event(client, tid, event_type="action", title="Some action")

    resp = client.post(f"/api/v1/incident-timeline/{tid}/metrics", params={"org_id": ORG})
    assert resp.status_code == 201
    m = resp.json()
    assert m["mttd_minutes"] is None
    assert m["total_events"] == 1
    assert m["affected_systems_count"] == 0


# ---------------------------------------------------------------------------
# Test 5: POST /{bad_id}/metrics on missing timeline returns 404
# ---------------------------------------------------------------------------

def test_calculate_metrics_not_found_returns_404(client):
    resp = client.post(
        "/api/v1/incident-timeline/nonexistent-uuid/metrics",
        params={"org_id": ORG},
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test 6: GET /stats reflects real org metrics (avg_mttd populated after calc)
# ---------------------------------------------------------------------------

def test_stats_avg_mttd_populated_after_metrics_calculated(client):
    started = "2026-02-01T00:00:00"
    tl = _create_timeline(client, started_at=started, title="Stats Test")
    tid = tl["timeline_id"]
    _add_event(client, tid, event_type="detection", title="Alert",
               event_time="2026-02-01T02:00:00")  # 120 min MTTD

    client.post(f"/api/v1/incident-timeline/{tid}/metrics", params={"org_id": ORG})

    resp = client.get("/api/v1/incident-timeline/stats", params={"org_id": ORG})
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["total_timelines"] == 1
    assert stats["active_incidents"] == 1
    assert stats["avg_mttd"] == pytest.approx(120.0, abs=1.0)
    assert stats["by_type"]["breach"] == 1
    assert stats["by_severity"]["high"] == 1


# ---------------------------------------------------------------------------
# MTTR analytics endpoint: GET /api/v1/incident-timeline/analytics/mttr
# ---------------------------------------------------------------------------

def test_mttr_analytics_empty_org(client):
    """Fresh org returns nulls for avg fields and zero counts."""
    resp = client.get("/api/v1/incident-timeline/analytics/mttr", params={"org_id": "empty-org"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["org_id"] == "empty-org"
    assert data["avg_mttr_minutes"] is None
    assert data["total_timelines"] == 0


def test_mttr_analytics_populated_after_resolve(client):
    """Create timeline, resolve, compute metrics — analytics returns MTTR.

    timestamp_field must be the column name ('resolved_at'), not a value.
    The engine stamps the column with its own _now(), so MTTR will be based
    on now - started_at; we only assert it is non-None and non-negative.
    """
    tl = _create_timeline(client, title="Resolve Test")
    tid = tl["timeline_id"]

    # Resolve — omit timestamp_field so engine auto-selects 'resolved_at'
    resp = client.patch(
        f"/api/v1/incident-timeline/{tid}/status",
        params={"org_id": ORG},
        json={"status": "resolved"},
    )
    assert resp.status_code == 200

    # Calculate metrics
    resp = client.post(f"/api/v1/incident-timeline/{tid}/metrics", params={"org_id": ORG})
    assert resp.status_code == 201
    metrics = resp.json()
    assert metrics["mttr_minutes"] is not None
    assert metrics["mttr_minutes"] >= 0

    # MTTR analytics endpoint
    resp = client.get("/api/v1/incident-timeline/analytics/mttr", params={"org_id": ORG})
    assert resp.status_code == 200
    data = resp.json()
    assert data["avg_mttr_minutes"] is not None
    assert data["avg_mttr_minutes"] >= 0
    assert data["avg_mttr_hours"] is not None
    assert data["total_timelines"] == 1


def test_mttr_analytics_started_at_none_does_not_crash(client):
    """Regression: POST with started_at omitted (serialises as None) must not 500."""
    tl = _create_timeline(client, title="No started_at")
    resp = client.post(
        f"/api/v1/incident-timeline/{tl['timeline_id']}/metrics",
        params={"org_id": ORG},
    )
    # No started_at → MTTD/MTTR/MTTC will be None but endpoint must not crash
    assert resp.status_code == 201

    resp = client.get("/api/v1/incident-timeline/analytics/mttr", params={"org_id": ORG})
    assert resp.status_code == 200
