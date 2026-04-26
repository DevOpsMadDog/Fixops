"""Bulk-triage router validation tests — Multica issue 4f734f1d.

Covers the four contract requirements that were broken before this fix:

  (a) empty list rejected with 422
  (b) cross-org IDs rejected with 403 (NOT silent {"updated": 0})
  (c) invalid status enum rejected with 422 at the Pydantic boundary
  (d) happy path with valid alerts updates them all atomically

Auth is bypassed via FastAPI dependency_overrides so the tests focus on the
validation layer rather than the API-key plumbing (covered in test_auth.py).
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.alert_triage_router import router as alert_triage_router
from apps.api.auth_deps import api_key_auth
from core.alert_triage_engine import AlertTriageEngine
import apps.api.alert_triage_router as triage_router_module


@pytest.fixture()
def isolated_engine(tmp_path, monkeypatch):
    """Per-test AlertTriageEngine pointed at a fresh tmp DB.

    The router lazily caches a singleton in ``_engine``. We swap that
    cache out for a fresh engine so tests don't interfere with each other
    or with any pre-existing prod data.
    """
    db_path = str(tmp_path / "alert_triage_bulk_test.db")
    fresh = AlertTriageEngine(db_path=db_path)
    monkeypatch.setattr(triage_router_module, "_engine", fresh)
    return fresh


@pytest.fixture()
def client(isolated_engine):
    """FastAPI test client with auth bypassed."""
    app = FastAPI()
    app.include_router(alert_triage_router)
    # Bypass api_key_auth dependency for these tests
    app.dependency_overrides[api_key_auth] = lambda: None
    # Bypass any role-check dependencies registered at the router level
    for dep in alert_triage_router.dependencies:
        # require_role(...) returns Depends(_check). Override its callable.
        if hasattr(dep, "dependency"):
            app.dependency_overrides[dep.dependency] = lambda: None
    return TestClient(app)


def _ingest(engine: AlertTriageEngine, org_id: str, title: str = "test alert") -> str:
    a = engine.ingest_alert(
        org_id,
        {"title": title, "source_system": "siem", "severity": "high"},
    )
    return a["id"]


# ---------------------------------------------------------------------------
# (a) empty list → 422
# ---------------------------------------------------------------------------

def test_bulk_triage_empty_alert_ids_returns_422(client):
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": [], "action": "resolve"},
    )
    assert resp.status_code == 422, resp.text
    body = resp.json()
    # FastAPI surfaces Pydantic errors under "detail"
    text = repr(body).lower()
    assert "alert_ids" in text or "non-empty" in text or "at least" in text


def test_bulk_triage_missing_alert_ids_returns_422(client):
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"action": "resolve"},
    )
    assert resp.status_code == 422


def test_bulk_triage_alert_ids_with_only_whitespace_returns_422(client):
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": ["   ", ""], "action": "resolve"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# (b) cross-org IDs → 403
# ---------------------------------------------------------------------------

def test_bulk_triage_cross_org_ids_returns_403(client, isolated_engine):
    # Alert belongs to org2
    foreign_id = _ingest(isolated_engine, "org2", "foreign tenant alert")
    # Caller is org1, tries to triage org2's alert
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": [foreign_id], "action": "resolve"},
    )
    assert resp.status_code == 403, resp.text
    # The foreign alert MUST NOT have been mutated
    foreign = isolated_engine.get_alert("org2", foreign_id)
    assert foreign is not None
    assert foreign["status"] == "new", "cross-org alert was mutated"


def test_bulk_triage_mixed_own_and_foreign_ids_rejected_atomically(client, isolated_engine):
    own_id = _ingest(isolated_engine, "org1", "my alert")
    foreign_id = _ingest(isolated_engine, "org2", "foreign alert")
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": [own_id, foreign_id], "action": "resolve"},
    )
    assert resp.status_code == 403
    # Neither alert should have been touched (atomic rejection)
    assert isolated_engine.get_alert("org1", own_id)["status"] == "new"
    assert isolated_engine.get_alert("org2", foreign_id)["status"] == "new"


# ---------------------------------------------------------------------------
# (c) invalid action enum → 422
# ---------------------------------------------------------------------------

def test_bulk_triage_invalid_action_enum_returns_422(client, isolated_engine):
    own_id = _ingest(isolated_engine, "org1")
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": [own_id], "action": "delete_forever"},
    )
    assert resp.status_code == 422, resp.text
    text = repr(resp.json()).lower()
    assert "action" in text


def test_bulk_triage_empty_action_returns_422(client, isolated_engine):
    own_id = _ingest(isolated_engine, "org1")
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": [own_id], "action": ""},
    )
    assert resp.status_code == 422


def test_bulk_triage_missing_org_returns_422(client, isolated_engine):
    own_id = _ingest(isolated_engine, "org1")
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        json={"alert_ids": [own_id], "action": "resolve"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# (d) happy path → 200, all alerts updated
# ---------------------------------------------------------------------------

def test_bulk_triage_happy_path_updates_all(client, isolated_engine):
    ids = [_ingest(isolated_engine, "org1", f"alert-{i}") for i in range(3)]
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": ids, "action": "resolve"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["updated"] == 3
    assert body["action"] == "resolve"
    for aid in ids:
        rec = isolated_engine.get_alert("org1", aid)
        assert rec["status"] == "resolved"
        assert rec["resolved_at"] is not None


def test_bulk_triage_acknowledge_alias_maps_to_resolve(client, isolated_engine):
    own_id = _ingest(isolated_engine, "org1")
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": [own_id], "action": "acknowledge"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["updated"] == 1
    assert isolated_engine.get_alert("org1", own_id)["status"] == "resolved"


def test_bulk_triage_false_positive_action(client, isolated_engine):
    ids = [_ingest(isolated_engine, "org1", f"fp-{i}") for i in range(2)]
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": ids, "action": "false_positive"},
    )
    assert resp.status_code == 200
    for aid in ids:
        assert isolated_engine.get_alert("org1", aid)["status"] == "false_positive"


def test_bulk_triage_escalate_action(client, isolated_engine):
    own_id = _ingest(isolated_engine, "org1")
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": [own_id], "action": "escalate"},
    )
    assert resp.status_code == 200
    assert isolated_engine.get_alert("org1", own_id)["status"] == "escalated"


def test_bulk_triage_dedups_repeated_ids(client, isolated_engine):
    own_id = _ingest(isolated_engine, "org1")
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": [own_id, own_id, own_id], "action": "resolve"},
    )
    assert resp.status_code == 200
    # Pydantic dedupes — engine sees the ID exactly once.
    assert resp.json()["updated"] == 1


def test_bulk_triage_unknown_id_returns_404(client, isolated_engine):
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        params={"org_id": "org1"},
        json={"alert_ids": ["does-not-exist"], "action": "resolve"},
    )
    assert resp.status_code == 404


def test_bulk_triage_org_id_in_body_works(client, isolated_engine):
    own_id = _ingest(isolated_engine, "org1")
    resp = client.post(
        "/api/v1/alert-triage/bulk-triage",
        json={"alert_ids": [own_id], "action": "resolve", "org_id": "org1"},
    )
    assert resp.status_code == 200
    assert resp.json()["updated"] == 1
