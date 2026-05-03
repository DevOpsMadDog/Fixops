"""HTTP-layer tests for /api/v1/secrets-rotation router.

Uses FastAPI TestClient with the dependency override for get_org_id
so no real auth header is needed.
"""
from __future__ import annotations

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.secrets_rotation_router import router, _tracker
from apps.api.dependencies import get_org_id


# ---------------------------------------------------------------------------
# App fixture — isolated per test run with org_id override
# ---------------------------------------------------------------------------

ORG = "test-org-router"


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """Stand up a minimal app with the router mounted and org_id overridden."""
    import tempfile
    from core.secrets_rotation_tracker import SecretsRotationTracker

    # Point tracker at a temp DB so tests are isolated
    db_file = tempfile.mktemp(suffix=".db")
    tracker = SecretsRotationTracker(db_path=db_file)

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_org_id] = lambda: ORG

    # Patch module-level _tracker so the router uses our isolated instance
    import apps.api.secrets_rotation_router as rot_mod
    rot_mod._tracker = tracker

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c

    # restore
    rot_mod._tracker = _tracker


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _expose(client, secret_type="api_key", severity="high"):
    resp = client.post("/api/v1/secrets-rotation/expose", json={
        "secret_type": secret_type,
        "exposed_location": "config/.env",
        "detection_source": "scanner",
        "severity": severity,
    })
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_register_exposure_200(client):
    """POST /expose returns 200 and a rotation_id."""
    rec = _expose(client)
    assert "rotation_id" in rec
    assert rec["state"] == "pending"
    assert rec["org_id"] == ORG


def test_register_exposure_invalid_type_422(client):
    """POST /expose with unknown secret_type returns 422."""
    resp = client.post("/api/v1/secrets-rotation/expose", json={
        "secret_type": "not_a_real_type",
        "exposed_location": "somewhere",
    })
    assert resp.status_code == 422


def test_get_rotation_404_unknown(client):
    """GET /{id} for non-existent rotation returns 404."""
    resp = client.get("/api/v1/secrets-rotation/does-not-exist")
    assert resp.status_code == 404


def test_full_lifecycle_happy_path(client):
    """Register -> start -> confirm -> verify transitions all succeed."""
    rec = _expose(client, secret_type="token", severity="critical")
    rid = rec["rotation_id"]

    # start
    r = client.post(f"/api/v1/secrets-rotation/{rid}/start", json={"assignee": "alice"})
    assert r.status_code == 200
    assert r.json()["state"] == "in_progress"

    # confirm
    r = client.post(f"/api/v1/secrets-rotation/{rid}/confirm",
                    json={"rotated_by": "alice", "new_secret_hash": "raw-secret-value"})
    assert r.status_code == 200
    assert r.json()["state"] == "rotated"
    assert len(r.json()["new_secret_hash"]) == 64  # SHA-256, not raw value

    # verify
    r = client.post(f"/api/v1/secrets-rotation/{rid}/verify",
                    json={"verifier": "bob", "notes": "scanner clean"})
    assert r.status_code == 200
    assert r.json()["state"] == "verified"


def test_list_and_metrics_returns_data(client):
    """GET / and GET /metrics return lists/dicts with expected keys."""
    _expose(client, secret_type="password")

    list_resp = client.get("/api/v1/secrets-rotation/")
    assert list_resp.status_code == 200
    assert isinstance(list_resp.json(), list)

    metrics_resp = client.get("/api/v1/secrets-rotation/metrics")
    assert metrics_resp.status_code == 200
    m = metrics_resp.json()
    assert "total" in m
    assert "by_state" in m
    assert "overdue_count" in m


def test_audit_trail_records_transitions(client):
    """GET /{id}/audit returns ordered state history after lifecycle transitions."""
    rec = _expose(client, secret_type="ssh_key")
    rid = rec["rotation_id"]

    client.post(f"/api/v1/secrets-rotation/{rid}/start", json={"assignee": "devops"})
    client.post(f"/api/v1/secrets-rotation/{rid}/fail", json={"reason": "key still in use"})

    r = client.get(f"/api/v1/secrets-rotation/{rid}/audit")
    assert r.status_code == 200
    states = [e["to_state"] for e in r.json()]
    assert "pending" in states
    assert "in_progress" in states
    assert "failed" in states
