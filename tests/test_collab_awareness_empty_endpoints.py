"""Tests for collaboration/awareness/training GET / root summary endpoints.

Uses a mini FastAPI app (not create_app) to avoid pydantic schema conflicts
from unrelated routers.

Covers:
  - GET /api/v1/collaboration/
  - GET /api/v1/notifications/
  - GET /api/v1/awareness-gamification/
  - GET /api/v1/security-training/
"""
from __future__ import annotations

import sys
import pytest

sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-api")

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _make_app():
    from apps.api.auth_deps import api_key_auth
    from apps.api.collaboration_router import router as collab_router
    from apps.api.notification_router import router as notif_router
    from apps.api.security_awareness_gamification_router import router as gamif_router
    from apps.api.security_training_router import router as training_router

    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(collab_router)
    app.include_router(notif_router)
    app.include_router(gamif_router)
    app.include_router(training_router)
    return app


@pytest.fixture(scope="module")
def client():
    app = _make_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


VALID_STATES = {"healthy", "degraded", "empty", "error", "unknown"}


# ---------------------------------------------------------------------------
# Collaboration GET /
# ---------------------------------------------------------------------------

class TestCollaborationRoot:
    def test_returns_200(self, client):
        r = client.get("/api/v1/collaboration/")
        assert r.status_code == 200

    def test_envelope_fields(self, client):
        body = client.get("/api/v1/collaboration/").json()
        assert "status" in body
        assert "domain" in body
        assert "org_id" in body
        assert body["domain"] == "collaboration"

    def test_status_is_valid(self, client):
        body = client.get("/api/v1/collaboration/").json()
        assert body["status"] in VALID_STATES

    def test_summary_present_when_not_error(self, client):
        body = client.get("/api/v1/collaboration/").json()
        if body["status"] != "error":
            assert "summary" in body

    def test_empty_state_has_hint(self, client):
        body = client.get("/api/v1/collaboration/").json()
        if body["status"] == "empty":
            assert "hint" in body

    def test_org_id_param(self, client):
        r = client.get("/api/v1/collaboration/?org_id=test-org")
        assert r.status_code == 200
        assert r.json()["org_id"] == "test-org"


# ---------------------------------------------------------------------------
# Notifications GET /
# ---------------------------------------------------------------------------

class TestNotificationsRoot:
    def test_returns_200(self, client):
        r = client.get("/api/v1/notifications/")
        assert r.status_code == 200

    def test_envelope_fields(self, client):
        body = client.get("/api/v1/notifications/").json()
        assert "status" in body
        assert "domain" in body
        assert "org_id" in body
        assert body["domain"] == "notifications"

    def test_status_is_valid(self, client):
        body = client.get("/api/v1/notifications/").json()
        assert body["status"] in VALID_STATES

    def test_summary_has_rule_counts(self, client):
        body = client.get("/api/v1/notifications/").json()
        if body["status"] != "error":
            assert "summary" in body
            assert "total_rules" in body["summary"]
            assert "enabled_rules" in body["summary"]

    def test_empty_state_has_hint(self, client):
        body = client.get("/api/v1/notifications/").json()
        if body["status"] == "empty":
            assert "hint" in body

    def test_org_id_param(self, client):
        r = client.get("/api/v1/notifications/?org_id=acme")
        assert r.status_code == 200
        assert r.json()["org_id"] == "acme"


# ---------------------------------------------------------------------------
# Awareness Gamification GET /
# ---------------------------------------------------------------------------

class TestAwarenessGamificationRoot:
    def test_returns_200(self, client):
        r = client.get("/api/v1/awareness-gamification/")
        assert r.status_code == 200

    def test_envelope_fields(self, client):
        body = client.get("/api/v1/awareness-gamification/").json()
        assert "status" in body
        assert "domain" in body
        assert "org_id" in body
        assert body["domain"] == "awareness-gamification"

    def test_status_is_valid(self, client):
        body = client.get("/api/v1/awareness-gamification/").json()
        assert body["status"] in VALID_STATES

    def test_summary_present_when_not_error(self, client):
        body = client.get("/api/v1/awareness-gamification/").json()
        if body["status"] != "error":
            assert "summary" in body

    def test_empty_state_has_hint(self, client):
        body = client.get("/api/v1/awareness-gamification/").json()
        if body["status"] == "empty":
            assert "hint" in body
            assert "challenges" in body["hint"].lower()

    def test_org_id_param(self, client):
        r = client.get("/api/v1/awareness-gamification/?org_id=test-org")
        assert r.status_code == 200
        assert r.json()["org_id"] == "test-org"


# ---------------------------------------------------------------------------
# Security Training GET /
# ---------------------------------------------------------------------------

class TestSecurityTrainingRoot:
    def test_returns_200(self, client):
        r = client.get("/api/v1/security-training/")
        assert r.status_code == 200

    def test_envelope_fields(self, client):
        body = client.get("/api/v1/security-training/").json()
        assert "status" in body
        assert "domain" in body
        assert "org_id" in body
        assert body["domain"] == "security-training"

    def test_status_is_valid(self, client):
        body = client.get("/api/v1/security-training/").json()
        assert body["status"] in VALID_STATES

    def test_summary_present_when_not_error(self, client):
        body = client.get("/api/v1/security-training/").json()
        if body["status"] != "error":
            assert "summary" in body

    def test_empty_state_has_hint(self, client):
        body = client.get("/api/v1/security-training/").json()
        if body["status"] == "empty":
            assert "hint" in body
            assert "courses" in body["hint"].lower()

    def test_org_id_in_response(self, client):
        r = client.get("/api/v1/security-training/")
        assert r.status_code == 200
        assert "org_id" in r.json()
