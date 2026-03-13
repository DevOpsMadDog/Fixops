"""Tests for collaboration_router (suite-api/apps/api/collaboration_router.py).

Covers:
  - AddCommentRequest, AddWatcherRequest, RemoveWatcherRequest models
  - RecordActivityRequest model
  - SSRF protection (_get_slack_webhook_url)
  - Router endpoint basic functionality
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.collaboration_router import (
    AddCommentRequest,
    AddWatcherRequest,
    RemoveWatcherRequest,
    RecordActivityRequest,
    _get_slack_webhook_url,
    router,
)


# ──────────────────────────────────────────────────────
#  Pydantic model tests
# ──────────────────────────────────────────────────────


class TestCollaborationModels:
    def test_add_comment_request(self):
        req = AddCommentRequest(
            entity_type="finding",
            entity_id="FIND-001",
            org_id="org-1",
            author="alice",
            content="This needs urgent attention.",
        )
        assert req.entity_type == "finding"
        assert req.is_internal is True
        assert req.parent_comment_id is None

    def test_add_watcher_request(self):
        req = AddWatcherRequest(
            entity_type="remediation",
            entity_id="REM-001",
            user_id="user-1",
        )
        assert req.entity_type == "remediation"
        assert req.user_email is None

    def test_remove_watcher_request(self):
        req = RemoveWatcherRequest(
            entity_type="finding",
            entity_id="FIND-001",
            user_id="user-1",
        )
        assert req.user_id == "user-1"

    def test_record_activity_request(self):
        req = RecordActivityRequest(
            entity_type="finding",
            entity_id="FIND-001",
            org_id="org-1",
            activity_type="status_change",
            actor="admin",
            summary="Status changed to resolved",
        )
        assert req.activity_type == "status_change"


# ──────────────────────────────────────────────────────
#  SSRF protection
# ──────────────────────────────────────────────────────


class TestSSRFProtection:
    def test_get_slack_webhook_url_not_set(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_SLACK_WEBHOOK_URL", raising=False)
        assert _get_slack_webhook_url() is None

    def test_get_slack_webhook_url_set(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
        assert _get_slack_webhook_url() == "https://hooks.slack.com/services/T/B/X"


# ──────────────────────────────────────────────────────
#  Router endpoint tests
# ──────────────────────────────────────────────────────


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create test client with temp DB."""
    import apps.api.collaboration_router as mod
    monkeypatch.setattr(mod, "_collab_service", None)
    monkeypatch.setattr(mod, "_DB_PATH", tmp_path / "collab.db")
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestCollaborationEndpoints:
    def test_add_comment(self, client):
        resp = client.post("/api/v1/collaboration/comments", json={
            "entity_type": "finding",
            "entity_id": "FIND-001",
            "org_id": "org-1",
            "author": "tester",
            "content": "Test comment",
        })
        assert resp.status_code in (200, 201)

    def test_list_comments(self, client):
        resp = client.get("/api/v1/collaboration/comments?entity_type=finding&entity_id=FIND-001")
        assert resp.status_code == 200

    def test_add_watcher(self, client):
        resp = client.post("/api/v1/collaboration/watchers", json={
            "entity_type": "finding",
            "entity_id": "FIND-001",
            "user_id": "user-1",
        })
        assert resp.status_code in (200, 201)

    def test_list_activity(self, client):
        resp = client.get("/api/v1/collaboration/activities?org_id=org-1&entity_type=finding&entity_id=FIND-001")
        assert resp.status_code == 200
