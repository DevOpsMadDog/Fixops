"""
Unit tests for POST /api/v1/webhooks/notifications/test-fire/{webhook_id}

Covers:
- preview_only=true: returns payload envelope without any HTTP call
- preview_only=false, delivery success: delegates to _deliver_with_retry
- 404 when webhook_id not found for org
- invalid event_type rejected by Pydantic (422)
- custom_fields merged into preview payload
- payload envelope always contains test_fire=true flag

Strategy: isolate DB via _DB_PATH_OVERRIDE; mock _deliver_with_retry so tests
never make real HTTP calls.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import uuid
from typing import Any, Dict
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-api-token-for-webhooks")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi.testclient import TestClient

import apps.api.webhook_notifications_router as notif_router
from apps.api.webhook_notifications_router import (
    _build_test_fire_payload,
    _open_db,
)

# ---------------------------------------------------------------------------
# Minimal FastAPI app for isolated testing
# ---------------------------------------------------------------------------
from fastapi import FastAPI

_app = FastAPI()
_app.include_router(notif_router.router)

# Override auth dependency so tests don't need a real API key
from apps.api.auth_deps import api_key_auth


def _auth_override():
    return "test-key"


_app.dependency_overrides[api_key_auth] = _auth_override

client = TestClient(_app, raise_server_exceptions=True)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

AUTH_HEADERS = {"X-API-Key": "test-api-token-for-webhooks"}


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Redirect all SQLite calls to a per-test temp DB."""
    db_file = str(tmp_path / "test_webhook_notifications.db")
    original = notif_router._DB_PATH_OVERRIDE
    notif_router._DB_PATH_OVERRIDE = db_file
    # Initialise schema
    conn = _open_db()
    conn.close()
    yield db_file
    notif_router._DB_PATH_OVERRIDE = original


def _insert_webhook(
    db_path: str,
    org_id: str = "test-org",
    url: str = "https://example.com/hook",
    events: list | None = None,
) -> str:
    """Insert a webhook row directly and return its ID."""
    wh_id = str(uuid.uuid4())
    secret = "test-secret-abc123"
    now = "2026-05-03T00:00:00+00:00"
    events_json = json.dumps(events or ["finding.created", "alert.created"])
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO webhooks (id, org_id, url, secret, events, active, created_at, fail_count) "
        "VALUES (?, ?, ?, ?, ?, 1, ?, 0)",
        (wh_id, org_id, url, secret, events_json, now),
    )
    conn.commit()
    conn.close()
    return wh_id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBuildTestFirePayload:
    """Unit-test the payload builder in isolation."""

    def test_contains_required_keys(self):
        p = _build_test_fire_payload("wh-1", "org-1", "finding.created", {})
        assert p["webhook_id"] == "wh-1"
        assert p["org_id"] == "org-1"
        assert p["event_type"] == "finding.created"
        assert p["test_fire"] is True

    def test_sample_data_present(self):
        p = _build_test_fire_payload("wh-2", "org-2", "alert.created", {})
        assert "sample_data" in p
        assert p["sample_data"]["severity"] == "critical"

    def test_custom_fields_merged(self):
        p = _build_test_fire_payload("wh-3", "org-3", "sla.breach", {"my_key": "my_val"})
        assert p["my_key"] == "my_val"
        assert p["test_fire"] is True

    def test_timestamp_is_iso_string(self):
        from datetime import datetime
        p = _build_test_fire_payload("wh-4", "org-4", "finding.created", {})
        dt = datetime.fromisoformat(p["timestamp"])
        assert dt is not None


class TestTestFirePreviewMode:
    """preview_only=true — no HTTP call, payload returned."""

    def test_preview_returns_payload_envelope(self, isolated_db):
        wh_id = _insert_webhook(isolated_db)
        resp = client.post(
            f"/api/v1/webhooks/notifications/test-fire/{wh_id}",
            json={
                "org_id": "test-org",
                "event_type": "finding.created",
                "preview_only": True,
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] == "preview"
        assert body["delivery_skipped"] is True
        assert body["webhook_id"] == wh_id
        assert body["payload"]["test_fire"] is True

    def test_preview_does_not_call_deliver(self, isolated_db):
        wh_id = _insert_webhook(isolated_db)
        with patch.object(notif_router, "_deliver_with_retry") as mock_deliver:
            resp = client.post(
                f"/api/v1/webhooks/notifications/test-fire/{wh_id}",
                json={"org_id": "test-org", "preview_only": True},
                headers=AUTH_HEADERS,
            )
            assert resp.status_code == 200
            mock_deliver.assert_not_called()

    def test_preview_with_custom_fields(self, isolated_db):
        wh_id = _insert_webhook(isolated_db)
        resp = client.post(
            f"/api/v1/webhooks/notifications/test-fire/{wh_id}",
            json={
                "org_id": "test-org",
                "event_type": "sla.breach",
                "preview_only": True,
                "custom_fields": {"ticket_ref": "JIRA-999"},
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["payload"]["ticket_ref"] == "JIRA-999"
        assert body["event_type"] == "sla.breach"


class TestTestFireLiveMode:
    """preview_only=false — delegates to _deliver_with_retry."""

    def test_live_mode_calls_deliver_with_retry(self, isolated_db):
        wh_id = _insert_webhook(isolated_db)
        mock_result = {"status": "success", "http_status": 200, "error": None}
        with patch.object(notif_router, "_deliver_with_retry", return_value=mock_result) as mock_deliver:
            resp = client.post(
                f"/api/v1/webhooks/notifications/test-fire/{wh_id}",
                json={"org_id": "test-org", "preview_only": False},
                headers=AUTH_HEADERS,
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["mode"] == "live"
            assert body["status"] == "success"
            assert body["http_status"] == 200
            assert body["error"] is None
            assert body["payload_sent"]["test_fire"] is True
            mock_deliver.assert_called_once()

    def test_live_mode_failure_returned(self, isolated_db):
        wh_id = _insert_webhook(isolated_db)
        mock_result = {"status": "failed", "http_status": 503, "error": "HTTP 503"}
        with patch.object(notif_router, "_deliver_with_retry", return_value=mock_result):
            with patch.object(notif_router, "_update_webhook_state"):
                resp = client.post(
                    f"/api/v1/webhooks/notifications/test-fire/{wh_id}",
                    json={"org_id": "test-org"},
                    headers=AUTH_HEADERS,
                )
                assert resp.status_code == 200
                body = resp.json()
                assert body["status"] == "failed"
                assert body["error"] == "HTTP 503"


class TestTestFireValidation:
    """Input validation and 404 handling."""

    def test_404_when_webhook_not_found(self, isolated_db):
        resp = client.post(
            f"/api/v1/webhooks/notifications/test-fire/{uuid.uuid4()}",
            json={"org_id": "test-org", "preview_only": True},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 404

    def test_404_when_org_mismatch(self, isolated_db):
        wh_id = _insert_webhook(isolated_db, org_id="org-a")
        resp = client.post(
            f"/api/v1/webhooks/notifications/test-fire/{wh_id}",
            json={"org_id": "org-b", "preview_only": True},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 404

    def test_invalid_event_type_returns_422(self, isolated_db):
        wh_id = _insert_webhook(isolated_db)
        resp = client.post(
            f"/api/v1/webhooks/notifications/test-fire/{wh_id}",
            json={
                "org_id": "test-org",
                "event_type": "not.a.real.event",
                "preview_only": True,
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 422

    def test_default_event_type_is_finding_created(self, isolated_db):
        wh_id = _insert_webhook(isolated_db)
        with patch.object(notif_router, "_deliver_with_retry", return_value={"status": "success", "http_status": 200, "error": None}):
            with patch.object(notif_router, "_update_webhook_state"):
                resp = client.post(
                    f"/api/v1/webhooks/notifications/test-fire/{wh_id}",
                    json={"org_id": "test-org"},
                    headers=AUTH_HEADERS,
                )
                assert resp.status_code == 200
                assert resp.json()["event_type"] == "finding.created"
