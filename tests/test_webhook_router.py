"""
Tests for webhook_router.py — Okta Event Hook receiver + generic webhook ingestion.

Covers:
- GET /webhooks/okta/verify returns {"verification": token}
- GET /webhooks/okta/verify missing header returns 400
- POST /webhooks/okta/events stores events in DB
- user.session.start event recorded correctly (type, actor, ip, outcome)
- user.lifecycle.create event recorded
- user.lifecycle.deactivate event recorded correctly
- user.lifecycle.suspend event recorded
- user.authentication.sso event recorded
- user.account.update_profile event recorded
- POST /webhooks/okta/events with empty events list returns 0 received
- POST /webhooks/okta/events with invalid JSON returns 400
- POST /webhooks/okta/events with multiple events returns correct count
- POST /webhooks/generic/{source} stores payload
- POST /webhooks/generic/{source} returns 202 with event_id and source
- POST /webhooks/generic/{source} with invalid JSON returns 400
- GET /webhooks/events returns recent events (max 100)
- GET /webhooks/events filter by source works
- GET /webhooks/events filter by event_type works
- GET /webhooks/events with no events returns empty list
- GET /webhooks/events source + event_type combined filter works
- GET /webhooks/events limit param respected
"""
from __future__ import annotations

import os
import sys
import tempfile
from typing import Any, Dict
from unittest.mock import patch

import pytest

# Env must be set before importing FastAPI app modules
os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

import apps.api.webhook_router as webhook_module
from apps.api.webhook_router import router


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path):
    """Redirect the module-level DB to a fresh temp file for each test."""
    db_file = str(tmp_path / "test_webhook_events.db")
    original = webhook_module._DB_PATH_OVERRIDE
    webhook_module._DB_PATH_OVERRIDE = db_file
    yield db_file
    webhook_module._DB_PATH_OVERRIDE = original


@pytest.fixture()
def client(tmp_db):
    """TestClient wired to a fresh in-memory DB."""
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Sample payloads
# ---------------------------------------------------------------------------


def _okta_payload(event_type: str, actor_email: str = "jane@co.com", ip: str = "1.2.3.4", outcome: str = "SUCCESS") -> Dict[str, Any]:
    return {
        "source": "https://company.okta.com",
        "eventId": "evt-001",
        "eventTime": "2026-04-15T10:00:00Z",
        "data": {
            "events": [
                {
                    "uuid": f"uuid-{event_type}",
                    "published": "2026-04-15T10:00:00Z",
                    "eventType": event_type,
                    "actor": {
                        "id": "00u123",
                        "alternateId": actor_email,
                        "displayName": "Jane Doe",
                    },
                    "client": {"ipAddress": ip},
                    "outcome": {"result": outcome},
                }
            ]
        },
    }


# ---------------------------------------------------------------------------
# Okta verify tests
# ---------------------------------------------------------------------------


def test_okta_verify_returns_token(client):
    resp = client.get(
        "/api/v1/webhooks/okta/verify",
        headers={"x-okta-verification-challenge": "abc123token"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"verification": "abc123token"}


def test_okta_verify_arbitrary_token(client):
    token = "some-uuid-like-challenge-value-xyz"
    resp = client.get(
        "/api/v1/webhooks/okta/verify",
        headers={"x-okta-verification-challenge": token},
    )
    assert resp.status_code == 200
    assert resp.json()["verification"] == token


def test_okta_verify_missing_header_returns_400(client):
    resp = client.get("/api/v1/webhooks/okta/verify")
    assert resp.status_code == 400
    assert "x-okta-verification-challenge" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Okta events — ingestion tests
# ---------------------------------------------------------------------------


def test_okta_events_stores_session_start(client):
    payload = _okta_payload("user.session.start")
    resp = client.post("/api/v1/webhooks/okta/events", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["received"] == 1
    assert "user.session.start" in data["event_types"]


def test_okta_session_start_recorded_correctly(client):
    payload = _okta_payload("user.session.start", actor_email="alice@example.com", ip="10.0.0.1", outcome="SUCCESS")
    client.post("/api/v1/webhooks/okta/events", json=payload)

    events_resp = client.get("/api/v1/webhooks/events")
    assert events_resp.status_code == 200
    events = events_resp.json()["events"]
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "user.session.start"
    assert ev["actor_email"] == "alice@example.com"
    assert ev["ip_address"] == "10.0.0.1"
    assert ev["outcome"] == "SUCCESS"
    assert ev["source"] == "https://company.okta.com"


def test_okta_lifecycle_create_event(client):
    payload = _okta_payload("user.lifecycle.create")
    resp = client.post("/api/v1/webhooks/okta/events", json=payload)
    assert resp.status_code == 200
    assert resp.json()["received"] == 1


def test_okta_lifecycle_deactivate_handled(client):
    payload = _okta_payload("user.lifecycle.deactivate", actor_email="bob@corp.com")
    resp = client.post("/api/v1/webhooks/okta/events", json=payload)
    assert resp.status_code == 200
    assert resp.json()["received"] == 1

    events_resp = client.get("/api/v1/webhooks/events", params={"event_type": "user.lifecycle.deactivate"})
    events = events_resp.json()["events"]
    assert len(events) == 1
    assert events[0]["actor_email"] == "bob@corp.com"


def test_okta_lifecycle_suspend_event(client):
    payload = _okta_payload("user.lifecycle.suspend")
    resp = client.post("/api/v1/webhooks/okta/events", json=payload)
    assert resp.status_code == 200
    assert resp.json()["received"] == 1


def test_okta_authentication_sso_event(client):
    payload = _okta_payload("user.authentication.sso")
    resp = client.post("/api/v1/webhooks/okta/events", json=payload)
    assert resp.status_code == 200
    assert "user.authentication.sso" in resp.json()["event_types"]


def test_okta_account_update_profile_event(client):
    payload = _okta_payload("user.account.update_profile")
    resp = client.post("/api/v1/webhooks/okta/events", json=payload)
    assert resp.status_code == 200
    assert resp.json()["received"] == 1


def test_okta_events_empty_events_list(client):
    payload = {
        "source": "https://company.okta.com",
        "eventId": "evt-empty",
        "eventTime": "2026-04-15T10:00:00Z",
        "data": {"events": []},
    }
    resp = client.post("/api/v1/webhooks/okta/events", json=payload)
    assert resp.status_code == 200
    assert resp.json()["received"] == 0


def test_okta_events_multiple_events_in_one_request(client):
    payload = {
        "source": "https://company.okta.com",
        "eventId": "evt-multi",
        "eventTime": "2026-04-15T10:00:00Z",
        "data": {
            "events": [
                {
                    "uuid": "uuid-1",
                    "published": "2026-04-15T10:00:00Z",
                    "eventType": "user.session.start",
                    "actor": {"id": "00u1", "alternateId": "a@co.com"},
                    "client": {"ipAddress": "1.1.1.1"},
                    "outcome": {"result": "SUCCESS"},
                },
                {
                    "uuid": "uuid-2",
                    "published": "2026-04-15T10:01:00Z",
                    "eventType": "user.lifecycle.create",
                    "actor": {"id": "00u2", "alternateId": "b@co.com"},
                    "client": {"ipAddress": "2.2.2.2"},
                    "outcome": {"result": "SUCCESS"},
                },
            ]
        },
    }
    resp = client.post("/api/v1/webhooks/okta/events", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["received"] == 2
    assert set(data["event_types"]) == {"user.session.start", "user.lifecycle.create"}


def test_okta_events_invalid_json_returns_400(client):
    resp = client.post(
        "/api/v1/webhooks/okta/events",
        content=b"not json at all!!!",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Generic webhook tests
# ---------------------------------------------------------------------------


def test_generic_webhook_stores_payload(client):
    payload = {"action": "push", "ref": "refs/heads/main", "repo": "fixops"}
    resp = client.post("/api/v1/webhooks/generic/github", json=payload)
    assert resp.status_code == 202
    body = resp.json()
    assert body["source"] == "github"
    assert "event_id" in body
    assert body["status"] == "accepted"


def test_generic_webhook_appears_in_events_list(client):
    payload = {"alert": "cpu_high", "host": "server-01"}
    client.post("/api/v1/webhooks/generic/pagerduty", json=payload)

    events_resp = client.get("/api/v1/webhooks/events", params={"source": "pagerduty"})
    events = events_resp.json()["events"]
    assert len(events) == 1
    assert events[0]["source"] == "pagerduty"
    assert events[0]["event_type"] == "generic"


def test_generic_webhook_invalid_json_returns_400(client):
    resp = client.post(
        "/api/v1/webhooks/generic/test",
        content=b"{broken json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# List events tests
# ---------------------------------------------------------------------------


def test_list_events_empty_on_fresh_db(client):
    resp = client.get("/api/v1/webhooks/events")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["events"] == []


def test_list_events_returns_recent_events(client):
    client.post("/api/v1/webhooks/okta/events", json=_okta_payload("user.session.start"))
    client.post("/api/v1/webhooks/okta/events", json=_okta_payload("user.lifecycle.create"))

    resp = client.get("/api/v1/webhooks/events")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2


def test_list_events_filter_by_source(client):
    client.post("/api/v1/webhooks/okta/events", json=_okta_payload("user.session.start"))
    client.post("/api/v1/webhooks/generic/slack", json={"text": "hello"})

    resp = client.get("/api/v1/webhooks/events", params={"source": "slack"})
    events = resp.json()["events"]
    assert len(events) == 1
    assert events[0]["source"] == "slack"


def test_list_events_filter_by_event_type(client):
    client.post("/api/v1/webhooks/okta/events", json=_okta_payload("user.session.start"))
    client.post("/api/v1/webhooks/okta/events", json=_okta_payload("user.lifecycle.deactivate"))

    resp = client.get("/api/v1/webhooks/events", params={"event_type": "user.lifecycle.deactivate"})
    events = resp.json()["events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "user.lifecycle.deactivate"


def test_list_events_combined_source_and_type_filter(client):
    okta_payload = _okta_payload("user.session.start")
    client.post("/api/v1/webhooks/okta/events", json=okta_payload)
    client.post("/api/v1/webhooks/generic/datadog", json={"metric": "cpu"})

    resp = client.get(
        "/api/v1/webhooks/events",
        params={"source": "https://company.okta.com", "event_type": "user.session.start"},
    )
    events = resp.json()["events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "user.session.start"


def test_list_events_limit_param_respected(client):
    # Insert 5 events
    for i in range(5):
        client.post("/api/v1/webhooks/generic/source_x", json={"i": i})

    resp = client.get("/api/v1/webhooks/events", params={"limit": 3})
    assert resp.status_code == 200
    assert resp.json()["total"] == 3
