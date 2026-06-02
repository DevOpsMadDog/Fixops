"""Tests for wired GET /api/v1/webhooks/ index endpoint.

Verifies the endpoint returns real data from the SQLite store
(not a hardcoded empty list stub).
"""
import json
import datetime
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import apps.api.webhook_router as wr


def _make_client(tmp_db: str) -> TestClient:
    """Return a TestClient with the webhook router using tmp_db."""
    from apps.api.auth_deps import api_key_auth
    app = FastAPI()
    app.include_router(wr.router)
    # Bypass auth for this focused router test (the index wiring is under test,
    # not the auth layer); without this every request 401s.
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_db_override():
    """Ensure _DB_PATH_OVERRIDE is cleared before/after each test."""
    wr._DB_PATH_OVERRIDE = None
    yield
    wr._DB_PATH_OVERRIDE = None


def test_webhooks_index_empty(tmp_path):
    """Fresh DB returns count=0 and empty items list — not a hardcoded stub."""
    wr._DB_PATH_OVERRIDE = str(tmp_path / "wh_empty.db")
    client = _make_client(wr._DB_PATH_OVERRIDE)

    resp = client.get("/api/v1/webhooks/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["router"] == "webhooks"
    assert body["count"] == 0
    assert body["items"] == []


def test_webhooks_index_real_events(tmp_path):
    """After storing a real event, index returns count=1 with that row's data."""
    wr._DB_PATH_OVERRIDE = str(tmp_path / "wh_real.db")

    wr._store_event(
        event_id="test-uuid-001",
        source="okta",
        event_type="user.session.start",
        actor_email="alice@example.com",
        ip_address="1.2.3.4",
        outcome="SUCCESS",
        raw_json=json.dumps({"test": True}),
        received_at=datetime.datetime.utcnow().isoformat(),
    )

    client = _make_client(wr._DB_PATH_OVERRIDE)
    resp = client.get("/api/v1/webhooks/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["source"] == "okta"
    assert item["actor_email"] == "alice@example.com"
    assert item["event_type"] == "user.session.start"
