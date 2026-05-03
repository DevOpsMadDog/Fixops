"""Router-level API tests for log_management_router (SIEM log-ingest).

Covers:
  POST /api/v1/log-management/sources           — create log source
  GET  /api/v1/log-management/sources           — list sources + filter
  POST /api/v1/log-management/entries           — ingest a log entry
  GET  /api/v1/log-management/entries           — query entries with filters
  POST /api/v1/log-management/retention-policies — create retention policy
  GET  /api/v1/log-management/stats             — aggregate stats

6 tests, zero mocks, real SQLite engine via tmp_path isolation.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.log_management_engine import LogManagementEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path):
    """
    Mount log_management_router on an isolated FastAPI app.

    Override the module-level singleton so every test gets a fresh,
    tmp_path-backed SQLite DB with no cross-test bleed.
    """
    import apps.api.log_management_router as lmr

    # Inject an isolated engine — bypasses the default .fixops_data/ path.
    lmr._engine = LogManagementEngine(db_path=str(tmp_path / "lm_test.db"))

    app = FastAPI()
    app.include_router(lmr.router)
    yield TestClient(app, raise_server_exceptions=True)

    # Reset singleton so other test modules start fresh.
    lmr._engine = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_source(client: TestClient, **overrides) -> dict:
    payload = {
        "org_id": "test-org",
        "name": "auth-syslog",
        "log_type": "security",
        "format": "syslog",
        "retention_days": 30,
        "status": "active",
        **overrides,
    }
    resp = client.post("/api/v1/log-management/sources", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _source_id(body: dict) -> str:
    """Engine stores primary key as 'id' on source rows."""
    return body["source"]["id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_create_log_source_returns_source_id(client):
    """POST /sources must return a source dict with a valid source_id."""
    body = _create_source(client)
    assert body["status"] == "created"
    src = body["source"]
    # Engine stores the UUID under key "id" (not "source_id")
    assert "id" in src
    assert src["name"] == "auth-syslog"
    assert src["log_type"] == "security"


def test_list_sources_reflects_created_source(client):
    """GET /sources must list the source just created, filtered by log_type."""
    _create_source(client, name="net-flow", log_type="network", format="json")
    _create_source(client, name="app-errors", log_type="application", format="json")

    resp = client.get(
        "/api/v1/log-management/sources",
        params={"org_id": "test-org", "log_type": "network"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["sources"][0]["name"] == "net-flow"


def test_ingest_log_entry_and_retrieve(client):
    """POST /entries followed by GET /entries must return the ingested line."""
    src_body = _create_source(client)
    source_id = _source_id(src_body)

    ingest_resp = client.post(
        "/api/v1/log-management/entries",
        json={
            "org_id": "test-org",
            "source_id": source_id,
            "level": "error",
            "message": "Failed login attempt from 10.0.0.1",
            "metadata": {"ip": "10.0.0.1", "user": "bob"},
        },
    )
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["status"] == "stored"

    query_resp = client.get(
        "/api/v1/log-management/entries",
        params={"org_id": "test-org", "source_id": source_id, "level": "error"},
    )
    assert query_resp.status_code == 200
    entries = query_resp.json()["entries"]
    assert len(entries) >= 1
    assert "Failed login attempt" in entries[0]["message"]


def test_entries_full_text_search(client):
    """GET /entries?search= must narrow results to matching messages."""
    src_body = _create_source(client)
    sid = _source_id(src_body)

    for msg in ("brute force detected", "normal heartbeat", "SQL injection attempt"):
        client.post(
            "/api/v1/log-management/entries",
            json={"org_id": "test-org", "source_id": sid, "level": "warn", "message": msg},
        )

    resp = client.get(
        "/api/v1/log-management/entries",
        params={"org_id": "test-org", "search": "injection"},
    )
    assert resp.status_code == 200
    entries = resp.json()["entries"]
    assert len(entries) == 1
    assert "injection" in entries[0]["message"].lower()


def test_create_retention_policy(client):
    """POST /retention-policies must persist and return the policy."""
    resp = client.post(
        "/api/v1/log-management/retention-policies",
        json={
            "org_id": "test-org",
            "name": "90-day-security",
            "log_type": "security",
            "retention_days": 90,
            "action": "delete",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "created"
    policy = data["policy"]
    assert policy["name"] == "90-day-security"
    assert policy["retention_days"] == 90

    # Also verify it appears in list
    list_resp = client.get(
        "/api/v1/log-management/retention-policies",
        params={"org_id": "test-org"},
    )
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] == 1


def test_stats_reflects_ingested_data(client):
    """GET /stats must return accurate totals after source + entry creation."""
    src_body = _create_source(client)
    sid = _source_id(src_body)

    for level in ("info", "warn", "error"):
        client.post(
            "/api/v1/log-management/entries",
            json={
                "org_id": "test-org",
                "source_id": sid,
                "level": level,
                "message": f"test {level} log",
            },
        )

    resp = client.get("/api/v1/log-management/stats", params={"org_id": "test-org"})
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["total_sources"] >= 1
    assert stats["total_entries"] >= 3
    assert "entries_by_level" in stats
