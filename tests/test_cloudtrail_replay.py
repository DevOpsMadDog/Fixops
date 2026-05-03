"""Tests for CloudTrail replay endpoint — engine + HTTP router.

Covers: batch ingest, camelCase normalisation, dry_run, validation errors,
org isolation, and the FastAPI route via TestClient.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.cloud_security_analytics_engine import CloudSecurityAnalyticsEngine


ORG = "org-replay-test"

# ---------------------------------------------------------------------------
# Engine-level fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    return CloudSecurityAnalyticsEngine(db_path=str(tmp_path / "replay_csa.db"))


def _event(**kwargs):
    base = {
        "event_source": "cloudtrail",
        "event_type": "api_call",
        "severity": "low",
        "actor": "arn:aws:iam::123456789012:user/alice",
        "region": "us-east-1",
        "risk_score": 10.0,
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Engine: replay_cloudtrail
# ---------------------------------------------------------------------------


def test_replay_returns_summary(engine):
    events = [_event(), _event(severity="medium", risk_score=50.0)]
    result = engine.replay_cloudtrail(ORG, events)
    assert result["total"] == 2
    assert result["ingested"] == 2
    assert result["skipped"] == 0
    assert result["errors"] == []
    assert len(result["event_ids"]) == 2


def test_replay_events_persisted(engine):
    events = [_event(actor="bot-1"), _event(actor="bot-2")]
    engine.replay_cloudtrail(ORG, events)
    stored = engine.list_events(ORG)
    actors = {e["actor"] for e in stored}
    assert "bot-1" in actors and "bot-2" in actors


def test_replay_dry_run_does_not_persist(engine):
    events = [_event(actor="ghost-user")]
    result = engine.replay_cloudtrail(ORG, events, dry_run=True)
    assert result["dry_run"] is True
    assert result["ingested"] == 1
    stored = engine.list_events(ORG)
    assert all(e["actor"] != "ghost-user" for e in stored)


def test_replay_camelcase_normalisation(engine):
    """cloudtrail-format camelCase keys must map to the engine schema."""
    raw = {
        "eventSource": "cloudtrail",
        "eventType": "auth_event",
        "severity": "high",
        "awsRegion": "eu-west-1",
        "userIdentity": {"arn": "arn:aws:iam::000:user/bob", "accountId": "000111222"},
        "requestParameters": "{'key': 'val'}",
        "eventTime": "2026-05-03T10:00:00Z",
        "risk_score": 75.0,
    }
    result = engine.replay_cloudtrail(ORG, [raw])
    assert result["ingested"] == 1
    assert result["errors"] == []
    stored = engine.list_events(ORG, event_type="auth_event")
    assert len(stored) == 1
    ev = stored[0]
    assert ev["actor"] == "arn:aws:iam::000:user/bob"
    assert ev["region"] == "eu-west-1"
    assert ev["account_id"] == "000111222"


def test_replay_invalid_event_source_recorded_as_error(engine):
    events = [_event(event_source="bad-source")]
    result = engine.replay_cloudtrail(ORG, events)
    assert result["ingested"] == 0
    assert len(result["errors"]) == 1
    assert "invalid event_source" in result["errors"][0]["reason"]


def test_replay_mixed_valid_invalid(engine):
    events = [
        _event(actor="ok-user"),
        _event(event_type="not-a-type"),  # invalid
        _event(actor="also-ok"),
    ]
    result = engine.replay_cloudtrail(ORG, events)
    assert result["total"] == 3
    assert result["ingested"] == 2
    assert len(result["errors"]) == 1
    assert result["errors"][0]["index"] == 1


def test_replay_org_isolation(engine):
    engine.replay_cloudtrail("org-A", [_event(actor="user-a")])
    engine.replay_cloudtrail("org-B", [_event(actor="user-b")])
    org_a_events = engine.list_events("org-A")
    org_b_events = engine.list_events("org-B")
    assert all(e["actor"] == "user-a" for e in org_a_events)
    assert all(e["actor"] == "user-b" for e in org_b_events)


# ---------------------------------------------------------------------------
# HTTP router
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path):
    from apps.api import cloud_security_analytics_router as mod
    from apps.api.auth_deps import api_key_auth

    # Isolate engine to tmp DB
    mod._engine = CloudSecurityAnalyticsEngine(db_path=str(tmp_path / "http_replay.db"))

    app = FastAPI()
    app.include_router(mod.router)
    # Bypass auth for tests
    app.dependency_overrides[api_key_auth] = lambda: None
    yield TestClient(app)

    mod._engine = None  # reset singleton


def test_http_replay_ok(client):
    payload = {
        "org_id": "http-org",
        "events": [
            {
                "event_source": "cloudtrail",
                "event_type": "api_call",
                "severity": "low",
                "actor": "arn:aws:sts::123:assumed-role/lambda",
                "risk_score": 5.0,
            }
        ],
        "dry_run": False,
    }
    resp = client.post("/api/v1/cloud-analytics/cloud-trail-replay", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ingested"] == 1
    assert body["total"] == 1
    assert body["errors"] == []


def test_http_replay_dry_run(client):
    payload = {
        "org_id": "http-org",
        "events": [{"event_source": "cloudtrail", "event_type": "api_call", "severity": "low"}],
        "dry_run": True,
    }
    resp = client.post("/api/v1/cloud-analytics/cloud-trail-replay", json=payload)
    assert resp.status_code == 200
    assert resp.json()["dry_run"] is True
    assert resp.json()["ingested"] == 1


def test_http_replay_empty_events_rejected(client):
    payload = {"org_id": "http-org", "events": []}
    resp = client.post("/api/v1/cloud-analytics/cloud-trail-replay", json=payload)
    # Pydantic min_length=1 on events list → 422
    assert resp.status_code == 422
