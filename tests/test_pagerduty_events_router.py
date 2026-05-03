"""Tests for the PagerDuty Events API v2 router (NO MOCKS).

The engine talks to https://events.pagerduty.com via httpx. We:
  - Verify capability summary reflects routing-key presence
    (status: ok|empty|unavailable).
  - Verify endpoints return HTTP 503 when PAGERDUTY_ROUTING_KEY is unset and
    the request body provides no routing_key either.
  - Inject a stub httpx.Client into the singleton for happy-path tests so we
    still exercise the real parsing/normalisation code paths.

NO HARDCODED MOCK PAYLOADS in production code paths — the only stubs are in
this test file's local httpx adapter.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------- httpx stub


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Routes by URL substring. Records every call."""

    def __init__(self, responses: Dict[str, _StubResponse]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> _StubResponse:
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not_found"}, text="not found")

    def get(self, url, headers=None, params=None):
        self.calls.append(
            {"method": "GET", "url": url, "headers": dict(headers or {}), "params": params}
        )
        return self._match(url)

    def post(self, url, headers=None, json=None, data=None):
        self.calls.append(
            {"method": "POST", "url": url, "headers": dict(headers or {}), "json": json}
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------- helpers


def _build_app(
    *,
    routing_key: Optional[str],
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    from core import pagerduty_events_v2_engine as eng_mod

    eng_mod.reset_pagerduty_events_v2_engine()

    stub_client = _StubClient(stub_responses or {})
    eng_mod.get_pagerduty_events_v2_engine(
        routing_key=routing_key,
        client=stub_client,
    )

    from apps.api.pagerduty_events_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset() -> None:
    from core import pagerduty_events_v2_engine as eng_mod
    eng_mod.reset_pagerduty_events_v2_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_routing_key(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_ROUTING_KEY", raising=False)
    app, _ = _build_app(routing_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pagerduty-events/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "PagerDuty Events API v2"
    assert "/v2/enqueue" in body["endpoints"]
    assert "/v2/change/enqueue" in body["endpoints"]
    assert "/v2/dedup_key/lookup" in body["endpoints"]
    assert body["routing_key_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_routing_key_present_no_events(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "R0123456789ABCDEF0123456789ABCDEF")
    app, _ = _build_app(routing_key="R0123456789ABCDEF0123456789ABCDEF")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pagerduty-events/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["routing_key_present"] is True
    assert body["status"] == "empty"
    _reset()


# ============================================================ 503 paths


def test_enqueue_event_returns_503_when_no_routing_key(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_ROUTING_KEY", raising=False)
    app, _ = _build_app(routing_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty-events/v2/enqueue",
        headers=HEADERS,
        json={
            "event_action": "trigger",
            "payload": {
                "summary": "DB latency 99p exceeded SLO",
                "source": "prod-db-01",
                "severity": "critical",
            },
        },
    )
    assert r.status_code == 503, r.text
    assert "PAGERDUTY_ROUTING_KEY" in r.json()["detail"]
    _reset()


def test_change_enqueue_returns_503_when_no_routing_key(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_ROUTING_KEY", raising=False)
    app, _ = _build_app(routing_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty-events/v2/change/enqueue",
        headers=HEADERS,
        json={
            "payload": {
                "summary": "Deploy v1.2.3",
                "source": "ci-runner-1",
                "timestamp": "2026-05-04T10:00:00Z",
            }
        },
    )
    assert r.status_code == 503, r.text
    _reset()


def test_dedup_lookup_returns_503_when_no_routing_key(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_ROUTING_KEY", raising=False)
    app, _ = _build_app(routing_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pagerduty-events/v2/dedup_key/lookup",
        headers=HEADERS,
        params={"dedup_key": "abc123"},
    )
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ override path


def test_enqueue_event_uses_body_routing_key_when_env_unset(monkeypatch):
    """Per-request routing_key in the body MUST forward through even if env is unset."""
    monkeypatch.delenv("PAGERDUTY_ROUTING_KEY", raising=False)
    raw = {
        "status": "success",
        "message": "Event processed",
        "dedup_key": "from-body-rk-001",
    }
    app, stub = _build_app(
        routing_key=None,
        stub_responses={"/v2/enqueue": _StubResponse(202, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty-events/v2/enqueue",
        headers=HEADERS,
        json={
            "routing_key": "RBODYOVERRIDEFEDCBA9876543210ABCD",
            "event_action": "trigger",
            "payload": {
                "summary": "Per-request override",
                "source": "edge-proxy",
                "severity": "warning",
            },
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dedup_key"] == "from-body-rk-001"
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts and posts[0]["json"]["routing_key"] == "RBODYOVERRIDEFEDCBA9876543210ABCD"
    _reset()


# ============================================================ happy paths


def test_enqueue_trigger_event_happy_path(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "R0123456789ABCDEF0123456789ABCDEF")
    raw = {
        "status": "success",
        "message": "Event processed",
        "dedup_key": "ALDECI-CRIT-2026-05-04-001",
    }
    app, stub = _build_app(
        routing_key="R0123456789ABCDEF0123456789ABCDEF",
        stub_responses={"/v2/enqueue": _StubResponse(202, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty-events/v2/enqueue",
        headers=HEADERS,
        json={
            "event_action": "trigger",
            "payload": {
                "summary": "API latency p99 > 500ms",
                "source": "prod-api-01",
                "severity": "critical",
                "timestamp": "2026-05-04T10:00:00Z",
                "component": "api-gateway",
                "group": "production",
                "class": "latency-spike",
                "custom_details": {"p99_ms": 612, "trace_id": "tx-abc"},
            },
            "dedup_key": "ALDECI-CRIT-2026-05-04-001",
            "client": "ALDECI",
            "client_url": "https://aldeci.example.com/incidents/42",
            "links": [{"href": "https://example.com/runbook", "text": "Runbook"}],
            "images": [{"src": "https://example.com/graph.png", "alt": "p99 chart"}],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "success"
    assert body["dedup_key"] == "ALDECI-CRIT-2026-05-04-001"

    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts and "events.pagerduty.com" in posts[0]["url"]
    sent = posts[0]["json"]
    assert sent["routing_key"] == "R0123456789ABCDEF0123456789ABCDEF"
    assert sent["event_action"] == "trigger"
    assert sent["payload"]["summary"] == "API latency p99 > 500ms"
    assert sent["payload"]["severity"] == "critical"
    assert sent["dedup_key"] == "ALDECI-CRIT-2026-05-04-001"
    assert sent["client"] == "ALDECI"
    assert sent["links"][0]["href"] == "https://example.com/runbook"
    assert sent["images"][0]["src"] == "https://example.com/graph.png"
    _reset()


def test_enqueue_resolve_event_happy_path(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "R0123456789ABCDEF0123456789ABCDEF")
    raw = {
        "status": "success",
        "message": "Event processed",
        "dedup_key": "ALDECI-CRIT-2026-05-04-001",
    }
    app, stub = _build_app(
        routing_key="R0123456789ABCDEF0123456789ABCDEF",
        stub_responses={"/v2/enqueue": _StubResponse(202, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty-events/v2/enqueue",
        headers=HEADERS,
        json={
            "event_action": "resolve",
            "dedup_key": "ALDECI-CRIT-2026-05-04-001",
            "payload": {
                "summary": "Recovered",
                "source": "prod-api-01",
                "severity": "info",
            },
        },
    )
    assert r.status_code == 200, r.text
    sent = [c for c in stub.calls if c["method"] == "POST"][0]["json"]
    assert sent["event_action"] == "resolve"
    assert sent["dedup_key"] == "ALDECI-CRIT-2026-05-04-001"
    _reset()


def test_change_enqueue_happy_path(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "R0123456789ABCDEF0123456789ABCDEF")
    raw = {
        "status": "success",
        "message": "Change event processed",
        "change_id": "01EZB7DAVMYDDX35F2GTBYRMRD",
    }
    app, stub = _build_app(
        routing_key="R0123456789ABCDEF0123456789ABCDEF",
        stub_responses={"/v2/change/enqueue": _StubResponse(202, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty-events/v2/change/enqueue",
        headers=HEADERS,
        json={
            "payload": {
                "summary": "Deploy aldeci v1.2.3",
                "source": "ci-runner-1",
                "timestamp": "2026-05-04T10:00:00Z",
                "custom_details": {"git_sha": "abc123", "actor": "alice"},
            },
            "links": [{"href": "https://github.com/foo/bar/pull/42", "text": "PR #42"}],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "success"
    assert body["change_id"] == "01EZB7DAVMYDDX35F2GTBYRMRD"
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts and "events.pagerduty.com/v2/change/enqueue" in posts[0]["url"]
    sent = posts[0]["json"]
    assert sent["routing_key"] == "R0123456789ABCDEF0123456789ABCDEF"
    assert sent["payload"]["summary"] == "Deploy aldeci v1.2.3"
    assert sent["links"][0]["text"] == "PR #42"
    _reset()


def test_dedup_lookup_after_enqueue_returns_state(monkeypatch):
    """End-to-end: enqueue an event, then look up its dedup_key via the lookup endpoint."""
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "R0123456789ABCDEF0123456789ABCDEF")
    raw_enq = {
        "status": "success",
        "message": "Event processed",
        "dedup_key": "ALDECI-LOOKUP-001",
    }
    app, _ = _build_app(
        routing_key="R0123456789ABCDEF0123456789ABCDEF",
        stub_responses={"/v2/enqueue": _StubResponse(202, raw_enq)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    # 1. Enqueue
    r1 = client.post(
        "/api/v1/pagerduty-events/v2/enqueue",
        headers=HEADERS,
        json={
            "event_action": "trigger",
            "dedup_key": "ALDECI-LOOKUP-001",
            "payload": {
                "summary": "Lookup test",
                "source": "test-src",
                "severity": "warning",
            },
        },
    )
    assert r1.status_code == 200, r1.text

    # 2. Lookup
    r2 = client.get(
        "/api/v1/pagerduty-events/v2/dedup_key/lookup",
        headers=HEADERS,
        params={"dedup_key": "ALDECI-LOOKUP-001"},
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["dedup_key"] == "ALDECI-LOOKUP-001"
    assert body["status"] == "trigger"
    assert body["count"] == 1
    assert body["latest_event"]["event_action"] == "trigger"
    _reset()


def test_dedup_lookup_unknown_dedup_returns_unknown(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "R0123456789ABCDEF0123456789ABCDEF")
    app, _ = _build_app(routing_key="R0123456789ABCDEF0123456789ABCDEF")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pagerduty-events/v2/dedup_key/lookup",
        headers=HEADERS,
        params={"dedup_key": "never-seen"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dedup_key"] == "never-seen"
    assert body["status"] == "unknown"
    assert body["count"] == 0
    assert body["latest_event"] is None
    _reset()


# ============================================================ validation


def test_enqueue_trigger_rejects_invalid_severity(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "R0123456789ABCDEF0123456789ABCDEF")
    app, _ = _build_app(routing_key="R0123456789ABCDEF0123456789ABCDEF")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty-events/v2/enqueue",
        headers=HEADERS,
        json={
            "event_action": "trigger",
            "payload": {
                "summary": "x",
                "source": "y",
                "severity": "MEGA-CRITICAL",
            },
        },
    )
    assert r.status_code == 422, r.text
    _reset()


def test_enqueue_trigger_rejects_invalid_action(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "R0123456789ABCDEF0123456789ABCDEF")
    app, _ = _build_app(routing_key="R0123456789ABCDEF0123456789ABCDEF")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty-events/v2/enqueue",
        headers=HEADERS,
        json={
            "event_action": "delete-everything",
            "payload": {
                "summary": "x",
                "source": "y",
                "severity": "info",
            },
        },
    )
    assert r.status_code == 422, r.text
    _reset()


def test_enqueue_acknowledge_requires_dedup_key(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "R0123456789ABCDEF0123456789ABCDEF")
    app, _ = _build_app(routing_key="R0123456789ABCDEF0123456789ABCDEF")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty-events/v2/enqueue",
        headers=HEADERS,
        json={
            "event_action": "acknowledge",
            "payload": {
                "summary": "ack me",
                "source": "tst",
                "severity": "info",
            },
        },
    )
    assert r.status_code == 422, r.text
    assert "dedup_key" in r.json()["detail"]
    _reset()


# ============================================================ error mapping


def test_enqueue_event_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "R0123456789ABCDEF0123456789ABCDEF")
    app, _ = _build_app(
        routing_key="R0123456789ABCDEF0123456789ABCDEF",
        stub_responses={
            "/v2/enqueue": _StubResponse(429, {"error": "rate"}, text="rate")
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty-events/v2/enqueue",
        headers=HEADERS,
        json={
            "event_action": "trigger",
            "payload": {
                "summary": "rate-limited",
                "source": "prod",
                "severity": "warning",
            },
        },
    )
    assert r.status_code == 503, r.text
    assert "rate-limit" in r.json()["detail"].lower() or "429" in r.json()["detail"]
    _reset()
