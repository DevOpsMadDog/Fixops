"""Tests for the PagerDuty incident-management router (NO MOCKS).

The engine talks to https://api.pagerduty.com via httpx. We:
  - Verify capability summary reflects token presence (status: ok|empty|unavailable).
  - Verify endpoints return HTTP 503 when PAGERDUTY_API_TOKEN is unset.
  - Inject a stub httpx.Client into the singleton for happy-path tests so we
    still exercise the real parsing/normalisation code paths.

NO HARDCODED MOCK PAYLOADS in production code paths — the only stubs are
in the test file's local httpx adapter.
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

    def put(self, url, headers=None, json=None):
        self.calls.append(
            {"method": "PUT", "url": url, "headers": dict(headers or {}), "json": json}
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------- helpers


def _build_app(
    *,
    api_token: Optional[str],
    from_email: Optional[str],
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    from core import pagerduty_incident_engine as eng_mod

    eng_mod.reset_pagerduty_incident_engine()

    stub_client = _StubClient(stub_responses or {})
    eng_mod.get_pagerduty_incident_engine(
        api_token=api_token,
        from_email=from_email,
        client=stub_client,
    )

    from apps.api.pagerduty_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset() -> None:
    from core import pagerduty_incident_engine as eng_mod
    eng_mod.reset_pagerduty_incident_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_token(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_API_TOKEN", raising=False)
    monkeypatch.delenv("PAGERDUTY_FROM_EMAIL", raising=False)
    app, _ = _build_app(api_token=None, from_email=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pagerduty/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "PagerDuty"
    assert "/incidents" in body["endpoints"]
    assert "/services" in body["endpoints"]
    assert "/oncalls" in body["endpoints"]
    assert "/change_events/enqueue" in body["endpoints"]
    assert "/escalation_policies" in body["endpoints"]
    assert body["api_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_token_present(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "u+xxxx")
    monkeypatch.setenv("PAGERDUTY_FROM_EMAIL", "ops@example.com")
    app, _ = _build_app(api_token="u+xxxx", from_email="ops@example.com")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pagerduty/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["api_token_present"] is True
    assert body["from_email_present"] is True
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_list_incidents_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, from_email=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pagerduty/incidents", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "PAGERDUTY_API_TOKEN" in r.json()["detail"]
    _reset()


def test_list_services_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, from_email=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pagerduty/services", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_list_oncalls_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, from_email=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pagerduty/oncalls", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_enqueue_change_event_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, from_email=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty/change_events/enqueue",
        headers=HEADERS,
        json={
            "routing_key": "R0123456789ABCDEF0123456789ABCDEF",
            "payload": {
                "summary": "Build #2 of fixops",
                "source": "ci-runner-1",
                "timestamp": "2026-05-04T10:00:00Z",
                "custom_details": {"build_state": "passed"},
            },
        },
    )
    assert r.status_code == 503, r.text
    _reset()


def test_create_incident_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_API_TOKEN", raising=False)
    monkeypatch.delenv("PAGERDUTY_FROM_EMAIL", raising=False)
    app, _ = _build_app(api_token=None, from_email=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty/incidents",
        headers={**HEADERS, "From": "ops@example.com"},
        json={
            "incident": {
                "type": "incident",
                "title": "Critical CVE",
                "service": {"id": "PSVC001", "type": "service_reference"},
                "urgency": "high",
                "body": {"type": "incident_body", "details": "Severity 1"},
            }
        },
    )
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ happy paths


def test_list_incidents_happy_path(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "u+xxxx")
    raw = {
        "incidents": [
            {
                "id": "P12345",
                "incident_number": 42,
                "title": "API latency spike",
                "status": "triggered",
                "urgency": "high",
                "created_at": "2026-05-04T09:00:00Z",
                "service": {"id": "PSVC001", "summary": "Production API"},
                "assignments": [{"assignee": {"summary": "Alice"}}],
            }
        ],
        "offset": 0,
        "limit": 25,
        "more": False,
        "total": 1,
    }
    app, stub = _build_app(
        api_token="u+xxxx",
        from_email="ops@example.com",
        stub_responses={"/incidents": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pagerduty/incidents",
        headers=HEADERS,
        params=[("statuses[]", "triggered"), ("limit", "25"), ("offset", "0")],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["limit"] == 25
    assert body["offset"] == 0
    assert body["more"] is False
    assert body["total"] == 1
    assert body["incidents"][0]["id"] == "P12345"
    assert body["incidents"][0]["status"] == "triggered"
    # Verify Authorization header was set with Token token=...
    auth = stub.calls[0]["headers"].get("Authorization", "")
    assert auth.startswith("Token token=")
    # Verify statuses[] propagated
    sent_params = stub.calls[0]["params"]
    flat = [(k, v) for k, v in sent_params] if isinstance(sent_params, list) else list(sent_params.items())
    assert ("statuses[]", "triggered") in flat
    _reset()


def test_create_incident_happy_path(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "u+xxxx")
    monkeypatch.setenv("PAGERDUTY_FROM_EMAIL", "ops@example.com")
    raw = {
        "incident": {
            "id": "P67890",
            "incident_number": 99,
            "title": "Critical CVE",
            "status": "triggered",
            "urgency": "high",
        }
    }
    app, stub = _build_app(
        api_token="u+xxxx",
        from_email="ops@example.com",
        stub_responses={"/incidents": _StubResponse(201, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty/incidents",
        headers={**HEADERS, "From": "ops@example.com"},
        json={
            "incident": {
                "type": "incident",
                "title": "Critical CVE",
                "service": {"id": "PSVC001", "type": "service_reference"},
                "urgency": "high",
                "body": {"type": "incident_body", "details": "Sev 1"},
            }
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["incident"]["id"] == "P67890"
    # Verify From: was forwarded to PagerDuty
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts, "expected at least one POST"
    assert posts[0]["headers"].get("From") == "ops@example.com"
    # Verify body was forwarded as PagerDuty's nested wrapper
    sent_body = posts[0]["json"]
    assert sent_body["incident"]["title"] == "Critical CVE"
    assert sent_body["incident"]["service"]["id"] == "PSVC001"
    _reset()


def test_update_incident_happy_path(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "u+xxxx")
    monkeypatch.setenv("PAGERDUTY_FROM_EMAIL", "ops@example.com")
    raw = {
        "incident": {
            "id": "P67890",
            "incident_number": 99,
            "status": "resolved",
        }
    }
    app, stub = _build_app(
        api_token="u+xxxx",
        from_email="ops@example.com",
        stub_responses={"/incidents/P67890": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.put(
        "/api/v1/pagerduty/incidents/P67890",
        headers=HEADERS,
        json={"incident": {"type": "incident_reference", "status": "resolved"}},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["incident"]["status"] == "resolved"
    puts = [c for c in stub.calls if c["method"] == "PUT"]
    assert puts and puts[0]["json"]["incident"]["status"] == "resolved"
    _reset()


def test_add_incident_note_happy_path(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "u+xxxx")
    monkeypatch.setenv("PAGERDUTY_FROM_EMAIL", "ops@example.com")
    raw = {
        "note": {
            "id": "N12345",
            "content": "Mitigation deployed",
            "user": {"summary": "Alice"},
            "created_at": "2026-05-04T10:30:00Z",
        }
    }
    app, stub = _build_app(
        api_token="u+xxxx",
        from_email="ops@example.com",
        stub_responses={"/incidents/P67890/notes": _StubResponse(201, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty/incidents/P67890/notes",
        headers=HEADERS,
        json={"note": {"content": "Mitigation deployed"}},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["note"]["content"] == "Mitigation deployed"
    assert body["note"]["id"] == "N12345"
    _reset()


def test_list_services_happy_path(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "u+xxxx")
    raw = {
        "services": [
            {
                "id": "PSVC001",
                "name": "Production API",
                "status": "active",
                "escalation_policy": {"id": "PESC001", "summary": "Critical"},
                "integrations": [],
            }
        ]
    }
    app, _ = _build_app(
        api_token="u+xxxx",
        from_email="ops@example.com",
        stub_responses={"/services": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pagerduty/services", headers=HEADERS, params={"limit": 50})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["services"][0]["id"] == "PSVC001"
    assert body["services"][0]["status"] == "active"
    _reset()


def test_list_oncalls_happy_path(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "u+xxxx")
    raw = {
        "oncalls": [
            {
                "user": {"id": "PUSR001", "summary": "Alice"},
                "schedule": {"summary": "Primary On-Call"},
                "escalation_policy": {"summary": "Critical"},
                "escalation_level": 1,
                "start": "2026-05-04T00:00:00Z",
                "end": "2026-05-05T00:00:00Z",
            }
        ]
    }
    app, stub = _build_app(
        api_token="u+xxxx",
        from_email="ops@example.com",
        stub_responses={"/oncalls": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pagerduty/oncalls",
        headers=HEADERS,
        params=[("escalation_policy_ids[]", "PESC001"), ("time_zone", "UTC")],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["oncalls"][0]["user"]["id"] == "PUSR001"
    assert body["oncalls"][0]["escalation_level"] == 1
    sent_params = stub.calls[0]["params"]
    flat = [(k, v) for k, v in sent_params] if isinstance(sent_params, list) else list(sent_params.items())
    assert ("escalation_policy_ids[]", "PESC001") in flat
    assert ("time_zone", "UTC") in flat
    _reset()


def test_enqueue_change_event_happy_path(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "u+xxxx")
    raw = {
        "status": "success",
        "message": "Change event processed",
        "change_id": "01EZB7DAVMYDDX35F2GTBYRMRD",
    }
    app, stub = _build_app(
        api_token="u+xxxx",
        from_email="ops@example.com",
        stub_responses={"/v2/change/enqueue": _StubResponse(202, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty/change_events/enqueue",
        headers=HEADERS,
        json={
            "routing_key": "R0123456789ABCDEF0123456789ABCDEF",
            "payload": {
                "summary": "Deploy v1.2.3",
                "source": "ci-runner-1",
                "timestamp": "2026-05-04T10:00:00Z",
                "custom_details": {"build_state": "passed"},
            },
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "success"
    assert body["change_id"] == "01EZB7DAVMYDDX35F2GTBYRMRD"
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts and "events.pagerduty.com" in posts[0]["url"]
    sent = posts[0]["json"]
    assert sent["routing_key"].startswith("R012")
    assert sent["payload"]["summary"] == "Deploy v1.2.3"
    _reset()


# ============================================================ error mapping


def test_list_incidents_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "u+xxxx")
    app, _ = _build_app(
        api_token="u+xxxx",
        from_email="ops@example.com",
        stub_responses={"/incidents": _StubResponse(429, {"error": "rate"}, text="rate")},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pagerduty/incidents", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "rate-limit" in r.json()["detail"].lower() or "429" in r.json()["detail"]
    _reset()


def test_create_incident_validation_rejects_bad_urgency(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "u+xxxx")
    monkeypatch.setenv("PAGERDUTY_FROM_EMAIL", "ops@example.com")
    app, _ = _build_app(api_token="u+xxxx", from_email="ops@example.com")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/pagerduty/incidents",
        headers={**HEADERS, "From": "ops@example.com"},
        json={
            "incident": {
                "type": "incident",
                "title": "Sev 1",
                "service": {"id": "PSVC001", "type": "service_reference"},
                "urgency": "INVALID-URGENCY",
            }
        },
    )
    assert r.status_code == 422, r.text
    _reset()
