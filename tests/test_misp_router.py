"""Tests for misp_router — ALDECI.

Spins up a minimal FastAPI app with the MISP router mounted and stubs the
httpx.Client so we exercise normalization + error mapping without hitting a
live MISP instance.

NO MOCKS rule:
  * MISP_URL or MISP_AUTH_KEY missing → capability=unavailable, lookups → 503.
  * Happy paths inject a stub httpx client (not a hardcoded engine payload)
    so the real request → normalize pipeline runs.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# Stub httpx client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per (method, url-suffix)."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "json": json,
            }
        )
        for path, resp in self._responses.items():
            if url.endswith(path):
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


def _build_app(
    *,
    misp_url: Optional[str],
    auth_key: Optional[str],
    stub_responses: Optional[Dict[str, Any]] = None,
):
    """Construct an isolated app+engine bound to a stub client."""
    from core import misp_integration_engine as engine_mod

    engine_mod.reset_misp_integration_engine()

    stub = _StubClient(stub_responses or {})
    engine_mod.get_misp_integration_engine(
        misp_url=misp_url,
        auth_key=auth_key,
        client=stub,
    )

    from apps.api.misp_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset():
    from core import misp_integration_engine as engine_mod

    engine_mod.reset_misp_integration_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_unconfigured(monkeypatch):
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_AUTH_KEY", raising=False)
    app, _ = _build_app(misp_url=None, auth_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/misp/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "MISP"
    assert body["endpoints"] == [
        "/events",
        "/events/{id}",
        "/attributes/restSearch",
        "/feeds",
        "/tags",
    ]
    assert body["misp_url_present"] is False
    assert body["misp_auth_key_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_configured(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_AUTH_KEY", "test-auth-key")
    app, _ = _build_app(
        misp_url="https://misp.example.com", auth_key="test-auth-key"
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/misp/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["misp_url_present"] is True
    assert body["misp_auth_key_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# Lookup endpoints — 503 when unconfigured
# ---------------------------------------------------------------------------


def test_events_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_AUTH_KEY", raising=False)
    app, _ = _build_app(misp_url=None, auth_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/misp/events", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "MISP_URL" in detail or "MISP_AUTH_KEY" in detail
    _reset()


def test_event_view_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_AUTH_KEY", raising=False)
    app, _ = _build_app(misp_url=None, auth_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/misp/events/42", headers=HEADERS)
    assert r.status_code == 503
    _reset()


def test_attributes_rest_search_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_AUTH_KEY", raising=False)
    app, _ = _build_app(misp_url=None, auth_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/misp/attributes/restSearch",
        headers=HEADERS,
        json={"value": "8.8.8.8"},
    )
    assert r.status_code == 503
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx
# ---------------------------------------------------------------------------


def test_list_events_normalizes(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_AUTH_KEY", "test-key")
    raw = [
        {
            "Event": {
                "id": "10",
                "info": "Phishing campaign tracking",
                "threat_level_id": "2",
                "analysis": "1",
                "distribution": "1",
                "date": "2026-04-30",
                "timestamp": "1714435200",
                "published": True,
                "Org": {"name": "ACME-CERT"},
                "attribute_count": 17,
            }
        },
        {
            "Event": {
                "id": "11",
                "info": "Mirai botnet IOCs",
                "threat_level_id": "1",
                "analysis": "2",
                "distribution": "3",
                "date": "2026-04-29",
                "timestamp": "1714348800",
                "published": False,
                "Org": {"name": "ALDECI"},
                "Attribute": [{"id": "1"}, {"id": "2"}],
            }
        },
    ]
    app, stub = _build_app(
        misp_url="https://misp.example.com",
        auth_key="test-key",
        stub_responses={"/events/index": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/misp/events?limit=10&page=1", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 2
    assert len(body["events"]) == 2
    first = body["events"][0]
    assert first["id"] == "10"
    assert first["info"] == "Phishing campaign tracking"
    assert first["org_name"] == "ACME-CERT"
    assert first["attribute_count"] == 17
    assert first["published"] is True
    second = body["events"][1]
    assert second["attribute_count"] == 2  # derived from Attribute list

    # Verify Authorization header was sent.
    assert stub.calls
    assert stub.calls[0]["headers"].get("Authorization") == "test-key"
    assert stub.calls[0]["params"] == {"limit": 10, "page": 1}
    _reset()


def test_get_event_normalizes_attributes(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_AUTH_KEY", "test-key")
    raw = {
        "Event": {
            "id": "42",
            "info": "Targeted spear-phish",
            "threat_level_id": "2",
            "analysis": "1",
            "distribution": "1",
            "date": "2026-04-28",
            "timestamp": "1714262400",
            "published": True,
            "uuid": "abc-123",
            "Attribute": [
                {
                    "id": "100",
                    "type": "ip-dst",
                    "category": "Network activity",
                    "value": "203.0.113.7",
                    "to_ids": True,
                    "distribution": "5",
                },
                {
                    "id": "101",
                    "type": "url",
                    "category": "Payload delivery",
                    "value": "http://malicious.example/payload",
                    "to_ids": True,
                    "distribution": "5",
                },
            ],
            "Object": [{"name": "file", "id": "200"}],
            "RelatedEvent": [{"Event": {"id": "9"}}],
        }
    }
    app, _ = _build_app(
        misp_url="https://misp.example.com",
        auth_key="test-key",
        stub_responses={"/events/view/42": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/misp/events/42", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "Event" in body
    event = body["Event"]
    assert event["id"] == "42"
    assert event["info"] == "Targeted spear-phish"
    assert len(event["attributes"]) == 2
    assert event["attributes"][0]["type"] == "ip-dst"
    assert event["attributes"][0]["value"] == "203.0.113.7"
    assert event["attributes"][0]["to_ids"] is True
    assert len(event["objects"]) == 1
    assert len(event["related_events"]) == 1
    # Optional fields preserved.
    assert event["uuid"] == "abc-123"
    assert event["published"] is True
    _reset()


def test_attributes_rest_search_posts_body_and_normalizes(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_AUTH_KEY", "test-key")
    raw = {
        "response": {
            "Attribute": [
                {
                    "id": "555",
                    "type": "ip-dst",
                    "category": "Network activity",
                    "value": "8.8.8.8",
                    "event_id": "10",
                    "timestamp": "1714435200",
                },
                {
                    "id": "556",
                    "type": "ip-dst",
                    "category": "Network activity",
                    "value": "8.8.4.4",
                    "event_id": "11",
                    "timestamp": "1714435260",
                },
            ]
        }
    }
    app, stub = _build_app(
        misp_url="https://misp.example.com",
        auth_key="test-key",
        stub_responses={"/attributes/restSearch": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/misp/attributes/restSearch",
        headers=HEADERS,
        json={"type": "ip-dst", "last": "7d"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    attrs = body["response"]["Attribute"]
    assert len(attrs) == 2
    assert attrs[0]["value"] == "8.8.8.8"
    assert attrs[0]["event_id"] == "10"
    # Verify POST body merged defaults.
    assert stub.calls
    sent = stub.calls[-1]["json"]
    assert sent["type"] == "ip-dst"
    assert sent["last"] == "7d"
    assert sent["returnFormat"] == "json"
    _reset()


def test_attributes_rest_search_handles_response_list_form(monkeypatch):
    """Some MISP versions return response as a list of {Attribute:{...}}."""
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_AUTH_KEY", "test-key")
    raw = {
        "response": [
            {
                "Attribute": {
                    "id": "999",
                    "type": "domain",
                    "category": "Network activity",
                    "value": "evil.example",
                    "event_id": "77",
                    "timestamp": "1714000000",
                }
            }
        ]
    }
    app, _ = _build_app(
        misp_url="https://misp.example.com",
        auth_key="test-key",
        stub_responses={"/attributes/restSearch": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/misp/attributes/restSearch",
        headers=HEADERS,
        json={"value": "evil.example"},
    )
    assert r.status_code == 200, r.text
    attrs = r.json()["response"]["Attribute"]
    assert len(attrs) == 1
    assert attrs[0]["value"] == "evil.example"
    assert attrs[0]["type"] == "domain"
    _reset()


def test_list_feeds_normalizes_and_skips_disabled(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_AUTH_KEY", "test-key")
    raw = [
        {
            "Feed": {
                "id": "1",
                "name": "CIRCL OSINT Feed",
                "provider": "CIRCL",
                "url": "https://www.circl.lu/doc/misp/feed-osint/",
                "enabled": True,
                "source_format": "misp",
                "distribution": "3",
            }
        },
        {
            "Feed": {
                "id": "2",
                "name": "Disabled Feed",
                "provider": "Internal",
                "url": "https://example.com",
                "enabled": False,
            }
        },
    ]
    app, _ = _build_app(
        misp_url="https://misp.example.com",
        auth_key="test-key",
        stub_responses={"/feeds": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/misp/feeds", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    assert body["feeds"][0]["name"] == "CIRCL OSINT Feed"
    assert body["feeds"][0]["enabled"] is True
    _reset()


def test_list_tags_normalizes(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_AUTH_KEY", "test-key")
    raw = {
        "Tag": [
            {
                "id": "10",
                "name": "tlp:white",
                "colour": "#ffffff",
                "exportable": True,
            },
            {
                "id": "11",
                "name": "tlp:amber",
                "colour": "#ffbf00",
                "exportable": False,
            },
        ]
    }
    app, stub = _build_app(
        misp_url="https://misp.example.com",
        auth_key="test-key",
        stub_responses={"/tags": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/misp/tags?searchall=tlp", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["Tag"]) == 2
    assert body["Tag"][0]["name"] == "tlp:white"
    assert body["Tag"][0]["exportable"] is True
    # searchall should have been forwarded.
    assert stub.calls[-1]["params"] == {"searchall": "tlp"}
    _reset()


# ---------------------------------------------------------------------------
# Upstream error mapping
# ---------------------------------------------------------------------------


def test_events_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_AUTH_KEY", "test-key")
    app, _ = _build_app(
        misp_url="https://misp.example.com",
        auth_key="test-key",
        stub_responses={
            "/events/index": _StubResponse(429, {"message": "rate limit"}),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/misp/events", headers=HEADERS)
    assert r.status_code == 503
    assert "rate-limit" in r.json()["detail"].lower() or "429" in r.json()["detail"]
    _reset()


def test_events_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_AUTH_KEY", "bad-key")
    app, _ = _build_app(
        misp_url="https://misp.example.com",
        auth_key="bad-key",
        stub_responses={
            "/events/index": _StubResponse(401, {"message": "unauth"}),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/misp/events", headers=HEADERS)
    assert r.status_code == 503
    assert "credentials" in r.json()["detail"].lower() or "401" in r.json()["detail"]
    _reset()


def test_events_invalid_limit_returns_422(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_AUTH_KEY", "test-key")
    app, _ = _build_app(
        misp_url="https://misp.example.com", auth_key="test-key"
    )
    client = TestClient(app, raise_server_exceptions=True)

    # Out-of-range limit should fail at FastAPI Query validation (422).
    r = client.get("/api/v1/misp/events?limit=0", headers=HEADERS)
    assert r.status_code == 422
    _reset()
