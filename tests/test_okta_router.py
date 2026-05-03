"""Tests for okta_router (live Okta IAM REST surface) — ALDECI.

Spins up a minimal FastAPI app with the Okta router mounted. Each test
gets an isolated engine singleton + stub httpx.Client so we exercise the
real REST + parsing + Link-header pagination code paths without hitting
the network.

NO MOCKS rule:
  * When OKTA_DOMAIN / OKTA_API_TOKEN are unset the capability summary
    reports ``status="unavailable"`` and every live endpoint returns 503.
  * Happy-path tests inject a stub client (not baked-in fake payloads)
    so REST + result normalization all run.
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
# Stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal stand-in for httpx.Response with .json/.status_code/.text/.headers."""

    def __init__(
        self,
        status_code: int,
        payload: Any,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
    ):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)
        self.headers = headers or {}

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> Any:
        # Longest-match wins so /sessions/me/lifecycle/refresh beats /sessions.
        keys = sorted(self._responses.keys(), key=len, reverse=True)
        for path in keys:
            if path in url:
                return self._responses[path]
        return _StubResponse(
            404, {"errorSummary": "not found"}, text="not found"
        )

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "params": params or {},
                "headers": headers or {},
            }
        )
        return self._match(url)

    def post(
        self,
        url: str,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "json": json or {},
                "headers": headers or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


def _build_app(
    *,
    okta_domain: Optional[str],
    okta_api_token: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to a stub client."""
    from core import okta_iam_engine as engine_mod

    engine_mod.reset_okta_iam_engine()
    stub = _StubClient(stub_responses)
    engine_mod.get_okta_iam_engine(
        okta_domain=okta_domain,
        okta_api_token=okta_api_token,
        client=stub,
    )

    from apps.api.okta_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Always reset the singleton before AND after each test."""
    from core import okta_iam_engine as engine_mod
    engine_mod.reset_okta_iam_engine()
    yield
    engine_mod.reset_okta_iam_engine()


# ---------------------------------------------------------------------------
# Capability summary — env-driven status flags
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("OKTA_DOMAIN", raising=False)
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    app, _ = _build_app(
        okta_domain=None, okta_api_token=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/okta/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Okta"
    for ep in (
        "/api/v1/users",
        "/api/v1/groups",
        "/api/v1/apps",
        "/api/v1/logs",
        "/api/v1/sessions",
    ):
        assert ep in body["endpoints"]
    assert body["okta_domain_present"] is False
    assert body["okta_api_token_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_both_creds_present(monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", "acme.okta.test")
    monkeypatch.setenv("OKTA_API_TOKEN", "ssws-tok")
    app, _ = _build_app(
        okta_domain="acme.okta.test",
        okta_api_token="ssws-tok",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/okta/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["okta_domain_present"] is True
    assert body["okta_api_token_present"] is True
    assert body["status"] == "ok"


def test_capability_summary_empty_when_only_one_cred(monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", "acme.okta.test")
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    app, _ = _build_app(
        okta_domain="acme.okta.test",
        okta_api_token=None,
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/okta/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["okta_domain_present"] is True
    assert body["okta_api_token_present"] is False
    assert body["status"] == "empty"


# ---------------------------------------------------------------------------
# Live endpoints — unavailable path (no creds) returns 503
# ---------------------------------------------------------------------------


def test_users_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("OKTA_DOMAIN", raising=False)
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    app, _ = _build_app(
        okta_domain=None, okta_api_token=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/okta/api/v1/users",
        params={"limit": 5},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "OKTA_DOMAIN" in detail and "OKTA_API_TOKEN" in detail


def test_groups_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("OKTA_DOMAIN", raising=False)
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    app, _ = _build_app(
        okta_domain=None, okta_api_token=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/okta/api/v1/groups", headers=HEADERS)
    assert r.status_code == 503


def test_apps_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("OKTA_DOMAIN", raising=False)
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    app, _ = _build_app(
        okta_domain=None, okta_api_token=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/okta/api/v1/apps", headers=HEADERS)
    assert r.status_code == 503


def test_logs_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("OKTA_DOMAIN", raising=False)
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    app, _ = _build_app(
        okta_domain=None, okta_api_token=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/okta/api/v1/logs", headers=HEADERS)
    assert r.status_code == 503


def test_session_get_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("OKTA_DOMAIN", raising=False)
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    app, _ = _build_app(
        okta_domain=None, okta_api_token=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/okta/api/v1/sessions/sess-abc123",
        headers=HEADERS,
    )
    assert r.status_code == 503


def test_session_refresh_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("OKTA_DOMAIN", raising=False)
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    app, _ = _build_app(
        okta_domain=None, okta_api_token=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/okta/api/v1/sessions/me/lifecycle/refresh",
        headers=HEADERS,
    )
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# Live endpoints — happy path with stubbed httpx.Client
# ---------------------------------------------------------------------------


def test_users_happy_path_parses_payload_and_pagination(monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", "acme.okta.test")
    monkeypatch.setenv("OKTA_API_TOKEN", "ssws-tok")

    user_payload = [
        {
            "id": "00u1abc",
            "status": "ACTIVE",
            "created": "2025-01-01T00:00:00.000Z",
            "activated": "2025-01-01T00:05:00.000Z",
            "lastLogin": "2026-05-01T12:00:00.000Z",
            "profile": {
                "firstName": "Ada",
                "lastName": "Lovelace",
                "email": "ada@acme.test",
                "login": "ada@acme.test",
                "secondEmail": "",
                "mobilePhone": "",
            },
            "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}},
        }
    ]

    next_link = (
        '<https://acme.okta.test/api/v1/users?after=cursor-xyz>; rel="next"'
    )
    app, stub = _build_app(
        okta_domain="acme.okta.test",
        okta_api_token="ssws-tok",
        stub_responses={
            "/users": _StubResponse(
                200, user_payload, headers={"Link": next_link}
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/okta/api/v1/users",
        params={"q": "ada", "limit": 25},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["next_cursor"] == "cursor-xyz"
    assert len(body["users"]) == 1
    user = body["users"][0]
    assert user["id"] == "00u1abc"
    assert user["status"] == "ACTIVE"
    assert user["profile"]["email"] == "ada@acme.test"
    assert user["credentials"]["provider"]["type"] == "OKTA"

    # Confirm the engine actually called Okta with the SSWS auth header.
    assert stub.calls
    call = stub.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://acme.okta.test/api/v1/users"
    assert call["headers"]["Authorization"] == "SSWS ssws-tok"
    assert call["params"]["q"] == "ada"
    assert call["params"]["limit"] == 25
    # None-valued params must be stripped before reaching httpx.
    assert "filter" not in call["params"]
    assert "search" not in call["params"]
    assert "after" not in call["params"]


def test_groups_happy_path(monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", "acme.okta.test")
    monkeypatch.setenv("OKTA_API_TOKEN", "ssws-tok")
    payload = [
        {
            "id": "00g1xyz",
            "type": "OKTA_GROUP",
            "profile": {
                "name": "Engineering",
                "description": "All eng staff",
            },
            "_links": {"self": {"href": "https://acme.okta.test/api/v1/groups/00g1xyz"}},
        }
    ]
    app, stub = _build_app(
        okta_domain="acme.okta.test",
        okta_api_token="ssws-tok",
        stub_responses={"/groups": _StubResponse(200, payload)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/okta/api/v1/groups",
        params={"q": "eng"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["next_cursor"] is None
    assert body["groups"][0]["profile"]["name"] == "Engineering"
    assert stub.calls[0]["url"] == "https://acme.okta.test/api/v1/groups"


def test_apps_happy_path(monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", "acme.okta.test")
    monkeypatch.setenv("OKTA_API_TOKEN", "ssws-tok")
    payload = [
        {
            "id": "0oa1abc",
            "name": "salesforce",
            "label": "Salesforce",
            "status": "ACTIVE",
            "signOnMode": "SAML_2_0",
            "accessibility": {},
            "visibility": {"hide": {"iOS": False, "web": False}},
            "settings": {
                "notifications": {},
                "signOn": {},
                "app": {},
            },
        }
    ]
    app, stub = _build_app(
        okta_domain="acme.okta.test",
        okta_api_token="ssws-tok",
        stub_responses={"/apps": _StubResponse(200, payload)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/okta/api/v1/apps",
        params={"limit": 100},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["apps"][0]["label"] == "Salesforce"
    assert body["apps"][0]["signOnMode"] == "SAML_2_0"
    assert stub.calls[0]["params"]["limit"] == 100


def test_logs_happy_path_with_filters(monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", "acme.okta.test")
    monkeypatch.setenv("OKTA_API_TOKEN", "ssws-tok")
    payload = [
        {
            "uuid": "evt-1",
            "published": "2026-05-01T00:00:00.000Z",
            "eventType": "user.session.start",
            "version": "0",
            "severity": "INFO",
            "legacyEventType": "core.user_auth.login_success",
            "displayMessage": "User login to Okta",
            "actor": {
                "id": "00u1abc",
                "type": "User",
                "alternateId": "ada@acme.test",
                "displayName": "Ada Lovelace",
            },
            "client": {
                "userAgent": {"browser": "CHROME", "os": "Mac OS X"},
                "geographicalContext": {"country": "United States"},
            },
            "outcome": {"result": "SUCCESS", "reason": ""},
            "target": [],
        }
    ]
    app, stub = _build_app(
        okta_domain="acme.okta.test",
        okta_api_token="ssws-tok",
        stub_responses={"/logs": _StubResponse(200, payload)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/okta/api/v1/logs",
        params={
            "since": "2026-05-01T00:00:00Z",
            "filter": 'eventType eq "user.session.start"',
            "limit": 50,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["events"][0]["uuid"] == "evt-1"
    assert body["events"][0]["actor"]["alternateId"] == "ada@acme.test"
    assert body["events"][0]["outcome"]["result"] == "SUCCESS"
    # Confirm filter alias actually reaches the engine as ``filter`` param.
    assert stub.calls[0]["params"]["filter"] == 'eventType eq "user.session.start"'
    assert stub.calls[0]["params"]["since"] == "2026-05-01T00:00:00Z"


def test_session_get_happy_path(monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", "acme.okta.test")
    monkeypatch.setenv("OKTA_API_TOKEN", "ssws-tok")
    payload = {
        "id": "sess-abc123",
        "login": "ada@acme.test",
        "userId": "00u1abc",
        "expiresAt": "2026-05-04T12:00:00.000Z",
        "status": "ACTIVE",
        "lastPasswordVerification": "2026-05-04T08:00:00.000Z",
        "lastFactorVerification": "2026-05-04T08:00:01.000Z",
        "amr": ["pwd", "mfa"],
    }
    app, stub = _build_app(
        okta_domain="acme.okta.test",
        okta_api_token="ssws-tok",
        stub_responses={"/sessions/sess-abc123": _StubResponse(200, payload)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/okta/api/v1/sessions/sess-abc123",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "sess-abc123"
    assert body["userId"] == "00u1abc"
    assert body["amr"] == ["pwd", "mfa"]
    assert stub.calls[0]["url"] == "https://acme.okta.test/api/v1/sessions/sess-abc123"


def test_session_refresh_happy_path(monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", "acme.okta.test")
    monkeypatch.setenv("OKTA_API_TOKEN", "ssws-tok")
    refreshed = {
        "id": "sess-me",
        "login": "me@acme.test",
        "userId": "00u-me",
        "expiresAt": "2026-05-04T13:00:00.000Z",
        "status": "ACTIVE",
        "amr": ["pwd"],
    }
    app, stub = _build_app(
        okta_domain="acme.okta.test",
        okta_api_token="ssws-tok",
        stub_responses={
            "/sessions/me/lifecycle/refresh": _StubResponse(200, refreshed),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/okta/api/v1/sessions/me/lifecycle/refresh",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "sess-me"
    assert body["status"] == "ACTIVE"
    assert stub.calls[0]["method"] == "POST"
    assert stub.calls[0]["url"].endswith("/api/v1/sessions/me/lifecycle/refresh")


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


def test_upstream_error_maps_to_503(monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", "acme.okta.test")
    monkeypatch.setenv("OKTA_API_TOKEN", "ssws-tok")
    app, _ = _build_app(
        okta_domain="acme.okta.test",
        okta_api_token="ssws-tok",
        stub_responses={
            "/users": _StubResponse(
                401, {"errorCode": "E0000011"}, text="invalid token"
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/okta/api/v1/users", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "401" in r.json()["detail"]


def test_domain_normalization_strips_scheme(monkeypatch):
    """OKTA_DOMAIN may arrive as a full URL — must be normalized to host."""
    from core import okta_iam_engine as engine_mod
    engine_mod.reset_okta_iam_engine()
    eng = engine_mod.get_okta_iam_engine(
        okta_domain="https://acme.okta.test/",
        okta_api_token="t",
    )
    assert eng.base_url() == "https://acme.okta.test/api/v1"
    engine_mod.reset_okta_iam_engine()
