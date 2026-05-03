"""Tests for auth0_router — ALDECI.

Spins up a minimal FastAPI app with the Auth0 router mounted. Each test
gets an isolated engine (no SQLite cache; the engine is in-memory only).
The engine singleton is reset so state doesn't bleed between tests.

NO MOCKS rule:
  * /api/v2/* return HTTP 503 when AUTH0_DOMAIN/CLIENT_ID/CLIENT_SECRET unset.
  * Capability summary reports ``status="unavailable"`` when creds missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real networking + parsing code paths.
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
# httpx stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal stand-in for httpx.Response with .json() + .status_code."""

    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix.

    Token endpoint is keyed on '/oauth/token' and returns ``token_response``.
    All other endpoints look up a longest-prefix match in ``responses``.
    """

    def __init__(
        self,
        responses: Optional[Dict[str, Any]] = None,
        token_response: Optional[Any] = None,
    ):
        self._responses = responses or {}
        self._token_response = token_response or _StubResponse(
            200,
            {"access_token": "stub-token", "expires_in": 86400, "token_type": "Bearer"},
        )
        self.calls: List[Dict[str, Any]] = []

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {"method": "GET", "url": url, "headers": headers or {}, "params": params or {}}
        )
        # longest-prefix match so that /api/v2/users/{id}/roles wins over /api/v2/users/{id}
        match = None
        match_len = -1
        for path, resp in self._responses.items():
            if path in url and len(path) > match_len:
                match = resp
                match_len = len(path)
        if match is not None:
            return match
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,  # noqa: A002
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "data": data or {},
                "json": json or {},
            }
        )
        if "/oauth/token" in url:
            return self._token_response
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    domain: Optional[str],
    client_id: Optional[str],
    client_secret: Optional[str],
    stub_responses: Optional[Dict[str, Any]] = None,
    token_response: Optional[Any] = None,
):
    """Construct an isolated app+engine bound to the supplied stub client."""
    from core import auth0_engine as engine_mod

    engine_mod.reset_auth0_engine()

    stub_client = _StubClient(stub_responses or {}, token_response=token_response)
    engine_mod.get_auth0_engine(
        domain=domain,
        client_id=client_id,
        client_secret=client_secret,
        client=stub_client,
    )

    from apps.api.auth0_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import auth0_engine as engine_mod

    engine_mod.reset_auth0_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_creds_missing(monkeypatch):
    monkeypatch.delenv("AUTH0_DOMAIN", raising=False)
    monkeypatch.delenv("AUTH0_CLIENT_ID", raising=False)
    monkeypatch.delenv("AUTH0_CLIENT_SECRET", raising=False)

    app, _ = _build_app(domain=None, client_id=None, client_secret=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Auth0 Management API"
    assert body["endpoints"] == [
        "/api/v2/users",
        "/api/v2/clients",
        "/api/v2/connections",
        "/api/v2/logs",
        "/api/v2/roles",
    ]
    assert body["auth0_domain_present"] is False
    assert body["auth0_client_id_present"] is False
    assert body["auth0_client_secret_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_creds_present_no_token(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["auth0_domain_present"] is True
    assert body["auth0_client_id_present"] is True
    assert body["auth0_client_secret_present"] is True
    assert body["status"] == "empty"  # token not yet fetched
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


def test_users_returns_503_when_creds_missing(monkeypatch):
    monkeypatch.delenv("AUTH0_DOMAIN", raising=False)
    monkeypatch.delenv("AUTH0_CLIENT_ID", raising=False)
    monkeypatch.delenv("AUTH0_CLIENT_SECRET", raising=False)

    app, _ = _build_app(domain=None, client_id=None, client_secret=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/api/v2/users", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "AUTH0" in r.json()["detail"]
    _reset()


def test_clients_returns_503_when_creds_missing(monkeypatch):
    monkeypatch.delenv("AUTH0_DOMAIN", raising=False)
    monkeypatch.delenv("AUTH0_CLIENT_ID", raising=False)
    monkeypatch.delenv("AUTH0_CLIENT_SECRET", raising=False)

    app, _ = _build_app(domain=None, client_id=None, client_secret=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/api/v2/clients", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_logs_returns_503_when_creds_missing(monkeypatch):
    monkeypatch.delenv("AUTH0_DOMAIN", raising=False)
    monkeypatch.delenv("AUTH0_CLIENT_ID", raising=False)
    monkeypatch.delenv("AUTH0_CLIENT_SECRET", raising=False)

    app, _ = _build_app(domain=None, client_id=None, client_secret=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/api/v2/logs", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths via stub httpx.Client
# ---------------------------------------------------------------------------


def test_list_users_happy_path(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    users_payload = [
        {
            "user_id": "auth0|abc123",
            "email": "alice@example.com",
            "email_verified": True,
            "username": "alice",
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "2024-06-01T00:00:00.000Z",
            "identities": [
                {
                    "connection": "Username-Password-Authentication",
                    "user_id": "abc123",
                    "provider": "auth0",
                    "isSocial": False,
                }
            ],
            "app_metadata": {"role": "admin"},
            "user_metadata": {"locale": "en"},
            "logins_count": 42,
            "blocked": False,
        }
    ]
    stub_responses = {
        "/api/v2/users": _StubResponse(200, users_payload),
    }
    app, stub = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/auth0/api/v2/users",
        params={"per_page": 25, "page": 0, "search_engine": "v3"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["length"] == 1
    assert body["users"][0]["user_id"] == "auth0|abc123"
    assert body["users"][0]["email"] == "alice@example.com"

    # Token endpoint hit exactly once + GET to users
    paths = [c.get("url", "") for c in stub.calls]
    assert any("/oauth/token" in p for p in paths)
    assert any("/api/v2/users" in p for p in paths)
    _reset()


def test_get_user_happy_path(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    user_payload = {
        "user_id": "auth0|xyz789",
        "email": "bob@example.com",
        "email_verified": False,
        "name": "Bob Smith",
        "given_name": "Bob",
        "family_name": "Smith",
        "logins_count": 1,
    }
    stub_responses = {
        "/api/v2/users/auth0%7Cxyz789": _StubResponse(200, user_payload),
        # Also handle a path-encoded variant httpx may use:
        "/api/v2/users/auth0|xyz789": _StubResponse(200, user_payload),
    }
    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/api/v2/users/auth0|xyz789", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_id"] == "auth0|xyz789"
    assert body["email"] == "bob@example.com"
    _reset()


def test_get_user_404(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    stub_responses = {
        "/api/v2/users/missing": _StubResponse(404, {"error": "not found"}),
    }
    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/api/v2/users/missing", headers=HEADERS)
    assert r.status_code == 404, r.text
    _reset()


def test_user_roles_happy_path(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    roles_payload = [
        {"id": "rol_1", "name": "admin", "description": "Administrator"},
        {"id": "rol_2", "name": "viewer", "description": "Read-only"},
    ]
    stub_responses = {
        "/roles": _StubResponse(200, roles_payload),
    }
    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/api/v2/users/auth0|abc/roles", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_id"] == "auth0|abc"
    assert len(body["roles"]) == 2
    assert body["roles"][0]["name"] == "admin"
    _reset()


def test_user_permissions_happy_path(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    perms_payload = [
        {
            "permission_name": "read:scans",
            "resource_server_identifier": "https://api.example.com/",
        },
        {
            "permission_name": "write:scans",
            "resource_server_identifier": "https://api.example.com/",
        },
    ]
    stub_responses = {
        "/permissions": _StubResponse(200, perms_payload),
    }
    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/auth0/api/v2/users/auth0|abc/permissions",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_id"] == "auth0|abc"
    assert len(body["permissions"]) == 2
    assert body["permissions"][0]["permission_name"] == "read:scans"
    _reset()


def test_clients_happy_path(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    clients_payload = [
        {
            "client_id": "cli_abc",
            "name": "ALDECI Web SPA",
            "app_type": "spa",
            "is_first_party": True,
            "callbacks": ["https://app.example.com/callback"],
            "allowed_origins": ["https://app.example.com"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
            "oidc_conformant": True,
        }
    ]
    stub_responses = {
        "/api/v2/clients": _StubResponse(200, clients_payload),
    }
    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/auth0/api/v2/clients",
        params={"app_type": "spa", "per_page": 25},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["length"] == 1
    assert body["clients"][0]["client_id"] == "cli_abc"
    assert body["clients"][0]["app_type"] == "spa"
    _reset()


def test_clients_invalid_app_type(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/auth0/api/v2/clients",
        params={"app_type": "bogus_type"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()


def test_connections_happy_path(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    conns_payload = [
        {
            "id": "con_1",
            "name": "Username-Password-Authentication",
            "strategy": "auth0",
        },
        {"id": "con_2", "name": "google-oauth2", "strategy": "google-oauth2"},
    ]
    stub_responses = {
        "/api/v2/connections": _StubResponse(200, conns_payload),
    }
    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/api/v2/connections", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["length"] == 2
    assert body["connections"][0]["strategy"] == "auth0"
    _reset()


def test_logs_happy_path(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    logs_payload = [
        {
            "_id": "log_1",
            "date": "2026-05-04T12:00:00.000Z",
            "type": "s",
            "client_id": "cli_abc",
            "ip": "203.0.113.10",
            "user_id": "auth0|abc",
        }
    ]
    stub_responses = {
        "/api/v2/logs": _StubResponse(200, logs_payload),
    }
    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/auth0/api/v2/logs",
        params={"per_page": 10, "page": 0},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["length"] == 1
    assert body["logs"][0]["_id"] == "log_1"
    _reset()


def test_roles_happy_path(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    roles_payload = [
        {"id": "rol_admin", "name": "admin", "description": "Administrator"},
    ]
    stub_responses = {
        "/api/v2/roles": _StubResponse(200, roles_payload),
    }
    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/api/v2/roles", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["roles"]) == 1
    assert body["roles"][0]["name"] == "admin"
    _reset()


def test_role_permissions_happy_path(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    perms_payload = [
        {
            "permission_name": "read:scans",
            "resource_server_identifier": "https://api.example.com/",
            "resource_server_name": "ALDECI API",
        }
    ]
    stub_responses = {
        "/permissions": _StubResponse(200, perms_payload),
    }
    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/auth0/api/v2/roles/rol_admin/permissions",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["role_id"] == "rol_admin"
    assert body["permissions"][0]["permission_name"] == "read:scans"
    _reset()


# ---------------------------------------------------------------------------
# Token cache + 401 retry semantics
# ---------------------------------------------------------------------------


def test_token_endpoint_failure_returns_503(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    bad_token_response = _StubResponse(403, {"error": "access_denied"})
    app, _ = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses={"/api/v2/users": _StubResponse(200, [])},
        token_response=bad_token_response,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/auth0/api/v2/users", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "token endpoint" in r.json()["detail"].lower() or "403" in r.json()["detail"]
    _reset()


def test_token_cached_across_requests(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "csec")

    stub_responses = {
        "/api/v2/users": _StubResponse(200, []),
        "/api/v2/clients": _StubResponse(200, []),
        "/api/v2/roles": _StubResponse(200, []),
    }
    app, stub = _build_app(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        stub_responses=stub_responses,
    )
    client = TestClient(app, raise_server_exceptions=True)

    assert client.get("/api/v1/auth0/api/v2/users", headers=HEADERS).status_code == 200
    assert client.get("/api/v1/auth0/api/v2/clients", headers=HEADERS).status_code == 200
    assert client.get("/api/v1/auth0/api/v2/roles", headers=HEADERS).status_code == 200

    token_calls = [c for c in stub.calls if "/oauth/token" in c.get("url", "")]
    assert len(token_calls) == 1, f"expected single token fetch, got {len(token_calls)}"
    _reset()
