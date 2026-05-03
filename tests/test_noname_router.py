"""Tests for noname_router (Noname Security REST proxy).

Covers:
- GET / capability summary (unavailable + ok)
- 503 on every lookup endpoint when env unset (NO MOCKS)
- /api/v3/apis returns paginated data
- /api/v3/apis/{id} returns single API
- /api/v3/apis/{id}/endpoints returns per-API endpoints
- /api/v3/issues with severity/status/type/apiId filters
- /api/v3/inventory/endpoints
- /api/v3/sources w/ type filter
- /api/v3/posture-policies
- OAuth2 client_credentials w/ ~50 min in-memory token cache

Usage:
    pytest tests/test_noname_router.py -x --tb=short -q
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite-core and suite-api on path
for _p in ("suite-core", "suite-api"):
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def noname_env(monkeypatch):
    """Configure NONAME_BASE_URL + NONAME_CLIENT_ID + NONAME_CLIENT_SECRET."""
    monkeypatch.setenv("NONAME_BASE_URL", "https://tenant.nonamesecurity.com")
    monkeypatch.setenv("NONAME_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("NONAME_CLIENT_SECRET", "test-client-secret")
    from core.noname_engine import reset_noname_engine
    reset_noname_engine()
    yield
    reset_noname_engine()


@pytest.fixture()
def no_noname_env(monkeypatch):
    """Ensure env unset (NO MOCKS — must surface 503)."""
    for var in ("NONAME_BASE_URL", "NONAME_CLIENT_ID", "NONAME_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    from core.noname_engine import reset_noname_engine
    reset_noname_engine()
    yield
    reset_noname_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.noname_router import router
    a = FastAPI()
    a.include_router(router)
    return a


@pytest.fixture()
def client(app) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# httpx stub helpers
# ---------------------------------------------------------------------------


def _install_httpx_stub(monkeypatch, handler):
    """Replace httpx.Client with a transport-mocked instance."""
    import httpx as _httpx

    real_client_init = _httpx.Client.__init__

    def _patched_init(self, *args, **kwargs):
        kwargs.pop("verify", None)
        kwargs["transport"] = _httpx.MockTransport(handler)
        real_client_init(self, *args, **kwargs)

    monkeypatch.setattr(_httpx.Client, "__init__", _patched_init)


def _make_noname_handler(
    routes: Dict[str, Any],
    call_log: Optional[List] = None,
):
    """Build a handler that mints OAuth tokens + serves keyed REST payloads.

    ``routes`` maps a path-substring → response JSON (dict or list).
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if call_log is not None:
            call_log.append((request.method, str(request.url)))
        url = str(request.url)
        if "/oauth/token" in url:
            return httpx.Response(
                200,
                json={
                    "access_token": "fake-bearer-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        for needle, payload in routes.items():
            if needle in url:
                return httpx.Response(200, json=payload)
        return httpx.Response(404, json={"error": "not found", "url": url})

    return handler


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(client, no_noname_env):
    resp = client.get("/api/v1/noname/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Noname Security"
    assert body["noname_base_url_present"] is False
    assert body["noname_client_id_present"] is False
    assert body["noname_client_secret_present"] is False
    assert body["status"] == "unavailable"
    for ep in (
        "/api/v3/apis",
        "/api/v3/issues",
        "/api/v3/inventory/endpoints",
        "/api/v3/sources",
        "/api/v3/posture-policies",
    ):
        assert ep in body["endpoints"]


def test_capability_summary_ok_when_configured(client, noname_env):
    resp = client.get("/api/v1/noname/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["noname_base_url_present"] is True
    assert body["noname_client_id_present"] is True
    assert body["noname_client_secret_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 NO MOCKS path
# ---------------------------------------------------------------------------


def test_apis_503_when_unconfigured(client, no_noname_env):
    resp = client.get("/api/v1/noname/api/v3/apis")
    assert resp.status_code == 503
    assert "noname" in resp.json()["detail"].lower()


def test_issues_503_when_unconfigured(client, no_noname_env):
    resp = client.get("/api/v1/noname/api/v3/issues")
    assert resp.status_code == 503


def test_inventory_endpoints_503_when_unconfigured(client, no_noname_env):
    resp = client.get("/api/v1/noname/api/v3/inventory/endpoints")
    assert resp.status_code == 503


def test_sources_503_when_unconfigured(client, no_noname_env):
    resp = client.get("/api/v1/noname/api/v3/sources")
    assert resp.status_code == 503


def test_posture_policies_503_when_unconfigured(client, no_noname_env):
    resp = client.get("/api/v1/noname/api/v3/posture-policies")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# /api/v3/apis
# ---------------------------------------------------------------------------


def test_list_apis_returns_data_and_pagination(client, noname_env, monkeypatch):
    payload = {
        "data": [
            {
                "id": "api-1",
                "name": "checkout-svc",
                "baseUrl": "https://api.example.com/v1/checkout",
                "type": "REST",
                "environment": "production",
                "classification": "external",
                "riskScore": 87.5,
                "lastSeen": "2026-05-04T12:00:00Z",
                "firstSeen": "2025-11-01T08:14:00Z",
                "totalRequests": 1234567,
                "uniqueClients": 412,
                "sensitiveDataDetected": True,
                "source": {
                    "id": "src-1",
                    "name": "edge-gateway",
                    "type": "GATEWAY",
                },
                "owners": ["payments-team"],
            }
        ],
        "pagination": {
            "page": 1,
            "limit": 25,
            "totalCount": 47,
            "totalPages": 2,
        },
    }
    handler = _make_noname_handler({"/api/v3/apis": payload})
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/noname/api/v3/apis",
        params={"limit": 25, "page": 1, "filter": "environment == 'production'"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["id"] == "api-1"
    assert body["data"][0]["type"] == "REST"
    assert body["data"][0]["source"]["type"] == "GATEWAY"
    assert body["pagination"]["totalPages"] == 2


def test_get_api_returns_single(client, noname_env, monkeypatch):
    payload = {
        "id": "api-77",
        "name": "billing-svc",
        "baseUrl": "https://api.example.com/v1/billing",
        "type": "GraphQL",
        "environment": "staging",
        "classification": "internal",
        "riskScore": 42.1,
        "endpoints": [
            {"path": "/charges", "method": "POST"},
        ],
        "classifications": ["pci"],
    }
    handler = _make_noname_handler({"/api/v3/apis/api-77": payload})
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/noname/api/v3/apis/api-77")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == "api-77"
    assert body["type"] == "GraphQL"
    assert body["endpoints"][0]["method"] == "POST"


def test_list_api_endpoints(client, noname_env, monkeypatch):
    payload = {
        "data": [
            {
                "id": "ep-1",
                "path": "/v1/checkout",
                "method": "POST",
                "host": "api.example.com",
                "apiId": "api-1",
                "apiName": "checkout-svc",
                "environment": "production",
                "classification": "external",
                "parameters": [
                    {"name": "amount", "in": "body", "type": "number", "required": True}
                ],
                "responses": [{"statusCode": 200, "schema": {"type": "object"}}],
                "firstSeen": "2025-11-01T08:14:00Z",
                "lastSeen": "2026-05-04T12:00:00Z",
                "requestCount": 8211,
            }
        ],
        "pagination": {"page": 1, "limit": 50, "totalCount": 1, "totalPages": 1},
    }
    handler = _make_noname_handler({"/api/v3/apis/api-1/endpoints": payload})
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/noname/api/v3/apis/api-1/endpoints",
        params={"limit": 50, "page": 1},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["method"] == "POST"
    assert body["data"][0]["path"] == "/v1/checkout"


def test_get_api_invalid_id_returns_400(client, noname_env, monkeypatch):
    handler = _make_noname_handler({})
    _install_httpx_stub(monkeypatch, handler)
    resp = client.get("/api/v1/noname/api/v3/apis/" + ("x" * 300))
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/v3/issues
# ---------------------------------------------------------------------------


def test_list_issues_with_filters(client, noname_env, monkeypatch):
    payload = {
        "data": [
            {
                "id": "iss-1",
                "title": "Broken object-level authorization on /v1/orders/{id}",
                "description": "BOLA: attacker can read other tenants' orders",
                "severity": "critical",
                "status": "open",
                "type": "authorization",
                "owaspCategory": "API1:2023",
                "cweId": "CWE-639",
                "cweName": "Authorization Bypass Through User-Controlled Key",
                "firstDetectedAt": "2026-04-30T08:00:00Z",
                "lastDetectedAt": "2026-05-04T11:00:00Z",
                "resolvedAt": None,
                "apiId": "api-1",
                "apiName": "checkout-svc",
                "endpoint": "/v1/orders/{id}",
                "evidence": {"sample_request": "GET /v1/orders/42"},
                "recommendation": "Enforce tenant scoping in authz middleware",
                "assignee": "alice@example.com",
                "comments": [],
            }
        ],
        "pagination": {"page": 1, "limit": 50, "totalCount": 1, "totalPages": 1},
    }
    log: List = []
    handler = _make_noname_handler({"/api/v3/issues": payload}, call_log=log)
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/noname/api/v3/issues",
        params={
            "severity": "critical",
            "status": "open",
            "type": "authorization",
            "apiId": "api-1",
            "limit": 50,
            "page": 1,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["severity"] == "critical"
    assert body["data"][0]["owaspCategory"] == "API1:2023"
    # Confirm filters reached upstream
    issues_calls = [u for _m, u in log if "/api/v3/issues" in u]
    assert any("severity=critical" in u for u in issues_calls)
    assert any("status=open" in u for u in issues_calls)
    assert any("type=authorization" in u for u in issues_calls)
    assert any("apiId=api-1" in u for u in issues_calls)


# ---------------------------------------------------------------------------
# /api/v3/inventory/endpoints
# ---------------------------------------------------------------------------


def test_inventory_endpoints_returns_data(client, noname_env, monkeypatch):
    payload = {
        "data": [
            {
                "id": "ep-99",
                "path": "/v1/users",
                "method": "GET",
                "host": "api.example.com",
                "apiId": "api-2",
                "apiName": "users-svc",
                "environment": "production",
                "classification": "internal",
                "parameters": [
                    {"name": "page", "in": "query", "type": "integer", "required": False}
                ],
                "responses": [{"statusCode": 200, "schema": {"type": "array"}}],
                "firstSeen": "2026-01-01T00:00:00Z",
                "lastSeen": "2026-05-04T12:00:00Z",
                "requestCount": 4011,
            }
        ],
        "pagination": {"page": 1, "limit": 50, "totalCount": 1, "totalPages": 1},
    }
    handler = _make_noname_handler({"/api/v3/inventory/endpoints": payload})
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/noname/api/v3/inventory/endpoints",
        params={"limit": 50, "page": 1, "filter": "environment == 'production'"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["method"] == "GET"
    assert body["data"][0]["parameters"][0]["in"] == "query"


# ---------------------------------------------------------------------------
# /api/v3/sources
# ---------------------------------------------------------------------------


def test_list_sources_with_type(client, noname_env, monkeypatch):
    payload = {
        "data": [
            {
                "id": "src-1",
                "name": "aws-alb-prod",
                "type": "GATEWAY",
                "vendor": "AWS",
                "status": "active",
                "lastSeen": "2026-05-04T12:00:00Z",
                "configuredAt": "2025-09-01T00:00:00Z",
                "eventsCount": 9182334,
            }
        ]
    }
    log: List = []
    handler = _make_noname_handler({"/api/v3/sources": payload}, call_log=log)
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/noname/api/v3/sources", params={"type": "GATEWAY"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["vendor"] == "AWS"
    assert body["data"][0]["type"] == "GATEWAY"
    src_calls = [u for _m, u in log if "/api/v3/sources" in u]
    assert any("type=GATEWAY" in u for u in src_calls)


# ---------------------------------------------------------------------------
# /api/v3/posture-policies
# ---------------------------------------------------------------------------


def test_list_posture_policies(client, noname_env, monkeypatch):
    payload = {
        "data": [
            {
                "id": "pp-1",
                "name": "Block PII in production endpoints",
                "description": "Fail any external prod API exposing PII",
                "enabled": True,
                "severity": "high",
                "scope": {
                    "environments": ["production"],
                    "classifications": ["external"],
                },
                "conditions": {"sensitiveDataDetected": True},
            }
        ]
    }
    handler = _make_noname_handler({"/api/v3/posture-policies": payload})
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/noname/api/v3/posture-policies")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["enabled"] is True
    assert body["data"][0]["scope"]["environments"] == ["production"]


# ---------------------------------------------------------------------------
# OAuth2 token caching
# ---------------------------------------------------------------------------


def test_oauth_token_is_cached_across_requests(client, noname_env, monkeypatch):
    log: List = []
    payload_apis = {
        "data": [],
        "pagination": {"page": 1, "limit": 50, "totalCount": 0, "totalPages": 0},
    }
    handler = _make_noname_handler({"/api/v3/apis": payload_apis}, call_log=log)
    _install_httpx_stub(monkeypatch, handler)

    r1 = client.get("/api/v1/noname/api/v3/apis")
    r2 = client.get("/api/v1/noname/api/v3/apis")
    assert r1.status_code == 200
    assert r2.status_code == 200

    oauth_calls = [c for c in log if "/oauth/token" in c[1]]
    assert len(oauth_calls) == 1, f"expected 1 OAuth call, got {len(oauth_calls)}: {oauth_calls}"

    apis_calls = [c for c in log if "/api/v3/apis" in c[1]]
    assert len(apis_calls) == 2, f"expected 2 API calls, got {len(apis_calls)}: {apis_calls}"


def test_oauth_token_refreshes_after_ttl(client, noname_env, monkeypatch):
    log: List = []
    payload = {
        "data": [],
        "pagination": {"page": 1, "limit": 50, "totalCount": 0, "totalPages": 0},
    }
    handler = _make_noname_handler({"/api/v3/apis": payload}, call_log=log)
    _install_httpx_stub(monkeypatch, handler)

    r1 = client.get("/api/v1/noname/api/v3/apis")
    assert r1.status_code == 200

    # Force token expiry on the singleton
    from core.noname_engine import get_noname_engine
    eng = get_noname_engine()
    eng._token_expires_at = time.time() - 1.0

    r2 = client.get("/api/v1/noname/api/v3/apis")
    assert r2.status_code == 200

    oauth_calls = [c for c in log if "/oauth/token" in c[1]]
    assert len(oauth_calls) == 2, f"expected 2 OAuth calls (refresh), got {len(oauth_calls)}"
