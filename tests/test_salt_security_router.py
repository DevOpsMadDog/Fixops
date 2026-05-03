"""Tests for salt_security_router — ALDECI.

Spins up a minimal FastAPI app with the Salt Security router mounted. Each
test gets an isolated httpx stub client and resets the engine singleton so
state doesn't bleed between tests.

NO MOCKS rule:
  * GET /, GET /api/v1/incidents, GET /api/v1/api-catalog, etc. return HTTP
    503 when SALT creds are unset.
  * Capability summary reports ``status="unavailable"`` when creds are
    missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real OAuth + parsing code paths.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from tests.conftest import API_TOKEN

from fastapi import FastAPI
from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# httpx stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _resolve(self, url: str) -> _StubResponse:
        # Most-specific match first (longest path key)
        for path in sorted(self._responses.keys(), key=len, reverse=True):
            if path in url:
                return self._responses[path]
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "headers": dict(headers or {}),
                "params": dict(params or {}),
            }
        )
        return self._resolve(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(headers or {}),
                "json": json,
                "params": dict(params or {}),
            }
        )
        return self._resolve(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    creds: Optional[Dict[str, str]],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine."""
    from core import salt_security_engine as engine_mod

    engine_mod.reset_salt_security_engine()

    stub_client = _StubClient(stub_responses)
    if creds is None:
        engine_mod.get_salt_security_engine(client=stub_client)
    else:
        engine_mod.get_salt_security_engine(
            api_base=creds.get("api_base"),
            client_id=creds.get("client_id"),
            client_secret=creds.get("client_secret"),
            client=stub_client,
        )

    from apps.api.salt_security_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import salt_security_engine as engine_mod

    engine_mod.reset_salt_security_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in ("SALT_API_BASE", "SALT_CLIENT_ID", "SALT_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    _reset()
    yield
    _reset()


_OK_CREDS = {
    "api_base": "https://api.salt.security",
    "client_id": "salt-client-id",
    "client_secret": "salt-client-secret",
}

# Token response + a Bearer header is required on every GET below, so we
# always include the token endpoint in the stub map.
_TOKEN_OK = _StubResponse(
    200,
    {"access_token": "test-bearer-token", "expires_in": 3600, "token_type": "Bearer"},
)


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/salt-security/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Salt Security"
    assert "/api/v1/incidents" in body["endpoints"]
    assert "/api/v1/api-catalog" in body["endpoints"]
    assert "/api/v1/attackers" in body["endpoints"]
    assert "/api/v1/policies" in body["endpoints"]
    assert "/api/v1/sources" in body["endpoints"]
    assert body["salt_api_base_present"] is False
    assert body["salt_client_id_present"] is False
    assert body["salt_client_secret_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_creds_present():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/salt-security/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["salt_api_base_present"] is True
    assert body["salt_client_id_present"] is True
    assert body["salt_client_secret_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


def test_incidents_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/salt-security/api/v1/incidents", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "SALT" in r.json()["detail"]


def test_api_catalog_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/salt-security/api/v1/api-catalog", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_attackers_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/salt-security/api/v1/attackers", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_policies_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/salt-security/api/v1/policies", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_token_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/salt-security/api/oauth/token",
        json={
            "client_id": "x",
            "client_secret": "y",
            "grant_type": "client_credentials",
        },
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# Validation 422
# ---------------------------------------------------------------------------


def test_incidents_422_on_invalid_limit():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get(
        "/api/v1/salt-security/api/v1/incidents",
        params={"limit": 0},  # FastAPI Query(ge=1) → 422
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_token_422_on_missing_body():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/salt-security/api/oauth/token",
        json={"client_id": ""},  # missing client_secret + empty client_id
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# OAuth happy path
# ---------------------------------------------------------------------------


def test_token_happy_path_returns_access_token():
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/oauth/token": _TOKEN_OK},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/salt-security/api/oauth/token",
        json={
            "client_id": "salt-client-id",
            "client_secret": "salt-client-secret",
            "grant_type": "client_credentials",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"] == "test-bearer-token"
    assert body["expires_in"] == 3600
    assert body["token_type"] == "Bearer"

    # Upstream POST captured + body shape
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["method"] == "POST"
    assert call["url"].endswith("/api/oauth/token")
    assert call["json"]["grant_type"] == "client_credentials"
    assert call["json"]["client_id"] == "salt-client-id"


# ---------------------------------------------------------------------------
# Incidents happy path
# ---------------------------------------------------------------------------


def test_incidents_happy_path_normalizes():
    raw = {
        "data": [
            {
                "id": "inc-001",
                "title": "SQL Injection attempt on /api/v1/users",
                "description": "Detected sqlmap signature",
                "severity": "high",
                "status": "open",
                "attackType": "injection",
                "firstSeen": "2026-05-04T01:00:00Z",
                "lastSeen": "2026-05-04T01:23:45Z",
                "resolvedAt": None,
                "apiId": "api-100",
                "apiName": "user-service",
                "endpoint": "/api/v1/users",
                "attackerIp": "203.0.113.45",
                "attackerUserAgent": "sqlmap/1.7",
                "requestCount": 1234,
                "anomalyScore": 92,
                "evidence": [
                    {
                        "requestId": "req-001",
                        "timestamp": "2026-05-04T01:23:45Z",
                        "payload": "' OR 1=1 --",
                        "indicators": ["sql-keyword", "tautology"],
                    }
                ],
                "recommendation": "Block attacker IP and patch input validation",
                "assignee": "secops@example.com",
                "mitigatedBy": {"type": "wAF", "action": "block-ip"},
            }
        ],
        "totalCount": 1,
        "page": 1,
        "pageSize": 50,
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/oauth/token": _TOKEN_OK,
            "/api/v1/incidents": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/salt-security/api/v1/incidents",
        params={"severity": "high", "status": "open", "limit": 50, "offset": 0},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    assert body["page"] == 1
    assert body["pageSize"] == 50
    assert len(body["data"]) == 1
    inc = body["data"][0]
    assert inc["id"] == "inc-001"
    assert inc["severity"] == "high"
    assert inc["attackType"] == "injection"
    assert inc["evidence"][0]["indicators"] == ["sql-keyword", "tautology"]
    assert inc["mitigatedBy"]["type"] == "wAF"

    # Token fetched + Bearer header used on subsequent GET
    methods = [c["method"] for c in stub.calls]
    assert "POST" in methods  # token fetch
    assert "GET" in methods
    get_call = next(c for c in stub.calls if c["method"] == "GET")
    assert get_call["headers"].get("Authorization") == "Bearer test-bearer-token"


def test_incidents_filter_params_forwarded():
    raw = {"data": [], "totalCount": 0}
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/oauth/token": _TOKEN_OK,
            "/api/v1/incidents": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/salt-security/api/v1/incidents",
        params={
            "severity": "medium",
            "status": "investigating",
            "limit": 25,
            "offset": 100,
            "fromDate": "2026-05-01T00:00:00Z",
            "toDate": "2026-05-04T23:59:59Z",
            "apiId": "api-100",
            "attackerId": "atk-9",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    get_call = next(c for c in stub.calls if c["method"] == "GET")
    p = get_call["params"]
    assert p.get("severity") == "medium"
    assert p.get("status") == "investigating"
    assert int(p.get("limit")) == 25
    assert int(p.get("offset")) == 100
    assert p.get("fromDate") == "2026-05-01T00:00:00Z"
    assert p.get("apiId") == "api-100"
    assert p.get("attackerId") == "atk-9"


# ---------------------------------------------------------------------------
# API catalog happy path
# ---------------------------------------------------------------------------


def test_api_catalog_happy_path_normalizes():
    raw = {
        "data": [
            {
                "id": "api-100",
                "name": "user-service",
                "baseUrl": "https://api.example.com",
                "environment": "production",
                "classification": "external",
                "type": "REST",
                "totalEndpoints": 47,
                "riskScore": 78,
                "hasSensitiveData": True,
                "sensitiveDataTypes": ["PII", "PCI"],
                "totalRequests30d": 1234567,
                "totalIncidents": {"open": 3, "resolved": 21},
                "firstDiscovered": "2025-12-01T00:00:00Z",
                "lastSeen": "2026-05-04T01:00:00Z",
                "owners": [{"name": "Alice", "email": "alice@example.com"}],
            }
        ],
        "totalCount": 1,
        "page": 1,
        "pageSize": 50,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/oauth/token": _TOKEN_OK,
            "/api/v1/api-catalog": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/salt-security/api/v1/api-catalog",
        params={"limit": 50, "page": 1, "hasSensitiveData": "true"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    assert len(body["data"]) == 1
    api = body["data"][0]
    assert api["id"] == "api-100"
    assert api["riskScore"] == 78
    assert api["hasSensitiveData"] is True
    assert "PII" in api["sensitiveDataTypes"]
    assert api["totalIncidents"]["open"] == 3
    assert api["owners"][0]["email"] == "alice@example.com"


def test_api_catalog_single_entry_happy_path():
    raw = {
        "id": "api-100",
        "name": "user-service",
        "baseUrl": "https://api.example.com",
        "environment": "production",
        "classification": "external",
        "type": "REST",
        "totalEndpoints": 47,
        "riskScore": 78,
        "hasSensitiveData": True,
        "sensitiveDataTypes": ["PII"],
        "totalRequests30d": 0,
        "totalIncidents": {"open": 0, "resolved": 0},
        "firstDiscovered": "2025-12-01T00:00:00Z",
        "lastSeen": "2026-05-04T01:00:00Z",
        "owners": [],
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/oauth/token": _TOKEN_OK,
            "/api/v1/api-catalog/api-100": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/salt-security/api/v1/api-catalog/api-100", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "api-100"
    assert body["name"] == "user-service"
    assert body["riskScore"] == 78


def test_api_catalog_endpoints_happy_path():
    raw = {
        "data": [
            {
                "id": "ep-1",
                "apiId": "api-100",
                "method": "POST",
                "path": "/api/v1/users",
                "fullUrl": "https://api.example.com/api/v1/users",
                "authenticated": True,
                "hasSensitiveData": True,
                "sensitiveDataTypes": ["PII", "PCI"],
                "riskScore": 88,
                "totalRequests30d": 50000,
                "totalIncidents": 2,
                "firstSeen": "2025-12-01T00:00:00Z",
                "lastSeen": "2026-05-04T01:00:00Z",
            }
        ],
        "totalCount": 1,
        "page": 1,
        "pageSize": 50,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/oauth/token": _TOKEN_OK,
            "/api/v1/api-catalog/api-100/endpoints": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/salt-security/api/v1/api-catalog/api-100/endpoints",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    ep = body["data"][0]
    assert ep["method"] == "POST"
    assert ep["sensitiveDataTypes"] == ["PII", "PCI"]
    assert ep["riskScore"] == 88


# ---------------------------------------------------------------------------
# Attackers happy path
# ---------------------------------------------------------------------------


def test_attackers_happy_path_normalizes():
    raw = {
        "data": [
            {
                "id": "atk-9",
                "ipAddress": "203.0.113.45",
                "country": "RU",
                "asn": "AS12345",
                "isp": "Bad Hosting Inc",
                "status": "blocked",
                "riskScore": 95,
                "firstSeen": "2026-04-01T00:00:00Z",
                "lastSeen": "2026-05-04T01:23:45Z",
                "totalRequests": 12345,
                "totalIncidents": 7,
                "attackTypes": ["injection", "account-takeover"],
                "userAgents": ["sqlmap/1.7", "curl/8.0"],
                "geolocation": {"lat": 55.7558, "lng": 37.6173},
                "blockedAt": "2026-05-04T01:24:00Z",
                "blockReason": "Repeated injection attempts",
            }
        ],
        "pagination": {"nextPageToken": "tok-next-1"},
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/oauth/token": _TOKEN_OK,
            "/api/v1/attackers": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/salt-security/api/v1/attackers",
        params={"status": "blocked", "riskScoreGte": 80, "pageSize": 50},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pagination"]["nextPageToken"] == "tok-next-1"
    assert len(body["data"]) == 1
    atk = body["data"][0]
    assert atk["id"] == "atk-9"
    assert atk["status"] == "blocked"
    assert atk["riskScore"] == 95
    assert atk["geolocation"]["lat"] == 55.7558
    assert "injection" in atk["attackTypes"]


# ---------------------------------------------------------------------------
# Policies happy path
# ---------------------------------------------------------------------------


def test_policies_happy_path_normalizes():
    raw = {
        "data": [
            {
                "id": "pol-1",
                "name": "Block known sqlmap UA",
                "description": "Detection rule for sqlmap user-agent",
                "type": "detection",
                "enabled": True,
                "severity": "high",
                "action": "alert",
                "ruleCount": 3,
                "createdAt": "2025-11-01T00:00:00Z",
                "updatedAt": "2026-04-01T00:00:00Z",
            },
            {
                "id": "pol-2",
                "name": "Block IP after 100 4xx in 5min",
                "description": "Protection rule",
                "type": "protection",
                "enabled": True,
                "severity": "medium",
                "action": "block",
                "ruleCount": 1,
                "createdAt": "2025-11-01T00:00:00Z",
                "updatedAt": "2026-04-01T00:00:00Z",
            },
        ],
        "totalCount": 2,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/oauth/token": _TOKEN_OK,
            "/api/v1/policies": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/salt-security/api/v1/policies",
        params={"enabled": "true"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 2
    assert body["data"][0]["type"] == "detection"
    assert body["data"][1]["type"] == "protection"
    assert all(p["enabled"] is True for p in body["data"])


# ---------------------------------------------------------------------------
# Token caching — only one token POST across multiple GETs
# ---------------------------------------------------------------------------


def test_token_is_cached_across_multiple_calls():
    catalog_raw = {"data": [], "totalCount": 0}
    incidents_raw = {"data": [], "totalCount": 0}
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/oauth/token": _TOKEN_OK,
            "/api/v1/api-catalog": _StubResponse(200, catalog_raw),
            "/api/v1/incidents": _StubResponse(200, incidents_raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r1 = client.get(
        "/api/v1/salt-security/api/v1/api-catalog", headers=HEADERS
    )
    r2 = client.get(
        "/api/v1/salt-security/api/v1/incidents", headers=HEADERS
    )
    assert r1.status_code == 200, r1.text
    assert r2.status_code == 200, r2.text

    token_calls = [
        c for c in stub.calls if c["method"] == "POST" and "/oauth/token" in c["url"]
    ]
    # Exactly one token fetch despite two upstream GETs
    assert len(token_calls) == 1, [c["url"] for c in stub.calls]
