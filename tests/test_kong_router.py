"""Tests for kong_router — ALDECI.

Spins up a minimal FastAPI app with the Kong Admin router mounted. Each test
gets an isolated httpx stub client and resets the engine singleton so state
doesn't bleed between tests.

NO MOCKS rule:
  * GET / reports ``status="unavailable"`` when KONG_ADMIN_URL is unset.
  * All other endpoints return HTTP 503 when KONG_ADMIN_URL is unset.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real header + parsing code paths.
  * KONG_ADMIN_TOKEN is OPTIONAL — when set it MUST appear as
    ``Kong-Admin-Token`` on the upstream call; when unset that header MUST be
    absent.
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
        # httpx ``content`` is bytes; engine checks ``resp.content`` truthiness
        self.text = text or json.dumps(payload)
        self.content = self.text.encode("utf-8") if self.text else b""

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _resolve(self, url: str) -> _StubResponse:
        # longest-prefix match so /services/foo doesn't shadow /services
        for path in sorted(self._responses.keys(), key=len, reverse=True):
            if path in url:
                return self._responses[path]
        return _StubResponse(404, {"message": "not found"}, text="not found")

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **_: Any,
    ):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "params": dict(params or {}),
                "headers": dict(headers or {}),
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
    url: Optional[str],
    token: Optional[str] = None,
    stub_responses: Optional[Dict[str, Any]] = None,
):
    """Construct an isolated app+engine."""
    from core import kong_admin_engine as engine_mod

    engine_mod.reset_kong_admin_engine()

    stub_client = _StubClient(stub_responses or {})
    engine_mod.get_kong_admin_engine(
        kong_admin_url=url,
        kong_admin_token=token,
        client=stub_client,
    )

    from apps.api.kong_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import kong_admin_engine as engine_mod

    engine_mod.reset_kong_admin_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in ("KONG_ADMIN_URL", "KONG_ADMIN_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    _reset()
    yield
    _reset()


_OK_URL = "http://kong-admin.test:8001"
_OK_TOKEN = "kong-admin-token-value"


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_url():
    app, _ = _build_app(url="", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Kong API Gateway"
    assert body["endpoints"] == [
        "/services",
        "/routes",
        "/plugins",
        "/consumers",
        "/upstreams",
        "/certificates",
        "/sni",
    ]
    assert body["kong_admin_url_present"] is False
    assert body["kong_admin_token_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_url_present_token_optional():
    """KONG_ADMIN_TOKEN is OPTIONAL — URL alone is enough to be 'ok'."""
    app, _ = _build_app(url=_OK_URL, token="", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kong_admin_url_present"] is True
    assert body["kong_admin_token_present"] is False
    assert body["status"] == "ok"


def test_capability_summary_ok_with_token():
    app, _ = _build_app(url=_OK_URL, token=_OK_TOKEN, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/", headers=HEADERS)
    body = r.json()
    assert body["kong_admin_url_present"] is True
    assert body["kong_admin_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when URL missing
# ---------------------------------------------------------------------------


def test_services_503_when_url_missing():
    app, _ = _build_app(url="", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/services", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "kong_admin_unavailable"


def test_routes_503_when_url_missing():
    app, _ = _build_app(url="", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/routes", headers=HEADERS)
    assert r.status_code == 503


def test_plugins_503_when_url_missing():
    app, _ = _build_app(url="", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/plugins", headers=HEADERS)
    assert r.status_code == 503


def test_status_503_when_url_missing():
    app, _ = _build_app(url="", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/status", headers=HEADERS)
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_services_happy_path_normalizes_collection():
    raw = {
        "data": [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "payments",
                "host": "payments.internal",
                "port": 8080,
                "protocol": "http",
                "path": "/v1",
                "retries": 5,
                "connect_timeout": 60000,
                "write_timeout": 60000,
                "read_timeout": 60000,
                "tls_verify": True,
                "tls_verify_depth": None,
                "ca_certificates": [],
                "tags": ["prod", "team-payments"],
                "enabled": True,
                "created_at": 1700000000,
                "updated_at": 1700000010,
            }
        ],
        "next": None,
        "offset": None,
    }
    app, stub = _build_app(
        url=_OK_URL,
        token=_OK_TOKEN,
        stub_responses={"/services": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/kong/services",
        params={"size": 50, "tags": "prod"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body["data"], list)
    assert len(body["data"]) == 1
    assert body["data"][0]["name"] == "payments"
    assert body["data"][0]["protocol"] == "http"
    assert body["next"] is None
    assert body["offset"] is None

    # Verify Kong-Admin-Token header was forwarded
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["method"] == "GET"
    assert call["headers"].get("Kong-Admin-Token") == _OK_TOKEN
    assert call["headers"].get("Accept") == "application/json"
    assert call["params"]["size"] == 50
    assert call["params"]["tags"] == "prod"


def test_services_no_token_omits_header():
    raw = {"data": [], "next": None, "offset": None}
    app, stub = _build_app(
        url=_OK_URL,
        token="",
        stub_responses={"/services": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/services", headers=HEADERS)
    assert r.status_code == 200
    assert len(stub.calls) == 1
    # Token header MUST NOT appear when not configured
    assert "Kong-Admin-Token" not in stub.calls[0]["headers"]


def test_get_service_happy_path():
    raw = {
        "id": "11111111-1111-1111-1111-111111111111",
        "name": "payments",
        "host": "payments.internal",
        "port": 8080,
        "protocol": "https",
        "tls_verify": True,
        "tags": ["prod"],
        "enabled": True,
    }
    app, stub = _build_app(
        url=_OK_URL,
        token=_OK_TOKEN,
        stub_responses={"/services/payments": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/services/payments", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "11111111-1111-1111-1111-111111111111"
    assert body["name"] == "payments"
    assert body["protocol"] == "https"
    assert "/services/payments" in stub.calls[0]["url"]


def test_routes_happy_path_with_service_filter():
    raw = {
        "data": [
            {
                "id": "22222222-2222-2222-2222-222222222222",
                "name": "payments-route",
                "protocols": ["http", "https"],
                "methods": ["GET", "POST"],
                "hosts": ["api.example.com"],
                "paths": ["/payments"],
                "https_redirect_status_code": 426,
                "regex_priority": 0,
                "strip_path": True,
                "path_handling": "v0",
                "preserve_host": False,
                "request_buffering": True,
                "response_buffering": True,
                "tags": ["prod"],
                "service": {"id": "11111111-1111-1111-1111-111111111111"},
                "created_at": 1700000000,
                "updated_at": 1700000005,
            }
        ],
        "next": None,
        "offset": None,
    }
    app, stub = _build_app(
        url=_OK_URL,
        token=_OK_TOKEN,
        stub_responses={"/routes": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/kong/routes",
        params={
            "service.id": "11111111-1111-1111-1111-111111111111",
            "size": 25,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 1
    route = body["data"][0]
    assert route["name"] == "payments-route"
    assert "GET" in route["methods"]
    assert route["service"]["id"] == "11111111-1111-1111-1111-111111111111"

    # ?service.id=... should be forwarded to upstream
    upstream_params = stub.calls[0]["params"]
    assert upstream_params["service.id"] == "11111111-1111-1111-1111-111111111111"
    assert upstream_params["size"] == 25


def test_plugins_happy_path():
    raw = {
        "data": [
            {
                "id": "33333333-3333-3333-3333-333333333333",
                "name": "rate-limiting",
                "instance_name": "global-rl",
                "config": {
                    "minute": 60,
                    "hour": 1000,
                    "policy": "local",
                },
                "protocols": ["http", "https"],
                "enabled": True,
                "tags": ["prod"],
                "service": None,
                "route": None,
                "consumer": None,
                "created_at": 1700000000,
                "updated_at": 1700000010,
            }
        ],
        "next": None,
        "offset": None,
    }
    app, _ = _build_app(
        url=_OK_URL,
        token=_OK_TOKEN,
        stub_responses={"/plugins": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/plugins", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 1
    plugin = body["data"][0]
    assert plugin["name"] == "rate-limiting"
    assert plugin["config"]["minute"] == 60
    assert plugin["enabled"] is True


def test_consumer_key_auth_happy_path():
    raw = {
        "data": [
            {
                "id": "44444444-4444-4444-4444-444444444444",
                "key": "redacted-api-key-value",
                "ttl": None,
                "tags": ["prod"],
                "consumer": {"id": "55555555-5555-5555-5555-555555555555"},
                "created_at": 1700000000,
            }
        ],
        "next": None,
        "offset": None,
    }
    app, stub = _build_app(
        url=_OK_URL,
        token=_OK_TOKEN,
        stub_responses={
            "/consumers/alice/key-auth": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/consumers/alice/key-auth", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 1
    cred = body["data"][0]
    assert cred["consumer"]["id"] == "55555555-5555-5555-5555-555555555555"
    assert "/consumers/alice/key-auth" in stub.calls[0]["url"]


def test_upstreams_and_targets_happy_path():
    upstream_raw = {
        "data": [
            {
                "id": "66666666-6666-6666-6666-666666666666",
                "name": "payments-upstream",
                "algorithm": "round-robin",
                "hash_on": "none",
                "slots": 10000,
                "healthchecks": {
                    "active": {
                        "type": "http",
                        "http_path": "/healthz",
                        "timeout": 1,
                        "concurrency": 10,
                        "healthy": {"interval": 5, "http_statuses": [200, 302]},
                        "unhealthy": {
                            "interval": 5,
                            "http_statuses": [500, 503],
                            "tcp_failures": 2,
                            "http_failures": 5,
                            "timeouts": 3,
                        },
                    },
                    "passive": {
                        "type": "http",
                        "healthy": {
                            "http_statuses": [200, 201, 202, 203, 204],
                            "successes": 0,
                        },
                        "unhealthy": {
                            "http_statuses": [429, 500, 503],
                            "tcp_failures": 0,
                            "timeouts": 0,
                            "http_failures": 0,
                        },
                        "threshold": 0,
                    },
                },
                "tags": ["prod"],
                "use_srv_name": False,
                "created_at": 1700000000,
            }
        ],
        "next": None,
        "offset": None,
    }
    targets_raw = {
        "data": [
            {
                "id": "77777777-7777-7777-7777-777777777777",
                "target": "10.0.0.1:8080",
                "weight": 100,
                "upstream": {"id": "66666666-6666-6666-6666-666666666666"},
                "tags": ["prod"],
                "created_at": 1700000000,
            }
        ],
        "next": None,
        "offset": None,
    }
    app, _ = _build_app(
        url=_OK_URL,
        token=_OK_TOKEN,
        stub_responses={
            "/upstreams/payments-upstream/targets": _StubResponse(200, targets_raw),
            "/upstreams": _StubResponse(200, upstream_raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r1 = client.get("/api/v1/kong/upstreams", headers=HEADERS)
    assert r1.status_code == 200, r1.text
    assert r1.json()["data"][0]["algorithm"] == "round-robin"

    r2 = client.get(
        "/api/v1/kong/upstreams/payments-upstream/targets", headers=HEADERS
    )
    assert r2.status_code == 200, r2.text
    body2 = r2.json()
    assert body2["data"][0]["target"] == "10.0.0.1:8080"
    assert body2["data"][0]["weight"] == 100


def test_status_happy_path():
    raw = {
        "database": {"reachable": True},
        "server": {
            "connections_accepted": 12345,
            "connections_active": 7,
            "connections_handled": 12345,
            "connections_reading": 1,
            "connections_writing": 2,
            "connections_waiting": 4,
            "total_requests": 99999,
        },
        "memory": {
            "workers_lua_vms": [],
            "lua_shared_dicts": {},
        },
    }
    app, _ = _build_app(
        url=_OK_URL,
        token=_OK_TOKEN,
        stub_responses={"/status": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/status", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["database"]["reachable"] is True
    assert body["server"]["total_requests"] == 99999


# ---------------------------------------------------------------------------
# Upstream error mapping
# ---------------------------------------------------------------------------


def test_get_service_404_passes_through():
    app, _ = _build_app(
        url=_OK_URL,
        token=_OK_TOKEN,
        stub_responses={
            "/services/missing": _StubResponse(404, {"message": "Not found"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/services/missing", headers=HEADERS)
    assert r.status_code == 404, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "kong_upstream_error"
    assert detail["upstream_status"] == 404


def test_services_500_collapsed_to_502():
    app, _ = _build_app(
        url=_OK_URL,
        token=_OK_TOKEN,
        stub_responses={
            "/services": _StubResponse(500, {"message": "kong db crash"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/kong/services", headers=HEADERS)
    assert r.status_code == 502, r.text
    detail = r.json()["detail"]
    assert detail["upstream_status"] == 500
