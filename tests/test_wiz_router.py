"""Tests for wiz_router (Wiz CNAPP/CSPM REST proxy).

Covers:
- GET /                              capability summary (unavailable + ok)
- POST /graphql                      passthrough w/ data + errors
- GET  /issues                       list issues w/ filters
- GET  /inventory                    list inventory w/ filters
- GET  /vulnerabilities              list vulnerabilities
- GET  /threats                      list threat-detection signals
- 503 on lookup endpoints when env unset (NO MOCKS rule)
- OAuth2 client_credentials token flow + 30-min in-memory cache

Usage:
    pytest tests/test_wiz_router.py -x --tb=short -q
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict

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
def wiz_env(monkeypatch):
    """Configure WIZ_CLIENT_ID + WIZ_CLIENT_SECRET + WIZ_API_URL."""
    monkeypatch.setenv("WIZ_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("WIZ_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("WIZ_API_URL", "https://api.us17.app.wiz.io/graphql")
    from core.wiz_cnapp_engine import reset_wiz_cnapp_engine
    reset_wiz_cnapp_engine()
    yield
    reset_wiz_cnapp_engine()


@pytest.fixture()
def no_wiz_env(monkeypatch):
    """Ensure env unset (NO MOCKS — must surface 503)."""
    for var in ("WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET", "WIZ_API_URL"):
        monkeypatch.delenv(var, raising=False)
    from core.wiz_cnapp_engine import reset_wiz_cnapp_engine
    reset_wiz_cnapp_engine()
    yield
    reset_wiz_cnapp_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.wiz_router import router
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


def _make_wiz_handler(graphql_response: Dict[str, Any], call_log=None):
    """Build a handler that mints OAuth tokens + serves GraphQL payloads."""

    def handler(request: httpx.Request) -> httpx.Response:
        if call_log is not None:
            call_log.append((request.method, str(request.url)))
        if "auth.app.wiz.io/oauth/token" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "access_token": "fake-bearer-token",
                    "token_type": "Bearer",
                    "expires_in": 86400,
                },
            )
        # GraphQL endpoint
        return httpx.Response(200, json=graphql_response)

    return handler


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(client, no_wiz_env):
    resp = client.get("/api/v1/wiz/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Wiz CNAPP"
    assert body["wiz_client_id_present"] is False
    assert body["wiz_client_secret_present"] is False
    assert body["wiz_api_url_present"] is False
    assert body["status"] == "unavailable"
    for ep in ("/graphql", "/issues", "/inventory", "/vulnerabilities", "/threats"):
        assert ep in body["endpoints"]


def test_capability_summary_ok_when_configured(client, wiz_env):
    resp = client.get("/api/v1/wiz/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["wiz_client_id_present"] is True
    assert body["wiz_client_secret_present"] is True
    assert body["wiz_api_url_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 NO MOCKS path
# ---------------------------------------------------------------------------


def test_graphql_503_when_unconfigured(client, no_wiz_env):
    resp = client.post("/api/v1/wiz/graphql", json={"query": "query {}"})
    assert resp.status_code == 503
    assert "wiz" in resp.json()["detail"].lower()


def test_issues_503_when_unconfigured(client, no_wiz_env):
    resp = client.get("/api/v1/wiz/issues")
    assert resp.status_code == 503


def test_inventory_503_when_unconfigured(client, no_wiz_env):
    resp = client.get("/api/v1/wiz/inventory")
    assert resp.status_code == 503


def test_vulnerabilities_503_when_unconfigured(client, no_wiz_env):
    resp = client.get("/api/v1/wiz/vulnerabilities")
    assert resp.status_code == 503


def test_threats_503_when_unconfigured(client, no_wiz_env):
    resp = client.get("/api/v1/wiz/threats")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# GraphQL passthrough
# ---------------------------------------------------------------------------


def test_graphql_passthrough_returns_data(client, wiz_env, monkeypatch):
    handler = _make_wiz_handler({"data": {"viewer": {"id": "u-1"}}})
    _install_httpx_stub(monkeypatch, handler)

    resp = client.post(
        "/api/v1/wiz/graphql",
        json={"query": "query { viewer { id } }"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"] == {"viewer": {"id": "u-1"}}
    assert "errors" not in body


def test_graphql_passthrough_surfaces_errors(client, wiz_env, monkeypatch):
    handler = _make_wiz_handler(
        {"data": None, "errors": [{"message": "field unknown"}]},
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.post(
        "/api/v1/wiz/graphql",
        json={"query": "query { bogus }"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"] == {}
    assert body["errors"][0]["message"] == "field unknown"


# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------


def test_issues_returns_nodes_and_pageinfo(client, wiz_env, monkeypatch):
    handler = _make_wiz_handler(
        {
            "data": {
                "issues": {
                    "nodes": [
                        {
                            "id": "iss-1",
                            "status": "OPEN",
                            "severity": "CRITICAL",
                            "type": "TOXIC_COMBINATION",
                            "sourceRule": {"name": "Public RDS w/ broad sg"},
                        }
                    ],
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-xyz"},
                }
            }
        },
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/wiz/issues",
        params={"status": "OPEN", "severity": "CRITICAL,HIGH", "first": 25},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["issues"]) == 1
    assert body["issues"][0]["id"] == "iss-1"
    assert body["pageInfo"]["hasNextPage"] is True
    assert body["pageInfo"]["endCursor"] == "cursor-xyz"


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def test_inventory_returns_nodes(client, wiz_env, monkeypatch):
    handler = _make_wiz_handler(
        {
            "data": {
                "cloudResources": {
                    "nodes": [
                        {
                            "id": "res-1",
                            "name": "prod-bastion",
                            "type": "VIRTUAL_MACHINE",
                            "region": "us-east-1",
                            "providerUniqueId": "i-0abc",
                            "project": {"id": "p-1", "name": "prod"},
                        }
                    ],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        },
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/wiz/inventory",
        params={"type": "VIRTUAL_MACHINE,CONTAINER_IMAGE", "first": 10},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["nodes"][0]["type"] == "VIRTUAL_MACHINE"
    assert body["pageInfo"]["hasNextPage"] is False


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


def test_vulnerabilities_returns_findings(client, wiz_env, monkeypatch):
    handler = _make_wiz_handler(
        {
            "data": {
                "vulnerabilityFindings": {
                    "nodes": [
                        {
                            "id": "v-1",
                            "name": "CVE-2024-12345",
                            "vendorSeverity": "CRITICAL",
                            "score": 9.8,
                            "cvss31": {"score": 9.8, "vector": "AV:N/AC:L/PR:N"},
                            "fixedVersion": "1.2.4",
                        }
                    ],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        },
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/wiz/vulnerabilities", params={"severity": "CRITICAL"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["nodes"][0]["name"] == "CVE-2024-12345"
    assert body["nodes"][0]["score"] == 9.8


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------


def test_threats_returns_signals(client, wiz_env, monkeypatch):
    handler = _make_wiz_handler(
        {
            "data": {
                "threatDetections": {
                    "nodes": [
                        {
                            "id": "t-1",
                            "name": "Suspicious IAM AssumeRole",
                            "severity": "HIGH",
                            "ruleName": "iam.privilege_escalation",
                        }
                    ],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        },
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/wiz/threats", params={"first": 5})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["nodes"][0]["id"] == "t-1"


# ---------------------------------------------------------------------------
# OAuth2 token caching
# ---------------------------------------------------------------------------


def test_oauth_token_is_cached_across_requests(client, wiz_env, monkeypatch):
    call_log: list = []
    handler = _make_wiz_handler({"data": {"ping": "pong"}}, call_log=call_log)
    _install_httpx_stub(monkeypatch, handler)

    # Two GraphQL calls in quick succession
    resp1 = client.post("/api/v1/wiz/graphql", json={"query": "query { ping }"})
    resp2 = client.post("/api/v1/wiz/graphql", json={"query": "query { ping }"})
    assert resp1.status_code == 200
    assert resp2.status_code == 200

    # Exactly ONE OAuth round-trip should have happened
    oauth_calls = [c for c in call_log if "auth.app.wiz.io/oauth/token" in c[1]]
    assert len(oauth_calls) == 1, f"expected 1 OAuth call, got {len(oauth_calls)}: {oauth_calls}"
    # And TWO GraphQL calls
    gql_calls = [c for c in call_log if "api.us17.app.wiz.io/graphql" in c[1]]
    assert len(gql_calls) == 2, f"expected 2 GraphQL calls, got {len(gql_calls)}: {gql_calls}"


def test_oauth_token_refreshes_after_ttl(client, wiz_env, monkeypatch):
    call_log: list = []
    handler = _make_wiz_handler({"data": {"ping": "pong"}}, call_log=call_log)
    _install_httpx_stub(monkeypatch, handler)

    resp1 = client.post("/api/v1/wiz/graphql", json={"query": "query { ping }"})
    assert resp1.status_code == 200

    # Force token expiry on the singleton
    from core.wiz_cnapp_engine import get_wiz_cnapp_engine
    eng = get_wiz_cnapp_engine()
    eng._token_expires_at = time.time() - 1.0

    resp2 = client.post("/api/v1/wiz/graphql", json={"query": "query { ping }"})
    assert resp2.status_code == 200

    oauth_calls = [c for c in call_log if "auth.app.wiz.io/oauth/token" in c[1]]
    assert len(oauth_calls) == 2, f"expected 2 OAuth calls (refresh), got {len(oauth_calls)}"
