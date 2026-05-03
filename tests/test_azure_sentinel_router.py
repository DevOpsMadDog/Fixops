"""Tests for azure_sentinel_router (Microsoft Sentinel REST proxy).

Covers:
- GET /                         capability summary (unavailable + ok)
- GET /incidents                503 when unconfigured + live-stubbed shape
- GET /alertRules               live-stubbed shape
- GET /bookmarks                live-stubbed shape
- GET /watchlists               live-stubbed shape
- POST /entities/expand         live-stubbed entity graph
- token cached across calls (fetched once)

Usage:
    pytest tests/test_azure_sentinel_router.py -x --tb=short -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite-core and suite-api on path.
for _p in ("suite-core", "suite-api"):
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sentinel_env(monkeypatch):
    """Configure AZURE_* env for the engine."""
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-uuid-aaa")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-uuid-bbb")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-ccc")
    from core.azure_sentinel_engine import reset_azure_sentinel_engine
    reset_azure_sentinel_engine()
    yield
    reset_azure_sentinel_engine()


@pytest.fixture()
def no_sentinel_env(monkeypatch):
    """Ensure env is unset (NO MOCKS — must surface 503)."""
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    from core.azure_sentinel_engine import reset_azure_sentinel_engine
    reset_azure_sentinel_engine()
    yield
    reset_azure_sentinel_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.azure_sentinel_router import router
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


def _make_handler(routes, token_calls):
    """Build a handler that resolves AAD token + Sentinel paths."""

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        path = request.url.path

        # AAD token endpoint.
        if "login.microsoftonline.com" in host and path.endswith("/oauth2/v2.0/token"):
            token_calls.append(path)
            return httpx.Response(
                200,
                json={
                    "token_type": "Bearer",
                    "expires_in": 3599,
                    "access_token": "live-bearer-token",
                },
            )

        # Sentinel resource paths.
        for matcher, response in routes:
            if matcher(request):
                return response

        return httpx.Response(404, json={"error": f"no stub for {request.method} {path}"})

    return handler


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(client, no_sentinel_env):
    resp = client.get("/api/v1/azure-sentinel/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Azure Sentinel"
    assert body["azure_tenant_present"] is False
    assert body["azure_client_present"] is False
    assert body["status"] == "unavailable"
    for ep in ("/incidents", "/alertRules", "/bookmarks", "/watchlists", "/entities"):
        assert ep in body["endpoints"]


def test_capability_summary_ok_when_configured(client, sentinel_env):
    resp = client.get("/api/v1/azure-sentinel/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["azure_tenant_present"] is True
    assert body["azure_client_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 NO MOCKS path
# ---------------------------------------------------------------------------


def test_incidents_503_when_unconfigured(client, no_sentinel_env):
    resp = client.get(
        "/api/v1/azure-sentinel/incidents",
        params={"subscriptionId": "s", "resourceGroupName": "r", "workspaceName": "w"},
    )
    assert resp.status_code == 503
    assert "azure sentinel" in resp.json()["detail"].lower()


def test_alert_rules_503_when_unconfigured(client, no_sentinel_env):
    resp = client.get(
        "/api/v1/azure-sentinel/alertRules",
        params={"subscriptionId": "s", "resourceGroupName": "r", "workspaceName": "w"},
    )
    assert resp.status_code == 503


def test_bookmarks_503_when_unconfigured(client, no_sentinel_env):
    resp = client.get(
        "/api/v1/azure-sentinel/bookmarks",
        params={"subscriptionId": "s", "resourceGroupName": "r", "workspaceName": "w"},
    )
    assert resp.status_code == 503


def test_watchlists_503_when_unconfigured(client, no_sentinel_env):
    resp = client.get(
        "/api/v1/azure-sentinel/watchlists",
        params={"subscriptionId": "s", "resourceGroupName": "r", "workspaceName": "w"},
    )
    assert resp.status_code == 503


def test_expand_entity_503_when_unconfigured(client, no_sentinel_env):
    resp = client.post(
        "/api/v1/azure-sentinel/entities/expand",
        json={
            "entity": {"kind": "Account", "id": "ent-1"},
            "expansionId": "exp-uuid",
            "subscriptionId": "s",
            "resourceGroupName": "r",
            "workspaceName": "w",
        },
    )
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Live (stubbed) lookup paths
# ---------------------------------------------------------------------------


def _sentinel_path(suffix: str) -> str:
    return (
        "/subscriptions/sub-1/resourceGroups/rg-1"
        "/providers/Microsoft.OperationalInsights/workspaces/ws-1"
        "/providers/Microsoft.SecurityInsights"
        f"{suffix}"
    )


def test_list_incidents_live(client, sentinel_env, monkeypatch):
    token_calls: list = []
    incidents_payload = {
        "value": [
            {
                "id": "/sub/.../incidents/inc-1",
                "name": "inc-1",
                "type": "Microsoft.SecurityInsights/incidents",
                "properties": {
                    "title": "Suspicious sign-in",
                    "description": "Multiple failed logins",
                    "severity": "High",
                    "status": "New",
                    "classification": "Undetermined",
                    "owner": {"objectId": "user-1"},
                    "createdTimeUtc": "2026-01-01T00:00:00Z",
                    "lastModifiedTimeUtc": "2026-01-01T00:05:00Z",
                    "incidentNumber": 42,
                },
            }
        ],
        "nextLink": None,
    }

    def _is_incidents(req):
        return req.method == "GET" and req.url.path == _sentinel_path("/incidents")

    handler = _make_handler(
        [(_is_incidents, httpx.Response(200, json=incidents_payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/azure-sentinel/incidents",
        params={
            "subscriptionId": "sub-1",
            "resourceGroupName": "rg-1",
            "workspaceName": "ws-1",
            "$filter": "properties/severity eq 'High'",
            "$top": 25,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"][0]["properties"]["incidentNumber"] == 42
    assert body["value"][0]["properties"]["title"] == "Suspicious sign-in"
    assert len(token_calls) == 1  # token fetched once


def test_list_alert_rules_live(client, sentinel_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "/sub/.../alertRules/rule-1",
                "name": "rule-1",
                "kind": "Scheduled",
                "properties": {
                    "displayName": "Brute force",
                    "description": "Detect brute force",
                    "severity": "Medium",
                    "enabled": True,
                    "query": "SigninLogs | where ResultType != 0",
                    "tactics": ["CredentialAccess"],
                },
            }
        ]
    }

    def _is_rules(req):
        return req.method == "GET" and req.url.path == _sentinel_path("/alertRules")

    handler = _make_handler(
        [(_is_rules, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/azure-sentinel/alertRules",
        params={
            "subscriptionId": "sub-1",
            "resourceGroupName": "rg-1",
            "workspaceName": "ws-1",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"][0]["kind"] == "Scheduled"
    assert body["value"][0]["properties"]["enabled"] is True


def test_list_bookmarks_live(client, sentinel_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "/sub/.../bookmarks/bk-1",
                "name": "bk-1",
                "properties": {
                    "displayName": "Suspicious user",
                    "query": "SigninLogs | take 10",
                    "queryResult": "10 rows",
                    "tags": ["investigate"],
                    "notes": "follow-up",
                },
            }
        ]
    }

    def _is_bookmarks(req):
        return req.method == "GET" and req.url.path == _sentinel_path("/bookmarks")

    handler = _make_handler(
        [(_is_bookmarks, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/azure-sentinel/bookmarks",
        params={
            "subscriptionId": "sub-1",
            "resourceGroupName": "rg-1",
            "workspaceName": "ws-1",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"][0]["properties"]["displayName"] == "Suspicious user"


def test_list_watchlists_live(client, sentinel_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "/sub/.../watchlists/wl-1",
                "name": "wl-1",
                "properties": {
                    "displayName": "Privileged users",
                    "source": "Local file",
                    "itemsSearchKey": "userId",
                    "contentType": "Text/Csv",
                    "numberOfLinesToSkip": 0,
                },
            }
        ]
    }

    def _is_watchlists(req):
        return req.method == "GET" and req.url.path == _sentinel_path("/watchlists")

    handler = _make_handler(
        [(_is_watchlists, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/azure-sentinel/watchlists",
        params={
            "subscriptionId": "sub-1",
            "resourceGroupName": "rg-1",
            "workspaceName": "ws-1",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"][0]["properties"]["itemsSearchKey"] == "userId"


def test_expand_entity_live(client, sentinel_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": {
            "entities": [
                {"kind": "Account", "id": "u-1"},
                {"kind": "Host", "id": "h-1"},
            ],
            "edges": [
                {"source": "u-1", "target": "h-1", "kind": "logged-on"},
            ],
        }
    }

    def _is_expand(req):
        return (
            req.method == "POST"
            and req.url.path == _sentinel_path("/entities/ent-1/expand")
        )

    handler = _make_handler(
        [(_is_expand, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.post(
        "/api/v1/azure-sentinel/entities/expand",
        json={
            "entity": {"kind": "Account", "id": "ent-1"},
            "expansionId": "98b974fd-cc64-48b8-9bd0-3a209f5b944b",
            "subscriptionId": "sub-1",
            "resourceGroupName": "rg-1",
            "workspaceName": "ws-1",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "entities" in body["value"]
    assert "edges" in body["value"]
    assert body["value"]["entities"][0]["kind"] == "Account"


# ---------------------------------------------------------------------------
# Token cache
# ---------------------------------------------------------------------------


def test_token_cached_across_two_calls(client, sentinel_env, monkeypatch):
    token_calls: list = []
    payload = {"value": [], "nextLink": None}

    def _is_incidents(req):
        return req.method == "GET" and req.url.path == _sentinel_path("/incidents")

    handler = _make_handler(
        [(_is_incidents, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    for _ in range(2):
        resp = client.get(
            "/api/v1/azure-sentinel/incidents",
            params={
                "subscriptionId": "sub-1",
                "resourceGroupName": "rg-1",
                "workspaceName": "ws-1",
            },
        )
        assert resp.status_code == 200, resp.text

    # Token should only be fetched once across both calls.
    assert len(token_calls) == 1


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_incidents_validation_requires_query_params(client, sentinel_env):
    resp = client.get("/api/v1/azure-sentinel/incidents")
    assert resp.status_code == 422


def test_expand_entity_validation_rejects_empty_kind(client, sentinel_env):
    resp = client.post(
        "/api/v1/azure-sentinel/entities/expand",
        json={
            "entity": {"kind": "", "id": "ent-1"},
            "expansionId": "exp-uuid",
            "subscriptionId": "s",
            "resourceGroupName": "r",
            "workspaceName": "w",
        },
    )
    assert resp.status_code == 422
