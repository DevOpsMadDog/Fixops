"""Tests for mongodb_atlas_router — MongoDB Atlas Admin API connector — ALDECI.

Spins up a minimal FastAPI app with the MongoDB Atlas router mounted. Each
test gets an isolated environment and a stub httpx.AsyncClient so we exercise
the real Digest-auth injection + parsing code paths without hitting the network.

NO MOCKS rule:
  * When MONGODB_ATLAS_PUBLIC_KEY / MONGODB_ATLAS_PRIVATE_KEY are unset every
    live endpoint returns HTTP 503 with ``{"error":"mongodb_atlas_not_configured",...}``.
  * Happy-path tests stub the httpx.AsyncClient context manager; real router
    code runs (auth setup, path building, response parsing).
  * GET / (connector info) returns 200 even when unconfigured.
"""
from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}

# Stub Atlas credentials used in happy-path tests
_STUB_PUB = "atlaspubkey123"
_STUB_PRIV = "atlasprivkey456"
_STUB_ORG_ID = "5e2211c17a3e5a48f5497de3"
_STUB_GROUP_ID = "5e2211c17a3e5a48f5497de4"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    """Return a FastAPI app with the MongoDB Atlas router mounted."""
    from apps.api.mongodb_atlas_router import router
    app = FastAPI()
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Async httpx stub client factory
# ---------------------------------------------------------------------------


def _make_async_client(responses: Dict[str, Any]) -> MagicMock:
    """Build a MagicMock httpx.AsyncClient that returns pre-canned responses."""
    import httpx
    mock_client = MagicMock(spec=httpx.AsyncClient)

    async def _mock_get(url: str, *, headers=None, params=None):
        for suffix, payload in responses.items():
            if suffix in url:
                resp = MagicMock()
                resp.status_code = 200
                resp.text = json.dumps(payload)
                resp.json = MagicMock(return_value=payload)
                return resp
        resp = MagicMock()
        resp.status_code = 404
        body = {"error": "RESOURCE_NOT_FOUND", "detail": "no match"}
        resp.text = json.dumps(body)
        resp.json = MagicMock(return_value=body)
        return resp

    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=_mock_get)
    return mock_client


# ---------------------------------------------------------------------------
# Test 1: GET / returns 200 + connector info even when unconfigured
# ---------------------------------------------------------------------------


def test_connector_info_returns_200_when_unconfigured(monkeypatch):
    monkeypatch.delenv("MONGODB_ATLAS_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("MONGODB_ATLAS_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("MONGODB_ATLAS_ORG_ID", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/mongodb-atlas/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "MongoDB Atlas Admin API"
    assert body["public_key_present"] is False
    assert body["private_key_present"] is False
    assert body["status"] == "unavailable"
    assert "/orgs/{org_id}/projects" in body["endpoints"]
    assert "/groups/{group_id}/clusters" in body["endpoints"]


# ---------------------------------------------------------------------------
# Test 2: 503 when public key is missing
# ---------------------------------------------------------------------------


def test_projects_returns_503_when_public_key_missing(monkeypatch):
    monkeypatch.delenv("MONGODB_ATLAS_PUBLIC_KEY", raising=False)
    monkeypatch.setenv("MONGODB_ATLAS_PRIVATE_KEY", _STUB_PRIV)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(f"/api/v1/mongodb-atlas/orgs/{_STUB_ORG_ID}/projects", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "mongodb_atlas_not_configured"
    assert "MONGODB_ATLAS_PUBLIC_KEY" in detail["needed"]
    assert "MONGODB_ATLAS_PRIVATE_KEY" in detail["needed"]


# ---------------------------------------------------------------------------
# Test 3: 503 when private key is missing
# ---------------------------------------------------------------------------


def test_clusters_returns_503_when_private_key_missing(monkeypatch):
    monkeypatch.setenv("MONGODB_ATLAS_PUBLIC_KEY", _STUB_PUB)
    monkeypatch.delenv("MONGODB_ATLAS_PRIVATE_KEY", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(f"/api/v1/mongodb-atlas/groups/{_STUB_GROUP_ID}/clusters", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "mongodb_atlas_not_configured"
    assert "MONGODB_ATLAS_PRIVATE_KEY" in detail["needed"]


# ---------------------------------------------------------------------------
# Test 4: Missing X-API-Key returns 401
# ---------------------------------------------------------------------------


def test_missing_api_key_returns_401(monkeypatch):
    monkeypatch.delenv("MONGODB_ATLAS_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("MONGODB_ATLAS_PRIVATE_KEY", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    # No X-API-Key header on a protected endpoint
    r = client.get(f"/api/v1/mongodb-atlas/groups/{_STUB_GROUP_ID}/clusters")
    assert r.status_code == 401, r.text


# ---------------------------------------------------------------------------
# Test 5: GET /orgs/{org_id}/projects happy path
# ---------------------------------------------------------------------------


def test_list_projects_happy_path(monkeypatch):
    monkeypatch.setenv("MONGODB_ATLAS_PUBLIC_KEY", _STUB_PUB)
    monkeypatch.setenv("MONGODB_ATLAS_PRIVATE_KEY", _STUB_PRIV)

    payload = {
        "results": [
            {"id": _STUB_GROUP_ID, "name": "prod-project", "orgId": _STUB_ORG_ID},
            {"id": "5e2211c17a3e5a48f5497de5", "name": "dev-project", "orgId": _STUB_ORG_ID},
        ],
        "totalCount": 2,
    }
    stub_client = _make_async_client({f"/orgs/{_STUB_ORG_ID}/groups": payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.mongodb_atlas_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get(
            f"/api/v1/mongodb-atlas/orgs/{_STUB_ORG_ID}/projects",
            headers=HEADERS,
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["results"]) == 2
    assert body["total_count"] == 2
    assert body["results"][0]["name"] == "prod-project"
    assert body["results"][1]["name"] == "dev-project"


# ---------------------------------------------------------------------------
# Test 6: GET /groups/{group_id}/clusters happy path
# ---------------------------------------------------------------------------


def test_list_clusters_happy_path(monkeypatch):
    monkeypatch.setenv("MONGODB_ATLAS_PUBLIC_KEY", _STUB_PUB)
    monkeypatch.setenv("MONGODB_ATLAS_PRIVATE_KEY", _STUB_PRIV)

    payload = {
        "results": [
            {
                "id": "cluster-abc",
                "name": "Cluster0",
                "providerSettings": {"providerName": "AWS", "regionName": "US_EAST_1"},
                "stateName": "IDLE",
                "mongoDBVersion": "7.0.6",
            }
        ],
        "totalCount": 1,
    }
    stub_client = _make_async_client({f"/groups/{_STUB_GROUP_ID}/clusters": payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.mongodb_atlas_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get(
            f"/api/v1/mongodb-atlas/groups/{_STUB_GROUP_ID}/clusters",
            headers=HEADERS,
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_count"] == 1
    assert body["results"][0]["name"] == "Cluster0"
    assert body["results"][0]["stateName"] == "IDLE"


# ---------------------------------------------------------------------------
# Test 7: GET /groups/{group_id}/databaseUsers happy path
# ---------------------------------------------------------------------------


def test_list_database_users_happy_path(monkeypatch):
    monkeypatch.setenv("MONGODB_ATLAS_PUBLIC_KEY", _STUB_PUB)
    monkeypatch.setenv("MONGODB_ATLAS_PRIVATE_KEY", _STUB_PRIV)

    payload = {
        "results": [
            {
                "username": "app-user",
                "databaseName": "admin",
                "roles": [{"roleName": "readWrite", "databaseName": "appdb"}],
            },
            {
                "username": "readonly-user",
                "databaseName": "admin",
                "roles": [{"roleName": "read", "databaseName": "appdb"}],
            },
        ],
        "totalCount": 2,
    }
    stub_client = _make_async_client({f"/groups/{_STUB_GROUP_ID}/databaseUsers": payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.mongodb_atlas_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get(
            f"/api/v1/mongodb-atlas/groups/{_STUB_GROUP_ID}/databaseUsers",
            headers=HEADERS,
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_count"] == 2
    assert body["results"][0]["username"] == "app-user"
    assert body["results"][1]["username"] == "readonly-user"


# ---------------------------------------------------------------------------
# Test 8: GET /groups/{group_id}/accessList happy path
# ---------------------------------------------------------------------------


def test_list_access_list_happy_path(monkeypatch):
    monkeypatch.setenv("MONGODB_ATLAS_PUBLIC_KEY", _STUB_PUB)
    monkeypatch.setenv("MONGODB_ATLAS_PRIVATE_KEY", _STUB_PRIV)

    payload = {
        "results": [
            {"cidrBlock": "10.0.0.0/8", "comment": "internal VPC"},
            {"cidrBlock": "192.168.1.100/32", "comment": "CI runner"},
        ],
        "totalCount": 2,
    }
    stub_client = _make_async_client({f"/groups/{_STUB_GROUP_ID}/accessList": payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.mongodb_atlas_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get(
            f"/api/v1/mongodb-atlas/groups/{_STUB_GROUP_ID}/accessList",
            headers=HEADERS,
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_count"] == 2
    assert body["results"][0]["cidrBlock"] == "10.0.0.0/8"
    assert body["results"][1]["cidrBlock"] == "192.168.1.100/32"
