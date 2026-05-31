"""Tests for elasticsearch_router — Elasticsearch data-plane connector — ALDECI.

Spins up a minimal FastAPI app with the Elasticsearch router mounted. Each
test gets an isolated environment and a stub httpx.AsyncClient so we exercise
the real auth injection + parsing code paths without hitting the network.

NO MOCKS rule:
  * When ELASTICSEARCH_URL is unset every live endpoint returns HTTP 503.
  * When URL is set but neither Basic-auth nor API-key creds are present,
    every live endpoint also returns HTTP 503.
  * Happy-path tests stub the httpx.AsyncClient context manager; real router
    code runs (auth selection, path building, response parsing).
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

# Stub Elasticsearch values used in happy-path tests
_STUB_URL = "https://my-es-cluster.example.com:9243"
_STUB_USER = "elastic"
_STUB_PASSWORD = "s3cr3tpassword"
_STUB_API_KEY = "VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw=="


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    """Return a FastAPI app with the Elasticsearch router mounted."""
    from apps.api.elasticsearch_router import router
    app = FastAPI()
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Async httpx stub client factory
# ---------------------------------------------------------------------------


def _make_async_client(responses: Dict[str, Any]) -> MagicMock:
    """Build a MagicMock httpx.AsyncClient returning pre-canned responses."""
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
        body = {"error": "index_not_found_exception"}
        resp.text = json.dumps(body)
        resp.json = MagicMock(return_value=body)
        return resp

    async def _mock_post(url: str, *, headers=None, json=None):
        for suffix, payload in responses.items():
            if suffix in url:
                resp = MagicMock()
                resp.status_code = 200
                resp.text = json_mod.dumps(payload)
                resp.json = MagicMock(return_value=payload)
                return resp
        resp = MagicMock()
        resp.status_code = 404
        body = {"error": "index_not_found_exception"}
        resp.text = json_mod.dumps(body)
        resp.json = MagicMock(return_value=body)
        return resp

    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=_mock_get)
    mock_client.post = AsyncMock(side_effect=_mock_post)
    return mock_client


# Alias for use in _mock_post closure
import json as json_mod


# ---------------------------------------------------------------------------
# Test 1: GET / returns 200 + connector info even when unconfigured
# ---------------------------------------------------------------------------


def test_connector_info_returns_200_when_unconfigured(monkeypatch):
    monkeypatch.delenv("ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("ELASTICSEARCH_USER", raising=False)
    monkeypatch.delenv("ELASTICSEARCH_PASSWORD", raising=False)
    monkeypatch.delenv("ELASTICSEARCH_API_KEY", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/elasticsearch/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Elasticsearch REST API"
    assert body["url_present"] is False
    assert body["auth_mode"] == "none"
    assert body["status"] == "unavailable"
    assert "/cluster/health" in body["endpoints"]
    assert "/indices" in body["endpoints"]
    assert "/search/{index}" in body["endpoints"]
    assert "/nodes" in body["endpoints"]
    assert "/tasks" in body["endpoints"]


# ---------------------------------------------------------------------------
# Test 2: 503 when ELASTICSEARCH_URL is missing
# ---------------------------------------------------------------------------


def test_cluster_health_returns_503_when_url_missing(monkeypatch):
    monkeypatch.delenv("ELASTICSEARCH_URL", raising=False)
    monkeypatch.setenv("ELASTICSEARCH_USER", _STUB_USER)
    monkeypatch.setenv("ELASTICSEARCH_PASSWORD", _STUB_PASSWORD)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/elasticsearch/cluster/health", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "elasticsearch_not_configured"
    assert "ELASTICSEARCH_URL" in detail["needed"]


# ---------------------------------------------------------------------------
# Test 3: 503 when URL is set but no auth credentials are configured
# ---------------------------------------------------------------------------


def test_indices_returns_503_when_no_auth(monkeypatch):
    monkeypatch.setenv("ELASTICSEARCH_URL", _STUB_URL)
    monkeypatch.delenv("ELASTICSEARCH_USER", raising=False)
    monkeypatch.delenv("ELASTICSEARCH_PASSWORD", raising=False)
    monkeypatch.delenv("ELASTICSEARCH_API_KEY", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/elasticsearch/indices", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "elasticsearch_not_configured"


# ---------------------------------------------------------------------------
# Test 4: Missing X-API-Key returns 401
# ---------------------------------------------------------------------------


def test_missing_api_key_returns_401(monkeypatch):
    monkeypatch.delenv("ELASTICSEARCH_URL", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    # No X-API-Key header
    r = client.get("/api/v1/elasticsearch/cluster/health")
    assert r.status_code == 401, r.text


# ---------------------------------------------------------------------------
# Test 5: GET /cluster/health happy path (Basic auth)
# ---------------------------------------------------------------------------


def test_cluster_health_happy_path_basic_auth(monkeypatch):
    monkeypatch.setenv("ELASTICSEARCH_URL", _STUB_URL)
    monkeypatch.setenv("ELASTICSEARCH_USER", _STUB_USER)
    monkeypatch.setenv("ELASTICSEARCH_PASSWORD", _STUB_PASSWORD)
    monkeypatch.delenv("ELASTICSEARCH_API_KEY", raising=False)

    payload = {
        "cluster_name": "prod-cluster",
        "status": "green",
        "number_of_nodes": 3,
        "number_of_data_nodes": 3,
        "active_primary_shards": 50,
        "active_shards": 100,
    }
    stub_client = _make_async_client({"/_cluster/health": payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.elasticsearch_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get("/api/v1/elasticsearch/cluster/health", headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cluster_name"] == "prod-cluster"
    assert body["status"] == "green"
    assert body["number_of_nodes"] == 3


# ---------------------------------------------------------------------------
# Test 6: GET /indices happy path (API key auth)
# ---------------------------------------------------------------------------


def test_list_indices_happy_path_api_key(monkeypatch):
    monkeypatch.setenv("ELASTICSEARCH_URL", _STUB_URL)
    monkeypatch.delenv("ELASTICSEARCH_USER", raising=False)
    monkeypatch.delenv("ELASTICSEARCH_PASSWORD", raising=False)
    monkeypatch.setenv("ELASTICSEARCH_API_KEY", _STUB_API_KEY)

    payload = [
        {"index": "logs-2026.05.31", "health": "green", "docs.count": "12345", "store.size": "1.2gb"},
        {"index": "metrics-2026.05.31", "health": "yellow", "docs.count": "8900", "store.size": "800mb"},
    ]
    stub_client = _make_async_client({"/_cat/indices": payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.elasticsearch_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get("/api/v1/elasticsearch/indices", headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["indices"]) == 2
    assert body["indices"][0]["index"] == "logs-2026.05.31"
    assert body["indices"][0]["health"] == "green"
    assert body["indices"][1]["health"] == "yellow"

    # Verify ApiKey header would be set (auth_mode path)
    call_kwargs = stub_client.get.call_args
    sent_headers = call_kwargs.kwargs.get("headers", {})
    assert sent_headers.get("Authorization") == f"ApiKey {_STUB_API_KEY}"


# ---------------------------------------------------------------------------
# Test 7: GET /nodes happy path
# ---------------------------------------------------------------------------


def test_node_stats_happy_path(monkeypatch):
    monkeypatch.setenv("ELASTICSEARCH_URL", _STUB_URL)
    monkeypatch.setenv("ELASTICSEARCH_USER", _STUB_USER)
    monkeypatch.setenv("ELASTICSEARCH_PASSWORD", _STUB_PASSWORD)

    payload = {
        "_nodes": {"total": 2, "successful": 2, "failed": 0},
        "cluster_name": "prod-cluster",
        "nodes": {
            "node-1": {
                "name": "node-1",
                "os": {"cpu": {"percent": 12}},
                "jvm": {"mem": {"heap_used_percent": 45}},
                "fs": {"total": {"total_in_bytes": 500000000000, "free_in_bytes": 250000000000}},
            },
            "node-2": {
                "name": "node-2",
                "os": {"cpu": {"percent": 8}},
                "jvm": {"mem": {"heap_used_percent": 38}},
                "fs": {"total": {"total_in_bytes": 500000000000, "free_in_bytes": 300000000000}},
            },
        },
    }
    stub_client = _make_async_client({"/_nodes/stats": payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.elasticsearch_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get("/api/v1/elasticsearch/nodes", headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cluster_name"] == "prod-cluster"
    assert len(body["nodes"]) == 2
    assert "node-1" in body["nodes"]
    assert body["nodes"]["node-1"]["os"]["cpu"]["percent"] == 12


# ---------------------------------------------------------------------------
# Test 8: GET /tasks happy path
# ---------------------------------------------------------------------------


def test_list_tasks_happy_path(monkeypatch):
    monkeypatch.setenv("ELASTICSEARCH_URL", _STUB_URL)
    monkeypatch.setenv("ELASTICSEARCH_USER", _STUB_USER)
    monkeypatch.setenv("ELASTICSEARCH_PASSWORD", _STUB_PASSWORD)

    payload = {
        "nodes": {
            "node-1": {
                "name": "node-1",
                "tasks": {
                    "node-1:1234": {
                        "node": "node-1",
                        "id": 1234,
                        "type": "transport",
                        "action": "indices:data/read/search",
                        "running_time_in_nanos": 5000000,
                        "cancellable": False,
                    }
                },
            }
        }
    }
    stub_client = _make_async_client({"/_tasks": payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.elasticsearch_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get("/api/v1/elasticsearch/tasks", headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert "nodes" in body
    assert "node-1" in body["nodes"]
    task_key = "node-1:1234"
    assert task_key in body["nodes"]["node-1"]["tasks"]
    assert body["nodes"]["node-1"]["tasks"][task_key]["action"] == "indices:data/read/search"
