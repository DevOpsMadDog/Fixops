"""Tests for databricks_router — Databricks REST connector surface — ALDECI.

Spins up a minimal FastAPI app with the Databricks router mounted. Each test
gets an isolated environment and a stub httpx.AsyncClient so we exercise the
real auth-header injection + parsing code paths without hitting the network.

NO MOCKS rule:
  * When DATABRICKS_HOST / DATABRICKS_TOKEN are unset every live endpoint
    returns HTTP 503 with ``{"error":"databricks_not_configured",...}``.
  * Happy-path tests use an async stub transport (not baked-in fake payloads)
    so auth-header injection + result normalisation all run through the real
    router code.
  * GET / (connector info) returns 200 even when unconfigured.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}

# Databricks workspace stub values used in happy-path tests
_STUB_HOST = "adb-1234567890123456.7.azuredatabricks.net"
_STUB_TOKEN = "dapi-test-token-abc123"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    """Return a FastAPI app with the databricks router mounted."""
    from apps.api.databricks_router import router
    app = FastAPI()
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Async httpx stub transport
# ---------------------------------------------------------------------------


class _StubTransport(httpx.AsyncBaseTransport if False else object):
    """Stub transport that returns pre-canned responses keyed by URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses

    async def handle_async_request(self, request: Any) -> Any:
        import httpx
        url_str = str(request.url)
        for suffix, payload in self._responses.items():
            if suffix in url_str:
                body = json.dumps(payload).encode()
                return httpx.Response(200, content=body, request=request)
        # Default 404
        body = json.dumps({"error_code": "RESOURCE_DOES_NOT_EXIST"}).encode()
        return httpx.Response(404, content=body, request=request)


def _make_async_client(responses: Dict[str, Any]):
    """Build a real httpx.AsyncClient backed by _StubTransport."""
    import httpx
    transport = httpx.MockTransport if hasattr(httpx, "MockTransport") else None  # noqa
    # Use httpx.AsyncClient with a mock transport
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
        body = {"error_code": "RESOURCE_DOES_NOT_EXIST"}
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
    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.delenv("DATABRICKS_TOKEN", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/databricks/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Databricks REST API"
    assert body["databricks_host_present"] is False
    assert body["databricks_token_present"] is False
    assert body["status"] == "unavailable"
    assert "/clusters" in body["endpoints"]
    assert "/jobs" in body["endpoints"]
    assert "/runs/{run_id}" in body["endpoints"]
    assert "/workspace/list" in body["endpoints"]
    assert "/warehouses" in body["endpoints"]


# ---------------------------------------------------------------------------
# Test 2: GET /clusters returns 503 + not_configured when DATABRICKS_HOST unset
# ---------------------------------------------------------------------------


def test_clusters_returns_503_when_host_unset(monkeypatch):
    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.setenv("DATABRICKS_TOKEN", _STUB_TOKEN)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/databricks/clusters", headers=HEADERS)
    assert r.status_code == 503, r.text
    body = r.json()
    detail = body["detail"]
    assert detail["error"] == "databricks_not_configured"
    assert "DATABRICKS_HOST" in detail["needed"]
    assert "DATABRICKS_TOKEN" in detail["needed"]


# ---------------------------------------------------------------------------
# Test 3: GET /jobs returns 503 + not_configured when DATABRICKS_TOKEN unset
# ---------------------------------------------------------------------------


def test_jobs_returns_503_when_token_unset(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", _STUB_HOST)
    monkeypatch.delenv("DATABRICKS_TOKEN", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/databricks/jobs", headers=HEADERS)
    assert r.status_code == 503, r.text
    body = r.json()
    detail = body["detail"]
    assert detail["error"] == "databricks_not_configured"
    assert "DATABRICKS_TOKEN" in detail["needed"]


# ---------------------------------------------------------------------------
# Test 4: GET /clusters returns 200 + parsed cluster list when configured
# ---------------------------------------------------------------------------


def test_clusters_happy_path(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", _STUB_HOST)
    monkeypatch.setenv("DATABRICKS_TOKEN", _STUB_TOKEN)

    clusters_payload = {
        "clusters": [
            {
                "cluster_id": "0523-123456-abc1",
                "cluster_name": "prod-ml-cluster",
                "state": "RUNNING",
                "num_workers": 4,
                "spark_version": "13.3.x-scala2.12",
                "node_type_id": "Standard_DS3_v2",
            },
            {
                "cluster_id": "0523-234567-def2",
                "cluster_name": "dev-etl-cluster",
                "state": "TERMINATED",
                "num_workers": 2,
                "spark_version": "13.3.x-scala2.12",
                "node_type_id": "Standard_DS3_v2",
            },
        ]
    }

    stub_client = _make_async_client({"/api/2.0/clusters/list": clusters_payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.databricks_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get("/api/v1/databricks/clusters", headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["clusters"]) == 2
    assert body["clusters"][0]["cluster_id"] == "0523-123456-abc1"
    assert body["clusters"][0]["state"] == "RUNNING"
    assert body["clusters"][1]["cluster_name"] == "dev-etl-cluster"

    # Verify Bearer token was sent
    call_kwargs = stub_client.get.call_args
    sent_headers = call_kwargs.kwargs.get("headers", {})
    assert sent_headers.get("Authorization") == f"Bearer {_STUB_TOKEN}"


# ---------------------------------------------------------------------------
# Test 5: GET /runs/{run_id} returns 200 + parsed run data when configured
# ---------------------------------------------------------------------------


def test_get_run_happy_path(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", _STUB_HOST)
    monkeypatch.setenv("DATABRICKS_TOKEN", _STUB_TOKEN)

    run_payload = {
        "job_id": 42,
        "run_id": 9001,
        "original_attempt_run_id": 9001,
        "state": {
            "life_cycle_state": "TERMINATED",
            "result_state": "SUCCESS",
            "state_message": "",
        },
        "task": {
            "notebook_task": {"notebook_path": "/Repos/prod/etl_pipeline"}
        },
        "cluster_spec": {"existing_cluster_id": "0523-123456-abc1"},
        "start_time": 1716500000000,
        "end_time": 1716503600000,
        "run_duration": 3600000,
        "trigger": "PERIODIC",
    }

    stub_client = _make_async_client({"/api/2.1/jobs/runs/get": run_payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.databricks_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get("/api/v1/databricks/runs/9001", headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["run_id"] == 9001
    assert body["state"]["life_cycle_state"] == "TERMINATED"
    assert body["state"]["result_state"] == "SUCCESS"
    assert body["job_id"] == 42

    # Verify run_id param forwarded and Bearer token sent
    call_kwargs = stub_client.get.call_args
    sent_params = call_kwargs.kwargs.get("params", {})
    assert sent_params.get("run_id") == 9001
    sent_headers = call_kwargs.kwargs.get("headers", {})
    assert sent_headers.get("Authorization") == f"Bearer {_STUB_TOKEN}"


# ---------------------------------------------------------------------------
# Test 6: Missing X-API-Key returns 401
# ---------------------------------------------------------------------------


def test_missing_api_key_returns_401(monkeypatch):
    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.delenv("DATABRICKS_TOKEN", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    # No X-API-Key header on a protected endpoint
    r = client.get("/api/v1/databricks/clusters")
    assert r.status_code == 401, r.text


# ---------------------------------------------------------------------------
# Test 7: GET /jobs happy path — pagination fields forwarded
# ---------------------------------------------------------------------------


def test_jobs_happy_path_with_pagination(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", _STUB_HOST)
    monkeypatch.setenv("DATABRICKS_TOKEN", _STUB_TOKEN)

    jobs_payload = {
        "jobs": [
            {"job_id": 1, "settings": {"name": "nightly-etl"}, "created_time": 1716400000000},
            {"job_id": 2, "settings": {"name": "ml-training"}, "created_time": 1716410000000},
        ],
        "has_more": True,
        "next_page_token": "token-abc123",
    }

    stub_client = _make_async_client({"/api/2.1/jobs/list": jobs_payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.databricks_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get(
            "/api/v1/databricks/jobs",
            params={"limit": 2, "expand_tasks": True},
            headers=HEADERS,
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["jobs"]) == 2
    assert body["jobs"][0]["settings"]["name"] == "nightly-etl"
    assert body["has_more"] is True
    assert body["next_page_token"] == "token-abc123"

    call_kwargs = stub_client.get.call_args
    sent_params = call_kwargs.kwargs.get("params", {})
    assert sent_params.get("limit") == 2
    sent_headers = call_kwargs.kwargs.get("headers", {})
    assert sent_headers.get("Authorization") == f"Bearer {_STUB_TOKEN}"


# ---------------------------------------------------------------------------
# Test 8: GET /workspace/list returns objects list
# ---------------------------------------------------------------------------


def test_workspace_list_happy_path(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", _STUB_HOST)
    monkeypatch.setenv("DATABRICKS_TOKEN", _STUB_TOKEN)

    ws_payload = {
        "objects": [
            {"object_type": "NOTEBOOK", "path": "/Repos/prod/etl_pipeline", "language": "PYTHON"},
            {"object_type": "DIRECTORY", "path": "/Repos/prod/ml"},
        ]
    }

    stub_client = _make_async_client({"/api/2.0/workspace/list": ws_payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.databricks_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get(
            "/api/v1/databricks/workspace/list",
            params={"path": "/Repos/prod"},
            headers=HEADERS,
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["objects"]) == 2
    assert body["objects"][0]["object_type"] == "NOTEBOOK"
    assert body["objects"][1]["object_type"] == "DIRECTORY"


# ---------------------------------------------------------------------------
# Test 9: GET / returns "ok" status when both creds present
# ---------------------------------------------------------------------------


def test_connector_info_ok_when_configured(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", _STUB_HOST)
    monkeypatch.setenv("DATABRICKS_TOKEN", _STUB_TOKEN)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/databricks/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["databricks_host_present"] is True
    assert body["databricks_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# Test 10: GET /warehouses returns 503 when both creds absent
# ---------------------------------------------------------------------------


def test_warehouses_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.delenv("DATABRICKS_TOKEN", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/databricks/warehouses", headers=HEADERS)
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["detail"]["error"] == "databricks_not_configured"
