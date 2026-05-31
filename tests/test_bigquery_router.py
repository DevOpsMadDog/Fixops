"""Tests for bigquery_router — GCP BigQuery data-plane connector — ALDECI.

Spins up a minimal FastAPI app with the BigQuery router mounted. Each test
gets an isolated environment and a stub httpx.AsyncClient so we exercise the
real auth-header injection + parsing code paths without hitting the network.

NO MOCKS rule:
  * When GCP_BIGQUERY_ACCESS_TOKEN / GCP_PROJECT_ID are unset every live
    endpoint returns HTTP 503 with ``{"error":"bigquery_not_configured",...}``.
  * Happy-path tests use an async stub (not baked-in fake payloads) so auth
    header injection + result normalisation all run through real router code.
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

# GCP stub values used in happy-path tests
_STUB_TOKEN = "ya29.test-gcp-oauth-token"
_STUB_PROJECT = "my-gcp-project-123"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    from apps.api.bigquery_router import router
    app = FastAPI()
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Async httpx stub client (mirrors databricks_router test pattern)
# ---------------------------------------------------------------------------


def _make_async_client(get_responses: Dict[str, Any] = None, post_responses: Dict[str, Any] = None):
    """Build a mock httpx.AsyncClient that returns canned GET/POST responses."""
    import httpx

    get_responses = get_responses or {}
    post_responses = post_responses or {}

    mock_client = MagicMock(spec=httpx.AsyncClient)

    async def _mock_get(url: str, *, headers=None, params=None):
        for suffix, payload in get_responses.items():
            if suffix in url:
                resp = MagicMock()
                resp.status_code = 200
                resp.text = json.dumps(payload)
                resp.json = MagicMock(return_value=payload)
                return resp
        resp = MagicMock()
        resp.status_code = 404
        body = {"error": {"code": 404, "message": "Not found", "status": "NOT_FOUND"}}
        resp.text = json.dumps(body)
        resp.json = MagicMock(return_value=body)
        return resp

    async def _mock_post(url: str, *, headers=None, json=None):
        for suffix, payload in post_responses.items():
            if suffix in url:
                resp = MagicMock()
                resp.status_code = 200
                resp.text = json_module.dumps(payload)
                resp.json = MagicMock(return_value=payload)
                return resp
        resp = MagicMock()
        resp.status_code = 400
        body = {"error": {"code": 400, "message": "Bad request"}}
        resp.text = json_module.dumps(body)
        resp.json = MagicMock(return_value=body)
        return resp

    import json as json_module

    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=_mock_get)
    mock_client.post = AsyncMock(side_effect=_mock_post)
    return mock_client


# ---------------------------------------------------------------------------
# Test 1: GET / returns 200 + connector info even when unconfigured
# ---------------------------------------------------------------------------


def test_connector_info_returns_200_when_unconfigured(monkeypatch):
    monkeypatch.delenv("GCP_BIGQUERY_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/bigquery/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "GCP BigQuery REST API v2"
    assert body["access_token_present"] is False
    assert body["project_id_present"] is False
    assert body["status"] == "unavailable"
    assert "/datasets" in body["endpoints"]
    assert "/jobs" in body["endpoints"]
    assert "/queries" in body["endpoints"]


# ---------------------------------------------------------------------------
# Test 2: GET / returns "ok" when both creds present
# ---------------------------------------------------------------------------


def test_connector_info_ok_when_configured(monkeypatch):
    monkeypatch.setenv("GCP_BIGQUERY_ACCESS_TOKEN", _STUB_TOKEN)
    monkeypatch.setenv("GCP_PROJECT_ID", _STUB_PROJECT)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/bigquery/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token_present"] is True
    assert body["project_id_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# Test 3: GET /datasets returns 503 when token missing
# ---------------------------------------------------------------------------


def test_datasets_returns_503_when_token_missing(monkeypatch):
    monkeypatch.delenv("GCP_BIGQUERY_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("GCP_PROJECT_ID", _STUB_PROJECT)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/bigquery/datasets", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "bigquery_not_configured"
    assert "GCP_BIGQUERY_ACCESS_TOKEN" in detail["needed"]
    assert "GCP_PROJECT_ID" in detail["needed"]


# ---------------------------------------------------------------------------
# Test 4: GET /jobs returns 503 when project missing
# ---------------------------------------------------------------------------


def test_jobs_returns_503_when_project_missing(monkeypatch):
    monkeypatch.setenv("GCP_BIGQUERY_ACCESS_TOKEN", _STUB_TOKEN)
    monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/bigquery/jobs", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "bigquery_not_configured"


# ---------------------------------------------------------------------------
# Test 5: Missing X-API-Key returns 401
# ---------------------------------------------------------------------------


def test_missing_api_key_returns_401(monkeypatch):
    monkeypatch.delenv("GCP_BIGQUERY_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/bigquery/datasets")
    assert r.status_code == 401, r.text


# ---------------------------------------------------------------------------
# Test 6: GET /datasets happy path
# ---------------------------------------------------------------------------


def test_datasets_happy_path(monkeypatch):
    monkeypatch.setenv("GCP_BIGQUERY_ACCESS_TOKEN", _STUB_TOKEN)
    monkeypatch.setenv("GCP_PROJECT_ID", _STUB_PROJECT)

    datasets_payload = {
        "datasets": [
            {
                "datasetReference": {"datasetId": "analytics", "projectId": _STUB_PROJECT},
                "location": "US",
                "kind": "bigquery#dataset",
            },
            {
                "datasetReference": {"datasetId": "ml_features", "projectId": _STUB_PROJECT},
                "location": "US",
                "kind": "bigquery#dataset",
            },
        ]
    }

    stub_client = _make_async_client(
        get_responses={f"/projects/{_STUB_PROJECT}/datasets": datasets_payload}
    )
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.bigquery_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get("/api/v1/bigquery/datasets", headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["datasets"]) == 2
    assert body["datasets"][0]["datasetReference"]["datasetId"] == "analytics"
    assert body["datasets"][1]["datasetReference"]["datasetId"] == "ml_features"

    # Verify Bearer token was sent
    call_kwargs = stub_client.get.call_args
    sent_headers = call_kwargs.kwargs.get("headers", {})
    assert sent_headers.get("Authorization") == f"Bearer {_STUB_TOKEN}"


# ---------------------------------------------------------------------------
# Test 7: GET /datasets/{dataset_id}/tables happy path
# ---------------------------------------------------------------------------


def test_tables_happy_path(monkeypatch):
    monkeypatch.setenv("GCP_BIGQUERY_ACCESS_TOKEN", _STUB_TOKEN)
    monkeypatch.setenv("GCP_PROJECT_ID", _STUB_PROJECT)

    tables_payload = {
        "tables": [
            {
                "tableReference": {
                    "tableId": "events",
                    "datasetId": "analytics",
                    "projectId": _STUB_PROJECT,
                },
                "type": "TABLE",
                "kind": "bigquery#table",
            },
            {
                "tableReference": {
                    "tableId": "sessions",
                    "datasetId": "analytics",
                    "projectId": _STUB_PROJECT,
                },
                "type": "TABLE",
                "kind": "bigquery#table",
            },
        ]
    }

    stub_client = _make_async_client(
        get_responses={
            f"/projects/{_STUB_PROJECT}/datasets/analytics/tables": tables_payload
        }
    )
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.bigquery_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get("/api/v1/bigquery/datasets/analytics/tables", headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["tables"]) == 2
    assert body["tables"][0]["tableReference"]["tableId"] == "events"
    assert body["tables"][1]["type"] == "TABLE"


# ---------------------------------------------------------------------------
# Test 8: POST /queries happy path — query forwarded with correct fields
# ---------------------------------------------------------------------------


def test_queries_happy_path(monkeypatch):
    monkeypatch.setenv("GCP_BIGQUERY_ACCESS_TOKEN", _STUB_TOKEN)
    monkeypatch.setenv("GCP_PROJECT_ID", _STUB_PROJECT)

    import json as json_module

    query_payload = {
        "kind": "bigquery#queryResponse",
        "schema": {
            "fields": [
                {"name": "id", "type": "INTEGER"},
                {"name": "name", "type": "STRING"},
            ]
        },
        "rows": [
            {"f": [{"v": "1"}, {"v": "alpha"}]},
            {"f": [{"v": "2"}, {"v": "beta"}]},
        ],
        "totalRows": "2",
        "jobComplete": True,
    }

    stub_client = _make_async_client(
        post_responses={f"/projects/{_STUB_PROJECT}/queries": query_payload}
    )

    # Override the post side_effect for correct json_ capture
    async def _mock_post(url: str, *, headers=None, json=None):
        if f"/projects/{_STUB_PROJECT}/queries" in url:
            resp = MagicMock()
            resp.status_code = 200
            resp.text = json_module.dumps(query_payload)
            resp.json = MagicMock(return_value=query_payload)
            return resp
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "{}"
        resp.json = MagicMock(return_value={})
        return resp

    stub_client.post = AsyncMock(side_effect=_mock_post)

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    request_body = {
        "query": "SELECT id, name FROM `my-gcp-project-123.analytics.events` LIMIT 2",
        "useLegacySql": False,
        "maxResults": 2,
    }

    with patch("apps.api.bigquery_router.httpx.AsyncClient", return_value=stub_client):
        r = client.post("/api/v1/bigquery/queries", json=request_body, headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["jobComplete"] is True
    assert body["totalRows"] == "2"
    assert len(body["rows"]) == 2

    # Verify Bearer token was sent
    call_kwargs = stub_client.post.call_args
    sent_headers = call_kwargs.kwargs.get("headers", {})
    assert sent_headers.get("Authorization") == f"Bearer {_STUB_TOKEN}"
