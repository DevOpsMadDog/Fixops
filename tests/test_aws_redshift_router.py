"""Tests for aws_redshift_router — AWS Redshift Data API connector — ALDECI.

Spins up a minimal FastAPI app with the Redshift router mounted. Each test
gets an isolated environment and patches boto3.client so we exercise the real
credential-checking + error-handling code paths without hitting AWS.

NO MOCKS rule:
  * When AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION are unset
    every live endpoint returns HTTP 503 with
    ``{"error":"redshift_not_configured",...}``.
  * Happy-path tests patch boto3.client with a MagicMock — auth validation
    and boto3 call construction still run through the real router code.
  * GET / (connector info) returns 200 even when unconfigured.
"""
from __future__ import annotations

import os
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}

_STUB_KEY = "AKIATEST1234567890AB"
_STUB_SECRET = "testSecretKey1234567890ABCDEFGHIJKLMNOP"
_STUB_REGION = "us-east-1"
_STUB_CLUSTER = "my-redshift-cluster"
_STUB_DATABASE = "analytics"
_STUB_DB_USER = "admin"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    from apps.api.aws_redshift_router import router
    app = FastAPI()
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Boto3 client stub factory
# ---------------------------------------------------------------------------


def _make_boto_client(service_responses: Dict[str, Any] = None) -> MagicMock:
    """Build a mock boto3 client with pre-canned method return values."""
    service_responses = service_responses or {}
    mock_client = MagicMock()

    # Wire each method name to return the provided payload
    for method_name, payload in service_responses.items():
        getattr(mock_client, method_name).return_value = payload

    return mock_client


# ---------------------------------------------------------------------------
# Test 1: GET / returns 200 + connector info even when unconfigured
# ---------------------------------------------------------------------------


def test_connector_info_returns_200_when_unconfigured(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-redshift/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "AWS Redshift Data API"
    assert body["access_key_present"] is False
    assert body["secret_key_present"] is False
    assert body["region_present"] is False
    assert body["status"] == "unavailable"
    assert "/clusters" in body["endpoints"]
    assert "/queries" in body["endpoints"]
    assert "/queries/{statement_id}" in body["endpoints"]
    assert "/queries/{statement_id}/result" in body["endpoints"]


# ---------------------------------------------------------------------------
# Test 2: GET / returns "ok" when all creds present
# ---------------------------------------------------------------------------


def test_connector_info_ok_when_configured(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _STUB_KEY)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _STUB_SECRET)
    monkeypatch.setenv("AWS_REGION", _STUB_REGION)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-redshift/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_key_present"] is True
    assert body["secret_key_present"] is True
    assert body["region_present"] is True
    assert body["status"] == "ok"
    assert body["region"] == _STUB_REGION


# ---------------------------------------------------------------------------
# Test 3: GET /clusters returns 503 when creds missing
# ---------------------------------------------------------------------------


def test_clusters_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-redshift/clusters", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "redshift_not_configured"
    assert "AWS_ACCESS_KEY_ID" in detail["needed"]
    assert "AWS_SECRET_ACCESS_KEY" in detail["needed"]
    assert "AWS_REGION" in detail["needed"]


# ---------------------------------------------------------------------------
# Test 4: Missing X-API-Key returns 401
# ---------------------------------------------------------------------------


def test_missing_api_key_returns_401(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-redshift/clusters")
    assert r.status_code == 401, r.text


# ---------------------------------------------------------------------------
# Test 5: GET /clusters happy path
# ---------------------------------------------------------------------------


def test_clusters_happy_path(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _STUB_KEY)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _STUB_SECRET)
    monkeypatch.setenv("AWS_REGION", _STUB_REGION)

    clusters_payload = {
        "Clusters": [
            {
                "ClusterIdentifier": "my-redshift-cluster",
                "NodeType": "ra3.xlplus",
                "ClusterStatus": "available",
                "MasterUsername": "admin",
                "DBName": "analytics",
                "NumberOfNodes": 2,
                "Endpoint": {
                    "Address": "my-redshift-cluster.abc123.us-east-1.redshift.amazonaws.com",
                    "Port": 5439,
                },
            },
            {
                "ClusterIdentifier": "dev-redshift-cluster",
                "NodeType": "dc2.large",
                "ClusterStatus": "available",
                "MasterUsername": "devadmin",
                "DBName": "dev",
                "NumberOfNodes": 1,
                "Endpoint": {
                    "Address": "dev-redshift-cluster.def456.us-east-1.redshift.amazonaws.com",
                    "Port": 5439,
                },
            },
        ],
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }

    mock_boto_client = _make_boto_client({"describe_clusters": clusters_payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.aws_redshift_router.boto3") as mock_boto_mod:
        mock_boto_mod.client.return_value = mock_boto_client
        r = client.get("/api/v1/aws-redshift/clusters", headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["clusters"]) == 2
    assert body["clusters"][0]["ClusterIdentifier"] == "my-redshift-cluster"
    assert body["clusters"][0]["ClusterStatus"] == "available"
    assert body["clusters"][1]["NodeType"] == "dc2.large"

    # Verify boto3.client was called with redshift service + correct region
    with patch("apps.api.aws_redshift_router.boto3") as mock_boto_mod2:
        mock_boto_mod2.client.return_value = mock_boto_client
        client2 = TestClient(_build_app(), raise_server_exceptions=True)
        client2.get("/api/v1/aws-redshift/clusters", headers=HEADERS)
        assert mock_boto_mod2.client.call_args[0][0] == "redshift"
        assert mock_boto_mod2.client.call_args[1]["region_name"] == _STUB_REGION
        assert mock_boto_mod2.client.call_args[1]["aws_access_key_id"] == _STUB_KEY


# ---------------------------------------------------------------------------
# Test 6: POST /queries returns 503 when query env vars unset
# ---------------------------------------------------------------------------


def test_queries_returns_503_when_cluster_unset(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _STUB_KEY)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _STUB_SECRET)
    monkeypatch.setenv("AWS_REGION", _STUB_REGION)
    monkeypatch.delenv("REDSHIFT_CLUSTER_IDENTIFIER", raising=False)
    monkeypatch.delenv("REDSHIFT_DATABASE", raising=False)
    monkeypatch.delenv("REDSHIFT_DB_USER", raising=False)

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/aws-redshift/queries",
        json={"sql": "SELECT 1"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "redshift_query_not_configured"
    assert "REDSHIFT_CLUSTER_IDENTIFIER" in detail["needed"]


# ---------------------------------------------------------------------------
# Test 7: GET /queries/{statement_id} describe happy path
# ---------------------------------------------------------------------------


def test_describe_statement_happy_path(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _STUB_KEY)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _STUB_SECRET)
    monkeypatch.setenv("AWS_REGION", _STUB_REGION)

    import datetime

    describe_payload = {
        "Id": "abc-stmt-001",
        "Status": "FINISHED",
        "QueryString": "SELECT 1",
        "ClusterIdentifier": _STUB_CLUSTER,
        "Database": _STUB_DATABASE,
        "DbUser": _STUB_DB_USER,
        "CreatedAt": datetime.datetime(2026, 5, 31, 10, 0, 0),
        "UpdatedAt": datetime.datetime(2026, 5, 31, 10, 0, 5),
        "Duration": 5000000000,
        "ResultRows": 1,
        "HasResultSet": True,
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }

    mock_boto_client = _make_boto_client({"describe_statement": describe_payload})

    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.aws_redshift_router.boto3") as mock_boto_mod:
        mock_boto_mod.client.return_value = mock_boto_client
        r = client.get(
            "/api/v1/aws-redshift/queries/abc-stmt-001",
            headers=HEADERS,
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["Id"] == "abc-stmt-001"
    assert body["Status"] == "FINISHED"
    assert body["HasResultSet"] is True
    # ResponseMetadata should be stripped
    assert "ResponseMetadata" not in body

    # Verify describe_statement called with correct Id
    mock_boto_client.describe_statement.assert_called_once_with(Id="abc-stmt-001")
