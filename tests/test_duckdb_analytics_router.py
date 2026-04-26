"""Smoke tests for duckdb_analytics_router."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Reset module singleton + data dir
    from apps.api import duckdb_analytics_router as router_mod
    from core.duckdb_analytics_engine import AnalyticsEngine

    router_mod._engine_singleton = AnalyticsEngine(data_dir=tmp_path)

    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router_mod.router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app)


def test_health(client):
    r = client.get("/api/v1/duckdb-analytics/health")
    assert r.status_code == 200
    assert r.json()["engine"] == "duckdb_analytics"


def test_status(client):
    r = client.get("/api/v1/duckdb-analytics/status")
    assert r.status_code == 200
    assert r.json()["ready"] is True


def test_domains_empty_dir(client):
    r = client.get("/api/v1/duckdb-analytics/domains")
    assert r.status_code == 200
    assert r.json() == []


def test_risk_summary_empty(client):
    r = client.get("/api/v1/duckdb-analytics/risk-summary", params={"org_id": "ddb-test"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["org_id"] == "ddb-test"
    assert body["total_risks"] == 0
    assert body["critical_risks"] == 0


def test_executive_dashboard(client):
    r = client.get(
        "/api/v1/duckdb-analytics/executive-dashboard", params={"org_id": "ddb-exec"}
    )
    assert r.status_code == 200, r.text
    assert "domains_online" in r.json()


def test_custom_query_invalid_db_name(client):
    r = client.post(
        "/api/v1/duckdb-analytics/custom-query",
        json={"db_name": "Bad-Name!", "table_name": "x"},
    )
    assert r.status_code == 422


def test_custom_query_db_not_found(client):
    r = client.post(
        "/api/v1/duckdb-analytics/custom-query",
        json={"db_name": "nonexistent_db", "table_name": "tbl"},
    )
    assert r.status_code == 404
