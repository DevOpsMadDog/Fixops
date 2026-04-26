"""Smoke tests for graphrag_router."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDECI_DATA_DIR", str(tmp_path))
    from apps.api import graphrag_router as router_mod
    from core.graphrag_engine import GraphRAGEngine

    router_mod._engine_singleton = GraphRAGEngine()

    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router_mod.router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app)


def test_health(client):
    r = client.get("/api/v1/graphrag/health")
    assert r.status_code == 200
    assert r.json()["engine"] == "graphrag"


def test_status(client):
    r = client.get("/api/v1/graphrag/status")
    assert r.status_code == 200
    body = r.json()
    assert body["engine"] == "graphrag"


def test_query(client):
    r = client.post(
        "/api/v1/graphrag/query",
        json={
            "org_id": "graphrag-test",
            "query_text": "What are critical vulnerabilities?",
            "target_cores": [1, 2],
            "max_results": 5,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "answer" in body
    assert "evidence" in body


def test_query_invalid_core_rejected(client):
    r = client.post(
        "/api/v1/graphrag/query",
        json={
            "org_id": "graphrag-test",
            "query_text": "x",
            "target_cores": [99],
        },
    )
    # Validation either via Pydantic (422) or engine ValueError (422)
    assert r.status_code == 422


def test_traced_stats_empty(client):
    r = client.get(
        "/api/v1/graphrag/traced-stats", params={"org_id": "graphrag-empty"}
    )
    assert r.status_code == 200
    assert r.json()["total_queries"] == 0


def test_cache_clear(client):
    r = client.post("/api/v1/graphrag/cache/clear")
    assert r.status_code == 200
    assert r.json()["cleared"] is True
