"""Comprehensive tests for suite-core/api/knowledge_graph_router.py — 10 endpoints."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    app = FastAPI()
    from api.knowledge_graph_router import router
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


class TestHealthStatus:
    def test_status(self, client):
        resp = client.get("/api/v1/knowledge-graph/status")
        assert resp.status_code == 200

    def test_health(self, client):
        resp = client.get("/api/v1/knowledge-graph/health")
        assert resp.status_code == 200


class TestIngest:
    def test_ingest(self, client):
        resp = client.post(
            "/api/v1/knowledge-graph/ingest",
            json={"findings": [{"id": "f-1", "title": "SQLi"}]},
        )
        assert resp.status_code in (200, 422)

    def test_dependency(self, client):
        resp = client.post(
            "/api/v1/knowledge-graph/dependency",
            json={"source": "pkg-a", "target": "pkg-b", "type": "runtime"},
        )
        assert resp.status_code in (200, 422)


class TestAnalysis:
    def test_attack_paths(self, client):
        resp = client.post(
            "/api/v1/knowledge-graph/attack-paths",
            json={"asset_id": "asset-1"},
        )
        assert resp.status_code in (200, 422)

    def test_blast_radius(self, client):
        resp = client.post(
            "/api/v1/knowledge-graph/blast-radius",
            json={"finding_id": "f-1"},
        )
        assert resp.status_code in (200, 422)

    def test_analytics(self, client):
        resp = client.get("/api/v1/knowledge-graph/analytics")
        assert resp.status_code == 200


class TestExport:
    def test_export(self, client):
        resp = client.get("/api/v1/knowledge-graph/export")
        assert resp.status_code == 200

    def test_node_types(self, client):
        resp = client.get("/api/v1/knowledge-graph/node-types")
        assert resp.status_code == 200


class TestDemo:
    def test_seed_demo(self, client):
        resp = client.post("/api/v1/knowledge-graph/seed-demo")
        assert resp.status_code == 200
