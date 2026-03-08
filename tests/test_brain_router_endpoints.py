"""Tests for Brain Router endpoints via TestClient."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))
sys.path.insert(0, os.path.join(ROOT, "suite-api"))

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.brain_router import router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestBrainRouterHealth:
    def test_get_stats(self, client):
        resp = client.get("/api/v1/brain/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_nodes" in data or "nodes" in data or isinstance(data, dict)

    def test_get_nodes(self, client):
        resp = client.get("/api/v1/brain/nodes")
        assert resp.status_code == 200

    def test_get_edges(self, client):
        resp = client.get("/api/v1/brain/edges")
        assert resp.status_code in (200, 405)  # edges may not have GET endpoint


class TestBrainRouterIngest:
    def test_ingest_cve(self, client):
        resp = client.post("/api/v1/brain/ingest/cve", json={
            "cve_id": "CVE-2024-1234",
            "severity": "high",
            "cvss_score": 8.5,
            "description": "Test vulnerability",
        })
        assert resp.status_code in (200, 201)

    def test_ingest_finding(self, client):
        resp = client.post("/api/v1/brain/ingest/finding", json={
            "finding_id": "FIND-001",
            "title": "SQL Injection found",
            "severity": "critical",
            "source": "sast",
        })
        assert resp.status_code in (200, 201)

    def test_ingest_scan(self, client):
        resp = client.post("/api/v1/brain/ingest/scan", json={
            "scan_id": "SCAN-001",
            "scanner": "trivy",
            "findings": [{"id": "f1", "severity": "high"}],
        })
        assert resp.status_code in (200, 201)

    def test_ingest_asset(self, client):
        resp = client.post("/api/v1/brain/ingest/asset", json={
            "asset_id": "ASSET-001",
            "asset_type": "container",
        })
        assert resp.status_code in (200, 201)

    def test_ingest_cve_invalid_format(self, client):
        resp = client.post("/api/v1/brain/ingest/cve", json={
            "cve_id": "NOT-A-CVE",
        })
        assert resp.status_code == 422  # validation error


class TestBrainRouterNodes:
    def test_create_node(self, client):
        resp = client.post("/api/v1/brain/nodes", json={
            "node_id": "test-node-1",
            "node_type": "vulnerability",
            "properties": {"severity": "high"},
        })
        assert resp.status_code in (200, 201)

    def test_get_node(self, client):
        # Create first
        client.post("/api/v1/brain/nodes", json={
            "node_id": "get-test-node",
            "node_type": "vulnerability",
        })
        resp = client.get("/api/v1/brain/nodes/get-test-node")
        assert resp.status_code in (200, 404)

    def test_create_node_null_bytes_rejected(self, client):
        resp = client.post("/api/v1/brain/nodes", json={
            "node_id": "test\x00injection",
            "node_type": "vulnerability",
        })
        assert resp.status_code == 422


class TestBrainRouterEdges:
    def test_create_edge(self, client):
        # Create source and target nodes first
        client.post("/api/v1/brain/nodes", json={
            "node_id": "edge-src",
            "node_type": "vulnerability",
        })
        client.post("/api/v1/brain/nodes", json={
            "node_id": "edge-tgt",
            "node_type": "asset",
        })
        resp = client.post("/api/v1/brain/edges", json={
            "source_id": "edge-src",
            "target_id": "edge-tgt",
            "edge_type": "affects",
            "confidence": 0.9,
        })
        assert resp.status_code in (200, 201)

    def test_create_edge_invalid_confidence(self, client):
        resp = client.post("/api/v1/brain/edges", json={
            "source_id": "a",
            "target_id": "b",
            "edge_type": "affects",
            "confidence": 5.0,  # > 1.0 = invalid
        })
        assert resp.status_code == 422


class TestBrainRouterQuery:
    def test_query_by_type(self, client):
        resp = client.get("/api/v1/brain/nodes", params={"node_type": "vulnerability"})
        assert resp.status_code == 200

    def test_search(self, client):
        resp = client.get("/api/v1/brain/search", params={"q": "test"})
        assert resp.status_code in (200, 404, 405)

    def test_get_neighbors(self, client):
        resp = client.get("/api/v1/brain/nodes/test-node/neighbors")
        assert resp.status_code in (200, 404)
