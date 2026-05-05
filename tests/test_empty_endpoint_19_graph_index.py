"""Tests for empty endpoint #19: GET /api/v1/graph/ — validates real implementation.

The canonical handler is suite-evidence-risk/api/graph_router.py::graph_summary,
which calls build_graph_from_sources() and returns real node/edge counts.
The gap_router.py fallback (KnowledgeGraphEngine) covers the case where the
evidence-risk router is not mounted.
"""
import os
import pytest

os.environ["FIXOPS_API_TOKEN"] = "fixops_test_key_ep19"
API_KEY = "fixops_test_key_ep19"
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from apps.api.app import create_app
    return TestClient(create_app(), headers=HEADERS)


def test_graph_index_not_stub(client):
    """GET /api/v1/graph/ must not return the bare stub {items:[], count:0}."""
    resp = client.get("/api/v1/graph/?org_id=test-org")
    assert resp.status_code == 200
    data = resp.json()
    # Old stub was: {"router": "graph", "items": [], "count": 0}
    # Real handler returns either:
    #   evidence-risk: {"nodes": N, "edges": M, "configured_sources": {...}}
    #   gap fallback:  {"node_count": N, "edge_count": M, "status": "ok"|"degraded", ...}
    is_evidence_risk = "nodes" in data and "configured_sources" in data
    is_gap_fallback = "node_count" in data and "status" in data
    assert is_evidence_risk or is_gap_fallback, (
        f"Response looks like bare stub or unknown shape: {data}"
    )
    # Must not be the old empty stub
    assert data.get("items") is None, f"Still returning stub items=[]: {data}"


def test_graph_index_has_numeric_counts(client):
    """GET /api/v1/graph/ counts must be non-negative integers."""
    resp = client.get("/api/v1/graph/")
    assert resp.status_code == 200
    data = resp.json()
    # Accept either shape
    node_count = data.get("nodes", data.get("node_count", None))
    edge_count = data.get("edges", data.get("edge_count", None))
    assert node_count is not None, f"No node count in response: {data}"
    assert edge_count is not None, f"No edge count in response: {data}"
    assert isinstance(node_count, int) and node_count >= 0
    assert isinstance(edge_count, int) and edge_count >= 0
