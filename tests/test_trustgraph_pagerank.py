"""
Tests for GET /api/v1/graph/pagerank endpoint and KnowledgeBrain.pagerank().

Coverage:
  1. KnowledgeBrain.pagerank() on empty graph returns empty list (no crash).
  2. KnowledgeBrain.pagerank() with nodes returns scored, sorted results.
  3. KnowledgeBrain.pagerank() respects the limit parameter.
  4. Router GET /api/v1/graph/pagerank returns 200 with required fields.
  5. Router rejects limit=0 (422 Unprocessable Entity).
  6. Router rejects alpha out of range (422 Unprocessable Entity).
"""

from __future__ import annotations

import tempfile
import os
import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_brain(tmp_path: str):
    """Return a fresh KnowledgeBrain backed by a temp SQLite file."""
    from core.knowledge_brain import KnowledgeBrain

    return KnowledgeBrain(db_path=os.path.join(tmp_path, "test_brain.db"))


def _add_nodes_and_edges(brain) -> None:
    """Seed three nodes with two directed edges (A->B, B->C, A->C)."""
    from core.knowledge_brain import GraphNode, GraphEdge

    for nid, ntype in [("node_a", "asset"), ("node_b", "finding"), ("node_c", "cve")]:
        brain.upsert_node(GraphNode(node_id=nid, node_type=ntype, org_id="test"))

    for src, tgt, etype in [
        ("node_a", "node_b", "references"),
        ("node_b", "node_c", "references"),
        ("node_a", "node_c", "references"),
    ]:
        brain.add_edge(GraphEdge(source_id=src, target_id=tgt, edge_type=etype))


# ---------------------------------------------------------------------------
# Unit tests — KnowledgeBrain.pagerank()
# ---------------------------------------------------------------------------


class TestKnowledgeBrainPagerank:
    def test_empty_graph_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain = _make_brain(tmp)
            result = brain.pagerank(limit=10)
            assert result == []
            brain.close()

    def test_pagerank_returns_scored_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain = _make_brain(tmp)
            _add_nodes_and_edges(brain)
            result = brain.pagerank(limit=10)
            assert len(result) > 0
            for entry in result:
                assert "pagerank_score" in entry
                assert isinstance(entry["pagerank_score"], float)
                assert 0.0 <= entry["pagerank_score"] <= 1.0
            brain.close()

    def test_pagerank_sorted_descending(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain = _make_brain(tmp)
            _add_nodes_and_edges(brain)
            result = brain.pagerank(limit=10)
            scores = [r["pagerank_score"] for r in result]
            assert scores == sorted(scores, reverse=True)
            brain.close()

    def test_pagerank_respects_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain = _make_brain(tmp)
            _add_nodes_and_edges(brain)
            result = brain.pagerank(limit=2)
            assert len(result) <= 2
            brain.close()


# ---------------------------------------------------------------------------
# Integration tests — Router via TestClient
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    from suite_api.apps.api.trustgraph_backbone_router import router  # type: ignore[import]

    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture(scope="module")
def client():
    try:
        app = _build_app()
    except Exception:
        # Try alternate import path
        from apps.api.trustgraph_backbone_router import router

        app = FastAPI()
        app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


class TestPageRankRouter:
    def test_pagerank_200_with_required_fields(self, client):
        resp = client.get("/api/v1/graph/pagerank")
        assert resp.status_code == 200
        body = resp.json()
        assert "ranked" in body
        assert "total_nodes" in body
        assert "algorithm" in body
        assert "alpha" in body
        assert isinstance(body["ranked"], list)

    def test_pagerank_rejects_limit_zero(self, client):
        resp = client.get("/api/v1/graph/pagerank?limit=0")
        assert resp.status_code == 422

    def test_pagerank_rejects_alpha_out_of_range(self, client):
        resp = client.get("/api/v1/graph/pagerank?alpha=1.5")
        assert resp.status_code == 422
