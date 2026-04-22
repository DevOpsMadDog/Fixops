"""Tests for GAP-029 NL Graph Assistant.

Covers:
- graphrag_engine.query_with_trace (NL-to-traversal, cache, edge matching, graceful-empty)
- ai_security_advisor_engine.answer_graph_question (explanation template)
- intelligent_security_engine.nl_graph_assistant (thin convenience wrapper)
- nl_graph_router endpoints (/query, /trace, /history, /stats)
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_data_dir(monkeypatch, tmp_path):
    """Point ALDECI_DATA_DIR to a temp dir so each test has its own cache DB."""
    monkeypatch.setenv("ALDECI_DATA_DIR", str(tmp_path))
    # Force re-creation of traced DB under temp dir.
    yield tmp_path


@pytest.fixture()
def graphrag_engine(isolated_data_dir):
    from core.graphrag_engine import GraphRAGEngine
    return GraphRAGEngine()


@pytest.fixture()
def advisor_engine(isolated_data_dir):
    from core.ai_security_advisor_engine import AISecurityAdvisorEngine
    # Direct advisor to a temp DB
    db_path = isolated_data_dir / "advisor.db"
    return AISecurityAdvisorEngine(db_path=str(db_path))


@pytest.fixture()
def api_client(isolated_data_dir):
    """Spin up a minimal FastAPI app with only the nl_graph_router mounted.

    Uses FastAPI's dependency_overrides to bypass api_key_auth — this is the
    supported mechanism (monkeypatching the symbol doesn't retro-fit already-
    captured Depends() bindings).
    """
    # Reset module-level engine singletons each test
    import apps.api.nl_graph_router as router_mod
    router_mod._advisor = None
    router_mod._graphrag = None

    from apps.api.auth_deps import api_key_auth
    from apps.api.nl_graph_router import router as nl_router
    app = FastAPI()
    app.include_router(nl_router)

    async def _noop_auth():
        return {"sub": "test"}

    app.dependency_overrides[api_key_auth] = _noop_auth
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1-8: query_with_trace core behavior
# ---------------------------------------------------------------------------


def test_query_with_trace_returns_required_fields(graphrag_engine):
    r = graphrag_engine.query_with_trace("org-1", "What depends on payments-api?")
    assert "question" in r
    assert "parsed_entities" in r
    assert "parsed_edges" in r
    assert "traversal_trace" in r
    assert "answer_summary" in r
    assert "cached" in r


def test_traversal_trace_is_a_list(graphrag_engine):
    r = graphrag_engine.query_with_trace("org-1", "What reaches the database?")
    assert isinstance(r["traversal_trace"], list)


def test_cache_hit_on_second_identical_question(graphrag_engine):
    q = "Who owns the checkout service?"
    r1 = graphrag_engine.query_with_trace("org-1", q)
    r2 = graphrag_engine.query_with_trace("org-1", q)
    assert r1["cached"] is False
    assert r2["cached"] is True
    # Question hash-equivalence
    assert r1["question"] == r2["question"]


def test_different_questions_do_not_collide(graphrag_engine):
    a = graphrag_engine.query_with_trace("org-1", "Who owns payments?")
    b = graphrag_engine.query_with_trace("org-1", "What depends on payments?")
    assert a["cached"] is False
    assert b["cached"] is False


def test_empty_graph_returns_gracefully(graphrag_engine):
    r = graphrag_engine.query_with_trace(
        "org-ghost", "What depends on nonexistent-service-xyz?"
    )
    assert r["traversal_trace"] == []
    assert "answer_summary" in r
    assert isinstance(r["answer_summary"], str)
    assert len(r["answer_summary"]) > 0


def test_question_with_no_entity_produces_empty_trace(graphrag_engine):
    r = graphrag_engine.query_with_trace("org-1", "how are you")
    # No entity, no edge → empty trace, still structured response
    assert r["traversal_trace"] == []


def test_org_id_isolation(graphrag_engine):
    q = "Who owns the billing DB?"
    graphrag_engine.query_with_trace("org-A", q)
    r_b = graphrag_engine.query_with_trace("org-B", q)
    # Second org sees a cache miss (own namespace)
    assert r_b["cached"] is False


def test_who_owns_parses_owned_by_edge(graphrag_engine):
    r = graphrag_engine.query_with_trace(
        "org-1", "Who owns the billing-service?"
    )
    assert "owned_by" in r["parsed_edges"]


def test_what_reaches_parses_connected_to_edge(graphrag_engine):
    r = graphrag_engine.query_with_trace(
        "org-1", "What reaches the prod-db from the DMZ?"
    )
    assert "connected_to" in r["parsed_edges"]


def test_which_deps_parses_depends_on_edge(graphrag_engine):
    r = graphrag_engine.query_with_trace(
        "org-1", "Which services depend on kafka?"
    )
    assert "depends_on" in r["parsed_edges"]


def test_run_on_parses_deployed_on_edge(graphrag_engine):
    r = graphrag_engine.query_with_trace(
        "org-1", "What runs on the primary cluster?"
    )
    assert "deployed_on" in r["parsed_edges"]


def test_question_with_no_recognized_edge_still_returns_result(graphrag_engine):
    r = graphrag_engine.query_with_trace(
        "org-1", "Tell me about Service Foo."
    )
    # No edge keywords — parsed_edges should be empty, but still no crash
    assert isinstance(r["parsed_edges"], list)


def test_parsed_entities_includes_capitalized_tokens(graphrag_engine):
    r = graphrag_engine.query_with_trace(
        "org-1", "What depends on PaymentsService?"
    )
    assert any("PaymentsService" in e for e in r["parsed_entities"])


def test_question_sha256_stable(graphrag_engine):
    from core.graphrag_engine import GraphRAGEngine
    h1 = GraphRAGEngine._sha256("hello")
    h2 = GraphRAGEngine._sha256("hello")
    assert h1 == h2
    assert len(h1) == 64


# ---------------------------------------------------------------------------
# 15-18: ai_security_advisor_engine.answer_graph_question
# ---------------------------------------------------------------------------


def test_answer_graph_question_returns_explanation(advisor_engine):
    r = advisor_engine.answer_graph_question(
        "org-1", "Who owns the payments service?"
    )
    assert "explanation" in r
    assert isinstance(r["explanation"], str)
    assert len(r["explanation"]) > 0


def test_answer_graph_question_preserves_trace_fields(advisor_engine):
    r = advisor_engine.answer_graph_question(
        "org-1", "What reaches prod-db?"
    )
    for key in ("question", "parsed_entities", "parsed_edges",
                "traversal_trace", "answer_summary"):
        assert key in r


def test_answer_graph_question_empty_trace_has_explanation(advisor_engine):
    r = advisor_engine.answer_graph_question("org-1", "how are you")
    # Even empty trace produces deterministic explanation
    assert "Based on 0 hops" in r["explanation"]


def test_answer_graph_question_rejects_empty(advisor_engine):
    with pytest.raises(ValueError):
        advisor_engine.answer_graph_question("org-1", "")


def test_answer_graph_question_rejects_empty_org(advisor_engine):
    with pytest.raises(ValueError):
        advisor_engine.answer_graph_question("", "Who owns x?")


# ---------------------------------------------------------------------------
# 20-21: intelligent_security_engine.nl_graph_assistant
# ---------------------------------------------------------------------------


def test_intelligent_engine_nl_graph_assistant_chains_to_advisor(isolated_data_dir):
    from core.intelligent_security_engine import IntelligentSecurityEngine
    eng = IntelligentSecurityEngine()
    r = eng.nl_graph_assistant("org-1", "Who owns payments?")
    assert "explanation" in r
    assert "traversal_trace" in r


def test_intelligent_engine_nl_graph_assistant_validates_inputs(isolated_data_dir):
    from core.intelligent_security_engine import IntelligentSecurityEngine
    eng = IntelligentSecurityEngine()
    with pytest.raises(ValueError):
        eng.nl_graph_assistant("", "q")
    with pytest.raises(ValueError):
        eng.nl_graph_assistant("org", "")


# ---------------------------------------------------------------------------
# 22-25: nl_graph_router smoke tests
# ---------------------------------------------------------------------------


def test_router_query_endpoint_smoke(api_client):
    r = api_client.post(
        "/api/v1/nl-graph/query",
        params={"org_id": "org-1"},
        json={"question": "Who owns the payments service?"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "explanation" in body
    assert "traversal_trace" in body


def test_router_trace_endpoint_smoke(api_client):
    r = api_client.post(
        "/api/v1/nl-graph/trace",
        params={"org_id": "org-1"},
        json={"question": "What depends on kafka?"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "traversal_trace" in body
    assert "parsed_edges" in body


def test_router_history_endpoint_returns_list(api_client):
    # Seed at least one query
    api_client.post(
        "/api/v1/nl-graph/query",
        params={"org_id": "org-hist"},
        json={"question": "Who owns auth?"},
    )
    r = api_client.get(
        "/api/v1/nl-graph/history", params={"org_id": "org-hist"}
    )
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert len(body) >= 1


def test_router_stats_endpoint_returns_totals(api_client):
    api_client.post(
        "/api/v1/nl-graph/query",
        params={"org_id": "org-stats"},
        json={"question": "What depends on db?"},
    )
    r = api_client.get(
        "/api/v1/nl-graph/stats", params={"org_id": "org-stats"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["org_id"] == "org-stats"
    assert body["total_queries"] >= 1
    assert "avg_hops_per_query" in body


def test_router_query_rejects_empty_question(api_client):
    r = api_client.post(
        "/api/v1/nl-graph/query",
        params={"org_id": "org-1"},
        json={"question": ""},
    )
    # Pydantic min_length=1 rejection
    assert r.status_code == 422


def test_router_query_rejects_missing_body(api_client):
    r = api_client.post(
        "/api/v1/nl-graph/query",
        params={"org_id": "org-1"},
        json={},
    )
    assert r.status_code == 422
