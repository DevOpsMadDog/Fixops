"""Smoke tests for GraphRAGEngine — baseline coverage."""
import pytest

from core.graphrag_engine import (
    GraphRAGEngine,
    GraphQuery,
    GraphRAGResult,
    TrustGraphQueryBuilder,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def engine():
    return GraphRAGEngine()


@pytest.fixture()
def simple_query():
    return GraphQuery(
        query_text="What are critical vulnerabilities?",
        target_cores=[1, 2],
        max_results=5,
    )


# ── GraphQuery ────────────────────────────────────────────────────────────────

def test_graph_query_creation():
    q = GraphQuery(query_text="test query")
    assert q.query_text == "test query"


def test_graph_query_defaults():
    q = GraphQuery(query_text="test")
    assert isinstance(q.target_cores, list)
    assert q.max_results > 0


def test_graphrag_result_to_dict(engine, simple_query):
    """GraphRAGResult (not GraphQuery) has to_dict()."""
    result = engine.query(simple_query)
    d = result.to_dict()
    assert isinstance(d, dict)


# ── Instantiation ─────────────────────────────────────────────────────────────

def test_instantiation_default():
    engine = GraphRAGEngine()
    assert engine is not None


def test_instantiation_custom_ttl():
    engine = GraphRAGEngine(cache_ttl_seconds=60)
    assert engine is not None


# ── query() ───────────────────────────────────────────────────────────────────

def test_query_returns_graphrag_result(engine, simple_query):
    result = engine.query(simple_query)
    assert isinstance(result, GraphRAGResult)


def test_query_result_has_answer(engine, simple_query):
    result = engine.query(simple_query)
    assert hasattr(result, "answer")
    assert isinstance(result.answer, str)


def test_query_result_has_evidence(engine, simple_query):
    result = engine.query(simple_query)
    assert hasattr(result, "evidence")
    assert isinstance(result.evidence, list)


def test_query_result_confidence_in_range(engine, simple_query):
    result = engine.query(simple_query)
    assert 0.0 <= result.confidence <= 1.0


def test_query_empty_cores(engine):
    q = GraphQuery(query_text="test", target_cores=[])
    result = engine.query(q)
    assert isinstance(result, GraphRAGResult)


def test_query_single_core(engine):
    q = GraphQuery(query_text="threat actors", target_cores=[2], max_results=3)
    result = engine.query(q)
    assert isinstance(result, GraphRAGResult)


def test_query_caches_result(engine, simple_query):
    """Second identical query should return same result (cached)."""
    r1 = engine.query(simple_query)
    r2 = engine.query(simple_query)
    assert r1.answer == r2.answer


# ── clear_cache() ────────────────────────────────────────────────────────────

def test_clear_cache_does_not_raise(engine):
    engine.clear_cache()  # no exception


def test_clear_cache_then_query_works(engine, simple_query):
    engine.query(simple_query)
    engine.clear_cache()
    result = engine.query(simple_query)
    assert isinstance(result, GraphRAGResult)


# ── TrustGraphQueryBuilder ────────────────────────────────────────────────────

def test_builder_instantiation():
    builder = TrustGraphQueryBuilder()
    assert builder is not None


def test_builder_from_core_returns_self():
    builder = TrustGraphQueryBuilder()
    ret = builder.from_core(1)
    assert ret is builder


def test_builder_where_returns_self():
    builder = TrustGraphQueryBuilder()
    ret = builder.from_core(1).where("criticality", "eq", "critical")
    assert ret is builder


def test_builder_related_to_returns_self():
    builder = TrustGraphQueryBuilder()
    ret = builder.from_core(1).related_to("Service")
    assert ret is builder


def test_builder_limit_returns_self():
    builder = TrustGraphQueryBuilder()
    ret = builder.from_core(1).limit(10)
    assert ret is builder


def test_builder_execute_returns_list():
    builder = TrustGraphQueryBuilder()
    result = builder.from_core(1).limit(5).execute()
    assert isinstance(result, list)


def test_builder_build_query_dict():
    builder = TrustGraphQueryBuilder()
    builder.from_core(1).where("severity", "eq", "high").limit(20)
    d = builder.build_query_dict()
    assert isinstance(d, dict)


def test_builder_chained_fluent():
    result = (
        TrustGraphQueryBuilder()
        .from_core(1)
        .where("criticality", "eq", "critical")
        .related_to("Service")
        .limit(10)
        .execute()
    )
    assert isinstance(result, list)
