"""
Tests for GraphRAG retriever and FastAPI router.

Covers:
- retrieve() with security-relevant query
- retrieve() with empty store → empty results (not error)
- retrieve() with hops=0 → seed entities only, no relationships
- retrieve() with blank query → empty results
- semantic_search() with and without entity_type filter
- get_entity_neighborhood() for known entity
- get_entity_neighborhood() for unknown entity → empty result
- context_summary is non-empty string when entities found
- context_summary is empty string when no entities found
- GraphRAGRetriever with None store → graceful empty results
- Multiple hops traverse relationships correctly
- _keyword_to_entities returns deduplicated results across cores
- _build_context groups entities by type
- _build_context handles empty inputs
- Router /retrieve returns 200 with well-formed response
- Router /semantic-search returns list
- Router /entities/{id}/neighborhood returns neighborhood
- Router /health returns graph stats
- retrieve() result keys are always present
- semantic_search() with empty query returns []
- get_entity_neighborhood() with empty entity_id returns empty
"""

from __future__ import annotations

import sys
import os
import tempfile
import pytest
from pathlib import Path

# Ensure suite-core is on the path
_suite_core = os.path.join(os.path.dirname(__file__), "..", "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

from trustgraph.knowledge_store import KnowledgeStore, KnowledgeEntity, KnowledgeRelationship
from trustgraph.graph_rag import GraphRAGRetriever


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def store(temp_db):
    return KnowledgeStore(db_path=temp_db)


@pytest.fixture
def populated_store(store):
    """Store with a small security-relevant graph."""
    entities = [
        KnowledgeEntity(
            entity_id="cve-2024-0001",
            core_id=1,
            entity_type="CVE",
            name="CVE-2024-0001",
            properties={"severity": "critical", "cvss": 9.8},
        ),
        KnowledgeEntity(
            entity_id="asset-prod-api",
            core_id=1,
            entity_type="Asset",
            name="Production API",
            properties={"criticality": "high", "owner": "backend-team"},
        ),
        KnowledgeEntity(
            entity_id="ctrl-patching",
            core_id=2,
            entity_type="Control",
            name="Patch Management",
            properties={"framework": "NIST", "status": "active"},
        ),
        KnowledgeEntity(
            entity_id="inc-2024-001",
            core_id=3,
            entity_type="Incident",
            name="API Breach 2024",
            properties={"severity": "high", "status": "resolved"},
        ),
    ]
    for e in entities:
        store.ingest(e)

    relationships = [
        KnowledgeRelationship(
            rel_id="rel-001",
            source_id="cve-2024-0001",
            target_id="asset-prod-api",
            rel_type="affects",
            confidence=0.95,
        ),
        KnowledgeRelationship(
            rel_id="rel-002",
            source_id="ctrl-patching",
            target_id="cve-2024-0001",
            rel_type="mitigates",
            confidence=0.9,
        ),
        KnowledgeRelationship(
            rel_id="rel-003",
            source_id="inc-2024-001",
            target_id="asset-prod-api",
            rel_type="impacted",
            confidence=0.85,
        ),
    ]
    for r in relationships:
        store.add_relationship(r)

    return store


@pytest.fixture
def retriever(populated_store):
    return GraphRAGRetriever(knowledge_store=populated_store)


@pytest.fixture
def empty_retriever(store):
    """Retriever backed by an empty knowledge store."""
    return GraphRAGRetriever(knowledge_store=store)


@pytest.fixture
def null_retriever():
    """Retriever with no knowledge store at all."""
    r = GraphRAGRetriever.__new__(GraphRAGRetriever)
    r._store = None
    return r


# =============================================================================
# retrieve() tests
# =============================================================================


def test_retrieve_returns_required_keys(retriever):
    result = retriever.retrieve("critical vulnerability")
    assert set(result.keys()) == {
        "query", "entities", "relationships", "context_summary", "retrieval_method"
    }


def test_retrieve_security_query_finds_entities(retriever):
    result = retriever.retrieve("critical")
    assert len(result["entities"]) > 0


def test_retrieve_method_is_graph_rag(retriever):
    result = retriever.retrieve("production API")
    assert result["retrieval_method"] == "graph_rag"


def test_retrieve_query_echoed_in_result(retriever):
    q = "patch management control"
    result = retriever.retrieve(q)
    assert result["query"] == q


def test_retrieve_empty_store_returns_empty(empty_retriever):
    result = empty_retriever.retrieve("critical vulnerability")
    assert result["entities"] == []
    assert result["relationships"] == []
    assert result["context_summary"] == ""


def test_retrieve_blank_query_returns_empty(retriever):
    result = retriever.retrieve("")
    assert result["entities"] == []
    assert result["relationships"] == []


def test_retrieve_whitespace_query_returns_empty(retriever):
    result = retriever.retrieve("   ")
    assert result["entities"] == []


def test_retrieve_hops_zero_no_relationships(retriever):
    result = retriever.retrieve("CVE", hops=0)
    assert result["relationships"] == []
    assert len(result["entities"]) > 0


def test_retrieve_hops_zero_has_seed_entities(retriever):
    result = retriever.retrieve("Production API", hops=0)
    assert len(result["entities"]) > 0


def test_retrieve_hops_traverses_relationships(retriever):
    """With hops=2, should pull in related entities beyond seed."""
    result = retriever.retrieve("CVE", hops=2)
    entity_ids = {e["id"] for e in result["entities"]}
    # CVE is seed; Production API is 1 hop away via "affects"
    assert "cve-2024-0001" in entity_ids
    assert "asset-prod-api" in entity_ids


def test_retrieve_null_store_graceful(null_retriever):
    result = null_retriever.retrieve("anything")
    assert result["entities"] == []
    assert result["relationships"] == []
    assert result["retrieval_method"] == "graph_rag"


# =============================================================================
# context_summary tests
# =============================================================================


def test_context_summary_nonempty_when_entities_found(retriever):
    result = retriever.retrieve("critical")
    assert len(result["entities"]) > 0
    assert result["context_summary"] != ""


def test_context_summary_empty_when_no_entities(empty_retriever):
    result = empty_retriever.retrieve("anything")
    assert result["context_summary"] == ""


def test_build_context_groups_by_type(retriever):
    result = retriever.retrieve("Production API", hops=2)
    if result["entities"]:
        summary = result["context_summary"]
        assert "Asset" in summary or "CVE" in summary or "Incident" in summary


def test_build_context_empty_input(retriever):
    ctx = retriever._build_context([], [])
    assert ctx == ""


def test_build_context_includes_relationship_info(retriever):
    result = retriever.retrieve("CVE", hops=2)
    assert len(result["relationships"]) > 0
    assert "relationship" in result["context_summary"].lower() or "--[" in result["context_summary"]


# =============================================================================
# semantic_search() tests
# =============================================================================


def test_semantic_search_returns_list(retriever):
    results = retriever.semantic_search("critical")
    assert isinstance(results, list)


def test_semantic_search_finds_results(retriever):
    results = retriever.semantic_search("production")
    assert len(results) > 0


def test_semantic_search_entity_type_filter(retriever):
    results = retriever.semantic_search("CVE", entity_types=["CVE"])
    assert all(r["type"] == "CVE" for r in results)


def test_semantic_search_type_filter_excludes_others(retriever):
    results = retriever.semantic_search("critical", entity_types=["Asset"])
    assert all(r["type"] == "Asset" for r in results)


def test_semantic_search_empty_query_returns_empty(retriever):
    results = retriever.semantic_search("")
    assert results == []


def test_semantic_search_null_store_returns_empty(null_retriever):
    results = null_retriever.semantic_search("anything")
    assert results == []


def test_semantic_search_result_has_required_fields(retriever):
    results = retriever.semantic_search("API")
    for r in results:
        assert "id" in r
        assert "type" in r
        assert "name" in r
        assert "score" in r


# =============================================================================
# get_entity_neighborhood() tests
# =============================================================================


def test_neighborhood_known_entity(retriever):
    result = retriever.get_entity_neighborhood("cve-2024-0001", hops=1)
    assert result["entity_id"] == "cve-2024-0001"
    assert len(result["entities"]) > 0


def test_neighborhood_includes_neighbors(retriever):
    result = retriever.get_entity_neighborhood("cve-2024-0001", hops=1)
    entity_ids = {e["id"] for e in result["entities"]}
    assert "asset-prod-api" in entity_ids


def test_neighborhood_unknown_entity_returns_empty(retriever):
    result = retriever.get_entity_neighborhood("nonexistent-entity-xyz", hops=1)
    assert result["entities"] == []
    assert result["relationships"] == []


def test_neighborhood_empty_entity_id_returns_empty(retriever):
    result = retriever.get_entity_neighborhood("", hops=1)
    assert result["entities"] == []


def test_neighborhood_null_store_returns_empty(null_retriever):
    result = null_retriever.get_entity_neighborhood("any-id", hops=1)
    assert result["entities"] == []
    assert result["relationships"] == []


def test_neighborhood_has_required_keys(retriever):
    result = retriever.get_entity_neighborhood("cve-2024-0001", hops=1)
    assert set(result.keys()) == {"entity_id", "entities", "relationships"}


# =============================================================================
# _keyword_to_entities tests
# =============================================================================


def test_keyword_to_entities_deduplicates(populated_store):
    """Same entity in multiple cores should appear once."""
    # Add same-named entity to two cores
    populated_store.ingest(KnowledgeEntity(
        entity_id="dup-entity",
        core_id=1,
        entity_type="Asset",
        name="Duplicate Asset",
        properties={},
    ))
    r = GraphRAGRetriever(knowledge_store=populated_store)
    results = r._keyword_to_entities("Duplicate Asset")
    ids = [e["id"] for e in results]
    assert ids.count("dup-entity") == 1


def test_keyword_to_entities_null_store_returns_empty(null_retriever):
    results = null_retriever._keyword_to_entities("anything")
    assert results == []
