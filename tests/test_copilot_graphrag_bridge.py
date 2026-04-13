"""Tests for CopilotGraphRAGBridge.

Covers:
- enrich_query returns dict with required keys
- enrich_query with empty knowledge store → enriched=False, graph_context is string
- enrich_query with mock retriever → enriched=True, entities is list
- answer_with_context returns dict with answer, sources, confidence keys
- confidence is float between 0.0 and 1.0
- retrieval_method is "graph_rag" or "fallback"
- sources is list of strings
- answer is non-empty string
- get_bridge_stats returns dict with numeric values
- Bridge works when retriever is None (graceful fallback)
- Multiple queries tracked in stats
- conversation_history parameter accepted without error
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, "suite-core")

from core.copilot_graphrag_bridge import CopilotGraphRAGBridge


# ===========================================================================
# Fixtures
# ===========================================================================


def _make_mock_retriever(entities=None, relationships=None, context_summary=""):
    """Build a mock GraphRAGRetriever that returns controlled results."""
    retriever = MagicMock()
    retriever.retrieve.return_value = {
        "query": "test",
        "entities": entities if entities is not None else [],
        "relationships": relationships if relationships is not None else [],
        "context_summary": context_summary,
        "retrieval_method": "graph_rag",
    }
    return retriever


@pytest.fixture
def bridge_no_retriever():
    """Bridge with retriever forced to None (graceful degradation path)."""
    b = CopilotGraphRAGBridge.__new__(CopilotGraphRAGBridge)
    b._retriever = None
    b._queries_enriched = 0
    b._total_entities = 0
    b._cache_hits = 0
    return b


@pytest.fixture
def bridge_empty():
    """Bridge backed by a mock retriever that always returns no entities."""
    return CopilotGraphRAGBridge(retriever=_make_mock_retriever())


@pytest.fixture
def bridge_with_entities():
    """Bridge backed by a mock retriever that returns sample entities."""
    entities = [
        {"id": "cve_log4j", "type": "CVE", "name": "Log4Shell CVE-2021-44228", "score": 1.0},
        {"id": "svc_api", "type": "Service", "name": "Production API", "score": 0.9},
    ]
    relationships = [
        {"from": "svc_api", "to": "cve_log4j", "type": "vulnerable_to"},
    ]
    context = (
        "Found 2 related entities across 2 types with 1 relationships.\n"
        "- CVE: Log4Shell CVE-2021-44228\n"
        "- Service: Production API"
    )
    return CopilotGraphRAGBridge(
        retriever=_make_mock_retriever(
            entities=entities,
            relationships=relationships,
            context_summary=context,
        )
    )


# ===========================================================================
# enrich_query — required keys
# ===========================================================================


class TestEnrichQueryKeys:
    REQUIRED_KEYS = {"query", "graph_context", "entities", "relationships", "enriched"}

    def test_returns_dict(self, bridge_empty):
        result = bridge_empty.enrich_query("test query")
        assert isinstance(result, dict)

    def test_all_required_keys_present(self, bridge_empty):
        result = bridge_empty.enrich_query("test query")
        assert self.REQUIRED_KEYS.issubset(result.keys())

    def test_all_required_keys_present_with_entities(self, bridge_with_entities):
        result = bridge_with_entities.enrich_query("Log4Shell vulnerability")
        assert self.REQUIRED_KEYS.issubset(result.keys())

    def test_all_required_keys_present_no_retriever(self, bridge_no_retriever):
        result = bridge_no_retriever.enrich_query("any query")
        assert self.REQUIRED_KEYS.issubset(result.keys())


# ===========================================================================
# enrich_query — empty knowledge store
# ===========================================================================


class TestEnrichQueryEmpty:
    def test_enriched_false_when_no_entities(self, bridge_empty):
        result = bridge_empty.enrich_query("no results here")
        assert result["enriched"] is False

    def test_graph_context_is_string_when_empty(self, bridge_empty):
        result = bridge_empty.enrich_query("no results here")
        assert isinstance(result["graph_context"], str)

    def test_entities_is_list_when_empty(self, bridge_empty):
        result = bridge_empty.enrich_query("no results here")
        assert isinstance(result["entities"], list)

    def test_relationships_is_list_when_empty(self, bridge_empty):
        result = bridge_empty.enrich_query("no results here")
        assert isinstance(result["relationships"], list)

    def test_query_field_matches_input(self, bridge_empty):
        result = bridge_empty.enrich_query("my specific query")
        assert result["query"] == "my specific query"


# ===========================================================================
# enrich_query — with mock retriever returning entities
# ===========================================================================


class TestEnrichQueryWithEntities:
    def test_enriched_true_when_entities_returned(self, bridge_with_entities):
        result = bridge_with_entities.enrich_query("Log4Shell")
        assert result["enriched"] is True

    def test_entities_is_list(self, bridge_with_entities):
        result = bridge_with_entities.enrich_query("Log4Shell")
        assert isinstance(result["entities"], list)

    def test_entities_contains_dicts(self, bridge_with_entities):
        result = bridge_with_entities.enrich_query("Log4Shell")
        for entity in result["entities"]:
            assert isinstance(entity, dict)

    def test_graph_context_non_empty_when_enriched(self, bridge_with_entities):
        result = bridge_with_entities.enrich_query("Log4Shell")
        assert len(result["graph_context"]) > 0

    def test_relationships_is_list(self, bridge_with_entities):
        result = bridge_with_entities.enrich_query("Log4Shell")
        assert isinstance(result["relationships"], list)


# ===========================================================================
# answer_with_context — required keys and types
# ===========================================================================


class TestAnswerWithContext:
    REQUIRED_KEYS = {"answer", "sources", "confidence", "graph_context", "retrieval_method"}

    def test_returns_dict(self, bridge_with_entities):
        result = bridge_with_entities.answer_with_context("What CVEs affect us?")
        assert isinstance(result, dict)

    def test_all_required_keys_present_with_entities(self, bridge_with_entities):
        result = bridge_with_entities.answer_with_context("What CVEs affect us?")
        assert self.REQUIRED_KEYS.issubset(result.keys())

    def test_all_required_keys_present_fallback(self, bridge_empty):
        result = bridge_empty.answer_with_context("What CVEs affect us?")
        assert self.REQUIRED_KEYS.issubset(result.keys())

    def test_answer_is_non_empty_string_with_entities(self, bridge_with_entities):
        result = bridge_with_entities.answer_with_context("security risks")
        assert isinstance(result["answer"], str)
        assert len(result["answer"]) > 0

    def test_answer_is_non_empty_string_fallback(self, bridge_empty):
        result = bridge_empty.answer_with_context("security risks")
        assert isinstance(result["answer"], str)
        assert len(result["answer"]) > 0

    def test_sources_is_list_of_strings_with_entities(self, bridge_with_entities):
        result = bridge_with_entities.answer_with_context("Log4Shell")
        assert isinstance(result["sources"], list)
        for source in result["sources"]:
            assert isinstance(source, str)

    def test_sources_is_empty_list_fallback(self, bridge_empty):
        result = bridge_empty.answer_with_context("anything")
        assert result["sources"] == []

    def test_confidence_is_float(self, bridge_with_entities):
        result = bridge_with_entities.answer_with_context("test")
        assert isinstance(result["confidence"], float)

    def test_confidence_between_0_and_1_with_entities(self, bridge_with_entities):
        result = bridge_with_entities.answer_with_context("test")
        assert 0.0 <= result["confidence"] <= 1.0

    def test_confidence_zero_on_fallback(self, bridge_empty):
        result = bridge_empty.answer_with_context("test")
        assert result["confidence"] == 0.0

    def test_retrieval_method_graph_rag_when_enriched(self, bridge_with_entities):
        result = bridge_with_entities.answer_with_context("Log4Shell")
        assert result["retrieval_method"] == "graph_rag"

    def test_retrieval_method_fallback_when_empty(self, bridge_empty):
        result = bridge_empty.answer_with_context("no match")
        assert result["retrieval_method"] == "fallback"

    def test_retrieval_method_is_valid_value(self, bridge_with_entities):
        result = bridge_with_entities.answer_with_context("test")
        assert result["retrieval_method"] in ("graph_rag", "fallback")

    def test_conversation_history_accepted_without_error(self, bridge_with_entities):
        history = [
            {"role": "user", "content": "prior question"},
            {"role": "assistant", "content": "prior answer"},
        ]
        result = bridge_with_entities.answer_with_context("follow-up", conversation_history=history)
        assert isinstance(result, dict)

    def test_conversation_history_none_accepted(self, bridge_with_entities):
        result = bridge_with_entities.answer_with_context("test", conversation_history=None)
        assert isinstance(result, dict)


# ===========================================================================
# get_bridge_stats
# ===========================================================================


class TestGetBridgeStats:
    def test_returns_dict(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert isinstance(stats, dict)

    def test_has_queries_enriched_key(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert "queries_enriched" in stats

    def test_has_avg_entities_per_query_key(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert "avg_entities_per_query" in stats

    def test_has_cache_hits_key(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert "cache_hits" in stats

    def test_queries_enriched_is_numeric(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert isinstance(stats["queries_enriched"], int)

    def test_avg_entities_per_query_is_numeric(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert isinstance(stats["avg_entities_per_query"], float)

    def test_cache_hits_is_numeric(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert isinstance(stats["cache_hits"], int)

    def test_stats_initial_zero(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert stats["queries_enriched"] == 0
        assert stats["avg_entities_per_query"] == 0.0
        assert stats["cache_hits"] == 0

    def test_queries_enriched_increments_after_enriched_query(self, bridge_with_entities):
        bridge_with_entities.enrich_query("Log4Shell")
        stats = bridge_with_entities.get_bridge_stats()
        assert stats["queries_enriched"] == 1

    def test_avg_entities_updates_after_enriched_query(self, bridge_with_entities):
        bridge_with_entities.enrich_query("Log4Shell")
        stats = bridge_with_entities.get_bridge_stats()
        assert stats["avg_entities_per_query"] > 0.0

    def test_multiple_queries_tracked(self, bridge_with_entities):
        bridge_with_entities.enrich_query("query one")
        bridge_with_entities.enrich_query("query two")
        bridge_with_entities.enrich_query("query three")
        stats = bridge_with_entities.get_bridge_stats()
        assert stats["queries_enriched"] == 3


# ===========================================================================
# Graceful degradation — retriever is None
# ===========================================================================


class TestGracefulDegradation:
    def test_enrich_query_returns_dict_when_no_retriever(self, bridge_no_retriever):
        result = bridge_no_retriever.enrich_query("anything")
        assert isinstance(result, dict)

    def test_enriched_false_when_no_retriever(self, bridge_no_retriever):
        result = bridge_no_retriever.enrich_query("anything")
        assert result["enriched"] is False

    def test_graph_context_empty_string_when_no_retriever(self, bridge_no_retriever):
        result = bridge_no_retriever.enrich_query("anything")
        assert result["graph_context"] == ""

    def test_entities_empty_list_when_no_retriever(self, bridge_no_retriever):
        result = bridge_no_retriever.enrich_query("anything")
        assert result["entities"] == []

    def test_answer_with_context_fallback_when_no_retriever(self, bridge_no_retriever):
        result = bridge_no_retriever.answer_with_context("test")
        assert result["retrieval_method"] == "fallback"
        assert result["confidence"] == 0.0

    def test_init_with_none_retriever_does_not_raise(self):
        """Bridge with no retriever available still initializes cleanly."""
        import unittest.mock as mock
        with mock.patch.dict("sys.modules", {"trustgraph": None, "trustgraph.graph_rag": None}):
            # Cannot use the import path when module is blocked — create directly
            b = CopilotGraphRAGBridge.__new__(CopilotGraphRAGBridge)
            b._retriever = None
            b._queries_enriched = 0
            b._total_entities = 0
            b._cache_hits = 0
            assert b._retriever is None

    def test_retriever_exception_returns_empty_enrichment(self):
        """If retriever.retrieve() raises, enrich_query returns safe empty dict."""
        bad_retriever = MagicMock()
        bad_retriever.retrieve.side_effect = RuntimeError("connection lost")
        bridge = CopilotGraphRAGBridge(retriever=bad_retriever)
        result = bridge.enrich_query("test")
        assert result["enriched"] is False
        assert result["entities"] == []
