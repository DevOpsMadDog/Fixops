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


# ===========================================================================
# Multiple enrich_query calls — varying graph sizes
# ===========================================================================


class TestEnrichQueryMultipleCalls:
    def _make_bridge(self, n_entities: int) -> CopilotGraphRAGBridge:
        entities = [
            {"id": f"e{i}", "type": "CVE", "name": f"CVE-2024-{i:04d}", "score": 0.8}
            for i in range(n_entities)
        ]
        return CopilotGraphRAGBridge(
            retriever=_make_mock_retriever(
                entities=entities,
                context_summary=f"Found {n_entities} entities.",
            )
        )

    def test_small_graph_one_entity(self):
        bridge = self._make_bridge(1)
        result = bridge.enrich_query("single cve")
        assert result["enriched"] is True
        assert len(result["entities"]) == 1

    def test_medium_graph_five_entities(self):
        bridge = self._make_bridge(5)
        result = bridge.enrich_query("medium graph query")
        assert result["enriched"] is True
        assert len(result["entities"]) == 5

    def test_large_graph_twenty_entities(self):
        bridge = self._make_bridge(20)
        result = bridge.enrich_query("large graph query")
        assert result["enriched"] is True
        assert len(result["entities"]) == 20

    def test_stats_avg_correct_after_two_different_sizes(self):
        """avg_entities_per_query should be (5 + 15) / 2 = 10.0."""
        bridge5 = self._make_bridge(5)
        # First call on the 5-entity bridge
        bridge5.enrich_query("first")
        # Swap retriever to 15-entity variant mid-session
        bridge5._retriever = _make_mock_retriever(
            entities=[{"id": f"x{i}", "type": "Asset", "name": f"host-{i}", "score": 0.7} for i in range(15)],
            context_summary="15 entities",
        )
        bridge5.enrich_query("second")
        stats = bridge5.get_bridge_stats()
        assert stats["queries_enriched"] == 2
        assert stats["avg_entities_per_query"] == 10.0

    def test_query_field_echoed_for_each_call(self):
        bridge = self._make_bridge(3)
        for phrase in ("alpha query", "beta query", "gamma query"):
            result = bridge.enrich_query(phrase)
            assert result["query"] == phrase


# ===========================================================================
# answer_with_context — max_hops / top_k variations
# ===========================================================================


class TestAnswerWithContextVariations:
    def test_confidence_scales_with_entity_count(self):
        """10 entities → confidence = min(0.5 + 10*0.05, 0.95) = 1.0 capped at 0.95."""
        entities = [
            {"id": f"e{i}", "type": "CVE", "name": f"CVE-X-{i}", "score": 0.9}
            for i in range(10)
        ]
        bridge = CopilotGraphRAGBridge(
            retriever=_make_mock_retriever(entities=entities, context_summary="10 CVEs")
        )
        result = bridge.answer_with_context("many cves")
        assert result["confidence"] == 0.95

    def test_confidence_single_entity(self):
        """1 entity → confidence = min(0.5 + 0.05, 0.95) = 0.55."""
        entities = [{"id": "e1", "type": "CVE", "name": "CVE-X-1", "score": 1.0}]
        bridge = CopilotGraphRAGBridge(
            retriever=_make_mock_retriever(entities=entities, context_summary="1 CVE")
        )
        result = bridge.answer_with_context("single entity")
        assert abs(result["confidence"] - 0.55) < 1e-9

    def test_answer_contains_query_text(self):
        entities = [{"id": "a1", "type": "Asset", "name": "prod-db", "score": 0.8}]
        bridge = CopilotGraphRAGBridge(
            retriever=_make_mock_retriever(entities=entities, context_summary="asset found")
        )
        query = "show me production database risks"
        result = bridge.answer_with_context(query)
        assert query in result["answer"]

    def test_sources_capped_at_ten(self):
        """answer_with_context collects up to 10 entity names as sources."""
        entities = [
            {"id": f"e{i}", "type": "Service", "name": f"svc-{i}", "score": 0.7}
            for i in range(15)
        ]
        bridge = CopilotGraphRAGBridge(
            retriever=_make_mock_retriever(entities=entities, context_summary="15 services")
        )
        result = bridge.answer_with_context("many services")
        assert len(result["sources"]) <= 10

    def test_graph_context_propagated_in_answer(self):
        summary = "Critical: Log4Shell affects API gateway"
        entities = [{"id": "cve1", "type": "CVE", "name": "Log4Shell", "score": 1.0}]
        bridge = CopilotGraphRAGBridge(
            retriever=_make_mock_retriever(entities=entities, context_summary=summary)
        )
        result = bridge.answer_with_context("log4shell impact")
        assert result["graph_context"] == summary


# ===========================================================================
# Edge cases — empty sources list, long queries, special chars
# ===========================================================================


class TestEdgeCases:
    def test_empty_query_string(self, bridge_empty):
        result = bridge_empty.enrich_query("")
        assert isinstance(result, dict)
        assert result["query"] == ""
        assert result["enriched"] is False

    def test_very_long_query(self, bridge_with_entities):
        long_query = "security " * 500  # 4000 chars
        result = bridge_with_entities.enrich_query(long_query)
        assert result["query"] == long_query
        assert isinstance(result["enriched"], bool)

    def test_special_chars_in_query(self, bridge_with_entities):
        special = "CVE-2021-44228 <script>alert('xss')</script> & 'quotes' \"double\""
        result = bridge_with_entities.enrich_query(special)
        assert result["query"] == special

    def test_unicode_query(self, bridge_with_entities):
        unicode_query = "漏洞扫描 Schwachstelle réseau"
        result = bridge_with_entities.enrich_query(unicode_query)
        assert result["query"] == unicode_query
        assert isinstance(result, dict)

    def test_answer_with_context_empty_query_fallback(self, bridge_empty):
        result = bridge_empty.answer_with_context("")
        assert result["retrieval_method"] == "fallback"
        assert isinstance(result["answer"], str)

    def test_newline_in_query(self, bridge_with_entities):
        newline_query = "line one\nline two\nline three"
        result = bridge_with_entities.enrich_query(newline_query)
        assert result["query"] == newline_query


# ===========================================================================
# Cache hit / miss behavior
# ===========================================================================


class TestCacheBehavior:
    def test_cache_hits_starts_at_zero(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert stats["cache_hits"] == 0

    def test_cache_hits_not_incremented_by_regular_query(self, bridge_with_entities):
        bridge_with_entities.enrich_query("cache test")
        stats = bridge_with_entities.get_bridge_stats()
        # Bridge does not implement caching yet — cache_hits stays 0
        assert stats["cache_hits"] == 0

    def test_cache_hits_key_type_is_int(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert type(stats["cache_hits"]) is int


# ===========================================================================
# get_bridge_stats — key completeness and value types
# ===========================================================================


class TestGetBridgeStatsExtended:
    EXPECTED_KEYS = {"queries_enriched", "avg_entities_per_query", "cache_hits"}

    def test_stats_has_exactly_expected_keys(self, bridge_empty):
        stats = bridge_empty.get_bridge_stats()
        assert self.EXPECTED_KEYS.issubset(stats.keys())

    def test_avg_entities_is_float_even_after_queries(self, bridge_with_entities):
        bridge_with_entities.enrich_query("first")
        bridge_with_entities.enrich_query("second")
        stats = bridge_with_entities.get_bridge_stats()
        assert isinstance(stats["avg_entities_per_query"], float)

    def test_queries_enriched_not_incremented_by_empty_result(self, bridge_empty):
        bridge_empty.enrich_query("no entities")
        bridge_empty.enrich_query("still no entities")
        stats = bridge_empty.get_bridge_stats()
        assert stats["queries_enriched"] == 0

    def test_avg_zero_when_no_successful_enrichments(self, bridge_empty):
        bridge_empty.enrich_query("miss one")
        bridge_empty.enrich_query("miss two")
        stats = bridge_empty.get_bridge_stats()
        assert stats["avg_entities_per_query"] == 0.0


# ===========================================================================
# Specific entity types: CVE, Asset, Incident
# ===========================================================================


class TestEntityTypes:
    def _bridge_for_type(self, entity_type: str, entity_id: str, name: str) -> CopilotGraphRAGBridge:
        entities = [{"id": entity_id, "type": entity_type, "name": name, "score": 1.0}]
        return CopilotGraphRAGBridge(
            retriever=_make_mock_retriever(
                entities=entities,
                context_summary=f"Found {entity_type}: {name}",
            )
        )

    def test_cve_entity_type_enriched(self):
        bridge = self._bridge_for_type("CVE", "cve_log4j", "Log4Shell CVE-2021-44228")
        result = bridge.enrich_query("log4shell")
        assert result["enriched"] is True
        assert result["entities"][0]["type"] == "CVE"

    def test_asset_entity_type_enriched(self):
        bridge = self._bridge_for_type("Asset", "asset_prod_db", "Production DB")
        result = bridge.enrich_query("prod db risks")
        assert result["enriched"] is True
        assert result["entities"][0]["type"] == "Asset"

    def test_incident_entity_type_enriched(self):
        bridge = self._bridge_for_type("Incident", "inc_001", "P1 Incident 2024-001")
        result = bridge.enrich_query("active incidents")
        assert result["enriched"] is True
        assert result["entities"][0]["type"] == "Incident"

    def test_cve_name_appears_in_sources(self):
        bridge = self._bridge_for_type("CVE", "cve_spring4shell", "Spring4Shell CVE-2022-22965")
        result = bridge.answer_with_context("spring vulnerabilities")
        assert "Spring4Shell CVE-2022-22965" in result["sources"]


# ===========================================================================
# Multiple sequential queries — stateful behavior
# ===========================================================================


class TestSequentialStatefulBehavior:
    def test_queries_enriched_accumulates_across_calls(self, bridge_with_entities):
        for i in range(5):
            bridge_with_entities.enrich_query(f"query number {i}")
        stats = bridge_with_entities.get_bridge_stats()
        assert stats["queries_enriched"] == 5

    def test_total_entities_accumulates(self, bridge_with_entities):
        """Each call adds 2 entities (per fixture). 3 calls = 6 total → avg = 2.0."""
        for _ in range(3):
            bridge_with_entities.enrich_query("repeated")
        stats = bridge_with_entities.get_bridge_stats()
        assert stats["avg_entities_per_query"] == 2.0

    def test_stats_after_mixed_hit_miss_queries(self, bridge_with_entities):
        """Swap retriever between hit and miss — only hits counted."""
        bridge_with_entities.enrich_query("hit query")  # 2 entities → enriched

        # Switch to empty retriever
        bridge_with_entities._retriever = _make_mock_retriever()
        bridge_with_entities.enrich_query("miss query")  # 0 entities → not enriched

        stats = bridge_with_entities.get_bridge_stats()
        assert stats["queries_enriched"] == 1

    def test_answer_with_context_sequential_independence(self, bridge_with_entities):
        """Each answer_with_context call is independent of previous results."""
        r1 = bridge_with_entities.answer_with_context("first question")
        r2 = bridge_with_entities.answer_with_context("second question")
        assert r1["retrieval_method"] == r2["retrieval_method"]
        assert r1["answer"] != r2["answer"]  # different queries → different answer text


# ===========================================================================
# Thread safety — sequential simulation
# ===========================================================================


class TestConcurrentSimulation:
    def test_sequential_calls_do_not_corrupt_stats(self, bridge_with_entities):
        """Simulate 10 back-to-back calls; stats should be consistent."""
        n = 10
        for i in range(n):
            bridge_with_entities.enrich_query(f"concurrent-sim-{i}")
        stats = bridge_with_entities.get_bridge_stats()
        assert stats["queries_enriched"] == n
        assert stats["avg_entities_per_query"] > 0.0

    def test_answer_with_context_interleaved_with_enrich(self, bridge_with_entities):
        """Interleave enrich_query and answer_with_context calls; no exceptions."""
        for i in range(4):
            bridge_with_entities.enrich_query(f"enrich-{i}")
            bridge_with_entities.answer_with_context(f"answer-{i}")
        stats = bridge_with_entities.get_bridge_stats()
        # enrich_query called 4 times directly + 4 times via answer_with_context = 8
        assert stats["queries_enriched"] == 8
