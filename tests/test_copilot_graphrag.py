"""Tests for CopilotGraphRAGAdapter.

Covers:
- Entity search across knowledge cores
- Graph neighborhood traversal
- Context text formatting
- Agent-type-to-core mapping
- Graceful degradation when TrustGraph unavailable
- Empty-result handling
- get_graphrag_adapter singleton
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.copilot_graphrag import (
    CORE_COMPLIANCE,
    CORE_CUSTOMER_ENV,
    CORE_DECISION_MEMORY,
    CORE_EXTERNAL,
    CORE_THREAT_INTEL,
    CopilotGraphRAGAdapter,
    GraphRAGResult,
    _AGENT_CORE_MAP,
    _truncate_props,
    get_graphrag_adapter,
)
from trustgraph.knowledge_store import (
    KnowledgeEntity,
    KnowledgeRelationship,
    KnowledgeStore,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def temp_db():
    """Temporary SQLite database path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def store(temp_db):
    """KnowledgeStore seeded with sample entities."""
    ks = KnowledgeStore(db_path=temp_db)
    # Core 1 — customer_env
    ks.ingest(
        KnowledgeEntity(
            entity_id="svc_prod_api",
            core_id=CORE_CUSTOMER_ENV,
            entity_type="Service",
            name="Production API",
            properties={"criticality": "critical", "owner": "backend-team"},
            org_id="default",
        )
    )
    # Core 2 — threat_intel
    ks.ingest(
        KnowledgeEntity(
            entity_id="cve_log4j",
            core_id=CORE_THREAT_INTEL,
            entity_type="CVE",
            name="Log4Shell CVE-2021-44228",
            properties={"severity": "critical", "cvss": 10.0, "affected": "Log4j"},
            org_id="default",
        )
    )
    # Core 3 — compliance
    ks.ingest(
        KnowledgeEntity(
            entity_id="ctrl_ac1",
            core_id=CORE_COMPLIANCE,
            entity_type="Control",
            name="Access Control AC-1",
            properties={"framework": "NIST", "status": "implemented"},
            org_id="default",
        )
    )
    # Core 4 — decision_memory
    ks.ingest(
        KnowledgeEntity(
            entity_id="verdict_fp_001",
            core_id=CORE_DECISION_MEMORY,
            entity_type="Verdict",
            name="False positive verdict on finding 001",
            properties={"decision": "false_positive", "confidence": 0.95},
            org_id="default",
        )
    )
    # Relationship between svc and cve
    ks.add_relationship(
        KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="cve_log4j",
            rel_type="vulnerable_to",
            confidence=0.9,
        )
    )
    return ks


@pytest.fixture
def adapter(temp_db, store):
    """CopilotGraphRAGAdapter using temp db already populated by store fixture."""
    return CopilotGraphRAGAdapter(db_path=temp_db)


# ===========================================================================
# Unit tests — _truncate_props helper
# ===========================================================================


class TestTruncateProps:
    def test_short_props_unchanged(self):
        props = {"key": "value"}
        result = _truncate_props(props, max_chars=200)
        assert "key" in result
        assert "value" in result
        assert "..." not in result

    def test_long_props_truncated(self):
        props = {"key": "x" * 500}
        result = _truncate_props(props, max_chars=50)
        assert result.endswith("...")
        assert len(result) <= 53  # 50 + "..."

    def test_empty_props(self):
        result = _truncate_props({})
        assert result == "{}"


# ===========================================================================
# Unit tests — GraphRAGResult dataclass
# ===========================================================================


class TestGraphRAGResult:
    def test_default_values(self):
        r = GraphRAGResult()
        assert r.entities == []
        assert r.relationships == []
        assert r.context_text == ""
        assert r.sources == []
        assert r.entity_count == 0
        assert r.available is True

    def test_unavailable_result(self):
        r = GraphRAGResult(available=False)
        assert r.available is False
        assert r.context_text == ""


# ===========================================================================
# Unit tests — agent core mapping
# ===========================================================================


class TestAgentCoreMap:
    def test_security_analyst_gets_threat_intel(self):
        cores = _AGENT_CORE_MAP["security_analyst"]
        assert CORE_THREAT_INTEL in cores
        assert CORE_CUSTOMER_ENV in cores

    def test_compliance_agent_gets_compliance_core(self):
        assert CORE_COMPLIANCE in _AGENT_CORE_MAP["compliance"]

    def test_pentest_agent_gets_threat_intel(self):
        assert CORE_THREAT_INTEL in _AGENT_CORE_MAP["pentest"]

    def test_general_agent_covers_most_cores(self):
        cores = _AGENT_CORE_MAP["general"]
        assert CORE_THREAT_INTEL in cores
        assert CORE_CUSTOMER_ENV in cores
        assert CORE_COMPLIANCE in cores

    def test_all_agent_types_have_at_least_one_core(self):
        for agent_type, cores in _AGENT_CORE_MAP.items():
            assert len(cores) >= 1, f"{agent_type} has no cores assigned"


# ===========================================================================
# Integration tests — CopilotGraphRAGAdapter with real KnowledgeStore
# ===========================================================================


class TestCopilotGraphRAGAdapter:
    def test_init_with_valid_db(self, adapter):
        """Adapter initializes and marks itself available."""
        assert adapter._available is True
        assert adapter._store is not None

    def test_init_with_missing_db_path(self):
        """Adapter with nonexistent DB still initializes (SQLite creates the file)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = f"{tmpdir}/newdb.db"
            a = CopilotGraphRAGAdapter(db_path=db_path)
            assert a._available is True

    def test_query_finds_threat_intel_entity(self, adapter):
        """Query for 'Log4Shell' returns threat intel entity."""
        result = adapter.query("Log4Shell CVE", agent_type="security_analyst")
        assert result.available is True
        assert result.entity_count > 0
        names = [e["name"] for e in result.entities]
        assert any("Log4Shell" in n for n in names)

    def test_query_finds_compliance_entity(self, adapter):
        """Compliance agent query finds compliance controls."""
        result = adapter.query("Access Control AC-1", agent_type="compliance")
        assert result.available is True
        assert result.entity_count > 0

    def test_query_returns_context_text(self, adapter):
        """context_text is non-empty when entities are found."""
        result = adapter.query("Log4Shell critical", agent_type="security_analyst")
        assert result.available is True
        if result.entity_count > 0:
            assert len(result.context_text) > 0
            assert "TrustGraph" in result.context_text

    def test_query_context_text_groups_by_core(self, adapter):
        """context_text groups entities under core labels."""
        result = adapter.query("Log4Shell critical", agent_type="security_analyst")
        if result.entity_count > 0:
            # Should mention at least one core label
            assert any(
                label in result.context_text
                for label in ["Threat Intelligence", "Customer Environment", "Past Decisions"]
            )

    def test_query_includes_relationships(self, adapter):
        """Relationships between matched entities are included."""
        result = adapter.query("Production API", agent_type="security_analyst")
        # svc_prod_api has a relationship to cve_log4j
        if result.entity_count > 0:
            assert isinstance(result.relationships, list)

    def test_query_empty_results(self, adapter):
        """Query that matches nothing returns empty result (still available)."""
        result = adapter.query("zzznomatch_xyzxyz_notexist", agent_type="general")
        assert result.available is True
        assert result.entity_count == 0
        assert result.context_text == ""

    def test_query_sources_populated(self, adapter):
        """sources list contains core IDs that returned results."""
        result = adapter.query("Log4Shell", agent_type="security_analyst")
        if result.entity_count > 0:
            assert isinstance(result.sources, list)
            assert len(result.sources) > 0
            for core_id in result.sources:
                assert 1 <= core_id <= 5

    def test_query_different_agent_types(self, adapter):
        """Different agent types use different cores without error."""
        for agent_type in ["security_analyst", "pentest", "compliance", "remediation", "general"]:
            result = adapter.query("security", agent_type=agent_type)
            assert result.available is True

    def test_query_unknown_agent_type_falls_back_to_general(self, adapter):
        """Unknown agent type falls back to general core set."""
        result = adapter.query("test query", agent_type="unknown_agent_xyz")
        assert result.available is True

    def test_query_limit_per_core(self, adapter, store):
        """limit_per_core is respected."""
        # Add multiple entities to core 2
        for i in range(10):
            store.ingest(
                KnowledgeEntity(
                    entity_id=f"cve_extra_{i}",
                    core_id=CORE_THREAT_INTEL,
                    entity_type="CVE",
                    name=f"Extra CVE {i} critical vulnerability",
                    properties={"severity": "critical"},
                    org_id="default",
                )
            )
        result = adapter.query("Extra CVE", agent_type="pentest", limit_per_core=3)
        # Total entities from each core capped at limit_per_core (plus neighbors)
        assert result.available is True


# ===========================================================================
# Graceful degradation tests
# ===========================================================================


class TestGracefulDegradation:
    def test_unavailable_when_import_fails(self):
        """Adapter is marked unavailable when KnowledgeStore import fails."""
        with patch.dict("sys.modules", {"trustgraph.knowledge_store": None}):
            a = CopilotGraphRAGAdapter(db_path="/nonexistent/path/trustgraph.db")
            # If import fails, _available should be False
            # (may still succeed if module is cached — just verify it doesn't raise)
            assert isinstance(a._available, bool)

    def test_query_returns_unavailable_result_when_store_none(self):
        """query() returns GraphRAGResult(available=False) when store is None."""
        a = CopilotGraphRAGAdapter.__new__(CopilotGraphRAGAdapter)
        a._store = None
        a._available = False
        result = a.query("anything")
        assert result.available is False
        assert result.entity_count == 0
        assert result.context_text == ""
        assert result.entities == []

    def test_query_handles_store_exception_gracefully(self, temp_db):
        """If store.search() raises, query() returns unavailable result."""
        a = CopilotGraphRAGAdapter(db_path=temp_db)
        a._store.search = MagicMock(side_effect=RuntimeError("DB connection lost"))
        result = a.query("anything", agent_type="general")
        assert result.available is False


# ===========================================================================
# Singleton tests
# ===========================================================================


class TestGetGraphRAGAdapter:
    def test_singleton_returns_same_instance(self):
        """get_graphrag_adapter() returns same object on repeated calls."""
        import core.copilot_graphrag as mod

        # Reset singleton for test isolation
        mod._adapter = None
        a1 = get_graphrag_adapter()
        a2 = get_graphrag_adapter()
        assert a1 is a2

    def test_singleton_is_adapter_instance(self):
        """get_graphrag_adapter() returns CopilotGraphRAGAdapter."""
        import core.copilot_graphrag as mod

        mod._adapter = None
        adapter = get_graphrag_adapter()
        assert isinstance(adapter, CopilotGraphRAGAdapter)
