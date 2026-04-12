"""
Comprehensive tests for TrustGraph Knowledge Cores and MCP Server.

Tests cover:
- KnowledgeStore CRUD operations
- Full-text search with FTS5
- Relationship management
- Graph traversal
- Core statistics
- TrustGraphMCPServer tool execution
- Resource reading
- Multi-tenant support
- Cross-core queries
"""

from __future__ import annotations

import json
import pytest
import tempfile
from datetime import datetime
from pathlib import Path

from trustgraph.knowledge_store import (
    KnowledgeStore,
    KnowledgeEntity,
    KnowledgeRelationship,
)
from trustgraph.mcp_server import TrustGraphMCPServer


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def knowledge_store(temp_db):
    """Create KnowledgeStore instance."""
    return KnowledgeStore(db_path=temp_db)


@pytest.fixture
def mcp_server(knowledge_store):
    """Create TrustGraphMCPServer instance."""
    return TrustGraphMCPServer(knowledge_store=knowledge_store)


@pytest.fixture
def sample_entities():
    """Create sample entities for testing."""
    return [
        KnowledgeEntity(
            entity_id="svc_prod_api",
            core_id=1,
            entity_type="Service",
            name="Production API",
            properties={"criticality": "critical", "owner": "backend-team", "env": "prod"},
            org_id="org_123",
        ),
        KnowledgeEntity(
            entity_id="svc_web_app",
            core_id=1,
            entity_type="Service",
            name="Web Application",
            properties={"criticality": "high", "owner": "frontend-team", "env": "prod"},
            org_id="org_123",
        ),
        KnowledgeEntity(
            entity_id="cve_2024_1234",
            core_id=2,
            entity_type="CVE",
            name="Critical RCE in Log4j",
            properties={"severity": "critical", "cvss": 9.8, "affected": ["Log4j 2.0-2.14"]},
            org_id="org_123",
        ),
        KnowledgeEntity(
            entity_id="control_ac_1",
            core_id=3,
            entity_type="Control",
            name="Access Control - AC-1",
            properties={"framework": "NIST", "status": "implemented", "evidence_count": 5},
            org_id="org_123",
        ),
        KnowledgeEntity(
            entity_id="verdict_001",
            core_id=4,
            entity_type="Verdict",
            name="Council Decision on Finding #456",
            properties={"decision": "false_positive", "confidence": 0.95},
            org_id="org_123",
        ),
        KnowledgeEntity(
            entity_id="competitor_acme",
            core_id=5,
            entity_type="Competitor",
            name="ACME Security Inc.",
            properties={"market_share": "15%", "pricing_model": "per_user"},
            org_id="org_123",
        ),
    ]


# ============================================================================
# KnowledgeStore Tests
# ============================================================================


class TestKnowledgeStoreBasics:
    """Test basic CRUD operations."""

    def test_ingest_entity(self, knowledge_store, sample_entities):
        """Test ingesting an entity."""
        entity = sample_entities[0]
        knowledge_store.ingest(entity)

        retrieved = knowledge_store.get_entity(entity.entity_id)
        assert retrieved is not None
        assert retrieved.entity_id == entity.entity_id
        assert retrieved.name == entity.name
        assert retrieved.core_id == entity.core_id

    def test_get_nonexistent_entity(self, knowledge_store):
        """Test retrieving non-existent entity."""
        entity = knowledge_store.get_entity("nonexistent")
        assert entity is None

    def test_update_entity(self, knowledge_store, sample_entities):
        """Test updating an entity."""
        entity = sample_entities[0]
        knowledge_store.ingest(entity)

        # Update entity
        entity.properties["criticality"] = "maximum"
        knowledge_store.ingest(entity)

        retrieved = knowledge_store.get_entity(entity.entity_id)
        assert retrieved.properties["criticality"] == "maximum"

    def test_soft_delete_entity(self, knowledge_store, sample_entities):
        """Test soft delete of entity."""
        entity = sample_entities[0]
        knowledge_store.ingest(entity)

        knowledge_store.delete_entity(entity.entity_id)

        retrieved = knowledge_store.get_entity(entity.entity_id)
        assert retrieved is None

    def test_entity_to_dict(self, sample_entities):
        """Test entity serialization."""
        entity = sample_entities[0]
        d = entity.to_dict()

        assert d["entity_id"] == entity.entity_id
        assert d["name"] == entity.name
        assert isinstance(d["created_at"], str)


# ============================================================================
# KnowledgeStore Search Tests
# ============================================================================


class TestKnowledgeStoreSearch:
    """Test full-text search functionality."""

    def test_fts_search_by_name(self, knowledge_store, sample_entities):
        """Test FTS search by entity name."""
        for entity in sample_entities[:2]:
            knowledge_store.ingest(entity)

        results = knowledge_store.search(core_id=1, query_text="Production")
        assert len(results) > 0
        assert any(r.entity_id == "svc_prod_api" for r in results)

    def test_fts_search_by_properties(self, knowledge_store, sample_entities):
        """Test FTS search by properties."""
        for entity in sample_entities[:2]:
            knowledge_store.ingest(entity)

        results = knowledge_store.search(core_id=1, query_text="critical")
        assert len(results) > 0

    def test_search_with_entity_type_filter(self, knowledge_store, sample_entities):
        """Test search with entity type filter."""
        for entity in sample_entities[:2]:
            knowledge_store.ingest(entity)

        results = knowledge_store.search(
            core_id=1,
            query_text="prod",
            filters={"entity_type": "Service"},
        )
        assert all(r.entity_type == "Service" for r in results)

    def test_search_with_org_id_filter(self, knowledge_store, sample_entities):
        """Test search with org_id filter."""
        knowledge_store.ingest(sample_entities[0])

        # Search with matching org_id
        results = knowledge_store.search(
            core_id=1,
            query_text="Production",
            filters={"org_id": "org_123"},
        )
        assert len(results) == 1

        # Search with non-matching org_id
        results = knowledge_store.search(
            core_id=1,
            query_text="Production",
            filters={"org_id": "org_456"},
        )
        assert len(results) == 0

    def test_search_limit(self, knowledge_store, sample_entities):
        """Test search result limit."""
        for entity in sample_entities[:3]:
            knowledge_store.ingest(entity)

        results = knowledge_store.search(core_id=1, query_text="", limit=1)
        assert len(results) <= 1

    def test_search_across_cores(self, knowledge_store, sample_entities):
        """Test that searches respect core boundaries."""
        for entity in sample_entities:
            knowledge_store.ingest(entity)

        # Search core 1
        results_core1 = knowledge_store.search(core_id=1, query_text="prod")
        # Search core 2
        results_core2 = knowledge_store.search(core_id=2, query_text="prod")

        assert all(r.core_id == 1 for r in results_core1)
        assert all(r.core_id == 2 for r in results_core2)


# ============================================================================
# KnowledgeStore Relationship Tests
# ============================================================================


class TestKnowledgeStoreRelationships:
    """Test relationship management."""

    def test_add_relationship(self, knowledge_store, sample_entities):
        """Test adding a relationship."""
        for entity in sample_entities[:2]:
            knowledge_store.ingest(entity)

        rel = KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="svc_web_app",
            rel_type="depends_on",
            confidence=0.95,
        )
        knowledge_store.add_relationship(rel)

        rels = knowledge_store.get_relationships("svc_prod_api")
        assert len(rels) > 0
        assert any(r.rel_id == "rel_001" for r in rels)

    def test_get_relationships_by_type(self, knowledge_store, sample_entities):
        """Test filtering relationships by type."""
        for entity in sample_entities[:2]:
            knowledge_store.ingest(entity)

        rel1 = KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="svc_web_app",
            rel_type="depends_on",
        )
        rel2 = KnowledgeRelationship(
            rel_id="rel_002",
            source_id="svc_prod_api",
            target_id="svc_web_app",
            rel_type="owns",
        )

        knowledge_store.add_relationship(rel1)
        knowledge_store.add_relationship(rel2)

        rels = knowledge_store.get_relationships("svc_prod_api", rel_type="depends_on")
        assert len(rels) == 1
        assert rels[0].rel_type == "depends_on"

    def test_bidirectional_relationships(self, knowledge_store, sample_entities):
        """Test that relationships are returned in both directions."""
        for entity in sample_entities[:2]:
            knowledge_store.ingest(entity)

        rel = KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="svc_web_app",
            rel_type="depends_on",
        )
        knowledge_store.add_relationship(rel)

        # Get relationships from source
        rels_from_source = knowledge_store.get_relationships("svc_prod_api")
        assert len(rels_from_source) > 0

        # Get relationships from target
        rels_from_target = knowledge_store.get_relationships("svc_web_app")
        assert len(rels_from_target) > 0

    def test_relationship_confidence(self, knowledge_store, sample_entities):
        """Test relationship confidence scoring."""
        for entity in sample_entities[:2]:
            knowledge_store.ingest(entity)

        rel = KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="svc_web_app",
            rel_type="depends_on",
            confidence=0.75,
        )
        knowledge_store.add_relationship(rel)

        rels = knowledge_store.get_relationships("svc_prod_api")
        assert rels[0].confidence == 0.75

    def test_invalid_relationship_confidence(self, sample_entities):
        """Test that invalid confidence scores are rejected."""
        with pytest.raises(ValueError):
            KnowledgeRelationship(
                rel_id="rel_001",
                source_id="svc_prod_api",
                target_id="svc_web_app",
                rel_type="depends_on",
                confidence=1.5,  # Invalid: > 1
            )


# ============================================================================
# KnowledgeStore Graph Traversal Tests
# ============================================================================


class TestKnowledgeStoreGraphTraversal:
    """Test graph traversal functionality."""

    def test_get_neighbors_depth_1(self, knowledge_store, sample_entities):
        """Test getting direct neighbors."""
        for entity in sample_entities[:3]:
            knowledge_store.ingest(entity)

        # Create relationships
        rel1 = KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="svc_web_app",
            rel_type="depends_on",
        )
        rel2 = KnowledgeRelationship(
            rel_id="rel_002",
            source_id="svc_prod_api",
            target_id="cve_2024_1234",
            rel_type="affected_by",
        )

        knowledge_store.add_relationship(rel1)
        knowledge_store.add_relationship(rel2)

        neighbors = knowledge_store.get_neighbors("svc_prod_api", depth=1)
        neighbor_ids = [n.entity_id for n in neighbors]

        assert "svc_web_app" in neighbor_ids
        assert "cve_2024_1234" in neighbor_ids

    def test_get_neighbors_depth_2(self, knowledge_store, sample_entities):
        """Test graph traversal at depth 2."""
        for entity in sample_entities[:4]:
            knowledge_store.ingest(entity)

        # Create chain: svc_prod_api -> svc_web_app -> cve_2024_1234
        rel1 = KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="svc_web_app",
            rel_type="depends_on",
        )
        rel2 = KnowledgeRelationship(
            rel_id="rel_002",
            source_id="svc_web_app",
            target_id="cve_2024_1234",
            rel_type="affected_by",
        )

        knowledge_store.add_relationship(rel1)
        knowledge_store.add_relationship(rel2)

        neighbors = knowledge_store.get_neighbors("svc_prod_api", depth=2)
        neighbor_ids = [n.entity_id for n in neighbors]

        # Should include both direct and 2-hop neighbors
        assert "svc_web_app" in neighbor_ids

    def test_no_neighbors(self, knowledge_store, sample_entities):
        """Test entity with no relationships."""
        knowledge_store.ingest(sample_entities[0])

        neighbors = knowledge_store.get_neighbors("svc_prod_api")
        assert len(neighbors) == 0


# ============================================================================
# KnowledgeStore Statistics Tests
# ============================================================================


class TestKnowledgeStoreStats:
    """Test core statistics."""

    def test_core_stats_empty(self, knowledge_store):
        """Test stats for empty core."""
        stats = knowledge_store.core_stats(1)

        assert stats["entity_count"] == 0
        assert stats["relationship_count"] == 0
        assert stats["core_id"] == 1

    def test_core_stats_with_entities(self, knowledge_store, sample_entities):
        """Test stats with entities."""
        for entity in sample_entities[:2]:
            knowledge_store.ingest(entity)

        stats = knowledge_store.core_stats(1)

        assert stats["entity_count"] == 2
        assert "Service" in stats["entity_types"]
        assert stats["entity_types"]["Service"] == 2

    def test_core_stats_with_relationships(self, knowledge_store, sample_entities):
        """Test stats including relationships."""
        for entity in sample_entities[:2]:
            knowledge_store.ingest(entity)

        rel = KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="svc_web_app",
            rel_type="depends_on",
        )
        knowledge_store.add_relationship(rel)

        stats = knowledge_store.core_stats(1)

        assert stats["entity_count"] == 2
        assert stats["relationship_count"] == 1

    def test_core_stats_type_breakdown(self, knowledge_store, sample_entities):
        """Test entity type breakdown in stats."""
        for entity in sample_entities[:4]:
            knowledge_store.ingest(entity)

        stats_core1 = knowledge_store.core_stats(1)
        assert stats_core1["entity_types"]["Service"] == 2

        stats_core3 = knowledge_store.core_stats(3)
        assert stats_core3["entity_types"]["Control"] == 1


# ============================================================================
# TrustGraphMCPServer Tests
# ============================================================================


class TestTrustGraphMCPServerTools:
    """Test MCP tool execution."""

    def test_list_tools(self, mcp_server):
        """Test listing available tools."""
        tools = mcp_server.list_tools()

        tool_names = [t["name"] for t in tools]
        assert "trustgraph.query" in tool_names
        assert "trustgraph.ingest" in tool_names
        assert "trustgraph.search" in tool_names
        assert "trustgraph.relate" in tool_names
        assert "trustgraph.get_entity" in tool_names
        assert "trustgraph.list_cores" in tool_names
        assert "trustgraph.core_stats" in tool_names

    def test_tool_ingest(self, mcp_server):
        """Test ingest tool."""
        result = mcp_server.call_tool(
            "trustgraph.ingest",
            {
                "entity_id": "svc_test",
                "core_id": 1,
                "entity_type": "Service",
                "name": "Test Service",
                "properties": {"env": "test"},
            },
            org_id="org_123",
        )

        assert result["status"] == "ingested"
        assert result["entity_id"] == "svc_test"

    def test_tool_search(self, mcp_server, sample_entities):
        """Test search tool."""
        for entity in sample_entities[:2]:
            mcp_server.knowledge_store.ingest(entity)

        result = mcp_server.call_tool(
            "trustgraph.search",
            {
                "core_id": 1,
                "query": "Production",
            },
            org_id="org_123",
        )

        assert result["count"] > 0
        assert "results" in result

    def test_tool_relate(self, mcp_server, sample_entities):
        """Test relate tool."""
        for entity in sample_entities[:2]:
            mcp_server.knowledge_store.ingest(entity)

        result = mcp_server.call_tool(
            "trustgraph.relate",
            {
                "source_id": "svc_prod_api",
                "target_id": "svc_web_app",
                "rel_type": "depends_on",
                "confidence": 0.95,
            },
        )

        assert result["status"] == "related"
        assert result["rel_type"] == "depends_on"

    def test_tool_get_entity(self, mcp_server, sample_entities):
        """Test get_entity tool."""
        mcp_server.knowledge_store.ingest(sample_entities[0])

        result = mcp_server.call_tool(
            "trustgraph.get_entity",
            {
                "entity_id": "svc_prod_api",
            },
        )

        assert "entity" in result
        assert result["entity"]["entity_id"] == "svc_prod_api"

    def test_tool_get_entity_not_found(self, mcp_server):
        """Test get_entity tool with non-existent entity."""
        result = mcp_server.call_tool(
            "trustgraph.get_entity",
            {
                "entity_id": "nonexistent",
            },
        )

        assert "error" in result

    def test_tool_list_cores(self, mcp_server):
        """Test list_cores tool."""
        result = mcp_server.call_tool("trustgraph.list_cores", {})

        assert "cores" in result
        assert result["total_cores"] == 5

    def test_tool_core_stats(self, mcp_server, sample_entities):
        """Test core_stats tool."""
        mcp_server.knowledge_store.ingest(sample_entities[0])

        result = mcp_server.call_tool(
            "trustgraph.core_stats",
            {
                "core_id": 1,
            },
        )

        assert result["core_id"] == 1
        assert "stats" in result
        assert result["stats"]["entity_count"] == 1

    def test_tool_audit_logging(self, mcp_server):
        """Test that tool calls are audited."""
        mcp_server.call_tool(
            "trustgraph.list_cores",
            {},
            org_id="org_123",
        )

        audit_log = mcp_server.get_audit_log(limit=1)
        assert len(audit_log) > 0
        assert audit_log[-1]["tool_id"] == "trustgraph.list_cores"
        assert audit_log[-1]["org_id"] == "org_123"
        assert audit_log[-1]["status"] == "success"


# ============================================================================
# TrustGraphMCPServer Resource Tests
# ============================================================================


class TestTrustGraphMCPServerResources:
    """Test MCP resource serving."""

    def test_list_resources(self, mcp_server):
        """Test listing available resources."""
        resources = mcp_server.list_resources()

        resource_uris = [r["uri"] for r in resources]
        assert "trustgraph://cores/{core_id}" in resource_uris

    def test_read_core_resource(self, mcp_server, sample_entities):
        """Test reading core resource."""
        mcp_server.knowledge_store.ingest(sample_entities[0])

        result = mcp_server.read_resource("trustgraph://cores/1")

        assert result["core_id"] == 1
        assert result["name"] == "Customer Environment Core"

    def test_read_entity_resource(self, mcp_server, sample_entities):
        """Test reading entity resource."""
        mcp_server.knowledge_store.ingest(sample_entities[0])

        result = mcp_server.read_resource("trustgraph://entities/svc_prod_api")

        assert "entity" in result
        assert result["entity"]["entity_id"] == "svc_prod_api"

    def test_read_relationships_resource(self, mcp_server, sample_entities):
        """Test reading relationships resource."""
        for entity in sample_entities[:2]:
            mcp_server.knowledge_store.ingest(entity)

        rel = KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="svc_web_app",
            rel_type="depends_on",
        )
        mcp_server.knowledge_store.add_relationship(rel)

        result = mcp_server.read_resource("trustgraph://relationships/svc_prod_api")

        assert result["entity_id"] == "svc_prod_api"
        assert "relationships" in result
        assert len(result["relationships"]) > 0

    def test_read_invalid_resource(self, mcp_server):
        """Test reading invalid resource."""
        result = mcp_server.read_resource("trustgraph://invalid/123")

        assert "error" in result


# ============================================================================
# Multi-Tenant Tests
# ============================================================================


class TestMultiTenant:
    """Test multi-tenant support."""

    def test_search_respects_org_id(self, knowledge_store):
        """Test that search respects org_id boundaries."""
        entity1 = KnowledgeEntity(
            entity_id="svc_001",
            core_id=1,
            entity_type="Service",
            name="Service 1",
            org_id="org_123",
        )
        entity2 = KnowledgeEntity(
            entity_id="svc_002",
            core_id=1,
            entity_type="Service",
            name="Service 2",
            org_id="org_456",
        )

        knowledge_store.ingest(entity1)
        knowledge_store.ingest(entity2)

        # Search org_123
        results_123 = knowledge_store.search(
            core_id=1,
            query_text="Service",
            filters={"org_id": "org_123"},
        )
        assert len(results_123) == 1
        assert results_123[0].org_id == "org_123"

        # Search org_456
        results_456 = knowledge_store.search(
            core_id=1,
            query_text="Service",
            filters={"org_id": "org_456"},
        )
        assert len(results_456) == 1
        assert results_456[0].org_id == "org_456"

    def test_tool_ingest_respects_org_id(self, mcp_server):
        """Test that tool ingest respects org_id."""
        mcp_server.call_tool(
            "trustgraph.ingest",
            {
                "entity_id": "svc_001",
                "core_id": 1,
                "entity_type": "Service",
                "name": "Service 1",
            },
            org_id="org_123",
        )

        entity = mcp_server.knowledge_store.get_entity("svc_001")
        assert entity.org_id == "org_123"


# ============================================================================
# Cross-Core Query Tests
# ============================================================================


class TestCrossCoreQueries:
    """Test cross-core relationship and querying."""

    def test_cross_core_relationship(self, knowledge_store, sample_entities):
        """Test creating relationships across cores."""
        # Ingest entities from different cores
        knowledge_store.ingest(sample_entities[0])  # Core 1
        knowledge_store.ingest(sample_entities[2])  # Core 2

        # Create cross-core relationship
        rel = KnowledgeRelationship(
            rel_id="rel_cross",
            source_id="svc_prod_api",  # Core 1
            target_id="cve_2024_1234",  # Core 2
            rel_type="affected_by",
            confidence=0.99,
        )
        knowledge_store.add_relationship(rel)

        # Verify relationship was created
        rels = knowledge_store.get_relationships("svc_prod_api")
        assert len(rels) > 0
        assert any(r.target_id == "cve_2024_1234" for r in rels)

    def test_cross_core_graph_traversal(self, knowledge_store, sample_entities):
        """Test graph traversal across cores."""
        # Setup entities and relationships across cores
        knowledge_store.ingest(sample_entities[0])  # Core 1: Service
        knowledge_store.ingest(sample_entities[2])  # Core 2: CVE
        knowledge_store.ingest(sample_entities[3])  # Core 3: Control

        # Create cross-core relationships
        rel1 = KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="cve_2024_1234",
            rel_type="affected_by",
        )
        rel2 = KnowledgeRelationship(
            rel_id="rel_002",
            source_id="cve_2024_1234",
            target_id="control_ac_1",
            rel_type="mitigated_by",
        )

        knowledge_store.add_relationship(rel1)
        knowledge_store.add_relationship(rel2)

        # Traverse from service
        neighbors = knowledge_store.get_neighbors("svc_prod_api", depth=2)
        neighbor_ids = [n.entity_id for n in neighbors]

        assert "cve_2024_1234" in neighbor_ids
        assert "control_ac_1" in neighbor_ids


# ============================================================================
# Data Integrity Tests
# ============================================================================


class TestDataIntegrity:
    """Test data integrity and edge cases."""

    def test_relationship_with_same_source_target(self, knowledge_store, sample_entities):
        """Test self-referencing relationship."""
        knowledge_store.ingest(sample_entities[0])

        rel = KnowledgeRelationship(
            rel_id="rel_self",
            source_id="svc_prod_api",
            target_id="svc_prod_api",
            rel_type="related_to",
        )

        knowledge_store.add_relationship(rel)

        rels = knowledge_store.get_relationships("svc_prod_api")
        assert len(rels) > 0

    def test_duplicate_relationships(self, knowledge_store, sample_entities):
        """Test that duplicate relationships are replaced."""
        for entity in sample_entities[:2]:
            knowledge_store.ingest(entity)

        rel = KnowledgeRelationship(
            rel_id="rel_001",
            source_id="svc_prod_api",
            target_id="svc_web_app",
            rel_type="depends_on",
            confidence=0.90,
        )

        knowledge_store.add_relationship(rel)

        # Add same relationship with different confidence
        rel.confidence = 0.95
        knowledge_store.add_relationship(rel)

        rels = knowledge_store.get_relationships("svc_prod_api")
        assert rels[0].confidence == 0.95

    def test_large_properties(self, knowledge_store):
        """Test entity with large properties object."""
        large_props = {f"prop_{i}": f"value_{i}" * 100 for i in range(100)}

        entity = KnowledgeEntity(
            entity_id="entity_large",
            core_id=1,
            entity_type="Service",
            name="Large Entity",
            properties=large_props,
        )

        knowledge_store.ingest(entity)

        retrieved = knowledge_store.get_entity("entity_large")
        assert len(retrieved.properties) == 100

    def test_unicode_in_properties(self, knowledge_store):
        """Test unicode characters in properties."""
        entity = KnowledgeEntity(
            entity_id="entity_unicode",
            core_id=1,
            entity_type="Service",
            name="Unicode Service 🔒",
            properties={"description": "Émojis and über characters", "owner": "用户"},
        )

        knowledge_store.ingest(entity)

        retrieved = knowledge_store.get_entity("entity_unicode")
        assert "🔒" in retrieved.name
        assert "用户" in retrieved.properties["owner"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
