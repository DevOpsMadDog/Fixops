"""Coverage tests for core.knowledge_brain — KnowledgeBrain graph."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.knowledge_brain import (
    EntityType, EdgeType, GraphNode, GraphEdge, GraphQueryResult, get_brain,
)


class TestEntityType:
    def test_has_values(self):
        assert len(EntityType) > 0

    def test_cve(self):
        assert EntityType.CVE.value == "cve"

    def test_finding(self):
        assert EntityType.FINDING.value == "finding"

    def test_asset(self):
        assert EntityType.ASSET.value == "asset"


class TestEdgeType:
    def test_has_values(self):
        assert len(EdgeType) > 0

    def test_exploits(self):
        assert EdgeType.EXPLOITS.value == "exploits"

    def test_affects(self):
        assert EdgeType.AFFECTS.value == "affects"


class TestGraphNode:
    def test_creation(self):
        node = GraphNode(
            node_id="CVE-2024-001",
            node_type=EntityType.CVE,
            properties={"severity": "high"},
        )
        assert node.node_id == "CVE-2024-001"
        assert node.node_type == EntityType.CVE

    def test_defaults(self):
        node = GraphNode(
            node_id="N1",
            node_type=EntityType.ASSET,
            properties={},
        )
        assert node.org_id is None
        assert isinstance(node.created_at, str)


class TestGraphEdge:
    def test_creation(self):
        edge = GraphEdge(
            source_id="CVE-001",
            target_id="ASSET-001",
            edge_type=EdgeType.AFFECTS,
            properties={"impact": "high"},
        )
        assert edge.source_id == "CVE-001"
        assert edge.confidence == 1.0


class TestKnowledgeBrain:
    @pytest.fixture(autouse=True)
    def _reset(self):
        from core.knowledge_brain import KnowledgeBrain
        KnowledgeBrain.reset_instance()
        yield
        KnowledgeBrain.reset_instance()

    @pytest.fixture
    def brain(self, tmp_path):
        b = get_brain(db_path=str(tmp_path / "test_brain.db"))
        yield b
        b.close()

    def test_upsert_and_get_node(self, brain):
        node = GraphNode(
            node_id="CVE-2024-001",
            node_type=EntityType.CVE,
            properties={"severity": "high", "title": "Test CVE"},
        )
        brain.upsert_node(node)
        retrieved = brain.get_node("CVE-2024-001")
        assert retrieved is not None

    def test_get_node_not_found(self, brain):
        result = brain.get_node("nonexistent-node")
        assert result is None

    def test_delete_node(self, brain):
        node = GraphNode(node_id="TO-DELETE", node_type=EntityType.ASSET, properties={"temp": True})
        brain.upsert_node(node)
        brain.delete_node("TO-DELETE")
        assert brain.get_node("TO-DELETE") is None

    def test_add_and_get_edge(self, brain):
        n1 = GraphNode(node_id="N1", node_type=EntityType.CVE, properties={"a": 1})
        n2 = GraphNode(node_id="N2", node_type=EntityType.ASSET, properties={"b": 2})
        brain.upsert_node(n1)
        brain.upsert_node(n2)
        edge = GraphEdge(
            source_id="N1", target_id="N2",
            edge_type=EdgeType.AFFECTS,
            properties={"weight": 0.9},
        )
        brain.add_edge(edge)
        edges = brain.get_edges("N1")
        assert isinstance(edges, list)

    def test_get_edges_empty(self, brain):
        edges = brain.get_edges("no-such-node")
        assert isinstance(edges, list)

    def test_node_count(self, brain):
        count = brain.node_count()
        assert isinstance(count, int)

    def test_edge_count(self, brain):
        count = brain.edge_count()
        assert isinstance(count, int)

    def test_stats(self, brain):
        s = brain.stats()
        assert isinstance(s, dict)

    def test_ingest_cve(self, brain):
        node = brain.ingest_cve("CVE-2024-999", severity="critical")
        assert node is not None

    def test_ingest_finding(self, brain):
        node = brain.ingest_finding("FIND-001", cve_id="CVE-2024-999")
        assert node is not None

    def test_ingest_asset(self, brain):
        node = brain.ingest_asset("ASSET-001", hostname="web-01")
        assert node is not None

    def test_query_nodes(self, brain):
        brain.ingest_cve("CVE-2024-100")
        result = brain.query_nodes(node_type="cve")
        assert isinstance(result, GraphQueryResult)

    def test_most_connected(self, brain):
        result = brain.most_connected(limit=5)
        assert isinstance(result, list)
