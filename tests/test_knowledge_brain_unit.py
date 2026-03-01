"""Unit tests for knowledge_brain.py — V3 Decision Intelligence.

Tests the KnowledgeBrain knowledge graph that stores all security entities.
Uses temp SQLite DBs to avoid polluting production data.
"""

import os
import tempfile

import pytest
from core.knowledge_brain import (
    EdgeType,
    EntityType,
    GraphEdge,
    GraphNode,
    GraphQueryResult,
    KnowledgeBrain,
    get_brain,
)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------

class TestEntityType:
    def test_cve_type(self):
        assert EntityType.CVE.value == "cve"

    def test_finding_type(self):
        assert EntityType.FINDING.value == "finding"

    def test_asset_type(self):
        assert EntityType.ASSET.value == "asset"

    def test_remediation_type(self):
        assert EntityType.REMEDIATION.value == "remediation"

    def test_all_types_are_strings(self):
        for t in EntityType:
            assert isinstance(t.value, str)

    def test_type_count(self):
        assert len(EntityType) >= 10


class TestEdgeType:
    def test_affects_type(self):
        assert EdgeType.AFFECTS.value == "affects"

    def test_exploits_type(self):
        assert EdgeType.EXPLOITS.value == "exploits"

    def test_mitigates_type(self):
        assert EdgeType.MITIGATES.value == "mitigates"

    def test_all_types_are_strings(self):
        for t in EdgeType:
            assert isinstance(t.value, str)


# ---------------------------------------------------------------------------
# GraphNode dataclass (uses node_id, not id)
# ---------------------------------------------------------------------------

class TestGraphNode:
    def test_create_node(self):
        node = GraphNode(
            node_id="CVE-2024-1234",
            node_type=EntityType.CVE,
            properties={"severity": "high", "cvss": 8.5},
        )
        assert node.node_id == "CVE-2024-1234"
        assert node.node_type == EntityType.CVE

    def test_post_init_defaults(self):
        node = GraphNode(
            node_id="test-node",
            node_type=EntityType.ASSET,
        )
        assert node.node_id == "test-node"
        assert isinstance(node.properties, dict)

    def test_node_org_id(self):
        node = GraphNode(
            node_id="n1",
            node_type=EntityType.FINDING,
            org_id="org-123",
        )
        assert node.org_id == "org-123"


# ---------------------------------------------------------------------------
# GraphEdge dataclass
# ---------------------------------------------------------------------------

class TestGraphEdge:
    def test_create_edge(self):
        edge = GraphEdge(
            source_id="CVE-2024-1234",
            target_id="asset-web-1",
            edge_type=EdgeType.AFFECTS,
        )
        assert edge.source_id == "CVE-2024-1234"
        assert edge.target_id == "asset-web-1"
        assert edge.edge_type == EdgeType.AFFECTS

    def test_edge_default_confidence(self):
        edge = GraphEdge(
            source_id="a",
            target_id="b",
            edge_type=EdgeType.EXPLOITS,
        )
        assert edge.confidence == 1.0


# ---------------------------------------------------------------------------
# KnowledgeBrain
# ---------------------------------------------------------------------------

class TestKnowledgeBrain:
    def setup_method(self):
        """Create a temp DB for each test."""
        self.tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmpfile.close()
        KnowledgeBrain.reset_instance()
        self.brain = KnowledgeBrain(db_path=self.tmpfile.name)

    def teardown_method(self):
        self.brain.close()
        KnowledgeBrain.reset_instance()
        for f in [self.tmpfile.name, self.tmpfile.name + "-wal", self.tmpfile.name + "-shm"]:
            try:
                os.unlink(f)
            except OSError:
                pass

    def test_upsert_and_get_node(self):
        node = GraphNode(
            node_id="CVE-2024-0001",
            node_type=EntityType.CVE,
            properties={"severity": "critical", "cvss": 9.8},
        )
        result = self.brain.upsert_node(node)
        assert result.node_id == "CVE-2024-0001"

        retrieved = self.brain.get_node("CVE-2024-0001")
        assert retrieved is not None

    def test_get_node_not_found(self):
        result = self.brain.get_node("nonexistent-node")
        assert result is None

    def test_upsert_node_update(self):
        node1 = GraphNode(
            node_id="asset-1",
            node_type=EntityType.ASSET,
            properties={"name": "Web Server", "version": "1.0"},
        )
        self.brain.upsert_node(node1)

        node2 = GraphNode(
            node_id="asset-1",
            node_type=EntityType.ASSET,
            properties={"name": "Web Server", "version": "2.0"},
        )
        self.brain.upsert_node(node2)

        retrieved = self.brain.get_node("asset-1")
        assert retrieved is not None

    def test_delete_node(self):
        node = GraphNode(
            node_id="to-delete",
            node_type=EntityType.FINDING,
            properties={"title": "Test Finding"},
        )
        self.brain.upsert_node(node)
        assert self.brain.get_node("to-delete") is not None

        result = self.brain.delete_node("to-delete")
        assert result is True
        assert self.brain.get_node("to-delete") is None

    def test_delete_node_not_found(self):
        result = self.brain.delete_node("nonexistent")
        assert result is False

    def test_add_and_get_edges(self):
        n1 = GraphNode(node_id="cve-1", node_type=EntityType.CVE, properties={})
        n2 = GraphNode(node_id="asset-1", node_type=EntityType.ASSET, properties={})
        self.brain.upsert_node(n1)
        self.brain.upsert_node(n2)

        edge = GraphEdge(
            source_id="cve-1",
            target_id="asset-1",
            edge_type=EdgeType.AFFECTS,
        )
        result = self.brain.add_edge(edge)
        assert result is not None

        edges = self.brain.get_edges("cve-1")
        assert len(edges) >= 1

    def test_get_edges_direction_out(self):
        n1 = GraphNode(node_id="src", node_type=EntityType.CVE, properties={})
        n2 = GraphNode(node_id="tgt", node_type=EntityType.ASSET, properties={})
        self.brain.upsert_node(n1)
        self.brain.upsert_node(n2)
        self.brain.add_edge(GraphEdge(source_id="src", target_id="tgt", edge_type=EdgeType.AFFECTS))

        edges_out = self.brain.get_edges("src", direction="out")
        assert len(edges_out) >= 1

    def test_delete_edge(self):
        n1 = GraphNode(node_id="a", node_type=EntityType.CVE, properties={})
        n2 = GraphNode(node_id="b", node_type=EntityType.ASSET, properties={})
        self.brain.upsert_node(n1)
        self.brain.upsert_node(n2)
        self.brain.add_edge(GraphEdge(source_id="a", target_id="b", edge_type=EdgeType.AFFECTS))

        result = self.brain.delete_edge("a", "b", EdgeType.AFFECTS.value)
        assert result is True

    def test_query_nodes(self):
        for i in range(5):
            node = GraphNode(
                node_id=f"finding-{i}",
                node_type=EntityType.FINDING,
                properties={"severity": "high" if i % 2 == 0 else "low"},
            )
            self.brain.upsert_node(node)

        results = self.brain.query_nodes(node_type=EntityType.FINDING.value)
        assert isinstance(results, GraphQueryResult)

    def test_get_neighbors(self):
        nodes = [
            GraphNode(node_id="center", node_type=EntityType.ASSET, properties={}),
            GraphNode(node_id="n1", node_type=EntityType.CVE, properties={}),
            GraphNode(node_id="n2", node_type=EntityType.FINDING, properties={}),
        ]
        for n in nodes:
            self.brain.upsert_node(n)
        self.brain.add_edge(GraphEdge(source_id="center", target_id="n1", edge_type=EdgeType.AFFECTS))
        self.brain.add_edge(GraphEdge(source_id="center", target_id="n2", edge_type=EdgeType.AFFECTS))

        neighbors = self.brain.get_neighbors("center")
        assert isinstance(neighbors, GraphQueryResult)

    def test_stats(self):
        node = GraphNode(node_id="stat-test", node_type=EntityType.CVE, properties={})
        self.brain.upsert_node(node)
        stats = self.brain.stats()
        assert isinstance(stats, dict)

    def test_node_count(self):
        for i in range(3):
            self.brain.upsert_node(GraphNode(node_id=f"count-{i}", node_type=EntityType.ASSET, properties={}))
        count = self.brain.node_count()
        assert count >= 3

    def test_edge_count(self):
        count = self.brain.edge_count()
        assert isinstance(count, int)
        assert count >= 0

    @pytest.mark.timeout(15)
    def test_most_connected(self):
        # most_connected involves graph traversal — may be slow on fresh DB
        most = self.brain.most_connected(limit=3)
        assert isinstance(most, list)

    def test_risk_score_for_node(self):
        self.brain.upsert_node(GraphNode(node_id="scored-node", node_type=EntityType.CVE, properties={"cvss": 9.0}))
        score = self.brain.risk_score_for_node("scored-node")
        assert isinstance(score, float)

    def test_ingest_cve(self):
        result = self.brain.ingest_cve(
            cve_id="CVE-2024-9999",
            severity="critical",
            cvss=9.8,
            description="Test CVE",
        )
        assert result is not None
        # Node IDs are prefixed with entity type
        node = self.brain.get_node(result.node_id)
        assert node is not None

    def test_ingest_finding(self):
        result = self.brain.ingest_finding(
            finding_id="find-001",
            title="SQL Injection in login",
            severity="high",
            tool="sast",
        )
        assert result is not None
        node = self.brain.get_node(result.node_id)
        assert node is not None

    def test_ingest_scan(self):
        result = self.brain.ingest_scan(
            scan_id="scan-001",
            tool="sast_engine",
            target="api-service",
        )
        assert result is not None
        node = self.brain.get_node(result.node_id)
        assert node is not None

    def test_ingest_asset(self):
        result = self.brain.ingest_asset(
            asset_id="asset-web-1",
            name="Production Web Server",
            asset_type="compute",
        )
        assert result is not None
        node = self.brain.get_node(result.node_id)
        assert node is not None

    def test_ingest_remediation(self):
        result = self.brain.ingest_remediation(
            task_id="rem-001",
            finding_id="find-001",
            fix_type="code_patch",
            status="pending",
        )
        assert result is not None
        node = self.brain.get_node(result.node_id)
        assert node is not None

    def test_log_and_get_events(self):
        self.brain.log_event(
            event_type="scan_completed",
            source="sast_engine",
            data={"findings": 5, "duration_s": 12},
        )
        events = self.brain.get_events(limit=10)
        assert isinstance(events, list)

    def test_find_paths(self):
        for nid in ["path-a", "path-b", "path-c"]:
            self.brain.upsert_node(GraphNode(node_id=nid, node_type=EntityType.ASSET, properties={}))
        self.brain.add_edge(GraphEdge(source_id="path-a", target_id="path-b", edge_type=EdgeType.AFFECTS))
        self.brain.add_edge(GraphEdge(source_id="path-b", target_id="path-c", edge_type=EdgeType.AFFECTS))

        paths = self.brain.find_paths("path-a", "path-c", max_depth=5)
        assert isinstance(paths, list)

    def test_close(self):
        self.brain.close()


# ---------------------------------------------------------------------------
# Module-level function
# ---------------------------------------------------------------------------

class TestGetBrain:
    def test_get_brain_creates_instance(self):
        KnowledgeBrain.reset_instance()
        tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmpfile.close()
        try:
            brain = get_brain(db_path=tmpfile.name)
            assert isinstance(brain, KnowledgeBrain)
            brain.close()
        finally:
            KnowledgeBrain.reset_instance()
            for f in [tmpfile.name, tmpfile.name + "-wal", tmpfile.name + "-shm"]:
                try:
                    os.unlink(f)
                except OSError:
                    pass
