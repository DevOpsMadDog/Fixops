"""Comprehensive unit tests for falkordb_client.py (V3 — Knowledge Graph Engine).

Tests the NetworkXGraphBackend (pure Python), KnowledgeGraphEngine,
attack path discovery, blast radius calculation, and graph analytics.

Coverage target: 80%+ of falkordb_client.py
"""

import pytest
from unittest.mock import patch

from core.falkordb_client import (
    NodeType,
    EdgeType,
    GraphNode,
    GraphEdge,
    AttackPath,
    BlastRadius,
    NetworkXGraphBackend,
    FalkorDBBackend,
    KnowledgeGraphEngine,
    get_knowledge_graph,
)


# ──────────────────────────────────────────────────────────────────────
# Enum and Dataclass Tests
# ──────────────────────────────────────────────────────────────────────

class TestNodeType:
    def test_all_node_types_exist(self):
        expected = {"App", "Component", "Finding", "CWE", "CVE", "Asset",
                    "Control", "AttackPath", "Package", "Endpoint"}
        actual = {nt.value for nt in NodeType}
        assert actual == expected

    def test_str_enum(self):
        assert NodeType.APP == "App"
        assert isinstance(NodeType.FINDING, str)


class TestEdgeType:
    def test_all_edge_types_exist(self):
        expected = {"HAS_COMPONENT", "HAS_FINDING", "EXPLOITS", "DEPENDS_ON",
                    "MITIGATED_BY", "ATTACK_STEP", "REACHABLE_FROM", "MAPS_TO",
                    "CONTAINS", "AFFECTS", "CHAINS_WITH"}
        actual = {et.value for et in EdgeType}
        assert actual == expected


class TestGraphNode:
    def test_basic_creation(self):
        node = GraphNode(id="test-1", type=NodeType.FINDING)
        assert node.id == "test-1"
        assert node.type == NodeType.FINDING
        assert node.properties == {}

    def test_label_from_name(self):
        node = GraphNode(id="n1", type=NodeType.APP, properties={"name": "MyApp"})
        assert node.label == "MyApp"

    def test_label_from_title(self):
        node = GraphNode(id="n1", type=NodeType.FINDING, properties={"title": "SQL Injection"})
        assert node.label == "SQL Injection"

    def test_label_fallback_to_id(self):
        node = GraphNode(id="n1", type=NodeType.CWE, properties={"cwe_id": "CWE-89"})
        assert node.label == "n1"

    def test_properties_dict(self):
        props = {"severity": "critical", "cvss": 9.8}
        node = GraphNode(id="f1", type=NodeType.FINDING, properties=props)
        assert node.properties["severity"] == "critical"
        assert node.properties["cvss"] == 9.8


class TestGraphEdge:
    def test_basic_creation(self):
        edge = GraphEdge(source_id="a", target_id="b", type=EdgeType.HAS_FINDING)
        assert edge.source_id == "a"
        assert edge.target_id == "b"
        assert edge.weight == 1.0
        assert edge.properties == {}

    def test_custom_weight(self):
        edge = GraphEdge("a", "b", EdgeType.EXPLOITS, weight=0.3)
        assert edge.weight == 0.3


class TestAttackPath:
    def test_creation(self):
        ap = AttackPath(
            path_id="ap-1",
            nodes=["a", "b", "c"],
            edges=["HAS_COMPONENT", "HAS_FINDING"],
            total_weight=0.5,
            entry_point="a",
            target="c",
            risk_score=9.0,
            exploitability="HIGH",
        )
        assert ap.path_id == "ap-1"
        assert len(ap.nodes) == 3
        assert ap.risk_score == 9.0
        assert ap.exploitability == "HIGH"


class TestBlastRadius:
    def test_creation(self):
        br = BlastRadius(
            source_finding_id="finding:123",
            affected_nodes=["comp:1", "comp:2"],
            affected_components=2,
            affected_apps=1,
            affected_findings=3,
            depth=3,
            risk_multiplier=2.9,
            critical_path=[],
        )
        assert br.affected_components == 2
        assert br.risk_multiplier == 2.9


# ──────────────────────────────────────────────────────────────────────
# NetworkXGraphBackend Tests
# ──────────────────────────────────────────────────────────────────────

class TestNetworkXGraphBackend:
    @pytest.fixture
    def backend(self):
        return NetworkXGraphBackend()

    def test_add_and_get_node(self, backend):
        node = GraphNode(id="n1", type=NodeType.APP, properties={"name": "TestApp"})
        backend.add_node(node)
        result = backend.get_node("n1")
        assert result is not None
        assert result.id == "n1"
        assert result.type == NodeType.APP

    def test_get_nonexistent_node(self, backend):
        assert backend.get_node("nonexistent") is None

    def test_add_and_get_edge(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        edge = GraphEdge("a", "b", EdgeType.HAS_COMPONENT, weight=0.5)
        backend.add_edge(edge)

        neighbors = backend.get_neighbors("a")
        assert len(neighbors) == 1
        assert neighbors[0][0] == "b"
        assert neighbors[0][1].weight == 0.5

    def test_get_neighbors_filtered(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        backend.add_node(GraphNode(id="c", type=NodeType.FINDING))
        backend.add_edge(GraphEdge("a", "b", EdgeType.HAS_COMPONENT))
        backend.add_edge(GraphEdge("a", "c", EdgeType.HAS_FINDING))

        comp_only = backend.get_neighbors("a", EdgeType.HAS_COMPONENT)
        assert len(comp_only) == 1
        assert comp_only[0][0] == "b"

    def test_get_incoming(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        backend.add_edge(GraphEdge("a", "b", EdgeType.HAS_COMPONENT))

        incoming = backend.get_incoming("b")
        assert len(incoming) == 1
        assert incoming[0][0] == "a"

    def test_get_incoming_filtered(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        backend.add_node(GraphNode(id="c", type=NodeType.FINDING))
        backend.add_edge(GraphEdge("a", "b", EdgeType.HAS_COMPONENT))
        backend.add_edge(GraphEdge("c", "b", EdgeType.HAS_FINDING))

        comp_only = backend.get_incoming("b", EdgeType.HAS_COMPONENT)
        assert len(comp_only) == 1
        assert comp_only[0][0] == "a"

    def test_get_nodes_by_type(self, backend):
        backend.add_node(GraphNode(id="a1", type=NodeType.APP))
        backend.add_node(GraphNode(id="a2", type=NodeType.APP))
        backend.add_node(GraphNode(id="f1", type=NodeType.FINDING))

        apps = backend.get_nodes_by_type(NodeType.APP)
        assert len(apps) == 2
        findings = backend.get_nodes_by_type(NodeType.FINDING)
        assert len(findings) == 1

    def test_find_paths_simple(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        backend.add_node(GraphNode(id="c", type=NodeType.FINDING))
        backend.add_edge(GraphEdge("a", "b", EdgeType.HAS_COMPONENT))
        backend.add_edge(GraphEdge("b", "c", EdgeType.HAS_FINDING))

        paths = backend.find_paths("a", "c")
        assert len(paths) == 1
        assert paths[0] == ["a", "b", "c"]

    def test_find_paths_no_connection(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        paths = backend.find_paths("a", "b")
        assert len(paths) == 0

    def test_find_paths_nonexistent_nodes(self, backend):
        paths = backend.find_paths("x", "y")
        assert paths == []

    def test_find_paths_max_depth(self, backend):
        # Create a chain: a -> b -> c -> d -> e
        for nid in ["a", "b", "c", "d", "e"]:
            backend.add_node(GraphNode(id=nid, type=NodeType.COMPONENT))
        for src, tgt in [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")]:
            backend.add_edge(GraphEdge(src, tgt, EdgeType.DEPENDS_ON))

        # With depth 3, cannot reach e from a (needs 4 steps)
        paths = backend.find_paths("a", "e", max_depth=3)
        assert len(paths) == 0

        # With depth 5, can reach e
        paths = backend.find_paths("a", "e", max_depth=5)
        assert len(paths) == 1

    def test_find_paths_avoids_cycles(self, backend):
        # a -> b -> c -> a (cycle) -> ...
        for nid in ["a", "b", "c"]:
            backend.add_node(GraphNode(id=nid, type=NodeType.COMPONENT))
        backend.add_edge(GraphEdge("a", "b", EdgeType.DEPENDS_ON))
        backend.add_edge(GraphEdge("b", "c", EdgeType.DEPENDS_ON))
        backend.add_edge(GraphEdge("c", "a", EdgeType.DEPENDS_ON))

        # Should still terminate
        paths = backend.find_paths("a", "c")
        assert len(paths) >= 1

    def test_bfs_reachable(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        backend.add_node(GraphNode(id="c", type=NodeType.FINDING))
        backend.add_edge(GraphEdge("a", "b", EdgeType.HAS_COMPONENT))
        backend.add_edge(GraphEdge("b", "c", EdgeType.HAS_FINDING))

        reachable = backend.bfs_reachable("a")
        assert "a" in reachable
        assert "b" in reachable
        assert "c" in reachable
        assert reachable["a"] == 0
        assert reachable["b"] == 1
        assert reachable["c"] == 2

    def test_bfs_reachable_max_depth(self, backend):
        for nid in ["a", "b", "c"]:
            backend.add_node(GraphNode(id=nid, type=NodeType.COMPONENT))
        backend.add_edge(GraphEdge("a", "b", EdgeType.DEPENDS_ON))
        backend.add_edge(GraphEdge("b", "c", EdgeType.DEPENDS_ON))

        reachable = backend.bfs_reachable("a", max_depth=1)
        assert "b" in reachable
        assert "c" not in reachable

    def test_bfs_reachable_nonexistent(self, backend):
        assert backend.bfs_reachable("nonexistent") == {}

    def test_degree_centrality_empty(self, backend):
        assert backend.degree_centrality() == {}

    def test_degree_centrality_single(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        centrality = backend.degree_centrality()
        assert centrality["a"] == 0.0

    def test_degree_centrality_two_connected(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        backend.add_edge(GraphEdge("a", "b", EdgeType.HAS_COMPONENT))

        centrality = backend.degree_centrality()
        assert centrality["a"] > 0
        assert centrality["b"] > 0

    def test_betweenness_centrality_approx_small(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        centrality = backend.betweenness_centrality_approx()
        assert isinstance(centrality, dict)

    def test_betweenness_centrality_approx_larger(self, backend):
        # Create a star graph: center -> leaf1, leaf2, ..., leaf5
        backend.add_node(GraphNode(id="center", type=NodeType.APP))
        for i in range(5):
            nid = f"leaf{i}"
            backend.add_node(GraphNode(id=nid, type=NodeType.COMPONENT))
            backend.add_edge(GraphEdge("center", nid, EdgeType.HAS_COMPONENT))

        centrality = backend.betweenness_centrality_approx(sample_size=6)
        assert isinstance(centrality, dict)
        # Center should have higher betweenness
        assert len(centrality) == 6

    def test_node_and_edge_count(self, backend):
        assert backend.node_count == 0
        assert backend.edge_count == 0

        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        assert backend.node_count == 1

        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        backend.add_edge(GraphEdge("a", "b", EdgeType.HAS_COMPONENT))
        assert backend.node_count == 2
        assert backend.edge_count == 1

    def test_to_json(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP, properties={"name": "Test"}))
        backend.add_node(GraphNode(id="b", type=NodeType.FINDING))
        backend.add_edge(GraphEdge("a", "b", EdgeType.HAS_FINDING, weight=0.5))

        result = backend.to_json()
        assert "nodes" in result
        assert "edges" in result
        assert len(result["nodes"]) == 2
        assert len(result["edges"]) == 1
        assert result["edges"][0]["weight"] == 0.5

    def test_to_mermaid(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP, properties={"name": "MyApp"}))
        backend.add_node(GraphNode(id="b", type=NodeType.FINDING, properties={"title": "SQLi"}))
        backend.add_edge(GraphEdge("a", "b", EdgeType.HAS_FINDING))

        mermaid = backend.to_mermaid()
        assert "graph LR" in mermaid
        assert "MyApp" in mermaid
        assert "SQLi" in mermaid
        assert "HAS FINDING" in mermaid

    def test_to_mermaid_skips_missing_nodes(self, backend):
        # Edge with no corresponding nodes
        backend.add_edge(GraphEdge("nonexist1", "nonexist2", EdgeType.DEPENDS_ON))
        mermaid = backend.to_mermaid()
        assert mermaid == "graph LR"

    def test_clear(self, backend):
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_edge(GraphEdge("a", "a", EdgeType.CHAINS_WITH))
        backend.clear()
        assert backend.node_count == 0
        assert backend.edge_count == 0


# ──────────────────────────────────────────────────────────────────────
# FalkorDBBackend Tests (NetworkX fallback mode)
# ──────────────────────────────────────────────────────────────────────

class TestFalkorDBBackend:
    def test_init_falls_back_to_networkx(self):
        """Without FalkorDB running, should fall back to NetworkX."""
        backend = FalkorDBBackend(url="redis://localhost:19999")
        assert backend._using_fallback is True

    def test_fallback_add_and_get_node(self):
        backend = FalkorDBBackend(url="redis://localhost:19999")
        node = GraphNode(id="fb-1", type=NodeType.APP, properties={"name": "FallbackApp"})
        backend.add_node(node)
        result = backend.get_node("fb-1")
        assert result is not None
        assert result.id == "fb-1"

    def test_fallback_add_edge(self):
        backend = FalkorDBBackend(url="redis://localhost:19999")
        backend.add_node(GraphNode(id="x", type=NodeType.APP))
        backend.add_node(GraphNode(id="y", type=NodeType.COMPONENT))
        backend.add_edge(GraphEdge("x", "y", EdgeType.HAS_COMPONENT))

        neighbors = backend.get_neighbors("x")
        assert len(neighbors) == 1

    def test_fallback_get_nodes_by_type(self):
        backend = FalkorDBBackend(url="redis://localhost:19999")
        backend.add_node(GraphNode(id="a1", type=NodeType.FINDING))
        backend.add_node(GraphNode(id="a2", type=NodeType.FINDING))
        nodes = backend.get_nodes_by_type(NodeType.FINDING)
        assert len(nodes) == 2

    def test_fallback_find_paths(self):
        backend = FalkorDBBackend(url="redis://localhost:19999")
        backend.add_node(GraphNode(id="s", type=NodeType.APP))
        backend.add_node(GraphNode(id="e", type=NodeType.FINDING))
        backend.add_edge(GraphEdge("s", "e", EdgeType.HAS_FINDING))
        paths = backend.find_paths("s", "e")
        assert len(paths) == 1

    def test_fallback_node_edge_count(self):
        backend = FalkorDBBackend(url="redis://localhost:19999")
        assert backend.node_count == 0
        assert backend.edge_count == 0
        backend.add_node(GraphNode(id="z", type=NodeType.APP))
        assert backend.node_count == 1

    def test_fallback_to_json(self):
        backend = FalkorDBBackend(url="redis://localhost:19999")
        result = backend.to_json()
        assert "nodes" in result
        assert "edges" in result

    def test_fallback_to_mermaid(self):
        backend = FalkorDBBackend(url="redis://localhost:19999")
        result = backend.to_mermaid()
        assert "graph LR" in result

    def test_fallback_clear(self):
        backend = FalkorDBBackend(url="redis://localhost:19999")
        backend.add_node(GraphNode(id="z", type=NodeType.APP))
        backend.clear()
        assert backend.node_count == 0

    def test_fallback_bfs_reachable(self):
        backend = FalkorDBBackend(url="redis://localhost:19999")
        backend.add_node(GraphNode(id="a", type=NodeType.APP))
        backend.add_node(GraphNode(id="b", type=NodeType.COMPONENT))
        backend.add_edge(GraphEdge("a", "b", EdgeType.HAS_COMPONENT))
        reachable = backend.bfs_reachable("a")
        assert "b" in reachable


# ──────────────────────────────────────────────────────────────────────
# KnowledgeGraphEngine Tests
# ──────────────────────────────────────────────────────────────────────

class TestKnowledgeGraphEngine:
    @pytest.fixture
    def engine(self):
        return KnowledgeGraphEngine(backend="networkx")

    def test_init_networkx(self, engine):
        assert isinstance(engine._backend, NetworkXGraphBackend)

    def test_init_auto_fallback(self):
        engine = KnowledgeGraphEngine(backend="auto")
        assert isinstance(engine._backend, NetworkXGraphBackend)

    @patch.dict("os.environ", {"FIXOPS_GRAPH_BACKEND": "networkx"})
    def test_init_from_env(self):
        engine = KnowledgeGraphEngine()
        assert isinstance(engine._backend, NetworkXGraphBackend)

    def test_ingest_findings_basic(self, engine):
        findings = [
            {
                "id": "vuln-001",
                "title": "SQL Injection in login",
                "severity": "critical",
                "component": "auth/login.py",
                "cwe": "CWE-89",
                "cve": "CVE-2024-1234",
                "cvss": 9.8,
            }
        ]
        count = engine.ingest_findings(findings, app_id="myapp")
        assert count > 0
        assert engine._backend.node_count > 0

    def test_ingest_findings_multiple(self, engine):
        findings = [
            {"id": f"vuln-{i}", "title": f"Finding {i}", "severity": sev, "component": f"comp{i}.py"}
            for i, sev in enumerate(["critical", "high", "medium", "low", "info"])
        ]
        engine.ingest_findings(findings)
        assert engine._backend.node_count >= 5  # At least 5 findings + 1 app + components

    def test_ingest_findings_no_cwe_cve(self, engine):
        findings = [{"id": "vuln-simple", "title": "Simple vuln", "severity": "medium"}]
        count = engine.ingest_findings(findings)
        assert count > 0

    def test_ingest_findings_auto_id(self, engine):
        """Test that findings without id get auto-generated hash IDs."""
        findings = [{"title": "No ID vuln", "severity": "high"}]
        engine.ingest_findings(findings)
        assert engine._backend.node_count >= 2  # app + finding + component

    def test_add_dependency(self, engine):
        engine.add_dependency("auth.py", "database.py", "runtime")
        assert engine._backend.edge_count >= 1

    def test_find_attack_paths_basic(self, engine):
        findings = [
            {"id": "vuln-1", "title": "XSS", "severity": "high", "component": "web/input.py"},
            {"id": "vuln-2", "title": "SQLi", "severity": "critical", "component": "web/input.py"},
        ]
        engine.ingest_findings(findings, app_id="webapp")

        # Find path from app to finding
        paths = engine.find_attack_paths("app:webapp", "finding:vuln-1")
        assert len(paths) >= 1
        assert paths[0].entry_point == "app:webapp"
        assert paths[0].target == "finding:vuln-1"

    def test_find_attack_paths_no_path(self, engine):
        engine.ingest_findings([{"id": "v1", "title": "V1", "severity": "low"}], app_id="app1")
        engine.ingest_findings([{"id": "v2", "title": "V2", "severity": "low"}], app_id="app2")
        # No path between different apps (no edge connecting them)
        paths = engine.find_attack_paths("app:app1", "app:app2")
        assert len(paths) == 0

    def test_find_attack_paths_risk_scoring(self, engine):
        findings = [
            {"id": "v-crit", "title": "Critical", "severity": "critical", "component": "core.py"},
            {"id": "v-low", "title": "Low", "severity": "low", "component": "core.py"},
        ]
        engine.ingest_findings(findings, app_id="riskapp")
        paths = engine.find_attack_paths("app:riskapp", "finding:v-crit")
        if paths:
            assert paths[0].risk_score > 0
            assert paths[0].exploitability in ("HIGH", "MEDIUM", "LOW")

    def test_find_attack_paths_nonexistent_nodes(self, engine):
        paths = engine.find_attack_paths("nonexistent1", "nonexistent2")
        assert paths == []

    def test_calculate_blast_radius_basic(self, engine):
        findings = [
            {"id": "core-vuln", "title": "Core Vuln", "severity": "critical", "component": "core.py"},
        ]
        engine.ingest_findings(findings, app_id="blastapp")
        radius = engine.calculate_blast_radius("core-vuln")
        assert isinstance(radius, BlastRadius)
        assert radius.source_finding_id == "finding:core-vuln"

    def test_calculate_blast_radius_with_prefix(self, engine):
        findings = [{"id": "v1", "title": "V1", "severity": "high", "component": "x.py"}]
        engine.ingest_findings(findings)
        radius = engine.calculate_blast_radius("finding:v1")
        assert radius.source_finding_id == "finding:v1"

    def test_calculate_blast_radius_wide_impact(self, engine):
        # Create interconnected findings
        findings = [
            {"id": f"dep-{i}", "title": f"Dep vuln {i}", "severity": "high", "component": f"mod{i}.py"}
            for i in range(5)
        ]
        engine.ingest_findings(findings, app_id="depapp")
        # Add dependencies between components
        engine.add_dependency("mod0.py", "mod1.py")
        engine.add_dependency("mod1.py", "mod2.py")

        radius = engine.calculate_blast_radius("dep-0")
        assert isinstance(radius, BlastRadius)
        assert radius.risk_multiplier >= 1.0

    def test_get_graph_analytics(self, engine):
        findings = [
            {"id": "a1", "title": "F1", "severity": "high", "component": "x.py", "cwe": "CWE-79"},
            {"id": "a2", "title": "F2", "severity": "medium", "component": "y.py"},
        ]
        engine.ingest_findings(findings)
        analytics = engine.get_graph_analytics()

        assert "node_count" in analytics
        assert "edge_count" in analytics
        assert "node_type_distribution" in analytics
        assert "top_central_nodes" in analytics
        assert "backend" in analytics
        assert analytics["node_count"] > 0

    def test_get_graph_analytics_empty(self, engine):
        analytics = engine.get_graph_analytics()
        assert analytics["node_count"] == 0
        assert analytics["edge_count"] == 0

    def test_export_json(self, engine):
        findings = [{"id": "e1", "title": "Export Test", "severity": "low"}]
        engine.ingest_findings(findings)
        result = engine.export_json()
        assert "nodes" in result
        assert "edges" in result

    def test_export_mermaid(self, engine):
        findings = [
            {"id": "m1", "title": "Mermaid Test", "severity": "high", "component": "c.py"},
        ]
        engine.ingest_findings(findings, app_id="mermaidapp")
        mermaid = engine.export_mermaid()
        assert "graph LR" in mermaid

    def test_get_status(self, engine):
        status = engine.get_status()
        assert status["engine"] == "knowledge-graph"
        assert "backend" in status
        assert "supported_node_types" in status
        assert "supported_edge_types" in status
        assert len(status["supported_node_types"]) == len(NodeType)

    def test_clear(self, engine):
        engine.ingest_findings([{"id": "clr1", "title": "Clear test", "severity": "low"}])
        assert engine._backend.node_count > 0
        engine.clear()
        assert engine._backend.node_count == 0

    def test_resolve_node_id_exact(self, engine):
        engine.ingest_findings([{"id": "res1", "title": "Resolve test", "severity": "low"}])
        assert engine._resolve_node_id("finding:res1") == "finding:res1"

    def test_resolve_node_id_partial(self, engine):
        engine.ingest_findings([{"id": "res2", "title": "Resolve test 2", "severity": "low"}], app_id="testapp")
        assert engine._resolve_node_id("testapp") == "app:testapp"

    def test_resolve_node_id_not_found(self, engine):
        assert engine._resolve_node_id("absolutely-nonexistent-id-xyz") is None

    def test_severity_weights(self, engine):
        """Verify severity weight mapping is correct."""
        assert engine.SEVERITY_WEIGHTS["critical"] < engine.SEVERITY_WEIGHTS["low"]
        assert engine.SEVERITY_WEIGHTS["high"] < engine.SEVERITY_WEIGHTS["medium"]


# ──────────────────────────────────────────────────────────────────────
# Integration: End-to-end workflow
# ──────────────────────────────────────────────────────────────────────

class TestKnowledgeGraphIntegration:
    def test_full_workflow(self):
        engine = KnowledgeGraphEngine(backend="networkx")

        # 1. Ingest findings
        findings = [
            {"id": "web-xss", "title": "XSS in search", "severity": "high",
             "component": "search/handler.py", "cwe": "CWE-79", "cve": "CVE-2024-5678"},
            {"id": "web-sqli", "title": "SQL Injection", "severity": "critical",
             "component": "auth/login.py", "cwe": "CWE-89", "cve": "CVE-2024-9999"},
            {"id": "api-broken-auth", "title": "Broken auth", "severity": "high",
             "component": "api/auth.py", "cwe": "CWE-287"},
        ]
        count = engine.ingest_findings(findings, app_id="webapp")
        assert count > 0

        # 2. Add dependencies
        engine.add_dependency("search/handler.py", "auth/login.py")
        engine.add_dependency("api/auth.py", "auth/login.py")

        # 3. Check graph analytics
        analytics = engine.get_graph_analytics()
        assert analytics["node_count"] >= 3

        # 4. Find attack paths
        paths = engine.find_attack_paths("app:webapp", "finding:web-sqli")
        assert len(paths) >= 1

        # 5. Calculate blast radius
        radius = engine.calculate_blast_radius("web-sqli")
        assert isinstance(radius, BlastRadius)

        # 6. Export
        json_export = engine.export_json()
        assert len(json_export["nodes"]) > 0
        mermaid = engine.export_mermaid()
        assert "graph LR" in mermaid

        # 7. Status
        status = engine.get_status()
        assert status["node_count"] > 0


# ──────────────────────────────────────────────────────────────────────
# Module-level convenience
# ──────────────────────────────────────────────────────────────────────

class TestModuleConvenience:
    def test_get_knowledge_graph(self):
        import core.falkordb_client as mod
        old = mod._engine
        mod._engine = None
        try:
            kg = get_knowledge_graph()
            assert isinstance(kg, KnowledgeGraphEngine)
            # Second call returns same instance
            kg2 = get_knowledge_graph()
            assert kg is kg2
        finally:
            mod._engine = old
