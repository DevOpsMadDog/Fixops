"""Unit tests for attack_graph_gnn.py — V3 Decision Intelligence.

Tests the SecurityGraph, GraphNeuralPredictor, and attack path analysis
that powers ALdeci's blast radius estimation and critical path identification.
"""

import numpy as np
from core.attack_graph_gnn import (
    AttackPath,
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphNeuralPredictor,
    NodeType,
    SecurityGraph,
    analyze_attack_surface,
)


# ---------------------------------------------------------------------------
# NodeType / EdgeType enums
# ---------------------------------------------------------------------------

class TestEnums:
    def test_node_types(self):
        assert NodeType.COMPUTE.value == "compute"
        assert NodeType.STORAGE.value == "storage"
        assert NodeType.NETWORK.value == "network"
        assert NodeType.IDENTITY.value == "identity"
        assert NodeType.SERVICE.value == "service"
        assert NodeType.FUNCTION.value == "function"
        assert NodeType.PACKAGE.value == "package"
        assert NodeType.VULNERABILITY.value == "vulnerability"
        assert NodeType.CONTROL.value == "control"
        assert NodeType.DATA.value == "data"

    def test_edge_types(self):
        assert EdgeType.CONNECTS_TO.value == "connects_to"
        assert EdgeType.RUNS_ON.value == "runs_on"
        assert EdgeType.DEPENDS_ON.value == "depends_on"
        assert EdgeType.AUTHENTICATES_AS.value == "authenticates_as"
        assert EdgeType.STORES.value == "stores"
        assert EdgeType.EXPOSES.value == "exposes"
        assert EdgeType.AFFECTS.value == "affects"
        assert EdgeType.PROTECTS.value == "protects"


# ---------------------------------------------------------------------------
# GraphNode dataclass
# ---------------------------------------------------------------------------

class TestGraphNode:
    def test_create_node(self):
        node = GraphNode(
            id="web-server-1",
            node_type=NodeType.COMPUTE,
            properties={"name": "Web Server"},
            risk_score=0.7,
        )
        assert node.id == "web-server-1"
        assert node.node_type == NodeType.COMPUTE
        assert node.risk_score == 0.7

    def test_node_to_dict(self):
        node = GraphNode(
            id="db-1",
            node_type=NodeType.STORAGE,
            risk_score=0.5,
        )
        d = node.to_dict()
        assert isinstance(d, dict)
        assert d["id"] == "db-1"

    def test_node_default_risk(self):
        node = GraphNode(
            id="svc-1",
            node_type=NodeType.SERVICE,
        )
        assert node.risk_score == 0.0

    def test_node_embedding_none_default(self):
        node = GraphNode(id="test", node_type=NodeType.COMPUTE)
        assert node.embedding is None


# ---------------------------------------------------------------------------
# GraphEdge dataclass
# ---------------------------------------------------------------------------

class TestGraphEdge:
    def test_create_edge(self):
        edge = GraphEdge(
            source_id="web-1",
            target_id="db-1",
            edge_type=EdgeType.CONNECTS_TO,
            weight=0.8,
        )
        assert edge.source_id == "web-1"
        assert edge.target_id == "db-1"
        assert edge.weight == 0.8

    def test_edge_to_dict(self):
        edge = GraphEdge(
            source_id="svc-1",
            target_id="pkg-1",
            edge_type=EdgeType.DEPENDS_ON,
            weight=1.0,
        )
        d = edge.to_dict()
        assert isinstance(d, dict)
        assert d["source"] == "svc-1"

    def test_edge_default_weight(self):
        edge = GraphEdge(
            source_id="a",
            target_id="b",
            edge_type=EdgeType.AFFECTS,
        )
        assert edge.weight == 1.0


# ---------------------------------------------------------------------------
# AttackPath dataclass
# ---------------------------------------------------------------------------

class TestAttackPath:
    def test_create_path(self):
        path = AttackPath(
            path=["entry", "web-1", "db-1"],
            probability=0.85,
            impact_score=8.5,
            techniques=["T1190", "T1078"],
            entry_point="entry",
            target="db-1",
            blast_radius=5,
        )
        assert len(path.path) == 3
        assert path.probability == 0.85
        assert path.blast_radius == 5

    def test_path_to_dict(self):
        path = AttackPath(
            path=["entry", "svc-1"],
            probability=0.5,
            impact_score=6.0,
            techniques=["T1046"],
            entry_point="entry",
            target="svc-1",
            blast_radius=2,
        )
        d = path.to_dict()
        assert isinstance(d, dict)
        assert "path" in d
        assert "probability" in d


# ---------------------------------------------------------------------------
# SecurityGraph
# ---------------------------------------------------------------------------

class TestSecurityGraph:
    def setup_method(self):
        self.graph = SecurityGraph()

    def test_add_node(self):
        node = self.graph.add_node("web-1", NodeType.COMPUTE, risk_score=0.6)
        assert isinstance(node, GraphNode)
        assert node.id == "web-1"

    def test_add_edge(self):
        self.graph.add_node("web-1", NodeType.COMPUTE, risk_score=0.6)
        self.graph.add_node("db-1", NodeType.STORAGE, risk_score=0.5)
        edge = self.graph.add_edge("web-1", "db-1", EdgeType.CONNECTS_TO, weight=0.8)
        assert isinstance(edge, GraphEdge)
        neighbors = self.graph.get_neighbors("web-1")
        assert "db-1" in neighbors

    def test_get_predecessors(self):
        self.graph.add_node("svc-1", NodeType.SERVICE, risk_score=0.4)
        self.graph.add_node("pkg-1", NodeType.PACKAGE, risk_score=0.3)
        self.graph.add_edge("svc-1", "pkg-1", EdgeType.DEPENDS_ON)
        preds = self.graph.get_predecessors("pkg-1")
        assert isinstance(preds, list)

    def test_get_edge(self):
        self.graph.add_node("a", NodeType.COMPUTE, risk_score=0.5)
        self.graph.add_node("b", NodeType.STORAGE, risk_score=0.5)
        self.graph.add_edge("a", "b", EdgeType.STORES, weight=0.9)
        retrieved = self.graph.get_edge("a", "b")
        assert retrieved is not None

    def test_get_edge_missing(self):
        result = self.graph.get_edge("nonexistent-1", "nonexistent-2")
        assert result is None

    def test_to_dict(self):
        self.graph.add_node("x", NodeType.NETWORK, risk_score=0.2)
        d = self.graph.to_dict()
        assert isinstance(d, dict)

    def test_multiple_nodes(self):
        for i in range(5):
            self.graph.add_node(f"node-{i}", NodeType.SERVICE, risk_score=0.1 * i)
        d = self.graph.to_dict()
        assert isinstance(d, dict)


# ---------------------------------------------------------------------------
# GraphNeuralPredictor
# ---------------------------------------------------------------------------

class TestGraphNeuralPredictor:
    def _build_sample_graph(self):
        graph = SecurityGraph()
        graph.add_node("web-server", NodeType.COMPUTE, risk_score=0.7)
        graph.add_node("api-service", NodeType.SERVICE, risk_score=0.5)
        graph.add_node("database", NodeType.STORAGE, risk_score=0.8)
        graph.add_node("vuln-sqli", NodeType.VULNERABILITY, risk_score=0.9)
        graph.add_node("iam-role", NodeType.IDENTITY, risk_score=0.3)
        graph.add_node("sensitive-data", NodeType.DATA, risk_score=0.9)

        graph.add_edge("web-server", "api-service", EdgeType.CONNECTS_TO, weight=0.9)
        graph.add_edge("api-service", "database", EdgeType.CONNECTS_TO, weight=0.8)
        graph.add_edge("vuln-sqli", "api-service", EdgeType.AFFECTS, weight=1.0)
        graph.add_edge("api-service", "iam-role", EdgeType.AUTHENTICATES_AS, weight=0.7)
        graph.add_edge("database", "sensitive-data", EdgeType.STORES, weight=1.0)
        return graph

    def test_init(self):
        predictor = GraphNeuralPredictor()
        assert predictor is not None

    def test_init_custom_params(self):
        predictor = GraphNeuralPredictor(embedding_dim=32, num_layers=5)
        assert predictor is not None

    def test_compute_node_embeddings(self):
        graph = self._build_sample_graph()
        predictor = GraphNeuralPredictor(embedding_dim=16, num_layers=3)
        embeddings = predictor.compute_node_embeddings(graph)
        assert isinstance(embeddings, dict)
        assert len(embeddings) > 0
        for node_id, emb in embeddings.items():
            assert isinstance(emb, np.ndarray)

    def test_propagate_risk(self):
        graph = self._build_sample_graph()
        predictor = GraphNeuralPredictor()
        risk_scores = predictor.propagate_risk(graph, vulnerability_nodes=["vuln-sqli"])
        assert isinstance(risk_scores, dict)
        assert len(risk_scores) > 0
        for node_id, score in risk_scores.items():
            assert isinstance(score, float)
            assert 0.0 <= score <= 1.0

    def test_find_attack_paths(self):
        graph = self._build_sample_graph()
        predictor = GraphNeuralPredictor()
        paths = predictor.find_attack_paths(
            graph=graph,
            entry_points=["web-server"],
            targets=["sensitive-data"],
        )
        assert isinstance(paths, list)
        for path in paths:
            assert isinstance(path, AttackPath)
            assert len(path.path) >= 2

    def test_find_attack_paths_no_path(self):
        graph = SecurityGraph()
        graph.add_node("a", NodeType.COMPUTE, risk_score=0.5)
        graph.add_node("b", NodeType.COMPUTE, risk_score=0.5)
        predictor = GraphNeuralPredictor()
        paths = predictor.find_attack_paths(graph, entry_points=["a"], targets=["b"])
        assert isinstance(paths, list)

    def test_identify_critical_nodes(self):
        graph = self._build_sample_graph()
        predictor = GraphNeuralPredictor()
        critical = predictor.identify_critical_nodes(graph)
        assert isinstance(critical, list)
        for item in critical:
            assert isinstance(item, dict)


# ---------------------------------------------------------------------------
# Module-level function
# ---------------------------------------------------------------------------

class TestAnalyzeAttackSurface:
    def test_basic_analysis(self):
        infrastructure = [
            {"id": "web", "type": "compute", "risk_score": 0.7},
            {"id": "db", "type": "storage", "risk_score": 0.8},
        ]
        connections = [
            {"source": "web", "target": "db", "type": "connects_to", "weight": 0.9},
        ]
        vulnerabilities = [
            {"cve_id": "CVE-2024-001", "affected_node": "web", "severity": "high", "cvss": 8.5},
        ]
        result = analyze_attack_surface(
            infrastructure=infrastructure,
            connections=connections,
            vulnerabilities=vulnerabilities,
        )
        assert isinstance(result, dict)

    def test_empty_analysis(self):
        result = analyze_attack_surface(infrastructure=[], connections=[], vulnerabilities=[])
        assert isinstance(result, dict)
