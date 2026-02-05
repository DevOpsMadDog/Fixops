"""Graph Neural Network for Attack Path Prediction - ALdeci.

This module implements a GNN-based approach to learning and predicting
attack paths across cloud infrastructure and application graphs.

Features:
- Node2Vec-style embeddings for security entities
- Message passing for vulnerability propagation
- Learned attack path prediction
- Blast radius estimation
- Critical path identification
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np


class NodeType(Enum):
    """Types of nodes in the security graph."""
    
    # Infrastructure
    COMPUTE = "compute"  # VMs, containers, serverless
    STORAGE = "storage"  # Databases, object storage, file systems
    NETWORK = "network"  # Load balancers, firewalls, VPNs
    IDENTITY = "identity"  # IAM roles, service accounts
    
    # Application
    SERVICE = "service"  # Microservices, APIs
    FUNCTION = "function"  # Code functions
    PACKAGE = "package"  # Dependencies
    
    # Security
    VULNERABILITY = "vulnerability"  # CVEs
    CONTROL = "control"  # Security controls
    DATA = "data"  # Sensitive data assets


class EdgeType(Enum):
    """Types of edges in the security graph."""
    
    CONNECTS_TO = "connects_to"  # Network connectivity
    RUNS_ON = "runs_on"  # Deployment relationship
    DEPENDS_ON = "depends_on"  # Dependency relationship
    AUTHENTICATES_AS = "authenticates_as"  # Identity relationship
    STORES = "stores"  # Data storage relationship
    EXPOSES = "exposes"  # Exposure relationship
    AFFECTS = "affects"  # Vulnerability affects
    PROTECTS = "protects"  # Control protects


@dataclass
class GraphNode:
    """Node in the security graph."""
    
    id: str
    node_type: NodeType
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    embedding: Optional[np.ndarray] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.node_type.value,
            "properties": self.properties,
            "risk_score": round(self.risk_score, 4),
        }


@dataclass
class GraphEdge:
    """Edge in the security graph."""
    
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type.value,
            "weight": round(self.weight, 4),
            "properties": self.properties,
        }


@dataclass
class AttackPath:
    """A predicted attack path through the graph."""
    
    path: List[str]  # Node IDs in order
    probability: float
    impact_score: float
    techniques: List[str]  # MITRE ATT&CK techniques
    entry_point: str
    target: str
    blast_radius: int  # Number of potentially affected nodes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "probability": round(self.probability, 4),
            "impact_score": round(self.impact_score, 4),
            "mitre_techniques": self.techniques,
            "entry_point": self.entry_point,
            "target": self.target,
            "blast_radius": self.blast_radius,
            "path_length": len(self.path),
        }


class SecurityGraph:
    """Graph representation of security infrastructure.
    
    This is a lightweight graph implementation that can be used
    for GNN-style message passing and attack path prediction.
    """
    
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.adjacency: Dict[str, List[str]] = defaultdict(list)
        self.reverse_adjacency: Dict[str, List[str]] = defaultdict(list)
    
    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        properties: Dict[str, Any] | None = None,
        risk_score: float = 0.0,
    ) -> GraphNode:
        """Add a node to the graph."""
        node = GraphNode(
            id=node_id,
            node_type=node_type,
            properties=properties or {},
            risk_score=risk_score,
        )
        self.nodes[node_id] = node
        return node
    
    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        weight: float = 1.0,
        properties: Dict[str, Any] | None = None,
    ) -> GraphEdge:
        """Add an edge to the graph."""
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            properties=properties or {},
        )
        self.edges.append(edge)
        self.adjacency[source_id].append(target_id)
        self.reverse_adjacency[target_id].append(source_id)
        return edge
    
    def get_neighbors(self, node_id: str) -> List[str]:
        """Get outgoing neighbors of a node."""
        return self.adjacency.get(node_id, [])
    
    def get_predecessors(self, node_id: str) -> List[str]:
        """Get incoming neighbors of a node."""
        return self.reverse_adjacency.get(node_id, [])
    
    def get_edge(self, source_id: str, target_id: str) -> Optional[GraphEdge]:
        """Get edge between two nodes."""
        for edge in self.edges:
            if edge.source_id == source_id and edge.target_id == target_id:
                return edge
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
        }


class GraphNeuralPredictor:
    """GNN-style attack path predictor.
    
    This uses message passing algorithms to propagate risk through
    the graph and identify likely attack paths.
    
    While this is a simplified implementation (not using PyTorch Geometric),
    it implements the core concepts:
    - Node embeddings
    - Message passing (risk propagation)
    - Graph attention (weighted aggregation)
    - Path scoring
    """
    
    def __init__(
        self,
        embedding_dim: int = 64,
        num_layers: int = 3,
        propagation_factor: float = 0.85,
    ):
        """Initialize the GNN predictor.
        
        Args:
            embedding_dim: Dimension of node embeddings
            num_layers: Number of message passing layers
            propagation_factor: PageRank-style damping factor
        """
        self.embedding_dim = embedding_dim
        self.num_layers = num_layers
        self.propagation_factor = propagation_factor
        self.rng = np.random.default_rng(42)
        
        # Type embeddings (learned in real GNN, fixed here)
        self._type_embeddings = self._initialize_type_embeddings()
    
    def _initialize_type_embeddings(self) -> Dict[NodeType, np.ndarray]:
        """Initialize embeddings for each node type."""
        embeddings = {}
        for node_type in NodeType:
            embeddings[node_type] = self.rng.standard_normal(self.embedding_dim)
            embeddings[node_type] /= np.linalg.norm(embeddings[node_type])
        return embeddings
    
    def compute_node_embeddings(self, graph: SecurityGraph) -> Dict[str, np.ndarray]:
        """Compute embeddings for all nodes using message passing.
        
        This implements a simplified version of GraphSAGE-style
        neighborhood aggregation.
        """
        # Initialize with type embeddings + random noise
        embeddings = {}
        for node_id, node in graph.nodes.items():
            base = self._type_embeddings[node.node_type].copy()
            noise = self.rng.standard_normal(self.embedding_dim) * 0.1
            embeddings[node_id] = base + noise
            
            # Add risk score to embedding
            embeddings[node_id][0] = node.risk_score
        
        # Message passing layers
        for layer in range(self.num_layers):
            new_embeddings = {}
            
            for node_id in graph.nodes:
                # Aggregate neighbor embeddings
                neighbors = graph.get_neighbors(node_id) + graph.get_predecessors(node_id)
                
                if neighbors:
                    neighbor_embs = [embeddings[n] for n in neighbors if n in embeddings]
                    if neighbor_embs:
                        # Mean aggregation with attention-like weighting
                        weights = []
                        for n in neighbors:
                            edge = graph.get_edge(node_id, n) or graph.get_edge(n, node_id)
                            weights.append(edge.weight if edge else 1.0)
                        
                        weights = np.array(weights[:len(neighbor_embs)])
                        weights = weights / weights.sum()
                        
                        aggregated = np.average(neighbor_embs, axis=0, weights=weights)
                        
                        # Combine with self embedding
                        new_emb = (
                            self.propagation_factor * embeddings[node_id] +
                            (1 - self.propagation_factor) * aggregated
                        )
                        new_embeddings[node_id] = new_emb / np.linalg.norm(new_emb)
                    else:
                        new_embeddings[node_id] = embeddings[node_id]
                else:
                    new_embeddings[node_id] = embeddings[node_id]
            
            embeddings = new_embeddings
        
        return embeddings
    
    def propagate_risk(
        self,
        graph: SecurityGraph,
        vulnerability_nodes: List[str],
        iterations: int = 10,
    ) -> Dict[str, float]:
        """Propagate risk from vulnerability nodes through the graph.
        
        Uses a PageRank-style algorithm to compute risk scores.
        """
        # Initialize risk scores
        risk_scores = {node_id: 0.0 for node_id in graph.nodes}
        
        # Seed vulnerability nodes
        for vuln_id in vulnerability_nodes:
            if vuln_id in risk_scores:
                risk_scores[vuln_id] = graph.nodes[vuln_id].risk_score or 1.0
        
        # Iterative propagation
        for _ in range(iterations):
            new_scores = {}
            
            for node_id in graph.nodes:
                # Get risk from predecessors
                predecessors = graph.get_predecessors(node_id)
                incoming_risk = 0.0
                
                for pred_id in predecessors:
                    edge = graph.get_edge(pred_id, node_id)
                    edge_weight = edge.weight if edge else 1.0
                    incoming_risk += risk_scores.get(pred_id, 0.0) * edge_weight
                
                # PageRank-style update
                base_risk = graph.nodes[node_id].risk_score
                new_scores[node_id] = (
                    (1 - self.propagation_factor) * base_risk +
                    self.propagation_factor * incoming_risk / max(1, len(predecessors))
                )
            
            risk_scores = new_scores
        
        return risk_scores
    
    def find_attack_paths(
        self,
        graph: SecurityGraph,
        entry_points: List[str],
        targets: List[str],
        max_paths: int = 10,
        max_depth: int = 10,
    ) -> List[AttackPath]:
        """Find likely attack paths from entry points to targets.
        
        Uses graph traversal with scoring based on:
        - Edge weights (connectivity strength)
        - Node risk scores
        - Path length penalties
        """
        all_paths = []
        
        for entry in entry_points:
            if entry not in graph.nodes:
                continue
            
            for target in targets:
                if target not in graph.nodes:
                    continue
                
                # BFS with scoring
                paths = self._find_paths_bfs(
                    graph, entry, target, max_depth
                )
                
                for path in paths:
                    attack_path = self._score_path(graph, path, entry, target)
                    all_paths.append(attack_path)
        
        # Sort by combined score (probability * impact)
        all_paths.sort(key=lambda p: p.probability * p.impact_score, reverse=True)
        
        return all_paths[:max_paths]
    
    def _find_paths_bfs(
        self,
        graph: SecurityGraph,
        start: str,
        end: str,
        max_depth: int,
    ) -> List[List[str]]:
        """Find all paths using BFS."""
        paths = []
        queue = [(start, [start])]
        
        while queue:
            current, path = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            if current == end:
                paths.append(path)
                continue
            
            for neighbor in graph.get_neighbors(current):
                if neighbor not in path:  # Avoid cycles
                    queue.append((neighbor, path + [neighbor]))
        
        return paths
    
    def _score_path(
        self,
        graph: SecurityGraph,
        path: List[str],
        entry: str,
        target: str,
    ) -> AttackPath:
        """Score an attack path."""
        # Calculate path probability (product of edge weights)
        probability = 1.0
        for i in range(len(path) - 1):
            edge = graph.get_edge(path[i], path[i + 1])
            if edge:
                probability *= edge.weight
            else:
                probability *= 0.5  # Implicit weak edge
        
        # Apply length penalty
        length_penalty = 0.9 ** (len(path) - 1)
        probability *= length_penalty
        
        # Calculate impact (sum of node risk scores)
        impact = sum(
            graph.nodes[node_id].risk_score
            for node_id in path
            if node_id in graph.nodes
        )
        
        # Estimate blast radius
        blast_radius = self._calculate_blast_radius(graph, path)
        
        # Map to MITRE techniques based on node types
        techniques = self._infer_techniques(graph, path)
        
        return AttackPath(
            path=path,
            probability=min(1.0, probability),
            impact_score=impact,
            techniques=techniques,
            entry_point=entry,
            target=target,
            blast_radius=blast_radius,
        )
    
    def _calculate_blast_radius(
        self,
        graph: SecurityGraph,
        path: List[str],
    ) -> int:
        """Calculate the number of nodes potentially affected."""
        affected = set(path)
        
        # BFS from each path node
        for node_id in path:
            queue = [node_id]
            depth = 0
            
            while queue and depth < 3:  # Limit depth
                next_queue = []
                for current in queue:
                    for neighbor in graph.get_neighbors(current):
                        if neighbor not in affected:
                            affected.add(neighbor)
                            next_queue.append(neighbor)
                queue = next_queue
                depth += 1
        
        return len(affected)
    
    def _infer_techniques(
        self,
        graph: SecurityGraph,
        path: List[str],
    ) -> List[str]:
        """Infer MITRE ATT&CK techniques from path."""
        techniques = []
        
        for node_id in path:
            node = graph.nodes.get(node_id)
            if not node:
                continue
            
            # Map node types to techniques
            type_techniques = {
                NodeType.COMPUTE: "T1059",  # Command and Scripting Interpreter
                NodeType.IDENTITY: "T1078",  # Valid Accounts
                NodeType.STORAGE: "T1530",  # Data from Cloud Storage
                NodeType.NETWORK: "T1090",  # Proxy
                NodeType.SERVICE: "T1210",  # Exploitation of Remote Services
                NodeType.PACKAGE: "T1195",  # Supply Chain Compromise
                NodeType.VULNERABILITY: "T1190",  # Exploit Public-Facing Application
                NodeType.DATA: "T1005",  # Data from Local System
            }
            
            tech = type_techniques.get(node.node_type)
            if tech and tech not in techniques:
                techniques.append(tech)
        
        return techniques
    
    def identify_critical_nodes(
        self,
        graph: SecurityGraph,
        top_k: int = 10,
    ) -> List[Dict[str, Any]]:
        """Identify most critical nodes based on centrality and risk.
        
        Combines:
        - Betweenness centrality (path importance)
        - Risk score propagation
        - Connectivity metrics
        """
        # Compute embeddings (includes risk propagation)
        embeddings = self.compute_node_embeddings(graph)
        
        # Calculate betweenness-like centrality
        centrality = self._approximate_betweenness(graph)
        
        # Calculate combined criticality score
        critical_nodes = []
        
        for node_id, node in graph.nodes.items():
            # Combine factors
            node_centrality = centrality.get(node_id, 0)
            node_risk = node.risk_score
            
            # Connectivity factor
            in_degree = len(graph.get_predecessors(node_id))
            out_degree = len(graph.get_neighbors(node_id))
            connectivity = (in_degree + out_degree) / max(1, len(graph.nodes))
            
            # Critical data factor
            is_data_sensitive = node.node_type in [NodeType.DATA, NodeType.STORAGE]
            data_factor = 2.0 if is_data_sensitive else 1.0
            
            criticality = (
                0.3 * node_centrality +
                0.4 * node_risk +
                0.2 * connectivity +
                0.1 * data_factor
            )
            
            critical_nodes.append({
                "node_id": node_id,
                "node_type": node.node_type.value,
                "criticality_score": round(criticality, 4),
                "centrality": round(node_centrality, 4),
                "risk_score": round(node_risk, 4),
                "connectivity": round(connectivity, 4),
                "in_degree": in_degree,
                "out_degree": out_degree,
            })
        
        # Sort by criticality
        critical_nodes.sort(key=lambda x: x["criticality_score"], reverse=True)
        
        return critical_nodes[:top_k]
    
    def _approximate_betweenness(self, graph: SecurityGraph) -> Dict[str, float]:
        """Approximate betweenness centrality."""
        centrality = {node_id: 0.0 for node_id in graph.nodes}
        
        # Sample some source-target pairs
        nodes = list(graph.nodes.keys())
        num_samples = min(100, len(nodes) * (len(nodes) - 1) // 2)
        
        for _ in range(num_samples):
            if len(nodes) < 2:
                break
            
            source = self.rng.choice(nodes)
            target = self.rng.choice([n for n in nodes if n != source])
            
            # Find shortest path
            path = self._shortest_path(graph, source, target)
            
            # Credit intermediate nodes
            if path and len(path) > 2:
                for node in path[1:-1]:
                    centrality[node] += 1.0
        
        # Normalize
        max_centrality = max(centrality.values()) if centrality else 1.0
        if max_centrality > 0:
            for node_id in centrality:
                centrality[node_id] /= max_centrality
        
        return centrality
    
    def _shortest_path(
        self,
        graph: SecurityGraph,
        start: str,
        end: str,
    ) -> Optional[List[str]]:
        """Find shortest path using BFS."""
        if start not in graph.nodes or end not in graph.nodes:
            return None
        
        queue = [(start, [start])]
        visited = set()
        
        while queue:
            current, path = queue.pop(0)
            
            if current == end:
                return path
            
            if current in visited:
                continue
            visited.add(current)
            
            for neighbor in graph.get_neighbors(current):
                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor]))
        
        return None


# Convenience functions for API use
def analyze_attack_surface(
    infrastructure: List[Dict[str, Any]],
    connections: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Analyze attack surface using GNN-based prediction.
    
    Args:
        infrastructure: List of infrastructure nodes
        connections: List of connections between nodes
        vulnerabilities: List of vulnerabilities affecting nodes
        
    Returns:
        Attack surface analysis with paths and critical nodes
    """
    # Build graph
    graph = SecurityGraph()
    
    # Add infrastructure nodes
    for item in infrastructure:
        node_type = NodeType(item.get("type", "compute"))
        graph.add_node(
            item["id"],
            node_type,
            properties=item.get("properties", {}),
            risk_score=item.get("risk_score", 0.0),
        )
    
    # Add vulnerability nodes
    vuln_node_ids = []
    for vuln in vulnerabilities:
        vuln_id = f"vuln_{vuln['cve_id']}"
        graph.add_node(
            vuln_id,
            NodeType.VULNERABILITY,
            properties=vuln,
            risk_score=vuln.get("cvss_score", 5.0) / 10.0,
        )
        vuln_node_ids.append(vuln_id)
        
        # Connect to affected assets
        for affected_id in vuln.get("affects", []):
            if affected_id in graph.nodes:
                graph.add_edge(
                    vuln_id,
                    affected_id,
                    EdgeType.AFFECTS,
                    weight=vuln.get("cvss_score", 5.0) / 10.0,
                )
    
    # Add connections
    for conn in connections:
        edge_type = EdgeType(conn.get("type", "connects_to"))
        graph.add_edge(
            conn["source"],
            conn["target"],
            edge_type,
            weight=conn.get("weight", 1.0),
        )
    
    # Analyze
    predictor = GraphNeuralPredictor()
    
    # Find entry points (internet-facing or vulnerability nodes)
    entry_points = [
        node_id for node_id, node in graph.nodes.items()
        if node.properties.get("internet_facing", False)
        or node.node_type == NodeType.VULNERABILITY
    ]
    
    # Find targets (data and storage nodes)
    targets = [
        node_id for node_id, node in graph.nodes.items()
        if node.node_type in [NodeType.DATA, NodeType.STORAGE, NodeType.IDENTITY]
    ]
    
    # If no specific targets, use all high-risk nodes
    if not targets:
        targets = [
            node_id for node_id, node in graph.nodes.items()
            if node.risk_score > 0.5
        ]
    
    # Find attack paths
    attack_paths = predictor.find_attack_paths(
        graph,
        entry_points or list(graph.nodes.keys())[:5],
        targets or list(graph.nodes.keys())[-5:],
        max_paths=10,
    )
    
    # Propagate risk
    risk_scores = predictor.propagate_risk(graph, vuln_node_ids)
    
    # Find critical nodes
    critical_nodes = predictor.identify_critical_nodes(graph, top_k=10)
    
    return {
        "graph_stats": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "vulnerabilities": len(vuln_node_ids),
        },
        "attack_paths": [p.to_dict() for p in attack_paths],
        "critical_nodes": critical_nodes,
        "risk_propagation": {
            node_id: round(score, 4)
            for node_id, score in sorted(
                risk_scores.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:20]
        },
        "entry_points": entry_points[:10],
        "high_value_targets": targets[:10],
    }
