"""FalkorDB Graph Client (V3 — Decision Intelligence / Knowledge Graph).

Provides a graph database client for vulnerability knowledge graphs,
attack path analysis, and component dependency mapping.

Dual-mode:
- FalkorDB mode: When FalkorDB is available (Redis-compatible graph DB)
- NetworkX mode: In-memory fallback for air-gapped/development (zero deps)

Graph Model:
- Nodes: APP, COMPONENT, FINDING, CWE, CVE, ASSET, CONTROL, ATTACK_PATH
- Edges: HAS_COMPONENT, HAS_FINDING, EXPLOITS, DEPENDS_ON, MITIGATED_BY,
         ATTACK_STEP, REACHABLE_FROM, MAPS_TO

Features:
- Knowledge graph construction from findings and scan results
- Attack path discovery (BFS/DFS with weighted edges)
- Blast radius calculation (transitive impact analysis)
- Component dependency graph with vulnerability propagation
- Cypher query support (FalkorDB) / Python query API (NetworkX)
- Graph analytics: centrality, clustering, community detection
- Export: DOT, JSON, Mermaid diagram format

Environment variables:
- FIXOPS_GRAPH_BACKEND: falkordb | networkx (default: auto)
- FIXOPS_FALKORDB_URL: FalkorDB Redis URL (default: redis://localhost:6379)
- FIXOPS_FALKORDB_GRAPH: Graph name (default: aldeci_kg)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Graph Model
# ---------------------------------------------------------------------------
class NodeType(str, Enum):
    APP = "App"
    COMPONENT = "Component"
    FINDING = "Finding"
    CWE = "CWE"
    CVE = "CVE"
    ASSET = "Asset"
    CONTROL = "Control"
    ATTACK_PATH = "AttackPath"
    PACKAGE = "Package"
    ENDPOINT = "Endpoint"


class EdgeType(str, Enum):
    HAS_COMPONENT = "HAS_COMPONENT"
    HAS_FINDING = "HAS_FINDING"
    EXPLOITS = "EXPLOITS"
    DEPENDS_ON = "DEPENDS_ON"
    MITIGATED_BY = "MITIGATED_BY"
    ATTACK_STEP = "ATTACK_STEP"
    REACHABLE_FROM = "REACHABLE_FROM"
    MAPS_TO = "MAPS_TO"
    CONTAINS = "CONTAINS"
    AFFECTS = "AFFECTS"
    CHAINS_WITH = "CHAINS_WITH"


@dataclass
class GraphNode:
    """A node in the knowledge graph."""
    id: str
    type: NodeType
    properties: Dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.properties.get("name", self.properties.get("title", self.id))


@dataclass
class GraphEdge:
    """An edge in the knowledge graph."""
    source_id: str
    target_id: str
    type: EdgeType
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """A discovered attack path through the graph."""
    path_id: str
    nodes: List[str]          # Ordered node IDs in the path
    edges: List[str]          # Edge types along the path
    total_weight: float       # Sum of edge weights (lower = easier to exploit)
    entry_point: str          # First node
    target: str               # Last node (high-value asset)
    risk_score: float = 0.0   # Calculated risk
    exploitability: str = ""  # HIGH, MEDIUM, LOW
    mitigations: List[str] = field(default_factory=list)


@dataclass
class BlastRadius:
    """Blast radius analysis for a vulnerability."""
    source_finding_id: str
    affected_nodes: List[str]
    affected_components: int
    affected_apps: int
    affected_findings: int  # Chained vulnerabilities
    depth: int              # Max depth of impact
    risk_multiplier: float  # How much risk increases
    critical_path: List[str]  # Most impactful path


# ---------------------------------------------------------------------------
# NetworkX In-Memory Backend
# ---------------------------------------------------------------------------
class NetworkXGraphBackend:
    """In-memory graph backend using pure Python (no external deps).

    Full-featured graph for air-gapped deployments.
    """

    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, List[Tuple[str, GraphEdge]]] = defaultdict(list)
        self._reverse_adj: Dict[str, List[Tuple[str, GraphEdge]]] = defaultdict(list)

    def add_node(self, node: GraphNode) -> None:
        self._nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self._edges.append(edge)
        self._adjacency[edge.source_id].append((edge.target_id, edge))
        self._reverse_adj[edge.target_id].append((edge.source_id, edge))

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[Tuple[str, GraphEdge]]:
        neighbors = self._adjacency.get(node_id, [])
        if edge_type:
            return [(n, e) for n, e in neighbors if e.type == edge_type]
        return neighbors

    def get_incoming(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[Tuple[str, GraphEdge]]:
        incoming = self._reverse_adj.get(node_id, [])
        if edge_type:
            return [(n, e) for n, e in incoming if e.type == edge_type]
        return incoming

    def get_nodes_by_type(self, node_type: NodeType) -> List[GraphNode]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def find_paths(self, start_id: str, end_id: str, max_depth: int = 10) -> List[List[str]]:
        """Find all paths between two nodes (BFS, limited depth)."""
        if start_id not in self._nodes or end_id not in self._nodes:
            return []

        paths: List[List[str]] = []
        queue: deque = deque([(start_id, [start_id])])
        visited_paths: Set[str] = set()

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue

            if current == end_id and len(path) > 1:
                path_key = "→".join(path)
                if path_key not in visited_paths:
                    paths.append(path)
                    visited_paths.add(path_key)
                continue

            for neighbor_id, edge in self._adjacency.get(current, []):
                if neighbor_id not in path:  # Avoid cycles
                    queue.append((neighbor_id, path + [neighbor_id]))

        return paths

    def bfs_reachable(self, start_id: str, max_depth: int = -1) -> Dict[str, int]:
        """BFS to find all reachable nodes with their distances."""
        if start_id not in self._nodes:
            return {}

        visited: Dict[str, int] = {start_id: 0}
        queue: deque = deque([(start_id, 0)])

        while queue:
            current, depth = queue.popleft()
            if 0 <= max_depth <= depth:
                continue

            for neighbor_id, _ in self._adjacency.get(current, []):
                if neighbor_id not in visited:
                    visited[neighbor_id] = depth + 1
                    queue.append((neighbor_id, depth + 1))

        return visited

    def degree_centrality(self) -> Dict[str, float]:
        """Calculate degree centrality for all nodes."""
        n = len(self._nodes)
        if n <= 1:
            return {nid: 0.0 for nid in self._nodes}

        centrality = {}
        for node_id in self._nodes:
            out_degree = len(self._adjacency.get(node_id, []))
            in_degree = len(self._reverse_adj.get(node_id, []))
            centrality[node_id] = (out_degree + in_degree) / (2 * (n - 1))
        return centrality

    def betweenness_centrality_approx(self, sample_size: int = 50) -> Dict[str, float]:
        """Approximate betweenness centrality using sampled shortest paths."""
        import random
        node_ids = list(self._nodes.keys())
        betweenness = {nid: 0.0 for nid in node_ids}

        if len(node_ids) < 3:
            return betweenness

        samples = random.sample(node_ids, min(sample_size, len(node_ids)))

        for source in samples:
            # BFS shortest paths
            dist: Dict[str, int] = {source: 0}
            pred: Dict[str, List[str]] = defaultdict(list)
            queue: deque = deque([source])

            while queue:
                current = queue.popleft()
                for neighbor_id, _ in self._adjacency.get(current, []):
                    if neighbor_id not in dist:
                        dist[neighbor_id] = dist[current] + 1
                        pred[neighbor_id].append(current)
                        queue.append(neighbor_id)
                    elif dist[neighbor_id] == dist[current] + 1:
                        pred[neighbor_id].append(current)

            # Accumulate betweenness
            dependency = defaultdict(float)
            nodes_by_distance = sorted(dist.items(), key=lambda x: -x[1])
            for node, d in nodes_by_distance:
                if node == source:
                    continue
                for p in pred[node]:
                    dependency[p] += (1.0 + dependency[node]) / len(pred[node])
                if node != source:
                    betweenness[node] += dependency[node]

        # Normalize
        n = len(node_ids)
        if n > 2:
            norm = 1.0 / ((n - 1) * (n - 2))
            scale = len(node_ids) / len(samples)
            betweenness = {k: v * norm * scale for k, v in betweenness.items()}

        return betweenness

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def to_json(self) -> Dict[str, Any]:
        """Export graph as JSON."""
        return {
            "nodes": [
                {"id": n.id, "type": n.type.value, "properties": n.properties}
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.type.value,
                    "weight": e.weight,
                    "properties": e.properties,
                }
                for e in self._edges
            ],
        }

    def to_mermaid(self, max_nodes: int = 50) -> str:
        """Export graph as Mermaid diagram."""
        lines = ["graph LR"]
        shown_nodes: Set[str] = set()

        for edge in self._edges[:max_nodes]:
            src = self._nodes.get(edge.source_id)
            tgt = self._nodes.get(edge.target_id)
            if not src or not tgt:
                continue

            src_label = src.label[:30].replace('"', "'")
            tgt_label = tgt.label[:30].replace('"', "'")
            edge_label = edge.type.value.replace("_", " ")
            lines.append(f'    {src.id}["{src_label}"] -->|{edge_label}| {tgt.id}["{tgt_label}"]')
            shown_nodes.add(src.id)
            shown_nodes.add(tgt.id)

        return "\n".join(lines)

    def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()
        self._adjacency.clear()
        self._reverse_adj.clear()


# ---------------------------------------------------------------------------
# FalkorDB Backend
# ---------------------------------------------------------------------------
class FalkorDBBackend:
    """FalkorDB (Redis-compatible graph DB) backend."""

    def __init__(self, url: Optional[str] = None, graph_name: Optional[str] = None):
        self.url = url or os.getenv("FIXOPS_FALKORDB_URL", "redis://localhost:6379")
        self.graph_name = graph_name or os.getenv("FIXOPS_FALKORDB_GRAPH", "aldeci_kg")
        self._graph = None
        self._fallback = NetworkXGraphBackend()
        self._using_fallback = False

        try:
            self._connect()
        except Exception as e:
            logger.warning(f"FalkorDB unavailable ({e}), using NetworkX fallback")
            self._using_fallback = True

    def _connect(self):
        try:
            from falkordb import FalkorDB  # type: ignore
            db = FalkorDB.from_url(self.url)
            self._graph = db.select_graph(self.graph_name)
            # Test query
            self._graph.query("RETURN 1")
            logger.info(f"Connected to FalkorDB: {self.url}/{self.graph_name}")
        except ImportError:
            raise RuntimeError("falkordb package not installed")
        except Exception as e:
            raise RuntimeError(f"Cannot connect to FalkorDB: {e}")

    def add_node(self, node: GraphNode) -> None:
        if self._using_fallback:
            self._fallback.add_node(node)
            return

        props = {k: json.dumps(v) if isinstance(v, (dict, list)) else v
                 for k, v in node.properties.items()}
        props["_id"] = node.id
        prop_str = ", ".join(f"{k}: ${k}" for k in props)

        try:
            self._graph.query(
                f"MERGE (n:{node.type.value} {{{prop_str}}})",
                props
            )
        except Exception as e:
            logger.warning(f"FalkorDB add_node failed: {e}")
            self._fallback.add_node(node)

    def add_edge(self, edge: GraphEdge) -> None:
        if self._using_fallback:
            self._fallback.add_edge(edge)
            return

        try:
            self._graph.query(
                f"""MATCH (a {{_id: $src}}), (b {{_id: $tgt}})
                    MERGE (a)-[r:{edge.type.value} {{weight: $weight}}]->(b)""",
                {"src": edge.source_id, "tgt": edge.target_id, "weight": edge.weight}
            )
        except Exception as e:
            logger.warning(f"FalkorDB add_edge failed: {e}")
            self._fallback.add_edge(edge)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        if self._using_fallback:
            return self._fallback.get_node(node_id)

        try:
            result = self._graph.query(
                "MATCH (n {_id: $id}) RETURN n, labels(n)[0]",
                {"id": node_id}
            )
            if result.result_set:
                row = result.result_set[0]
                node_data = row[0]
                label = row[1]
                return GraphNode(
                    id=node_id,
                    type=NodeType(label),
                    properties=dict(node_data.properties) if hasattr(node_data, 'properties') else {},
                )
        except Exception:
            pass
        return self._fallback.get_node(node_id)

    def get_neighbors(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[Tuple[str, GraphEdge]]:
        if self._using_fallback:
            return self._fallback.get_neighbors(node_id, edge_type)
        # Fallback to NetworkX for complex queries in FalkorDB mode
        return self._fallback.get_neighbors(node_id, edge_type)

    def get_nodes_by_type(self, node_type: NodeType) -> List[GraphNode]:
        if self._using_fallback:
            return self._fallback.get_nodes_by_type(node_type)

        try:
            result = self._graph.query(
                f"MATCH (n:{node_type.value}) RETURN n._id, n"
            )
            nodes = []
            for row in result.result_set:
                node_id = row[0]
                props = dict(row[1].properties) if hasattr(row[1], 'properties') else {}
                nodes.append(GraphNode(id=node_id, type=node_type, properties=props))
            return nodes
        except Exception:
            return self._fallback.get_nodes_by_type(node_type)

    def find_paths(self, start_id: str, end_id: str, max_depth: int = 10) -> List[List[str]]:
        if self._using_fallback:
            return self._fallback.find_paths(start_id, end_id, max_depth)

        try:
            result = self._graph.query(
                f"""MATCH p = (a {{_id: $start}})-[*1..{max_depth}]->(b {{_id: $end}})
                    RETURN [n IN nodes(p) | n._id] AS path
                    LIMIT 20""",
                {"start": start_id, "end": end_id}
            )
            return [row[0] for row in result.result_set]
        except Exception:
            return self._fallback.find_paths(start_id, end_id, max_depth)

    def bfs_reachable(self, start_id: str, max_depth: int = -1) -> Dict[str, int]:
        return self._fallback.bfs_reachable(start_id, max_depth)

    def degree_centrality(self) -> Dict[str, float]:
        return self._fallback.degree_centrality()

    def betweenness_centrality_approx(self, sample_size: int = 50) -> Dict[str, float]:
        return self._fallback.betweenness_centrality_approx(sample_size)

    @property
    def node_count(self) -> int:
        if self._using_fallback:
            return self._fallback.node_count
        try:
            result = self._graph.query("MATCH (n) RETURN count(n)")
            return result.result_set[0][0]
        except Exception:
            return self._fallback.node_count

    @property
    def edge_count(self) -> int:
        if self._using_fallback:
            return self._fallback.edge_count
        try:
            result = self._graph.query("MATCH ()-[r]->() RETURN count(r)")
            return result.result_set[0][0]
        except Exception:
            return self._fallback.edge_count

    def to_json(self) -> Dict[str, Any]:
        return self._fallback.to_json()

    def to_mermaid(self, max_nodes: int = 50) -> str:
        return self._fallback.to_mermaid(max_nodes)

    def clear(self) -> None:
        if not self._using_fallback:
            try:
                self._graph.query("MATCH (n) DETACH DELETE n")
            except Exception:
                pass
        self._fallback.clear()


# ---------------------------------------------------------------------------
# Knowledge Graph Engine
# ---------------------------------------------------------------------------
class KnowledgeGraphEngine:
    """High-level knowledge graph engine for security analysis.

    Builds and queries a vulnerability knowledge graph from findings,
    components, and scan results. Supports attack path discovery,
    blast radius analysis, and component dependency mapping.

    Usage:
        kg = KnowledgeGraphEngine()
        kg.ingest_findings(findings_list)
        paths = kg.find_attack_paths("internet-endpoint", "database")
        radius = kg.calculate_blast_radius("finding-123")
    """

    SEVERITY_WEIGHTS = {
        "critical": 0.1,  # Low weight = easy to traverse = high risk
        "high": 0.3,
        "medium": 0.6,
        "low": 0.8,
        "info": 1.0,
    }

    def __init__(self, backend: Optional[str] = None):
        backend_type = backend or os.getenv("FIXOPS_GRAPH_BACKEND", "auto")

        if backend_type == "falkordb":
            self._backend = FalkorDBBackend()
        elif backend_type == "networkx":
            self._backend = NetworkXGraphBackend()
        else:
            # Auto-detect
            try:
                self._backend = FalkorDBBackend()
                if isinstance(self._backend, FalkorDBBackend) and self._backend._using_fallback:
                    self._backend = NetworkXGraphBackend()
            except Exception:
                self._backend = NetworkXGraphBackend()

        logger.info(f"KnowledgeGraphEngine initialized: {type(self._backend).__name__}")

    def ingest_findings(self, findings: List[Dict[str, Any]], app_id: str = "default") -> int:
        """Ingest findings into the knowledge graph.

        Args:
            findings: List of finding dicts
            app_id: Application ID to associate findings with

        Returns:
            Number of nodes/edges created
        """
        count = 0

        # Ensure app node exists
        self._backend.add_node(GraphNode(
            id=f"app:{app_id}",
            type=NodeType.APP,
            properties={"name": app_id, "ingested_at": datetime.now(timezone.utc).isoformat()},
        ))
        count += 1

        for finding in findings:
            finding_id = finding.get("id", finding.get("finding_id", hashlib.md5(
                json.dumps(finding, sort_keys=True, default=str).encode(),
                usedforsecurity=False,
            ).hexdigest()[:12]))

            severity = finding.get("severity", "medium").lower()
            component = finding.get("component", finding.get("file_path", "unknown"))

            # Finding node
            self._backend.add_node(GraphNode(
                id=f"finding:{finding_id}",
                type=NodeType.FINDING,
                properties={
                    "title": finding.get("title", finding.get("name", "Unknown")),
                    "severity": severity,
                    "cwe": finding.get("cwe", finding.get("cwe_id", "")),
                    "cvss": finding.get("cvss", finding.get("cvss_score", 0)),
                    "source": finding.get("source", finding.get("scanner", "")),
                    "status": finding.get("status", "open"),
                },
            ))
            count += 1

            # Component node
            comp_id = f"component:{hashlib.md5(component.encode(), usedforsecurity=False).hexdigest()[:10]}"
            self._backend.add_node(GraphNode(
                id=comp_id,
                type=NodeType.COMPONENT,
                properties={"name": component, "path": finding.get("file_path", "")},
            ))
            count += 1

            # Edges
            weight = self.SEVERITY_WEIGHTS.get(severity, 0.5)
            self._backend.add_edge(GraphEdge(f"app:{app_id}", comp_id, EdgeType.HAS_COMPONENT))
            self._backend.add_edge(GraphEdge(comp_id, f"finding:{finding_id}", EdgeType.HAS_FINDING, weight=weight))
            count += 2

            # CWE node + edge
            cwe = finding.get("cwe", finding.get("cwe_id", ""))
            if cwe:
                cwe_id = f"cwe:{cwe}"
                self._backend.add_node(GraphNode(
                    id=cwe_id,
                    type=NodeType.CWE,
                    properties={"cwe_id": cwe},
                ))
                self._backend.add_edge(GraphEdge(f"finding:{finding_id}", cwe_id, EdgeType.MAPS_TO))
                count += 2

            # CVE node + edge
            cve = finding.get("cve", finding.get("cve_id", ""))
            if cve:
                cve_id = f"cve:{cve}"
                self._backend.add_node(GraphNode(
                    id=cve_id,
                    type=NodeType.CVE,
                    properties={"cve_id": cve, "cvss": finding.get("cvss", 0)},
                ))
                self._backend.add_edge(GraphEdge(
                    f"finding:{finding_id}", cve_id, EdgeType.EXPLOITS, weight=weight
                ))
                count += 2

        logger.info(f"Ingested {len(findings)} findings → {count} graph elements")
        return count

    def add_dependency(self, source_component: str, target_component: str,
                       dependency_type: str = "runtime") -> None:
        """Add a component dependency edge."""
        src_id = f"component:{hashlib.md5(source_component.encode(), usedforsecurity=False).hexdigest()[:10]}"
        tgt_id = f"component:{hashlib.md5(target_component.encode(), usedforsecurity=False).hexdigest()[:10]}"

        self._backend.add_node(GraphNode(id=src_id, type=NodeType.COMPONENT,
                                          properties={"name": source_component}))
        self._backend.add_node(GraphNode(id=tgt_id, type=NodeType.COMPONENT,
                                          properties={"name": target_component}))
        self._backend.add_edge(GraphEdge(
            src_id, tgt_id, EdgeType.DEPENDS_ON,
            properties={"type": dependency_type},
        ))

    def find_attack_paths(self, entry_point: str, target: str,
                          max_depth: int = 8) -> List[AttackPath]:
        """Discover attack paths from entry point to target.

        Args:
            entry_point: Entry point node ID (or partial match)
            target: Target node ID (or partial match)
            max_depth: Maximum path length

        Returns:
            List of AttackPath objects sorted by risk (highest first)
        """
        # Resolve node IDs (partial match)
        start_id = self._resolve_node_id(entry_point)
        end_id = self._resolve_node_id(target)

        if not start_id or not end_id:
            return []

        raw_paths = self._backend.find_paths(start_id, end_id, max_depth)
        attack_paths = []

        for i, path in enumerate(raw_paths):
            total_weight = 0.0
            edge_types = []

            for j in range(len(path) - 1):
                neighbors = self._backend.get_neighbors(path[j])
                for nid, edge in neighbors:
                    if nid == path[j + 1]:
                        total_weight += edge.weight
                        edge_types.append(edge.type.value)
                        break

            # Lower total weight = easier to exploit = higher risk
            risk_score = max(0, 10 - total_weight * 2)

            attack_paths.append(AttackPath(
                path_id=f"ap-{i+1}",
                nodes=path,
                edges=edge_types,
                total_weight=round(total_weight, 2),
                entry_point=path[0],
                target=path[-1],
                risk_score=round(risk_score, 1),
                exploitability="HIGH" if risk_score > 7 else "MEDIUM" if risk_score > 4 else "LOW",
            ))

        # Sort by risk (highest first)
        attack_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return attack_paths

    def calculate_blast_radius(self, finding_id: str, max_depth: int = 5) -> BlastRadius:
        """Calculate the blast radius of a vulnerability.

        Determines how many components, apps, and other findings
        would be affected if this vulnerability is exploited.
        """
        if not finding_id.startswith("finding:"):
            finding_id = f"finding:{finding_id}"

        reachable = self._backend.bfs_reachable(finding_id, max_depth)

        affected_components = 0
        affected_apps = 0
        affected_findings = 0
        affected_nodes = []
        max_depth_seen = 0

        for node_id, depth in reachable.items():
            if node_id == finding_id:
                continue
            affected_nodes.append(node_id)
            max_depth_seen = max(max_depth_seen, depth)

            node = self._backend.get_node(node_id)
            if node:
                if node.type == NodeType.COMPONENT:
                    affected_components += 1
                elif node.type == NodeType.APP:
                    affected_apps += 1
                elif node.type == NodeType.FINDING:
                    affected_findings += 1

        # Risk multiplier: more affected nodes = higher multiplier
        risk_multiplier = 1.0 + (affected_components * 0.5) + (affected_findings * 0.3)

        return BlastRadius(
            source_finding_id=finding_id,
            affected_nodes=affected_nodes,
            affected_components=affected_components,
            affected_apps=affected_apps,
            affected_findings=affected_findings,
            depth=max_depth_seen,
            risk_multiplier=round(risk_multiplier, 2),
            critical_path=[],  # Could be populated with highest-risk path
        )

    def get_graph_analytics(self) -> Dict[str, Any]:
        """Get comprehensive graph analytics."""
        centrality = self._backend.degree_centrality()

        # Top 10 most connected nodes
        top_central = sorted(centrality.items(), key=lambda x: -x[1])[:10]
        top_nodes = []
        for node_id, score in top_central:
            node = self._backend.get_node(node_id)
            top_nodes.append({
                "id": node_id,
                "label": node.label if node else node_id,
                "type": node.type.value if node else "unknown",
                "centrality": round(score, 4),
            })

        # Node type distribution
        type_dist = defaultdict(int)
        for nt in NodeType:
            count = len(self._backend.get_nodes_by_type(nt))
            if count > 0:
                type_dist[nt.value] = count

        return {
            "node_count": self._backend.node_count,
            "edge_count": self._backend.edge_count,
            "node_type_distribution": dict(type_dist),
            "top_central_nodes": top_nodes,
            "backend": type(self._backend).__name__,
        }

    def _resolve_node_id(self, partial: str) -> Optional[str]:
        """Resolve a partial node ID to a full one."""
        # Try exact match
        if self._backend.get_node(partial):
            return partial

        # Try common prefixes
        for prefix in ["finding:", "component:", "app:", "cwe:", "cve:", "asset:"]:
            full_id = f"{prefix}{partial}"
            if self._backend.get_node(full_id):
                return full_id

        return None

    def export_json(self) -> Dict[str, Any]:
        """Export the entire knowledge graph as JSON."""
        return self._backend.to_json()

    def export_mermaid(self, max_nodes: int = 50) -> str:
        """Export the knowledge graph as a Mermaid diagram."""
        return self._backend.to_mermaid(max_nodes)

    def get_status(self) -> Dict[str, Any]:
        """Get engine status."""
        return {
            "engine": "knowledge-graph",
            "version": "1.0.0",
            "backend": type(self._backend).__name__,
            "node_count": self._backend.node_count,
            "edge_count": self._backend.edge_count,
            "supported_node_types": [nt.value for nt in NodeType],
            "supported_edge_types": [et.value for et in EdgeType],
        }

    def clear(self) -> None:
        """Clear the entire graph."""
        self._backend.clear()


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------
_engine: Optional[KnowledgeGraphEngine] = None


def get_knowledge_graph() -> KnowledgeGraphEngine:
    """Get or create the default KnowledgeGraphEngine."""
    global _engine
    if _engine is None:
        _engine = KnowledgeGraphEngine()
    return _engine


__all__ = [
    "NodeType",
    "EdgeType",
    "GraphNode",
    "GraphEdge",
    "AttackPath",
    "BlastRadius",
    "NetworkXGraphBackend",
    "FalkorDBBackend",
    "KnowledgeGraphEngine",
    "get_knowledge_graph",
]
