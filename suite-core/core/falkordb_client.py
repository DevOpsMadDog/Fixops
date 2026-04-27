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

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


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
        _emit_event("asset.discovered", {"module": __name__, "action": "add_node"})
        self._nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        _emit_event("finding.updated", {"module": __name__, "action": "add_edge"})
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
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
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
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
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
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
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
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
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
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
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
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
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
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
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
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            return self._fallback.node_count

    @property
    def edge_count(self) -> int:
        if self._using_fallback:
            return self._fallback.edge_count
        try:
            result = self._graph.query("MATCH ()-[r]->() RETURN count(r)")
            return result.result_set[0][0]
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            return self._fallback.edge_count

    def to_json(self) -> Dict[str, Any]:
        return self._fallback.to_json()

    def to_mermaid(self, max_nodes: int = 50) -> str:
        return self._fallback.to_mermaid(max_nodes)

    def clear(self) -> None:
        if not self._using_fallback:
            try:
                self._graph.query("MATCH (n) DETACH DELETE n")
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
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
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
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


# ---------------------------------------------------------------------------
# Attack Path Traversal Engine (V2)
# Advanced BFS/DFS path finding with risk scoring, blast radius, and internet
# reachability analysis
# ---------------------------------------------------------------------------
@dataclass
class AttackPathResult:
    """Enriched attack path result with full risk scoring."""
    path_id: str
    nodes: List[str]
    edges: List[str]
    hop_count: int
    total_weight: float
    risk_score: float
    exploitability: str        # CRITICAL, HIGH, MEDIUM, LOW
    internet_reachable: bool
    data_stores_reachable: List[str]
    cve_ids_on_path: List[str]
    cvss_scores_on_path: List[float]
    max_cvss: float
    entry_point: str
    target: str
    mitigations: List[str] = field(default_factory=list)
    discovered_at: str = ""


@dataclass
class BlastRadiusV2:
    """Enhanced blast radius analysis with transitive impact scoring."""
    source_finding_id: str
    affected_nodes: List[str]
    affected_components: int
    affected_apps: int
    affected_findings: int
    chained_cves: List[str]
    max_impact_depth: int
    risk_multiplier: float
    critical_path: List[str]
    data_exposure_risk: str     # NONE, LOW, MEDIUM, HIGH, CRITICAL
    estimated_affected_users: int
    internet_blast_paths: int   # Paths reaching internet-exposed nodes


@dataclass
class InternetReachabilityPath:
    """A path from an internet-facing node to a sensitive data store."""
    path_id: str
    internet_entry_node: str
    data_store_node: str
    path_nodes: List[str]
    hop_count: int
    risk_score: float
    findings_blocking: List[str]   # Findings that must be exploited to traverse
    vulnerability_gate: bool        # True if a vuln is required to traverse


class AttackPathTraversalEngine:
    """Advanced attack path analysis engine for vulnerability knowledge graphs.

    Provides:
    - find_attack_paths(): Multi-algorithm path finding (BFS + DFS + Dijkstra)
    - calculate_blast_radius(): Comprehensive transitive impact analysis
    - get_internet_reachable_paths(): All paths from internet to data stores
    - rank_paths_by_risk(): Composite risk scoring with multiple dimensions

    Each method works on top of the KnowledgeGraphEngine backend,
    supporting both FalkorDB (Cypher queries) and NetworkX (Python BFS/DFS).

    Usage:
        kg = KnowledgeGraphEngine()
        traversal = AttackPathTraversalEngine(kg)
        paths = traversal.find_attack_paths("internet:api-gateway", "db:payments", max_hops=5)
        radius = traversal.calculate_blast_radius("finding:CVE-2024-1234")
        inet_paths = traversal.get_internet_reachable_paths()
        ranked = traversal.rank_paths_by_risk(paths)
    """

    # Node patterns that indicate internet-facing components
    INTERNET_ENTRY_PATTERNS = [
        "internet", "public", "api-gateway", "load-balancer", "cdn",
        "external", "ingress", "web", "frontend", "reverse-proxy", "nginx",
    ]

    # Node patterns that indicate sensitive data stores
    DATA_STORE_PATTERNS = [
        "database", "db:", "postgres", "mysql", "redis", "elasticsearch",
        "s3", "blob", "storage", "vault", "secret", "pii", "pan", "phi",
        "payment", "credential", "auth", "token", "key",
    ]

    def __init__(self, graph_engine: "KnowledgeGraphEngine"):
        self._graph = graph_engine
        self._backend = graph_engine._backend
        logger.info("AttackPathTraversalEngine initialized")

    def find_attack_paths(
        self,
        source_id: str,
        target_id: str,
        max_hops: int = 5,
        algorithm: str = "bfs",
    ) -> List[AttackPathResult]:
        """Find all attack paths from source to target node.

        Args:
            source_id: Starting node ID (e.g., internet-facing component)
            target_id: Target node ID (e.g., database, PII store)
            max_hops: Maximum path length in hops (default: 5)
            algorithm: "bfs" | "dfs" | "dijkstra" (default: bfs)

        Returns:
            List of AttackPathResult sorted by risk_score descending
        """
        # Resolve node IDs
        resolved_source = self._graph._resolve_node_id(source_id)
        resolved_target = self._graph._resolve_node_id(target_id)

        if not resolved_source:
            logger.warning("Attack path source not found: %s", source_id)
            return []
        if not resolved_target:
            logger.warning("Attack path target not found: %s", target_id)
            return []

        # Get raw paths
        if algorithm == "dfs":
            raw_paths = self._dfs_paths(resolved_source, resolved_target, max_hops)
        elif algorithm == "dijkstra":
            raw_paths = self._dijkstra_paths(resolved_source, resolved_target, max_hops)
        else:
            raw_paths = self._backend.find_paths(resolved_source, resolved_target, max_hops)

        results = []
        for i, path in enumerate(raw_paths[:50]):  # Cap at 50 paths
            result = self._enrich_path(path, f"ap-v2-{i+1}")
            results.append(result)

        return self.rank_paths_by_risk(results)

    def _dfs_paths(
        self, start_id: str, end_id: str, max_depth: int
    ) -> List[List[str]]:
        """DFS-based path finding (finds deeper paths that BFS might miss)."""
        paths: List[List[str]] = []
        stack = [(start_id, [start_id])]
        visited_paths: set = set()

        while stack and len(paths) < 100:
            current, path = stack.pop()

            if len(path) > max_depth:
                continue

            if current == end_id and len(path) > 1:
                key = "→".join(path)
                if key not in visited_paths:
                    paths.append(path)
                    visited_paths.add(key)
                continue

            for neighbor_id, _ in self._backend.get_neighbors(current):
                if neighbor_id not in path:
                    stack.append((neighbor_id, path + [neighbor_id]))

        return paths

    def _dijkstra_paths(
        self, start_id: str, end_id: str, max_depth: int
    ) -> List[List[str]]:
        """Dijkstra-based shortest weighted path (lowest risk weight = highest risk)."""
        import heapq as _heapq

        # Priority queue: (total_weight, path)
        pq = [(0.0, [start_id])]
        visited: Dict[str, float] = {}
        paths: List[List[str]] = []

        while pq and len(paths) < 20:
            weight, path = _heapq.heappop(pq)
            current = path[-1]

            if len(path) > max_depth:
                continue

            if current in visited and visited[current] <= weight:
                continue
            visited[current] = weight

            if current == end_id and len(path) > 1:
                paths.append(path)
                continue

            for neighbor_id, edge in self._backend.get_neighbors(current):
                if neighbor_id not in path:
                    new_weight = weight + edge.weight
                    _heapq.heappush(pq, (new_weight, path + [neighbor_id]))

        return paths

    def _enrich_path(self, path: List[str], path_id: str) -> AttackPathResult:
        """Enrich a raw path with risk scores, CVE data, and reachability info."""
        total_weight = 0.0
        edge_types: List[str] = []
        cve_ids: List[str] = []
        cvss_scores: List[float] = []
        data_stores: List[str] = []
        is_internet_reachable = False

        for j in range(len(path) - 1):
            neighbors = self._backend.get_neighbors(path[j])
            for nid, edge in neighbors:
                if nid == path[j + 1]:
                    total_weight += edge.weight
                    edge_types.append(edge.type.value)
                    break

        for node_id in path:
            node = self._backend.get_node(node_id)
            if node:
                # Check internet entry
                node_str = (node.label + " " + node_id).lower()
                if any(p in node_str for p in self.INTERNET_ENTRY_PATTERNS):
                    is_internet_reachable = True

                # Check data stores
                if any(p in node_str for p in self.DATA_STORE_PATTERNS):
                    data_stores.append(node_id)

                # Collect CVE/CVSS data
                if node.type == NodeType.CVE:
                    cve_id = node.properties.get("cve_id", node_id)
                    cve_ids.append(cve_id)
                if node.type == NodeType.FINDING:
                    cvss = float(node.properties.get("cvss", 0) or 0)
                    if cvss > 0:
                        cvss_scores.append(cvss)

        max_cvss = max(cvss_scores) if cvss_scores else 0.0
        hop_count = len(path) - 1

        # Composite risk score (0–10)
        # Lower weight = easier path = higher risk
        weight_risk = max(0, 10 - total_weight)
        # More CVEs on path = higher risk
        cve_bonus = min(2.0, len(cve_ids) * 0.5)
        # High CVSS = higher risk
        cvss_bonus = min(2.0, max_cvss / 5.0)
        # Internet reachable = higher risk
        inet_bonus = 1.5 if is_internet_reachable else 0.0
        # Shorter path = easier = higher risk
        hop_penalty = max(0, (5 - hop_count) * 0.2)

        risk_score = min(10.0, weight_risk + cve_bonus + cvss_bonus + inet_bonus + hop_penalty)

        if risk_score >= 8.5:
            exploitability = "CRITICAL"
        elif risk_score >= 6.5:
            exploitability = "HIGH"
        elif risk_score >= 4.0:
            exploitability = "MEDIUM"
        else:
            exploitability = "LOW"

        return AttackPathResult(
            path_id=path_id,
            nodes=path,
            edges=edge_types,
            hop_count=hop_count,
            total_weight=round(total_weight, 3),
            risk_score=round(risk_score, 2),
            exploitability=exploitability,
            internet_reachable=is_internet_reachable,
            data_stores_reachable=data_stores,
            cve_ids_on_path=cve_ids,
            cvss_scores_on_path=cvss_scores,
            max_cvss=max_cvss,
            entry_point=path[0],
            target=path[-1],
            discovered_at=datetime.now(timezone.utc).isoformat(),
        )

    def calculate_blast_radius(
        self,
        finding_id: str,
        max_depth: int = 5,
    ) -> BlastRadiusV2:
        """Calculate enhanced blast radius for a finding.

        Args:
            finding_id: Finding node ID (with or without 'finding:' prefix)
            max_depth: Maximum traversal depth for impact analysis

        Returns:
            BlastRadiusV2 with comprehensive impact assessment
        """
        if not finding_id.startswith("finding:"):
            finding_id = f"finding:{finding_id}"

        reachable = self._backend.bfs_reachable(finding_id, max_depth)

        affected_components = 0
        affected_apps = 0
        affected_findings = 0
        chained_cves: List[str] = []
        affected_nodes: List[str] = []
        max_depth_seen = 0
        has_sensitive_data = False
        internet_blast_paths = 0

        for node_id, depth in reachable.items():
            if node_id == finding_id:
                continue

            affected_nodes.append(node_id)
            max_depth_seen = max(max_depth_seen, depth)
            node = self._backend.get_node(node_id)

            if node:
                if node.type == NodeType.COMPONENT:
                    affected_components += 1
                    # Check if this component is internet-facing
                    name = node.label.lower()
                    if any(p in name for p in self.INTERNET_ENTRY_PATTERNS):
                        internet_blast_paths += 1
                    if any(p in name for p in self.DATA_STORE_PATTERNS):
                        has_sensitive_data = True
                elif node.type == NodeType.APP:
                    affected_apps += 1
                elif node.type == NodeType.FINDING:
                    affected_findings += 1
                elif node.type == NodeType.CVE:
                    cve_id = node.properties.get("cve_id", node_id)
                    chained_cves.append(cve_id)

        # Risk multiplier
        risk_multiplier = (
            1.0
            + (affected_components * 0.5)
            + (affected_findings * 0.3)
            + (len(chained_cves) * 0.4)
            + (2.0 if has_sensitive_data else 0.0)
        )

        # Data exposure risk
        if has_sensitive_data and affected_components > 5:
            data_exposure = "CRITICAL"
        elif has_sensitive_data or affected_components > 10:
            data_exposure = "HIGH"
        elif affected_components > 5:
            data_exposure = "MEDIUM"
        elif affected_components > 0:
            data_exposure = "LOW"
        else:
            data_exposure = "NONE"

        # Critical path: highest-centrality nodes in affected set
        centrality = self._backend.degree_centrality()
        critical_path = sorted(
            affected_nodes,
            key=lambda nid: centrality.get(nid, 0),
            reverse=True,
        )[:5]

        return BlastRadiusV2(
            source_finding_id=finding_id,
            affected_nodes=affected_nodes,
            affected_components=affected_components,
            affected_apps=affected_apps,
            affected_findings=affected_findings,
            chained_cves=chained_cves,
            max_impact_depth=max_depth_seen,
            risk_multiplier=round(risk_multiplier, 2),
            critical_path=critical_path,
            data_exposure_risk=data_exposure,
            estimated_affected_users=affected_apps * 1000,  # Heuristic estimate
            internet_blast_paths=internet_blast_paths,
        )

    def get_internet_reachable_paths(
        self,
        max_paths: int = 50,
        max_hops: int = 6,
    ) -> List[InternetReachabilityPath]:
        """Find all paths from internet-facing nodes to sensitive data stores.

        This is the core "crown jewels" analysis — shows all paths
        an external attacker could traverse to reach sensitive data.

        Args:
            max_paths: Maximum number of paths to return
            max_hops: Maximum path depth

        Returns:
            List of InternetReachabilityPath sorted by risk score
        """
        # Find all internet entry nodes
        all_nodes = list(self._backend._nodes.values()) if hasattr(
            self._backend, "_nodes"
        ) else self._backend.get_nodes_by_type(NodeType.COMPONENT)

        internet_nodes = []
        data_store_nodes = []

        for node in all_nodes:
            name_lower = (node.label + " " + node.id).lower()
            if any(p in name_lower for p in self.INTERNET_ENTRY_PATTERNS):
                internet_nodes.append(node.id)
            if any(p in name_lower for p in self.DATA_STORE_PATTERNS):
                data_store_nodes.append(node.id)

        # Also include endpoints as internet entry points
        endpoints = self._backend.get_nodes_by_type(NodeType.ENDPOINT)
        internet_nodes.extend([e.id for e in endpoints])

        if not internet_nodes or not data_store_nodes:
            logger.info(
                "Internet reachability analysis: %d entry nodes, %d data stores",
                len(internet_nodes), len(data_store_nodes),
            )
            return []

        results: List[InternetReachabilityPath] = []
        path_counter = 0

        for entry_node in internet_nodes[:20]:  # Cap entry nodes
            for data_node in data_store_nodes[:10]:  # Cap data stores
                if len(results) >= max_paths:
                    break

                raw_paths = self._backend.find_paths(entry_node, data_node, max_hops)
                for path in raw_paths[:5]:  # Max 5 paths per pair
                    path_counter += 1
                    findings_on_path = [
                        nid for nid in path
                        if nid.startswith("finding:")
                    ]

                    # Enriched path
                    enriched = self._enrich_path(path, f"inet-{path_counter}")

                    ir_path = InternetReachabilityPath(
                        path_id=f"inet-{path_counter}",
                        internet_entry_node=entry_node,
                        data_store_node=data_node,
                        path_nodes=path,
                        hop_count=len(path) - 1,
                        risk_score=enriched.risk_score,
                        findings_blocking=findings_on_path,
                        vulnerability_gate=len(findings_on_path) > 0,
                    )
                    results.append(ir_path)

        # Sort by risk score
        results.sort(key=lambda p: p.risk_score, reverse=True)

        logger.info(
            "Internet reachability analysis: %d paths found (%d entry nodes, %d data stores)",
            len(results), len(internet_nodes), len(data_store_nodes),
        )
        return results[:max_paths]

    def rank_paths_by_risk(
        self,
        paths: List[AttackPathResult],
    ) -> List[AttackPathResult]:
        """Sort attack paths by composite risk score.

        Scoring dimensions:
        1. risk_score (primary, 0–10)
        2. internet_reachable bonus (+1.0)
        3. max_cvss contribution
        4. data stores reachable bonus
        5. hop count penalty (shorter = easier)

        Args:
            paths: List of AttackPathResult to rank

        Returns:
            Paths sorted by composite score (highest risk first)
        """
        def composite_score(p: AttackPathResult) -> float:
            score = p.risk_score
            # Internet-facing paths are higher priority
            score += 0.5 if p.internet_reachable else 0.0
            # Paths reaching sensitive data are higher priority
            score += min(2.0, len(p.data_stores_reachable) * 0.5)
            # High CVSS paths
            score += min(1.0, p.max_cvss / 10.0)
            return score

        return sorted(paths, key=composite_score, reverse=True)

    def get_attack_surface_summary(self) -> Dict[str, Any]:
        """Generate an executive-level attack surface summary.

        Returns a risk dashboard showing:
        - Internet entry points
        - Critical data stores
        - Number of viable attack paths
        - Highest risk path overview
        """
        inet_paths = self.get_internet_reachable_paths(max_paths=100)

        critical_paths = [p for p in inet_paths if p.risk_score >= 8.0]
        high_paths = [p for p in inet_paths if 6.0 <= p.risk_score < 8.0]
        gated_paths = [p for p in inet_paths if p.vulnerability_gate]
        ungated_paths = [p for p in inet_paths if not p.vulnerability_gate]

        top_path = inet_paths[0] if inet_paths else None

        return {
            "total_internet_reachable_paths": len(inet_paths),
            "critical_risk_paths": len(critical_paths),
            "high_risk_paths": len(high_paths),
            "paths_requiring_vuln_exploit": len(gated_paths),
            "paths_without_vuln_gate": len(ungated_paths),
            "top_risk_path": {
                "path_id": top_path.path_id,
                "risk_score": top_path.risk_score,
                "hop_count": top_path.hop_count,
                "entry": top_path.internet_entry_node,
                "target": top_path.data_store_node,
            } if top_path else None,
            "unique_entry_nodes": len({p.internet_entry_node for p in inet_paths}),
            "unique_data_stores": len({p.data_store_node for p in inet_paths}),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Natural Language to Cypher Query Engine
# ---------------------------------------------------------------------------

# Pre-built query templates for common security questions
NL_QUERY_TEMPLATES: List[Dict[str, Any]] = [
    {
        "description": "Find all critical findings",
        "patterns": ["critical findings", "all critical", "severity critical", "critical vulnerabilities"],
        "cypher": "MATCH (f:Finding {severity: 'critical'}) RETURN f._id, f.title, f.cvss LIMIT 50",
        "networkx_func": "get_nodes_by_type",
        "networkx_filter": {"type": "FINDING", "severity": "critical"},
    },
    {
        "description": "Find attack paths to database",
        "patterns": ["attack path to database", "attack paths to database", "reach the database", "path to db", "database access"],
        "cypher": "MATCH p = ()-[*1..5]->(n) WHERE n._id CONTAINS 'db' OR n._id CONTAINS 'database' RETURN p LIMIT 20",
        "networkx_func": "find_paths_to_pattern",
        "networkx_pattern": "db",
    },
    {
        "description": "List all internet-facing components",
        "patterns": ["internet facing", "internet-facing", "public facing", "external endpoints", "exposed services"],
        "cypher": "MATCH (c:Component) WHERE c.name CONTAINS 'internet' OR c.name CONTAINS 'public' RETURN c._id, c.name LIMIT 50",
        "networkx_func": "get_nodes_by_type",
        "networkx_filter": {"type": "COMPONENT", "name_contains": "internet"},
    },
    {
        "description": "Find unpatched high and critical CVEs",
        "patterns": ["unpatched cve", "open cve", "cve not fixed", "outstanding vulnerabilities"],
        "cypher": "MATCH (f:Finding)-[:EXPLOITS]->(c:CVE) WHERE f.status = 'open' AND f.severity IN ['critical', 'high'] RETURN f._id, c.cve_id, f.cvss ORDER BY f.cvss DESC LIMIT 30",
        "networkx_func": "get_open_cves",
    },
    {
        "description": "Find components with most vulnerabilities",
        "patterns": ["most vulnerable component", "highest risk component", "component with most findings"],
        "cypher": "MATCH (c:Component)-[:HAS_FINDING]->(f:Finding) RETURN c.name, count(f) as finding_count ORDER BY finding_count DESC LIMIT 10",
        "networkx_func": "rank_by_finding_count",
    },
    {
        "description": "Find compliance violations for SOC2",
        "patterns": ["soc2 violation", "soc 2 gap", "soc2 compliance", "cc6 control"],
        "cypher": "MATCH (f:Finding) WHERE f.status = 'open' AND f.severity IN ['critical', 'high', 'medium'] RETURN f._id, f.title, f.severity LIMIT 30",
        "networkx_func": "get_compliance_violations",
        "framework": "soc2",
    },
    {
        "description": "Find all RCE vulnerabilities",
        "patterns": ["rce", "remote code execution", "code execution", "arbitrary code"],
        "cypher": "MATCH (f:Finding) WHERE f.title CONTAINS 'RCE' OR f.title CONTAINS 'Code Execution' OR f.cwe IN ['CWE-78', 'CWE-94', 'CWE-77'] RETURN f._id, f.title, f.cvss ORDER BY f.cvss DESC LIMIT 20",
        "networkx_func": "get_by_cwe",
        "cwe_list": ["CWE-78", "CWE-94", "CWE-77"],
    },
    {
        "description": "Find all SQL injection vulnerabilities",
        "patterns": ["sql injection", "sqli", "sql vuln", "database injection"],
        "cypher": "MATCH (f:Finding) WHERE f.cwe = 'CWE-89' OR f.title CONTAINS 'SQL' RETURN f._id, f.title, f.severity LIMIT 20",
        "networkx_func": "get_by_cwe",
        "cwe_list": ["CWE-89"],
    },
    {
        "description": "Find findings overdue for SLA",
        "patterns": ["sla breach", "overdue findings", "past sla", "sla violation"],
        "cypher": "MATCH (f:Finding) WHERE f.status = 'open' AND f.severity = 'critical' RETURN f._id, f.title, f.created_at ORDER BY f.created_at ASC LIMIT 20",
        "networkx_func": "get_overdue_findings",
    },
    {
        "description": "Find all findings in a specific application",
        "patterns": ["findings in app", "vulnerabilities in application", "app security status"],
        "cypher": "MATCH (a:App {_id: $app_id})-[:HAS_COMPONENT]->(c:Component)-[:HAS_FINDING]->(f:Finding) RETURN f._id, f.title, f.severity LIMIT 50",
        "networkx_func": "get_app_findings",
        "requires_params": ["app_id"],
    },
]


class NLQueryEngine:
    """Natural Language to Cypher/Python query translator for the knowledge graph.

    Converts plain English security questions into graph queries using:
    1. Template matching: fast keyword-based matching for common questions
    2. LLM translation: for novel/complex questions via the inference backend

    Supports both FalkorDB (Cypher) and NetworkX (Python API) backends.

    Usage:
        engine = NLQueryEngine(kg_engine, inference_backend)
        result = engine.nl_to_cypher("Which apps have critical SQL injection issues?")
        result = engine.query("Show me all internet-facing components with open CVEs")
    """

    # Cypher injection prevention: blocked keywords
    CYPHER_BLOCKLIST = [
        "DELETE", "DETACH", "DROP", "CREATE", "SET", "REMOVE", "MERGE",
        "CALL", "LOAD", "PERIODIC", "--", "/*", "*/",
    ]

    def __init__(
        self,
        graph_engine: "KnowledgeGraphEngine",
        inference_backend: Optional[Any] = None,
    ):
        self._graph = graph_engine
        self._backend = graph_engine._backend
        self._inference = inference_backend
        self._query_history: List[Dict[str, Any]] = []
        logger.info("NLQueryEngine initialized (inference_backend=%s)",
                    type(inference_backend).__name__ if inference_backend else "none")

    def nl_to_cypher(self, question: str) -> Dict[str, Any]:
        """Convert a natural language security question to Cypher query.

        First tries template matching (fast, no LLM), then falls back
        to LLM-powered translation for novel questions.

        Args:
            question: Natural language question about the security graph

        Returns:
            Dict with: cypher, description, method (template|llm|fallback),
                       parameters, estimated_rows
        """
        question_lower = question.lower().strip()

        # Step 1: Template matching
        template_result = self._match_template(question_lower)
        if template_result:
            self._log_query(question, template_result["cypher"], "template")
            return template_result

        # Step 2: LLM translation (if backend available)
        if self._inference:
            try:
                llm_result = self._llm_translate(question)
                if llm_result:
                    validated = self._validate_and_sanitize_cypher(llm_result["cypher"])
                    if validated:
                        llm_result["cypher"] = validated
                        self._log_query(question, validated, "llm")
                        return llm_result
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.warning("LLM Cypher translation failed: %s", e)

        # Step 3: Fallback — generic node search
        fallback_cypher = self._build_fallback_query(question_lower)
        self._log_query(question, fallback_cypher, "fallback")
        return {
            "cypher": fallback_cypher,
            "description": f"Generic search for: {question}",
            "method": "fallback",
            "parameters": {},
            "estimated_rows": 50,
        }

    def query(
        self,
        question: str,
        parameters: Optional[Dict[str, Any]] = None,
        max_results: int = 100,
    ) -> Dict[str, Any]:
        """Execute a natural language query against the knowledge graph.

        Args:
            question: Natural language security question
            parameters: Optional parameters for parameterized queries
            max_results: Maximum result rows

        Returns:
            Dict with: results, query_used, method, execution_time_ms, count
        """
        import time as _time
        start = _time.time()

        translation = self.nl_to_cypher(question)
        cypher = translation.get("cypher", "")
        method = translation.get("method", "fallback")

        # Apply parameter substitution
        params = parameters or translation.get("parameters", {})

        # Execute against FalkorDB if available
        results = []
        try:
            if (hasattr(self._backend, "_graph") and
                    not self._backend._using_fallback and
                    self._backend._graph is not None):
                # FalkorDB execution
                query_result = self._backend._graph.query(cypher, params)
                for row in query_result.result_set[:max_results]:
                    if isinstance(row, (list, tuple)):
                        results.append([
                            dict(item.properties) if hasattr(item, "properties") else item
                            for item in row
                        ])
                    else:
                        results.append(row)
            else:
                # NetworkX fallback execution
                results = self._execute_networkx_query(translation, params, max_results)
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("Query execution error: %s (falling back to NX)", e)
            results = self._execute_networkx_query(translation, params, max_results)

        elapsed = (_time.time() - start) * 1000

        return {
            "question": question,
            "results": results,
            "count": len(results),
            "query_used": cypher,
            "method": method,
            "execution_time_ms": round(elapsed, 1),
            "parameters_used": params,
        }

    def _match_template(self, question_lower: str) -> Optional[Dict[str, Any]]:
        """Match question against pre-built templates."""
        for template in NL_QUERY_TEMPLATES:
            for pattern in template["patterns"]:
                if pattern in question_lower:
                    return {
                        "cypher": template["cypher"],
                        "description": template["description"],
                        "method": "template",
                        "parameters": {},
                        "estimated_rows": 50,
                        "template_id": template["description"],
                    }
        return None

    def _llm_translate(self, question: str) -> Optional[Dict[str, Any]]:
        """Use LLM to translate natural language to Cypher."""
        if not self._inference:
            return None

        graph_schema = self._describe_graph_schema()

        system_prompt = (
            "You are a Cypher query expert for a security vulnerability knowledge graph.\n"
            "Graph schema:\n"
            f"{graph_schema}\n\n"
            "Convert the user's natural language question to a valid, read-only Cypher query.\n"
            "Rules:\n"
            "1. Only use MATCH, WHERE, RETURN, ORDER BY, LIMIT (NO writes)\n"
            "2. All queries must have LIMIT <= 100\n"
            "3. Use node labels: App, Component, Finding, CWE, CVE, Asset, Control, Endpoint\n"
            "4. Use relationship types: HAS_COMPONENT, HAS_FINDING, EXPLOITS, DEPENDS_ON, MAPS_TO\n"
            "5. Node ID property is _id\n\n"
            'Respond ONLY with valid JSON: {"cypher": "<query>", "description": "<what it does>"}'
        )

        response, _ = self._inference.generate(
            prompt=f"Convert to Cypher: {question}",
            system_prompt=system_prompt,
            max_tokens=512,
            temperature=0.1,
        )

        # Parse response
        try:
            import re as _re
            json_match = _re.search(r"\{[^{}]*\}", response, _re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                if "cypher" in parsed:
                    return {
                        "cypher": parsed["cypher"],
                        "description": parsed.get("description", question),
                        "method": "llm",
                        "parameters": {},
                        "estimated_rows": 50,
                    }
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("LLM response parse error: %s", e)

        return None

    def _validate_and_sanitize_cypher(self, cypher: str) -> Optional[str]:
        """Validate Cypher query for safety (read-only enforcement).

        Args:
            cypher: Cypher query string to validate

        Returns:
            Sanitized query or None if blocked
        """
        if not cypher or not cypher.strip():
            return None

        cypher_upper = cypher.upper()

        # Block write operations
        for blocked in self.CYPHER_BLOCKLIST:
            if blocked in cypher_upper:
                logger.warning("Blocked unsafe Cypher keyword: %s", blocked)
                return None

        # Must contain MATCH and RETURN
        if "MATCH" not in cypher_upper:
            logger.warning("Cypher query missing MATCH clause")
            return None
        if "RETURN" not in cypher_upper:
            logger.warning("Cypher query missing RETURN clause")
            return None

        # Enforce LIMIT
        if "LIMIT" not in cypher_upper:
            cypher = cypher.rstrip(";").strip() + " LIMIT 100"

        return cypher.strip()

    def _build_fallback_query(self, question_lower: str) -> str:
        """Build a generic fallback query based on keywords in the question."""
        if "finding" in question_lower or "vulnerability" in question_lower:
            return "MATCH (f:Finding) RETURN f._id, f.title, f.severity LIMIT 50"
        elif "component" in question_lower or "service" in question_lower:
            return "MATCH (c:Component) RETURN c._id, c.name LIMIT 50"
        elif "app" in question_lower or "application" in question_lower:
            return "MATCH (a:App) RETURN a._id, a.name LIMIT 20"
        elif "cve" in question_lower:
            return "MATCH (c:CVE) RETURN c._id, c.cve_id, c.cvss ORDER BY c.cvss DESC LIMIT 30"
        elif "attack" in question_lower or "path" in question_lower:
            return "MATCH p = ()-[r:ATTACK_STEP*1..3]->(t) RETURN p LIMIT 20"
        else:
            return "MATCH (n) RETURN n._id, labels(n)[0] as type LIMIT 50"

    def _execute_networkx_query(
        self,
        translation: Dict[str, Any],
        params: Dict[str, Any],
        max_results: int,
    ) -> List[Any]:
        """Execute query against NetworkX backend."""
        func_name = translation.get("networkx_func")
        nx_filter = translation.get("networkx_filter", {})

        if func_name == "get_nodes_by_type" and nx_filter:
            node_type_str = nx_filter.get("type", "FINDING")
            try:
                node_type = NodeType(node_type_str)
                nodes = self._backend.get_nodes_by_type(node_type)
                # Apply additional filters
                if "severity" in nx_filter:
                    nodes = [n for n in nodes
                             if n.properties.get("severity") == nx_filter["severity"]]
                if "name_contains" in nx_filter:
                    nodes = [n for n in nodes
                             if nx_filter["name_contains"] in n.label.lower()]
                return [
                    {"id": n.id, "label": n.label, "properties": n.properties}
                    for n in nodes[:max_results]
                ]
            except ValueError:
                pass

        # Generic: return all nodes of most relevant type
        all_nodes = []
        for nt in NodeType:
            try:
                nodes = self._backend.get_nodes_by_type(nt)
                all_nodes.extend(nodes[:20])
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                pass

        return [
            {"id": n.id, "type": n.type.value, "label": n.label}
            for n in all_nodes[:max_results]
        ]

    def _describe_graph_schema(self) -> str:
        """Generate a schema description for LLM context."""
        node_counts = {}
        for nt in NodeType:
            count = len(self._backend.get_nodes_by_type(nt))
            if count > 0:
                node_counts[nt.value] = count

        return (
            f"Nodes: {', '.join(f'{k}({v})' for k, v in node_counts.items())}\n"
            f"Edge types: {', '.join(et.value for et in EdgeType)}\n"
            f"Node properties: Finding(title, severity, cwe, cvss, status), "
            f"Component(name, path), App(name), CVE(cve_id, cvss)"
        )

    def _log_query(self, question: str, cypher: str, method: str) -> None:
        """Log a query to history."""
        self._query_history.append({
            "question": question,
            "cypher": cypher,
            "method": method,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        if len(self._query_history) > 5000:
            self._query_history = self._query_history[-2500:]

    def get_query_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent query history."""
        return self._query_history[-limit:]

    def get_template_list(self) -> List[Dict[str, str]]:
        """List all available pre-built query templates."""
        return [
            {"description": t["description"], "patterns": t["patterns"]}
            for t in NL_QUERY_TEMPLATES
        ]


# ---------------------------------------------------------------------------
# Extend KnowledgeGraphEngine with V2 attack path engine
# ---------------------------------------------------------------------------
def get_attack_path_engine(
    kg: Optional["KnowledgeGraphEngine"] = None,
) -> AttackPathTraversalEngine:
    """Get an AttackPathTraversalEngine for a KnowledgeGraphEngine.

    Args:
        kg: Optional KnowledgeGraphEngine (default: global engine)

    Returns:
        AttackPathTraversalEngine instance
    """
    if kg is None:
        kg = get_knowledge_graph()
    return AttackPathTraversalEngine(kg)


def get_nl_query_engine(
    kg: Optional["KnowledgeGraphEngine"] = None,
    inference_backend: Optional[Any] = None,
) -> NLQueryEngine:
    """Get an NLQueryEngine for a KnowledgeGraphEngine.

    Args:
        kg: Optional KnowledgeGraphEngine (default: global engine)
        inference_backend: Optional inference backend for LLM translation

    Returns:
        NLQueryEngine instance
    """
    if kg is None:
        kg = get_knowledge_graph()
    return NLQueryEngine(kg, inference_backend)


# ---------------------------------------------------------------------------
# Update __all__
# ---------------------------------------------------------------------------
__all__ = [  # type: ignore[assignment]
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
    # V2 additions
    "AttackPathResult",
    "BlastRadiusV2",
    "InternetReachabilityPath",
    "AttackPathTraversalEngine",
    "NL_QUERY_TEMPLATES",
    "NLQueryEngine",
    "get_attack_path_engine",
    "get_nl_query_engine",
]
