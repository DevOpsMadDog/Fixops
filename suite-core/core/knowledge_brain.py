"""
FixOps Knowledge Brain — The Central Intelligence Graph.

Unified knowledge graph that stores ALL security entities and their relationships.
Every API call writes to the graph, every query reads from it.
Built on ProvenanceGraph's proven SQLite + NetworkX pattern.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import networkx as nx
except (ImportError, AttributeError):
    nx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Entity & Edge Type Enums
# ---------------------------------------------------------------------------


class EntityType(str, Enum):
    """All entity types stored in the Knowledge Brain."""
    CVE = "cve"
    CWE = "cwe"
    CPE = "cpe"
    ASSET = "asset"
    FINDING = "finding"
    REMEDIATION = "remediation"
    ATTACK = "attack"
    EVIDENCE = "evidence"
    USER = "user"
    TEAM = "team"
    SCAN = "scan"
    SESSION = "session"
    CLUSTER = "cluster"
    BUNDLE = "bundle"
    TASK = "task"
    WORKFLOW = "workflow"
    REPORT = "report"
    INTEGRATION = "integration"
    POLICY = "policy"
    COMMENT = "comment"
    COMPONENT = "component"
    SERVICE = "service"
    FEED = "feed"
    THREAT_ACTOR = "threat_actor"
    TECHNIQUE = "technique"
    PLAYBOOK = "playbook"
    ORGANIZATION = "organization"
    EXPOSURE_CASE = "exposure_case"
    CONNECTOR = "connector"
    ALERT = "alert"
    AGENT = "agent"


class EdgeType(str, Enum):
    """All relationship types in the Knowledge Brain."""
    EXPLOITS = "exploits"
    MITIGATES = "mitigates"
    AFFECTS = "affects"
    CHAINS_TO = "chains_to"
    CORRELATES_WITH = "correlates_with"
    BELONGS_TO = "belongs_to"
    CREATED_BY = "created_by"
    ASSIGNED_TO = "assigned_to"
    FOUND_BY = "found_by"
    CLUSTERED_IN = "clustered_in"
    REMEDIATED_BY = "remediated_by"
    EVIDENCED_BY = "evidenced_by"
    MEMBER_OF = "member_of"
    USED_BY = "used_by"
    EXPOSED_ON = "exposed_on"
    OWNED_BY = "owned_by"
    HAS_POLICY = "has_policy"
    HAS_EPSS = "has_epss"
    IN_KEV = "in_kev"
    DEPENDS_ON = "depends_on"
    TRIGGERS = "triggers"
    REFERENCES = "references"
    PRODUCED_BY = "produced_by"
    INCLUDES = "includes"
    TARGETS = "targets"
    DETECTED_BY = "detected_by"
    BLOCKS = "blocks"
    PARENT_OF = "parent_of"
    MAPS_TO = "maps_to"
    GROUPS = "groups"
    RESOLVES = "resolves"


@dataclass
class GraphNode:
    """A node in the Knowledge Brain."""
    node_id: str
    node_type: EntityType
    org_id: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


@dataclass
class GraphEdge:
    """An edge in the Knowledge Brain."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass
class GraphQueryResult:
    """Result of a graph query."""
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    total_nodes: int = 0
    total_edges: int = 0
    query_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# Knowledge Brain Core Engine
# ---------------------------------------------------------------------------


class KnowledgeBrain:
    """
    The Central Intelligence Graph for FixOps.

    Every security entity (CVE, finding, asset, scan, user, etc.) is a node.
    Every relationship (affects, mitigates, belongs_to, etc.) is an edge.
    Persisted in SQLite for durability, NetworkX for fast traversal.
    Thread-safe for concurrent API access.
    """

    _instance: Optional["KnowledgeBrain"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: str | Path = "fixops_brain.db") -> None:
        self.db_path = str(db_path)
        self._conn_lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()
        if nx is not None:
            self._graph = nx.MultiDiGraph()
        else:
            self._graph = None
        self._load_from_db()
        logger.info(
            "KnowledgeBrain initialized: %d nodes, %d edges (db=%s)",
            self.node_count(), self.edge_count(), self.db_path,
        )

    @classmethod
    def get_instance(cls, db_path: str | Path = "fixops_brain.db") -> "KnowledgeBrain":
        """Get or create the singleton KnowledgeBrain instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(db_path=db_path)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (for testing)."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.close()
                cls._instance = None

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def _create_tables(self) -> None:
        with self._conn_lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS brain_nodes (
                    node_id    TEXT PRIMARY KEY,
                    node_type  TEXT NOT NULL,
                    org_id     TEXT,
                    properties TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_nodes_type ON brain_nodes(node_type);
                CREATE INDEX IF NOT EXISTS idx_nodes_org  ON brain_nodes(org_id);

                CREATE TABLE IF NOT EXISTS brain_edges (
                    source_id  TEXT NOT NULL,
                    target_id  TEXT NOT NULL,
                    edge_type  TEXT NOT NULL,
                    properties TEXT NOT NULL DEFAULT '{}',
                    confidence REAL NOT NULL DEFAULT 1.0,
                    created_at TEXT NOT NULL,
                    UNIQUE(source_id, target_id, edge_type)
                );
                CREATE INDEX IF NOT EXISTS idx_edges_source ON brain_edges(source_id);
                CREATE INDEX IF NOT EXISTS idx_edges_target ON brain_edges(target_id);
                CREATE INDEX IF NOT EXISTS idx_edges_type   ON brain_edges(edge_type);

                CREATE TABLE IF NOT EXISTS brain_events (
                    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    source     TEXT NOT NULL,
                    data       TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_type ON brain_events(event_type);
            """)

    def _load_from_db(self) -> None:
        """Load all nodes and edges from SQLite into NetworkX graph."""
        if self._graph is None:
            return
        with self._conn_lock:
            cursor = self._conn.execute(
                "SELECT node_id, node_type, org_id, properties, created_at, updated_at FROM brain_nodes"
            )
            for row in cursor:
                node_id, node_type, org_id, props_json, created_at, updated_at = row
                props = json.loads(props_json)
                self._graph.add_node(
                    node_id, node_type=node_type, org_id=org_id,
                    created_at=created_at, updated_at=updated_at, **props,
                )
            cursor = self._conn.execute(
                "SELECT source_id, target_id, edge_type, properties, confidence, created_at FROM brain_edges"
            )
            for row in cursor:
                src, tgt, edge_type, props_json, confidence, created_at = row
                props = json.loads(props_json)
                self._graph.add_edge(
                    src, tgt, edge_type=edge_type, confidence=confidence,
                    created_at=created_at, **props,
                )

    # ------------------------------------------------------------------
    # Node CRUD
    # ------------------------------------------------------------------
    def upsert_node(self, node: GraphNode) -> GraphNode:
        """Insert or update a node in the brain."""
        node.updated_at = datetime.now(timezone.utc).isoformat()
        props_json = json.dumps(node.properties, default=str, sort_keys=True)
        with self._conn_lock:
            self._conn.execute(
                """INSERT INTO brain_nodes (node_id, node_type, org_id, properties, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(node_id) DO UPDATE SET
                       node_type=excluded.node_type,
                       org_id=excluded.org_id,
                       properties=excluded.properties,
                       updated_at=excluded.updated_at""",
                (node.node_id, node.node_type.value if isinstance(node.node_type, EntityType) else node.node_type,
                 node.org_id, props_json, node.created_at, node.updated_at),
            )
            self._conn.commit()
        if self._graph is not None:
            self._graph.add_node(
                node.node_id, node_type=node.node_type.value if isinstance(node.node_type, EntityType) else node.node_type,
                org_id=node.org_id, created_at=node.created_at,
                updated_at=node.updated_at, **node.properties,
            )
        return node

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get a node by ID."""
        with self._conn_lock:
            row = self._conn.execute(
                "SELECT node_id, node_type, org_id, properties, created_at, updated_at FROM brain_nodes WHERE node_id = ?",
                (node_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "node_id": row[0], "node_type": row[1], "org_id": row[2],
            "properties": json.loads(row[3]), "created_at": row[4], "updated_at": row[5],
        }

    def delete_node(self, node_id: str) -> bool:
        """Delete a node and all its edges."""
        with self._conn_lock:
            self._conn.execute("DELETE FROM brain_edges WHERE source_id = ? OR target_id = ?", (node_id, node_id))
            cursor = self._conn.execute("DELETE FROM brain_nodes WHERE node_id = ?", (node_id,))
            self._conn.commit()
        if self._graph is not None and self._graph.has_node(node_id):
            self._graph.remove_node(node_id)
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Edge CRUD
    # ------------------------------------------------------------------
    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        """Add or update an edge."""
        props_json = json.dumps(edge.properties, default=str, sort_keys=True)
        edge_type_val = edge.edge_type.value if isinstance(edge.edge_type, EdgeType) else edge.edge_type
        with self._conn_lock:
            self._conn.execute(
                """INSERT INTO brain_edges (source_id, target_id, edge_type, properties, confidence, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_id, target_id, edge_type) DO UPDATE SET
                       properties=excluded.properties,
                       confidence=excluded.confidence""",
                (edge.source_id, edge.target_id, edge_type_val,
                 props_json, edge.confidence, edge.created_at),
            )
            self._conn.commit()
        if self._graph is not None:
            self._graph.add_edge(
                edge.source_id, edge.target_id, edge_type=edge_type_val,
                confidence=edge.confidence, created_at=edge.created_at,
                **edge.properties,
            )
        return edge

    def get_edges(self, node_id: str, direction: str = "both") -> List[Dict[str, Any]]:
        """Get all edges connected to a node."""
        results = []
        with self._conn_lock:
            if direction in ("out", "both"):
                cursor = self._conn.execute(
                    "SELECT source_id, target_id, edge_type, properties, confidence, created_at FROM brain_edges WHERE source_id = ?",
                    (node_id,),
                )
                for row in cursor:
                    results.append({
                        "source_id": row[0], "target_id": row[1], "edge_type": row[2],
                        "properties": json.loads(row[3]), "confidence": row[4], "created_at": row[5],
                    })
            if direction in ("in", "both"):
                cursor = self._conn.execute(
                    "SELECT source_id, target_id, edge_type, properties, confidence, created_at FROM brain_edges WHERE target_id = ?",
                    (node_id,),
                )
                for row in cursor:
                    results.append({
                        "source_id": row[0], "target_id": row[1], "edge_type": row[2],
                        "properties": json.loads(row[3]), "confidence": row[4], "created_at": row[5],
                    })
        return results

    def delete_edge(self, source_id: str, target_id: str, edge_type: str) -> bool:
        """Delete a specific edge."""
        with self._conn_lock:
            cursor = self._conn.execute(
                "DELETE FROM brain_edges WHERE source_id = ? AND target_id = ? AND edge_type = ?",
                (source_id, target_id, edge_type),
            )
            self._conn.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def query_nodes(
        self,
        node_type: Optional[str] = None,
        org_id: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> GraphQueryResult:
        """Query nodes with optional filters."""
        start = time.monotonic()
        conditions = []
        params: list = []
        if node_type:
            conditions.append("node_type = ?")
            params.append(node_type)
        if org_id:
            conditions.append("org_id = ?")
            params.append(org_id)
        if search:
            conditions.append("(node_id LIKE ? OR properties LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with self._conn_lock:
            count_row = self._conn.execute(
                f"SELECT COUNT(*) FROM brain_nodes {where}", params
            ).fetchone()
            total = count_row[0] if count_row else 0

            params_page = params + [limit, offset]
            cursor = self._conn.execute(
                f"SELECT node_id, node_type, org_id, properties, created_at, updated_at FROM brain_nodes {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                params_page,
            )
            nodes = []
            for row in cursor:
                nodes.append({
                    "node_id": row[0], "node_type": row[1], "org_id": row[2],
                    "properties": json.loads(row[3]), "created_at": row[4], "updated_at": row[5],
                })

        elapsed = (time.monotonic() - start) * 1000
        return GraphQueryResult(nodes=nodes, edges=[], total_nodes=total, query_time_ms=elapsed)

    def get_neighbors(self, node_id: str, depth: int = 1, edge_types: Optional[List[str]] = None) -> GraphQueryResult:
        """Get neighbors of a node up to N hops deep."""
        start = time.monotonic()
        visited_nodes: Set[str] = {node_id}
        frontier: Set[str] = {node_id}
        all_edges: List[Dict[str, Any]] = []

        for _ in range(depth):
            next_frontier: Set[str] = set()
            for nid in frontier:
                edges = self.get_edges(nid)
                for e in edges:
                    if edge_types and e["edge_type"] not in edge_types:
                        continue
                    all_edges.append(e)
                    other = e["target_id"] if e["source_id"] == nid else e["source_id"]
                    if other not in visited_nodes:
                        visited_nodes.add(other)
                        next_frontier.add(other)
            frontier = next_frontier
            if not frontier:
                break

        nodes = [self.get_node(nid) for nid in visited_nodes]
        nodes = [n for n in nodes if n is not None]
        elapsed = (time.monotonic() - start) * 1000
        return GraphQueryResult(
            nodes=nodes, edges=all_edges,
            total_nodes=len(nodes), total_edges=len(all_edges),
            query_time_ms=elapsed,
        )

    def find_paths(self, source_id: str, target_id: str, max_depth: int = 5) -> List[List[str]]:
        """Find all paths between two nodes (up to max_depth)."""
        if self._graph is not None and nx is not None:
            try:
                paths = list(nx.all_simple_paths(self._graph, source_id, target_id, cutoff=max_depth))
                return [list(p) for p in paths[:20]]  # Cap at 20 paths
            except (nx.NodeNotFound, nx.NetworkXError):
                return []
        # Fallback: BFS
        return self._bfs_paths(source_id, target_id, max_depth)

    def _bfs_paths(self, source: str, target: str, max_depth: int) -> List[List[str]]:
        """BFS path finding without NetworkX."""
        from collections import deque
        paths: List[List[str]] = []
        queue: deque = deque([(source, [source])])
        while queue and len(paths) < 20:
            node, path = queue.popleft()
            if len(path) > max_depth + 1:
                continue
            if node == target and len(path) > 1:
                paths.append(path)
                continue
            edges = self.get_edges(node, direction="out")
            for e in edges:
                next_node = e["target_id"]
                if next_node not in path:
                    queue.append((next_node, path + [next_node]))
        return paths


    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        """Get comprehensive graph statistics."""
        with self._conn_lock:
            node_count = self._conn.execute("SELECT COUNT(*) FROM brain_nodes").fetchone()[0]
            edge_count = self._conn.execute("SELECT COUNT(*) FROM brain_edges").fetchone()[0]
            type_counts = {}
            for row in self._conn.execute("SELECT node_type, COUNT(*) FROM brain_nodes GROUP BY node_type"):
                type_counts[row[0]] = row[1]
            edge_type_counts = {}
            for row in self._conn.execute("SELECT edge_type, COUNT(*) FROM brain_edges GROUP BY edge_type"):
                edge_type_counts[row[0]] = row[1]
            org_counts = {}
            for row in self._conn.execute("SELECT org_id, COUNT(*) FROM brain_nodes WHERE org_id IS NOT NULL GROUP BY org_id"):
                org_counts[row[0]] = row[1]

        density = 0.0
        if self._graph is not None and nx is not None and node_count > 1:
            try:
                density = nx.density(self._graph)
            except Exception:
                pass

        return {
            "total_nodes": node_count,
            "total_edges": edge_count,
            "density": density,
            "node_types": type_counts,
            "edge_types": edge_type_counts,
            "organizations": org_counts,
        }

    def node_count(self) -> int:
        with self._conn_lock:
            return self._conn.execute("SELECT COUNT(*) FROM brain_nodes").fetchone()[0]

    def edge_count(self) -> int:
        with self._conn_lock:
            return self._conn.execute("SELECT COUNT(*) FROM brain_edges").fetchone()[0]

    def most_connected(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most connected nodes (highest degree)."""
        if self._graph is not None and nx is not None:
            try:
                degrees = sorted(self._graph.degree(), key=lambda x: x[1], reverse=True)[:limit]
                results = []
                for node_id, degree in degrees:
                    node = self.get_node(node_id)
                    if node:
                        node["degree"] = degree
                        results.append(node)
                return results
            except Exception:
                pass
        # Fallback
        with self._conn_lock:
            cursor = self._conn.execute("""
                SELECT node_id, cnt FROM (
                    SELECT source_id AS node_id, COUNT(*) AS cnt FROM brain_edges GROUP BY source_id
                    UNION ALL
                    SELECT target_id AS node_id, COUNT(*) AS cnt FROM brain_edges GROUP BY target_id
                ) GROUP BY node_id ORDER BY SUM(cnt) DESC LIMIT ?
            """, (limit,))
            results = []
            for row in cursor:
                node = self.get_node(row[0])
                if node:
                    node["degree"] = row[1]
                    results.append(node)
            return results

    def risk_score_for_node(self, node_id: str) -> float:
        """Calculate composite risk score based on graph context."""
        node = self.get_node(node_id)
        if not node:
            return 0.0
        base_risk = {
            "cve": 0.8, "finding": 0.7, "attack": 0.9, "threat_actor": 0.95,
            "technique": 0.85, "vulnerability": 0.8, "component": 0.3,
            "asset": 0.4, "service": 0.5,
        }.get(node["node_type"], 0.2)
        # Severity amplifier
        severity = node["properties"].get("severity", "").upper()
        sev_mult = {"CRITICAL": 1.5, "HIGH": 1.3, "MEDIUM": 1.0, "LOW": 0.6}.get(severity, 1.0)
        # Connectivity amplifier: more connections = more risk
        edges = self.get_edges(node_id)
        conn_mult = min(1.0 + len(edges) * 0.05, 2.0)
        return min(base_risk * sev_mult * conn_mult, 1.0)

    # ------------------------------------------------------------------
    # Convenience Ingest Methods
    # ------------------------------------------------------------------
    def ingest_cve(self, cve_id: str, org_id: Optional[str] = None, **props) -> GraphNode:
        """Ingest a CVE into the brain."""
        node = GraphNode(node_id=f"cve:{cve_id}", node_type=EntityType.CVE, org_id=org_id, properties={"cve_id": cve_id, **props})
        return self.upsert_node(node)

    def ingest_finding(self, finding_id: str, org_id: Optional[str] = None, cve_id: Optional[str] = None, **props) -> GraphNode:
        """Ingest a security finding."""
        node = GraphNode(node_id=f"finding:{finding_id}", node_type=EntityType.FINDING, org_id=org_id, properties={"finding_id": finding_id, **props})
        self.upsert_node(node)
        if cve_id:
            self.add_edge(GraphEdge(source_id=f"finding:{finding_id}", target_id=f"cve:{cve_id}", edge_type=EdgeType.REFERENCES))
        return node

    def ingest_scan(self, scan_id: str, org_id: Optional[str] = None, findings: Optional[List[str]] = None, **props) -> GraphNode:
        """Ingest a scan result."""
        node = GraphNode(node_id=f"scan:{scan_id}", node_type=EntityType.SCAN, org_id=org_id, properties={"scan_id": scan_id, **props})
        self.upsert_node(node)
        for fid in (findings or []):
            self.add_edge(GraphEdge(source_id=f"scan:{scan_id}", target_id=f"finding:{fid}", edge_type=EdgeType.DETECTED_BY))
        return node

    def ingest_asset(self, asset_id: str, org_id: Optional[str] = None, **props) -> GraphNode:
        """Ingest an asset."""
        return self.upsert_node(GraphNode(node_id=f"asset:{asset_id}", node_type=EntityType.ASSET, org_id=org_id, properties={"asset_id": asset_id, **props}))

    def ingest_remediation(self, task_id: str, finding_id: Optional[str] = None, org_id: Optional[str] = None, **props) -> GraphNode:
        """Ingest a remediation task."""
        node = GraphNode(node_id=f"remediation:{task_id}", node_type=EntityType.REMEDIATION, org_id=org_id, properties={"task_id": task_id, **props})
        self.upsert_node(node)
        if finding_id:
            self.add_edge(GraphEdge(source_id=f"remediation:{task_id}", target_id=f"finding:{finding_id}", edge_type=EdgeType.MITIGATES))
        return node

    def log_event(self, event_type: str, source: str, data: Dict[str, Any]) -> None:
        """Log an event to the brain's event log."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn_lock:
            self._conn.execute(
                "INSERT INTO brain_events (event_type, source, data, created_at) VALUES (?, ?, ?, ?)",
                (event_type, source, json.dumps(data, default=str), now),
            )
            self._conn.commit()

    def get_events(self, event_type: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent events from the brain."""
        with self._conn_lock:
            if event_type:
                cursor = self._conn.execute(
                    "SELECT event_id, event_type, source, data, created_at FROM brain_events WHERE event_type = ? ORDER BY event_id DESC LIMIT ?",
                    (event_type, limit),
                )
            else:
                cursor = self._conn.execute(
                    "SELECT event_id, event_type, source, data, created_at FROM brain_events ORDER BY event_id DESC LIMIT ?",
                    (limit,),
                )
            return [
                {"event_id": r[0], "event_type": r[1], "source": r[2], "data": json.loads(r[3]), "created_at": r[4]}
                for r in cursor
            ]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        """Close database connection."""
        with self._conn_lock:
            self._conn.close()
        logger.info("KnowledgeBrain closed")


# ---------------------------------------------------------------------------
# Module-level singleton accessor
# ---------------------------------------------------------------------------
def get_brain(db_path: str | Path | None = None) -> KnowledgeBrain:
    """Get the global KnowledgeBrain instance.

    Uses ``FIXOPS_BRAIN_DB_PATH`` env-var so that **all** suites
    (api, core, attack, feeds, evidence-risk, integrations) share
    a single SQLite file regardless of which process imports this.
    """
    import os
    if db_path is None:
        db_path = os.environ.get("FIXOPS_BRAIN_DB_PATH", "data/fixops_brain.db")
    resolved = Path(db_path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return KnowledgeBrain.get_instance(db_path=resolved)