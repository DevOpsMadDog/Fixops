"""Attack path analysis — graph-based lateral movement path discovery.

SQLite-backed engine for modeling attack paths through a network.
Given an entry point (compromised host), finds all paths an attacker
could take to reach crown jewel assets using known vulnerabilities
and network topology.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Optional

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

_logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# ML GNN attack path scorer (optional — degrades gracefully if unavailable)
# ---------------------------------------------------------------------------

try:
    from core.ml.attack_path_gnn import AttackPathGNN as _AttackPathGNN

    _gnn: Optional[_AttackPathGNN] = _AttackPathGNN()
except (ImportError, Exception):
    _gnn = None

VALID_NODE_TYPES = {
    "workstation",
    "server",
    "database",
    "cloud_service",
    "network_device",
    "external",
}


class AttackNode:
    """Represents a network node (host, service, database) in the attack graph."""

    __slots__ = (
        "node_id", "node_type", "name", "risk_score",
        "is_crown_jewel", "vulnerabilities", "org_id",
    )

    def __init__(
        self,
        node_id: str,
        node_type: str,
        name: str,
        risk_score: float = 50.0,
        is_crown_jewel: bool = False,
        vulnerabilities: list[str] | None = None,
        org_id: str = "default",
    ) -> None:
        self.node_id = node_id
        self.node_type = node_type
        self.name = name
        self.risk_score = risk_score
        self.is_crown_jewel = is_crown_jewel
        self.vulnerabilities = vulnerabilities or []
        self.org_id = org_id

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "name": self.name,
            "risk_score": self.risk_score,
            "is_crown_jewel": self.is_crown_jewel,
            "vulnerabilities": self.vulnerabilities,
            "org_id": self.org_id,
        }


class AttackEdge:
    """Represents a possible lateral movement path between nodes."""

    __slots__ = ("edge_id", "from_node", "to_node", "protocol", "port", "requires_vuln", "org_id")

    def __init__(
        self,
        edge_id: str,
        from_node: str,
        to_node: str,
        protocol: str = "tcp",
        port: int = 0,
        requires_vuln: str | None = None,
        org_id: str = "default",
    ) -> None:
        self.edge_id = edge_id
        self.from_node = from_node
        self.to_node = to_node
        self.protocol = protocol
        self.port = port
        self.requires_vuln = requires_vuln
        self.org_id = org_id

    def to_dict(self) -> dict:
        return {
            "edge_id": self.edge_id,
            "from_node": self.from_node,
            "to_node": self.to_node,
            "protocol": self.protocol,
            "port": self.port,
            "requires_vuln": self.requires_vuln,
            "org_id": self.org_id,
        }


class AttackPathEngine:
    """SQLite-backed attack path analysis engine.

    Models lateral movement through a network graph. Uses BFS to
    enumerate attack paths from entry points to crown jewel assets.
    """

    def __init__(self, db_path: str = "data/attack_paths.db") -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        _logger.info("AttackPathEngine initialised", db=db_path)

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id       TEXT PRIMARY KEY,
                    node_type     TEXT NOT NULL,
                    name          TEXT NOT NULL,
                    risk_score    REAL NOT NULL DEFAULT 50.0,
                    is_crown_jewel INTEGER NOT NULL DEFAULT 0,
                    vulnerabilities TEXT NOT NULL DEFAULT '[]',
                    org_id        TEXT NOT NULL DEFAULT 'default'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS edges (
                    edge_id      TEXT PRIMARY KEY,
                    from_node    TEXT NOT NULL,
                    to_node      TEXT NOT NULL,
                    protocol     TEXT NOT NULL DEFAULT 'tcp',
                    port         INTEGER NOT NULL DEFAULT 0,
                    requires_vuln TEXT,
                    org_id       TEXT NOT NULL DEFAULT 'default'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_node, org_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_org ON nodes(org_id)")
            # GAP-026 — choke-point analysis cache (max-flow min-cut results)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS choke_point_analyses (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    source_count   INTEGER NOT NULL,
                    sink_count     INTEGER NOT NULL,
                    cache_key      TEXT NOT NULL,
                    analysis_json  TEXT NOT NULL,
                    computed_at    REAL NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_choke_org ON choke_point_analyses(org_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_choke_cache "
                "ON choke_point_analyses(org_id, cache_key)"
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------

    def add_node(
        self,
        node_id: str,
        node_type: str,
        name: str,
        risk_score: float = 50.0,
        is_crown_jewel: bool = False,
        vulnerabilities: list[str] | None = None,
        org_id: str = "default",
    ) -> dict:
        """Add a network node to the attack graph.

        node_type: 'workstation'|'server'|'database'|'cloud_service'|'network_device'|'external'
        vulnerabilities: list of CVE IDs present on this node
        Returns: {node_id, node_type, name, is_crown_jewel, ...}
        """
        if node_type not in VALID_NODE_TYPES:
            raise ValueError(
                f"Invalid node_type '{node_type}'. Must be one of: {sorted(VALID_NODE_TYPES)}"
            )
        vulns = vulnerabilities or []
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO nodes
                    (node_id, node_type, name, risk_score, is_crown_jewel, vulnerabilities, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (node_id, node_type, name, risk_score, int(is_crown_jewel),
                 json.dumps(vulns), org_id),
            )
        node = AttackNode(node_id, node_type, name, risk_score, is_crown_jewel, vulns, org_id)
        _logger.debug("Node added", node_id=node_id, node_type=node_type)
        return node.to_dict()

    def get_node(self, node_id: str, org_id: str = "default") -> Optional[dict]:
        """Return node dict or None if not found.

        org_id guard prevents cross-tenant reads: a caller who knows another
        tenant's node_id will receive None instead of the node data.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM nodes WHERE node_id = ? AND org_id = ?",
                (node_id, org_id),
            ).fetchone()
        return self._row_to_node(row) if row else None

    def list_nodes(
        self,
        org_id: str = "default",
        is_crown_jewel: bool | None = None,
    ) -> list[dict]:
        """Return all nodes for org, optionally filtered by crown jewel status."""
        query = "SELECT * FROM nodes WHERE org_id = ?"
        params: list = [org_id]
        if is_crown_jewel is not None:
            query += " AND is_crown_jewel = ?"
            params.append(int(is_crown_jewel))
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_node(r) for r in rows]

    def remove_node(self, node_id: str, org_id: str = "default") -> bool:
        """Remove a node (and its org-scoped edges). Returns True if node existed.

        org_id guard prevents cross-tenant deletes: only nodes belonging to
        org_id are affected, so a caller with a foreign node_id gets False.
        """
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM nodes WHERE node_id = ? AND org_id = ?",
                (node_id, org_id),
            )
            if cur.rowcount > 0:
                conn.execute(
                    "DELETE FROM edges WHERE (from_node = ? OR to_node = ?) AND org_id = ?",
                    (node_id, node_id, org_id),
                )
        return cur.rowcount > 0

    @staticmethod
    def _row_to_node(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["is_crown_jewel"] = bool(d["is_crown_jewel"])
        d["vulnerabilities"] = json.loads(d.get("vulnerabilities", "[]"))
        return d

    # ------------------------------------------------------------------
    # Edges
    # ------------------------------------------------------------------

    def add_edge(
        self,
        from_node: str,
        to_node: str,
        protocol: str = "tcp",
        port: int = 0,
        requires_vuln: str | None = None,
        org_id: str = "default",
    ) -> dict:
        """Add a directed edge (possible lateral movement path).

        requires_vuln: CVE ID required to traverse this edge (None = always traversable)
        Returns: {edge_id, from_node, to_node, protocol, port}
        """
        edge_id = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO edges (edge_id, from_node, to_node, protocol, port, requires_vuln, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (edge_id, from_node, to_node, protocol, port, requires_vuln, org_id),
            )
        edge = AttackEdge(edge_id, from_node, to_node, protocol, port, requires_vuln, org_id)
        _logger.debug("Edge added", from_node=from_node, to_node=to_node)
        return edge.to_dict()

    # ------------------------------------------------------------------
    # Graph traversal helpers
    # ------------------------------------------------------------------

    def _load_adjacency(self, org_id: str) -> dict[str, list[dict]]:
        """Return adjacency map: from_node -> list of edge dicts."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM edges WHERE org_id = ?", (org_id,)
            ).fetchall()
        adj: dict[str, list[dict]] = {}
        for row in rows:
            e = dict(row)
            adj.setdefault(e["from_node"], []).append(e)
        return adj

    def _load_nodes_map(self, org_id: str) -> dict[str, dict]:
        """Return node_id -> node dict for org."""
        rows = self.list_nodes(org_id=org_id)
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "attack_path_engine", "org_id": "unknown", "source_engine": "attack_path_engine"})
            except Exception as exc:
                _logger.warning("FINDING_CREATED emit failed: %s", exc)
        return {r["node_id"]: r for r in rows}

    # ------------------------------------------------------------------
    # Path analysis
    # ------------------------------------------------------------------

    def find_attack_paths(
        self,
        entry_point: str,
        target: str | None = None,
        max_hops: int = 5,
        org_id: str = "default",
    ) -> dict:
        """Find all attack paths from entry_point to crown jewels (or specific target).

        Uses BFS to enumerate paths up to max_hops.
        Returns: {
            entry_point, target_nodes_reached: list,
            paths: [{path: [node_ids], hops: int, risk_score: float,
                    vulnerabilities_required: list[str]}],
            total_paths: int, max_blast_radius: int
        }
        """
        adj = self._load_adjacency(org_id)
        nodes_map = self._load_nodes_map(org_id)

        # Determine targets
        if target:
            target_ids = {target}
        else:
            target_ids = {
                nid for nid, n in nodes_map.items() if n["is_crown_jewel"]
            }

        paths: list[dict] = []
        target_nodes_reached: set[str] = set()

        # BFS — state: (current_node, path_so_far, vulns_required)
        queue: deque[tuple[str, list[str], list[str]]] = deque()
        queue.append((entry_point, [entry_point], []))

        # Visited per path length to avoid infinite loops but allow multi-path
        # Use (node, frozenset of path) to allow same node via different routes
        # but cap at max_hops to prevent explosion
        visited_states: set[tuple[str, tuple[str, ...]]] = set()

        while queue:
            current, path, vulns = queue.popleft()

            state = (current, tuple(path))
            if state in visited_states:
                continue
            visited_states.add(state)

            # Check if current node is a target
            if current in target_ids and current != entry_point:
                risk = self._compute_path_risk(path, nodes_map)
                paths.append({
                    "path": list(path),
                    "hops": len(path) - 1,
                    "risk_score": risk,
                    "vulnerabilities_required": list(vulns),
                })
                target_nodes_reached.add(current)
                # Don't stop — keep exploring for other paths

            # Only expand further if we haven't hit the hop limit
            if len(path) - 1 >= max_hops:
                continue

            for edge in adj.get(current, []):
                next_node = edge["to_node"]
                if next_node in path:
                    # Avoid cycles in a single path
                    continue
                new_vulns = list(vulns)
                if edge.get("requires_vuln"):
                    new_vulns.append(edge["requires_vuln"])
                queue.append((next_node, path + [next_node], new_vulns))

        # GNN-enhanced path scoring
        if _gnn is not None and paths:
            try:
                gnn_nodes = [
                    {
                        "id": nid,
                        "type": nodes_map.get(nid, {}).get("node_type", ""),
                        "properties": {
                            "severity_score": nodes_map.get(nid, {}).get("risk_score", 50.0),
                            "criticality": 1.0 if nodes_map.get(nid, {}).get("is_crown_jewel") else 0.5,
                        },
                    }
                    for nid in nodes_map
                ]
                gnn_edges = [
                    {"source_id": e["from_node"], "target_id": e["to_node"], "weight": 1.0}
                    for edge_list in adj.values()
                    for e in edge_list
                ]
                _gnn.fit(gnn_nodes, gnn_edges)
                for p in paths:
                    path_score = _gnn.score_path(p["path"])
                    if path_score.risk_score > 0:
                        p["risk_score"] = round(
                            (p["risk_score"] + path_score.risk_score) / 2.0, 2
                        )
                        p["gnn_risk_score"] = round(path_score.risk_score, 2)
            except Exception as exc:
                _logger.warning("GNN path scoring failed: %s", exc)

        # Sort by hops then risk
        paths.sort(key=lambda p: (p["hops"], -p["risk_score"]))

        return {
            "entry_point": entry_point,
            "target_nodes_reached": sorted(target_nodes_reached),
            "paths": paths,
            "total_paths": len(paths),
            "max_blast_radius": len(
                self._reachable_set(entry_point, adj)
            ),
        }

    def find_shortest_path(
        self,
        from_node: str,
        to_node: str,
        org_id: str = "default",
    ) -> Optional[dict]:
        """Find shortest path between two specific nodes."""
        adj = self._load_adjacency(org_id)
        nodes_map = self._load_nodes_map(org_id)

        # BFS for shortest path
        queue: deque[tuple[str, list[str], list[str]]] = deque()
        queue.append((from_node, [from_node], []))
        visited: set[str] = {from_node}

        while queue:
            current, path, vulns = queue.popleft()

            for edge in adj.get(current, []):
                next_node = edge["to_node"]
                if next_node in visited:
                    continue
                new_path = path + [next_node]
                new_vulns = list(vulns)
                if edge.get("requires_vuln"):
                    new_vulns.append(edge["requires_vuln"])

                if next_node == to_node:
                    return {
                        "path": new_path,
                        "hops": len(new_path) - 1,
                        "risk_score": self._compute_path_risk(new_path, nodes_map),
                        "vulnerabilities_required": new_vulns,
                    }

                visited.add(next_node)
                queue.append((next_node, new_path, new_vulns))

        return None

    def get_blast_radius(self, entry_point: str, org_id: str = "default") -> dict:
        """Find all nodes reachable from entry_point.

        Returns: {entry_point, reachable_nodes: list, crown_jewels_at_risk: list,
                  max_depth: int, total_reachable: int}
        """
        adj = self._load_adjacency(org_id)
        nodes_map = self._load_nodes_map(org_id)

        # BFS with depth tracking
        queue: deque[tuple[str, int]] = deque([(entry_point, 0)])
        visited: dict[str, int] = {entry_point: 0}

        while queue:
            current, depth = queue.popleft()
            for edge in adj.get(current, []):
                next_node = edge["to_node"]
                if next_node not in visited:
                    visited[next_node] = depth + 1
                    queue.append((next_node, depth + 1))

        # Exclude the entry point itself
        reachable = [
            {"node_id": nid, "depth": d, **nodes_map.get(nid, {"name": nid})}
            for nid, d in visited.items()
            if nid != entry_point
        ]
        crown_jewels_at_risk = [
            r for r in reachable
            if nodes_map.get(r["node_id"], {}).get("is_crown_jewel")
        ]
        max_depth = max((r["depth"] for r in reachable), default=0)

        return {
            "entry_point": entry_point,
            "reachable_nodes": reachable,
            "crown_jewels_at_risk": crown_jewels_at_risk,
            "max_depth": max_depth,
            "total_reachable": len(reachable),
        }

    def get_crown_jewels_at_risk(self, org_id: str = "default") -> list[dict]:
        """List crown jewels and which entry points can reach them."""
        nodes_map = self._load_nodes_map(org_id)
        self._load_adjacency(org_id)

        crown_jewels = [n for n in nodes_map.values() if n["is_crown_jewel"]]
        # Reverse adjacency for reverse BFS
        reverse_adj: dict[str, list[str]] = {}
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM edges WHERE org_id = ?", (org_id,)
            ).fetchall()
        for row in rows:
            e = dict(row)
            reverse_adj.setdefault(e["to_node"], []).append(e["from_node"])

        results = []
        for cj in crown_jewels:
            cj_id = cj["node_id"]
            # BFS backwards to find all entry points that can reach this crown jewel
            visited: set[str] = {cj_id}
            queue: deque[str] = deque([cj_id])
            ancestors: list[str] = []
            while queue:
                current = queue.popleft()
                for pred in reverse_adj.get(current, []):
                    if pred not in visited:
                        visited.add(pred)
                        ancestors.append(pred)
                        queue.append(pred)

            results.append({
                **cj,
                "reachable_from": ancestors,
                "reachable_from_count": len(ancestors),
            })
        return results

    def get_graph_stats(self, org_id: str = "default") -> dict:
        """Return {total_nodes, total_edges, crown_jewel_count, avg_connections_per_node}."""
        with self._conn() as conn:
            total_nodes = conn.execute(
                "SELECT COUNT(*) FROM nodes WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            total_edges = conn.execute(
                "SELECT COUNT(*) FROM edges WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            crown_jewel_count = conn.execute(
                "SELECT COUNT(*) FROM nodes WHERE org_id = ? AND is_crown_jewel = 1",
                (org_id,),
            ).fetchone()[0]

        avg_connections = (
            round(total_edges / total_nodes, 2) if total_nodes > 0 else 0.0
        )
        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "crown_jewel_count": crown_jewel_count,
            "avg_connections_per_node": avg_connections,
        }

    # ------------------------------------------------------------------
    # Toxic combinations
    # ------------------------------------------------------------------

    def get_toxic_combinations(self, org_id: str = "default") -> list[dict]:
        """Detect assets where multiple medium-severity findings chain into critical risk.

        A "toxic combination" is any asset node that:
        - Has 3 or more vulnerabilities (findings chained together), AND
        - Is internet-exposed (connected FROM an 'external' node, directly or
          indirectly within 1 hop, or is itself of type 'external').

        For each such asset the method returns:
          - asset: the node dict
          - findings: the vulnerability IDs present on the asset
          - combined_risk: amplified risk score (asset risk_score * 1.5, capped at 100)
          - attack_chain: list of external-node IDs that can directly reach the asset

        Returns: list of toxic combo dicts, sorted by combined_risk descending.
        """
        nodes_map = self._load_nodes_map(org_id)

        # Build reverse adjacency: to_node -> list of from_node IDs
        reverse_adj: dict[str, list[str]] = {}
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT from_node, to_node FROM edges WHERE org_id = ?", (org_id,)
            ).fetchall()
        for row in rows:
            reverse_adj.setdefault(row["to_node"], []).append(row["from_node"])

        # Identify external node IDs
        external_ids = {
            nid for nid, n in nodes_map.items() if n["node_type"] == "external"
        }

        results: list[dict] = []
        for nid, node in nodes_map.items():
            vulns = node.get("vulnerabilities") or []
            if len(vulns) < 3:
                continue

            # Determine internet-exposure: node itself is external, OR a direct
            # predecessor is an external node.
            predecessors = reverse_adj.get(nid, [])
            is_internet_exposed = (
                node["node_type"] == "external"
                or bool(external_ids.intersection(predecessors))
            )
            if not is_internet_exposed:
                continue

            attack_chain = [p for p in predecessors if p in external_ids]
            combined_risk = min(100.0, round(node["risk_score"] * 1.5, 2))

            results.append({
                "asset": node,
                "findings": vulns,
                "combined_risk": combined_risk,
                "attack_chain": attack_chain,
            })

        results.sort(key=lambda x: x["combined_risk"], reverse=True)
        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_path_risk(path: list[str], nodes_map: dict[str, dict]) -> float:
        """Average risk score across path nodes."""
        if not path:
            return 0.0
        scores = [nodes_map.get(nid, {}).get("risk_score", 50.0) for nid in path]
        return round(sum(scores) / len(scores), 2)

    @staticmethod
    def _reachable_set(entry_point: str, adj: dict[str, list[dict]]) -> set[str]:
        """BFS to find all reachable node IDs from entry_point."""
        visited: set[str] = {entry_point}
        queue: deque[str] = deque([entry_point])
        while queue:
            current = queue.popleft()
            for edge in adj.get(current, []):
                nxt = edge["to_node"]
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)
        visited.discard(entry_point)
        return visited

    # ------------------------------------------------------------------
    # GAP-026 — Choke-point analyzer (max-flow min-cut)
    # ------------------------------------------------------------------
    #
    # Given an attack graph, we model each real edge with unit capacity and
    # run the Edmonds-Karp algorithm to compute max-flow from a virtual
    # super-source (linking every source_id) to a virtual super-sink
    # (linking every sink_id). With unit capacities, the max-flow equals
    # the number of edge-disjoint paths from sources to sinks, and the
    # min-cut identifies the set of edges whose removal maximally reduces
    # blast radius. We rank each min-cut edge by the per-edge impact
    # (reachable sinks lost if that edge is removed).
    #
    # Implementation notes:
    #   * Pure-Python, stdlib only (no networkx / scipy).
    #   * Residual graph is a dict-of-dicts keyed by node name.
    #   * Virtual nodes use reserved names '__SRC__' / '__SNK__'; we reject
    #     real node_ids that collide with these sentinels.
    #   * For each candidate choke edge, we recompute blast radius with
    #     that edge removed to derive a concrete reduction percentage,
    #     which is the intuition customers care about.
    # ------------------------------------------------------------------

    _VIRTUAL_SOURCE = "__SRC__"
    _VIRTUAL_SINK = "__SNK__"

    @staticmethod
    def _bfs_augmenting_path(
        residual: dict[str, dict[str, int]],
        source: str,
        sink: str,
    ) -> Optional[list[str]]:
        """BFS for an augmenting path in the residual graph.

        Returns the path as a list of node ids (source..sink), or None if
        no augmenting path exists. Uses a deterministic ordering (sorted
        neighbours) so results are reproducible across runs.
        """
        if source == sink:
            return [source]
        parent: dict[str, str] = {source: source}
        queue: deque[str] = deque([source])
        while queue:
            u = queue.popleft()
            if u not in residual:
                continue
            # Sorted for deterministic BFS order — important for caching.
            for v in sorted(residual[u].keys()):
                if v in parent:
                    continue
                cap = residual[u][v]
                if cap <= 0:
                    continue
                parent[v] = u
                if v == sink:
                    # Reconstruct path.
                    path: list[str] = [v]
                    while path[-1] != source:
                        path.append(parent[path[-1]])
                    path.reverse()
                    return path
                queue.append(v)
        return None

    @classmethod
    def _edmonds_karp(
        cls,
        capacity: dict[str, dict[str, int]],
        source: str,
        sink: str,
    ) -> tuple[int, dict[str, dict[str, int]]]:
        """Pure-Python Edmonds-Karp max-flow.

        ``capacity`` is a dict-of-dicts of original capacities. Returns the
        tuple ``(max_flow, residual)`` where ``residual[u][v]`` is the
        remaining capacity after flow has been pushed.
        """
        # Build residual graph — include reverse edges with 0 initial capacity.
        residual: dict[str, dict[str, int]] = {}
        for u, nbrs in capacity.items():
            residual.setdefault(u, {})
            for v, cap in nbrs.items():
                residual[u][v] = residual[u].get(v, 0) + cap
                residual.setdefault(v, {})
                residual[v].setdefault(u, 0)

        if source not in residual or sink not in residual:
            return 0, residual

        max_flow = 0
        while True:
            path = cls._bfs_augmenting_path(residual, source, sink)
            if not path:
                break
            # Bottleneck capacity along the path.
            bottleneck = min(
                residual[path[i]][path[i + 1]] for i in range(len(path) - 1)
            )
            if bottleneck <= 0:
                break
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                residual[u][v] -= bottleneck
                residual[v][u] = residual[v].get(u, 0) + bottleneck
            max_flow += bottleneck
        return max_flow, residual

    @staticmethod
    def _reachable_in_residual(
        residual: dict[str, dict[str, int]],
        source: str,
    ) -> set[str]:
        """Return the set of nodes reachable from ``source`` using edges
        with strictly positive residual capacity."""
        visited: set[str] = {source}
        queue: deque[str] = deque([source])
        while queue:
            u = queue.popleft()
            for v, cap in residual.get(u, {}).items():
                if cap > 0 and v not in visited:
                    visited.add(v)
                    queue.append(v)
        return visited

    def _build_capacity_graph(
        self,
        adj: dict[str, list[dict]],
        sources: list[str],
        sinks: list[str],
    ) -> tuple[dict[str, dict[str, int]], list[dict]]:
        """Construct a unit-capacity graph with virtual super-source/sink.

        Returns a tuple ``(capacity_map, real_edges)`` where ``real_edges``
        is the list of edge rows participating in the graph. We only
        include real edges (not the virtual super-source/sink connectors)
        in the ranking output.
        """
        capacity: dict[str, dict[str, int]] = {}
        real_edges: list[dict] = []
        for _, edge_list in adj.items():
            for e in edge_list:
                u, v = e["from_node"], e["to_node"]
                if u in {self._VIRTUAL_SOURCE, self._VIRTUAL_SINK} or v in {
                    self._VIRTUAL_SOURCE,
                    self._VIRTUAL_SINK,
                }:
                    # Refuse to build over reserved ids — defensive.
                    continue
                capacity.setdefault(u, {})
                # Unit capacity. If duplicate edges exist, collapse to 1.
                capacity[u][v] = 1
                real_edges.append(e)
        # Connect virtual super-source to every source node.
        capacity.setdefault(self._VIRTUAL_SOURCE, {})
        for s in sources:
            capacity[self._VIRTUAL_SOURCE][s] = 10**9  # effectively unbounded
        # Connect every sink node to virtual super-sink.
        for t in sinks:
            capacity.setdefault(t, {})
            capacity[t][self._VIRTUAL_SINK] = 10**9
        capacity.setdefault(self._VIRTUAL_SINK, {})
        return capacity, real_edges

    @staticmethod
    def _count_reachable(
        adj: dict[str, list[dict]],
        sources: list[str],
        sinks: set[str],
    ) -> int:
        """Count sinks reachable from any source via BFS on ``adj``."""
        visited: set[str] = set(sources)
        queue: deque[str] = deque(sources)
        while queue:
            u = queue.popleft()
            for e in adj.get(u, []):
                v = e["to_node"]
                if v not in visited:
                    visited.add(v)
                    queue.append(v)
        return sum(1 for s in sinks if s in visited)

    @staticmethod
    def _cache_key(
        source_ids: list[str],
        sink_ids: list[str],
        top_k: int,
        adj: dict[str, list[dict]],
    ) -> str:
        """Deterministic SHA-256 key including edge topology.

        We include edges so that cache entries are invalidated when the
        underlying graph changes (e.g. a new edge added between the same
        set of nodes).
        """
        edge_sig = sorted(
            (e["from_node"], e["to_node"]) for edges in adj.values() for e in edges
        )
        payload = json.dumps(
            {
                "s": sorted(source_ids),
                "t": sorted(sink_ids),
                "k": top_k,
                "e": edge_sig,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def compute_choke_points(
        self,
        org_id: str,
        source_ids: list[str],
        sink_ids: list[str],
        top_k: int = 10,
    ) -> list[dict]:
        """Rank attack-graph edges by max-flow min-cut impact.

        Builds a unit-capacity residual graph, runs Edmonds-Karp from a
        virtual super-source connecting ``source_ids`` to a virtual
        super-sink connecting ``sink_ids``, then identifies min-cut edges.
        Each min-cut edge is annotated with the percentage reduction in
        reachable sinks if that edge is removed.

        Returns a list of dicts (sorted by ``blast_reduction_pct`` desc,
        then ``edge_id``) of at most ``top_k`` entries. Results are cached
        in ``choke_point_analyses`` — identical queries reuse the cached
        row.

        Raises:
            ValueError: if ``source_ids`` or ``sink_ids`` is empty, or
                ``top_k`` < 1.
        """
        if not source_ids:
            raise ValueError("source_ids must not be empty")
        if not sink_ids:
            raise ValueError("sink_ids must not be empty")
        if top_k < 1:
            raise ValueError("top_k must be >= 1")

        # Dedup while preserving order.
        source_ids = list(dict.fromkeys(source_ids))
        sink_ids = list(dict.fromkeys(sink_ids))

        adj = self._load_adjacency(org_id)
        sinks_set = set(sink_ids)

        cache_key = self._cache_key(source_ids, sink_ids, top_k, adj)
        with self._lock:
            # Cache hit — return stored ranking verbatim.
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT analysis_json FROM choke_point_analyses "
                    "WHERE org_id = ? AND cache_key = ? LIMIT 1",
                    (org_id, cache_key),
                ).fetchone()
            if row is not None:
                payload = json.loads(row["analysis_json"])
                return payload.get("edges", [])

            # Baseline reach (no edges removed).
            baseline_reach = self._count_reachable(adj, source_ids, sinks_set)
            if baseline_reach == 0:
                # No path from any source to any sink — nothing to cut.
                ranked: list[dict] = []
                self._persist_analysis(
                    org_id, source_ids, sink_ids, cache_key,
                    ranked, baseline_reach, 0,
                )
                return ranked

            capacity, real_edges = self._build_capacity_graph(
                adj, source_ids, sink_ids
            )
            max_flow, residual = self._edmonds_karp(
                capacity, self._VIRTUAL_SOURCE, self._VIRTUAL_SINK
            )

            # Min-cut: edges (u,v) in the original capacity graph where u is
            # reachable from source in residual and v is not.
            reachable = self._reachable_in_residual(residual, self._VIRTUAL_SOURCE)
            cut_pairs: set[tuple[str, str]] = set()
            for u, nbrs in capacity.items():
                if u not in reachable:
                    continue
                for v, cap in nbrs.items():
                    if cap <= 0:
                        continue
                    if v in reachable:
                        continue
                    cut_pairs.add((u, v))

            # For each real edge matching a cut pair, compute its per-edge
            # blast-reduction impact by rebuilding adjacency without that
            # single edge and re-counting reachable sinks.
            ranked = []
            seen_ids: set[str] = set()
            for edge in real_edges:
                if (edge["from_node"], edge["to_node"]) not in cut_pairs:
                    continue
                if edge["edge_id"] in seen_ids:
                    continue
                seen_ids.add(edge["edge_id"])
                adj_wo = self._adj_without_edge(adj, edge["edge_id"])
                reach_after = self._count_reachable(adj_wo, source_ids, sinks_set)
                reduction = baseline_reach - reach_after
                blast_reduction_pct = round(
                    (reduction / baseline_reach) * 100.0, 2
                ) if baseline_reach else 0.0
                ranked.append({
                    "edge_id": edge["edge_id"],
                    "source": edge["from_node"],
                    "target": edge["to_node"],
                    "flow_value": 1,  # unit capacity
                    "blast_reduction_pct": blast_reduction_pct,
                    "sinks_saved": reduction,
                })

            # Deterministic ordering: highest reduction first, then edge_id.
            ranked.sort(
                key=lambda r: (-r["blast_reduction_pct"], r["edge_id"])
            )
            ranked = ranked[:top_k]

            self._persist_analysis(
                org_id, source_ids, sink_ids, cache_key, ranked,
                baseline_reach, max_flow,
            )
            return ranked

    def _adj_without_edge(
        self,
        adj: dict[str, list[dict]],
        edge_id: str,
    ) -> dict[str, list[dict]]:
        """Return a shallow copy of ``adj`` with ``edge_id`` removed."""
        out: dict[str, list[dict]] = {}
        for u, edges in adj.items():
            filtered = [e for e in edges if e["edge_id"] != edge_id]
            if filtered:
                out[u] = filtered
        return out

    def _persist_analysis(
        self,
        org_id: str,
        source_ids: list[str],
        sink_ids: list[str],
        cache_key: str,
        ranked: list[dict],
        baseline_reach: int,
        max_flow: int,
    ) -> str:
        """Insert the analysis row and return the new analysis id."""
        analysis_id = str(uuid.uuid4())
        payload = {
            "edges": ranked,
            "sources": source_ids,
            "sinks": sink_ids,
            "baseline_reach": baseline_reach,
            "max_flow": max_flow,
        }
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO choke_point_analyses
                    (id, org_id, source_count, sink_count, cache_key,
                     analysis_json, computed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id, org_id, len(source_ids), len(sink_ids),
                    cache_key, json.dumps(payload), time.time(),
                ),
            )
        return analysis_id

    def list_analyses(self, org_id: str = "default") -> list[dict]:
        """Return cached choke-point analyses for ``org_id`` (newest first)."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, org_id, source_count, sink_count, computed_at "
                "FROM choke_point_analyses WHERE org_id = ? "
                "ORDER BY computed_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_analysis(
        self,
        analysis_id: str,
        org_id: str = "default",
    ) -> Optional[dict]:
        """Return the full cached analysis row or None if missing.

        ``org_id`` guard prevents cross-tenant reads.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM choke_point_analyses "
                "WHERE id = ? AND org_id = ? LIMIT 1",
                (analysis_id, org_id),
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["analysis"] = json.loads(d.pop("analysis_json"))
        return d

    def get_choke_point_stats(self, org_id: str = "default") -> dict:
        """Return summary stats: analyses count, avg/max top blast reduction."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT analysis_json FROM choke_point_analyses WHERE org_id = ?",
                (org_id,),
            ).fetchall()
        total = len(rows)
        top_reductions: list[float] = []
        for r in rows:
            try:
                payload = json.loads(r["analysis_json"])
                edges = payload.get("edges") or []
                if edges:
                    top_reductions.append(float(edges[0].get("blast_reduction_pct", 0.0)))
            except (ValueError, TypeError):
                continue
        avg_top = round(sum(top_reductions) / len(top_reductions), 2) if top_reductions else 0.0
        max_top = round(max(top_reductions), 2) if top_reductions else 0.0
        return {
            "total_analyses": total,
            "avg_top_blast_reduction_pct": avg_top,
            "max_top_blast_reduction_pct": max_top,
        }
