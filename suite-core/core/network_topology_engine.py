"""Network Topology Mapper Engine — ALDECI.

Map and analyze network topology: nodes, edges, segments, path-finding,
and external exposure detection.

Multi-tenant via org_id. SQLite WAL-backed. Thread-safe via RLock.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "network_topology.db"
)

_VALID_NODE_TYPES = {"server", "workstation", "router", "switch", "firewall", "cloud_instance", "iot"}
_VALID_CRITICALITY = {"critical", "high", "medium", "low"}
_VALID_ZONES = {"dmz", "internal", "external", "restricted"}


class NetworkTopologyEngine:
    """SQLite WAL-backed network topology mapper.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS topology_nodes (
                    node_id      TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    node_type    TEXT NOT NULL DEFAULT 'server',
                    hostname     TEXT NOT NULL DEFAULT '',
                    ip           TEXT NOT NULL DEFAULT '',
                    os           TEXT NOT NULL DEFAULT '',
                    location     TEXT NOT NULL DEFAULT '',
                    criticality  TEXT NOT NULL DEFAULT 'medium',
                    tags         TEXT NOT NULL DEFAULT '[]',
                    created_at   DATETIME NOT NULL,
                    updated_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tnode_org
                    ON topology_nodes (org_id, node_type);

                CREATE INDEX IF NOT EXISTS idx_tnode_crit
                    ON topology_nodes (org_id, criticality);

                CREATE TABLE IF NOT EXISTS topology_edges (
                    edge_id        TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    src_node_id    TEXT NOT NULL,
                    dst_node_id    TEXT NOT NULL,
                    protocol       TEXT NOT NULL DEFAULT '',
                    port           INTEGER NOT NULL DEFAULT 0,
                    bidirectional  INTEGER NOT NULL DEFAULT 1,
                    created_at     DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tedge_org
                    ON topology_edges (org_id);

                CREATE INDEX IF NOT EXISTS idx_tedge_src
                    ON topology_edges (org_id, src_node_id);

                CREATE INDEX IF NOT EXISTS idx_tedge_dst
                    ON topology_edges (org_id, dst_node_id);

                CREATE TABLE IF NOT EXISTS network_segments (
                    segment_id   TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL DEFAULT '',
                    vlan         TEXT NOT NULL DEFAULT '',
                    subnet       TEXT NOT NULL DEFAULT '',
                    zone         TEXT NOT NULL DEFAULT 'internal',
                    node_count   INTEGER NOT NULL DEFAULT 0,
                    created_at   DATETIME NOT NULL,
                    updated_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_seg_org
                    ON network_segments (org_id, zone);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _node_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        return d

    @staticmethod
    def _edge_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["bidirectional"] = bool(d["bidirectional"])
        return d

    @staticmethod
    def _seg_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------

    def add_node(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a network node. Returns the created node dict."""
        node_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        node_type = data.get("node_type", "server")
        if node_type not in _VALID_NODE_TYPES:
            node_type = "server"

        criticality = data.get("criticality", "medium")
        if criticality not in _VALID_CRITICALITY:
            criticality = "medium"

        tags = json.dumps(data.get("tags") or [])

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO topology_nodes
                        (node_id, org_id, node_type, hostname, ip, os, location,
                         criticality, tags, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        node_id, org_id, node_type,
                        data.get("hostname", ""),
                        data.get("ip", ""),
                        data.get("os", ""),
                        data.get("location", ""),
                        criticality, tags, now, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "network_topology", "org_id": org_id, "source_engine": "network_topology"})
            except Exception:
                pass

        return {
            "node_id": node_id,
            "org_id": org_id,
            "node_type": node_type,
            "hostname": data.get("hostname", ""),
            "ip": data.get("ip", ""),
            "os": data.get("os", ""),
            "location": data.get("location", ""),
            "criticality": criticality,
            "tags": data.get("tags") or [],
            "created_at": now,
            "updated_at": now,
        }

    def list_nodes(
        self,
        org_id: str,
        node_type: Optional[str] = None,
        criticality: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List nodes for an org, optionally filtered by type or criticality."""
        query = "SELECT * FROM topology_nodes WHERE org_id=?"
        params: list = [org_id]

        if node_type:
            query += " AND node_type=?"
            params.append(node_type)
        if criticality:
            query += " AND criticality=?"
            params.append(criticality)

        query += " ORDER BY criticality, hostname"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._node_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Edges
    # ------------------------------------------------------------------

    def add_edge(
        self,
        org_id: str,
        src_node_id: str,
        dst_node_id: str,
        protocol: str,
        port: int,
        bidirectional: bool = True,
    ) -> Dict[str, Any]:
        """Add a network edge between two nodes. Returns the created edge dict."""
        edge_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO topology_edges
                        (edge_id, org_id, src_node_id, dst_node_id, protocol,
                         port, bidirectional, created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        edge_id, org_id, src_node_id, dst_node_id,
                        protocol, port, 1 if bidirectional else 0, now,
                    ),
                )

        return {
            "edge_id": edge_id,
            "org_id": org_id,
            "src_node_id": src_node_id,
            "dst_node_id": dst_node_id,
            "protocol": protocol,
            "port": port,
            "bidirectional": bidirectional,
            "created_at": now,
        }

    def list_edges(
        self,
        org_id: str,
        node_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List edges for an org, optionally filtered to those touching node_id."""
        if node_id:
            query = (
                "SELECT * FROM topology_edges "
                "WHERE org_id=? AND (src_node_id=? OR (dst_node_id=? AND bidirectional=1)) "
                "ORDER BY created_at"
            )
            params = [org_id, node_id, node_id]
        else:
            query = "SELECT * FROM topology_edges WHERE org_id=? ORDER BY created_at"
            params = [org_id]

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._edge_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Segments
    # ------------------------------------------------------------------

    def add_segment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a network segment. Returns the created segment dict."""
        segment_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        zone = data.get("zone", "internal")
        if zone not in _VALID_ZONES:
            zone = "internal"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO network_segments
                        (segment_id, org_id, name, vlan, subnet, zone,
                         node_count, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        segment_id, org_id,
                        data.get("name", ""),
                        data.get("vlan", ""),
                        data.get("subnet", ""),
                        zone,
                        int(data.get("node_count", 0)),
                        now, now,
                    ),
                )

        return {
            "segment_id": segment_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "vlan": data.get("vlan", ""),
            "subnet": data.get("subnet", ""),
            "zone": zone,
            "node_count": int(data.get("node_count", 0)),
            "created_at": now,
            "updated_at": now,
        }

    def list_segments(self, org_id: str) -> List[Dict[str, Any]]:
        """List all segments for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM network_segments WHERE org_id=? ORDER BY zone, name",
                (org_id,),
            ).fetchall()
        return [self._seg_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Graph traversal
    # ------------------------------------------------------------------

    def get_neighbors(self, org_id: str, node_id: str) -> List[Dict[str, Any]]:
        """Return all nodes directly connected to node_id via edges."""
        # Collect neighbor node IDs
        with self._conn() as conn:
            # outbound edges
            out_rows = conn.execute(
                "SELECT dst_node_id FROM topology_edges WHERE org_id=? AND src_node_id=?",
                (org_id, node_id),
            ).fetchall()
            # inbound edges (bidirectional)
            in_rows = conn.execute(
                "SELECT src_node_id FROM topology_edges "
                "WHERE org_id=? AND dst_node_id=? AND bidirectional=1",
                (org_id, node_id),
            ).fetchall()

        neighbor_ids = {r[0] for r in out_rows} | {r[0] for r in in_rows}
        if not neighbor_ids:
            return []

        placeholders = ",".join("?" * len(neighbor_ids))
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM topology_nodes WHERE org_id=? AND node_id IN ({placeholders})",  # nosec B608
                [org_id] + list(neighbor_ids),
            ).fetchall()
        return [self._node_to_dict(r) for r in rows]

    def find_path(
        self,
        org_id: str,
        src_node_id: str,
        dst_node_id: str,
    ) -> List[str]:
        """BFS shortest path between src and dst. Returns list of node_ids (inclusive),
        or empty list if no path exists."""
        if src_node_id == dst_node_id:
            return [src_node_id]

        # Build adjacency from DB
        with self._conn() as conn:
            edge_rows = conn.execute(
                "SELECT src_node_id, dst_node_id, bidirectional "
                "FROM topology_edges WHERE org_id=?",
                (org_id,),
            ).fetchall()

        adjacency: Dict[str, set] = {}
        for row in edge_rows:
            src, dst, bidir = row[0], row[1], bool(row[2])
            adjacency.setdefault(src, set()).add(dst)
            if bidir:
                adjacency.setdefault(dst, set()).add(src)

        # BFS
        visited = {src_node_id}
        queue: deque = deque([[src_node_id]])

        while queue:
            path = queue.popleft()
            current = path[-1]
            for neighbor in adjacency.get(current, set()):
                if neighbor == dst_node_id:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])

        return []  # no path found

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_topology_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary statistics for an org's topology."""
        with self._conn() as conn:
            total_nodes = conn.execute(
                "SELECT COUNT(*) FROM topology_nodes WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            total_edges = conn.execute(
                "SELECT COUNT(*) FROM topology_edges WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT node_type, COUNT(*) as cnt FROM topology_nodes "
                "WHERE org_id=? GROUP BY node_type",
                (org_id,),
            ).fetchall()

            crit_rows = conn.execute(
                "SELECT criticality, COUNT(*) as cnt FROM topology_nodes "
                "WHERE org_id=? GROUP BY criticality",
                (org_id,),
            ).fetchall()

            segment_count = conn.execute(
                "SELECT COUNT(*) FROM network_segments WHERE org_id=?", (org_id,)
            ).fetchone()[0]

        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "by_type": {r[0]: r[1] for r in type_rows},
            "by_criticality": {r[0]: r[1] for r in crit_rows},
            "segment_count": segment_count,
        }

    def detect_exposure(self, org_id: str) -> List[Dict[str, Any]]:
        """Find critical/high internal nodes reachable from external-zone nodes.

        Returns list of exposure dicts: {external_node, internal_node, path}.
        """
        with self._conn() as conn:
            # Nodes in external segments (by zone column in segments) OR
            # we infer "external" from node data — use a simple heuristic:
            # fetch external-segment node IDs via segment zone tag stored in
            # network_segments. For nodes not in a segment we check if their
            # location contains "external" / "dmz".
            conn.execute(
                "SELECT segment_id FROM network_segments "
                "WHERE org_id=? AND zone IN ('external','dmz')",
                (org_id,),
            ).fetchall()

            # Since nodes don't have a direct segment_id FK in this schema,
            # we treat nodes with location containing 'external' or 'dmz' as
            # external entry points.
            ext_node_rows = conn.execute(
                "SELECT node_id FROM topology_nodes "
                "WHERE org_id=? AND (LOWER(location) LIKE '%external%' OR LOWER(location) LIKE '%dmz%')",
                (org_id,),
            ).fetchall()

            critical_node_rows = conn.execute(
                "SELECT node_id, hostname FROM topology_nodes "
                "WHERE org_id=? AND criticality IN ('critical','high') "
                "AND LOWER(location) NOT LIKE '%external%' "
                "AND LOWER(location) NOT LIKE '%dmz%'",
                (org_id,),
            ).fetchall()

        external_ids = [r[0] for r in ext_node_rows]
        critical_nodes = {r[0]: r[1] for r in critical_node_rows}

        if not external_ids or not critical_nodes:
            return []

        exposures: List[Dict[str, Any]] = []
        for ext_id in external_ids:
            for crit_id, crit_hostname in critical_nodes.items():
                path = self.find_path(org_id, ext_id, crit_id)
                if path and len(path) > 1:
                    exposures.append(
                        {
                            "external_node_id": ext_id,
                            "internal_node_id": crit_id,
                            "internal_hostname": crit_hostname,
                            "path": path,
                            "hop_count": len(path) - 1,
                        }
                    )

        return exposures
