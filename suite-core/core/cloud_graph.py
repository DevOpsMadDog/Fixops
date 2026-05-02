"""
Cloud Resource Graph Engine — relationship mapper for cloud infrastructure.

Builds a graph of cloud resources (VPCs, subnets, EC2, RDS, IAM, etc.) and
their relationships. Provides attack path analysis, blast radius, exposure
detection, and overprivilege detection. SQLite-backed persistence.

Usage:
    from core.cloud_graph import CloudGraphEngine, GraphNode, GraphEdge, NodeType, EdgeType
    engine = CloudGraphEngine()
    engine.build_graph_from_resources(resources, org_id="my-org")
    graph = engine.get_graph("my-org")
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_CLOUD_GRAPH_DB", ".fixops_data/cloud_graph.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class NodeType(str, Enum):
    VPC = "VPC"
    SUBNET = "SUBNET"
    SECURITY_GROUP = "SECURITY_GROUP"
    EC2 = "EC2"
    RDS = "RDS"
    S3 = "S3"
    LAMBDA = "LAMBDA"
    EKS = "EKS"
    IAM_ROLE = "IAM_ROLE"
    IAM_USER = "IAM_USER"
    LOAD_BALANCER = "LOAD_BALANCER"
    API_GATEWAY = "API_GATEWAY"
    CLOUDFRONT = "CLOUDFRONT"
    ROUTE_TABLE = "ROUTE_TABLE"
    NAT_GATEWAY = "NAT_GATEWAY"


class EdgeType(str, Enum):
    CONTAINS = "CONTAINS"
    CONNECTS_TO = "CONNECTS_TO"
    HAS_ACCESS = "HAS_ACCESS"
    EXPOSES = "EXPOSES"
    ROUTES_TO = "ROUTES_TO"
    INHERITS = "INHERITS"
    ATTACHED_TO = "ATTACHED_TO"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class GraphNode(BaseModel):
    id: str = Field(default_factory=lambda: f"node-{uuid.uuid4().hex[:12]}")
    type: NodeType
    name: str
    provider: str = "AWS"
    region: str = "us-east-1"
    config: Dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    vulnerabilities: List[str] = Field(default_factory=list)
    public: bool = False


class GraphEdge(BaseModel):
    id: str = Field(default_factory=lambda: f"edge-{uuid.uuid4().hex[:12]}")
    source_id: str
    target_id: str
    type: EdgeType
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CloudGraph(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------


class _GraphDB:
    """SQLite persistence for cloud graph nodes and edges."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    region TEXT NOT NULL,
                    config TEXT DEFAULT '{}',
                    risk_score REAL DEFAULT 0.0,
                    vulnerabilities TEXT DEFAULT '[]',
                    public INTEGER DEFAULT 0,
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_nodes_org ON graph_nodes(org_id);
                CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(type);
                CREATE INDEX IF NOT EXISTS idx_nodes_public ON graph_nodes(public);

                CREATE TABLE IF NOT EXISTS graph_edges (
                    id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}',
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_edges_org ON graph_edges(org_id);
                CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_id);
                CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_id);
                CREATE INDEX IF NOT EXISTS idx_edges_type ON graph_edges(type);
            """)
            self._conn.commit()

    def upsert_node(self, node: GraphNode, org_id: str) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO graph_nodes
                   (id, type, name, provider, region, config, risk_score, vulnerabilities, public, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    node.id, node.type.value, node.name, node.provider, node.region,
                    json.dumps(node.config), node.risk_score,
                    json.dumps(node.vulnerabilities), int(node.public), org_id,
                ),
            )
            self._conn.commit()

    def upsert_edge(self, edge: GraphEdge, org_id: str) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO graph_edges
                   (id, source_id, target_id, type, metadata, org_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    edge.id, edge.source_id, edge.target_id,
                    edge.type.value, json.dumps(edge.metadata), org_id,
                ),
            )
            self._conn.commit()

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, type, name, provider, region, config, risk_score, vulnerabilities, public "
                "FROM graph_nodes WHERE id = ?",
                (node_id,),
            ).fetchone()
        return self._row_to_node(row) if row else None

    def list_nodes(
        self,
        org_id: str,
        type_filter: Optional[str] = None,
        public_only: bool = False,
    ) -> List[GraphNode]:
        query = (
            "SELECT id, type, name, provider, region, config, risk_score, vulnerabilities, public "
            "FROM graph_nodes WHERE org_id = ?"
        )
        params: List[Any] = [org_id]
        if type_filter:
            query += " AND type = ?"
            params.append(type_filter)
        if public_only:
            query += " AND public = 1"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_node(r) for r in rows]

    def list_edges(
        self,
        org_id: str,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        edge_type: Optional[str] = None,
    ) -> List[GraphEdge]:
        query = (
            "SELECT id, source_id, target_id, type, metadata "
            "FROM graph_edges WHERE org_id = ?"
        )
        params: List[Any] = [org_id]
        if source_id:
            query += " AND source_id = ?"
            params.append(source_id)
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        if edge_type:
            query += " AND type = ?"
            params.append(edge_type)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_edge(r) for r in rows]

    def delete_nodes_for_org(self, org_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM graph_nodes WHERE org_id = ?", (org_id,))
            self._conn.execute("DELETE FROM graph_edges WHERE org_id = ?", (org_id,))
            self._conn.commit()

    def get_node_count(self, org_id: str) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM graph_nodes WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

    def get_edge_count(self, org_id: str) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM graph_edges WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

    def get_node_counts_by_type(self, org_id: str) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT type, COUNT(*) FROM graph_nodes WHERE org_id = ? GROUP BY type",
                (org_id,),
            ).fetchall()
        return {r[0]: r[1] for r in rows}

    @staticmethod
    def _row_to_node(row: tuple) -> GraphNode:
        return GraphNode(
            id=row[0],
            type=NodeType(row[1]),
            name=row[2],
            provider=row[3],
            region=row[4],
            config=json.loads(row[5] or "{}"),
            risk_score=row[6],
            vulnerabilities=json.loads(row[7] or "[]"),
            public=bool(row[8]),
        )

    @staticmethod
    def _row_to_edge(row: tuple) -> GraphEdge:
        return GraphEdge(
            id=row[0],
            source_id=row[1],
            target_id=row[2],
            type=EdgeType(row[3]),
            metadata=json.loads(row[4] or "{}"),
        )


# ---------------------------------------------------------------------------
# Cloud Graph Engine
# ---------------------------------------------------------------------------


class CloudGraphEngine:
    """Graph-based cloud resource relationship mapper.

    Discovers and stores relationships between cloud resources, computes
    attack paths, blast radius, and risk rankings.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _GraphDB(db_path)
        logger.info("cloud_graph_engine.init", db_path=db_path)

    # ------------------------------------------------------------------
    # Core CRUD
    # ------------------------------------------------------------------

    def add_node(self, node: GraphNode, org_id: str = "default") -> GraphNode:
        """Persist a graph node and return it."""
        self._db.upsert_node(node, org_id)
        logger.debug("cloud_graph.add_node", node_id=node.id, type=node.type, org_id=org_id)
        return node

    def add_edge(self, edge: GraphEdge, org_id: str = "default") -> GraphEdge:
        """Persist a graph edge and return it."""
        self._db.upsert_edge(edge, org_id)
        logger.debug("cloud_graph.add_edge", edge_id=edge.id, type=edge.type, org_id=org_id)
        return edge

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def build_graph_from_resources(
        self, resources: List[Dict[str, Any]], org_id: str = "default"
    ) -> CloudGraph:
        """Build a complete cloud graph from a list of raw resource dicts.

        Each resource dict should have: id, type (NodeType value), name,
        provider, region, config, risk_score, vulnerabilities, public.
        Auto-infers edges from resource configs.
        """
        # Clear existing graph for this org before rebuild
        self._db.delete_nodes_for_org(org_id)

        nodes: List[GraphNode] = []
        for r in resources:
            node = GraphNode(
                id=r.get("id", f"node-{uuid.uuid4().hex[:12]}"),
                type=NodeType(r["type"]),
                name=r.get("name", r.get("id", "unknown")),
                provider=r.get("provider", "AWS"),
                region=r.get("region", "us-east-1"),
                config=r.get("config", {}),
                risk_score=float(r.get("risk_score", 0.0)),
                vulnerabilities=r.get("vulnerabilities", []),
                public=bool(r.get("public", False)),
            )
            self._db.upsert_node(node, org_id)
            nodes.append(node)

        inferred_edges = self._infer_edges(nodes)
        for edge in inferred_edges:
            self._db.upsert_edge(edge, org_id)

        graph = CloudGraph(
            nodes=nodes,
            edges=inferred_edges,
            stats=self.get_graph_stats(org_id),
        )
        logger.info(
            "cloud_graph.build_complete",
            org_id=org_id,
            nodes=len(nodes),
            edges=len(inferred_edges),
        )
        return graph

    def _infer_edges(self, nodes: List[GraphNode]) -> List[GraphEdge]:
        """Auto-detect relationships between nodes from their configs.

        Rules:
        - Same VPC ID → VPC CONTAINS subnet/EC2/RDS/Lambda/EKS/LB/NAT
        - security_group_ids in config → SECURITY_GROUP ATTACHED_TO resource
        - iam_role_arn in config → IAM_ROLE HAS_ACCESS resource
        - target_group / alb_arn → LOAD_BALANCER ROUTES_TO EC2/EKS
        - subnet_id in config → SUBNET CONTAINS resource
        - route_table_id → ROUTE_TABLE ROUTES_TO SUBNET
        - CloudFront → EXPOSES LOAD_BALANCER or API_GATEWAY
        - API_GATEWAY → EXPOSES LAMBDA
        """
        edges: List[GraphEdge] = []
        {n.id: n for n in nodes}

        # Build lookup indexes
        vpc_nodes: Dict[str, GraphNode] = {}       # vpc_id → VPC node
        subnet_nodes: Dict[str, GraphNode] = {}    # subnet_id → SUBNET node
        sg_nodes: Dict[str, GraphNode] = {}        # sg_id → SG node
        role_nodes: Dict[str, GraphNode] = {}      # role_arn/role_id → IAM_ROLE node
        rt_nodes: Dict[str, GraphNode] = {}        # route_table_id → ROUTE_TABLE node
        lb_nodes: Dict[str, GraphNode] = {}        # lb_arn/lb_id → LB node

        for n in nodes:
            cfg = n.config
            if n.type == NodeType.VPC:
                for key in ("vpc_id", "id", "resource_id"):
                    if cfg.get(key):
                        vpc_nodes[cfg[key]] = n
                vpc_nodes[n.id] = n
            elif n.type == NodeType.SUBNET:
                for key in ("subnet_id", "id", "resource_id"):
                    if cfg.get(key):
                        subnet_nodes[cfg[key]] = n
                subnet_nodes[n.id] = n
            elif n.type == NodeType.SECURITY_GROUP:
                for key in ("group_id", "sg_id", "id", "resource_id"):
                    if cfg.get(key):
                        sg_nodes[cfg[key]] = n
                sg_nodes[n.id] = n
            elif n.type == NodeType.IAM_ROLE:
                for key in ("role_arn", "role_id", "id", "resource_id"):
                    if cfg.get(key):
                        role_nodes[cfg[key]] = n
                role_nodes[n.id] = n
            elif n.type == NodeType.ROUTE_TABLE:
                for key in ("route_table_id", "id", "resource_id"):
                    if cfg.get(key):
                        rt_nodes[cfg[key]] = n
                rt_nodes[n.id] = n
            elif n.type == NodeType.LOAD_BALANCER:
                for key in ("lb_arn", "lb_id", "id", "resource_id"):
                    if cfg.get(key):
                        lb_nodes[cfg[key]] = n
                lb_nodes[n.id] = n

        _seen_edges: set = set()

        def _add_edge(source: GraphNode, target: GraphNode, etype: EdgeType, meta: Optional[Dict] = None) -> None:
            key = (source.id, target.id, etype.value)
            if key in _seen_edges:
                return
            _seen_edges.add(key)
            edges.append(GraphEdge(
                source_id=source.id,
                target_id=target.id,
                type=etype,
                metadata=meta or {},
            ))

        _containable = {
            NodeType.SUBNET, NodeType.EC2, NodeType.RDS, NodeType.LAMBDA,
            NodeType.EKS, NodeType.LOAD_BALANCER, NodeType.NAT_GATEWAY,
            NodeType.SECURITY_GROUP, NodeType.ROUTE_TABLE,
        }

        for n in nodes:
            cfg = n.config

            # VPC CONTAINS resource
            vpc_id = cfg.get("vpc_id")
            if vpc_id and vpc_id in vpc_nodes and n.type in _containable:
                _add_edge(vpc_nodes[vpc_id], n, EdgeType.CONTAINS, {"vpc_id": vpc_id})

            # SUBNET CONTAINS resource
            subnet_id = cfg.get("subnet_id")
            if subnet_id and subnet_id in subnet_nodes and n.type not in {NodeType.VPC, NodeType.SUBNET}:
                _add_edge(subnet_nodes[subnet_id], n, EdgeType.CONTAINS, {"subnet_id": subnet_id})

            # SECURITY_GROUP ATTACHED_TO resource
            sg_ids = cfg.get("security_group_ids", [])
            if isinstance(sg_ids, str):
                sg_ids = [sg_ids]
            for sg_id in sg_ids:
                if sg_id in sg_nodes:
                    _add_edge(sg_nodes[sg_id], n, EdgeType.ATTACHED_TO, {"sg_id": sg_id})

            # IAM_ROLE HAS_ACCESS resource
            role_arn = cfg.get("iam_role_arn") or cfg.get("role_arn")
            if role_arn and role_arn in role_nodes:
                _add_edge(role_nodes[role_arn], n, EdgeType.HAS_ACCESS, {"role_arn": role_arn})

            # ROUTE_TABLE ROUTES_TO SUBNET
            if n.type == NodeType.SUBNET:
                rt_id = cfg.get("route_table_id")
                if rt_id and rt_id in rt_nodes:
                    _add_edge(rt_nodes[rt_id], n, EdgeType.ROUTES_TO, {"route_table_id": rt_id})

            # LOAD_BALANCER ROUTES_TO EC2/EKS
            if n.type in {NodeType.EC2, NodeType.EKS}:
                lb_arn = cfg.get("load_balancer_arn") or cfg.get("alb_arn")
                if lb_arn and lb_arn in lb_nodes:
                    _add_edge(lb_nodes[lb_arn], n, EdgeType.ROUTES_TO, {"lb_arn": lb_arn})

            # API_GATEWAY EXPOSES LAMBDA
            if n.type == NodeType.LAMBDA:
                apigw_id = cfg.get("api_gateway_id")
                if apigw_id:
                    for apigw_node in nodes:
                        if apigw_node.type == NodeType.API_GATEWAY and (
                            apigw_node.config.get("api_id") == apigw_id
                            or apigw_node.id == apigw_id
                        ):
                            _add_edge(apigw_node, n, EdgeType.EXPOSES, {"api_gateway_id": apigw_id})

            # CLOUDFRONT EXPOSES LOAD_BALANCER / API_GATEWAY
            if n.type == NodeType.CLOUDFRONT:
                origin = cfg.get("origin_id") or cfg.get("origin_domain")
                if origin:
                    for candidate in nodes:
                        if candidate.type in {NodeType.LOAD_BALANCER, NodeType.API_GATEWAY}:
                            cand_cfg = candidate.config
                            if (
                                cand_cfg.get("lb_arn") == origin
                                or cand_cfg.get("lb_id") == origin
                                or cand_cfg.get("api_id") == origin
                                or candidate.id == origin
                                or candidate.name == origin
                            ):
                                _add_edge(n, candidate, EdgeType.EXPOSES, {"origin": origin})

            # IAM_USER INHERITS IAM_ROLE (attached roles)
            if n.type == NodeType.IAM_USER:
                attached_roles = cfg.get("attached_role_arns", [])
                if isinstance(attached_roles, str):
                    attached_roles = [attached_roles]
                for r_arn in attached_roles:
                    if r_arn in role_nodes:
                        _add_edge(n, role_nodes[r_arn], EdgeType.INHERITS, {"role_arn": r_arn})

        return edges

    # ------------------------------------------------------------------
    # Query / retrieval
    # ------------------------------------------------------------------

    def get_graph(
        self,
        org_id: str = "default",
        node_type: Optional[NodeType] = None,
        public_only: bool = False,
    ) -> CloudGraph:
        """Return the full graph or a filtered view."""
        type_filter = node_type.value if node_type else None
        nodes = self._db.list_nodes(org_id, type_filter=type_filter, public_only=public_only)
        node_ids = {n.id for n in nodes}
        all_edges = self._db.list_edges(org_id)
        # Only include edges where both endpoints are in the filtered node set
        edges = [e for e in all_edges if e.source_id in node_ids and e.target_id in node_ids]
        return CloudGraph(nodes=nodes, edges=edges, stats=self.get_graph_stats(org_id))

    def get_exposed_resources(self, org_id: str = "default") -> List[GraphNode]:
        """Return internet-reachable (public=True) nodes."""
        return self._db.list_nodes(org_id, public_only=True)

    def get_overprivileged_roles(self, org_id: str = "default") -> List[GraphNode]:
        """Return IAM roles/users with overly permissive policies.

        Heuristic: risk_score >= 0.7 OR config contains wildcard actions.
        """
        roles = self._db.list_nodes(org_id, type_filter=NodeType.IAM_ROLE.value)
        users = self._db.list_nodes(org_id, type_filter=NodeType.IAM_USER.value)
        overprivileged: List[GraphNode] = []
        for node in roles + users:
            if node.risk_score >= 0.7:
                overprivileged.append(node)
                continue
            # Check for wildcard actions in policy
            policies = node.config.get("policies", [])
            if isinstance(policies, list):
                for policy in policies:
                    actions = policy.get("actions", []) if isinstance(policy, dict) else []
                    if "*" in actions or "iam:*" in actions or "s3:*" in actions:
                        overprivileged.append(node)
                        break
            elif isinstance(policies, str) and "*" in policies:
                overprivileged.append(node)
        return overprivileged

    def find_attack_paths(self, org_id: str = "default") -> List[List[GraphNode]]:
        """Find paths from internet (public nodes) to sensitive data.

        Traverses the graph from public-facing nodes (EC2, LB, API_GW,
        CloudFront) toward sensitive targets (RDS, S3, IAM roles).
        Returns list of node paths (each path is a list of GraphNode).
        """
        all_nodes = self._db.list_nodes(org_id)
        all_edges = self._db.list_edges(org_id)
        node_map: Dict[str, GraphNode] = {n.id: n for n in all_nodes}

        # Build adjacency: source → [targets]
        adjacency: Dict[str, List[str]] = {}
        for edge in all_edges:
            adjacency.setdefault(edge.source_id, []).append(edge.target_id)
            # Also traverse ATTACHED_TO and HAS_ACCESS in both directions for paths
            if edge.type in {EdgeType.ATTACHED_TO, EdgeType.HAS_ACCESS, EdgeType.ROUTES_TO}:
                adjacency.setdefault(edge.target_id, []).append(edge.source_id)

        # Entry points: public-facing nodes
        _entry_types = {NodeType.LOAD_BALANCER, NodeType.API_GATEWAY, NodeType.CLOUDFRONT, NodeType.EC2}
        entry_nodes = [n for n in all_nodes if n.public or n.type in _entry_types and n.public]

        # Sensitive targets
        _sensitive_types = {NodeType.RDS, NodeType.S3, NodeType.IAM_ROLE, NodeType.IAM_USER}
        sensitive_ids = {n.id for n in all_nodes if n.type in _sensitive_types}

        paths: List[List[GraphNode]] = []

        def _dfs(current_id: str, path: List[str], visited: set) -> None:
            if current_id in sensitive_ids and len(path) > 1:
                paths.append([node_map[nid] for nid in path if nid in node_map])
                return
            if len(path) >= 6:  # max depth
                return
            for neighbor_id in adjacency.get(current_id, []):
                if neighbor_id not in visited and neighbor_id in node_map:
                    visited.add(neighbor_id)
                    _dfs(neighbor_id, path + [neighbor_id], visited)
                    visited.discard(neighbor_id)

        for entry in entry_nodes:
            _dfs(entry.id, [entry.id], {entry.id})

        return paths

    def find_blast_radius(self, node_id: str, org_id: str = "default") -> CloudGraph:
        """Return the subgraph of resources affected if node_id is compromised.

        Traverses outbound edges from the given node up to depth 4.
        """
        all_nodes = self._db.list_nodes(org_id)
        all_edges = self._db.list_edges(org_id)
        node_map: Dict[str, GraphNode] = {n.id: n for n in all_nodes}

        adjacency: Dict[str, List[str]] = {}
        for edge in all_edges:
            adjacency.setdefault(edge.source_id, []).append(edge.target_id)

        affected_ids: set = set()

        def _bfs(start_id: str, max_depth: int = 4) -> None:
            queue = [(start_id, 0)]
            visited = {start_id}
            while queue:
                current, depth = queue.pop(0)
                if depth >= max_depth:
                    continue
                for neighbor in adjacency.get(current, []):
                    if neighbor not in visited and neighbor in node_map:
                        visited.add(neighbor)
                        affected_ids.add(neighbor)
                        queue.append((neighbor, depth + 1))

        _bfs(node_id)

        # Include the origin node
        affected_ids.add(node_id)

        affected_nodes = [node_map[nid] for nid in affected_ids if nid in node_map]
        affected_node_ids = {n.id for n in affected_nodes}
        affected_edges = [
            e for e in all_edges
            if e.source_id in affected_node_ids and e.target_id in affected_node_ids
        ]

        return CloudGraph(
            nodes=affected_nodes,
            edges=affected_edges,
            stats={"blast_radius": len(affected_nodes), "origin_node": node_id},
        )

    def get_network_segmentation(self, org_id: str = "default") -> Dict[str, Any]:
        """Analyse VPC/subnet isolation.

        Returns per-VPC breakdown of subnets and resources, and flags
        VPCs that contain public resources alongside private ones (mixed).
        """
        all_nodes = self._db.list_nodes(org_id)
        all_edges = self._db.list_edges(org_id)

        vpc_nodes = {n.id: n for n in all_nodes if n.type == NodeType.VPC}
        subnet_nodes = {n.id: n for n in all_nodes if n.type == NodeType.SUBNET}

        # Map VPC → contained node IDs
        vpc_contents: Dict[str, List[str]] = {vid: [] for vid in vpc_nodes}
        for edge in all_edges:
            if edge.type == EdgeType.CONTAINS and edge.source_id in vpc_nodes:
                vpc_contents[edge.source_id].append(edge.target_id)

        node_map: Dict[str, GraphNode] = {n.id: n for n in all_nodes}
        result: Dict[str, Any] = {
            "vpc_count": len(vpc_nodes),
            "subnet_count": len(subnet_nodes),
            "vpcs": {},
        }

        for vpc_id, vpc_node in vpc_nodes.items():
            contained = [node_map[nid] for nid in vpc_contents[vpc_id] if nid in node_map]
            public_count = sum(1 for n in contained if n.public)
            private_count = len(contained) - public_count
            result["vpcs"][vpc_id] = {
                "name": vpc_node.name,
                "region": vpc_node.region,
                "total_resources": len(contained),
                "public_resources": public_count,
                "private_resources": private_count,
                "mixed_exposure": public_count > 0 and private_count > 0,
                "types": list({n.type.value for n in contained}),
            }

        return result

    def calculate_risk_paths(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """Return attack paths ranked by cumulative risk score."""
        raw_paths = self.find_attack_paths(org_id)
        ranked: List[Dict[str, Any]] = []
        for path_nodes in raw_paths:
            if not path_nodes:
                continue
            total_risk = sum(n.risk_score for n in path_nodes)
            max_risk = max(n.risk_score for n in path_nodes)
            ranked.append({
                "path": [{"id": n.id, "name": n.name, "type": n.type.value} for n in path_nodes],
                "length": len(path_nodes),
                "total_risk_score": round(total_risk, 3),
                "max_node_risk": round(max_risk, 3),
                "entry_point": path_nodes[0].name if path_nodes else None,
                "target": path_nodes[-1].name if path_nodes else None,
            })
        ranked.sort(key=lambda x: x["total_risk_score"], reverse=True)
        return ranked

    def get_graph_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return summary statistics for the org's graph."""
        node_count = self._db.get_node_count(org_id)
        edge_count = self._db.get_edge_count(org_id)
        by_type = self._db.get_node_counts_by_type(org_id)
        public_nodes = self._db.list_nodes(org_id, public_only=True)
        return {
            "org_id": org_id,
            "total_nodes": node_count,
            "total_edges": edge_count,
            "public_nodes": len(public_nodes),
            "nodes_by_type": by_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------

_engine_instance: Optional[CloudGraphEngine] = None
_engine_lock = threading.Lock()


def get_cloud_graph_engine() -> CloudGraphEngine:
    """Return the process-level CloudGraphEngine singleton."""
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = CloudGraphEngine()
    return _engine_instance
