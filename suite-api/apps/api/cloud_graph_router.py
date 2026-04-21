"""Cloud Resource Graph Engine API Router.

Provides endpoints for building, querying, and analysing cloud resource
relationship graphs. Replicates core Wiz graph-query capabilities.

Endpoints:
  POST /build          — build graph from raw resource list
  GET  /graph          — full graph (nodes + edges)
  GET  /nodes/{id}     — single node
  POST /nodes          — add a single node
  POST /edges          — add a single edge
  GET  /exposed        — internet-exposed resources
  GET  /attack-paths   — paths from internet to sensitive data
  GET  /blast-radius/{node_id} — affected resources if node compromised
  GET  /overprivileged — IAM roles/users with excessive permissions
  GET  /segmentation   — VPC/subnet isolation analysis
  GET  /risk-paths     — attack paths ranked by risk
  GET  /stats          — graph statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

try:
    from core.cloud_graph import (
        CloudGraph,
        CloudGraphEngine,
        EdgeType,
        GraphEdge,
        GraphNode,
        NodeType,
        get_cloud_graph_engine,
    )

    _engine: Optional[CloudGraphEngine] = None

    def _get_engine() -> CloudGraphEngine:
        global _engine
        if _engine is None:
            _engine = get_cloud_graph_engine()
        return _engine

    _HAS_ENGINE = True
except ImportError as _exc:
    _logger.warning("cloud_graph_router: cloud_graph module unavailable: %s", _exc)
    _HAS_ENGINE = False
    GraphNode = None  # type: ignore[assignment,misc]
    GraphEdge = None  # type: ignore[assignment,misc]

router = APIRouter(prefix="/api/v1/cloud-graph", tags=["cloud-graph"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class BuildGraphRequest(BaseModel):
    resources: List[Dict[str, Any]] = Field(..., description="List of raw cloud resource dicts")
    org_id: str = Field("default", description="Organisation ID")


class AddNodeRequest(BaseModel):
    type: str = Field(..., description="NodeType value")
    name: str = Field(..., description="Resource name")
    provider: str = Field("AWS", description="Cloud provider")
    region: str = Field("us-east-1", description="Cloud region")
    config: Dict[str, Any] = Field(default_factory=dict, description="Resource config dict")
    risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Risk score 0-1")
    vulnerabilities: List[str] = Field(default_factory=list, description="Known CVEs/issues")
    public: bool = Field(False, description="Internet-reachable?")
    org_id: str = Field("default", description="Organisation ID")


class AddEdgeRequest(BaseModel):
    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    type: str = Field(..., description="EdgeType value")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Edge metadata")
    org_id: str = Field("default", description="Organisation ID")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_engine() -> "CloudGraphEngine":
    if not _HAS_ENGINE:
        raise HTTPException(status_code=503, detail="cloud_graph module unavailable")
    return _get_engine()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/build", response_model=CloudGraph, summary="Build cloud resource graph")
def build_graph(req: BuildGraphRequest) -> "CloudGraph":
    """Ingest raw resource list, auto-infer relationships, and persist the graph."""
    engine = _require_engine()
    try:
        return engine.build_graph_from_resources(req.resources, org_id=req.org_id)
    except Exception as exc:
        _logger.exception("cloud_graph.build failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Graph build failed: {exc}") from exc


@router.get("/graph", response_model=CloudGraph, summary="Get cloud graph")
def get_graph(
    org_id: str = Query("default", description="Organisation ID"),
    node_type: Optional[str] = Query(None, description="Filter by NodeType"),
    public_only: bool = Query(False, description="Return only public nodes"),
) -> "CloudGraph":
    """Return the full cloud resource graph, optionally filtered."""
    engine = _require_engine()
    try:
        nt = NodeType(node_type) if node_type else None
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid node_type: {node_type}")
    return engine.get_graph(org_id, node_type=nt, public_only=public_only)


@router.post("/nodes", response_model=GraphNode, summary="Add a graph node")
def add_node(req: AddNodeRequest) -> "GraphNode":
    """Add a single cloud resource node to the graph."""
    engine = _require_engine()
    try:
        node_type = NodeType(req.type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid node type: {req.type}")
    node = GraphNode(
        type=node_type,
        name=req.name,
        provider=req.provider,
        region=req.region,
        config=req.config,
        risk_score=req.risk_score,
        vulnerabilities=req.vulnerabilities,
        public=req.public,
    )
    try:
        return engine.add_node(node, org_id=req.org_id)
    except Exception as exc:
        _logger.exception("cloud_graph.add_node failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Add node failed: {exc}") from exc


@router.post("/edges", response_model=GraphEdge, summary="Add a graph edge")
def add_edge(req: AddEdgeRequest) -> "GraphEdge":
    """Add a relationship edge between two nodes."""
    engine = _require_engine()
    try:
        edge_type = EdgeType(req.type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid edge type: {req.type}")
    edge = GraphEdge(
        source_id=req.source_id,
        target_id=req.target_id,
        type=edge_type,
        metadata=req.metadata,
    )
    try:
        return engine.add_edge(edge, org_id=req.org_id)
    except Exception as exc:
        _logger.exception("cloud_graph.add_edge failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Add edge failed: {exc}") from exc


@router.get("/exposed", response_model=List[GraphNode] if GraphNode else None, summary="Internet-exposed resources")
def get_exposed_resources(
    org_id: str = Query("default", description="Organisation ID"),
) -> List["GraphNode"]:
    """Return all internet-reachable (public=True) cloud resources."""
    engine = _require_engine()
    return engine.get_exposed_resources(org_id)


@router.get("/attack-paths", summary="Attack paths from internet to sensitive data")
def get_attack_paths(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Find traversal paths from public-facing nodes to sensitive resources."""
    engine = _require_engine()
    paths = engine.find_attack_paths(org_id)
    serialised = [
        [{"id": n.id, "name": n.name, "type": n.type.value, "risk_score": n.risk_score} for n in path]
        for path in paths
    ]
    return {"org_id": org_id, "path_count": len(serialised), "paths": serialised}


@router.get("/blast-radius/{node_id}", response_model=CloudGraph, summary="Blast radius for a node")
def get_blast_radius(
    node_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> "CloudGraph":
    """Return the subgraph of resources affected if the given node is compromised."""
    engine = _require_engine()
    graph = engine.find_blast_radius(node_id, org_id)
    if not graph.nodes:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found or has no blast radius")
    return graph


@router.get("/overprivileged", response_model=List[GraphNode] if GraphNode else None, summary="Overprivileged IAM entities")
def get_overprivileged_roles(
    org_id: str = Query("default", description="Organisation ID"),
) -> List["GraphNode"]:
    """Return IAM roles and users with excessive permissions."""
    engine = _require_engine()
    return engine.get_overprivileged_roles(org_id)


@router.get("/segmentation", summary="Network segmentation analysis")
def get_network_segmentation(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Analyse VPC and subnet isolation — flags mixed public/private VPCs."""
    engine = _require_engine()
    return engine.get_network_segmentation(org_id)


@router.get("/risk-paths", summary="Ranked attack paths by risk score")
def get_risk_paths(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return attack paths sorted by cumulative risk score (highest first)."""
    engine = _require_engine()
    paths = engine.calculate_risk_paths(org_id)
    return {"org_id": org_id, "path_count": len(paths), "paths": paths}


@router.get("/stats", summary="Graph statistics")
def get_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return node/edge counts and per-type breakdown for the org."""
    engine = _require_engine()
    return engine.get_graph_stats(org_id)
