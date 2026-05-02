"""GNN Attack Path Prediction Router — /api/v1/attack-paths/gnn.

Exposes the GraphNeuralPredictor and SecurityGraph for GNN-based
attack path prediction, risk propagation, and critical node identification.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/attack-paths/gnn", tags=["GNN Attack Paths"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class InfrastructureNode(BaseModel):
    id: str
    type: str = "compute"
    properties: Dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0


class Connection(BaseModel):
    source: str
    target: str
    edge_type: str = "connects_to"
    weight: float = 1.0
    properties: Dict[str, Any] = Field(default_factory=dict)


class Vulnerability(BaseModel):
    id: str
    affects_node: str
    cvss_score: float = 5.0
    properties: Dict[str, Any] = Field(default_factory=dict)


class AttackSurfaceRequest(BaseModel):
    """Full attack surface analysis request."""
    infrastructure: List[InfrastructureNode]
    connections: List[Connection]
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)


class RiskPropagationRequest(BaseModel):
    """Request to propagate risk from specific vulnerability nodes."""
    infrastructure: List[InfrastructureNode]
    connections: List[Connection]
    source_nodes: List[str] = Field(
        ..., description="Node IDs to propagate risk from"
    )
    max_depth: int = 5
    decay_factor: float = 0.8


class PathQueryRequest(BaseModel):
    """Request to find attack paths between specific nodes."""
    infrastructure: List[InfrastructureNode]
    connections: List[Connection]
    entry_points: List[str]
    targets: List[str]
    max_paths: int = 10
    max_depth: int = 10


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/analyze", summary="Full attack surface analysis")
async def analyze_attack_surface(req: AttackSurfaceRequest) -> Dict[str, Any]:
    """Analyze attack surface using GNN-based prediction.

    Builds a security graph, identifies entry points and high-value targets,
    finds attack paths, propagates risk, and identifies critical nodes.
    """
    from core.attack_graph_gnn import analyze_attack_surface

    infra = [n.model_dump() for n in req.infrastructure]
    conns = [c.model_dump() for c in req.connections]
    vulns = [v.model_dump() for v in req.vulnerabilities]

    return analyze_attack_surface(infra, conns, vulns)


@router.post("/paths", summary="Find attack paths")
async def find_paths(req: PathQueryRequest) -> Dict[str, Any]:
    """Find attack paths from entry points to targets."""
    from core.attack_graph_gnn import (
        EdgeType,
        GraphNeuralPredictor,
        NodeType,
        SecurityGraph,
    )

    graph = SecurityGraph()
    for node in req.infrastructure:
        try:
            nt = NodeType(node.type)
        except ValueError:
            nt = NodeType.COMPUTE
        graph.add_node(node.id, nt, node.properties, node.risk_score)

    for conn in req.connections:
        try:
            et = EdgeType(conn.edge_type)
        except ValueError:
            et = EdgeType.CONNECTS_TO
        graph.add_edge(conn.source, conn.target, et, conn.weight, conn.properties)

    predictor = GraphNeuralPredictor()
    paths = predictor.find_attack_paths(
        graph, req.entry_points, req.targets, req.max_paths, req.max_depth,
    )
    return {
        "paths": [p.to_dict() for p in paths],
        "count": len(paths),
    }


@router.post("/propagate", summary="Risk propagation")
async def propagate_risk(req: RiskPropagationRequest) -> Dict[str, Any]:
    """Propagate risk from source nodes through the graph."""
    from core.attack_graph_gnn import (
        EdgeType,
        GraphNeuralPredictor,
        NodeType,
        SecurityGraph,
    )

    graph = SecurityGraph()
    for node in req.infrastructure:
        try:
            nt = NodeType(node.type)
        except ValueError:
            nt = NodeType.COMPUTE
        graph.add_node(node.id, nt, node.properties, node.risk_score)

    for conn in req.connections:
        try:
            et = EdgeType(conn.edge_type)
        except ValueError:
            et = EdgeType.CONNECTS_TO
        graph.add_edge(conn.source, conn.target, et, conn.weight, conn.properties)

    predictor = GraphNeuralPredictor()
    risk_scores = predictor.propagate_risk(graph, req.source_nodes)
    critical = predictor.identify_critical_nodes(graph, top_k=20)

    return {
        "risk_scores": {
            nid: round(score, 4)
            for nid, score in sorted(risk_scores.items(), key=lambda x: x[1], reverse=True)[:50]
        },
        "critical_nodes": critical,
        "source_nodes": req.source_nodes,
    }


@router.get("/node-types", summary="List node types")
async def list_node_types() -> List[str]:
    """List all valid node types for graph construction."""
    from core.attack_graph_gnn import NodeType
    return [nt.value for nt in NodeType]


@router.get("/edge-types", summary="List edge types")
async def list_edge_types() -> List[str]:
    """List all valid edge types for graph construction."""
    from core.attack_graph_gnn import EdgeType
    return [et.value for et in EdgeType]

