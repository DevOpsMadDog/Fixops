"""Attack Path Analysis API Router.

Endpoints for modeling lateral movement through a network graph,
finding paths from entry points to crown jewel assets, and computing
blast radius for compromised hosts.

Prefix: /api/v1/attack-paths
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.attack_path_engine import AttackPathEngine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/attack-paths", tags=["attack-paths"])

# ---------------------------------------------------------------------------
# Singleton engine
# ---------------------------------------------------------------------------

_engine: Optional[AttackPathEngine] = None


def _get_engine() -> AttackPathEngine:
    global _engine
    if _engine is None:
        _engine = AttackPathEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AddNodeRequest(BaseModel):
    node_id: str = Field(..., description="Unique node identifier (e.g. hostname or IP)")
    node_type: str = Field(
        ...,
        description=(
            "Node type: workstation|server|database|cloud_service|"
            "network_device|external"
        ),
    )
    name: str = Field(..., description="Human-readable node name")
    risk_score: float = Field(50.0, ge=0.0, le=100.0, description="Risk score 0-100")
    is_crown_jewel: bool = Field(False, description="Whether this node is a crown jewel asset")
    vulnerabilities: list[str] = Field(
        default_factory=list, description="CVE IDs present on this node"
    )
    org_id: str = Field("default", description="Organisation ID")


class AddEdgeRequest(BaseModel):
    from_node: str = Field(..., description="Source node ID")
    to_node: str = Field(..., description="Destination node ID")
    protocol: str = Field("tcp", description="Network protocol")
    port: int = Field(0, ge=0, le=65535, description="Network port (0 = any)")
    requires_vuln: Optional[str] = Field(
        None, description="CVE ID required to traverse this edge"
    )
    org_id: str = Field("default", description="Organisation ID")


class AnalyzeRequest(BaseModel):
    entry_point: str = Field(..., description="Compromised host node ID")
    target: Optional[str] = Field(None, description="Specific target node ID (None = all crown jewels)")
    max_hops: int = Field(5, ge=1, le=20, description="Maximum lateral movement hops")
    org_id: str = Field("default", description="Organisation ID")


class BlastRadiusRequest(BaseModel):
    entry_point: str = Field(..., description="Compromised host node ID")
    org_id: str = Field("default", description="Organisation ID")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/nodes", summary="Add a network node to the attack graph")
def add_node(req: AddNodeRequest) -> dict:
    try:
        return _get_engine().add_node(
            node_id=req.node_id,
            node_type=req.node_type,
            name=req.name,
            risk_score=req.risk_score,
            is_crown_jewel=req.is_crown_jewel,
            vulnerabilities=req.vulnerabilities,
            org_id=req.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to add node")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/nodes", summary="List network nodes")
def list_nodes(
    org_id: str = Query("default", description="Organisation ID"),
    is_crown_jewel: Optional[bool] = Query(None, description="Filter by crown jewel status"),
) -> list[dict]:
    try:
        return _get_engine().list_nodes(org_id=org_id, is_crown_jewel=is_crown_jewel)
    except Exception as exc:
        logger.exception("Failed to list nodes")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete("/nodes/{node_id}", summary="Remove a network node and its edges")
def remove_node(
    node_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> dict:
    try:
        found = _get_engine().remove_node(node_id, org_id=org_id)
        if not found:
            raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
        return {"removed": True, "node_id": node_id}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to remove node")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/edges", summary="Add a lateral movement edge between nodes")
def add_edge(req: AddEdgeRequest) -> dict:
    try:
        return _get_engine().add_edge(
            from_node=req.from_node,
            to_node=req.to_node,
            protocol=req.protocol,
            port=req.port,
            requires_vuln=req.requires_vuln,
            org_id=req.org_id,
        )
    except Exception as exc:
        logger.exception("Failed to add edge")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/analyze", summary="Find attack paths from an entry point")
def analyze(req: AnalyzeRequest) -> dict:
    try:
        return _get_engine().find_attack_paths(
            entry_point=req.entry_point,
            target=req.target,
            max_hops=req.max_hops,
            org_id=req.org_id,
        )
    except Exception as exc:
        logger.exception("Failed to analyze attack paths")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/blast-radius", summary="Compute blast radius from a compromised entry point")
def blast_radius(req: BlastRadiusRequest) -> dict:
    try:
        return _get_engine().get_blast_radius(
            entry_point=req.entry_point,
            org_id=req.org_id,
        )
    except Exception as exc:
        logger.exception("Failed to compute blast radius")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/crown-jewels-at-risk", summary="List crown jewels and which entry points can reach them")
def crown_jewels_at_risk(
    org_id: str = Query("default", description="Organisation ID"),
) -> list[dict]:
    try:
        return _get_engine().get_crown_jewels_at_risk(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to get crown jewels at risk")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", summary="Attack graph statistics")
def stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> dict:
    try:
        return _get_engine().get_graph_stats(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to get graph stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/toxic-combinations", summary="Detect assets where chained medium findings create critical risk")
def toxic_combinations(
    org_id: str = Query("default", description="Organisation ID"),
) -> list[dict]:
    """Return assets with 3+ vulnerabilities that are internet-exposed.

    Each result contains:
    - asset: the node metadata
    - findings: list of CVE IDs present on the asset
    - combined_risk: amplified risk score (capped at 100)
    - attack_chain: external nodes that can directly reach this asset
    """
    try:
        return _get_engine().get_toxic_combinations(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to detect toxic combinations")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/", summary="Attack paths index", tags=["attack-paths"])
async def attack_paths_index(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return a summary of attack paths for the org."""
    try:
        nodes = _get_engine().list_nodes(org_id=org_id)
        return {"router": "attack-paths", "org_id": org_id, "items": nodes, "count": len(nodes)}
    except Exception as exc:
        logger.warning("attack_paths_index fallback: %s", exc)
        return {"router": "attack-paths", "org_id": org_id, "items": [], "count": 0}
