"""
Network Segmentation Analyzer API Router.

Endpoints for managing network zones, recording flows, detecting
segmentation violations, and querying risk metrics.

Auth is applied centrally by app.py.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.network_analyzer import (
    FlowDirection,
    ZoneType,
    get_network_analyzer,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/network", tags=["network-segmentation"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class DefineZoneRequest(BaseModel):
    name: str = Field(..., min_length=1, description="Zone name")
    type: ZoneType = Field(..., description="Zone type")
    cidrs: List[str] = Field(default_factory=list, description="CIDR blocks")
    assets: List[str] = Field(default_factory=list, description="Asset IDs")
    trust_level: int = Field(50, ge=0, le=100, description="Trust level 0-100")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AddFlowRequest(BaseModel):
    source_zone: str = Field(..., description="Source zone ID")
    dest_zone: str = Field(..., description="Destination zone ID")
    ports: List[int] = Field(default_factory=list, description="Destination ports")
    protocol: str = Field("tcp", description="Network protocol")
    direction: Optional[FlowDirection] = Field(None, description="Flow direction (auto-detected if omitted)")
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Zone endpoints
# ---------------------------------------------------------------------------


@router.post("/zones", response_model=Dict[str, Any], status_code=201)
def create_zone(req: DefineZoneRequest) -> Dict[str, Any]:
    """Define a new network zone."""
    analyzer = get_network_analyzer()
    try:
        zone = analyzer.define_zone(
            name=req.name,
            zone_type=req.type,
            cidrs=req.cidrs,
            assets=req.assets,
            trust_level=req.trust_level,
            metadata=req.metadata,
        )
        return zone.to_dict()
    except Exception as exc:
        logger.exception("Failed to create zone")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/zones", response_model=List[Dict[str, Any]])
def list_zones() -> List[Dict[str, Any]]:
    """List all network zones."""
    analyzer = get_network_analyzer()
    return [z.to_dict() for z in analyzer.list_zones()]


@router.get("/zones/{zone_id}", response_model=Dict[str, Any])
def get_zone(zone_id: str) -> Dict[str, Any]:
    """Get a single zone by ID."""
    analyzer = get_network_analyzer()
    zone = analyzer.get_zone(zone_id)
    if zone is None:
        raise HTTPException(status_code=404, detail=f"Zone '{zone_id}' not found")
    return zone.to_dict()


# ---------------------------------------------------------------------------
# Flow endpoints
# ---------------------------------------------------------------------------


@router.post("/flows", response_model=Dict[str, Any], status_code=201)
def add_flow(req: AddFlowRequest) -> Dict[str, Any]:
    """Record an observed network flow between two zones."""
    analyzer = get_network_analyzer()
    try:
        flow = analyzer.add_flow(
            source_zone=req.source_zone,
            dest_zone=req.dest_zone,
            ports=req.ports,
            protocol=req.protocol,
            direction=req.direction,
            metadata=req.metadata,
        )
        return flow.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to record flow")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/flows", response_model=List[Dict[str, Any]])
def list_flows(
    allowed: Optional[bool] = Query(None, description="Filter by allowed status"),
) -> List[Dict[str, Any]]:
    """List recorded network flows."""
    analyzer = get_network_analyzer()
    return [f.to_dict() for f in analyzer.list_flows(allowed=allowed)]


# ---------------------------------------------------------------------------
# Analysis endpoints
# ---------------------------------------------------------------------------


@router.get("/analysis/segmentation", response_model=Dict[str, Any])
def analyze_segmentation() -> Dict[str, Any]:
    """Check all flows against zone segmentation policies."""
    try:
        analyzer = get_network_analyzer()
        return analyzer.analyze_segmentation()
    except Exception:
        return {"zones": [], "violations": [], "score": 0}


@router.post("/analysis/detect-violations", response_model=List[Dict[str, Any]])
def detect_violations() -> List[Dict[str, Any]]:
    """Detect and persist unauthorized cross-zone traffic violations."""
    analyzer = get_network_analyzer()
    violations = analyzer.detect_violations()
    return [v.to_dict() for v in violations]


@router.get("/analysis/zone-matrix", response_model=Dict[str, Any])
def get_zone_matrix() -> Dict[str, Any]:
    """Get zone-to-zone communication matrix."""
    analyzer = get_network_analyzer()
    return analyzer.get_zone_matrix()


@router.get("/analysis/lateral-movement", response_model=Dict[str, Any])
def get_lateral_movement_risk() -> Dict[str, Any]:
    """Assess lateral movement risk across the network."""
    analyzer = get_network_analyzer()
    return analyzer.get_lateral_movement_risk()


@router.get("/analysis/segmentation-score", response_model=Dict[str, Any])
def get_micro_segmentation_score() -> Dict[str, Any]:
    """Get micro-segmentation score (0-100)."""
    analyzer = get_network_analyzer()
    return analyzer.get_micro_segmentation_score()


@router.get("/stats", response_model=Dict[str, Any])
def get_network_stats() -> Dict[str, Any]:
    """Return aggregate network statistics."""
    analyzer = get_network_analyzer()
    return analyzer.get_network_stats()
