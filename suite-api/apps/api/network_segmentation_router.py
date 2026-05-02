"""Network Segmentation Router — ALDECI.

Prefix: /api/v1/network-segmentation
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/network-segmentation/segments                      create_segment
  GET    /api/v1/network-segmentation/segments                      list_segments
  POST   /api/v1/network-segmentation/flow-policies                 add_flow_policy
  GET    /api/v1/network-segmentation/flow-policies                 list_flow_policies
  POST   /api/v1/network-segmentation/check-flow                    check_flow_allowed
  GET    /api/v1/network-segmentation/lateral-movement-risk         detect_lateral_movement_risk
  GET    /api/v1/network-segmentation/score                         get_segmentation_score
  GET    /api/v1/network-segmentation/stats                         get_segmentation_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/network-segmentation",
    tags=["Network Segmentation"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.network_segmentation_engine import NetworkSegmentationEngine
        _engine = NetworkSegmentationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SegmentCreate(BaseModel):
    name: str
    cidr: str = ""
    segment_type: str
    trust_level: int = Field(default=5, ge=0, le=10)
    description: str = ""


class FlowPolicyCreate(BaseModel):
    src_segment_id: str
    dst_segment_id: str
    action: str
    ports: List[str] = []
    justification: str = ""


class FlowCheckRequest(BaseModel):
    src_segment_id: str
    dst_segment_id: str
    port: int = Field(..., ge=0, le=65535)


# ---------------------------------------------------------------------------
# Segment routes
# ---------------------------------------------------------------------------

@router.post("/segments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_segment(body: SegmentCreate, org_id: str = Query(default="default")):
    """Create a network segment."""
    try:
        return _get_engine().create_segment(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/segments", dependencies=[Depends(api_key_auth)])
def list_segments(
    org_id: str = Query(default="default"),
    segment_type: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List segments (canonical envelope, batch-7).

    Class-c contract: empty IS correct for fresh tenants — network segments
    are defined via manual network discovery or asset-import flows, not
    auto-derivable from any public source. Always returns full envelope with
    pagination context + filters echo + actionable hint when empty.
    """
    rows = _get_engine().list_segments(org_id, segment_type=segment_type) or []
    paged = rows[offset : offset + limit] if offset else rows[:limit]
    envelope: Dict[str, Any] = {
        "items": paged,
        "segments": paged,  # legacy key preserved
        "total": len(rows),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
        "filters_applied": {
            "segment_type": segment_type,
        },
    }
    if not rows:
        envelope["hint"] = (
            "Define network segments via POST /api/v1/network-segmentation/segments "
            "(manual network discovery entry). Empty IS the correct response for a "
            "fresh tenant — no public source exists."
        )
    return envelope


# ---------------------------------------------------------------------------
# Flow policy routes
# ---------------------------------------------------------------------------

@router.post("/flow-policies", dependencies=[Depends(api_key_auth)], status_code=201)
def add_flow_policy(body: FlowPolicyCreate, org_id: str = Query(default="default")):
    """Add a flow policy between two segments."""
    try:
        return _get_engine().add_flow_policy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/flow-policies", dependencies=[Depends(api_key_auth)])
def list_flow_policies(org_id: str = Query(default="default")):
    """List all flow policies for the org."""
    return _get_engine().list_flow_policies(org_id)


# ---------------------------------------------------------------------------
# Flow check
# ---------------------------------------------------------------------------

@router.post("/check-flow", dependencies=[Depends(api_key_auth)])
def check_flow_allowed(body: FlowCheckRequest, org_id: str = Query(default="default")):
    """Check whether traffic between two segments on a given port is allowed."""
    return _get_engine().check_flow_allowed(
        org_id,
        body.src_segment_id,
        body.dst_segment_id,
        body.port,
    )


# ---------------------------------------------------------------------------
# Risk analysis routes
# ---------------------------------------------------------------------------

@router.get("/lateral-movement-risk", dependencies=[Depends(api_key_auth)])
def detect_lateral_movement_risk(org_id: str = Query(default="default")):
    """Detect segment pairs with risky allow-all flows between different trust levels."""
    return _get_engine().detect_lateral_movement_risk(org_id)


@router.get("/score", dependencies=[Depends(api_key_auth)])
def get_segmentation_score(org_id: str = Query(default="default")):
    """Return segmentation score (0-100), grade (A-F), and findings."""
    return _get_engine().get_segmentation_score(org_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_segmentation_stats(org_id: str = Query(default="default")):
    """Return aggregated segmentation statistics for the org."""
    return _get_engine().get_segmentation_stats(org_id)
