"""Microsegmentation Policy Router — ALDECI.

Prefix: /api/v1/microsegmentation
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/microsegmentation/segments              create_segment
  GET    /api/v1/microsegmentation/segments              list_segments
  GET    /api/v1/microsegmentation/segments/{id}         get_segment
  POST   /api/v1/microsegmentation/policies              create_policy
  GET    /api/v1/microsegmentation/policies              list_policies
  POST   /api/v1/microsegmentation/violations            record_violation
  GET    /api/v1/microsegmentation/violations            list_violations
  GET    /api/v1/microsegmentation/stats                 get_segmentation_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/microsegmentation",
    tags=["Microsegmentation Policy"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.microsegmentation_policy_engine import MicrosegmentationPolicyEngine
        _engine = MicrosegmentationPolicyEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SegmentCreate(BaseModel):
    name: str
    segment_type: str
    cidr_range: str = ""
    description: str = ""
    enforcement_mode: str = "monitoring"


class PolicyCreate(BaseModel):
    src_segment_id: str
    dst_segment_id: str
    policy_action: str = "allow"
    protocol: str = "tcp"
    port_range: str = ""
    description: str = ""


class ViolationCreate(BaseModel):
    segment_id: str
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = "tcp"
    port: int = Field(default=0, ge=0)
    violation_type: str = "blocked_traffic"
    severity: str = "medium"


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_microsegmentation_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """5-state envelope summarising microsegmentation posture for the org.

    States: ok | warning | critical | empty | error
    Calls the real engine — no mocks.
    """
    try:
        stats = _get_engine().get_segmentation_stats(org_id)
        total_segments = stats.get("total_segments", 0)
        total_violations = stats.get("total_violations", 0)
        open_violations = stats.get("open_violations", stats.get("violations_open", total_violations))

        if total_segments == 0:
            state = "empty"
            message = (
                "No microsegments defined. Author segments via "
                "POST /api/v1/microsegmentation/segments."
            )
        elif open_violations > 10:
            state = "critical"
            message = f"{open_violations} open violation(s) across {total_segments} segment(s)."
        elif open_violations > 0:
            state = "warning"
            message = f"{open_violations} open violation(s) across {total_segments} segment(s)."
        else:
            state = "ok"
            message = f"{total_segments} segment(s) enforced, no open violations."

        return {
            "state": state,
            "message": message,
            "org_id": org_id,
            "stats": stats,
            "links": {
                "segments": "/api/v1/microsegmentation/segments",
                "policies": "/api/v1/microsegmentation/policies",
                "violations": "/api/v1/microsegmentation/violations",
                "stats": "/api/v1/microsegmentation/stats",
            },
        }
    except Exception as exc:
        _logger.exception("microsegmentation_summary_failed")
        return {
            "state": "error",
            "message": str(exc),
            "org_id": org_id,
            "stats": {},
            "links": {},
        }


# ---------------------------------------------------------------------------
# Segment routes
# ---------------------------------------------------------------------------

@router.post("/segments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_segment(body: SegmentCreate, org_id: str = Query(default="default")):
    """Create a microsegment."""
    try:
        return _get_engine().create_segment(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/segments", dependencies=[Depends(api_key_auth)])
def list_segments(
    org_id: str = Query(default="default"),
    segment_type: Optional[str] = Query(None),
    enforcement_mode: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List microsegments (canonical envelope, batch-7).

    Class-c contract: empty IS correct for fresh tenants — microsegmentation
    policies are manually authored by network/security engineers, not
    auto-derivable from any public source. Always returns full envelope with
    pagination context + filters echo + actionable hint when empty.
    """
    rows = _get_engine().list_segments(
        org_id, segment_type=segment_type, enforcement_mode=enforcement_mode
    ) or []
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
            "enforcement_mode": enforcement_mode,
        },
    }
    if not rows:
        envelope["hint"] = (
            "Define microsegmentation policies via POST /api/v1/microsegmentation/segments "
            "(manual policy authoring). Empty IS the correct response for a fresh "
            "tenant — no public source exists."
        )
    return envelope


@router.get("/segments/{segment_id}", dependencies=[Depends(api_key_auth)])
def get_segment(segment_id: str, org_id: str = Query(default="default")):
    """Get a single microsegment by ID."""
    seg = _get_engine().get_segment(org_id, segment_id)
    if not seg:
        raise HTTPException(status_code=404, detail="Segment not found")
    return seg


# ---------------------------------------------------------------------------
# Policy routes
# ---------------------------------------------------------------------------

@router.post("/policies", dependencies=[Depends(api_key_auth)], status_code=201)
def create_policy(body: PolicyCreate, org_id: str = Query(default="default")):
    """Create a microsegmentation policy between two segments."""
    try:
        return _get_engine().create_policy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/policies", dependencies=[Depends(api_key_auth)])
def list_policies(
     org_id: str = Query(default="default"),
    src_segment_id: Optional[str] = Query(None),
    dst_segment_id: Optional[str] = Query(None),
    policy_action: Optional[str] = Query(None),
):
    """List policies with optional filters."""
    return _get_engine().list_policies(
        org_id,
        src_segment_id=src_segment_id,
        dst_segment_id=dst_segment_id,
        policy_action=policy_action,
    )


# ---------------------------------------------------------------------------
# Violation routes
# ---------------------------------------------------------------------------

@router.post("/violations", dependencies=[Depends(api_key_auth)], status_code=201)
def record_violation(body: ViolationCreate, org_id: str = Query(default="default")):
    """Record a microsegmentation policy violation."""
    try:
        return _get_engine().record_violation(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/violations", dependencies=[Depends(api_key_auth)])
def list_violations(
     org_id: str = Query(default="default"),
    segment_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List violations with optional filters."""
    return _get_engine().list_violations(org_id, segment_id=segment_id, severity=severity)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_segmentation_stats(org_id: str = Query(default="default")):
    """Return aggregated microsegmentation statistics for the org."""
    return _get_engine().get_segmentation_stats(org_id)
