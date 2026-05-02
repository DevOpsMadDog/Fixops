"""Security Roadmap / Strategic Planning API Router — ALDECI.

Prefix: /api/v1/security-roadmap
Auth:   api_key_auth (X-API-Key / Bearer JWT / ?api_key=)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(
    prefix="/api/v1/security-roadmap",
    tags=["security-roadmap"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_roadmap_engine import SecurityRoadmapEngine
        _engine = SecurityRoadmapEngine()
    return _engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class InitiativeCreate(BaseModel):
    title: str
    description: str = ""
    category: str = "technology"
    priority: str = "medium"
    status: str = "planned"
    owner: str = ""
    budget_usd: float = 0.0
    start_date: str = ""
    target_date: str = ""
    completion_date: str = ""
    risk_reduction_score: float = 0.0


class InitiativeUpdate(BaseModel):
    status: Optional[str] = None
    owner: Optional[str] = None
    budget_usd: Optional[float] = None
    target_date: Optional[str] = None


class MilestoneCreate(BaseModel):
    title: str
    description: str = ""
    due_date: str = ""
    status: str = "pending"
    completion_date: str = ""


class GapCreate(BaseModel):
    title: str
    description: str = ""
    gap_type: str = "capability"
    severity: str = "medium"
    linked_initiative_id: str = ""


class GapLink(BaseModel):
    initiative_id: str


class MetricCreate(BaseModel):
    metric_name: str
    target_value: float = 0.0
    current_value: float = 0.0
    unit: str = ""


# ---------------------------------------------------------------------------
# Initiatives
# ---------------------------------------------------------------------------


@router.post(
    "/initiatives",
    dependencies=[Depends(api_key_auth)],
    summary="Create a security initiative",
)
def create_initiative(
    org_id: str = Query(..., description="Organisation ID"),
    body: InitiativeCreate = ...,
) -> Dict[str, Any]:
    engine = _get_engine()
    result = engine.create_initiative(org_id, body.model_dump())
    if not result:
        raise HTTPException(status_code=500, detail="Failed to create initiative")
    return result


@router.get(
    "/initiatives",
    dependencies=[Depends(api_key_auth)],
    summary="List security initiatives",
)
def list_initiatives(
    org_id: str = Query(..., description="Organisation ID"),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    return _get_engine().list_initiatives(org_id, status=status, category=category)


@router.get(
    "/initiatives/{initiative_id}",
    dependencies=[Depends(api_key_auth)],
    summary="Get a single initiative",
)
def get_initiative(
    initiative_id: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    result = _get_engine().get_initiative(org_id, initiative_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Initiative not found")
    return result


@router.patch(
    "/initiatives/{initiative_id}",
    dependencies=[Depends(api_key_auth)],
    summary="Update an initiative (status, owner, budget_usd, target_date)",
)
def update_initiative(
    initiative_id: str,
    org_id: str = Query(..., description="Organisation ID"),
    body: InitiativeUpdate = ...,
) -> Dict[str, Any]:
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    ok = _get_engine().update_initiative(org_id, initiative_id, data)
    if not ok:
        raise HTTPException(status_code=404, detail="Initiative not found or no valid fields")
    return {"updated": True, "initiative_id": initiative_id}


# ---------------------------------------------------------------------------
# Milestones
# ---------------------------------------------------------------------------


@router.post(
    "/initiatives/{initiative_id}/milestones",
    dependencies=[Depends(api_key_auth)],
    summary="Add a milestone to an initiative",
)
def add_milestone(
    initiative_id: str,
    org_id: str = Query(..., description="Organisation ID"),
    body: MilestoneCreate = ...,
) -> Dict[str, Any]:
    engine = _get_engine()
    result = engine.add_milestone(org_id, initiative_id, body.model_dump())
    if not result:
        raise HTTPException(status_code=500, detail="Failed to add milestone")
    return result


@router.get(
    "/initiatives/{initiative_id}/milestones",
    dependencies=[Depends(api_key_auth)],
    summary="List milestones for an initiative",
)
def list_milestones(
    initiative_id: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_milestones(org_id, initiative_id)


@router.post(
    "/milestones/{milestone_id}/complete",
    dependencies=[Depends(api_key_auth)],
    summary="Mark a milestone as completed",
)
def complete_milestone(
    milestone_id: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    ok = _get_engine().complete_milestone(org_id, milestone_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Milestone not found")
    return {"completed": True, "milestone_id": milestone_id}


# ---------------------------------------------------------------------------
# Gaps
# ---------------------------------------------------------------------------


@router.post(
    "/gaps",
    dependencies=[Depends(api_key_auth)],
    summary="Record a security gap",
)
def add_gap(
    org_id: str = Query(..., description="Organisation ID"),
    body: GapCreate = ...,
) -> Dict[str, Any]:
    engine = _get_engine()
    result = engine.add_gap(org_id, body.model_dump())
    if not result:
        raise HTTPException(status_code=500, detail="Failed to add gap")
    return result


@router.get(
    "/gaps",
    dependencies=[Depends(api_key_auth)],
    summary="List security gaps",
)
def list_gaps(
    org_id: str = Query(..., description="Organisation ID"),
    severity: Optional[str] = Query(None),
    resolved: bool = Query(False),
) -> List[Dict[str, Any]]:
    return _get_engine().list_gaps(org_id, severity=severity, resolved=resolved)


@router.post(
    "/gaps/{gap_id}/link",
    dependencies=[Depends(api_key_auth)],
    summary="Link a gap to an initiative",
)
def link_gap_to_initiative(
    gap_id: str,
    org_id: str = Query(..., description="Organisation ID"),
    body: GapLink = ...,
) -> Dict[str, Any]:
    ok = _get_engine().link_gap_to_initiative(org_id, gap_id, body.initiative_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Gap not found")
    return {"linked": True, "gap_id": gap_id, "initiative_id": body.initiative_id}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@router.post(
    "/initiatives/{initiative_id}/metrics",
    dependencies=[Depends(api_key_auth)],
    summary="Add a success metric to an initiative",
)
def add_metric(
    initiative_id: str,
    org_id: str = Query(..., description="Organisation ID"),
    body: MetricCreate = ...,
) -> Dict[str, Any]:
    engine = _get_engine()
    result = engine.add_metric(org_id, initiative_id, body.model_dump())
    if not result:
        raise HTTPException(status_code=500, detail="Failed to add metric")
    return result


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get(
    "/stats",
    dependencies=[Depends(api_key_auth)],
    summary="Get aggregate roadmap stats for an org",
)
def get_roadmap_stats(
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    return _get_engine().get_roadmap_stats(org_id)
