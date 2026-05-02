"""Security Capacity Planning Router — ALDECI.

Endpoints for SecurityCapacityPlanningEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/capacity-planning
Auth:   api_key_auth dependency on ALL endpoints

Routes:
  POST  /api/v1/capacity-planning/resources                        register_resource
  PUT   /api/v1/capacity-planning/resources/{id}/utilization       update_utilization
  POST  /api/v1/capacity-planning/demands                          add_demand
  PUT   /api/v1/capacity-planning/demands/{id}/assign              assign_resource
  POST  /api/v1/capacity-planning/snapshots                        take_snapshot
  GET   /api/v1/capacity-planning/summary                          get_capacity_summary
  GET   /api/v1/capacity-planning/skill-gaps                       get_skill_gap_analysis
  GET   /api/v1/capacity-planning/teams                            get_team_breakdown
"""
from __future__ import annotations

import logging
from typing import List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/capacity-planning",
    tags=["Security Capacity Planning"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_capacity_planning_engine import (
            SecurityCapacityPlanningEngine,
        )
        _engine = SecurityCapacityPlanningEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ResourceCreate(BaseModel):
    resource_name: str
    role: str = "analyst"
    team: str = ""
    fte: float = 1.0
    skills: List[str] = []
    certifications: List[str] = []
    cost_per_year: float = 0.0


class UtilizationUpdate(BaseModel):
    utilization_pct: float


class DemandCreate(BaseModel):
    demand_name: str
    domain: str = "detection"
    priority: str = "medium"
    required_fte: float = 1.0
    required_skills: List[str] = []
    timeline: str = "q1"


class ResourceAssign(BaseModel):
    resource_id: str


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@router.post("/resources", dependencies=[Depends(api_key_auth)], status_code=201)
def register_resource(body: ResourceCreate, org_id: str = Query(default="default")):
    """Register a new security team resource."""
    try:
        return _get_engine().register_resource(
            org_id=org_id,
            resource_name=body.resource_name,
            role=body.role,
            team=body.team,
            fte=body.fte,
            skills=body.skills,
            certifications=body.certifications,
            cost_per_year=body.cost_per_year,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/resources/{resource_id}/utilization", dependencies=[Depends(api_key_auth)])
def update_utilization(resource_id: str, body: UtilizationUpdate, org_id: str = Query(default="default")):
    """Update utilization percentage for a resource (clamped 0-100)."""
    try:
        return _get_engine().update_utilization(resource_id, org_id, body.utilization_pct)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Demands
# ---------------------------------------------------------------------------

@router.post("/demands", dependencies=[Depends(api_key_auth)], status_code=201)
def add_demand(body: DemandCreate, org_id: str = Query(default="default")):
    """Add a capacity demand with auto-computed gap_fte."""
    try:
        return _get_engine().add_demand(
            org_id=org_id,
            demand_name=body.demand_name,
            domain=body.domain,
            priority=body.priority,
            required_fte=body.required_fte,
            required_skills=body.required_skills,
            timeline=body.timeline,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/demands/{demand_id}/assign", dependencies=[Depends(api_key_auth)])
def assign_resource(demand_id: str, body: ResourceAssign, org_id: str = Query(default="default")):
    """Assign a resource to a demand."""
    try:
        return _get_engine().assign_resource(demand_id, org_id, body.resource_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

@router.post("/snapshots", dependencies=[Depends(api_key_auth)], status_code=201)
def take_snapshot(org_id: str = Query(default="default")):
    """Take a capacity snapshot for the current date."""
    try:
        return _get_engine().take_snapshot(org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_capacity_summary(org_id: str = Query(default="default")):
    """Get aggregated capacity summary."""
    return _get_engine().get_capacity_summary(org_id)


@router.get("/skill-gaps", dependencies=[Depends(api_key_auth)])
def get_skill_gap_analysis(org_id: str = Query(default="default")):
    """Get open demands with no assigned resource (skill gaps)."""
    return _get_engine().get_skill_gap_analysis(org_id)


@router.get("/teams", dependencies=[Depends(api_key_auth)])
def get_team_breakdown(org_id: str = Query(default="default")):
    """Get per-team resource count, total FTE, and avg utilization."""
    return _get_engine().get_team_breakdown(org_id)
