"""Security Posture Maturity Router — ALDECI.

CMMI-style security maturity assessment across capability domains.

Prefix: /api/v1/posture-maturity
Auth: api_key_auth on ALL endpoints

Routes:
  POST   /api/v1/posture-maturity/assessments              record_assessment
  PUT    /api/v1/posture-maturity/assessments/{id}         update_level
  POST   /api/v1/posture-maturity/roadmap                  create_roadmap_item
  PUT    /api/v1/posture-maturity/roadmap/{id}/advance     advance_roadmap_item
  POST   /api/v1/posture-maturity/snapshots                take_snapshot
  GET    /api/v1/posture-maturity/overview                 get_maturity_overview
  GET    /api/v1/posture-maturity/domains                  get_domain_breakdown
  GET    /api/v1/posture-maturity/roadmap                  get_roadmap
  GET    /api/v1/posture-maturity/overdue                  get_overdue_reviews
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/posture-maturity",
    tags=["Security Posture Maturity"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_posture_maturity_engine import SecurityPostureMaturityEngine
        _engine = SecurityPostureMaturityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RecordAssessmentRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    domain: str = Field(..., description="Security domain")
    capability: str = Field(..., description="Capability being assessed")
    maturity_level: int = Field(..., ge=1, description="Current maturity level (1–max_level)")
    max_level: int = Field(default=5, ge=1, description="Maximum maturity level (default 5)")
    evidence: str = Field(default="", description="Supporting evidence")
    assessor: str = Field(default="", description="Who performed the assessment")
    next_review: str = Field(default="", description="ISO-8601 date/time for next review")


class UpdateLevelRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    maturity_level: int = Field(..., ge=1, description="New maturity level")
    evidence: str = Field(default="", description="Updated evidence")


class CreateRoadmapItemRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    domain: str = Field(..., description="Security domain")
    capability: str = Field(..., description="Capability to improve")
    current_level: int = Field(..., ge=1, description="Current maturity level")
    target_level: int = Field(..., ge=1, description="Target maturity level")
    priority: str = Field(default="medium", description="critical/high/medium/low")
    effort: str = Field(default="medium", description="low/medium/high/very-high")
    timeline: str = Field(default="", description="Planned timeline (e.g. Q3 2026)")
    owner: str = Field(default="", description="Responsible owner")


class AdvanceRoadmapRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")


class TakeSnapshotRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/assessments", summary="Record a capability maturity assessment")
def record_assessment(req: RecordAssessmentRequest) -> Dict[str, Any]:
    try:
        return _get_engine().record_assessment(
            org_id=req.org_id,
            domain=req.domain,
            capability=req.capability,
            maturity_level=req.maturity_level,
            max_level=req.max_level,
            evidence=req.evidence,
            assessor=req.assessor,
            next_review=req.next_review,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/assessments/{assessment_id}", summary="Update maturity level for an assessment")
def update_level(assessment_id: str, req: UpdateLevelRequest) -> Dict[str, Any]:
    try:
        return _get_engine().update_level(
            assessment_id=assessment_id,
            org_id=req.org_id,
            maturity_level=req.maturity_level,
            evidence=req.evidence,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/roadmap", summary="Create a roadmap item")
def create_roadmap_item(req: CreateRoadmapItemRequest) -> Dict[str, Any]:
    try:
        return _get_engine().create_roadmap_item(
            org_id=req.org_id,
            domain=req.domain,
            capability=req.capability,
            current_level=req.current_level,
            target_level=req.target_level,
            priority=req.priority,
            effort=req.effort,
            timeline=req.timeline,
            owner=req.owner,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/roadmap/{item_id}/advance", summary="Advance roadmap item status")
def advance_roadmap_item(item_id: str, req: AdvanceRoadmapRequest) -> Dict[str, Any]:
    try:
        return _get_engine().advance_roadmap_item(item_id=item_id, org_id=req.org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/snapshots", summary="Take a maturity snapshot")
def take_snapshot(req: TakeSnapshotRequest) -> Dict[str, Any]:
    return _get_engine().take_snapshot(org_id=req.org_id)


@router.get("/overview", summary="Get maturity overview (snapshot + assessments + roadmap)")
def get_maturity_overview(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_maturity_overview(org_id=org_id)


@router.get("/domains", summary="Get per-domain maturity breakdown")
def get_domain_breakdown(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    return _get_engine().get_domain_breakdown(org_id=org_id)


@router.get("/roadmap", summary="List roadmap items")
def get_roadmap(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None, description="Filter by status"),
) -> List[Dict[str, Any]]:
    return _get_engine().get_roadmap(org_id=org_id, status=status)


@router.get("/overdue", summary="Get assessments with overdue reviews")
def get_overdue_reviews(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    return _get_engine().get_overdue_reviews(org_id=org_id)
