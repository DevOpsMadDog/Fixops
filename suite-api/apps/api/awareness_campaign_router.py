"""Awareness Campaign Router — ALDECI.

Manages security awareness campaigns and participation tracking.

Prefix: /api/v1/awareness-campaigns
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/awareness-campaigns/campaigns                       create_campaign
  GET    /api/v1/awareness-campaigns/campaigns                       list_campaigns
  GET    /api/v1/awareness-campaigns/campaigns/{id}                  get_campaign
  PATCH  /api/v1/awareness-campaigns/campaigns/{id}/status           update_campaign_status
  POST   /api/v1/awareness-campaigns/campaigns/{id}/participations   record_participation
  GET    /api/v1/awareness-campaigns/participations                  list_participations
  GET    /api/v1/awareness-campaigns/stats                           get_campaign_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/awareness-campaigns",
    tags=["Awareness Campaigns"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.awareness_campaign_engine import AwarenessCampaignEngine
        _engine = AwarenessCampaignEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateCampaignRequest(BaseModel):
    title: str = Field(..., description="Campaign title")
    campaign_type: str = Field(
        default="training",
        description="phishing_sim | training | quiz | newsletter | video | tabletop",
    )
    campaign_status: str = Field(
        default="draft",
        description="draft | active | completed | paused | cancelled",
    )
    target_department: Optional[str] = Field(default=None)
    target_count: Optional[int] = Field(default=0, ge=0)
    start_date: Optional[str] = Field(default=None)
    end_date: Optional[str] = Field(default=None)
    created_by: Optional[str] = Field(default=None)


class UpdateStatusRequest(BaseModel):
    campaign_status: str = Field(
        ...,
        description="draft | active | completed | paused | cancelled",
    )


class RecordParticipationRequest(BaseModel):
    user_id: str = Field(..., description="User ID of the participant")
    result: str = Field(
        ...,
        description="pass | fail | incomplete | click | report",
    )
    department: Optional[str] = Field(default=None)
    score: Optional[float] = Field(default=0, ge=0, le=100)
    completed_at: Optional[str] = Field(default=None)
    time_spent_minutes: Optional[float] = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/campaigns", dependencies=[Depends(api_key_auth)])
def create_campaign(
    req: CreateCampaignRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a new awareness campaign."""
    try:
        return _get_engine().create_campaign(
            org_id,
            {
                "title": req.title,
                "campaign_type": req.campaign_type,
                "campaign_status": req.campaign_status,
                "target_department": req.target_department or "",
                "target_count": req.target_count or 0,
                "start_date": req.start_date or "",
                "end_date": req.end_date or "",
                "created_by": req.created_by or "",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/campaigns", dependencies=[Depends(api_key_auth)])
def list_campaigns(
    org_id: str = Query(..., description="Organization ID"),
    campaign_type: Optional[str] = Query(default=None),
    campaign_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List campaigns with optional filters."""
    return _get_engine().list_campaigns(
        org_id, campaign_type=campaign_type, campaign_status=campaign_status
    )


@router.get("/campaigns/{campaign_id}", dependencies=[Depends(api_key_auth)])
def get_campaign(
    campaign_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single campaign by ID."""
    campaign = _get_engine().get_campaign(org_id, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")
    return campaign


@router.patch("/campaigns/{campaign_id}/status", dependencies=[Depends(api_key_auth)])
def update_campaign_status(
    campaign_id: str,
    req: UpdateStatusRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update campaign status."""
    try:
        return _get_engine().update_campaign_status(org_id, campaign_id, req.campaign_status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/campaigns/{campaign_id}/participations", dependencies=[Depends(api_key_auth)])
def record_participation(
    campaign_id: str,
    req: RecordParticipationRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Record a user participation result for a campaign."""
    try:
        return _get_engine().record_participation(
            org_id,
            campaign_id,
            {
                "user_id": req.user_id,
                "result": req.result,
                "department": req.department or "",
                "score": req.score or 0,
                "completed_at": req.completed_at,
                "time_spent_minutes": req.time_spent_minutes or 0,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/participations", dependencies=[Depends(api_key_auth)])
def list_participations(
    org_id: str = Query(..., description="Organization ID"),
    campaign_id: Optional[str] = Query(default=None),
    result: Optional[str] = Query(default=None),
    department: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List participations with optional filters."""
    return _get_engine().list_participations(
        org_id, campaign_id=campaign_id, result=result, department=department
    )


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_campaign_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregate campaign statistics."""
    return _get_engine().get_campaign_stats(org_id)
