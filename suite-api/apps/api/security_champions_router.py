"""Security Champions Router — ALDECI.

Endpoints for the Security Champions Program engine.

Prefix: /api/v1/security-champions
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/security-champions/champions                       list_champions
  POST   /api/v1/security-champions/champions                       add_champion
  GET    /api/v1/security-champions/champions/{id}                  get_champion
  POST   /api/v1/security-champions/champions/{id}/activities       log_activity
  GET    /api/v1/security-champions/champions/{id}/certifications   list_certifications
  POST   /api/v1/security-champions/champions/{id}/certifications   add_certification
  GET    /api/v1/security-champions/campaigns                       list_campaigns
  POST   /api/v1/security-champions/campaigns                       create_campaign
  GET    /api/v1/security-champions/stats                           get_program_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-champions",
    tags=["Security Champions"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_champions_engine import SecurityChampionsEngine
        _engine = SecurityChampionsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ChampionCreate(BaseModel):
    name: str
    email: str = ""
    department: str = ""
    team: str = ""
    role: str = "champion"
    status: str = "active"
    joined_at: Optional[str] = None


class ActivityCreate(BaseModel):
    activity_type: str = "training"
    points_awarded: Optional[int] = None
    description: str = ""
    completed_at: Optional[str] = None
    verified_by: str = ""


class CertificationCreate(BaseModel):
    cert_name: str
    cert_provider: str = ""
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    status: str = "valid"


class CampaignCreate(BaseModel):
    title: str
    campaign_type: str = "awareness"
    start_date: str = ""
    end_date: str = ""
    target_department: str = ""
    participants_count: int = 0
    completion_rate: float = Field(default=0.0, ge=0.0, le=100.0)
    status: str = "planned"


# ---------------------------------------------------------------------------
# Champion routes
# ---------------------------------------------------------------------------

@router.get("/champions", dependencies=[Depends(api_key_auth)])
def list_champions(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    department: Optional[str] = Query(None),
):
    """List security champions, optionally filtered by status and/or department."""
    return _get_engine().list_champions(org_id, status=status, department=department)


@router.post("/champions", dependencies=[Depends(api_key_auth)], status_code=201)
def add_champion(body: ChampionCreate, org_id: str = Query(default="default")):
    """Register a new security champion."""
    try:
        return _get_engine().add_champion(org_id, body.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/champions/{champion_id}", dependencies=[Depends(api_key_auth)])
def get_champion(champion_id: str, org_id: str = Query(default="default")):
    """Get a single champion by ID."""
    champion = _get_engine().get_champion(org_id, champion_id)
    if not champion:
        raise HTTPException(status_code=404, detail="Champion not found")
    return champion


# ---------------------------------------------------------------------------
# Activity routes
# ---------------------------------------------------------------------------

@router.post(
    "/champions/{champion_id}/activities",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def log_activity(
    champion_id: str,
    body: ActivityCreate,
     org_id: str = Query(default="default"),
):
    """Log an activity for a champion. Auto-awards points and promotes level."""
    try:
        return _get_engine().log_activity(org_id, champion_id, body.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Certification routes
# ---------------------------------------------------------------------------

@router.get("/champions/{champion_id}/certifications", dependencies=[Depends(api_key_auth)])
def list_certifications(champion_id: str, org_id: str = Query(default="default")):
    """List certifications for a champion."""
    return _get_engine().list_certifications(org_id, champion_id=champion_id)


@router.post(
    "/champions/{champion_id}/certifications",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_certification(
    champion_id: str,
    body: CertificationCreate,
     org_id: str = Query(default="default"),
):
    """Add a certification for a champion."""
    try:
        return _get_engine().add_certification(org_id, champion_id, body.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Campaign routes
# ---------------------------------------------------------------------------

@router.get("/campaigns", dependencies=[Depends(api_key_auth)])
def list_campaigns(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
):
    """List campaigns, optionally filtered by status."""
    return _get_engine().list_campaigns(org_id, status=status)


@router.post("/campaigns", dependencies=[Depends(api_key_auth)], status_code=201)
def create_campaign(body: CampaignCreate, org_id: str = Query(default="default")):
    """Create a new awareness/training campaign."""
    try:
        return _get_engine().create_campaign(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_program_stats(org_id: str = Query(default="default")):
    """Return aggregated Security Champions program statistics."""
    return _get_engine().get_program_stats(org_id)
