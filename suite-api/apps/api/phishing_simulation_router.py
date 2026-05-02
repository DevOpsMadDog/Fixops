"""Phishing Simulation Router — ALDECI.

Endpoints for the Phishing Simulation engine.

Prefix: /api/v1/phishing
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/phishing/campaigns                              list_campaigns
  POST   /api/v1/phishing/campaigns                             create_campaign
  GET    /api/v1/phishing/campaigns/{campaign_id}               get_campaign
  POST   /api/v1/phishing/campaigns/{campaign_id}/targets       add_target
  GET    /api/v1/phishing/campaigns/{campaign_id}/targets       list_targets
  POST   /api/v1/phishing/targets/{target_id}/result            record_result
  GET    /api/v1/phishing/templates                             list_templates
  POST   /api/v1/phishing/templates                             create_template
  GET    /api/v1/phishing/campaigns/{campaign_id}/stats         get_campaign_stats
  GET    /api/v1/phishing/stats                                 get_org_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/phishing",
    tags=["Phishing Simulation"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.phishing_simulation_engine import PhishingSimulationEngine
        _engine = PhishingSimulationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CampaignCreate(BaseModel):
    name: str
    campaign_type: str = "email"
    template_id: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    target_group: str = ""
    status: str = "draft"


class TargetCreate(BaseModel):
    email: str
    name: str = ""
    department: str = ""


class TemplateCreate(BaseModel):
    name: str
    subject: str = ""
    difficulty: str = "medium"
    content: str = ""
    template_type: str = "email"
    sender_name: str = ""


class ResultAction(BaseModel):
    action: str


# ---------------------------------------------------------------------------
# Campaign routes
# ---------------------------------------------------------------------------

@router.get("/campaigns", dependencies=[Depends(api_key_auth)])
def list_campaigns(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
):
    """List campaigns for an org, optionally filtered by status."""
    return _get_engine().list_campaigns(org_id, status=status)


@router.post("/campaigns", dependencies=[Depends(api_key_auth)], status_code=201)
def create_campaign(body: CampaignCreate, org_id: str = Query(default="default")):
    """Create a new phishing simulation campaign."""
    try:
        return _get_engine().create_campaign(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/campaigns/{campaign_id}", dependencies=[Depends(api_key_auth)])
def get_campaign(campaign_id: str, org_id: str = Query(default="default")):
    """Get a single campaign by ID."""
    result = _get_engine()._get_campaign(campaign_id, org_id)
    if not result:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return result


# ---------------------------------------------------------------------------
# Target routes
# ---------------------------------------------------------------------------

@router.post(
    "/campaigns/{campaign_id}/targets",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_target(
    campaign_id: str,
    body: TargetCreate,
    org_id: str = Query(default="default"),
):
    """Add a target to a campaign."""
    try:
        return _get_engine().add_target(org_id, campaign_id, body.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/campaigns/{campaign_id}/targets", dependencies=[Depends(api_key_auth)])
def list_targets(campaign_id: str, org_id: str = Query(default="default")):
    """List all targets for a campaign."""
    return _get_engine().list_targets(org_id, campaign_id)


# ---------------------------------------------------------------------------
# Result routes
# ---------------------------------------------------------------------------

@router.post("/targets/{target_id}/result", dependencies=[Depends(api_key_auth)])
def record_result(
    target_id: str,
    body: ResultAction,
    org_id: str = Query(default="default"),
):
    """Record an action taken by a target (opened/clicked/reported/data_submitted)."""
    success = _get_engine().record_result(org_id, target_id, body.action)
    if not success:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action '{body.action}' or target not found",
        )
    return {"recorded": True, "target_id": target_id, "action": body.action}


# ---------------------------------------------------------------------------
# Template routes
# ---------------------------------------------------------------------------

@router.get("/templates", dependencies=[Depends(api_key_auth)])
def list_templates(org_id: str = Query(default="default")):
    """List all phishing templates for an org."""
    return _get_engine().list_templates(org_id)


@router.post("/templates", dependencies=[Depends(api_key_auth)], status_code=201)
def create_template(body: TemplateCreate, org_id: str = Query(default="default")):
    """Create a new phishing template."""
    try:
        return _get_engine().create_template(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats routes
# ---------------------------------------------------------------------------

@router.get("/campaigns/{campaign_id}/stats", dependencies=[Depends(api_key_auth)])
def get_campaign_stats(campaign_id: str, org_id: str = Query(default="default")):
    """Return aggregated stats for a specific campaign."""
    return _get_engine().get_campaign_stats(org_id, campaign_id=campaign_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_org_stats(org_id: str = Query(default="default")):
    """Return high-level org-wide phishing awareness statistics."""
    return _get_engine().get_org_stats(org_id)
