"""Red Team Management Router — ALDECI.

Endpoints for the Red Team Management engine.

Prefix: /api/v1/red-team
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/red-team/engagements                          list_engagements
  POST   /api/v1/red-team/engagements                          create_engagement
  GET    /api/v1/red-team/engagements/{id}                     get_engagement
  PATCH  /api/v1/red-team/engagements/{id}/status              update_engagement_status
  GET    /api/v1/red-team/engagements/{id}/findings            list_findings
  POST   /api/v1/red-team/engagements/{id}/findings            add_finding
  GET    /api/v1/red-team/engagements/{id}/ttps                list_ttps
  POST   /api/v1/red-team/engagements/{id}/ttps                add_ttp
  GET    /api/v1/red-team/operators                            list_operators
  POST   /api/v1/red-team/operators                            add_operator
  GET    /api/v1/red-team/stats                                get_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/red-team",
    tags=["Red Team Management"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.red_team_mgmt_engine import RedTeamManagementEngine
        _engine = RedTeamManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EngagementCreate(BaseModel):
    name: str
    engagement_type: str = "internal"
    methodology: str = "PTES"
    scope_description: str = ""
    start_date: str = ""
    end_date: str = ""
    lead_operator: str = ""
    classification: str = "confidential"


class EngagementStatusUpdate(BaseModel):
    status: str


class FindingCreate(BaseModel):
    title: str
    category: str = "initial_access"
    severity: str = "medium"
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    description: str = ""
    evidence_path: str = ""
    remediation_recommendation: str = ""
    status: str = "open"


class TTPCreate(BaseModel):
    tactic: str = ""
    technique_id: str = ""
    technique_name: str = ""
    procedure_description: str = ""
    outcome: str = "successful"
    detection_time_seconds: Optional[int] = None


class OperatorCreate(BaseModel):
    name: str
    specialization: str = "network"
    certifications: str = ""
    active_engagement_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Engagement routes
# ---------------------------------------------------------------------------

@router.get("/engagements", dependencies=[Depends(api_key_auth)])
def list_engagements(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
):
    """List red team engagements, optionally filtered by status."""
    return _get_engine().list_engagements(org_id, status=status)


@router.post("/engagements", dependencies=[Depends(api_key_auth)], status_code=201)
def create_engagement(body: EngagementCreate, org_id: str = Query(default="default")):
    """Create a new red team engagement."""
    try:
        return _get_engine().create_engagement(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/engagements/{engagement_id}", dependencies=[Depends(api_key_auth)])
def get_engagement(engagement_id: str, org_id: str = Query(default="default")):
    """Get a single engagement by ID, including findings summary."""
    eng = _get_engine().get_engagement(org_id, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return eng


@router.patch("/engagements/{engagement_id}/status", dependencies=[Depends(api_key_auth)])
def update_engagement_status(
    engagement_id: str,
    body: EngagementStatusUpdate,
     org_id: str = Query(default="default"),
):
    """Update the status of a red team engagement."""
    try:
        return _get_engine().update_engagement_status(org_id, engagement_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Finding routes
# ---------------------------------------------------------------------------

@router.get("/engagements/{engagement_id}/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
    engagement_id: str,
     org_id: str = Query(default="default"),
    severity: Optional[str] = Query(None),
):
    """List findings for an engagement, optionally filtered by severity."""
    return _get_engine().list_findings(org_id, engagement_id=engagement_id, severity=severity)


@router.post(
    "/engagements/{engagement_id}/findings",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_finding(
    engagement_id: str,
    body: FindingCreate,
     org_id: str = Query(default="default"),
):
    """Add a finding to a red team engagement."""
    try:
        return _get_engine().add_finding(org_id, engagement_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# TTP routes
# ---------------------------------------------------------------------------

@router.get("/engagements/{engagement_id}/ttps", dependencies=[Depends(api_key_auth)])
def list_ttps(engagement_id: str, org_id: str = Query(default="default")):
    """List TTPs executed during an engagement."""
    return _get_engine().list_ttps(org_id, engagement_id)


@router.post(
    "/engagements/{engagement_id}/ttps",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_ttp(
    engagement_id: str,
    body: TTPCreate,
     org_id: str = Query(default="default"),
):
    """Log a TTP for a red team engagement."""
    try:
        return _get_engine().add_ttp(org_id, engagement_id, body.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Operator routes
# ---------------------------------------------------------------------------

@router.get("/operators", dependencies=[Depends(api_key_auth)])
def list_operators(org_id: str = Query(default="default")):
    """List all red team operators for the org."""
    return _get_engine().list_operators(org_id)


@router.post("/operators", dependencies=[Depends(api_key_auth)], status_code=201)
def add_operator(body: OperatorCreate, org_id: str = Query(default="default")):
    """Register a new red team operator."""
    try:
        return _get_engine().add_operator(org_id, body.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")):
    """Return aggregated red team statistics for the org."""
    return _get_engine().get_stats(org_id)
