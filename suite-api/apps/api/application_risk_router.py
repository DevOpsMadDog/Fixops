"""Application Risk Router — ALDECI.

Endpoints for the Application Risk engine.

Prefix: /api/v1/app-risk
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/app-risk/applications                          register_application
  GET  /api/v1/app-risk/applications                          list_applications
  GET  /api/v1/app-risk/applications/{app_id}                 get_application
  POST /api/v1/app-risk/applications/{app_id}/assess          assess_risk
  POST /api/v1/app-risk/applications/{app_id}/findings        add_finding
  GET  /api/v1/app-risk/findings                              list_findings
  POST /api/v1/app-risk/findings/{finding_id}/resolve         resolve_finding
  GET  /api/v1/app-risk/stats                                 get_app_risk_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/app-risk",
    tags=["Application Risk"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.application_risk_engine import ApplicationRiskEngine
        _engine = ApplicationRiskEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ApplicationCreate(BaseModel):
    name: str
    app_type: str = "web"
    tech_stack: str = ""
    owner_team: str = ""
    environment: str = "prod"


class AssessmentData(BaseModel):
    auth_controls: bool = False
    input_validation: bool = False
    encryption: bool = False
    dependency_scan: bool = True
    sast_findings: int = 0
    dast_findings: int = 0
    internet_exposed: bool = False


class FindingCreate(BaseModel):
    title: str = ""
    severity: str = "medium"
    finding_type: str = "sast"
    cve_id: str = ""


class FindingResolve(BaseModel):
    resolution: str


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------

@router.post("/applications", dependencies=[Depends(api_key_auth)], status_code=201)
def register_application(body: ApplicationCreate, org_id: str = Query(default="default")):
    """Register a new application."""
    try:
        return _get_engine().register_application(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/applications", dependencies=[Depends(api_key_auth)])
def list_applications(
     org_id: str = Query(default="default"),
    app_type: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
):
    """List applications with optional filters."""
    return _get_engine().list_applications(
        org_id,
        app_type=app_type,
        environment=environment,
    )


@router.get("/applications/{app_id}", dependencies=[Depends(api_key_auth)])
def get_application(app_id: str, org_id: str = Query(default="default")):
    """Get a single application by ID."""
    result = _get_engine().get_application(org_id, app_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Application not found")
    return result


@router.post("/applications/{app_id}/assess", dependencies=[Depends(api_key_auth)])
def assess_risk(app_id: str, body: AssessmentData, org_id: str = Query(default="default")):
    """Assess application risk and compute score."""
    return _get_engine().assess_risk(org_id, app_id, body.model_dump())


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@router.post(
    "/applications/{app_id}/findings",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_finding(app_id: str, body: FindingCreate, org_id: str = Query(default="default")):
    """Add a security finding to an application."""
    try:
        return _get_engine().add_finding(org_id, app_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
     org_id: str = Query(default="default"),
    app_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List findings with optional filters."""
    return _get_engine().list_findings(
        org_id,
        app_id=app_id,
        severity=severity,
        status=status,
    )


@router.post("/findings/{finding_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_finding(finding_id: str, body: FindingResolve, org_id: str = Query(default="default")):
    """Resolve a security finding."""
    try:
        return _get_engine().resolve_finding(org_id, finding_id, body.resolution)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_app_risk_stats(org_id: str = Query(default="default")):
    """Return aggregated application risk statistics."""
    return _get_engine().get_app_risk_stats(org_id)
