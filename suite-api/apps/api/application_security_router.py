"""Application Security Router — ALDECI.

Endpoints for the Application Security engine (SAST, DAST, scan runs, stats).

Prefix: /api/v1/appsec
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/appsec/apps                          register_app
  GET    /api/v1/appsec/apps                          list_apps
  GET    /api/v1/appsec/apps/{app_id}                 get_app
  GET    /api/v1/appsec/apps/{app_id}/sast            list_sast_findings
  POST   /api/v1/appsec/apps/{app_id}/sast            add_sast_finding
  GET    /api/v1/appsec/apps/{app_id}/dast            list_dast_findings
  POST   /api/v1/appsec/apps/{app_id}/dast            add_dast_finding
  POST   /api/v1/appsec/apps/{app_id}/scans           log_scan_run
  PATCH  /api/v1/appsec/findings/sast/{id}/status     update_sast_finding_status
  PATCH  /api/v1/appsec/findings/dast/{id}/status     update_dast_finding_status
  GET    /api/v1/appsec/stats                         get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/appsec",
    tags=["Application Security"],
)

_engines: Dict[str, Any] = {}


def _get_engine(org_id: str):
    if org_id not in _engines:
        from core.application_security_engine import ApplicationSecurityEngine
        _engines[org_id] = ApplicationSecurityEngine(org_id=org_id)
    return _engines[org_id]


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AppCreate(BaseModel):
    name: str
    app_type: str = "web"
    language: str = "other"
    repo_url: str = ""
    owner_team: str = ""
    criticality: str = "medium"
    security_score: float = Field(default=0.0, ge=0.0, le=100.0)
    status: str = "active"


class SASTFindingCreate(BaseModel):
    tool: str = "bandit"
    rule_id: str = ""
    title: str
    category: str = "injection"
    severity: str = "medium"
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""
    cwe_id: str = ""


class DASTFindingCreate(BaseModel):
    tool: str = "zap"
    endpoint: str = ""
    method: str = "GET"
    title: str
    category: str = "injection"
    severity: str = "medium"
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    request_sample: str = ""
    response_sample: str = ""


class ScanRunCreate(BaseModel):
    scan_type: str = "sast"
    tool: str = ""
    status: str = "running"
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0


class FindingStatusUpdate(BaseModel):
    status: str


# ---------------------------------------------------------------------------
# Application routes
# ---------------------------------------------------------------------------

@router.post("/apps", dependencies=[Depends(api_key_auth)], status_code=201)
def register_app(body: AppCreate, org_id: str = Query(default="default")):
    """Register a new application."""
    try:
        return _get_engine(org_id).register_app(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/apps", dependencies=[Depends(api_key_auth)])
def list_apps(
     org_id: str = Query(default="default"),
    app_type: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
):
    """List applications, optionally filtered by app_type and/or criticality."""
    return _get_engine(org_id).list_apps(org_id, app_type=app_type, criticality=criticality)


@router.get("/apps/{app_id}", dependencies=[Depends(api_key_auth)])
def get_app(app_id: str, org_id: str = Query(default="default")):
    """Get a single application with open findings summary."""
    app = _get_engine(org_id).get_app(org_id, app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return app


# ---------------------------------------------------------------------------
# SAST Finding routes
# ---------------------------------------------------------------------------

@router.get("/apps/{app_id}/sast", dependencies=[Depends(api_key_auth)])
def list_sast_findings(
    app_id: str,
     org_id: str = Query(default="default"),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List SAST findings for an application."""
    return _get_engine(org_id).list_sast_findings(
        org_id, app_id=app_id, severity=severity, status=status
    )


@router.post("/apps/{app_id}/sast", dependencies=[Depends(api_key_auth)], status_code=201)
def add_sast_finding(app_id: str, body: SASTFindingCreate, org_id: str = Query(default="default")):
    """Add a SAST finding to an application."""
    try:
        return _get_engine(org_id).add_sast_finding(org_id, app_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# DAST Finding routes
# ---------------------------------------------------------------------------

@router.get("/apps/{app_id}/dast", dependencies=[Depends(api_key_auth)])
def list_dast_findings(
    app_id: str,
     org_id: str = Query(default="default"),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List DAST findings for an application."""
    return _get_engine(org_id).list_dast_findings(
        org_id, app_id=app_id, severity=severity, status=status
    )


@router.post("/apps/{app_id}/dast", dependencies=[Depends(api_key_auth)], status_code=201)
def add_dast_finding(app_id: str, body: DASTFindingCreate, org_id: str = Query(default="default")):
    """Add a DAST finding to an application."""
    try:
        return _get_engine(org_id).add_dast_finding(org_id, app_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Scan Run routes
# ---------------------------------------------------------------------------

@router.post("/apps/{app_id}/scans", dependencies=[Depends(api_key_auth)], status_code=201)
def log_scan_run(app_id: str, body: ScanRunCreate, org_id: str = Query(default="default")):
    """Log a scan run for an application."""
    try:
        return _get_engine(org_id).log_scan_run(org_id, app_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Finding status update routes
# ---------------------------------------------------------------------------

@router.patch("/findings/sast/{finding_id}/status", dependencies=[Depends(api_key_auth)])
def update_sast_finding_status(
    finding_id: str, body: FindingStatusUpdate, org_id: str = Query(default="default")
):
    """Update the status of a SAST finding."""
    try:
        return _get_engine(org_id).update_finding_status(
            org_id, finding_id, "sast", body.status
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/findings/dast/{finding_id}/status", dependencies=[Depends(api_key_auth)])
def update_dast_finding_status(
    finding_id: str, body: FindingStatusUpdate, org_id: str = Query(default="default")
):
    """Update the status of a DAST finding."""
    try:
        return _get_engine(org_id).update_finding_status(
            org_id, finding_id, "dast", body.status
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")):
    """Return aggregated Application Security statistics for the org."""
    return _get_engine(org_id).get_stats(org_id)
