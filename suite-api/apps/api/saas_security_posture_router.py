"""SaaS Security Posture Management (SSPM) Router — ALDECI.

Prefix: /api/v1/sspm
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/sspm/apps                        register_app
  GET    /api/v1/sspm/apps                        list_apps
  GET    /api/v1/sspm/apps/{app_id}               get_app
  POST   /api/v1/sspm/apps/{app_id}/assess        assess_app
  GET    /api/v1/sspm/assessments                 list_assessments
  POST   /api/v1/sspm/apps/{app_id}/findings      record_finding
  GET    /api/v1/sspm/findings                    list_findings
  GET    /api/v1/sspm/stats                       get_sspm_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sspm",
    tags=["SaaS Security Posture"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.saas_security_posture_engine import SaasSecurityPostureEngine
        _engine = SaasSecurityPostureEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AppCreate(BaseModel):
    app_name: str
    app_category: str
    vendor: str = ""
    user_count: int = Field(default=0, ge=0)
    data_sensitivity: str = ""
    oauth_scopes: str = ""


class AssessmentCreate(BaseModel):
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    findings_count: int = Field(default=0, ge=0)
    assessor: str = ""
    assessment_date: Optional[str] = None
    notes: str = ""


class FindingCreate(BaseModel):
    finding_type: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""


# ---------------------------------------------------------------------------
# App routes
# ---------------------------------------------------------------------------

@router.post("/apps", dependencies=[Depends(api_key_auth)], status_code=201)
def register_app(body: AppCreate, org_id: str = Query(default="default")):
    """Register a new SaaS application."""
    try:
        return _get_engine().register_app(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/apps", dependencies=[Depends(api_key_auth)])
def list_apps(
     org_id: str = Query(default="default"),
    app_category: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List SaaS apps with optional filters.

    Type-a #20 wiring: when the org has no registered apps, the engine falls
    back to AppOmni live findings (when APPOMNI_API_KEY is set). Returns a
    5-state envelope (org_registered / appomni / needs_credentials / needs_data
    / connector_error). NEVER mocks.
    """
    return _get_engine().list_apps_with_appomni_fallback(
        org_id, app_category=app_category, risk_level=risk_level,
    )


@router.get("/apps/{app_id}", dependencies=[Depends(api_key_auth)])
def get_app(app_id: str, org_id: str = Query(default="default")):
    """Get a single SaaS app by ID."""
    app = _get_engine().get_app(org_id, app_id)
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    return app


# ---------------------------------------------------------------------------
# Assessment routes
# ---------------------------------------------------------------------------

@router.post("/apps/{app_id}/assess", dependencies=[Depends(api_key_auth)], status_code=201)
def assess_app(app_id: str, body: AssessmentCreate, org_id: str = Query(default="default")):
    """Conduct a security assessment for a SaaS app."""
    try:
        return _get_engine().assess_app(org_id, app_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assessments", dependencies=[Depends(api_key_auth)])
def list_assessments(
     org_id: str = Query(default="default"),
    app_id: Optional[str] = Query(None),
):
    """List assessments with optional app filter."""
    return _get_engine().list_assessments(org_id, app_id=app_id)


# ---------------------------------------------------------------------------
# Finding routes
# ---------------------------------------------------------------------------

@router.post("/apps/{app_id}/findings", dependencies=[Depends(api_key_auth)], status_code=201)
def record_finding(app_id: str, body: FindingCreate, org_id: str = Query(default="default")):
    """Record a security finding for a SaaS app."""
    try:
        return _get_engine().record_finding(org_id, app_id, body.model_dump())
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
        org_id, app_id=app_id, severity=severity, status=status
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_sspm_stats(org_id: str = Query(default="default")):
    """Return aggregated SSPM statistics for the org."""
    return _get_engine().get_sspm_stats(org_id)


# ---------------------------------------------------------------------------
# Root summary endpoint (5-state envelope)
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_sspm_root_summary(org_id: str = Query(default="default")):
    """Return a 5-state summary envelope for the SaaS Security Posture domain.

    States:
      healthy   — apps registered, no high-risk apps, open findings in bounds
      degraded  — high-risk apps or critical open findings present
      empty     — fresh tenant, no SaaS apps registered
      error     — engine raised an exception
      unknown   — stats structure unexpected
    """
    try:
        stats = _get_engine().get_sspm_stats(org_id)
    except Exception as exc:
        _logger.error("sspm.summary error: %s", exc)
        return {
            "status": "error",
            "org_id": org_id,
            "error": str(exc),
            "domain": "sspm",
        }

    total_apps = stats.get("total_apps", 0)
    high_risk_apps = stats.get("high_risk_apps", 0)
    critical_findings = stats.get("critical_findings", 0)

    if total_apps == 0:
        status = "empty"
    elif high_risk_apps > 0 or critical_findings > 0:
        status = "degraded"
    else:
        status = "healthy"

    envelope = {
        "status": status,
        "org_id": org_id,
        "domain": "sspm",
        "stats": stats,
    }
    if status == "empty":
        envelope["hint"] = (
            "Register SaaS applications via POST /api/v1/sspm/apps "
            "to begin SaaS security posture management."
        )
    return envelope
