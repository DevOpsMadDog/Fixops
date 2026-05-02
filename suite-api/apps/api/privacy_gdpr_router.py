"""Privacy & GDPR Router — ALDECI.

Endpoints for the Privacy GDPR compliance engine.

Prefix: /api/v1/privacy
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/privacy/dsrs                           create_dsr
  GET    /api/v1/privacy/dsrs                           list_dsrs
  POST   /api/v1/privacy/dsrs/{request_id}/fulfill      fulfill_dsr
  PATCH  /api/v1/privacy/dsrs/{request_id}/status       update_dsr_status
  POST   /api/v1/privacy/consents                       record_consent
  GET    /api/v1/privacy/consents                       list_consents
  POST   /api/v1/privacy/consents/{consent_id}/withdraw withdraw_consent
  POST   /api/v1/privacy/incidents                      report_incident
  GET    /api/v1/privacy/incidents                      list_incidents
  POST   /api/v1/privacy/incidents/{incident_id}/notify-dpa notify_dpa
  PATCH  /api/v1/privacy/incidents/{incident_id}/status update_incident_status
  POST   /api/v1/privacy/processing-activities          add_processing_activity
  GET    /api/v1/privacy/processing-activities          list_processing_activities
  GET    /api/v1/privacy/stats                          get_privacy_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/privacy",
    tags=["privacy"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.privacy_gdpr_engine import PrivacyGDPREngine
        _engine = PrivacyGDPREngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DSRCreate(BaseModel):
    request_type: str = "access"
    subject_email: str
    subject_name: str = ""
    identity_verified: bool = False
    regulation: str = "gdpr"
    notes: str = ""


class DSRStatusUpdate(BaseModel):
    status: str


class DSRFulfill(BaseModel):
    notes: str = ""


class ConsentCreate(BaseModel):
    subject_email: str
    purpose: str = "functional"
    consent_given: bool = True
    consent_date: Optional[str] = None
    source: str = "website"
    version: str = ""
    ip_address: str = ""


class IncidentCreate(BaseModel):
    incident_type: str = "breach"
    severity: str = "medium"
    records_affected: int = Field(default=0, ge=0)
    data_types_affected: List[str] = Field(default_factory=list)
    description: str = ""


class IncidentStatusUpdate(BaseModel):
    status: str


class ProcessingActivityCreate(BaseModel):
    activity_name: str
    purpose: str = ""
    legal_basis: str = "consent"
    data_categories: List[str] = Field(default_factory=list)
    data_subjects: List[str] = Field(default_factory=list)
    retention_period_days: int = Field(default=365, ge=1)
    third_party_recipients: List[str] = Field(default_factory=list)
    international_transfers: List[str] = Field(default_factory=list)
    dpiad_required: bool = False


# ---------------------------------------------------------------------------
# DSR routes
# ---------------------------------------------------------------------------

@router.post("/dsrs", dependencies=[Depends(api_key_auth)], status_code=201)
def create_dsr(body: DSRCreate, org_id: str = Query(default="default")):
    """Create a Data Subject Request (access, erasure, portability, etc.)."""
    try:
        return _get_engine().create_dsr(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/dsrs", dependencies=[Depends(api_key_auth)])
def list_dsrs(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    request_type: Optional[str] = Query(None),
):
    """List Data Subject Requests with optional filters. Includes overdue flag."""
    return _get_engine().list_dsrs(org_id, status=status, request_type=request_type)


@router.post("/dsrs/{request_id}/fulfill", dependencies=[Depends(api_key_auth)])
def fulfill_dsr(request_id: str, body: DSRFulfill, org_id: str = Query(default="default")):
    """Mark a Data Subject Request as fulfilled."""
    updated = _get_engine().fulfill_dsr(org_id, request_id, notes=body.notes)
    if not updated:
        raise HTTPException(status_code=404, detail="DSR not found")
    return {"fulfilled": True, "request_id": request_id}


@router.patch("/dsrs/{request_id}/status", dependencies=[Depends(api_key_auth)])
def update_dsr_status(
    request_id: str, body: DSRStatusUpdate, org_id: str = Query(default="default")
):
    """Update DSR status (received/processing/fulfilled/rejected/expired)."""
    try:
        updated = _get_engine().update_dsr_status(org_id, request_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="DSR not found")
    return {"updated": True, "request_id": request_id, "status": body.status}


# ---------------------------------------------------------------------------
# Consent routes
# ---------------------------------------------------------------------------

@router.post("/consents", dependencies=[Depends(api_key_auth)], status_code=201)
def record_consent(body: ConsentCreate, org_id: str = Query(default="default")):
    """Record a consent decision for a data subject."""
    try:
        return _get_engine().record_consent(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/consents", dependencies=[Depends(api_key_auth)])
def list_consents(
     org_id: str = Query(default="default"),
    subject_email: Optional[str] = Query(None),
    purpose: Optional[str] = Query(None),
):
    """List consent records with optional filters."""
    return _get_engine().list_consents(
        org_id, subject_email=subject_email, purpose=purpose
    )


@router.post("/consents/{consent_id}/withdraw", dependencies=[Depends(api_key_auth)])
def withdraw_consent(consent_id: str, org_id: str = Query(default="default")):
    """Withdraw consent for a data subject."""
    updated = _get_engine().withdraw_consent(org_id, consent_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Consent record not found")
    return {"withdrawn": True, "consent_id": consent_id}


# ---------------------------------------------------------------------------
# Privacy incident routes
# ---------------------------------------------------------------------------

@router.post("/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def report_incident(body: IncidentCreate, org_id: str = Query(default="default")):
    """Report a privacy incident. Sets 72h DPA notification deadline for qualifying breaches."""
    try:
        return _get_engine().report_incident(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/incidents", dependencies=[Depends(api_key_auth)])
def list_incidents(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List privacy incidents with optional filters."""
    return _get_engine().list_incidents(org_id, status=status, severity=severity)


@router.post(
    "/incidents/{incident_id}/notify-dpa", dependencies=[Depends(api_key_auth)]
)
def notify_dpa(incident_id: str, org_id: str = Query(default="default")):
    """Mark DPA as notified for a privacy incident."""
    updated = _get_engine().notify_dpa(org_id, incident_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"dpa_notified": True, "incident_id": incident_id}


@router.patch(
    "/incidents/{incident_id}/status", dependencies=[Depends(api_key_auth)]
)
def update_incident_status(
    incident_id: str, body: IncidentStatusUpdate, org_id: str = Query(default="default")
):
    """Update privacy incident status."""
    try:
        updated = _get_engine().update_incident_status(org_id, incident_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"updated": True, "incident_id": incident_id, "status": body.status}


# ---------------------------------------------------------------------------
# Processing activities (RoPA) routes
# ---------------------------------------------------------------------------

@router.post(
    "/processing-activities", dependencies=[Depends(api_key_auth)], status_code=201
)
def add_processing_activity(body: ProcessingActivityCreate, org_id: str = Query(default="default")):
    """Register a processing activity (GDPR Art 30 RoPA record)."""
    try:
        return _get_engine().add_processing_activity(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/processing-activities", dependencies=[Depends(api_key_auth)])
def list_processing_activities(org_id: str = Query(default="default")):
    """List all processing activities (RoPA) for org."""
    return _get_engine().list_processing_activities(org_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_privacy_stats(org_id: str = Query(default="default")):
    """Return aggregated privacy compliance stats for org."""
    return _get_engine().get_privacy_stats(org_id)


# ---------------------------------------------------------------------------
# Root summary endpoint (5-state envelope)
# ---------------------------------------------------------------------------


@router.get("/", dependencies=[Depends(api_key_auth)])
def get_privacy_gdpr_summary(org_id: str = Query(default="default")):
    """Return a 5-state summary envelope for the privacy & GDPR domain.

    States:
      healthy   — DSRs in bounds, no overdue, incidents closed
      degraded  — overdue DSRs or open incidents requiring DPA notification
      empty     — fresh tenant, no DSRs or incidents recorded
      error     — engine raised an exception
      unknown   — stats structure unexpected
    """
    try:
        stats = _get_engine().get_privacy_stats(org_id)
    except Exception as exc:
        _logger.error("privacy_gdpr.summary error: %s", exc)
        return {
            "status": "error",
            "org_id": org_id,
            "error": str(exc),
            "domain": "privacy-gdpr",
        }

    total_dsrs = stats.get("total_dsrs", 0)
    overdue = stats.get("overdue_dsrs", 0)
    needs_notification = stats.get("incidents_requiring_notification", 0)
    total_incidents = stats.get("total_incidents", 0)

    if total_dsrs == 0 and total_incidents == 0:
        status = "empty"
    elif overdue > 0 or needs_notification > 0:
        status = "degraded"
    else:
        status = "healthy"

    envelope = {
        "status": status,
        "org_id": org_id,
        "domain": "privacy-gdpr",
        "stats": stats,
    }
    if status == "empty":
        envelope["hint"] = (
            "Create Data Subject Requests via POST /api/v1/privacy/dsrs "
            "or report privacy incidents via POST /api/v1/privacy/incidents "
            "to begin privacy & GDPR tracking."
        )
    return envelope
