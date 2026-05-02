"""TPRM Exchange Router — ALDECI.

Endpoints for TPRMExchangeEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/tprm-exchange
Auth:   api_key_auth dependency on ALL endpoints

Routes:
  POST  /api/v1/tprm-exchange/vendors                              register_vendor
  POST  /api/v1/tprm-exchange/vendors/{id}/assessments             create_assessment
  PUT   /api/v1/tprm-exchange/assessments/{id}/complete            complete_assessment
  POST  /api/v1/tprm-exchange/vendors/{id}/incidents               report_incident
  PUT   /api/v1/tprm-exchange/incidents/{id}/resolve               resolve_incident
  GET   /api/v1/tprm-exchange/vendors/{id}                         get_vendor_detail
  GET   /api/v1/tprm-exchange/summary                              get_tprm_summary
  GET   /api/v1/tprm-exchange/overdue                              get_overdue_assessments
  GET   /api/v1/tprm-exchange/high-risk                            get_high_risk_vendors
"""
from __future__ import annotations

import logging
from typing import List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tprm-exchange",
    tags=["TPRM Exchange"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.tprm_exchange_engine import TPRMExchangeEngine
        _engine = TPRMExchangeEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class VendorCreate(BaseModel):
    vendor_name: str
    vendor_category: str = "saas"
    criticality: str = "medium"
    data_shared: List[str] = []
    contract_start: str = ""
    contract_end: str = ""
    annual_spend: float = 0.0
    primary_contact: str = ""


class AssessmentCreate(BaseModel):
    assessment_type: str = "annual"
    assessor: str = ""
    due_date: str = ""


class AssessmentComplete(BaseModel):
    score: float
    findings_count: int = 0
    critical_findings: int = 0
    next_assessment: str = ""


class IncidentReport(BaseModel):
    incident_type: str = "service_outage"
    severity: str = "medium"
    description: str = ""
    impact: str = ""


# ---------------------------------------------------------------------------
# Vendors
# ---------------------------------------------------------------------------

@router.post("/vendors", dependencies=[Depends(api_key_auth)], status_code=201)
def register_vendor(body: VendorCreate, org_id: str = Query(default="default")):
    """Register a new third-party vendor."""
    try:
        return _get_engine().register_vendor(
            org_id=org_id,
            vendor_name=body.vendor_name,
            vendor_category=body.vendor_category,
            criticality=body.criticality,
            data_shared=body.data_shared,
            contract_start=body.contract_start,
            contract_end=body.contract_end,
            annual_spend=body.annual_spend,
            primary_contact=body.primary_contact,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/vendors/{vendor_id}", dependencies=[Depends(api_key_auth)])
def get_vendor_detail(vendor_id: str, org_id: str = Query(default="default")):
    """Get vendor profile with all assessments and incidents."""
    try:
        return _get_engine().get_vendor_detail(vendor_id, org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------

@router.post("/vendors/{vendor_id}/assessments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_assessment(vendor_id: str, body: AssessmentCreate, org_id: str = Query(default="default")):
    """Create a new assessment for a vendor."""
    try:
        return _get_engine().create_assessment(
            vendor_id=vendor_id,
            org_id=org_id,
            assessment_type=body.assessment_type,
            assessor=body.assessor,
            due_date=body.due_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/assessments/{assessment_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_assessment(assessment_id: str, body: AssessmentComplete, org_id: str = Query(default="default")):
    """Complete an assessment and update vendor risk tier."""
    try:
        return _get_engine().complete_assessment(
            assessment_id=assessment_id,
            org_id=org_id,
            score=body.score,
            findings_count=body.findings_count,
            critical_findings=body.critical_findings,
            next_assessment=body.next_assessment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.post("/vendors/{vendor_id}/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def report_incident(vendor_id: str, body: IncidentReport, org_id: str = Query(default="default")):
    """Report a vendor incident."""
    try:
        return _get_engine().report_incident(
            vendor_id=vendor_id,
            org_id=org_id,
            incident_type=body.incident_type,
            severity=body.severity,
            description=body.description,
            impact=body.impact,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/incidents/{incident_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_incident(incident_id: str, org_id: str = Query(default="default")):
    """Resolve a vendor incident."""
    try:
        return _get_engine().resolve_incident(incident_id, org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_tprm_summary(org_id: str = Query(default="default")):
    """Get TPRM summary: totals, tier breakdown, overdue assessments."""
    return _get_engine().get_tprm_summary(org_id)


@router.get("/overdue", dependencies=[Depends(api_key_auth)])
def get_overdue_assessments(org_id: str = Query(default="default")):
    """Get assessments past their due date that are still in progress."""
    return _get_engine().get_overdue_assessments(org_id)


@router.get("/high-risk", dependencies=[Depends(api_key_auth)])
def get_high_risk_vendors(org_id: str = Query(default="default")):
    """Get tier-1 and tier-2 vendors ordered by risk score."""
    return _get_engine().get_high_risk_vendors(org_id)


# ---------------------------------------------------------------------------
# Root summary endpoint (5-state envelope)
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_tprm_root_summary(org_id: str = Query(default="default")):
    """Return a 5-state summary envelope for the TPRM Exchange domain.

    States:
      healthy   — vendors registered, no overdue assessments, no open incidents
      degraded  — overdue assessments or open incidents requiring attention
      empty     — fresh tenant, no vendors registered
      error     — engine raised an exception
      unknown   — summary structure unexpected
    """
    try:
        summary = _get_engine().get_tprm_summary(org_id)
    except Exception as exc:
        _logger.error("tprm_exchange.summary error: %s", exc)
        return {
            "status": "error",
            "org_id": org_id,
            "error": str(exc),
            "domain": "tprm-exchange",
        }

    total = summary.get("total_vendors", 0)
    overdue = summary.get("overdue_assessments", 0)
    open_incidents = summary.get("open_incidents", 0)

    if total == 0:
        status = "empty"
    elif overdue > 0 or open_incidents > 0:
        status = "degraded"
    else:
        status = "healthy"

    envelope = {
        "status": status,
        "org_id": org_id,
        "domain": "tprm-exchange",
        "summary": summary,
    }
    if status == "empty":
        envelope["hint"] = (
            "Register vendors via POST /api/v1/tprm-exchange/vendors "
            "to begin third-party risk management."
        )
    return envelope
