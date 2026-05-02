"""Third Party Vendor Router — ALDECI.

Prefix: /api/v1/third-party-vendor
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/third-party-vendor/vendors                    register_vendor
  GET    /api/v1/third-party-vendor/vendors                    list_vendors
  GET    /api/v1/third-party-vendor/vendors/{id}               get_vendor
  POST   /api/v1/third-party-vendor/vendors/{id}/assess        conduct_assessment
  GET    /api/v1/third-party-vendor/assessments                list_assessments
  POST   /api/v1/third-party-vendor/vendors/{id}/incidents     add_incident
  GET    /api/v1/third-party-vendor/incidents                  list_incidents
  GET    /api/v1/third-party-vendor/stats                      get_vendor_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/third-party-vendor",
    tags=["Third Party Vendor"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.third_party_vendor_engine import ThirdPartyVendorEngine
        _engine = ThirdPartyVendorEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class VendorCreate(BaseModel):
    name: str
    vendor_category: str
    website: str = ""
    primary_contact: str = ""
    data_access_level: str = "public"
    contract_status: str = "active"


class AssessmentCreate(BaseModel):
    assessment_type: str = "security_questionnaire"
    assessor: str = ""
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    findings_count: int = Field(default=0, ge=0)
    critical_findings: int = Field(default=0, ge=0)
    passed: bool = False
    assessment_date: Optional[str] = None
    next_review_date: Optional[str] = None
    notes: str = ""


class IncidentCreate(BaseModel):
    title: str = ""
    severity: str = "medium"
    description: str = ""
    impact: str = ""


# ---------------------------------------------------------------------------
# Vendor routes
# ---------------------------------------------------------------------------

@router.post("/vendors", dependencies=[Depends(api_key_auth)], status_code=201)
def register_vendor(body: VendorCreate, org_id: str = Query(default="default")):
    """Register a new third-party vendor."""
    try:
        return _get_engine().register_vendor(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/vendors", dependencies=[Depends(api_key_auth)])
def list_vendors(
     org_id: str = Query(default="default"),
    vendor_category: Optional[str] = Query(None),
    risk_rating: Optional[str] = Query(None),
    contract_status: Optional[str] = Query(None),
):
    """List vendors with optional filters."""
    return _get_engine().list_vendors(
        org_id,
        vendor_category=vendor_category,
        risk_rating=risk_rating,
        contract_status=contract_status,
    )


@router.get("/vendors/{vendor_id}", dependencies=[Depends(api_key_auth)])
def get_vendor(vendor_id: str, org_id: str = Query(default="default")):
    """Get a single vendor by ID."""
    vendor = _get_engine().get_vendor(org_id, vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return vendor


# ---------------------------------------------------------------------------
# Assessment routes
# ---------------------------------------------------------------------------

@router.post("/vendors/{vendor_id}/assess", dependencies=[Depends(api_key_auth)], status_code=201)
def conduct_assessment(vendor_id: str, body: AssessmentCreate, org_id: str = Query(default="default")):
    """Conduct a security assessment for a vendor."""
    try:
        return _get_engine().conduct_assessment(org_id, vendor_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assessments", dependencies=[Depends(api_key_auth)])
def list_assessments(
     org_id: str = Query(default="default"),
    vendor_id: Optional[str] = Query(None),
    assessment_type: Optional[str] = Query(None),
):
    """List assessments with optional filters."""
    return _get_engine().list_assessments(
        org_id, vendor_id=vendor_id, assessment_type=assessment_type
    )


# ---------------------------------------------------------------------------
# Incident routes
# ---------------------------------------------------------------------------

@router.post("/vendors/{vendor_id}/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def add_incident(vendor_id: str, body: IncidentCreate, org_id: str = Query(default="default")):
    """Record a vendor-related security incident."""
    return _get_engine().add_incident(org_id, vendor_id, body.model_dump())


@router.get("/incidents", dependencies=[Depends(api_key_auth)])
def list_incidents(
     org_id: str = Query(default="default"),
    vendor_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List incidents with optional filters."""
    return _get_engine().list_incidents(
        org_id, vendor_id=vendor_id, severity=severity, status=status
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_vendor_stats(org_id: str = Query(default="default")):
    """Return aggregated third-party vendor statistics for the org."""
    return _get_engine().get_vendor_stats(org_id)


# ---------------------------------------------------------------------------
# Root summary endpoint (5-state envelope)
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_third_party_vendor_root_summary(org_id: str = Query(default="default")):
    """Return a 5-state summary envelope for the Third-Party Vendor domain.

    States:
      healthy   — vendors registered, no critical vendors, no open incidents
      degraded  — critical vendors present or open incidents requiring attention
      empty     — fresh tenant, no vendors registered
      error     — engine raised an exception
      unknown   — stats structure unexpected
    """
    try:
        stats = _get_engine().get_vendor_stats(org_id)
    except Exception as exc:
        _logger.error("third_party_vendor.summary error: %s", exc)
        return {
            "status": "error",
            "org_id": org_id,
            "error": str(exc),
            "domain": "third-party-vendor",
        }

    total_vendors = stats.get("total_vendors", 0)
    critical_vendors = stats.get("critical_vendors", 0)
    active_incidents = stats.get("active_incidents", 0)

    if total_vendors == 0:
        status = "empty"
    elif critical_vendors > 0 or active_incidents > 0:
        status = "degraded"
    else:
        status = "healthy"

    envelope = {
        "status": status,
        "org_id": org_id,
        "domain": "third-party-vendor",
        "stats": stats,
    }
    if status == "empty":
        envelope["hint"] = (
            "Register vendors via POST /api/v1/third-party-vendor/vendors "
            "to begin third-party vendor management."
        )
    return envelope
