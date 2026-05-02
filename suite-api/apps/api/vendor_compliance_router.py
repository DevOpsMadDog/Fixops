"""Vendor Compliance Router — ALDECI.

Endpoints:
  POST /api/v1/vendor-compliance/vendors
  GET  /api/v1/vendor-compliance/vendors
  GET  /api/v1/vendor-compliance/vendors/{vendor_id}
  POST /api/v1/vendor-compliance/vendors/{vendor_id}/compliance-check
  POST /api/v1/vendor-compliance/requirements
  PUT  /api/v1/vendor-compliance/requirements/{req_id}/status
  GET  /api/v1/vendor-compliance/requirements
  GET  /api/v1/vendor-compliance/stats

Protected via api_key_auth dependency.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.vendor_compliance_engine import VendorComplianceEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vendor-compliance",
    tags=["vendor-compliance"],
    dependencies=[Depends(api_key_auth)],
)

_engine: Optional[VendorComplianceEngine] = None


def _get_engine() -> VendorComplianceEngine:
    global _engine
    if _engine is None:
        _engine = VendorComplianceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterVendorRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    name: str = Field(..., min_length=1, description="Vendor name")
    vendor_category: str = Field(..., description="One of: saas, paas, iaas, professional_services, hardware, support")
    contract_type: str = Field("annual", description="One of: annual, multi_year, month_to_month, one_time")
    contact_name: str = Field("", description="Primary contact name")
    contact_email: str = Field("", description="Primary contact email")
    contract_start: Optional[str] = Field(None, description="Contract start date (ISO 8601)")
    contract_end: Optional[str] = Field(None, description="Contract end date (ISO 8601)")


class ComplianceCheckRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    data_processing_agreement: bool = Field(False, description="DPA signed and current")
    security_questionnaire: bool = Field(False, description="Security questionnaire completed")
    pen_test_report: bool = Field(False, description="Recent penetration test report provided")
    soc2_report: bool = Field(False, description="SOC 2 report available")
    gdpr_compliance: bool = Field(False, description="GDPR compliance confirmed")
    insurance_certificate: bool = Field(False, description="Cyber insurance certificate on file")


class CreateRequirementRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    vendor_id: str = Field(..., description="ID of the vendor")
    requirement_name: str = Field(..., min_length=1, description="Requirement name")
    requirement_type: str = Field(..., description="One of: documentation, certification, audit, training, technical")
    due_date: str = Field(..., description="Due date (ISO 8601 or YYYY-MM-DD)")
    mandatory: bool = Field(True, description="Whether this requirement is mandatory")


class UpdateRequirementStatusRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    status: str = Field(..., description="One of: pending, in_progress, completed, waived")
    notes: str = Field("", description="Optional notes")


# ---------------------------------------------------------------------------
# Vendor endpoints
# ---------------------------------------------------------------------------


@router.post("/vendors", response_model=Dict[str, Any], status_code=201)
async def register_vendor(body: RegisterVendorRequest) -> Dict[str, Any]:
    """Register a new vendor."""
    engine = _get_engine()
    try:
        return engine.register_vendor(body.org_id, body.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/vendors", response_model=List[Dict[str, Any]])
async def list_vendors(
    org_id: str = Query("default", description="Organisation identifier"),
    vendor_category: Optional[str] = Query(None, description="Filter by vendor category"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> List[Dict[str, Any]]:
    """List vendors for an org with optional filters."""
    engine = _get_engine()
    return engine.list_vendors(org_id, vendor_category=vendor_category, status=status)


@router.get("/vendors/{vendor_id}", response_model=Dict[str, Any])
async def get_vendor(
    vendor_id: str,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Get a single vendor by ID."""
    engine = _get_engine()
    vendor = engine.get_vendor(org_id, vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail=f"Vendor '{vendor_id}' not found")
    return vendor


@router.post("/vendors/{vendor_id}/compliance-check", response_model=Dict[str, Any])
async def run_compliance_check(
    vendor_id: str,
    body: ComplianceCheckRequest,
) -> Dict[str, Any]:
    """Run a 6-item compliance check against a vendor."""
    engine = _get_engine()
    check_data = body.model_dump(exclude={"org_id"})
    return engine.run_compliance_check(body.org_id, vendor_id, check_data)


# ---------------------------------------------------------------------------
# Requirements endpoints
# ---------------------------------------------------------------------------


@router.post("/requirements", response_model=Dict[str, Any], status_code=201)
async def create_requirement(body: CreateRequirementRequest) -> Dict[str, Any]:
    """Create a compliance requirement for a vendor."""
    engine = _get_engine()
    try:
        return engine.create_compliance_requirement(body.org_id, body.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.put("/requirements/{req_id}/status", response_model=Dict[str, Any])
async def update_requirement_status(
    req_id: str,
    body: UpdateRequirementStatusRequest,
) -> Dict[str, Any]:
    """Update the status of a compliance requirement."""
    engine = _get_engine()
    try:
        return engine.update_requirement_status(body.org_id, req_id, body.status, body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/requirements", response_model=List[Dict[str, Any]])
async def list_requirements(
    org_id: str = Query("default", description="Organisation identifier"),
    vendor_id: Optional[str] = Query(None, description="Filter by vendor ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> List[Dict[str, Any]]:
    """List compliance requirements with optional filters."""
    engine = _get_engine()
    return engine.list_requirements(org_id, vendor_id=vendor_id, status=status)


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=Dict[str, Any])
async def get_stats(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return aggregate vendor compliance stats for an org."""
    engine = _get_engine()
    return engine.get_vendor_compliance_stats(org_id)


__all__ = ["router"]


# ---------------------------------------------------------------------------
# Root summary endpoint (5-state envelope)
# ---------------------------------------------------------------------------


@router.get("/", response_model=None)
async def get_vendor_compliance_root_summary(
    org_id: str = Query("default", description="Organisation identifier"),
):
    """Return a 5-state summary envelope for the Vendor Compliance domain.

    States:
      healthy   — vendors registered, avg compliance score >= 80, no overdue requirements
      degraded  — non-compliant vendors or overdue requirements present
      empty     — fresh tenant, no vendors registered
      error     — engine raised an exception
      unknown   — stats structure unexpected
    """
    try:
        stats = _get_engine().get_vendor_compliance_stats(org_id)
    except Exception as exc:
        logger.error("vendor_compliance.summary error: %s", exc)
        return {
            "status": "error",
            "org_id": org_id,
            "error": str(exc),
            "domain": "vendor-compliance",
        }

    total_vendors = stats.get("total_vendors", 0)
    non_compliant = stats.get("non_compliant_vendors", 0)
    overdue_requirements = stats.get("overdue_requirements", 0)

    if total_vendors == 0:
        status = "empty"
    elif non_compliant > 0 or overdue_requirements > 0:
        status = "degraded"
    else:
        status = "healthy"

    envelope: Dict[str, Any] = {
        "status": status,
        "org_id": org_id,
        "domain": "vendor-compliance",
        "stats": stats,
    }
    if status == "empty":
        envelope["hint"] = (
            "Register vendors via POST /api/v1/vendor-compliance/vendors "
            "to begin vendor compliance tracking."
        )
    return envelope
