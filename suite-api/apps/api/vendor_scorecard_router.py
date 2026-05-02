"""
Vendor Security Scorecard API router for ALDECI.

Provides endpoints for managing third-party vendor risk scores, assessments,
and SBOM supply chain integration.

Routes:
- POST   /api/v1/vendors              — add vendor
- GET    /api/v1/vendors              — list vendors
- GET    /api/v1/vendors/high-risk    — high risk vendors
- GET    /api/v1/vendors/risk-changes — recent score changes
- GET    /api/v1/vendors/stats        — vendor stats
- GET    /api/v1/vendors/{id}         — get vendor
- PUT    /api/v1/vendors/{id}         — update vendor
- DELETE /api/v1/vendors/{id}         — delete vendor
- POST   /api/v1/vendors/{id}/assess  — manual assessment
- POST   /api/v1/vendors/{id}/auto-assess — auto assessment
- GET    /api/v1/vendors/{id}/history — assessment history
- POST   /api/v1/vendors/{id}/link-sbom — link SBOM components

Protected by api_key_auth dependency.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_SIMULATION_WARNING = {
    "is_simulated": True,
    "engine": "vendor_scorecard",
    "real_integration_required": "/api/v1/connectors/vendor-risk/configure",
    "do_not_use_in_demo": True,
}

router = APIRouter(
    prefix="/api/v1/vendors",
    tags=["vendor-scorecard"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy singleton — avoids import-time SQLite init during tests
# ---------------------------------------------------------------------------

_scorecard = None


def _get_scorecard():
    global _scorecard
    if _scorecard is None:
        from core.vendor_scorecard import VendorScorecard
        _scorecard = VendorScorecard()
    return _scorecard


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AddVendorRequest(BaseModel):
    name: str = Field(..., description="Vendor name")
    domain: str = Field(..., description="Primary domain (e.g. vendor.com)")
    description: str = Field(default="", description="Short description")
    contact_email: str = Field(default="", description="Security contact email")
    tags: List[str] = Field(default_factory=list, description="Arbitrary tags")
    org_id: str = Field(default="default", description="Organisation ID")


class UpdateVendorRequest(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    description: Optional[str] = None
    contact_email: Optional[str] = None
    tags: Optional[List[str]] = None


class ManualAssessRequest(BaseModel):
    ssl_score: Optional[float] = Field(default=None, ge=0, le=100)
    headers_score: Optional[float] = Field(default=None, ge=0, le=100)
    dns_score: Optional[float] = Field(default=None, ge=0, le=100)
    vulnerability_score: Optional[float] = Field(default=None, ge=0, le=100)
    data_handling_score: Optional[float] = Field(default=None, ge=0, le=100)
    assessor: str = Field(default="analyst", description="Who performed the assessment")
    notes: str = Field(default="", description="Assessment notes")
    validity_days: int = Field(default=90, ge=1, le=365)


class LinkSBOMRequest(BaseModel):
    component_names: List[str] = Field(..., description="SBOM component names to link")


# ---------------------------------------------------------------------------
# Routes — collection-level (must come BEFORE /{id} routes)
# ---------------------------------------------------------------------------

@router.get("/high-risk", summary="High-risk vendors")
async def get_high_risk_vendors(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return vendors in CRITICAL or HIGH risk tier."""
    vendors = _get_scorecard().get_high_risk_vendors(org_id=org_id)
    return {
        "vendors": [v.model_dump() for v in vendors],
        "total": len(vendors),
    }


@router.get("/risk-changes", summary="Recent score changes")
async def get_risk_changes(
    org_id: str = Query(default="default"),
    days: int = Query(default=30, ge=1, le=365),
) -> Dict[str, Any]:
    """Return vendors whose risk score changed in the last N days."""
    changes = _get_scorecard().get_risk_changes(org_id=org_id, days=days)
    return {"changes": changes, "total": len(changes), "days": days}


@router.get("/stats", summary="Vendor portfolio stats")
async def get_vendor_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return aggregate statistics for the vendor portfolio."""
    return _get_scorecard().get_vendor_stats(org_id=org_id)


# ---------------------------------------------------------------------------
# Routes — collection CRUD
# ---------------------------------------------------------------------------

@router.post("", summary="Add vendor", status_code=201)
async def add_vendor(req: AddVendorRequest) -> Dict[str, Any]:
    """Register a new third-party vendor for risk tracking."""
    from core.vendor_scorecard import Vendor, VendorRiskTier

    vendor = Vendor(
        id=str(uuid.uuid4()),
        name=req.name,
        domain=req.domain,
        description=req.description,
        contact_email=req.contact_email,
        tier=VendorRiskTier.MEDIUM,
        tags=req.tags,
        sbom_component_count=0,
        org_id=req.org_id,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    result = _get_scorecard().add_vendor(vendor)
    return result.model_dump()


@router.get("", summary="List vendors")
async def list_vendors(
    org_id: Optional[str] = Query(default=None),
    tier: Optional[str] = Query(default=None, description="Filter by tier"),
) -> Dict[str, Any]:
    """List vendors, optionally filtered by org or risk tier."""
    from core.vendor_scorecard import VendorRiskTier

    tier_filter = None
    if tier is not None:
        try:
            tier_filter = VendorRiskTier(tier.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown tier {tier!r}. Use: critical, high, medium, low, minimal",
            )

    vendors = _get_scorecard().list_vendors(org_id=org_id, tier_filter=tier_filter)
    return {"vendors": [v.model_dump() for v in vendors], "total": len(vendors)}


# ---------------------------------------------------------------------------
# Routes — item-level
# ---------------------------------------------------------------------------

@router.get("/{vendor_id}", summary="Get vendor")
async def get_vendor(vendor_id: str) -> Dict[str, Any]:
    """Return full vendor record including latest assessment summary."""
    try:
        vendor = _get_scorecard().get_vendor(vendor_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    latest = _get_scorecard().get_latest_assessment(vendor_id)
    data = vendor.model_dump()
    data["latest_assessment"] = latest.model_dump() if latest else None
    return data


@router.put("/{vendor_id}", summary="Update vendor")
async def update_vendor(vendor_id: str, req: UpdateVendorRequest) -> Dict[str, Any]:
    """Apply partial updates to a vendor record."""
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    try:
        vendor = _get_scorecard().update_vendor(vendor_id, updates)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return vendor.model_dump()


@router.delete("/{vendor_id}", summary="Delete vendor")
async def delete_vendor(vendor_id: str) -> Dict[str, Any]:
    """Remove a vendor and all associated assessments."""
    try:
        _get_scorecard().delete_vendor(vendor_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"deleted": True, "vendor_id": vendor_id}


@router.post("/{vendor_id}/assess", summary="Manual assessment")
async def manual_assess(vendor_id: str, req: ManualAssessRequest) -> Dict[str, Any]:
    """Submit a manual security assessment with explicit factor scores."""
    factors: Dict[str, float] = {}
    for field_name in (
        "ssl_score", "headers_score", "dns_score",
        "vulnerability_score", "data_handling_score",
    ):
        val = getattr(req, field_name)
        if val is not None:
            factors[field_name] = val

    if not factors:
        raise HTTPException(
            status_code=400,
            detail="At least one factor score must be provided.",
        )

    try:
        assessment = _get_scorecard().assess_vendor(
            vendor_id=vendor_id,
            factors=factors,
            assessor=req.assessor,
            notes=req.notes,
            validity_days=req.validity_days,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return assessment.model_dump()


@router.post("/{vendor_id}/auto-assess", summary="Auto assessment")
async def auto_assess(vendor_id: str) -> Dict[str, Any]:
    """Automatically assess a vendor via domain security analysis."""
    try:
        assessment = _get_scorecard().auto_assess(vendor_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"data": assessment.model_dump(), "_simulation_warning": _SIMULATION_WARNING}


@router.get("/{vendor_id}/history", summary="Assessment history")
async def get_assessment_history(vendor_id: str) -> Dict[str, Any]:
    """Return full assessment history for a vendor, newest first."""
    try:
        _get_scorecard().get_vendor(vendor_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    history = _get_scorecard().get_assessment_history(vendor_id)
    return {
        "vendor_id": vendor_id,
        "assessments": [a.model_dump() for a in history],
        "total": len(history),
    }


@router.post("/{vendor_id}/link-sbom", summary="Link SBOM components")
async def link_sbom_components(vendor_id: str, req: LinkSBOMRequest) -> Dict[str, Any]:
    """Associate SBOM component names with this vendor for supply chain tracking."""
    try:
        _get_scorecard().link_sbom_components(vendor_id, req.component_names)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    components = _get_scorecard().get_vendor_components(vendor_id)
    return {
        "vendor_id": vendor_id,
        "linked_components": components,
        "total": len(components),
    }
