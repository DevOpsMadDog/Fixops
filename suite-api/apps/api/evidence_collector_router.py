"""
Evidence Collector API — compliance evidence management endpoints.

Supports 7 frameworks: SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF, CIS, GDPR.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.dependencies import get_org_id
from core.evidence_collector import (
    Evidence,
    EvidenceCollector,
    EvidenceStatus,
    EvidenceType,
)

router = APIRouter(prefix="/api/v1/evidence-collector", tags=["evidence-collector"])

_collector = EvidenceCollector()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class EvidenceCreateRequest(BaseModel):
    control_id: str
    framework: str
    type: EvidenceType
    title: str
    description: str
    collected_by: str
    file_hash: Optional[str] = None
    file_size: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class VerifyRequest(BaseModel):
    verifier: str


class RejectRequest(BaseModel):
    reason: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=Dict[str, Any], status_code=201)
async def add_evidence(
    body: EvidenceCreateRequest,
    org_id: str = Depends(get_org_id),
):
    """Add a new evidence record for a compliance control."""
    ev = Evidence(
        control_id=body.control_id,
        framework=body.framework,
        type=body.type,
        title=body.title,
        description=body.description,
        collected_by=body.collected_by,
        file_hash=body.file_hash,
        file_size=body.file_size,
        metadata=body.metadata,
        org_id=org_id,
    )
    created = _collector.add_evidence(ev)
    return created.model_dump(mode="json")


@router.get("", response_model=Dict[str, Any])
async def list_evidence(
    org_id: str = Depends(get_org_id),
    framework: Optional[str] = None,
    control_id: Optional[str] = None,
    status: Optional[EvidenceStatus] = None,
):
    """List evidence with optional filters."""
    evidences = _collector.list_evidence(
        org_id=org_id,
        framework=framework,
        control_id=control_id,
        status=status,
    )
    return {
        "items": [e.model_dump(mode="json") for e in evidences],
        "total": len(evidences),
    }


@router.get("/{evidence_id}", response_model=Dict[str, Any])
async def get_evidence(
    evidence_id: str,
    org_id: str = Depends(get_org_id),
):
    """Get a single evidence record by ID."""
    ev = _collector.get_evidence(evidence_id)
    if ev is None or ev.org_id != org_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return ev.model_dump(mode="json")


@router.post("/{evidence_id}/verify", response_model=Dict[str, Any])
async def verify_evidence(
    evidence_id: str,
    body: VerifyRequest,
    org_id: str = Depends(get_org_id),
):
    """Mark evidence as verified."""
    ev = _collector.get_evidence(evidence_id)
    if ev is None or ev.org_id != org_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    ok = _collector.verify_evidence(evidence_id, verifier=body.verifier)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to verify evidence")
    return {"id": evidence_id, "status": EvidenceStatus.VERIFIED.value, "verifier": body.verifier}


@router.post("/{evidence_id}/reject", response_model=Dict[str, Any])
async def reject_evidence(
    evidence_id: str,
    body: RejectRequest,
    org_id: str = Depends(get_org_id),
):
    """Reject evidence with a reason."""
    ev = _collector.get_evidence(evidence_id)
    if ev is None or ev.org_id != org_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    ok = _collector.reject_evidence(evidence_id, reason=body.reason)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to reject evidence")
    return {"id": evidence_id, "status": EvidenceStatus.REJECTED.value, "reason": body.reason}


@router.get("/frameworks/{framework}/controls", response_model=Dict[str, Any])
async def get_controls(framework: str):
    """Get control mappings for a compliance framework."""
    mappings = _collector.get_control_mappings(framework)
    if not mappings:
        raise HTTPException(status_code=404, detail=f"No controls found for framework: {framework}")
    return {
        "framework": framework,
        "controls": [m.model_dump() for m in mappings],
        "total": len(mappings),
    }


@router.get("/frameworks/{framework}/coverage", response_model=Dict[str, Any])
async def get_coverage(
    framework: str,
    org_id: str = Depends(get_org_id),
):
    """Get evidence coverage for a compliance framework."""
    return _collector.get_evidence_coverage(org_id=org_id, framework=framework)


@router.get("/frameworks/{framework}/gaps", response_model=Dict[str, Any])
async def get_gaps(
    framework: str,
    org_id: str = Depends(get_org_id),
):
    """Get evidence gaps (missing or incomplete coverage) for a framework."""
    gaps = _collector.get_evidence_gaps(org_id=org_id, framework=framework)
    return {
        "framework": framework,
        "gaps": gaps,
        "total_gaps": len(gaps),
    }


@router.post("/frameworks/{framework}/package", response_model=Dict[str, Any])
async def generate_package(
    framework: str,
    org_id: str = Depends(get_org_id),
):
    """Generate an auditor-ready evidence package for a framework."""
    mappings = _collector.get_control_mappings(framework)
    if not mappings:
        raise HTTPException(status_code=404, detail=f"No controls found for framework: {framework}")
    package = _collector.generate_evidence_package(org_id=org_id, framework=framework)
    return package.model_dump(mode="json")


@router.get("/stats", response_model=Dict[str, Any])
async def get_stats(org_id: str = Depends(get_org_id)):
    """Get aggregate evidence collection statistics for the org."""
    return _collector.get_collection_stats(org_id=org_id)
