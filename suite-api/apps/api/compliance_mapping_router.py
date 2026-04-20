"""Compliance Mapping Router — ALDECI.

Cross-framework control mapping: NIST CSF, ISO 27001, PCI-DSS, SOC 2, HIPAA,
GDPR, CIS Controls, NIST 800-53.

Prefix: /api/v1/compliance-mapping
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/compliance-mapping/controls                     add_control
  GET    /api/v1/compliance-mapping/controls                     list_controls
  GET    /api/v1/compliance-mapping/controls/{id}                get_control
  PATCH  /api/v1/compliance-mapping/controls/{id}/status        update_control_status
  POST   /api/v1/compliance-mapping/mappings                     add_mapping
  GET    /api/v1/compliance-mapping/mappings                     list_mappings
  POST   /api/v1/compliance-mapping/controls/{id}/evidence       add_evidence
  GET    /api/v1/compliance-mapping/evidence                     list_evidence
  GET    /api/v1/compliance-mapping/stats                        get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/compliance-mapping",
    tags=["Compliance Mapping"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.compliance_mapping_engine import ComplianceMappingEngine
        _engine = ComplianceMappingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AddControlRequest(BaseModel):
    control_id: str = Field(..., description="Control identifier (e.g. CC6.1, AC-2)")
    framework: str = Field(
        default="nist_csf",
        description=(
            "nist_csf | iso27001 | pci_dss | soc2 | hipaa | "
            "gdpr | cis_controls | nist_800_53"
        ),
    )
    control_name: str = Field(..., description="Short control name")
    description: Optional[str] = Field(default=None)
    control_status: str = Field(
        default="not_implemented",
        description="implemented | partial | not_implemented | not_applicable",
    )
    implementation_notes: Optional[str] = Field(default=None)
    owner: Optional[str] = Field(default=None)
    last_reviewed: Optional[str] = Field(default=None)


class UpdateControlStatusRequest(BaseModel):
    new_status: str = Field(
        ...,
        description="implemented | partial | not_implemented | not_applicable",
    )
    notes: Optional[str] = Field(default=None, description="Implementation notes")


class AddMappingRequest(BaseModel):
    source_control_id: str = Field(..., description="Source control identifier")
    target_control_id: str = Field(..., description="Target control identifier")
    source_framework: str = Field(..., description="Source framework key")
    target_framework: str = Field(..., description="Target framework key")
    mapping_strength: str = Field(
        ..., description="strong | moderate | weak"
    )
    notes: Optional[str] = Field(default=None)


class AddEvidenceRequest(BaseModel):
    evidence_type: str = Field(..., description="Type of evidence (e.g. policy, screenshot)")
    description: str = Field(..., description="Evidence description")
    file_reference: Optional[str] = Field(default=None)
    collected_at: Optional[str] = Field(default=None)
    expires_at: Optional[str] = Field(default=None)
    collector: Optional[str] = Field(default=None)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/controls", dependencies=[Depends(api_key_auth)])
def add_control(
    req: AddControlRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Add a compliance control."""
    try:
        return _get_engine().add_control(
            org_id,
            {
                "control_id": req.control_id,
                "framework": req.framework,
                "control_name": req.control_name,
                "description": req.description or "",
                "control_status": req.control_status,
                "implementation_notes": req.implementation_notes or "",
                "owner": req.owner or "",
                "last_reviewed": req.last_reviewed,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/controls", dependencies=[Depends(api_key_auth)])
def list_controls(
    org_id: str = Query(..., description="Organization ID"),
    framework: Optional[str] = Query(default=None),
    control_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List compliance controls with optional filters."""
    return _get_engine().list_controls(
        org_id, framework=framework, control_status=control_status
    )


@router.get("/controls/{control_id}", dependencies=[Depends(api_key_auth)])
def get_control(
    control_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single control by its primary-key ID."""
    record = _get_engine().get_control(org_id, control_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found")
    return record


@router.patch("/controls/{control_id}/status", dependencies=[Depends(api_key_auth)])
def update_control_status(
    control_id: str,
    req: UpdateControlStatusRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update control implementation status."""
    try:
        return _get_engine().update_control_status(
            org_id, control_id, req.new_status, notes=req.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/mappings", dependencies=[Depends(api_key_auth)])
def add_mapping(
    req: AddMappingRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Add a cross-framework control mapping."""
    try:
        return _get_engine().add_mapping(
            org_id,
            {
                "source_control_id": req.source_control_id,
                "target_control_id": req.target_control_id,
                "source_framework": req.source_framework,
                "target_framework": req.target_framework,
                "mapping_strength": req.mapping_strength,
                "notes": req.notes or "",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/mappings", dependencies=[Depends(api_key_auth)])
def list_mappings(
    org_id: str = Query(..., description="Organization ID"),
    source_framework: Optional[str] = Query(default=None),
    target_framework: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List control mappings with optional framework filters."""
    return _get_engine().list_mappings(
        org_id,
        source_framework=source_framework,
        target_framework=target_framework,
    )


@router.post("/controls/{control_id}/evidence", dependencies=[Depends(api_key_auth)])
def add_evidence(
    control_id: str,
    req: AddEvidenceRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Add evidence for a compliance control."""
    try:
        return _get_engine().add_evidence(
            org_id,
            control_id,
            {
                "evidence_type": req.evidence_type,
                "description": req.description,
                "file_reference": req.file_reference or "",
                "collected_at": req.collected_at,
                "expires_at": req.expires_at,
                "collector": req.collector or "",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/evidence", dependencies=[Depends(api_key_auth)])
def list_evidence(
    org_id: str = Query(..., description="Organization ID"),
    control_id: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List evidence records; optionally filter by control ID."""
    return _get_engine().list_evidence(org_id, control_id_param=control_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregate compliance mapping statistics."""
    return _get_engine().get_mapping_stats(org_id)


@router.get("/controls/{control_id}/context", dependencies=[Depends(api_key_auth)])
def get_control_context(
    control_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return TrustGraph cross-domain context for a control (related findings, assets, evidence)."""
    return _get_engine().get_control_context(org_id, control_id)


@router.get("", dependencies=[Depends(api_key_auth)])
def get_root(org_id: str = Query(default="default")):
    """Root endpoint — returns controls list for dashboard health-checks."""
    return _get_engine().list_controls(org_id)
