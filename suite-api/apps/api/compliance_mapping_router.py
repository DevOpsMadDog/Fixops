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

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

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
    """List compliance controls with optional filters.

    When the caller asks for ``framework=mitre_d3fend`` (or omits the filter)
    AND the org has not registered any D3FEND controls, the response falls
    back to the imported MITRE D3FEND ontology projected as derived rows
    (real public-source data — CC-BY-4.0). Each derived row carries
    ``source="mitre-d3fend"`` and ``source_iri=<IRI>`` so the UI can badge
    it. Org-registered rows always take precedence.
    """
    return _get_engine().list_controls_with_d3fend_fallback(
        org_id, framework=framework, control_status=control_status
    )


_d3fend_importer = None


def _get_d3fend_importer(file_path: Optional[str] = None, url: Optional[str] = None):
    """Return a configured D3fendImporter. file_path overrides url."""
    from feeds.d3fend.importer import D3fendImporter
    global _d3fend_importer
    if file_path or url:
        return D3fendImporter(url=url or None, file_path=file_path or None)
    if _d3fend_importer is None:
        _d3fend_importer = D3fendImporter()
    return _d3fend_importer


class ImportD3fendRequest(BaseModel):
    file_path: Optional[str] = Field(
        default=None,
        description=(
            "Local D3FEND JSON-LD file path. Used in air-gapped or "
            "corp-firewalled environments where the live MITRE source is "
            "unreachable. Mutually exclusive with url."
        ),
    )
    url: Optional[str] = Field(
        default=None,
        description=(
            "Override the D3FEND ontology source URL. Defaults to the live "
            "MITRE export at d3fend.mitre.org."
        ),
    )
    idempotent: bool = Field(
        default=True,
        description="Skip techniques already present in DB (default true).",
    )


@router.post("/import-d3fend", dependencies=[Depends(api_key_auth)])
def import_d3fend(
    req: Optional[ImportD3fendRequest] = None,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Import the MITRE D3FEND defensive-technique ontology into the local
    side-DB (data/d3fend.db). Triggered by admins to populate the catalogue
    so subsequent ``GET /controls?framework=mitre_d3fend`` calls surface
    real D3FEND techniques (hundreds of rows) instead of the six top-level
    countermeasure-category stubs.

    Source resolution order:
      1. ``req.file_path`` (admin-uploaded JSON-LD doc — air-gapped use)
      2. ``req.url`` (caller-supplied HTTP source override)
      3. Default candidate URLs from feeds.d3fend.importer.D3FEND_DEFAULT_URLS
    """
    from feeds.d3fend.importer import D3fendSourceError

    payload = req or ImportD3fendRequest()
    try:
        importer = _get_d3fend_importer(
            file_path=payload.file_path, url=payload.url
        )
        result = importer.run(idempotent=payload.idempotent)
    except D3fendSourceError as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "source_unreachable",
                "reason": str(exc),
                "remediation": (
                    "Download the D3FEND JSON-LD ontology from "
                    "https://d3fend.mitre.org/resources/ and POST again "
                    "with file_path=/path/to/d3fend.json"
                ),
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid D3FEND JSON-LD: {exc}")
    except Exception as exc:  # noqa: BLE001
        _logger.exception("import_d3fend failed")
        raise HTTPException(status_code=500, detail=str(exc))

    return result


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
