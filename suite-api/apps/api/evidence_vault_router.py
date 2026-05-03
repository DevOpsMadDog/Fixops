"""Evidence Vault API Router — ALDECI.

Endpoints (all under /api/v1/evidence-vault):

  POST   /evidence                       — store new evidence
  PUT    /evidence/{id}/seal             — seal evidence (immutable)
  POST   /evidence/{id}/access           — log an access event
  POST   /collections                    — create evidence collection
  POST   /collections/{id}/add-evidence  — add evidence to collection
  GET    /evidence/{id}                  — get evidence detail + access log
  GET    /search                         — search evidence (query params)
  GET    /summary                        — vault summary stats
  POST   /evidence/{id}/verify           — verify content integrity
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from core.evidence_vault_engine import EvidenceVaultEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/evidence-vault",
    tags=["evidence-vault"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = EvidenceVaultEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class StoreEvidenceIn(BaseModel):
    org_id: str
    evidence_name: str
    evidence_type: str = "screenshot"
    framework: str = "SOC2"
    control_id: str = ""
    collected_by: str = ""
    collection_method: str = "manual"
    file_path: str = ""
    content: str = ""
    retention_years: int = 7


class AccessLogIn(BaseModel):
    org_id: str
    accessed_by: str
    access_type: str = "view"
    access_reason: str = ""


class CreateCollectionIn(BaseModel):
    org_id: str
    collection_name: str
    framework: str = "SOC2"
    audit_period: str = ""
    auditor: str = ""


class AddToCollectionIn(BaseModel):
    org_id: str
    evidence_id: str


class VerifyIn(BaseModel):
    org_id: str
    content: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/")
async def get_vault_root(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Root health + summary for the evidence vault."""
    summary = _get_engine().get_vault_summary(org_id)
    return {"status": "ok", "prefix": "/api/v1/evidence-vault", **summary}


@router.post("/evidence", status_code=201)
async def store_evidence(body: StoreEvidenceIn) -> Dict[str, Any]:
    """Store a new compliance evidence artifact."""
    ev = _get_engine().store_evidence(
        org_id=body.org_id,
        evidence_name=body.evidence_name,
        evidence_type=body.evidence_type,
        framework=body.framework,
        control_id=body.control_id,
        collected_by=body.collected_by,
        collection_method=body.collection_method,
        file_path=body.file_path,
        content=body.content,
        retention_years=body.retention_years,
    )
    return ev


@router.put("/evidence/{evidence_id}/seal")
async def seal_evidence(evidence_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Seal evidence making it immutable."""
    try:
        ev = _get_engine().seal_evidence(evidence_id, org_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if ev is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return ev


@router.post("/evidence/{evidence_id}/access", status_code=201)
async def log_access(evidence_id: str, body: AccessLogIn) -> Dict[str, Any]:
    """Log an access event for an evidence item."""
    return _get_engine().log_access(
        evidence_id=evidence_id,
        org_id=body.org_id,
        accessed_by=body.accessed_by,
        access_type=body.access_type,
        access_reason=body.access_reason,
    )


@router.post("/collections", status_code=201)
async def create_collection(body: CreateCollectionIn) -> Dict[str, Any]:
    """Create an evidence collection for an audit."""
    return _get_engine().create_collection(
        org_id=body.org_id,
        collection_name=body.collection_name,
        framework=body.framework,
        audit_period=body.audit_period,
        auditor=body.auditor,
    )


@router.post("/collections/{collection_id}/add-evidence")
async def add_to_collection(collection_id: str, body: AddToCollectionIn) -> Dict[str, Any]:
    """Add an evidence item to a collection."""
    try:
        coll = _get_engine().add_to_collection(collection_id, body.evidence_id, body.org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return coll


@router.get("/evidence/{evidence_id}")
async def get_evidence_detail(evidence_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return evidence details plus last 20 access log entries."""
    ev = _get_engine().get_evidence_detail(evidence_id, org_id)
    if ev is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return ev


@router.get("/search")
async def search_evidence(
     org_id: str = Query(default="default"),
    framework: Optional[str] = Query(None),
    control_id: Optional[str] = Query(None),
    evidence_type: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Search evidence with optional filters."""
    items = _get_engine().search_evidence(
        org_id=org_id,
        framework=framework,
        control_id=control_id,
        evidence_type=evidence_type,
    )
    return {"items": items, "total": len(items)}


@router.get("/summary")
async def get_vault_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return vault statistics."""
    return _get_engine().get_vault_summary(org_id)


@router.post("/evidence/{evidence_id}/verify")
async def verify_integrity(evidence_id: str, body: VerifyIn) -> Dict[str, Any]:
    """Verify content integrity against stored SHA-256 hash."""
    return _get_engine().verify_integrity(evidence_id, body.org_id, body.content)
