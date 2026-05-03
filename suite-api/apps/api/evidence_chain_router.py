"""Evidence Chain API Router — ALDECI.

Endpoints (all under /api/v1/evidence-chain):

  Summary:
    GET  /                          — router summary + stats

  Cases:
    GET  /cases                     — list cases (filter: status)
    POST /cases                     — create a new case
    GET  /cases/{id}                — get a single case
    POST /cases/{id}/close          — close a case

  Evidence:
    GET  /cases/{id}/evidence       — list evidence for a case
    POST /cases/{id}/evidence       — add evidence to a case

  Chain of Custody:
    GET  /evidence/{id}/custody     — get full custody chain
    POST /evidence/{id}/custody     — record a custody transfer
    POST /evidence/{id}/seal        — seal evidence (immutable)
    GET  /evidence/{id}/verify      — verify integrity

  Export Coverage:
    POST /export-coverage           — verify export coverage against a filter
    GET  /verifications             — list past export-coverage verifications

  Stats:
    GET  /stats                     — evidence statistics
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.evidence_chain_engine import EvidenceChainEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/evidence-chain",
    tags=["evidence-chain"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = EvidenceChainEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CaseIn(BaseModel):
    case_number: str = ""
    case_title: str = ""
    case_type: str = "internal"
    investigator: str = ""
    created_at: Optional[str] = None


class CloseIn(BaseModel):
    closed_by: str = ""
    outcome: str = ""


class EvidenceIn(BaseModel):
    evidence_type: str = "file"
    filename: str = ""
    hash_md5: str = ""
    hash_sha256: str = ""
    size_bytes: int = 0
    collected_by: str = ""
    collection_method: str = ""
    storage_location: str = ""


class TransferIn(BaseModel):
    from_person: str = ""
    to_person: str = ""
    transfer_reason: str = ""
    location_change: str = ""


class SealIn(BaseModel):
    sealed_by: str = ""


class ExportCoverageIn(BaseModel):
    framework: Optional[str] = None
    severity_min: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    evidence_types: Optional[List[str]] = None
    case_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Summary (GET /)
# ---------------------------------------------------------------------------


@router.get("/")
def summary(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Router summary: stats snapshot for the evidence-chain domain."""
    try:
        stats = _get_engine().get_evidence_stats(org_id)
        return {
            "router": "evidence-chain",
            "prefix": "/api/v1/evidence-chain",
            "org_id": org_id,
            "stats": stats,
        }
    except Exception as exc:
        logger.exception("summary failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


@router.get("/cases")
def list_cases(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List all investigation cases for an org."""
    try:
        return _get_engine().list_cases(org_id, status=status)
    except Exception as exc:
        logger.exception("list_cases failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/cases", status_code=201)
def create_case(
    payload: CaseIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Create a new investigation case."""
    try:
        return _get_engine().create_case(org_id, payload.model_dump(exclude_none=True))
    except Exception as exc:
        logger.exception("create_case failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/cases/{case_id}")
def get_case(
    case_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get a single investigation case."""
    try:
        result = _get_engine()._get_case(org_id, case_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_case failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/cases/{case_id}/close")
def close_case(
    case_id: str,
    payload: CloseIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Close a case with outcome."""
    try:
        result = _get_engine().close_case(org_id, case_id, payload.closed_by, payload.outcome)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("close_case failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


@router.get("/cases/{case_id}/evidence")
def list_evidence(
    case_id: str,
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """List all evidence items for a case."""
    try:
        return _get_engine().list_evidence(org_id, case_id)
    except Exception as exc:
        logger.exception("list_evidence failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/cases/{case_id}/evidence", status_code=201)
def add_evidence(
    case_id: str,
    payload: EvidenceIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Add an evidence item to a case."""
    try:
        return _get_engine().add_evidence(org_id, case_id, payload.model_dump())
    except Exception as exc:
        logger.exception("add_evidence failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Chain of Custody
# ---------------------------------------------------------------------------


@router.get("/evidence/{evidence_id}/custody")
def get_custody_chain(
    evidence_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get the complete chain of custody for an evidence item."""
    try:
        result = _get_engine().get_custody_chain(org_id, evidence_id)
        if not result:
            raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_custody_chain failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/evidence/{evidence_id}/custody", status_code=201)
def transfer_custody(
    evidence_id: str,
    payload: TransferIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Record a custody transfer for an evidence item."""
    try:
        result = _get_engine().transfer_custody(org_id, evidence_id, payload.model_dump())
        if result is None:
            raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")
        return result
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("transfer_custody failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/evidence/{evidence_id}/seal")
def seal_evidence(
    evidence_id: str,
    payload: SealIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Seal evidence to prevent further custody transfers."""
    try:
        result = _get_engine().seal_evidence(org_id, evidence_id, payload.sealed_by)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("seal_evidence failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/evidence/{evidence_id}/verify")
def verify_integrity(
    evidence_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Verify hash consistency and chain integrity for an evidence item."""
    try:
        return _get_engine().verify_integrity(org_id, evidence_id)
    except Exception as exc:
        logger.exception("verify_integrity failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Export Coverage Verification
# ---------------------------------------------------------------------------


@router.post("/export-coverage", status_code=201)
def verify_export_coverage(
    payload: ExportCoverageIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Verify export coverage of evidence items against a compliance filter.

    Returns coverage_pct, gaps (evidence required by framework but excluded),
    and over_collection (evidence in export outside framework requirements).
    """
    try:
        return _get_engine().verify_export_coverage(
            org_id, payload.model_dump(exclude_none=True)
        )
    except Exception as exc:
        logger.exception("verify_export_coverage failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/verifications")
def list_verifications(
    org_id: str = Query("default"),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List past export-coverage verifications for an org (most recent first)."""
    try:
        return _get_engine().list_verifications(org_id, limit=limit)
    except Exception as exc:
        logger.exception("list_verifications failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return evidence statistics for an org."""
    try:
        return _get_engine().get_evidence_stats(org_id)
    except Exception as exc:
        logger.exception("get_evidence_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
