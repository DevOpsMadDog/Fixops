"""Export Coverage Verification API (GAP-040) — ALDECI.

Verifies that evidence exports (e.g., for NIST CSF, ISO 27001, SOC 2 audits)
cover all evidence required by compliance controls. Links audit-export events
to verification records for downstream audit trails.

Endpoints:
  POST /api/v1/export-coverage/verify         — verify export filter coverage
  GET  /api/v1/export-coverage/verifications  — list recent verifications
  POST /api/v1/export-coverage/audit-export   — record audit-export linkage
  GET  /api/v1/export-coverage/audit-history  — audit-export history

Protected via api_key_auth dependency.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.audit_management_engine import AuditManagementEngine
from core.evidence_chain_engine import EvidenceChainEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/export-coverage",
    tags=["export-coverage"],
    dependencies=[Depends(api_key_auth)],
)

# Lazy singletons
_evidence_engine: Optional[EvidenceChainEngine] = None
_audit_engine: Optional[AuditManagementEngine] = None


def _get_evidence_engine() -> EvidenceChainEngine:
    global _evidence_engine
    if _evidence_engine is None:
        _evidence_engine = EvidenceChainEngine()
    return _evidence_engine


def _get_audit_engine() -> AuditManagementEngine:
    global _audit_engine
    if _audit_engine is None:
        _audit_engine = AuditManagementEngine()
    return _audit_engine


# ---------------------------------------------------------------------------
# Pydantic bodies
# ---------------------------------------------------------------------------


class VerifyBody(BaseModel):
    export_filter: Dict[str, Any] = Field(default_factory=dict)


class AuditExportBody(BaseModel):
    framework: str
    export_filter: Dict[str, Any] = Field(default_factory=dict)
    verification_id: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/verify", status_code=201)
async def verify_export_coverage(
    body: VerifyBody,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Compute export-coverage metrics for a given filter and persist result."""
    try:
        return _get_evidence_engine().verify_export_coverage(org_id, body.export_filter)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/verifications")
async def list_verifications(
    org_id: str = Query("default", description="Organisation identifier"),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List recent export-coverage verifications for org."""
    return _get_evidence_engine().list_verifications(org_id, limit=limit)


@router.post("/audit-export", status_code=201)
async def record_audit_export(
    body: AuditExportBody,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Record that an audit export occurred, linked to a verification."""
    try:
        return _get_audit_engine().record_audit_export(
            org_id, body.framework, body.export_filter, body.verification_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/audit-history")
async def audit_export_history(
    org_id: str = Query("default", description="Organisation identifier"),
    framework: Optional[str] = Query(None, description="Filter by framework"),
) -> List[Dict[str, Any]]:
    """Return audit-export history for org, optionally filtered by framework."""
    return _get_audit_engine().audit_export_history(org_id, framework=framework)


__all__ = ["router"]
