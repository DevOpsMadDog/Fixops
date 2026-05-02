"""Audit Management API endpoints — ALDECI.

Manages audit lifecycle: planning, execution, findings, resolution.

Endpoints:
  POST /api/v1/audit-management/audits                        — create audit
  GET  /api/v1/audit-management/audits                        — list audits
  GET  /api/v1/audit-management/audits/{audit_id}             — get audit
  PUT  /api/v1/audit-management/audits/{audit_id}/start       — start audit
  POST /api/v1/audit-management/audits/{audit_id}/findings    — record finding
  PUT  /api/v1/audit-management/findings/{finding_id}/resolve — resolve finding
  PUT  /api/v1/audit-management/audits/{audit_id}/complete    — complete audit
  GET  /api/v1/audit-management/stats                         — audit stats

Protected via api_key_auth dependency.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.audit_management_engine import (
    AuditComplete,
    AuditCreate,
    AuditManagementEngine,
    FindingCreate,
    FindingResolve,
)
from fastapi import APIRouter, Depends, HTTPException, Query

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/audit-management",
    tags=["audit-management"],
    dependencies=[Depends(api_key_auth)],
)

# Lazy singleton
_engine: Optional[AuditManagementEngine] = None


def _get_engine() -> AuditManagementEngine:
    global _engine
    if _engine is None:
        _engine = AuditManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Audit endpoints
# ---------------------------------------------------------------------------


@router.post("/audits", status_code=201)
async def create_audit(
    body: AuditCreate,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Create a new audit in planned status."""
    try:
        return _get_engine().create_audit(org_id, body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/audits")
async def list_audits(
    org_id: str = Query("default", description="Organisation identifier"),
    audit_type: Optional[str] = Query(None, description="Filter by audit type"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> List[Dict[str, Any]]:
    """List audits for the org, optionally filtered."""
    return _get_engine().list_audits(org_id, audit_type=audit_type, status=status)


@router.get("/audits/{audit_id}")
async def get_audit(
    audit_id: str,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Get a single audit by ID."""
    try:
        return _get_engine().get_audit(org_id, audit_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/audits/{audit_id}/start")
async def start_audit(
    audit_id: str,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Transition audit to in_progress status."""
    try:
        return _get_engine().start_audit(org_id, audit_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/audits/{audit_id}/complete")
async def complete_audit(
    audit_id: str,
    body: AuditComplete,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Mark audit as completed with a summary."""
    try:
        return _get_engine().complete_audit(org_id, audit_id, body.summary)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Finding endpoints
# ---------------------------------------------------------------------------


@router.post("/audits/{audit_id}/findings", status_code=201)
async def record_finding(
    audit_id: str,
    body: FindingCreate,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Record a new finding against an audit."""
    try:
        return _get_engine().record_finding(org_id, audit_id, body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.put("/findings/{finding_id}/resolve")
async def resolve_finding(
    finding_id: str,
    body: FindingResolve,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Resolve a finding with resolution text."""
    try:
        return _get_engine().resolve_finding(
            org_id, finding_id, body.resolution, body.resolved_by
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_audit_stats(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return audit statistics for the org."""
    return _get_engine().get_audit_stats(org_id)


__all__ = ["router"]
