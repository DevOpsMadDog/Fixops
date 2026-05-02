"""Vulnerability Exception Router — ALDECI.

Prefix: /api/v1/vuln-exceptions
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/vuln-exceptions/exceptions                          create_exception
  GET    /api/v1/vuln-exceptions/exceptions                          list_exceptions
  GET    /api/v1/vuln-exceptions/exceptions/{exception_id}           get_exception
  POST   /api/v1/vuln-exceptions/exceptions/{exception_id}/approve   approve_exception
  POST   /api/v1/vuln-exceptions/exceptions/{exception_id}/reject    reject_exception
  POST   /api/v1/vuln-exceptions/exceptions/expire                   expire_exceptions
  GET    /api/v1/vuln-exceptions/stats                               get_exception_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vuln-exceptions",
    tags=["Vulnerability Exceptions"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.vuln_exception_engine import VulnExceptionEngine
        _engine = VulnExceptionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ExceptionCreate(BaseModel):
    cve_id: str
    asset_id: str
    reason: str
    exception_type: str
    requested_by: str = ""
    expiry_date: Optional[str] = None


class ApproveRequest(BaseModel):
    approved_by: str
    notes: str = ""


class RejectRequest(BaseModel):
    rejected_by: str
    reason: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", dependencies=[Depends(api_key_auth)], summary="Vulnerability exceptions — service summary")
def get_service_summary(org_id: str = Query(default="default")):
    """Return service status and exception statistics for the vuln exceptions domain."""
    try:
        stats = _get_engine().get_exception_stats(org_id)
    except Exception as exc:
        _logger.warning("get_exception_stats failed in summary: %s", exc)
        stats = {}
    return {
        "service": "vuln-exceptions",
        "status": "ok",
        "org_id": org_id,
        "stats": stats,
        "endpoints": [
            "POST /api/v1/vuln-exceptions/exceptions",
            "GET  /api/v1/vuln-exceptions/exceptions",
            "GET  /api/v1/vuln-exceptions/exceptions/{exception_id}",
            "POST /api/v1/vuln-exceptions/exceptions/{exception_id}/approve",
            "POST /api/v1/vuln-exceptions/exceptions/{exception_id}/reject",
            "POST /api/v1/vuln-exceptions/exceptions/expire",
            "GET  /api/v1/vuln-exceptions/stats",
        ],
    }


@router.post("/exceptions", dependencies=[Depends(api_key_auth)], status_code=201)
def create_exception(body: ExceptionCreate, org_id: str = Query(default="default")):
    """Create a new vulnerability exception request."""
    try:
        return _get_engine().create_exception(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/exceptions", dependencies=[Depends(api_key_auth)])
def list_exceptions(
     org_id: str = Query(default="default"),
    exception_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List exceptions for the org with optional filters."""
    return _get_engine().list_exceptions(
        org_id,
        exception_type=exception_type,
        status=status,
    )


@router.post("/exceptions/expire", dependencies=[Depends(api_key_auth)])
def expire_exceptions(org_id: str = Query(default="default")):
    """Expire approved exceptions whose expiry_date has passed."""
    return _get_engine().expire_exceptions(org_id)


@router.get("/exceptions/{exception_id}", dependencies=[Depends(api_key_auth)])
def get_exception(exception_id: str, org_id: str = Query(default="default")):
    """Retrieve a single exception by ID."""
    result = _get_engine().get_exception(org_id, exception_id)
    if not result:
        raise HTTPException(status_code=404, detail="Exception not found")
    return result


@router.post("/exceptions/{exception_id}/approve", dependencies=[Depends(api_key_auth)])
def approve_exception(
    exception_id: str, body: ApproveRequest, org_id: str = Query(default="default")
):
    """Approve a pending exception."""
    try:
        return _get_engine().approve_exception(
            org_id, exception_id, body.approved_by, notes=body.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/exceptions/{exception_id}/reject", dependencies=[Depends(api_key_auth)])
def reject_exception(
    exception_id: str, body: RejectRequest, org_id: str = Query(default="default")
):
    """Reject a pending exception."""
    try:
        return _get_engine().reject_exception(
            org_id, exception_id, body.rejected_by, body.reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_exception_stats(org_id: str = Query(default="default")):
    """Return aggregated exception statistics for the org."""
    return _get_engine().get_exception_stats(org_id)
