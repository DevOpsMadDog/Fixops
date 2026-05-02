"""Security Exception Router — ALDECI.

Exposes CRUD for security exceptions, reviews, assets, expiry checks, and stats.
Prefix: /api/v1/security-exceptions
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-exceptions",
    tags=["Security Exception Manager"],
)

# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_exception_engine import SecurityExceptionEngine
        _engine = SecurityExceptionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ExceptionRequest(BaseModel):
    title: str
    description: str = ""
    exception_type: str = "vulnerability"
    risk_level: str = "medium"
    requestor: str = ""
    approver: str = ""
    business_justification: str = ""
    compensating_controls: str = ""
    expires_at: Optional[str] = None


class ExceptionReview(BaseModel):
    action: str  # approve / reject / request_info / extend
    reviewer: str
    notes: str = ""
    new_expiry: Optional[str] = None


class AssetAdd(BaseModel):
    asset_name: str
    asset_type: str = ""


class RevokeRequest(BaseModel):
    revoker: str
    reason: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/{org_id}", summary="Request a security exception")
def request_exception(org_id: str, body: ExceptionRequest, _=Depends(api_key_auth)):
    engine = _get_engine()
    try:
        return engine.request_exception(org_id, body.model_dump())
    except Exception as exc:
        _logger.exception("request_exception failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{org_id}", summary="List security exceptions")
def list_exceptions(
    org_id: str,
    status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    _=Depends(api_key_auth),
):
    engine = _get_engine()
    return engine.list_exceptions(org_id, status=status, risk_level=risk_level)


@router.get("/{org_id}/expiring", summary="List exceptions expiring soon")
def check_expiring(
    org_id: str,
    days_ahead: int = Query(default=7, ge=1, le=90),
    _=Depends(api_key_auth),
):
    engine = _get_engine()
    return engine.check_expiring(org_id, days_ahead=days_ahead)


@router.get("/{org_id}/stats", summary="Get exception stats")
def get_exception_stats(org_id: str, _=Depends(api_key_auth)):
    engine = _get_engine()
    return engine.get_exception_stats(org_id)


@router.get("/{org_id}/{exception_id}", summary="Get a security exception")
def get_exception(org_id: str, exception_id: str, _=Depends(api_key_auth)):
    engine = _get_engine()
    result = engine.get_exception(org_id, exception_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Exception not found")
    return result


@router.post("/{org_id}/{exception_id}/review", summary="Review an exception")
def review_exception(org_id: str, exception_id: str, body: ExceptionReview, _=Depends(api_key_auth)):
    engine = _get_engine()
    try:
        return engine.review_exception(
            org_id, exception_id,
            action=body.action,
            reviewer=body.reviewer,
            notes=body.notes,
            new_expiry=body.new_expiry,
        )
    except Exception as exc:
        _logger.exception("review_exception failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/{org_id}/{exception_id}/assets", summary="Add asset to exception")
def add_asset(org_id: str, exception_id: str, body: AssetAdd, _=Depends(api_key_auth)):
    engine = _get_engine()
    try:
        return engine.add_asset(org_id, exception_id, body.model_dump())
    except Exception as exc:
        _logger.exception("add_asset failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{org_id}/{exception_id}/assets", summary="List assets for exception")
def list_assets(org_id: str, exception_id: str, _=Depends(api_key_auth)):
    engine = _get_engine()
    return engine.list_assets(org_id, exception_id)


@router.post("/{org_id}/{exception_id}/revoke", summary="Revoke an exception")
def revoke_exception(org_id: str, exception_id: str, body: RevokeRequest, _=Depends(api_key_auth)):
    engine = _get_engine()
    ok = engine.revoke_exception(org_id, exception_id, revoker=body.revoker, reason=body.reason)
    if not ok:
        raise HTTPException(status_code=404, detail="Exception not found")
    return {"revoked": True}
