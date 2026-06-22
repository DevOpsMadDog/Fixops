"""
Cloud Native Security Router — ALDECI.

Prefix: /api/v1/cloud-native
Auth:   Depends(api_key_auth)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.cloud_native_security_engine import get_engine
from fastapi import APIRouter, Depends, HTTPException, Query
from apps.api.dependencies import get_org_id  # SPEC-034
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

# SECURITY 2026-06-03: the module-level api_key_auth() below is a placeholder that returns
# True (no enforcement). Enforce the REAL request-based api_key_auth at the router level so
# every endpoint requires X-API-Key (401 without) — was returning 200 unauthenticated.
try:
    from apps.api.auth_deps import api_key_auth as _real_api_key_auth
    _AUTH_DEP = [Depends(_real_api_key_auth)]
except Exception:  # pragma: no cover
    def _api_key_auth_failclosed():
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="auth dependency unavailable")
    _AUTH_DEP = [Depends(_api_key_auth_failclosed)]

router = APIRouter(prefix="/api/v1/cloud-native", tags=["cloud-native"], dependencies=_AUTH_DEP)


# ---------------------------------------------------------------------------
# Auth dependency — matches pattern used across ALDECI routers
# ---------------------------------------------------------------------------

def api_key_auth():
    """Placeholder auth — real enforcement is at the gateway layer."""
    return True


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterAccountRequest(BaseModel):
    provider: str = "aws"
    account_id: str = ""
    account_name: str = ""
    region: str = "us-east-1"
    environment: str = "prod"


class RecordMisconfigRequest(BaseModel):
    account_id: str
    provider: str = "aws"
    service: str = "s3"
    check_name: str = ""
    severity: str = "medium"
    resource_id: str = ""
    resource_name: str = ""
    description: str = ""
    remediation: str = ""
    compliant: bool = False


class MarkCompliantRequest(BaseModel):
    fixed_by: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/accounts")
def list_accounts(
    org_id: str = Depends(get_org_id),
    provider: Optional[str] = Query(None),
    _auth: bool = Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List cloud accounts for an org."""
    try:
        return get_engine().list_accounts(org_id=org_id, provider=provider)
    except Exception as exc:
        _logger.exception("list_accounts failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/accounts", status_code=201)
def register_account(
    org_id: str = Depends(get_org_id),
    body: RegisterAccountRequest = ...,
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Register a new cloud account."""
    try:
        return get_engine().register_cloud_account(org_id=org_id, data=body.model_dump())
    except Exception as exc:
        _logger.exception("register_cloud_account failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/misconfigurations")
def list_misconfigurations(
    org_id: str = Depends(get_org_id),
    provider: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    include_compliant: bool = Query(False, description="Include already-compliant findings"),
    _auth: bool = Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List misconfigurations with optional filters."""
    try:
        return get_engine().list_misconfigurations(
            org_id=org_id,
            provider=provider,
            service=service,
            severity=severity,
            compliant=include_compliant,
        )
    except Exception as exc:
        _logger.exception("list_misconfigurations failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/misconfigurations", status_code=201)
def record_misconfiguration(
    org_id: str = Depends(get_org_id),
    body: RecordMisconfigRequest = ...,
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Record a cloud misconfiguration finding."""
    try:
        return get_engine().record_misconfiguration(org_id=org_id, data=body.model_dump())
    except Exception as exc:
        _logger.exception("record_misconfiguration failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/misconfigurations/{finding_id}/mark-compliant")
def mark_compliant(
    finding_id: str,
    org_id: str = Depends(get_org_id),
    body: MarkCompliantRequest = ...,
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Mark a misconfiguration as remediated."""
    try:
        return get_engine().mark_compliant(
            org_id=org_id,
            finding_id=finding_id,
            fixed_by=body.fixed_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("mark_compliant failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/accounts/{account_id}/posture-check")
def run_posture_check(
    account_id: str,
    org_id: str = Depends(get_org_id),
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Run a cloud posture check against an account."""
    try:
        return get_engine().run_posture_check(org_id=org_id, account_id=account_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("run_posture_check failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats")
def get_stats(
    org_id: str = Depends(get_org_id),
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get aggregate cloud security stats for an org."""
    try:
        return get_engine().get_cloud_stats(org_id=org_id)
    except Exception as exc:
        _logger.exception("get_cloud_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
