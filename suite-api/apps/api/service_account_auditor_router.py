"""
Service Account Auditor API — ALDECI.

Endpoints:
  POST   /api/v1/service-account-auditor/accounts              register_service_account
  GET    /api/v1/service-account-auditor/accounts              list_service_accounts
  POST   /api/v1/service-account-auditor/accounts/{id}/audit   run_audit
  GET    /api/v1/service-account-auditor/accounts/unused        get_unused_accounts
  GET    /api/v1/service-account-auditor/accounts/overprivileged get_overprivileged_accounts
  POST   /api/v1/service-account-auditor/accounts/{id}/rotate  rotate_credentials
  GET    /api/v1/service-account-auditor/accounts/{id}/rotation-history list_rotation_history
  GET    /api/v1/service-account-auditor/stats                  get_audit_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "service_account_auditor_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.service_account_auditor_engine import (
    ServiceAccountAuditorEngine,
    get_service_account_auditor,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/service-account-auditor",
    tags=["service-account-auditor"],
    dependencies=_AUTH_DEP,
)

_engine_singleton: Optional[ServiceAccountAuditorEngine] = None


def _engine() -> ServiceAccountAuditorEngine:
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = get_service_account_auditor()
    return _engine_singleton


# ============================================================================
# Request / Response models
# ============================================================================


class RegisterAccountRequest(BaseModel):
    org_id: str = Field(..., description="Organization identifier")
    name: str = Field(..., description="Service account name or identifier")
    system: str = Field(..., description="Platform: k8s, aws, gcp, azure, linux")
    permissions: List[str] = Field(default_factory=list, description="List of permissions/roles")
    last_used_days_ago: int = Field(0, ge=0, description="Days since last use")


class RunAuditRequest(BaseModel):
    org_id: str = Field(..., description="Organization identifier")


class RotateRequest(BaseModel):
    org_id: str = Field(..., description="Organization identifier")


# ============================================================================
# Endpoints
# ============================================================================


@router.get("/", summary="Service account auditor summary")
def get_auditor_summary(
    org_id: str = Query(..., description="Organization identifier"),
) -> Dict[str, Any]:
    """Return service account audit stats: total accounts, unused, overprivileged, risk breakdown."""
    try:
        return _engine().get_audit_stats(org_id)
    except Exception as exc:
        logger.exception("service_account_auditor GET / failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/accounts", summary="Register a service account for auditing")
def register_account(req: RegisterAccountRequest) -> Dict[str, Any]:
    """Register a new service account and compute its initial risk score."""
    try:
        return _engine().register_service_account(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("register_account failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/accounts", summary="List service accounts for an org")
def list_accounts(
    org_id: str = Query(..., description="Organization identifier"),
    system: Optional[str] = Query(None, description="Filter by system (k8s/aws/gcp/azure/linux)"),
) -> List[Dict[str, Any]]:
    """List all service accounts, optionally filtered by system."""
    try:
        return _engine().list_service_accounts(org_id, system=system)
    except Exception as exc:
        logger.exception("list_accounts failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/accounts/unused", summary="Get unused service accounts")
def get_unused(
    org_id: str = Query(..., description="Organization identifier"),
    days_threshold: int = Query(90, ge=1, description="Days of inactivity threshold"),
) -> List[Dict[str, Any]]:
    """Return service accounts not used in the last N days."""
    try:
        return _engine().get_unused_accounts(org_id, days_threshold=days_threshold)
    except Exception as exc:
        logger.exception("get_unused failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/accounts/overprivileged", summary="Get overprivileged service accounts")
def get_overprivileged(
    org_id: str = Query(..., description="Organization identifier"),
) -> List[Dict[str, Any]]:
    """Return service accounts with risk_score > 70."""
    try:
        return _engine().get_overprivileged_accounts(org_id)
    except Exception as exc:
        logger.exception("get_overprivileged failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/accounts/{account_id}/audit", summary="Run a security audit on a service account")
def run_audit(account_id: str, req: RunAuditRequest) -> Dict[str, Any]:
    """Audit a specific service account and return findings with risk score."""
    try:
        return _engine().run_audit(req.org_id, account_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("run_audit failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/accounts/{account_id}/rotate", summary="Record a credential rotation event")
def rotate_credentials(account_id: str, req: RotateRequest) -> Dict[str, Any]:
    """Record that credentials for a service account were rotated."""
    try:
        return _engine().rotate_credentials(req.org_id, account_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("rotate_credentials failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/accounts/{account_id}/rotation-history", summary="Get credential rotation history")
def rotation_history(
    account_id: str,
    org_id: str = Query(..., description="Organization identifier"),
) -> List[Dict[str, Any]]:
    """Return all credential rotation events for a service account."""
    try:
        return _engine().list_rotation_history(org_id, account_id)
    except Exception as exc:
        logger.exception("rotation_history failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", summary="Get service account audit statistics")
def get_stats(
    org_id: str = Query(..., description="Organization identifier"),
) -> Dict[str, Any]:
    """Return aggregate stats: total accounts, high-risk count, overdue rotations."""
    try:
        return _engine().get_audit_stats(org_id)
    except Exception as exc:
        logger.exception("get_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
