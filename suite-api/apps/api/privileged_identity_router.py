"""Privileged Identity Management Router — ALDECI.

Manages PAM accounts, privileged sessions, and access certifications.

Prefix: /api/v1/privileged-identity
Auth: api_key_auth dependency on ALL endpoints

Routes:
  POST   /api/v1/privileged-identity/accounts                     register_account
  PUT    /api/v1/privileged-identity/accounts/{id}/risk            update_risk_level
  POST   /api/v1/privileged-identity/sessions                      open_session
  PUT    /api/v1/privileged-identity/sessions/{id}/close           close_session
  POST   /api/v1/privileged-identity/accounts/{id}/certify         certify_account
  PUT    /api/v1/privileged-identity/accounts/{id}/rotate          rotate_password
  GET    /api/v1/privileged-identity/summary                       get_privileged_summary
  GET    /api/v1/privileged-identity/high-risk                     get_high_risk_accounts
  GET    /api/v1/privileged-identity/sessions/active               get_active_sessions
  GET    /api/v1/privileged-identity/accounts/{id}/sessions        get_session_history
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/privileged-identity",
    tags=["Privileged Identity Management"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.privileged_identity_engine import PrivilegedIdentityEngine
        _engine = PrivilegedIdentityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class RegisterAccountBody(BaseModel):
    username: str = Field(..., description="Account username")
    account_type: str = Field(
        default="admin",
        description="service_account | admin | root | domain_admin | database_admin | application_account | shared",
    )
    system_name: str = Field(default="", description="Target system name")
    department: str = Field(default="", description="Owning department")
    owner: str = Field(default="", description="Account owner")
    mfa_enabled: bool = Field(default=False, description="MFA status")


class UpdateRiskBody(BaseModel):
    risk_level: str = Field(
        ..., description="critical | high | medium | low"
    )


class OpenSessionBody(BaseModel):
    account_id: str = Field(..., description="Privileged account ID")
    session_type: str = Field(
        default="ssh",
        description="ssh | rdp | database | api | console | jump_host",
    )
    target_system: str = Field(default="", description="Target system hostname/IP")


class CloseSessionBody(BaseModel):
    commands_executed: int = Field(default=0, description="Number of commands run")
    anomaly_score: float = Field(
        default=0.0, description="Anomaly score 0.0-10.0 (clamped)"
    )


class CertifyAccountBody(BaseModel):
    certified_by: str = Field(..., description="Certifier user ID")
    decision: str = Field(
        ..., description="approved | revoked | suspended"
    )
    justification: str = Field(default="", description="Certification justification")
    next_certification: str = Field(default="", description="Next certification date ISO")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/accounts", dependencies=[Depends(api_key_auth)])
def register_account(
    body: RegisterAccountBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Register a privileged account (deduped on org+username+system)."""
    try:
        return _get_engine().register_account(
            org_id=org_id,
            username=body.username,
            account_type=body.account_type,
            system_name=body.system_name,
            department=body.department,
            owner=body.owner,
            mfa_enabled=body.mfa_enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/accounts/{account_id}/risk", dependencies=[Depends(api_key_auth)])
def update_risk_level(
    account_id: str,
    body: UpdateRiskBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Override the risk level of a privileged account."""
    try:
        return _get_engine().update_risk_level(account_id, org_id, body.risk_level)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/sessions", dependencies=[Depends(api_key_auth)])
def open_session(
    body: OpenSessionBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Open a new privileged session."""
    try:
        return _get_engine().open_session(
            account_id=body.account_id,
            org_id=org_id,
            session_type=body.session_type,
            target_system=body.target_system,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/sessions/{session_id}/close", dependencies=[Depends(api_key_auth)])
def close_session(
    session_id: str,
    body: CloseSessionBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Close a privileged session and record metrics."""
    try:
        return _get_engine().close_session(
            session_id=session_id,
            org_id=org_id,
            commands_executed=body.commands_executed,
            anomaly_score=body.anomaly_score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/accounts/{account_id}/certify", dependencies=[Depends(api_key_auth)])
def certify_account(
    account_id: str,
    body: CertifyAccountBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Certify a privileged account (approved / revoked / suspended)."""
    try:
        return _get_engine().certify_account(
            account_id=account_id,
            org_id=org_id,
            certified_by=body.certified_by,
            decision=body.decision,
            justification=body.justification,
            next_certification=body.next_certification,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/accounts/{account_id}/rotate", dependencies=[Depends(api_key_auth)])
def rotate_password(
    account_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Record a password rotation for a privileged account."""
    try:
        return _get_engine().rotate_password(account_id, org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_privileged_summary(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return aggregate summary for privileged accounts."""
    return _get_engine().get_privileged_summary(org_id)


@router.get("/high-risk", dependencies=[Depends(api_key_auth)])
def get_high_risk_accounts(
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    """Return critical and high risk privileged accounts."""
    return _get_engine().get_high_risk_accounts(org_id)


@router.get("/sessions/active", dependencies=[Depends(api_key_auth)])
def get_active_sessions(
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    """Return active privileged sessions with account details."""
    return _get_engine().get_active_sessions(org_id)


@router.get("/accounts/{account_id}/sessions", dependencies=[Depends(api_key_auth)])
def get_session_history(
    account_id: str,
    org_id: str = Query(default="default"),
    limit: int = Query(default=20, ge=1, le=100),
) -> List[Dict[str, Any]]:
    """Return session history for a privileged account."""
    return _get_engine().get_session_history(account_id, org_id, limit=limit)
