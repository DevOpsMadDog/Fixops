"""Privileged Access Management (PAM) Router — ALDECI.

Endpoints:
  GET  /api/v1/pam/accounts              — list privileged accounts
  POST /api/v1/pam/accounts              — register a privileged account
  GET  /api/v1/pam/sessions              — list PAM sessions
  POST /api/v1/pam/sessions              — create a session request
  POST /api/v1/pam/sessions/{id}/approve — approve or deny a session
  POST /api/v1/pam/sessions/{id}/end     — end an active session
  GET  /api/v1/pam/policies              — list PAM policies
  POST /api/v1/pam/policies              — create a PAM policy
  GET  /api/v1/pam/stats                 — PAM summary statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.pam_engine import PAMEngine
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/pam", tags=["pam"])

# Module-level singleton
_engine = None  # lazy-initialised on first request


def _get_engine() -> PAMEngine:
    global _engine
    if _engine is None:
        _engine = PAMEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterAccountRequest(BaseModel):
    username: str
    account_type: str = Field(
        default="admin",
        description="One of: service, admin, root, sa, shared, emergency",
    )
    system: str = ""
    department: str = ""
    owner: str = ""
    is_vaulted: bool = False
    rotation_days: int = 90
    last_rotated: Optional[str] = None
    risk_score: int = Field(default=50, ge=0, le=100)
    status: str = "active"


class CreateSessionRequest(BaseModel):
    account_id: str
    requester: str = ""
    justification: str = ""
    session_type: str = Field(
        default="interactive",
        description="One of: interactive, api, scheduled",
    )
    target_system: str = ""
    requested_duration_minutes: int = Field(default=60, ge=1, le=1440)
    started_at: Optional[str] = None
    recording_enabled: bool = True


class ApproveSessionRequest(BaseModel):
    approver: str
    approved: bool


class CreatePolicyRequest(BaseModel):
    name: str
    require_approval: bool = True
    max_session_minutes: int = Field(default=60, ge=1, le=1440)
    allowed_hours: List[Any] = Field(default_factory=list)
    mfa_required: bool = True
    recording_required: bool = True


# ---------------------------------------------------------------------------
# Account endpoints
# ---------------------------------------------------------------------------


@router.get("/accounts", response_model=List[Dict[str, Any]])
async def list_accounts(
    account_type: Optional[str] = Query(None, description="Filter by account type"),
    account_status: Optional[str] = Query(None, alias="status", description="Filter by status"),
    org_id: str = Depends(get_org_id),
    engine: PAMEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List privileged accounts for the current org."""
    return engine.list_accounts(org_id, account_type=account_type, status=account_status)


@router.post("/accounts", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def register_account(
    payload: RegisterAccountRequest,
    org_id: str = Depends(get_org_id),
    engine: PAMEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Register a privileged account in the PAM vault."""
    return engine.register_account(org_id, payload.model_dump())


# ---------------------------------------------------------------------------
# Session endpoints
# ---------------------------------------------------------------------------


@router.get("/sessions", response_model=List[Dict[str, Any]])
async def list_sessions(
    approval_status: Optional[str] = Query(None, description="Filter by approval status"),
    org_id: str = Depends(get_org_id),
    engine: PAMEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List PAM sessions for the current org."""
    return engine.list_sessions(org_id, approval_status=approval_status)


@router.post("/sessions", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_session(
    payload: CreateSessionRequest,
    org_id: str = Depends(get_org_id),
    engine: PAMEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Create a PAM session request (requires approval unless policy allows)."""
    return engine.create_session(org_id, payload.model_dump())


@router.post("/sessions/{session_id}/approve", response_model=Dict[str, Any])
async def approve_session(
    session_id: str,
    payload: ApproveSessionRequest,
    org_id: str = Depends(get_org_id),
    engine: PAMEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Approve or deny a pending PAM session."""
    updated = engine.approve_session(
        org_id, session_id, payload.approver, payload.approved
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found or not in pending state",
        )
    return {
        "session_id": session_id,
        "approved": payload.approved,
        "approver": payload.approver,
        "status": "approved" if payload.approved else "denied",
    }


@router.post("/sessions/{session_id}/end", response_model=Dict[str, Any])
async def end_session(
    session_id: str,
    org_id: str = Depends(get_org_id),
    engine: PAMEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """End an active PAM session."""
    updated = engine.end_session(org_id, session_id)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found or already ended",
        )
    return {"session_id": session_id, "status": "ended"}


# ---------------------------------------------------------------------------
# Policy endpoints
# ---------------------------------------------------------------------------


@router.get("/policies", response_model=List[Dict[str, Any]])
async def list_policies(
    org_id: str = Depends(get_org_id),
    engine: PAMEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List PAM policies for the current org."""
    return engine.list_policies(org_id)


@router.post("/policies", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: CreatePolicyRequest,
    org_id: str = Depends(get_org_id),
    engine: PAMEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Create a new PAM policy."""
    return engine.create_policy(org_id, payload.model_dump())


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=Dict[str, Any])
async def get_stats(
    org_id: str = Depends(get_org_id),
    engine: PAMEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Return PAM summary statistics for the current org."""
    return engine.get_pam_stats(org_id)


__all__ = ["router"]
