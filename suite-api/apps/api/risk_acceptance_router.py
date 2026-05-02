"""
Risk Acceptance API Router.

Endpoints:
  POST   /api/v1/risk-acceptance/request      — submit a new risk acceptance request
  GET    /api/v1/risk-acceptance              — list acceptances (org-scoped)
  GET    /api/v1/risk-acceptance/pending      — acceptances awaiting approval
  GET    /api/v1/risk-acceptance/expiring     — acceptances expiring soon
  GET    /api/v1/risk-acceptance/stats        — org statistics
  POST   /api/v1/risk-acceptance/expire       — expire overdue acceptances
  GET    /api/v1/risk-acceptance/{id}         — get a single acceptance
  POST   /api/v1/risk-acceptance/{id}/approve — approve
  POST   /api/v1/risk-acceptance/{id}/reject  — reject
  POST   /api/v1/risk-acceptance/{id}/revoke  — revoke
  GET    /api/v1/risk-acceptance/{id}/history — review history

Auth: protected via get_org_id (API-key backed) on every endpoint.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.risk_acceptance import (
    AcceptanceReview,
    AcceptanceStatus,
    ReviewPriority,
    RiskAcceptance,
    RiskAcceptanceManager,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/risk-acceptance", tags=["risk-acceptance"])

# Module-level singleton (in-memory for tests; override db_path in production)
_manager = None  # lazy-initialised on first request


def _get_manager() -> RiskAcceptanceManager:
    global _manager
    if _manager is None:
        _manager = RiskAcceptanceManager()
    return _manager


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class RiskAcceptanceRequest(BaseModel):
    """Payload for requesting a new risk acceptance."""

    finding_id: str
    justification: str
    business_reason: str
    compensating_controls: str = ""
    requested_by: str
    expires_at: datetime
    priority: ReviewPriority = ReviewPriority.ROUTINE
    conditions: List[str] = Field(default_factory=list)
    risk_score_at_acceptance: float = 0.0


class ApproveRequest(BaseModel):
    approver: str
    comment: str = ""
    approver_role: str = "admin"


class RejectRequest(BaseModel):
    reviewer: str
    reason: str = ""


class RevokeRequest(BaseModel):
    revoker: str
    reason: str = ""


# ---------------------------------------------------------------------------
# Endpoints — fixed paths before parameterised ones
# ---------------------------------------------------------------------------


@router.post("/request", response_model=RiskAcceptance, status_code=status.HTTP_201_CREATED)
async def request_acceptance(
    payload: RiskAcceptanceRequest,
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> RiskAcceptance:
    """Submit a formal risk acceptance request for a finding."""
    return manager.request_acceptance(
        finding_id=payload.finding_id,
        justification=payload.justification,
        business_reason=payload.business_reason,
        compensating_controls=payload.compensating_controls,
        requested_by=payload.requested_by,
        expires_at=payload.expires_at,
        org_id=org_id,
        priority=payload.priority,
        conditions=payload.conditions,
        risk_score_at_acceptance=payload.risk_score_at_acceptance,
    )


@router.get("", response_model=List[RiskAcceptance])
async def list_acceptances(
    status_filter: Optional[AcceptanceStatus] = Query(None, alias="status"),
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> List[RiskAcceptance]:
    """List risk acceptances for the current org, optionally filtered by status."""
    return manager.list_acceptances(org_id, status_filter=status_filter)


@router.get("/pending", response_model=List[RiskAcceptance])
async def list_pending(
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> List[RiskAcceptance]:
    """List all pending risk acceptances awaiting approval."""
    return manager.get_pending_reviews(org_id)


@router.get("/expiring", response_model=List[RiskAcceptance])
async def list_expiring(
    days: int = Query(30, ge=1, le=365),
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> List[RiskAcceptance]:
    """List approved acceptances expiring within *days* days."""
    return manager.get_expiring_soon(org_id, days=days)


@router.get("/stats", response_model=Dict[str, Any])
async def acceptance_stats(
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Return summary statistics for the org's risk acceptances."""
    return manager.get_acceptance_stats(org_id)


@router.post("/expire", response_model=Dict[str, Any])
async def expire_overdue(
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Expire all overdue approved acceptances. Returns count of expired records."""
    count = manager.expire_overdue(org_id)
    return {"expired_count": count, "org_id": org_id}


# ---------------------------------------------------------------------------
# Parameterised endpoints — must come after fixed-path routes
# ---------------------------------------------------------------------------


@router.get("/{acceptance_id}", response_model=RiskAcceptance)
async def get_acceptance(
    acceptance_id: str,
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> RiskAcceptance:
    """Get a single risk acceptance by ID."""
    acceptance = manager.get_acceptance(acceptance_id)
    if acceptance is None:
        raise HTTPException(status_code=404, detail=f"Risk acceptance '{acceptance_id}' not found")
    return acceptance


@router.post("/{acceptance_id}/approve", response_model=RiskAcceptance)
async def approve_acceptance(
    acceptance_id: str,
    payload: ApproveRequest,
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> RiskAcceptance:
    """Approve a pending risk acceptance. Requires admin or security_analyst role."""
    try:
        return manager.approve(
            acceptance_id,
            approver=payload.approver,
            comment=payload.comment,
            approver_role=payload.approver_role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{acceptance_id}/reject", response_model=RiskAcceptance)
async def reject_acceptance(
    acceptance_id: str,
    payload: RejectRequest,
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> RiskAcceptance:
    """Reject a pending risk acceptance."""
    try:
        return manager.reject(acceptance_id, reviewer=payload.reviewer, reason=payload.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{acceptance_id}/revoke", response_model=RiskAcceptance)
async def revoke_acceptance(
    acceptance_id: str,
    payload: RevokeRequest,
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> RiskAcceptance:
    """Revoke a previously approved risk acceptance."""
    try:
        return manager.revoke(acceptance_id, revoker=payload.revoker, reason=payload.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{acceptance_id}/history", response_model=List[AcceptanceReview])
async def review_history(
    acceptance_id: str,
    org_id: str = Depends(get_org_id),
    manager: RiskAcceptanceManager = Depends(_get_manager),
) -> List[AcceptanceReview]:
    """Return the full review history for a risk acceptance."""
    acceptance = manager.get_acceptance(acceptance_id)
    if acceptance is None:
        raise HTTPException(status_code=404, detail=f"Risk acceptance '{acceptance_id}' not found")
    return manager.get_review_history(acceptance_id)
