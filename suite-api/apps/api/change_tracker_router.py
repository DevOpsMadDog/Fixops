"""
Change Management Tracker API — /api/v1/change-tracker/*

Endpoints:
  POST /api/v1/change-tracker/                       — record a change
  POST /api/v1/change-tracker/{change_id}/assess-risk — auto-assess risk
  POST /api/v1/change-tracker/{change_id}/approve     — approve a change
  POST /api/v1/change-tracker/{change_id}/reject      — reject a change
  GET  /api/v1/change-tracker/pending                 — pending reviews
  GET  /api/v1/change-tracker/high-risk               — high/critical changes
  GET  /api/v1/change-tracker/velocity                — change velocity trend
  GET  /api/v1/change-tracker/stats                   — aggregate statistics
  GET  /api/v1/change-tracker/correlate-incidents     — changes linked to incidents
  GET  /api/v1/change-tracker/{change_id}             — fetch a single change
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.change_tracker import Change, ChangeRisk, ChangeTracker, ChangeType
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/change-tracker", tags=["change-tracker"])

_tracker = ChangeTracker()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RecordChangeRequest(BaseModel):
    type: ChangeType = Field(..., description="Category of the change")
    description: str = Field(..., description="Human-readable description")
    author: str = Field(..., description="Who made the change (email or username)")
    affected_assets: List[str] = Field(default_factory=list, description="Impacted assets")
    risk_level: ChangeRisk = Field(ChangeRisk.NONE, description="Initial risk assessment")
    security_impact: str = Field("", description="Optional security impact note")
    org_id: str = Field("default", description="Organisation identifier")


class ApproveChangeRequest(BaseModel):
    approver: str = Field(..., description="Email or username of the approver")


class RejectChangeRequest(BaseModel):
    reviewer: str = Field(..., description="Email or username of the reviewer")
    reason: str = Field(..., description="Reason for rejection")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/", response_model=Change, summary="Record a change")
def record_change(req: RecordChangeRequest) -> Change:
    """Log a new change that may affect security posture."""
    try:
        return _tracker.record_change(
            type=req.type,
            description=req.description,
            author=req.author,
            affected_assets=req.affected_assets,
            risk_level=req.risk_level,
            security_impact=req.security_impact,
            org_id=req.org_id,
        )
    except Exception as exc:
        logger.exception("Failed to record change: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to record change: {exc}") from exc


@router.post("/{change_id}/assess-risk", response_model=Change, summary="Auto-assess risk")
def assess_risk(change_id: str) -> Change:
    """Run heuristic risk assessment on a change and persist the result."""
    try:
        return _tracker.assess_risk(change_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Risk assessment failed for %s: %s", change_id, exc)
        raise HTTPException(status_code=500, detail=f"Risk assessment failed: {exc}") from exc


@router.post("/{change_id}/approve", response_model=Change, summary="Approve a change")
def approve_change(change_id: str, req: ApproveChangeRequest) -> Change:
    """Approve a change after security review."""
    try:
        return _tracker.approve_change(change_id, approver=req.approver)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Approval failed for %s: %s", change_id, exc)
        raise HTTPException(status_code=500, detail=f"Approval failed: {exc}") from exc


@router.post("/{change_id}/reject", response_model=Change, summary="Reject a change")
def reject_change(change_id: str, req: RejectChangeRequest) -> Change:
    """Reject a change with a documented reason."""
    try:
        return _tracker.reject_change(change_id, reviewer=req.reviewer, reason=req.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Rejection failed for %s: %s", change_id, exc)
        raise HTTPException(status_code=500, detail=f"Rejection failed: {exc}") from exc


@router.get("/pending", response_model=List[Change], summary="Pending reviews")
def get_pending_reviews(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[Change]:
    """Return all changes awaiting review."""
    try:
        return _tracker.get_pending_reviews(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to fetch pending reviews: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch pending: {exc}") from exc


@router.get("/high-risk", response_model=List[Change], summary="High-risk changes")
def get_high_risk_changes(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[Change]:
    """Return changes flagged as HIGH or CRITICAL risk."""
    try:
        return _tracker.get_high_risk_changes(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to fetch high-risk changes: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch high-risk: {exc}") from exc


@router.get("/velocity", response_model=Dict[str, Any], summary="Change velocity")
def get_change_velocity(
    org_id: str = Query("default", description="Organisation identifier"),
    days: int = Query(30, ge=1, le=365, description="Look-back window in days"),
) -> Dict[str, Any]:
    """Return change velocity trend (changes per day) for an organisation."""
    try:
        return _tracker.get_change_velocity(org_id=org_id, days=days)
    except Exception as exc:
        logger.exception("Failed to compute velocity: %s", exc)
        raise HTTPException(status_code=500, detail=f"Velocity failed: {exc}") from exc


@router.get("/stats", response_model=Dict[str, Any], summary="Change statistics")
def get_change_stats(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return aggregate stats: counts by type, risk, and approval rate."""
    try:
        return _tracker.get_change_stats(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to compute stats: %s", exc)
        raise HTTPException(status_code=500, detail=f"Stats failed: {exc}") from exc


@router.get("/correlate-incidents", response_model=List[Dict[str, Any]], summary="Correlate with incidents")
def correlate_with_incidents(
    org_id: str = Query("default", description="Organisation identifier"),
    window_hours: int = Query(72, ge=1, le=720, description="Correlation time window in hours"),
) -> List[Dict[str, Any]]:
    """Return high-risk changes correlated to likely incident windows."""
    try:
        return _tracker.correlate_with_incidents(org_id=org_id, window_hours=window_hours)
    except Exception as exc:
        logger.exception("Correlation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Correlation failed: {exc}") from exc


@router.get("/{change_id}", response_model=Change, summary="Get a change")
def get_change(change_id: str) -> Change:
    """Fetch a single change by ID."""
    try:
        change = _tracker.get_change(change_id)
        if change is None:
            raise HTTPException(status_code=404, detail=f"Change not found: {change_id}")
        return change
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to fetch change %s: %s", change_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch change: {exc}") from exc
