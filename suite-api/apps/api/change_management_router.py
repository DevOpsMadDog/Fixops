"""
Change Management / CAB API Router — ALDECI.

Exposes 8 REST endpoints under /api/v1/changes for the full change
management lifecycle: CRUD, CAB approvals, conflict detection, calendar
management, and metrics.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from core.change_management import (
    ApprovalDecision,
    CABApproval,
    ChangeAdvisoryBoard,
    ChangeCategory,
    ChangeRiskLevel,
    FreezePeriod,
    ImpactAnalysis,
    MaintenanceWindow,
    RollbackPlan,
    get_cab,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/changes", tags=["change-management"])

# Module-level CAB instance (reuses singleton)
_cab: "ChangeAdvisoryBoard | None" = None  # lazy


def _get_cab() -> ChangeAdvisoryBoard:
    global _cab
    if _cab is None:
        _cab = get_cab()
    return _cab


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateChangeRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=10)
    category: ChangeCategory
    requestor_id: str
    requestor_name: str
    requestor_team: Optional[str] = None
    rollback_plan: RollbackPlan
    impact_analysis: Optional[ImpactAnalysis] = None
    scheduled_start: Optional[datetime] = None
    scheduled_end: Optional[datetime] = None
    priority: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    tags: List[str] = Field(default_factory=list)
    external_ticket_id: Optional[str] = None


class SubmitChangeRequest(BaseModel):
    actor_id: str
    actor_name: str


class AddApprovalRequest(BaseModel):
    approver_id: str
    approver_name: str
    approver_role: str
    decision: ApprovalDecision
    comments: Optional[str] = None
    conditions: List[str] = Field(default_factory=list)


class ImplementRequest(BaseModel):
    actor_id: str
    actor_name: str


class CompleteRequest(BaseModel):
    actor_id: str
    actor_name: str
    implementation_notes: Optional[str] = None
    post_implementation_review: Optional[str] = None


class RollbackRequest(BaseModel):
    actor_id: str
    actor_name: str
    reason: str


class RejectRequest(BaseModel):
    actor_id: str
    actor_name: str
    reason: str


class ImpactAssessRequest(BaseModel):
    actor_id: str
    actor_name: str
    impact: ImpactAnalysis


class OverrideRiskRequest(BaseModel):
    actor_id: str
    actor_name: str
    new_risk: ChangeRiskLevel
    justification: str


class CreateMaintenanceWindowRequest(BaseModel):
    name: str
    start_time: datetime
    end_time: datetime
    description: Optional[str] = None
    allowed_risk_levels: List[ChangeRiskLevel] = Field(
        default_factory=lambda: [ChangeRiskLevel.STANDARD, ChangeRiskLevel.NORMAL]
    )
    recurring: bool = False
    recurrence_days: Optional[int] = None


class CreateFreezePeriodRequest(BaseModel):
    name: str
    start_time: datetime
    end_time: datetime
    reason: str
    exception_allowed: bool = False


# ---------------------------------------------------------------------------
# Endpoint 1: List & create change requests
# ---------------------------------------------------------------------------


@router.get("")
async def list_changes(
    status: Optional[str] = Query(default=None),
    risk_level: Optional[str] = Query(default=None),
    requestor_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List change requests with optional filters."""
    changes = _get_cab().list_changes(
        status=status,
        risk_level=risk_level,
        requestor_id=requestor_id,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [c.model_dump(mode="json") for c in changes],
        "total": len(changes),
        "limit": limit,
        "offset": offset,
    }


@router.post("", status_code=201)
async def create_change(body: CreateChangeRequest) -> Dict[str, Any]:
    """Create a new change request in DRAFT status."""
    change = _get_cab().create_change_request(
        title=body.title,
        description=body.description,
        category=body.category,
        requestor_id=body.requestor_id,
        requestor_name=body.requestor_name,
        rollback_plan=body.rollback_plan,
        impact_analysis=body.impact_analysis,
        scheduled_start=body.scheduled_start,
        scheduled_end=body.scheduled_end,
        priority=body.priority,
        requestor_team=body.requestor_team,
        tags=body.tags,
        external_ticket_id=body.external_ticket_id,
    )
    return change.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Endpoint 2: Get, submit, approve/reject a single change
# ---------------------------------------------------------------------------


@router.get("/{change_id}")
async def get_change(change_id: str) -> Dict[str, Any]:
    """Get a specific change request by ID."""
    change = _get_cab().get_change(change_id)
    if not change:
        raise HTTPException(status_code=404, detail=f"Change {change_id} not found")
    return change.model_dump(mode="json")


@router.post("/{change_id}/submit")
async def submit_change(change_id: str, body: SubmitChangeRequest) -> Dict[str, Any]:
    """Submit a DRAFT change request for CAB review."""
    try:
        change = _get_cab().submit_change(change_id, body.actor_id, body.actor_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return change.model_dump(mode="json")


@router.post("/{change_id}/approve")
async def add_approval(change_id: str, body: AddApprovalRequest) -> Dict[str, Any]:
    """Add a CAB member approval, rejection, or conditional approval."""
    approval = CABApproval(
        approver_id=body.approver_id,
        approver_name=body.approver_name,
        approver_role=body.approver_role,
        decision=body.decision,
        comments=body.comments,
        conditions=body.conditions,
    )
    try:
        change, resolved = _get_cab().add_approval(change_id, approval)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"change": change.model_dump(mode="json"), "fully_resolved": resolved}


@router.post("/{change_id}/reject")
async def reject_change(change_id: str, body: RejectRequest) -> Dict[str, Any]:
    """Directly reject a change request."""
    try:
        change = _get_cab().reject_change(change_id, body.actor_id, body.actor_name, body.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return change.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Endpoint 3: Implementation lifecycle
# ---------------------------------------------------------------------------


@router.post("/{change_id}/implement")
async def start_implementation(change_id: str, body: ImplementRequest) -> Dict[str, Any]:
    """Start implementing an APPROVED change."""
    try:
        change = _get_cab().start_implementation(change_id, body.actor_id, body.actor_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return change.model_dump(mode="json")


@router.post("/{change_id}/complete")
async def complete_change(change_id: str, body: CompleteRequest) -> Dict[str, Any]:
    """Mark an IMPLEMENTING change as COMPLETED."""
    try:
        change = _get_cab().complete_change(
            change_id,
            body.actor_id,
            body.actor_name,
            body.implementation_notes,
            body.post_implementation_review,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return change.model_dump(mode="json")


@router.post("/{change_id}/rollback")
async def rollback_change(change_id: str, body: RollbackRequest) -> Dict[str, Any]:
    """Execute rollback for a change that is IMPLEMENTING or COMPLETED."""
    try:
        change = _get_cab().rollback_change(change_id, body.actor_id, body.actor_name, body.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return change.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Endpoint 4: Impact assessment & risk override
# ---------------------------------------------------------------------------


@router.post("/{change_id}/impact")
async def assess_impact(change_id: str, body: ImpactAssessRequest) -> Dict[str, Any]:
    """Attach or update impact analysis for a change request."""
    try:
        change = _get_cab().assess_impact(change_id, body.impact, body.actor_id, body.actor_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return change.model_dump(mode="json")


@router.post("/{change_id}/risk-override")
async def override_risk(change_id: str, body: OverrideRiskRequest) -> Dict[str, Any]:
    """Override risk classification for a change request with justification."""
    try:
        change = _get_cab().override_risk_level(
            change_id, body.new_risk, body.actor_id, body.actor_name, body.justification
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return change.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Endpoint 5: Audit trail
# ---------------------------------------------------------------------------


@router.get("/{change_id}/audit")
async def get_audit_trail(change_id: str) -> Dict[str, Any]:
    """Get the full audit trail for a change request."""
    change = _get_cab().get_change(change_id)
    if not change:
        raise HTTPException(status_code=404, detail=f"Change {change_id} not found")
    trail = _get_cab().get_audit_trail(change_id)
    return {
        "change_id": change_id,
        "entries": [e.model_dump(mode="json") for e in trail],
        "total": len(trail),
    }


# ---------------------------------------------------------------------------
# Endpoint 6: Conflict detection
# ---------------------------------------------------------------------------


@router.get("/{change_id}/conflicts")
async def check_conflicts(change_id: str) -> Dict[str, Any]:
    """Check a scheduled change for calendar conflicts and freeze periods."""
    change = _get_cab().get_change(change_id)
    if not change:
        raise HTTPException(status_code=404, detail=f"Change {change_id} not found")
    result = _get_cab().check_conflicts(change)
    return result.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Endpoint 7: Change calendar (maintenance windows + freeze periods)
# ---------------------------------------------------------------------------


@router.get("/calendar/windows")
async def list_maintenance_windows() -> Dict[str, Any]:
    """List all maintenance windows."""
    windows = _get_cab().list_maintenance_windows()
    return {"items": [w.model_dump(mode="json") for w in windows], "total": len(windows)}


@router.post("/calendar/windows", status_code=201)
async def create_maintenance_window(body: CreateMaintenanceWindowRequest) -> Dict[str, Any]:
    """Create a new maintenance window."""
    try:
        window = MaintenanceWindow(
            name=body.name,
            start_time=body.start_time,
            end_time=body.end_time,
            description=body.description,
            allowed_risk_levels=body.allowed_risk_levels,
            recurring=body.recurring,
            recurrence_days=body.recurrence_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    window = _get_cab().create_maintenance_window(window)
    return window.model_dump(mode="json")


@router.get("/calendar/freezes")
async def list_freeze_periods() -> Dict[str, Any]:
    """List all change freeze periods."""
    periods = _get_cab().list_freeze_periods()
    return {"items": [p.model_dump(mode="json") for p in periods], "total": len(periods)}


@router.post("/calendar/freezes", status_code=201)
async def create_freeze_period(body: CreateFreezePeriodRequest) -> Dict[str, Any]:
    """Create a new change freeze period."""
    try:
        period = FreezePeriod(
            name=body.name,
            start_time=body.start_time,
            end_time=body.end_time,
            reason=body.reason,
            exception_allowed=body.exception_allowed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    period = _get_cab().create_freeze_period(period)
    return period.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Endpoint 8: Metrics
# ---------------------------------------------------------------------------


@router.get("/metrics/summary")
async def get_metrics(
    period_days: int = Query(default=30, ge=1, le=365),
) -> Dict[str, Any]:
    """Get change management metrics for the specified period."""
    metrics = _get_cab().get_metrics(period_days=period_days)
    return metrics.model_dump(mode="json")


@router.post("/admin/expire-stale")
async def expire_stale_changes() -> Dict[str, Any]:
    """Expire change requests that have breached their SLA review deadline."""
    expired = _get_cab().expire_stale_changes()
    return {"expired_count": len(expired), "expired_ids": expired}
