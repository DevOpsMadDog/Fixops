"""Security Change Management Router — ALDECI.

Endpoints for the SecurityChangeManagementEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/change-management
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/change-management/changes                        create_change
  GET   /api/v1/change-management/changes                        list_changes
  GET   /api/v1/change-management/changes/{change_id}            get_change
  PATCH /api/v1/change-management/changes/{change_id}/status     update_change_status
  POST  /api/v1/change-management/changes/{change_id}/approvals  add_approver
  GET   /api/v1/change-management/approvals                      list_approvals
  GET   /api/v1/change-management/stats                          get_change_stats
"""
from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/change-management",
    tags=["Security Change Management"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_change_management_engine import (
            SecurityChangeManagementEngine,
        )
        _engine = SecurityChangeManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ChangeCreate(BaseModel):
    title: str
    change_type: str = "patch"
    description: str = ""
    priority: str = "medium"
    risk_level: str = "medium"
    requested_by: str = ""
    assigned_to: str = ""
    affected_systems: str = ""
    rollback_plan: str = ""
    scheduled_at: Optional[str] = None


class ChangeStatusUpdate(BaseModel):
    status: str
    notes: str = ""


class ApproverCreate(BaseModel):
    approver: str
    decision: str = "pending"
    comments: str = ""


# ---------------------------------------------------------------------------
# Changes
# ---------------------------------------------------------------------------

@router.post("/changes", dependencies=[Depends(api_key_auth)], status_code=201)
def create_change(body: ChangeCreate, org_id: str = Query(default="default")):
    """Create a new security change request in draft status."""
    try:
        return _get_engine().create_change(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/changes", dependencies=[Depends(api_key_auth)])
def list_changes(
     org_id: str = Query(default="default"),
    change_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
):
    """List changes with optional type, status, and priority filters."""
    return _get_engine().list_changes(
        org_id,
        change_type=change_type,
        status=status,
        priority=priority,
    )


@router.get("/changes/{change_id}", dependencies=[Depends(api_key_auth)])
def get_change(change_id: str, org_id: str = Query(default="default")):
    """Get a single change by ID."""
    change = _get_engine().get_change(org_id, change_id)
    if not change:
        raise HTTPException(status_code=404, detail="Change not found")
    return change


@router.patch("/changes/{change_id}/status", dependencies=[Depends(api_key_auth)])
def update_change_status(
    change_id: str,
    body: ChangeStatusUpdate,
     org_id: str = Query(default="default"),
):
    """Update change status. Sets completed_at when status=completed."""
    try:
        result = _get_engine().update_change_status(
            org_id, change_id, body.status, notes=body.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Change not found")
    return result


@router.post(
    "/changes/{change_id}/approvals",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_approver(change_id: str, body: ApproverCreate, org_id: str = Query(default="default")):
    """Add an approval record (approved/rejected/pending) to a change."""
    try:
        return _get_engine().add_approver(org_id, change_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------

@router.get("/approvals", dependencies=[Depends(api_key_auth)])
def list_approvals(
     org_id: str = Query(default="default"),
    change_id: Optional[str] = Query(None),
):
    """List all approvals for an org, optionally filtered by change_id."""
    return _get_engine().list_approvals(org_id, change_id=change_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_change_stats(org_id: str = Query(default="default")):
    """Return aggregated change management statistics for an org."""
    return _get_engine().get_change_stats(org_id)
