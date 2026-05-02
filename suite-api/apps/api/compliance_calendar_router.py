"""Compliance Calendar Router — ALDECI.

Compliance calendar tracking deadlines, audits, renewals, and regulatory
filings. Supports recurrence, reminders, views, and calendar summaries.

Prefix: /api/v1/compliance-calendar
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/compliance-calendar",
    tags=["Compliance Calendar"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.compliance_calendar_engine import ComplianceCalendarEngine
        _engine = ComplianceCalendarEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateEventRequest(BaseModel):
    event_name: str = Field(..., description="Name of the compliance event")
    event_type: str = Field(
        ...,
        description="audit | certification | filing | renewal | review | training | assessment | deadline",
    )
    framework: str = Field(
        ...,
        description="SOC2 | ISO27001 | PCI-DSS | HIPAA | GDPR | NIST | CIS | FedRAMP",
    )
    due_date: str = Field(..., description="Due date in YYYY-MM-DD format")
    recurrence: str = Field(
        default="none",
        description="none | weekly | monthly | quarterly | annual",
    )
    owner: str = Field(default="", description="Event owner/responsible party")
    priority: str = Field(
        default="medium",
        description="critical | high | medium | low",
    )
    reminder_days: int = Field(
        default=7,
        ge=0,
        description="Days before due_date to send reminder",
    )
    notes: str = Field(default="", description="Additional notes")


class CreateViewRequest(BaseModel):
    view_name: str = Field(..., description="Name for this calendar view")
    frameworks: List[str] = Field(default_factory=list, description="Frameworks to include")
    event_types: List[str] = Field(default_factory=list, description="Event types to include")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_compliance_calendar(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get compliance calendar summary for the org."""
    return _get_engine().get_calendar_summary(org_id)


@router.post("/events", dependencies=[Depends(api_key_auth)])
def create_event(
    req: CreateEventRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a compliance calendar event. Auto-creates a reminder record."""
    try:
        return _get_engine().create_event(
            org_id=org_id,
            event_name=req.event_name,
            event_type=req.event_type,
            framework=req.framework,
            due_date=req.due_date,
            recurrence=req.recurrence,
            owner=req.owner,
            priority=req.priority,
            reminder_days=req.reminder_days,
            notes=req.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/events/{event_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_event(
    event_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Mark a compliance event as completed. Creates next occurrence if recurring."""
    try:
        return _get_engine().complete_event(event_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/upcoming", dependencies=[Depends(api_key_auth)])
def get_upcoming_events(
    org_id: str = Query(..., description="Organization ID"),
    days_ahead: int = Query(default=30, ge=1, le=365),
) -> List[Dict[str, Any]]:
    """Return events due within the next N days."""
    return _get_engine().get_upcoming_events(org_id, days_ahead=days_ahead)


@router.get("/overdue", dependencies=[Depends(api_key_auth)])
def get_overdue_events(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """Return events that are past their due_date and still upcoming."""
    return _get_engine().get_overdue_events(org_id)


@router.post("/reminders/{reminder_id}/sent", dependencies=[Depends(api_key_auth)])
def mark_reminder_sent(
    reminder_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Mark a reminder as sent."""
    try:
        return _get_engine().mark_reminder_sent(reminder_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/reminders/due", dependencies=[Depends(api_key_auth)])
def get_due_reminders(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """Return unsent reminders whose reminder_date is today or earlier."""
    return _get_engine().get_due_reminders(org_id)


@router.post("/views", dependencies=[Depends(api_key_auth)])
def create_view(
    req: CreateViewRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a named calendar view with framework/event_type filters."""
    return _get_engine().create_view(
        org_id=org_id,
        view_name=req.view_name,
        frameworks=req.frameworks,
        event_types=req.event_types,
    )


@router.get("/framework/{framework}", dependencies=[Depends(api_key_auth)])
def get_events_by_framework(
    framework: str,
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """List all events for a specific compliance framework."""
    return _get_engine().get_events_by_framework(org_id, framework)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_calendar_summary(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return calendar summary: upcoming/overdue counts, by_framework, by_type."""
    return _get_engine().get_calendar_summary(org_id)
