"""
Compliance Calendar API — track deadlines, events, and activities.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
Supports 7 frameworks: SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF, CIS, GDPR.
"""
from __future__ import annotations

from datetime import date
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.dependencies import get_org_id
from core.compliance_calendar import (
    CalendarEvent,
    ComplianceCalendar,
    EventStatus,
    EventType,
)

router = APIRouter(prefix="/api/v1/compliance-calendar", tags=["compliance-calendar"])

_calendar = ComplianceCalendar()

_VALID_FRAMEWORKS = {"SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST-CSF", "CIS", "GDPR"}


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class CreateEventRequest(BaseModel):
    title: str
    event_type: EventType
    framework: str
    due_date: date
    assignee: Optional[str] = None
    reminder_days: int = Field(default=7, ge=1, le=365)
    recurring: bool = False
    recurrence_interval_days: Optional[int] = Field(default=None, ge=1, le=3650)


class EventResponse(BaseModel):
    id: str
    title: str
    event_type: str
    framework: str
    due_date: str
    assignee: Optional[str]
    status: str
    reminder_days: int
    recurring: bool
    recurrence_interval_days: Optional[int]
    org_id: str


def _to_response(event: CalendarEvent) -> EventResponse:
    d = event.to_dict()
    return EventResponse(**d)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/events", response_model=EventResponse, status_code=201)
async def create_event(
    body: CreateEventRequest,
    org_id: str = Depends(get_org_id),
):
    """Create a new compliance calendar event."""
    event = CalendarEvent(
        title=body.title,
        event_type=body.event_type,
        framework=body.framework,
        due_date=body.due_date,
        assignee=body.assignee,
        status=EventStatus.UPCOMING,
        reminder_days=body.reminder_days,
        recurring=body.recurring,
        recurrence_interval_days=body.recurrence_interval_days,
        org_id=org_id,
    )
    created = _calendar.add_event(event)
    return _to_response(created)


@router.get("/events", response_model=Dict[str, Any])
async def list_events(
    month: int = Query(..., ge=1, le=12),
    year: int = Query(..., ge=2000, le=2100),
    org_id: str = Depends(get_org_id),
):
    """List compliance events for a specific month and year."""
    events = _calendar.list_events(org_id=org_id, month=month, year=year)
    return {
        "items": [e.to_dict() for e in events],
        "total": len(events),
        "month": month,
        "year": year,
        "org_id": org_id,
    }


@router.get("/events/upcoming", response_model=Dict[str, Any])
async def get_upcoming(
    days: int = Query(30, ge=1, le=365),
    org_id: str = Depends(get_org_id),
):
    """Get events due within the next N days."""
    events = _calendar.get_upcoming(org_id=org_id, days=days)
    return {
        "items": [e.to_dict() for e in events],
        "total": len(events),
        "days": days,
        "org_id": org_id,
    }


@router.get("/events/overdue", response_model=Dict[str, Any])
async def get_overdue(
    org_id: str = Depends(get_org_id),
):
    """Get all overdue compliance events."""
    events = _calendar.get_overdue(org_id=org_id)
    return {
        "items": [e.to_dict() for e in events],
        "total": len(events),
        "org_id": org_id,
    }


@router.post("/events/{event_id}/complete", response_model=EventResponse)
async def complete_event(event_id: str):
    """Mark a compliance event as completed (spawns next recurrence if recurring)."""
    event = _calendar.complete_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return _to_response(event)


@router.get("/calendar-view", response_model=Dict[str, Any])
async def get_calendar_view(
    year: int = Query(..., ge=2000, le=2100),
    month: int = Query(..., ge=1, le=12),
    org_id: str = Depends(get_org_id),
):
    """Get full month calendar view grouped by day."""
    return _calendar.get_calendar_view(org_id=org_id, year=year, month=month)


@router.post("/generate/{framework}", response_model=Dict[str, Any], status_code=201)
async def auto_generate_events(
    framework: str,
    org_id: str = Depends(get_org_id),
):
    """Auto-generate recurring compliance events for a framework."""
    fw_upper = framework.upper()
    # Normalize hyphenated lookups (e.g. pci-dss -> PCI-DSS)
    if fw_upper not in _VALID_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Valid: {sorted(_VALID_FRAMEWORKS)}",
        )
    events = _calendar.auto_generate_events(org_id=org_id, framework=fw_upper)
    return {
        "framework": fw_upper,
        "org_id": org_id,
        "generated": len(events),
        "items": [e.to_dict() for e in events],
    }


@router.get("/stats", response_model=Dict[str, Any])
async def get_calendar_stats(
    org_id: str = Depends(get_org_id),
):
    """Get compliance calendar statistics (upcoming, overdue, completed counts)."""
    return _calendar.get_calendar_stats(org_id=org_id)
