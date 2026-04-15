"""Report Scheduler Router — schedule and deliver security reports via n8n.

Endpoints:
    POST   /api/v1/reports/schedules              create_schedule
    GET    /api/v1/reports/schedules              list_schedules
    DELETE /api/v1/reports/schedules/{id}         delete_schedule
    POST   /api/v1/reports/schedules/{id}/trigger trigger_report
    GET    /api/v1/reports/schedules/{id}/preview  get_preview
    GET    /api/v1/reports/history                delivery_history
    POST   /api/v1/reports/send-now               send_now
"""
from __future__ import annotations

import logging
import sys
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

sys.path.insert(0, "suite-core")
try:
    from core.report_scheduler import (
        CHANNELS,
        FORMATS,
        FREQUENCIES,
        REPORT_TYPES,
        ReportScheduler,
    )
except ImportError:
    from core.report_scheduler import (  # type: ignore[no-redef]
        CHANNELS,
        FORMATS,
        FREQUENCIES,
        REPORT_TYPES,
        ReportScheduler,
    )

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])

_scheduler: Optional[ReportScheduler] = None


def _get_scheduler() -> ReportScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = ReportScheduler()
    return _scheduler


# ============================================================================
# Request / Response models
# ============================================================================


class CreateScheduleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    report_type: str = Field(..., description=f"One of: {REPORT_TYPES}")
    frequency: str = Field(..., description=f"One of: {FREQUENCIES}")
    recipients: List[str] = Field(default_factory=list)
    channels: List[str] = Field(default=["email"], description=f"One of: {CHANNELS}")
    format: str = Field(default="json", description=f"One of: {FORMATS}")
    filters: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = Field(default="default")

    model_config = {"str_strip_whitespace": True}


class SendNowRequest(BaseModel):
    report_type: str = Field(..., description=f"One of: {REPORT_TYPES}")
    recipients: List[str] = Field(default_factory=list)
    channels: List[str] = Field(default=["email"])
    format: str = Field(default="json")
    filters: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = Field(default="default")

    model_config = {"str_strip_whitespace": True}


# ============================================================================
# Endpoints
# ============================================================================


@router.post("/schedules", summary="Create a report delivery schedule")
def create_schedule(body: CreateScheduleRequest) -> Dict[str, Any]:
    """Create a new scheduled report delivery. Returns the schedule_id."""
    sched = _get_scheduler()
    try:
        schedule_id = sched.create_schedule(
            org_id=body.org_id,
            schedule={
                "name": body.name,
                "report_type": body.report_type,
                "frequency": body.frequency,
                "recipients": body.recipients,
                "channels": body.channels,
                "format": body.format,
                "filters": body.filters,
            },
        )
        return {"schedule_id": schedule_id, "status": "created"}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create report schedule")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/schedules", summary="List report delivery schedules")
def list_schedules(
    org_id: str = Query(default="default", description="Organisation ID"),
) -> List[Dict[str, Any]]:
    """List all active schedules for the given org."""
    sched = _get_scheduler()
    return sched.list_schedules(org_id=org_id)


@router.delete("/schedules/{schedule_id}", summary="Delete a report delivery schedule")
def delete_schedule(schedule_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Delete a schedule by ID. Returns 404 if not found."""
    sched = _get_scheduler()
    deleted = sched.delete_schedule(schedule_id=schedule_id, org_id=org_id)
    if not deleted:
        raise HTTPException(
            status_code=404, detail=f"Schedule '{schedule_id}' not found"
        )
    return {"deleted": True, "schedule_id": schedule_id}


@router.post("/schedules/{schedule_id}/trigger", summary="Trigger immediate report delivery")
def trigger_report(schedule_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Manually trigger delivery of a report for the given schedule.

    Returns {status, report_id, channels_notified}.
    """
    sched = _get_scheduler()
    try:
        return sched.trigger_report(schedule_id=schedule_id, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to trigger report for schedule %s", schedule_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/schedules/{schedule_id}/preview", summary="Preview report data")
def get_preview(
    schedule_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return a preview of report data for the given schedule's report_type."""
    sched = _get_scheduler()
    schedule = sched._get_schedule(schedule_id)
    if schedule is None or schedule.get("org_id") != org_id:
        raise HTTPException(status_code=404, detail=f"Schedule '{schedule_id}' not found")
    try:
        return sched.get_report_preview(
            report_type=schedule["report_type"],
            org_id=org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to preview report for schedule %s", schedule_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/history", summary="Report delivery history")
def delivery_history(
    org_id: str = Query(default="default", description="Organisation ID"),
    limit: int = Query(default=50, ge=1, le=500, description="Max records"),
) -> List[Dict[str, Any]]:
    """Return past report deliveries for the org, newest first."""
    sched = _get_scheduler()
    return sched.get_delivery_history(org_id=org_id, limit=limit)


@router.post("/send-now", summary="Send a one-off report immediately")
def send_now(body: SendNowRequest) -> Dict[str, Any]:
    """Generate and deliver a one-off report without creating a persistent schedule.

    Returns {status, report_id, channels_notified}.
    """
    sched = _get_scheduler()
    # Create a transient schedule, trigger it, then delete it
    try:
        schedule_id = sched.create_schedule(
            org_id=body.org_id,
            schedule={
                "name": f"one-off-{body.report_type}",
                "report_type": body.report_type,
                "frequency": "daily",
                "recipients": body.recipients,
                "channels": body.channels,
                "format": body.format,
                "filters": body.filters,
            },
        )
        result = sched.trigger_report(schedule_id=schedule_id, org_id=body.org_id)
        sched.delete_schedule(schedule_id=schedule_id, org_id=body.org_id)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to send one-off report")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
