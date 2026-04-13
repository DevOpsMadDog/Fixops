"""
Report Scheduler Router — ALDECI.

8 endpoints for scheduled report delivery:
  POST   /api/v1/report-schedules/           create_schedule
  PUT    /api/v1/report-schedules/{id}       update_schedule
  DELETE /api/v1/report-schedules/{id}       delete_schedule
  GET    /api/v1/report-schedules/           list_schedules
  GET    /api/v1/report-schedules/{id}       get_schedule
  POST   /api/v1/report-schedules/{id}/deliver   deliver_now
  POST   /api/v1/report-schedules/run-due    run_due_schedules
  GET    /api/v1/report-schedules/log        delivery_log
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from core.report_scheduler import (
        DELIVERY_CHANNELS,
        REPORT_TYPES,
        SCHEDULE_TYPES,
        ReportScheduler,
    )
except ImportError:
    import sys
    sys.path.insert(0, "suite-core")
    from core.report_scheduler import (
        DELIVERY_CHANNELS,
        REPORT_TYPES,
        SCHEDULE_TYPES,
        ReportScheduler,
    )

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/report-schedules",
    tags=["report-scheduler"],
)

# Shared scheduler instance (file-backed, shared across requests)
_scheduler: Optional[ReportScheduler] = None


def _get_scheduler() -> ReportScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = ReportScheduler()
    return _scheduler


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class CreateScheduleRequest(BaseModel):
    name: str = Field(..., description="Human-readable schedule name")
    report_type: str = Field(..., description=f"One of: {REPORT_TYPES}")
    schedule_type: str = Field(..., description=f"One of: {SCHEDULE_TYPES}")
    channel: str = Field(..., description=f"One of: {DELIVERY_CHANNELS}")
    destination: str = Field(
        ...,
        description="Webhook URL, Slack webhook URL, email address, or S3 path",
    )
    org_id: str = Field("default", description="Organisation ID")
    config: Optional[Dict[str, Any]] = Field(
        None,
        description='Extra config, e.g. {"format": "pdf", "filters": {}}',
    )


class UpdateScheduleRequest(BaseModel):
    name: Optional[str] = None
    report_type: Optional[str] = None
    schedule_type: Optional[str] = None
    channel: Optional[str] = None
    destination: Optional[str] = None
    org_id: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    active: Optional[bool] = None


class RunDueRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID to process due schedules for")


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("", summary="Create a report delivery schedule")
def create_schedule(body: CreateScheduleRequest) -> Dict[str, Any]:
    """
    Create a new scheduled report delivery.

    Returns the created schedule including schedule_id and next_run_at.
    """
    sched = _get_scheduler()
    try:
        return sched.create_schedule(
            name=body.name,
            report_type=body.report_type,
            schedule_type=body.schedule_type,
            channel=body.channel,
            destination=body.destination,
            org_id=body.org_id,
            config=body.config,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create schedule")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put("/{schedule_id}", summary="Update a report delivery schedule")
def update_schedule(schedule_id: str, body: UpdateScheduleRequest) -> Dict[str, Any]:
    """
    Update one or more fields of an existing schedule.

    Returns the updated schedule dict.
    """
    sched = _get_scheduler()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        return sched.update_schedule(schedule_id, **updates)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to update schedule %s", schedule_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete("/{schedule_id}", summary="Delete a report delivery schedule")
def delete_schedule(schedule_id: str) -> Dict[str, Any]:
    """
    Delete a schedule by ID.

    Returns {"deleted": true} if found and removed, 404 otherwise.
    """
    sched = _get_scheduler()
    deleted = sched.delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(
            status_code=404, detail=f"Schedule '{schedule_id}' not found"
        )
    return {"deleted": True, "schedule_id": schedule_id}


@router.get("", summary="List report delivery schedules")
def list_schedules(
    org_id: str = Query("default", description="Organisation ID"),
    active_only: bool = Query(True, description="Return only active schedules"),
) -> List[Dict[str, Any]]:
    """
    List all schedules for the given org.

    Use active_only=false to include inactive schedules.
    """
    sched = _get_scheduler()
    return sched.list_schedules(org_id=org_id, active_only=active_only)


@router.get("/log", summary="Delivery log")
def delivery_log(
    schedule_id: Optional[str] = Query(None, description="Filter to a specific schedule"),
    limit: int = Query(50, ge=1, le=500, description="Max rows to return"),
) -> List[Dict[str, Any]]:
    """
    Return delivery history, newest first.

    Optionally filter to a single schedule_id.
    """
    sched = _get_scheduler()
    return sched.get_delivery_log(schedule_id=schedule_id, limit=limit)


@router.get("/{schedule_id}", summary="Get a single report delivery schedule")
def get_schedule(schedule_id: str) -> Dict[str, Any]:
    """
    Retrieve a single schedule by ID.

    Returns 404 if not found.
    """
    sched = _get_scheduler()
    result = sched.get_schedule(schedule_id)
    if result is None:
        raise HTTPException(
            status_code=404, detail=f"Schedule '{schedule_id}' not found"
        )
    return result


@router.post("/{schedule_id}/deliver", summary="Deliver a report now (manual trigger)")
def deliver_now(schedule_id: str) -> Dict[str, Any]:
    """
    Manually trigger delivery of a report for the given schedule.

    Returns delivery result with status 'sent' or 'failed'.
    """
    sched = _get_scheduler()
    try:
        return sched.deliver_report(schedule_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to deliver report for schedule %s", schedule_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/run-due", summary="Run all due schedules")
def run_due(body: RunDueRequest) -> Dict[str, Any]:
    """
    Execute all active schedules whose next_run_at is in the past.

    Returns a list of delivery results.
    """
    sched = _get_scheduler()
    results = sched.run_due_schedules(org_id=body.org_id)
    return {"executed": len(results), "results": results}
