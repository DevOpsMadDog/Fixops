"""Scheduled Reports Router — ALDECI.

REST endpoints for managing report schedules, triggering runs, templates, and stats.

Prefix: /api/v1/scheduled-reports
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/scheduled-reports/schedules              list_schedules
  POST   /api/v1/scheduled-reports/schedules              create_schedule
  GET    /api/v1/scheduled-reports/schedules/{id}         get_schedule
  PATCH  /api/v1/scheduled-reports/schedules/{id}         update_schedule
  POST   /api/v1/scheduled-reports/schedules/{id}/pause   pause_schedule
  POST   /api/v1/scheduled-reports/schedules/{id}/resume  resume_schedule
  DELETE /api/v1/scheduled-reports/schedules/{id}         delete_schedule
  POST   /api/v1/scheduled-reports/schedules/{id}/trigger trigger_report
  GET    /api/v1/scheduled-reports/runs                   list_runs
  GET    /api/v1/scheduled-reports/runs/{id}              get_run
  GET    /api/v1/scheduled-reports/templates              list_templates
  POST   /api/v1/scheduled-reports/templates              create_template
  GET    /api/v1/scheduled-reports/stats                  get_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/scheduled-reports",
    tags=["Scheduled Reports"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.scheduled_reports_engine import ScheduledReportsEngine
        _engine = ScheduledReportsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScheduleCreate(BaseModel):
    name: str
    report_type: str = "executive_summary"
    frequency: str = "weekly"
    hour_utc: int = Field(default=8, ge=0, le=23)
    day_of_week: Optional[int] = Field(default=None, ge=0, le=6)
    day_of_month: Optional[int] = Field(default=None, ge=1, le=31)
    recipients: List[str] = Field(default_factory=list)
    slack_webhook_url: str = ""
    format: str = "json"


class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    report_type: Optional[str] = None
    frequency: Optional[str] = None
    hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    day_of_week: Optional[int] = Field(default=None, ge=0, le=6)
    day_of_month: Optional[int] = Field(default=None, ge=1, le=31)
    recipients: Optional[List[str]] = None
    slack_webhook_url: Optional[str] = None
    format: Optional[str] = None


class TriggerRequest(BaseModel):
    override_recipients: Optional[List[str]] = None


class TemplateCreate(BaseModel):
    name: str
    report_type: str = "executive_summary"
    sections: List[str] = Field(default_factory=list)
    description: str = ""


# ---------------------------------------------------------------------------
# Schedule routes
# ---------------------------------------------------------------------------

@router.get("/schedules", dependencies=[Depends(api_key_auth)])
def list_schedules(
    org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(default=None),
    report_type: Optional[str] = Query(default=None),
):
    """List report schedules, optionally filtered by enabled status and report_type."""
    return _get_engine().list_schedules(org_id, enabled=enabled, report_type=report_type)


@router.post("/schedules", dependencies=[Depends(api_key_auth)], status_code=201)
def create_schedule(
    body: ScheduleCreate,
    org_id: str = Query(default="default"),
):
    """Create a new report schedule."""
    try:
        return _get_engine().create_schedule(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/schedules/{schedule_id}", dependencies=[Depends(api_key_auth)])
def get_schedule(schedule_id: str, org_id: str = Query(default="default")):
    """Get a single report schedule by ID."""
    sched = _get_engine().get_schedule(org_id, schedule_id)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return sched


@router.patch("/schedules/{schedule_id}", dependencies=[Depends(api_key_auth)])
def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    org_id: str = Query(default="default"),
):
    """Update fields on an existing schedule."""
    try:
        updates = {k: v for k, v in body.model_dump().items() if v is not None}
        return _get_engine().update_schedule(org_id, schedule_id, updates)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/schedules/{schedule_id}/pause", dependencies=[Depends(api_key_auth)])
def pause_schedule(schedule_id: str, org_id: str = Query(default="default")):
    """Pause a schedule (stops automatic execution)."""
    try:
        return _get_engine().pause_schedule(org_id, schedule_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/schedules/{schedule_id}/resume", dependencies=[Depends(api_key_auth)])
def resume_schedule(schedule_id: str, org_id: str = Query(default="default")):
    """Resume a paused schedule and recalculate next_run_at."""
    try:
        return _get_engine().resume_schedule(org_id, schedule_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/schedules/{schedule_id}", dependencies=[Depends(api_key_auth)])
def delete_schedule(schedule_id: str, org_id: str = Query(default="default")):
    """Permanently delete a report schedule."""
    deleted = _get_engine().delete_schedule(org_id, schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"deleted": True, "schedule_id": schedule_id}


@router.post(
    "/schedules/{schedule_id}/trigger",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def trigger_report(
    schedule_id: str,
    body: TriggerRequest,
    org_id: str = Query(default="default"),
):
    """Immediately trigger a report run for the given schedule."""
    try:
        return _get_engine().trigger_report(
            org_id, schedule_id, override_recipients=body.override_recipients
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Run routes
# ---------------------------------------------------------------------------

@router.get("/runs", dependencies=[Depends(api_key_auth)])
def list_runs(
    org_id: str = Query(default="default"),
    schedule_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
):
    """List report runs, optionally filtered by schedule and/or status."""
    return _get_engine().list_runs(
        org_id, schedule_id=schedule_id, status=status, limit=limit
    )


@router.get("/runs/{run_id}", dependencies=[Depends(api_key_auth)])
def get_run(run_id: str, org_id: str = Query(default="default")):
    """Get a single report run by ID."""
    run = _get_engine().get_run(org_id, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


# ---------------------------------------------------------------------------
# Template routes
# ---------------------------------------------------------------------------

@router.get("/templates", dependencies=[Depends(api_key_auth)])
def list_templates(
    org_id: str = Query(default="default"),
    report_type: Optional[str] = Query(default=None),
):
    """List report templates, optionally filtered by report_type."""
    return _get_engine().list_templates(org_id, report_type=report_type)


@router.post("/templates", dependencies=[Depends(api_key_auth)], status_code=201)
def create_template(
    body: TemplateCreate,
    org_id: str = Query(default="default"),
):
    """Create a new report template."""
    try:
        return _get_engine().create_template(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")):
    """Return aggregated scheduled-reports statistics for the org."""
    return _get_engine().get_stats(org_id)


# ---------------------------------------------------------------------------
# Default schedule seeding
# ---------------------------------------------------------------------------

@router.post("/seed-defaults", dependencies=[Depends(api_key_auth)], status_code=201)
def seed_defaults(
    org_id: str = Query(default="default"),
    overwrite: bool = Query(default=False),
):
    """Create the 3 canonical ALDECI report schedules for an org if they don't exist.

    Schedules created:
    - Daily Security Posture Summary (daily at 06:00 UTC)
    - Weekly Executive Briefing (Monday at 08:00 UTC)
    - Monthly Compliance Report (1st of month at 07:00 UTC)

    Set overwrite=true to delete and re-create any existing default schedules.
    Returns the list of newly created schedules (empty if all already exist).
    """
    return _get_engine().seed_default_schedules(org_id, overwrite=overwrite)
