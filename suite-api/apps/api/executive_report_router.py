"""
Executive Report API endpoints — ALDECI.

Provides board-ready security posture report generation, retrieval,
JSON export, and schedule management.

Protected with API key authentication (injected via app.include_router
dependencies — see app.py).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.executive_reports import (
    ExecutiveReport,
    ExecutiveReportEngine,
    ReportFrequency,
    ReportSchedule,
    ReportType,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/api/v1/reports/executive",
    tags=["executive-reports"],
)

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = ExecutiveReportEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class GenerateReportRequest(BaseModel):
    """Request body for report generation."""

    type: ReportType = Field(..., description="Report type to generate")
    org_id: str = Field("default", description="Organisation identifier")
    period_start: Optional[str] = Field(
        None, description="Period start (ISO 8601). Defaults to 30 days ago."
    )
    period_end: Optional[str] = Field(
        None, description="Period end (ISO 8601). Defaults to now."
    )
    frequency: ReportFrequency = Field(
        ReportFrequency.ON_DEMAND, description="Report frequency label"
    )


class CreateScheduleRequest(BaseModel):
    """Request body for schedule creation."""

    report_type: ReportType = Field(..., description="Report type to schedule")
    frequency: ReportFrequency = Field(..., description="Generation frequency")
    recipients: List[str] = Field(
        default_factory=list,
        description="Email addresses or identifiers for delivery",
    )
    org_id: str = Field("default", description="Organisation identifier")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_date(value: Optional[str], param_name: str) -> Optional[datetime]:
    """Parse an ISO date string into a UTC-aware datetime or raise 422."""
    if value is None:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid date format for '{param_name}'. "
                "Use ISO 8601 (e.g. 2024-01-01 or 2024-01-01T00:00:00Z)."
            ),
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/generate", response_model=ExecutiveReport, status_code=201)
async def generate_report(body: GenerateReportRequest) -> ExecutiveReport:
    """
    Generate a board-ready executive report for the requested type and period.

    Returns the full report including all sections.
    """
    start_dt = _parse_date(body.period_start, "period_start")
    end_dt = _parse_date(body.period_end, "period_end")

    try:
        report = _get_engine().generate_report(
            type=body.type,
            org_id=body.org_id,
            period_start=start_dt,
            period_end=end_dt,
            frequency=body.frequency,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return report


@router.get("", response_model=List[ExecutiveReport])
async def list_reports(
    org_id: str = Query("default", description="Organisation identifier"),
    type: Optional[ReportType] = Query(None, description="Filter by report type"),
    limit: int = Query(50, ge=1, le=200, description="Maximum results to return"),
) -> List[ExecutiveReport]:
    """List executive reports for an organisation, newest first."""
    return _get_engine().list_reports(org_id=org_id, type_filter=type, limit=limit)


@router.get("/{report_id}", response_model=ExecutiveReport)
async def get_report(report_id: str) -> ExecutiveReport:
    """Retrieve a single executive report by ID."""
    report = _get_engine().get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found")
    return report


@router.get("/{report_id}/export")
async def export_report_json(report_id: str) -> Dict[str, Any]:
    """Export a report as a JSON object."""
    report = _get_engine().get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found")
    import json
    return json.loads(_get_engine().export_json(report_id))


@router.post("/schedules", response_model=ReportSchedule, status_code=201)
async def create_schedule(body: CreateScheduleRequest) -> ReportSchedule:
    """Create a report schedule for recurring generation."""
    try:
        schedule = _get_engine().schedule_report(
            report_type=body.report_type,
            frequency=body.frequency,
            recipients=body.recipients,
            org_id=body.org_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return schedule


@router.get("/schedules/list", response_model=List[ReportSchedule])
async def list_schedules(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[ReportSchedule]:
    """List all report schedules for an organisation."""
    return _get_engine().list_schedules(org_id=org_id)


@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: str) -> None:
    """Delete a report schedule by ID."""
    deleted = _get_engine().delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(
            status_code=404, detail=f"Schedule '{schedule_id}' not found"
        )
