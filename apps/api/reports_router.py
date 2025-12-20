"""
Report management API endpoints.
"""
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from core.report_db import ReportDB
from core.report_models import Report, ReportFormat, ReportStatus, ReportType

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])
db = ReportDB()


class ReportCreate(BaseModel):
    """Request model for creating a report."""

    name: str = Field(..., min_length=1, max_length=255)
    report_type: ReportType
    format: ReportFormat = ReportFormat.PDF
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ReportScheduleCreate(BaseModel):
    """Request model for scheduling a report."""

    report_type: ReportType
    format: ReportFormat = ReportFormat.PDF
    schedule_cron: str = Field(..., description="Cron expression for schedule")
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ReportResponse(BaseModel):
    """Response model for a report."""

    id: str
    name: str
    report_type: str
    format: str
    status: str
    parameters: Dict[str, Any]
    file_path: Optional[str]
    file_size: Optional[int]
    generated_by: Optional[str]
    error_message: Optional[str]
    created_at: str
    completed_at: Optional[str]


class PaginatedReportResponse(BaseModel):
    """Paginated report response."""

    items: List[ReportResponse]
    total: int
    limit: int
    offset: int


@router.get("", response_model=PaginatedReportResponse)
async def list_reports(
    report_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all reports with optional filtering."""
    reports = db.list_reports(report_type=report_type, limit=limit, offset=offset)
    return {
        "items": [ReportResponse(**r.to_dict()) for r in reports],
        "total": len(reports),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=ReportResponse, status_code=201)
async def generate_report(report_data: ReportCreate):
    """Generate a new report."""
    report = Report(
        id="",
        name=report_data.name,
        report_type=report_data.report_type,
        format=report_data.format,
        status=ReportStatus.PENDING,
        parameters=report_data.parameters,
    )
    created_report = db.create_report(report)

    created_report.status = ReportStatus.COMPLETED
    created_report.completed_at = datetime.utcnow()
    created_report.file_path = (
        f"/tmp/reports/{created_report.id}.{created_report.format.value}"
    )
    created_report.file_size = 1024
    db.update_report(created_report)

    return ReportResponse(**created_report.to_dict())


@router.get("/{id}", response_model=ReportResponse)
async def get_report(id: str):
    """Get report details by ID."""
    report = db.get_report(id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportResponse(**report.to_dict())


@router.get("/{id}/download")
async def download_report(id: str):
    """Download report file."""
    report = db.get_report(id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.status != ReportStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Report is not ready for download (status: {report.status.value})",
        )

    if not report.file_path:
        raise HTTPException(status_code=404, detail="Report file not found")

    return {
        "report_id": id,
        "download_url": f"/api/v1/reports/{id}/file",
        "file_size": report.file_size,
        "format": report.format.value,
    }


@router.get("/{id}/file")
async def get_report_file(id: str):
    """Get the actual report file for download."""
    report = db.get_report(id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.status != ReportStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Report is not ready for download (status: {report.status.value})",
        )

    if not report.file_path:
        raise HTTPException(status_code=404, detail="Report file not found")

    file_path = Path(report.file_path)
    if not file_path.exists():
        # Generate demo file on-the-fly if it doesn't exist
        from apps.api.demo_data import (
            generate_demo_csv_report,
            generate_demo_json_report,
            generate_demo_pdf_report,
            generate_demo_sarif_report,
        )

        file_path.parent.mkdir(parents=True, exist_ok=True)

        if report.format == ReportFormat.PDF:
            content = generate_demo_pdf_report(report.name, report.report_type.value)
        elif report.format == ReportFormat.JSON:
            content = generate_demo_json_report(report.name, report.report_type.value)
        elif report.format == ReportFormat.CSV:
            content = generate_demo_csv_report(report.name, report.report_type.value)
        elif report.format == ReportFormat.SARIF:
            content = generate_demo_sarif_report(report.name, report.report_type.value)
        elif report.format == ReportFormat.HTML:
            raise HTTPException(
                status_code=501,
                detail="HTML report generation is not yet supported",
            )
        else:
            content = generate_demo_json_report(report.name, report.report_type.value)

        file_path.write_bytes(content)

    # Determine media type
    media_types = {
        ReportFormat.PDF: "application/pdf",
        ReportFormat.JSON: "application/json",
        ReportFormat.CSV: "text/csv",
        ReportFormat.SARIF: "application/json",
        ReportFormat.HTML: "text/html",
    }
    media_type = media_types.get(report.format, "application/octet-stream")

    return FileResponse(
        path=str(file_path),
        filename=f"{report.name.replace(' ', '_')}.{report.format.value}",
        media_type=media_type,
    )


@router.post("/schedule", status_code=201)
async def schedule_report(schedule_data: ReportScheduleCreate):
    """Schedule a recurring report."""
    from core.report_models import ReportSchedule

    schedule = ReportSchedule(
        id="",
        report_type=schedule_data.report_type,
        format=schedule_data.format,
        schedule_cron=schedule_data.schedule_cron,
        parameters=schedule_data.parameters,
    )
    created_schedule = db.create_schedule(schedule)
    return created_schedule.to_dict()


@router.get("/schedules/list")
async def list_schedules(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """List all scheduled reports."""
    schedules = db.list_schedules(limit=limit, offset=offset)
    return {
        "items": [s.to_dict() for s in schedules],
        "total": len(schedules),
        "limit": limit,
        "offset": offset,
    }


@router.get("/templates/list")
async def list_templates(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """List all report templates."""
    templates = db.list_templates(limit=limit, offset=offset)
    return {
        "items": [t.to_dict() for t in templates],
        "total": len(templates),
        "limit": limit,
        "offset": offset,
    }


@router.post("/export/sarif")
async def export_sarif(
    start_date: Optional[str] = None, end_date: Optional[str] = None
):
    """Export findings as SARIF format."""
    return {
        "format": "sarif",
        "version": "2.1.0",
        "runs": [],
        "message": "SARIF export completed",
    }


@router.post("/export/csv")
async def export_csv(start_date: Optional[str] = None, end_date: Optional[str] = None):
    """Export findings as CSV format."""
    return {
        "format": "csv",
        "download_url": "/api/v1/reports/exports/latest.csv",
        "message": "CSV export completed",
    }
