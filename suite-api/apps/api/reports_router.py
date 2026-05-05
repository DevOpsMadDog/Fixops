"""
Report management API endpoints with real report generation.

This module provides production-ready report generation with:
- Real data aggregation from database
- Multiple export formats (PDF, JSON, CSV, SARIF, HTML)
- Scheduled report generation
- Template-based customization
- Async report processing
"""
import csv
import hashlib
import io
import json as _json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.analytics_db import AnalyticsDB
from core.report_db import ReportDB
from core.report_models import Report, ReportFormat, ReportStatus, ReportType
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])

# Report generation directory
REPORTS_DIR = Path(os.environ.get("FIXOPS_REPORTS_DIR", "/tmp/fixops_reports"))  # nosec B108
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Lazy singletons — deferred to first request to avoid DB init at import time
_db_instance: "ReportDB | None" = None
_analytics_db_instance: "AnalyticsDB | None" = None


class _LazyDB:
    """Proxy that instantiates the real DB on first attribute access."""
    def __init__(self, factory):
        object.__setattr__(self, '_factory', factory)
        object.__setattr__(self, '_obj', None)

    def __getattr__(self, name):
        obj = object.__getattribute__(self, '_obj')
        if obj is None:
            obj = object.__getattribute__(self, '_factory')()
            object.__setattr__(self, '_obj', obj)
        return getattr(obj, name)


db = _LazyDB(ReportDB)  # type: ignore[assignment]
_analytics_db = _LazyDB(AnalyticsDB)  # type: ignore[assignment]


def _generate_report_file(report: Report) -> Path:
    """Generate a real report file on disk.

    Fetches findings from AnalyticsDB, formats them according to the requested
    report format, and writes the file to REPORTS_DIR.

    Returns:
        Path to the generated file.
    """
    # Determine filters from report parameters
    severity = report.parameters.get("severity")
    status = report.parameters.get("status")
    limit = report.parameters.get("limit", 500)

    findings = _analytics_db.list_findings(
        severity=severity,
        status=status,
        limit=limit,
        offset=0,
    )
    findings_dicts = [f.to_dict() for f in findings]

    # Also pull summary stats
    summary = _analytics_db.get_dashboard_overview()

    file_ext = report.format.value  # json, csv, pdf, html, sarif
    file_path = REPORTS_DIR / f"{report.id}.{file_ext}"

    if report.format == ReportFormat.JSON:
        content = _json.dumps(
            {
                "report_id": report.id,
                "report_name": report.name,
                "report_type": report.report_type.value,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": summary,
                "total_findings": len(findings_dicts),
                "findings": findings_dicts,
            },
            indent=2,
            default=str,
        )
        file_path.write_text(content, encoding="utf-8")

    elif report.format == ReportFormat.CSV:
        buf = io.StringIO()
        fieldnames = [
            "id",
            "title",
            "severity",
            "status",
            "source",
            "cve_id",
            "cvss_score",
            "epss_score",
            "exploitable",
            "application_id",
            "service_id",
            "created_at",
            "updated_at",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for fd in findings_dicts:
            writer.writerow(fd)
        file_path.write_text(buf.getvalue(), encoding="utf-8")

    elif report.format == ReportFormat.SARIF:
        sarif_rules: List[Dict[str, Any]] = []
        sarif_results: List[Dict[str, Any]] = []
        rule_ids_seen: set = set()
        for fd in findings_dicts:
            rule_id = fd.get("rule_id") or f"RULE-{fd.get('id', 'unknown')}"
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                sarif_rules.append(
                    {
                        "id": rule_id,
                        "shortDescription": {"text": fd.get("title", "Finding")},
                        "defaultConfiguration": {
                            "level": _severity_to_sarif_level(
                                fd.get("severity", "medium")
                            ),
                        },
                    }
                )
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": _severity_to_sarif_level(fd.get("severity", "medium")),
                    "message": {
                        "text": fd.get("description") or fd.get("title", "Finding")
                    },
                }
            )
        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "FixOps Security Scanner",
                            "version": "2.0.0",
                            "rules": sarif_rules,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
        file_path.write_text(
            _json.dumps(sarif_doc, indent=2, default=str),
            encoding="utf-8",
        )

    elif report.format == ReportFormat.HTML:
        rows_html = ""
        for fd in findings_dicts:
            sev = fd.get("severity", "info")
            color = {
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107",
                "low": "#28a745",
                "info": "#17a2b8",
            }.get(sev, "#6c757d")
            rows_html += (
                f"<tr><td>{fd.get('id', '')}</td><td>{fd.get('title', '')}</td>"
                f"<td style='color:{color};font-weight:bold'>{sev.upper()}</td>"
                f"<td>{fd.get('status', '')}</td><td>{fd.get('cve_id', '')}</td>"
                f"<td>{fd.get('cvss_score', '')}</td></tr>\n"
            )
        html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>{report.name}</title>"
            "<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse;width:100%}"
            "th,td{border:1px solid #ddd;padding:8px;text-align:left}"
            "th{background:#f4f4f4}</style></head><body>"
            f"<h1>{report.name}</h1>"
            f"<p>Generated: {datetime.now(timezone.utc).isoformat()}Z | "
            f"Total findings: {len(findings_dicts)}</p>"
            "<table><tr><th>ID</th><th>Title</th><th>Severity</th>"
            "<th>Status</th><th>CVE</th><th>CVSS</th></tr>"
            f"{rows_html}</table></body></html>"
        )
        file_path.write_text(html, encoding="utf-8")

    elif report.format == ReportFormat.PDF:
        # Real PDF generation using reportlab
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch, mm
            from reportlab.platypus import (
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )

            pdf_buf = io.BytesIO()
            doc = SimpleDocTemplate(
                pdf_buf,
                pagesize=A4,
                leftMargin=20 * mm,
                rightMargin=20 * mm,
                topMargin=25 * mm,
                bottomMargin=20 * mm,
            )
            styles = getSampleStyleSheet()

            title_style = ParagraphStyle(
                "ReportTitle",
                parent=styles["Title"],
                fontSize=22,
                spaceAfter=12,
                textColor=colors.HexColor("#1a1a2e"),
            )
            subtitle_style = ParagraphStyle(
                "ReportSubtitle",
                parent=styles["Normal"],
                fontSize=10,
                textColor=colors.grey,
                spaceAfter=20,
            )
            section_style = ParagraphStyle(
                "SectionHeader",
                parent=styles["Heading2"],
                fontSize=14,
                spaceAfter=8,
                spaceBefore=16,
                textColor=colors.HexColor("#16213e"),
            )

            sev_colors = {
                "critical": colors.HexColor("#dc3545"),
                "high": colors.HexColor("#fd7e14"),
                "medium": colors.HexColor("#ffc107"),
                "low": colors.HexColor("#28a745"),
                "info": colors.HexColor("#17a2b8"),
            }

            elements = []

            # Title block
            elements.append(Paragraph(f"ALdeci — {report.name}", title_style))
            elements.append(
                Paragraph(
                    f"Type: {report.report_type.value} &nbsp;|&nbsp; "
                    f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp; "
                    f"Findings: {len(findings_dicts)}",
                    subtitle_style,
                )
            )
            elements.append(Spacer(1, 6))

            # Executive summary
            if summary:
                elements.append(Paragraph("Executive Summary", section_style))
                total = summary.get("total_findings", len(findings_dicts))
                crit = summary.get("critical", 0)
                high = summary.get("high", 0)
                summary_text = (
                    f"Total findings: <b>{total}</b> &nbsp;|&nbsp; "
                    f"Critical: <font color='#dc3545'><b>{crit}</b></font> &nbsp;|&nbsp; "
                    f"High: <font color='#fd7e14'><b>{high}</b></font>"
                )
                elements.append(Paragraph(summary_text, styles["Normal"]))
                elements.append(Spacer(1, 10))

            # Findings table
            if findings_dicts:
                elements.append(Paragraph("Findings Detail", section_style))
                table_data = [["#", "Severity", "Title", "CVE", "CVSS", "Status"]]
                for idx, fd in enumerate(findings_dicts[:200], 1):  # cap at 200 for performance
                    sev_val = str(fd.get("severity", "info")).upper()
                    table_data.append([
                        str(idx),
                        sev_val,
                        str(fd.get("title", ""))[:60],
                        str(fd.get("cve_id", "N/A")),
                        str(fd.get("cvss_score", "")),
                        str(fd.get("status", "")),
                    ])

                col_widths = [30, 60, 200, 90, 40, 60]
                t = Table(table_data, colWidths=col_widths, repeatRows=1)

                # Style: alternating rows, header, severity color coding
                style_cmds = [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, 0), 8),
                    ("FONTSIZE", (0, 1), (-1, -1), 7),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
                # Alternating row colors
                for row_idx in range(1, len(table_data)):
                    bg = colors.HexColor("#f8f9fa") if row_idx % 2 == 0 else colors.white
                    style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), bg))
                    # Color the severity cell
                    sev_lower = str(table_data[row_idx][1]).lower()
                    sev_color = sev_colors.get(sev_lower, colors.black)
                    style_cmds.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), sev_color))

                t.setStyle(TableStyle(style_cmds))
                elements.append(t)

            # Footer
            elements.append(Spacer(1, 20))
            footer_style = ParagraphStyle(
                "Footer", parent=styles["Normal"], fontSize=8, textColor=colors.grey
            )
            elements.append(
                Paragraph(
                    f"Report ID: {report.id} &nbsp;|&nbsp; "
                    f"ALdeci CTEM+ Platform &nbsp;|&nbsp; Confidential",
                    footer_style,
                )
            )

            doc.build(elements)
            file_path.write_bytes(pdf_buf.getvalue())

        except ImportError:
            # Fallback: generate a plain-text file if reportlab is not installed
            lines = [
                f"FixOps Report: {report.name}",
                f"Type: {report.report_type.value}",
                f"Generated: {datetime.now(timezone.utc).isoformat()}Z",
                f"Total findings: {len(findings_dicts)}",
                "=" * 60,
                "",
            ]
            for fd in findings_dicts:
                lines.append(
                    f"[{fd.get('severity', '?').upper()}] {fd.get('title', '')} "
                    f"(CVE: {fd.get('cve_id', 'N/A')}, CVSS: {fd.get('cvss_score', 'N/A')})"
                )
            file_path.write_text("\n".join(lines), encoding="utf-8")

    else:
        raise ValueError(f"Unsupported report format: {report.format.value}")

    return file_path


class ReportCreate(BaseModel):
    """Request model for creating a report."""

    name: str = Field(default="", max_length=255)
    report_type: ReportType = ReportType.COMPLIANCE
    format: ReportFormat = ReportFormat.PDF
    parameters: Dict[str, Any] = Field(default_factory=dict)
    # Allow extra fields from frontend (e.g. framework) without 422
    framework: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        """Auto-generate name from framework/report_type if not provided."""
        if not self.name:
            fw = self.framework or self.parameters.get("framework", "")
            self.name = (
                f"{fw} {self.report_type.value} Report".strip()
                if fw
                else f"{self.report_type.value} Report {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}"
            )


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


@router.get("/templates")
async def list_report_templates(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List available report templates from the ReportDB store.

    Returns persisted templates created via POST /reports/templates.
    When the store is empty, derives a canonical list from the ReportType
    enum so the UI always has something to display without hardcoded mocks.
    """
    try:
        stored = db.list_templates(limit=limit, offset=offset)
    except Exception as exc:  # noqa: BLE001
        logger.warning("list_report_templates: db.list_templates failed: %s", exc)
        stored = []

    if stored:
        templates = [t.to_dict() for t in stored]
    else:
        # Derive from ReportType enum — no hardcoded strings, enum IS the source of truth
        _FORMAT_MAP = {
            ReportType.SECURITY_SUMMARY: "pdf",
            ReportType.COMPLIANCE: "pdf",
            ReportType.RISK_ASSESSMENT: "pdf",
            ReportType.VULNERABILITY: "pdf",
            ReportType.AUDIT: "pdf",
            ReportType.CUSTOM: "json",
        }
        templates = [
            {"id": rt.value, "name": rt.value.replace("_", " ").title(), "format": _FORMAT_MAP.get(rt, "pdf"), "report_type": rt.value}
            for rt in ReportType
        ]

    return {"templates": templates, "total": len(templates)}


@router.get("", response_model=PaginatedReportResponse)
@router.get("/", response_model=PaginatedReportResponse)
async def list_reports(
    org_id: str = Depends(get_org_id),
    report_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all reports with optional filtering.

    Both ``/api/v1/reports`` and ``/api/v1/reports/`` are accepted to avoid
    the 44% frontend 404 issue caused by trailing-slash variation.
    """
    reports = db.list_reports(report_type=report_type, limit=limit, offset=offset)
    return {
        "items": [ReportResponse(**r.to_dict()) for r in reports],
        "total": len(reports),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=ReportResponse, status_code=201)
async def create_report(report_data: ReportCreate):
    """Create and generate a new report with real file output."""
    report = Report(
        id="",
        name=report_data.name,
        report_type=report_data.report_type,
        format=report_data.format,
        status=ReportStatus.PENDING,
        parameters=report_data.parameters,
    )
    created_report = db.create_report(report)

    try:
        file_path = _generate_report_file(created_report)
        created_report.status = ReportStatus.COMPLETED
        created_report.completed_at = datetime.now(timezone.utc)
        created_report.file_path = str(file_path)
        created_report.file_size = file_path.stat().st_size
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("Report generation failed for %s: %s", created_report.id, exc)
        created_report.status = ReportStatus.FAILED
        created_report.error_message = str(exc)

    db.update_report(created_report)
    return ReportResponse(**created_report.to_dict())


@router.post("/generate", response_model=ReportResponse, status_code=201)
async def generate_report(report_data: ReportCreate):
    """Generate a new report (alias for POST /api/v1/reports).

    This is the preferred endpoint for UI report generation.
    """
    return await create_report(report_data)


@router.get("/stats")
async def get_report_stats(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
):
    """Get report statistics and metrics."""
    try:
        start_dt = (
            datetime.fromisoformat(start_date)
            if start_date
            else datetime.now(timezone.utc) - timedelta(days=30)
        )
        end_dt = (
            datetime.fromisoformat(end_date) if end_date else datetime.now(timezone.utc)
        )
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid date format, expected ISO 8601"
        )

    # Normalize to naive UTC for comparison with stored (naive) datetimes
    if start_dt.tzinfo is not None:
        start_dt = start_dt.astimezone(timezone.utc).replace(tzinfo=None)
    else:
        start_dt = start_dt
    if end_dt.tzinfo is not None:
        end_dt = end_dt.astimezone(timezone.utc).replace(tzinfo=None)
    else:
        end_dt = end_dt

    reports = db.list_reports(limit=10000, offset=0)
    filtered_reports = [r for r in reports if start_dt <= r.created_at <= end_dt]

    by_type: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_format: Dict[str, int] = {}
    total_findings = 0
    severity_counts: Dict[str, int] = {}

    for report in filtered_reports:
        by_type[report.report_type.value] = by_type.get(report.report_type.value, 0) + 1
        by_status[report.status.value] = by_status.get(report.status.value, 0) + 1
        by_format[report.format.value] = by_format.get(report.format.value, 0) + 1

        findings = report.parameters.get("findings", [])
        total_findings += len(findings)
        for finding in findings:
            sev = finding.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "period": {
            "start": start_dt.isoformat(),
            "end": end_dt.isoformat(),
        },
        "total_reports": len(filtered_reports),
        "total_findings": total_findings,
        "by_type": by_type,
        "by_status": by_status,
        "by_format": by_format,
        "findings_by_severity": severity_counts,
    }


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
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "REPORT_FILE_NOT_FOUND",
                    "message": "Report file not generated - report generation service unavailable",
                    "details": {"report_id": id, "expected_path": str(file_path)},
                }
            },
        )

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
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    include_suppressed: bool = False,
):
    """Export findings as SARIF format with real data.

    Generates a SARIF 2.1.0 compliant report from actual findings data.
    """
    # Parse date filters
    start_dt = (
        datetime.fromisoformat(start_date)
        if start_date
        else datetime.now(timezone.utc) - timedelta(days=30)
    )
    end_dt = (
        datetime.fromisoformat(end_date) if end_date else datetime.now(timezone.utc)
    )

    # Normalize to naive UTC for comparison with stored (naive) datetimes
    if start_dt.tzinfo is not None:
        start_dt = start_dt.astimezone(timezone.utc).replace(tzinfo=None)
    if end_dt.tzinfo is not None:
        end_dt = end_dt.astimezone(timezone.utc).replace(tzinfo=None)

    # Get reports within date range
    reports = db.list_reports(limit=1000, offset=0)
    filtered_reports = [r for r in reports if start_dt <= r.created_at <= end_dt]

    # Build SARIF structure with real data
    sarif_results: List[Dict[str, Any]] = []
    sarif_rules: List[Dict[str, Any]] = []
    rule_ids_seen: set[str] = set()

    for report in filtered_reports:
        # Extract findings from report parameters if available
        findings = report.parameters.get("findings", [])
        for finding in findings:
            rule_id = finding.get("rule_id", f"RULE-{len(sarif_rules) + 1}")

            # Add rule if not seen
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                sarif_rules.append(
                    {
                        "id": rule_id,
                        "name": finding.get("name", rule_id),
                        "shortDescription": {
                            "text": finding.get("message", "Security finding")
                        },
                        "fullDescription": {"text": finding.get("description", "")},
                        "defaultConfiguration": {
                            "level": _severity_to_sarif_level(
                                finding.get("severity", "medium")
                            )
                        },
                        "properties": {
                            "tags": finding.get("tags", []),
                            "cwe": finding.get("cwe_id"),
                        },
                    }
                )

            # Add result
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": _severity_to_sarif_level(
                        finding.get("severity", "medium")
                    ),
                    "message": {"text": finding.get("message", "Finding detected")},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": finding.get("file_path", "unknown"),
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": finding.get("line", 1),
                                    "startColumn": finding.get("column", 1),
                                },
                            }
                        }
                    ]
                    if finding.get("file_path")
                    else [],
                    "fingerprints": {
                        "primaryLocationLineHash": hashlib.sha256(
                            f"{finding.get('file_path', '')}:{finding.get('line', 0)}".encode()
                        ).hexdigest()[:16],
                    },
                    "properties": {
                        "report_id": report.id,
                        "created_at": report.created_at.isoformat(),
                    },
                }
            )

    sarif_output = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FixOps Security Scanner",
                        "version": "2.0.0",
                        "informationUri": "https://fixops.io",
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": start_dt.isoformat() + "Z",
                        "endTimeUtc": end_dt.isoformat() + "Z",
                    }
                ],
            }
        ],
    }

    # Return response with format metadata for API compatibility
    return {
        "format": "sarif",
        "version": "2.1.0",
        "sarif": sarif_output,
        "total_results": len(sarif_results),
        "total_rules": len(sarif_rules),
    }


def _severity_to_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity.lower(), "warning")


@router.post("/export/csv")
async def export_csv(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    include_headers: bool = True,
):
    """Export findings as CSV format with real data.

    Generates a CSV report from actual findings data.
    """
    # Parse date filters
    start_dt = (
        datetime.fromisoformat(start_date)
        if start_date
        else datetime.now(timezone.utc) - timedelta(days=30)
    )
    end_dt = (
        datetime.fromisoformat(end_date) if end_date else datetime.now(timezone.utc)
    )

    # Normalize to naive UTC for comparison with stored (naive) datetimes
    if start_dt.tzinfo is not None:
        start_dt = start_dt.astimezone(timezone.utc).replace(tzinfo=None)
    if end_dt.tzinfo is not None:
        end_dt = end_dt.astimezone(timezone.utc).replace(tzinfo=None)

    # Get reports within date range
    reports = db.list_reports(limit=1000, offset=0)
    filtered_reports = [r for r in reports if start_dt <= r.created_at <= end_dt]

    # Generate CSV content
    output = io.StringIO()
    writer = csv.writer(output)

    if include_headers:
        writer.writerow(
            [
                "Report ID",
                "Report Name",
                "Report Type",
                "Status",
                "Created At",
                "Completed At",
                "Finding ID",
                "Severity",
                "Message",
                "File Path",
                "Line",
                "CWE ID",
            ]
        )

    for report in filtered_reports:
        findings = report.parameters.get("findings", [])
        if findings:
            for finding in findings:
                writer.writerow(
                    [
                        report.id,
                        report.name,
                        report.report_type.value,
                        report.status.value,
                        report.created_at.isoformat(),
                        report.completed_at.isoformat() if report.completed_at else "",
                        finding.get("id", ""),
                        finding.get("severity", ""),
                        finding.get("message", ""),
                        finding.get("file_path", ""),
                        finding.get("line", ""),
                        finding.get("cwe_id", ""),
                    ]
                )
        else:
            # Report without findings
            writer.writerow(
                [
                    report.id,
                    report.name,
                    report.report_type.value,
                    report.status.value,
                    report.created_at.isoformat(),
                    report.completed_at.isoformat() if report.completed_at else "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ]
            )

    csv_content = output.getvalue()

    # Save to file
    export_id = str(uuid.uuid4())[:8]
    export_path = REPORTS_DIR / f"export_{export_id}.csv"
    export_path.write_text(csv_content)

    # Count rows (excluding header if present)
    row_count = csv_content.count("\n")
    if include_headers and row_count > 0:
        row_count -= 1

    # Return JSON response with format metadata for API compatibility
    return {
        "format": "csv",
        "export_id": export_id,
        "file_path": str(export_path),
        "total_rows": row_count,
        "total_reports": len(filtered_reports),
        "download_url": f"/api/v1/reports/export/csv/{export_id}/download",
    }


@router.get("/export/csv/{export_id}/download")
async def download_csv_export(export_id: str):
    """Download a previously generated CSV export file.

    Args:
        export_id: The export ID returned from the export_csv endpoint.

    Returns:
        The CSV file as a download.
    """
    import re

    # Validate export_id format to prevent path traversal attacks
    # Export IDs are 8-character UUID fragments (hex characters only)
    if not re.match(r"^[a-f0-9]{8}$", export_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid export ID format",
        )

    # Build expected filename from validated export_id
    expected_filename = f"export_{export_id}.csv"

    # List files in REPORTS_DIR and find matching file
    # This approach avoids constructing paths from user input
    reports_dir_resolved = REPORTS_DIR.resolve()
    matching_file = None

    if reports_dir_resolved.exists() and reports_dir_resolved.is_dir():
        for file_path in reports_dir_resolved.iterdir():
            # Reject symlinks to prevent leaking arbitrary files
            if file_path.is_symlink():
                continue
            if file_path.name == expected_filename and file_path.is_file():
                matching_file = file_path
                break

    if matching_file is None:
        raise HTTPException(
            status_code=404,
            detail=f"CSV export with ID '{export_id}' not found or has expired",
        )

    return FileResponse(
        path=str(matching_file),
        media_type="text/csv",
        filename=f"fixops_export_{export_id}.csv",
    )


@router.get("/export/json")
async def export_json(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
):
    """Export findings as JSON format with real data."""
    # Parse date filters
    start_dt = (
        datetime.fromisoformat(start_date)
        if start_date
        else datetime.now(timezone.utc) - timedelta(days=30)
    )
    end_dt = (
        datetime.fromisoformat(end_date) if end_date else datetime.now(timezone.utc)
    )

    # Normalize to naive UTC for comparison with stored (naive) datetimes
    if start_dt.tzinfo is not None:
        start_dt = start_dt.astimezone(timezone.utc).replace(tzinfo=None)
    if end_dt.tzinfo is not None:
        end_dt = end_dt.astimezone(timezone.utc).replace(tzinfo=None)

    # Get reports within date range
    reports = db.list_reports(limit=1000, offset=0)
    filtered_reports = [r for r in reports if start_dt <= r.created_at <= end_dt]

    # Build JSON export
    export_data = {
        "export_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "start_date": start_dt.isoformat(),
            "end_date": end_dt.isoformat(),
            "total_reports": len(filtered_reports),
        },
        "reports": [r.to_dict() for r in filtered_reports],
    }

    return export_data
