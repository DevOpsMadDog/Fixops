"""Executive Reporting API Router — ALDECI.

Endpoints (all under /api/v1/exec-reporting):

  Reports:
    POST   /reports              — create executive report
    GET    /reports              — list reports (filter: report_type, status)
    GET    /reports/{id}         — get report + metrics
    POST   /reports/{id}/metrics — add metric to report
    POST   /reports/{id}/publish — publish report

  KPIs:
    GET    /kpis                 — list all KPIs
    POST   /kpis                 — upsert KPI
    GET    /kpis/{name}          — get single KPI

  Board presentations:
    POST   /board-presentations  — create board presentation
    GET    /board-presentations  — list all presentations

  Summary:
    GET    /summary              — aggregated exec summary

Auth: api_key_auth from apps.api.auth_deps
"""
from __future__ import annotations

import io
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from apps.api.billing_router import requires_tier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/exec-reporting", tags=["exec-reporting"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.executive_reporting_engine import ExecutiveReportingEngine
        _engine = ExecutiveReportingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ReportIn(BaseModel):
    report_type: str = "monthly"
    title: str = ""
    period_start: str = ""
    period_end: str = ""
    sections: List[str] = Field(default_factory=list)
    created_by: str = ""


class MetricIn(BaseModel):
    metric_name: str
    metric_value: float = 0.0
    metric_unit: str = ""
    trend: str = "stable"
    comparison_value: float = 0.0
    comparison_period: str = ""
    narrative: str = ""


class KPIIn(BaseModel):
    kpi_name: str
    kpi_value: float
    target_value: float
    kpi_unit: str = ""
    trend: str = "stable"


class BoardPresentationIn(BaseModel):
    title: str = ""
    presentation_date: str = ""
    audience: str = "board"
    risk_summary: str = ""
    key_metrics: Dict[str, Any] = Field(default_factory=dict)
    action_items: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@router.post("/reports", status_code=201)
def create_report(
    payload: ReportIn,
    org_id: str = Depends(requires_tier("pro")),
) -> Dict[str, Any]:
    """Create an executive report."""
    try:
        return _get_engine().create_report(org_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("create_report failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/reports")
def list_reports(
    org_id: str = Query("default"),
    report_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List executive reports."""
    try:
        return _get_engine().list_reports(org_id, report_type=report_type, status=status)
    except Exception as exc:
        logger.exception("list_reports failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/reports/{report_id}")
def get_report(
    report_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get a report with its metrics."""
    try:
        result = _get_engine().get_report(org_id, report_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_report failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/reports/{report_id}/metrics", status_code=201)
def add_metric(
    report_id: str,
    payload: MetricIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Add a metric to a report."""
    try:
        return _get_engine().add_metric(org_id, report_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("add_metric failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/reports/{report_id}/publish")
def publish_report(
    report_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Publish a report."""
    try:
        ok = _get_engine().publish_report(org_id, report_id)
        if not ok:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        return {"report_id": report_id, "status": "published"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("publish_report failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# KPIs
# ---------------------------------------------------------------------------

@router.post("/kpis", status_code=201)
def set_kpi(
    payload: KPIIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Upsert a KPI."""
    try:
        return _get_engine().set_kpi(
            org_id,
            payload.kpi_name,
            payload.kpi_value,
            payload.target_value,
            payload.kpi_unit,
            payload.trend,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("set_kpi failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/kpis")
def list_kpis(
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """List all KPIs for org."""
    try:
        return _get_engine().list_kpis(org_id)
    except Exception as exc:
        logger.exception("list_kpis failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/kpis/{kpi_name}")
def get_kpi(
    kpi_name: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get a single KPI by name."""
    try:
        result = _get_engine().get_kpi(org_id, kpi_name)
        if result is None:
            raise HTTPException(status_code=404, detail=f"KPI '{kpi_name}' not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_kpi failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Board presentations
# ---------------------------------------------------------------------------

@router.post("/board-presentations", status_code=201)
def create_board_presentation(
    payload: BoardPresentationIn,
    org_id: str = Depends(requires_tier("enterprise")),
) -> Dict[str, Any]:
    """Create a board presentation."""
    try:
        return _get_engine().create_board_presentation(org_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("create_board_presentation failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/board-presentations")
def list_board_presentations(
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """List all board presentations."""
    try:
        return _get_engine().list_board_presentations(org_id)
    except Exception as exc:
        logger.exception("list_board_presentations failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

@router.get("/summary")
def get_exec_summary(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return aggregated executive summary."""
    try:
        return _get_engine().get_exec_summary(org_id)
    except Exception as exc:
        logger.exception("get_exec_summary failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/context/{entity_id}")
def get_trustgraph_context(
    entity_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return TrustGraph cross-domain context for an entity (related assets, findings, incidents)."""
    return _get_engine().get_trustgraph_context(org_id, entity_id)


# ---------------------------------------------------------------------------
# PDF Export
# ---------------------------------------------------------------------------

def _build_pdf_bytes(report: Dict[str, Any], kpis: List[Dict[str, Any]]) -> bytes:
    """Generate a PDF for an executive report using reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ExecTitle", parent=styles["Title"], fontSize=22, spaceAfter=4
    )
    h2_style = ParagraphStyle(
        "ExecH2", parent=styles["Heading2"], fontSize=13, spaceAfter=4
    )
    normal = styles["Normal"]

    story = []

    # Header
    story.append(Paragraph("ALDECI Executive Report", title_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.darkblue))
    story.append(Spacer(1, 0.15 * inch))

    # Report metadata
    meta = [
        ["Report Title", report.get("title") or report.get("report_type", "Executive Report")],
        ["Report Type", report.get("report_type", "monthly")],
        ["Status", report.get("status", "draft")],
        ["Period", f"{report.get('period_start', '')} – {report.get('period_end', '')}"],
        ["Created By", report.get("created_by", "ALDECI Platform")],
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
    ]
    meta_table = Table(meta, colWidths=[1.8 * inch, 4.5 * inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#003366")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.whitesmoke, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.2 * inch))

    # KPIs section
    if kpis:
        story.append(Paragraph("Key Performance Indicators", h2_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
        story.append(Spacer(1, 0.08 * inch))

        kpi_data = [["KPI Name", "Value", "Target", "Unit", "Trend"]]
        for k in kpis:
            val = k.get("kpi_value", 0)
            target = k.get("target_value", 0)
            kpi_data.append([
                k.get("kpi_name", ""),
                f"{val:.1f}",
                f"{target:.1f}",
                k.get("kpi_unit", ""),
                k.get("trend", "stable"),
            ])
        kpi_table = Table(kpi_data, colWidths=[2.4 * inch, 1.1 * inch, 1.1 * inch, 0.9 * inch, 0.9 * inch])
        kpi_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 0.2 * inch))

    # Metrics section
    metrics = report.get("metrics", [])
    if metrics:
        story.append(Paragraph("Report Metrics", h2_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
        story.append(Spacer(1, 0.08 * inch))
        m_data = [["Metric", "Value", "Unit", "Trend", "vs Prior Period"]]
        for m in metrics:
            m_data.append([
                m.get("metric_name", ""),
                f"{m.get('metric_value', 0):.2f}",
                m.get("metric_unit", ""),
                m.get("trend", "stable"),
                f"{m.get('comparison_value', 0):.2f} ({m.get('comparison_period', '')})",
            ])
        m_table = Table(m_data, colWidths=[2.0 * inch, 1.0 * inch, 0.8 * inch, 0.9 * inch, 1.7 * inch])
        m_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(m_table)
        story.append(Spacer(1, 0.2 * inch))

    # Footer note
    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    story.append(Paragraph(
        f"Generated by ALDECI Security Intelligence Platform — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ParagraphStyle("Footer", parent=normal, fontSize=7, textColor=colors.grey),
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()


@router.get("/reports/{report_id}/export/pdf")
def export_report_pdf(
    report_id: str,
    org_id: str = Query("default"),
) -> StreamingResponse:
    """Export an executive report as a PDF (uses reportlab)."""
    try:
        report = _get_engine().get_report(org_id, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        kpis = _get_engine().list_kpis(org_id)
        pdf_bytes = _build_pdf_bytes(report, kpis)
        safe_title = (report.get("title") or report.get("report_type", "report")).replace(" ", "_")[:40]
        filename = f"exec_report_{safe_title}_{report_id[:8]}.pdf"
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except ImportError as exc:
        raise HTTPException(
            status_code=501,
            detail="PDF export requires reportlab. Install with: pip install reportlab",
        ) from exc
    except Exception as exc:
        logger.exception("export_report_pdf failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/", summary="Executive reporting index", tags=["exec-reporting"])
async def exec_reporting_index(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return executive reporting summary for the org."""
    try:
        engine = _get_engine()
        reports = engine.list_reports(org_id=org_id) if hasattr(engine, "list_reports") else []
    except Exception:
        reports = []
    return {"router": "exec-reporting", "org_id": org_id, "items": reports, "count": len(reports)}
