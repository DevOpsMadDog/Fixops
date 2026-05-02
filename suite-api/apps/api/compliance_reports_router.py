"""
Compliance Reports router — 10 endpoints for multi-framework compliance reporting.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.compliance_reports import SUPPORTED_FRAMEWORKS, ComplianceReportGenerator
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/compliance-reports", tags=["compliance-reports"])
_generator = ComplianceReportGenerator()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class GenerateReportRequest(BaseModel):
    """Request body for generating a compliance report."""

    framework: str = Field(..., description=f"One of: {', '.join(SUPPORTED_FRAMEWORKS)}")
    title: Optional[str] = None
    findings_context: Optional[Dict[str, Any]] = None


class ReportSummary(BaseModel):
    """Lightweight report summary (no sections)."""

    id: str
    framework: str
    title: str
    generated_at: str
    score: float
    gaps_count: int
    org_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/frameworks")
async def list_frameworks() -> List[str]:
    """Return the list of supported compliance frameworks."""
    return SUPPORTED_FRAMEWORKS


@router.post("/generate", status_code=201)
async def generate_report(
    body: GenerateReportRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Generate and persist a compliance report for the requested framework."""
    try:
        report = _generator.generate_report(
            framework=body.framework,
            org_id=org_id,
            findings_context=body.findings_context,
            title=body.title,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "id": report.id,
        "framework": report.framework,
        "title": report.title,
        "generated_at": report.generated_at.isoformat(),
        "score": report.score,
        "gaps_count": report.gaps_count,
        "org_id": report.org_id,
        "sections_count": len(report.sections),
    }


@router.get("/", response_model=List[ReportSummary])
async def list_reports(
    framework: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    org_id: str = Depends(get_org_id),
) -> List[ReportSummary]:
    """List stored compliance reports with optional framework filter."""
    reports = _generator.list_reports(
        framework=framework, org_id=org_id, limit=limit, offset=offset
    )
    return [
        ReportSummary(
            id=r.id,
            framework=r.framework,
            title=r.title,
            generated_at=r.generated_at.isoformat(),
            score=r.score,
            gaps_count=r.gaps_count,
            org_id=r.org_id,
        )
        for r in reports
    ]


@router.get("/{report_id}")
async def get_report(report_id: str) -> Dict[str, Any]:
    """Retrieve a full compliance report including all sections."""
    report = _generator.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return report.model_dump()


@router.delete("/{report_id}", status_code=204)
async def delete_report(report_id: str) -> None:
    """Delete a compliance report."""
    deleted = _generator.delete_report(report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")


@router.get("/{report_id}/export/json")
async def export_json(report_id: str) -> PlainTextResponse:
    """Export report as JSON."""
    try:
        content = _generator.export_report(report_id, fmt="json")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return PlainTextResponse(content, media_type="application/json")


@router.get("/{report_id}/export/html")
async def export_html(report_id: str) -> PlainTextResponse:
    """Export report as HTML."""
    try:
        content = _generator.export_report(report_id, fmt="html")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return PlainTextResponse(content, media_type="text/html")


@router.get("/{report_id}/export/csv")
async def export_csv(report_id: str) -> PlainTextResponse:
    """Export report as CSV."""
    try:
        content = _generator.export_report(report_id, fmt="csv")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return PlainTextResponse(content, media_type="text/csv")


@router.get("/{report_id}/export/markdown")
async def export_markdown(report_id: str) -> PlainTextResponse:
    """Export report as Markdown."""
    try:
        content = _generator.export_report(report_id, fmt="markdown")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return PlainTextResponse(content, media_type="text/markdown")


@router.get("/{report_id}/gaps")
async def get_gaps(report_id: str) -> Dict[str, Any]:
    """Return only the gap controls from a compliance report."""
    report = _generator.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    gaps = [s for s in report.sections if s.get("status") == "gap"]
    return {
        "report_id": report_id,
        "framework": report.framework,
        "score": report.score,
        "gaps_count": report.gaps_count,
        "gaps": gaps,
    }
