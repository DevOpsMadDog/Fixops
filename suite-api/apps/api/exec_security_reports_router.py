"""
Executive Security Risk Report API endpoints — ALDECI.

Endpoints:
  POST /api/v1/reports/executive              — generate executive report
  POST /api/v1/reports/compliance/{framework} — generate compliance evidence package
  POST /api/v1/reports/findings/export        — CSV findings export
  GET  /api/v1/reports/recent                 — list recent reports (in-memory store)
  GET  /api/v1/reports/{report_id}            — retrieve a report by ID

Protected by API key + read:evidence scope (injected via app.include_router dependencies).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from core.report_generator import ExecutiveReportGenerator, ReportDocument
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reports", tags=["executive-security-reports"])

_generator = ExecutiveReportGenerator()

# In-memory recent-reports store (survives per-process lifetime; not persisted)
_recent_reports: Dict[str, Dict[str, Any]] = {}
_MAX_RECENT = 50


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ExecutiveReportRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    period_days: int = Field(30, ge=1, le=365, description="Look-back window in days")


class ComplianceReportRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")


class FindingsExportRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    days: int = Field(30, ge=1, le=365, description="Look-back window in days")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _store_report(doc: ReportDocument, report_type: str) -> None:
    """Keep the last _MAX_RECENT reports in memory."""
    _recent_reports[doc.report_id] = {
        **doc.to_dict(),
        "report_type": report_type,
    }
    if len(_recent_reports) > _MAX_RECENT:
        oldest_key = next(iter(_recent_reports))
        _recent_reports.pop(oldest_key, None)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/executive", summary="Generate executive security risk report")
def generate_executive_report(body: ExecutiveReportRequest) -> Dict[str, Any]:
    """
    Generate a full executive security risk report for the given organisation,
    covering the past *period_days* days.

    Returns report metadata and the full HTML content.
    """
    try:
        doc = _generator.generate_executive_report(
            org_id=body.org_id,
            period_days=body.period_days,
        )
    except Exception as exc:
        logger.exception("Executive report generation failed")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}") from exc

    _store_report(doc, "executive")
    return {
        "report_id": doc.report_id,
        "org_id": doc.org_id,
        "generated_at": doc.generated_at,
        "period_start": doc.period_start,
        "period_end": doc.period_end,
        "format": doc.format,
        "section_count": doc.section_count,
        "content_length": len(doc.content),
        "content": doc.content,
    }


@router.post(
    "/compliance/{framework}",
    summary="Generate compliance evidence package",
)
def generate_compliance_report(framework: str, body: ComplianceReportRequest) -> Dict[str, Any]:
    """
    Generate a compliance evidence package for the specified framework.

    Supported frameworks: SOC2, ISO27001, NIST_CSF, PCI_DSS, HIPAA, CIS_CONTROLS, GDPR
    """
    valid_frameworks = {"SOC2", "ISO27001", "NIST_CSF", "PCI_DSS", "HIPAA", "CIS_CONTROLS", "GDPR"}
    fw_upper = framework.upper()
    if fw_upper not in valid_frameworks:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Valid: {sorted(valid_frameworks)}",
        )

    try:
        doc = _generator.generate_compliance_evidence(
            framework=fw_upper,
            org_id=body.org_id,
        )
    except Exception as exc:
        logger.exception("Compliance report generation failed")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}") from exc

    _store_report(doc, f"compliance:{fw_upper}")
    return {
        "report_id": doc.report_id,
        "org_id": doc.org_id,
        "framework": fw_upper,
        "generated_at": doc.generated_at,
        "period_start": doc.period_start,
        "period_end": doc.period_end,
        "format": doc.format,
        "section_count": doc.section_count,
        "content_length": len(doc.content),
        "content": doc.content,
    }


@router.post("/findings/export", summary="Export findings as CSV for auditors")
def export_findings_csv(body: FindingsExportRequest) -> PlainTextResponse:
    """
    Export all findings for the given organisation as CSV.

    Returns a CSV file suitable for auditors and compliance teams.
    """
    try:
        csv_content = _generator.generate_csv_findings(
            org_id=body.org_id,
            days=body.days,
        )
    except Exception as exc:
        logger.exception("CSV findings export failed")
        raise HTTPException(status_code=500, detail=f"Export failed: {exc}") from exc

    filename = f"findings_export_{body.org_id}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/recent", summary="List recently generated reports")
def list_recent_reports(
    limit: int = Query(20, ge=1, le=50, description="Maximum number of reports to return"),
) -> Dict[str, Any]:
    """Return metadata for recently generated reports (this process lifetime)."""
    items = list(_recent_reports.values())
    # Most recent first (dict preserves insertion order in Python 3.7+)
    items = list(reversed(items))[:limit]
    return {"total": len(items), "reports": items}


@router.get("/{report_id}", summary="Get report content by ID")
def get_report(report_id: str) -> Dict[str, Any]:
    """
    Retrieve a previously generated report by its ID.

    Only reports generated in the current process lifetime are available
    (no persistent storage for generated HTML).
    """
    doc_meta = _recent_reports.get(report_id)
    if not doc_meta:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found. Reports are retained only for the lifetime of this process.",
        )
    return doc_meta
