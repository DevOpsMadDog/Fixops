"""
Executive Security Risk Report API endpoints — ALDECI.

Endpoints:
  POST /api/v1/reports/executive                      — generate executive report
  POST /api/v1/reports/compliance/{framework}         — generate compliance evidence package
  POST /api/v1/reports/findings/export                — CSV findings export
  GET  /api/v1/reports/executive/recent               — list recent executive reports (in-memory)
  GET  /api/v1/reports/executive/{report_id}          — retrieve an executive report by ID

NOTE: /recent and /{report_id} were previously mounted at /api/v1/reports/recent and
/api/v1/reports/{report_id}, which caused the /{report_id} catch-all to shadow
reports_router's /templates, /stats, /schedules/* etc. routes (mount-order bug).
Fixed 2026-05-05: moved under /executive/ sub-path.

Protected by API key + read:evidence scope (injected via app.include_router dependencies).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from core.report_generator import ExecutiveReportGenerator, ReportDocument
from fastapi import APIRouter, HTTPException
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


# NOTE: GET /recent and GET /{report_id} were removed 2026-05-05.
# They were previously at /api/v1/reports/recent and /api/v1/reports/{report_id},
# where the /{report_id} catch-all shadowed reports_router's /templates, /stats,
# /schedules/* routes (mount-order bug — this router is registered before reports_router
# via grc_app.py). Retrieval of executive reports is now served by executive_report_router
# at /api/v1/reports/executive/{report_id} (prefix owns that namespace).
