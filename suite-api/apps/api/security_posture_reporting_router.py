"""Security Posture Reporting API router — ALDECI.

Endpoints at /api/v1/posture-reports/* for creating executive/board/audit
posture reports, adding sections and metrics, publishing, and trend analysis.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "security_posture_reporting_router: auth_deps not available"
    )
    _AUTH_DEP = []

from core.security_posture_reporting_engine import SecurityPostureReportingEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/posture-reports",
    tags=["posture-reports"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[SecurityPostureReportingEngine] = None


def _get_engine() -> SecurityPostureReportingEngine:
    global _engine
    if _engine is None:
        _engine = SecurityPostureReportingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class CreateReportRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    report_name: str = Field(..., min_length=1, description="Report name")
    report_type: str = Field("monthly", description="executive/board/audit/compliance/operational/monthly/quarterly/annual")
    audience: str = Field("ciso", description="ciso/board/executives/auditors/regulators/team")
    period_start: str = Field(..., description="Period start ISO date")
    period_end: str = Field(..., description="Period end ISO date")
    generated_by: str = Field("", description="Author or system that generated the report")


class AddSectionRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    section_name: str = Field(..., min_length=1, description="Section name")
    section_type: str = Field("summary", description="summary/risk/compliance/incidents/vulnerabilities/recommendations/kpis")
    content: str = Field("", description="Section content / narrative")
    score: float = Field(0.0, ge=0.0, le=100.0, description="Section score 0-100")
    sort_order: int = Field(0, ge=0, description="Display order")


class AddMetricRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    metric_name: str = Field(..., min_length=1, description="Metric name")
    metric_value: float = Field(..., description="Current metric value")
    metric_unit: str = Field("", description="Unit label (e.g. %, ms, count)")
    previous_value: float = Field(0.0, description="Previous period value for trend computation")
    benchmark_value: float = Field(0.0, description="Industry benchmark value")


class ListReportsQuery(BaseModel):
    org_id: str = "default"
    report_type: Optional[str] = None
    status: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/reports", summary="Create a new posture report")
def create_report(req: CreateReportRequest) -> Dict[str, Any]:
    try:
        return _get_engine().create_report(
            org_id=req.org_id,
            report_name=req.report_name,
            report_type=req.report_type,
            audience=req.audience,
            period_start=req.period_start,
            period_end=req.period_end,
            generated_by=req.generated_by,
        )
    except Exception as exc:
        logger.exception("create_report failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/reports/{report_id}/sections", summary="Add a section to a report")
def add_section(report_id: str, req: AddSectionRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_section(
            report_id=report_id,
            org_id=req.org_id,
            section_name=req.section_name,
            section_type=req.section_type,
            content=req.content,
            score=req.score,
            sort_order=req.sort_order,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception("add_section failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/reports/{report_id}/metrics", summary="Add a metric to a report")
def add_metric(report_id: str, req: AddMetricRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_metric(
            report_id=report_id,
            org_id=req.org_id,
            metric_name=req.metric_name,
            metric_value=req.metric_value,
            metric_unit=req.metric_unit,
            previous_value=req.previous_value,
            benchmark_value=req.benchmark_value,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception("add_metric failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/reports/{report_id}/publish", summary="Publish a report")
def publish_report(
    report_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().publish_report(report_id=report_id, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception("publish_report failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/reports/{report_id}", summary="Get report detail with sections and metrics")
def get_report_detail(
    report_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    result = _get_engine().get_report_detail(report_id=report_id, org_id=org_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    return result


@router.get("/reports", summary="List posture reports")
def list_reports(
    org_id: str = Query("default", description="Organisation ID"),
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List posture reports (canonical envelope, batch-7).

    Class-c contract: empty IS correct for fresh tenants — posture reports are
    generated from compliance scans (executive/board/audit), not auto-derivable
    from any public source. Always returns full envelope with pagination
    context + filters echo + actionable hint when empty.
    """
    try:
        rows = _get_engine().list_reports(
            org_id=org_id, report_type=report_type, status=status
        ) or []
        paged = rows[offset : offset + limit] if offset else rows[:limit]
        envelope: Dict[str, Any] = {
            "items": paged,
            "reports": paged,  # legacy key preserved
            "total": len(rows),
            "org_id": org_id,
            "limit": limit,
            "offset": offset,
            "filters_applied": {
                "report_type": report_type,
                "status": status,
            },
        }
        if not rows:
            envelope["hint"] = (
                "Trigger a posture scan via POST /api/v1/posture-reports/reports "
                "to generate a report. Empty IS the correct response for a fresh "
                "tenant — no public source exists."
            )
        return envelope
    except Exception as exc:
        logger.exception("list_reports failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/reports/latest/{report_type}", summary="Get latest report of a given type")
def get_latest_report(
    report_type: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    result = _get_engine().get_latest_report(org_id=org_id, report_type=report_type)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No {report_type} report found")
    return result


@router.get("/trends", summary="Get metric trend summary across published reports")
def get_trend_summary(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().get_trend_summary(org_id=org_id)
    except Exception as exc:
        logger.exception("get_trend_summary failed")
        raise HTTPException(status_code=500, detail=str(exc))
