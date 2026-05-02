"""
Security Metrics & OKR Tracking API endpoints — ALDECI.

8 endpoints under /api/v1/metrics:

  GET  /dora              — DORA-like security metrics (MTTD, MTTC, MTTR, CFR)
  GET  /benchmarks        — Org vs industry benchmark comparison
  GET  /trends            — Time-series trend data (weekly/monthly/quarterly)
  GET  /sla               — SLA compliance per severity
  POST /roi               — ROI calculation
  GET  /objectives        — List all OKR objectives
  POST /objectives        — Create an OKR objective
  POST /objectives/{obj_id}/key-results      — Add a key result
  PATCH /objectives/{obj_id}/key-results/{kr_id} — Update key result progress
  DELETE /objectives/{obj_id}               — Delete an objective
  POST /events            — Ingest a security event
  POST /deployments       — Record a deployment
  POST /reports           — Generate a periodic report

Protected by api_key_auth dependency injected via app.include_router.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

from core.security_metrics import (
    Objective,
    ReportType,
    SecurityEvent,
    SecurityMetricsEngine,
    Severity,
    TrendPeriod,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/metrics", tags=["security-metrics"])

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = SecurityMetricsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response Pydantic models
# ---------------------------------------------------------------------------


class EventIngest(BaseModel):
    """Request body for ingesting a security event."""

    severity: Severity = Severity.MEDIUM
    detected_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    remediated_at: Optional[datetime] = None
    source: str = Field("unknown", min_length=1)
    team: str = Field("unknown", min_length=1)
    repo: str = Field("unknown", min_length=1)
    tags: List[str] = Field(default_factory=list)
    is_regression: bool = False


class DeploymentRecord(BaseModel):
    """Request body for recording a deployment."""

    is_failure: bool
    deployed_at: Optional[datetime] = None
    notes: str = ""


class ROIRequest(BaseModel):
    """Request body for ROI calculation."""

    program_cost_usd: float = Field(..., gt=0, description="Total annual program cost in USD")
    breaches_prevented: float = Field(..., ge=0, description="Estimated breaches prevented")
    tool_cost_usd: float = Field(0.0, ge=0)
    staff_cost_usd: float = Field(0.0, ge=0)
    training_cost_usd: float = Field(0.0, ge=0)
    industry: str = Field("global", description="Industry vertical for breach cost lookup")


class ObjectiveCreate(BaseModel):
    """Request body for creating an OKR objective."""

    title: str = Field(..., min_length=1, max_length=500)
    quarter: str = Field(..., min_length=1, description="e.g. Q2-2026")
    owner: str = Field("security-team", min_length=1)


class KeyResultAdd(BaseModel):
    """Request body for adding a key result."""

    title: str = Field(..., min_length=1, max_length=500)
    target_value: float = Field(..., description="Goal value to reach")
    current_value: float = Field(0.0, description="Current measured value")
    unit: str = Field("%", description="Unit of measurement")
    due_date: Optional[date] = None


class KeyResultUpdate(BaseModel):
    """Request body for updating a key result's progress."""

    current_value: float
    notes: str = ""


class ReportRequest(BaseModel):
    """Request body for report generation."""

    report_type: ReportType
    industry: str = "global_median"
    extra_context: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _parse_datetime_param(value: Optional[str], name: str) -> Optional[datetime]:
    """Parse an ISO 8601 datetime query param or raise HTTP 422."""
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
            detail=f"Invalid date format for '{name}'. Use ISO 8601, e.g. 2026-01-01T00:00:00Z",
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/dora",
    response_model=Dict[str, Any],
    summary="DORA-like security metrics",
    description=(
        "Compute Mean Time to Detect (MTTD), Mean Time to Contain (MTTC), "
        "Mean Time to Remediate (MTTR), and Change Failure Rate for the "
        "requested time window."
    ),
)
async def get_dora_metrics(
    days: int = Query(30, ge=1, le=365, description="Lookback window in days"),
    since: Optional[str] = Query(None, description="Window start (ISO 8601)"),
    until: Optional[str] = Query(None, description="Window end (ISO 8601)"),
) -> Dict[str, Any]:
    since_dt = _parse_datetime_param(since, "since")
    until_dt = _parse_datetime_param(until, "until")
    metrics = _get_engine().compute_dora_metrics(days=days, since=since_dt, until=until_dt)
    return {
        "mttd_hours": metrics.mttd_hours,
        "mttc_hours": metrics.mttc_hours,
        "mttr_hours": metrics.mttr_hours,
        "change_failure_rate": metrics.change_failure_rate,
        "change_failure_rate_pct": round(metrics.change_failure_rate * 100, 2),
        "sample_size": metrics.sample_size,
        "period_start": metrics.period_start.isoformat(),
        "period_end": metrics.period_end.isoformat(),
        "mttr_by_severity": metrics.by_severity,
    }


@router.get(
    "/benchmarks",
    response_model=List[Dict[str, Any]],
    summary="Industry benchmark comparison",
    description=(
        "Compare org DORA metrics against Verizon DBIR 2024 and SANS 2024 "
        "benchmarks. Returns percentile ranking for each metric."
    ),
)
async def get_benchmarks(
    days: int = Query(30, ge=1, le=365),
    industry: str = Query("global_median", description="Industry vertical"),
    since: Optional[str] = Query(None),
    until: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    since_dt = _parse_datetime_param(since, "since")
    until_dt = _parse_datetime_param(until, "until")
    dora = _get_engine().compute_dora_metrics(days=days, since=since_dt, until=until_dt)
    comparisons = _get_engine().compare_to_benchmarks(dora, industry=industry)
    return [
        {
            "metric_name": c.metric_name,
            "org_value": c.org_value,
            "unit": c.unit,
            "industry_median": c.industry_median,
            "industry_p25": c.industry_p25,
            "industry_p75": c.industry_p75,
            "org_percentile": round(c.org_percentile, 1),
            "benchmark_source": c.benchmark_source,
        }
        for c in comparisons
    ]


@router.get(
    "/trends",
    response_model=List[Dict[str, Any]],
    summary="Time-series trend data",
    description=(
        "Generate time-series data for vulnerability backlog, risk score, "
        "compliance percentage, and incident count. Supports weekly, monthly, "
        "and quarterly rollups."
    ),
)
async def get_trends(
    period: TrendPeriod = Query(TrendPeriod.WEEKLY, description="Rollup period"),
    periods: int = Query(12, ge=1, le=52, description="Number of periods to return"),
    until: Optional[str] = Query(None, description="End of last bucket (ISO 8601)"),
) -> List[Dict[str, Any]]:
    until_dt = _parse_datetime_param(until, "until")
    trend = _get_engine().get_trend_data(period=period, periods=periods, until=until_dt)
    return [
        {
            "period_label": t.period_label,
            "period_start": t.period_start.isoformat(),
            "period_end": t.period_end.isoformat(),
            "vuln_backlog": t.vuln_backlog,
            "risk_score": t.risk_score,
            "compliance_pct": t.compliance_pct,
            "incident_count": t.incident_count,
            "training_completion_pct": t.training_completion_pct,
            "phishing_click_rate_pct": t.phishing_click_rate_pct,
        }
        for t in trend
    ]


@router.get(
    "/sla",
    response_model=List[Dict[str, Any]],
    summary="SLA compliance per severity",
    description=(
        "Track SLA compliance for Critical (24h), High (7d), Medium (30d), "
        "and Low (90d) findings. Returns breach rate, average overdue time, "
        "and worst-offender team/repo."
    ),
)
async def get_sla_compliance(
    days: int = Query(30, ge=1, le=365),
    since: Optional[str] = Query(None),
    until: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    since_dt = _parse_datetime_param(since, "since")
    until_dt = _parse_datetime_param(until, "until")
    records = _get_engine().compute_sla_compliance(days=days, since=since_dt, until=until_dt)
    return [
        {
            "severity": r.severity.value,
            "sla_hours": r.sla_hours,
            "total_findings": r.total_findings,
            "within_sla": r.within_sla,
            "breached": r.breached,
            "breach_rate_pct": r.breach_rate_pct,
            "avg_overdue_hours": r.avg_overdue_hours,
            "worst_offender_team": r.worst_offender_team,
            "worst_offender_repo": r.worst_offender_repo,
        }
        for r in records
    ]


@router.post(
    "/roi",
    response_model=Dict[str, Any],
    summary="Security program ROI calculation",
    description=(
        "Calculate security program ROI: cost vs avoided losses using "
        "Ponemon/IBM 2024 breach cost data. Returns net benefit and "
        "payback period."
    ),
)
async def calculate_roi(body: ROIRequest) -> Dict[str, Any]:
    roi = _get_engine().compute_roi(
        program_cost_usd=body.program_cost_usd,
        breaches_prevented=body.breaches_prevented,
        tool_cost_usd=body.tool_cost_usd,
        staff_cost_usd=body.staff_cost_usd,
        training_cost_usd=body.training_cost_usd,
        industry=body.industry,
    )
    return {
        "program_cost_usd": roi.program_cost_usd,
        "tool_cost_usd": roi.tool_cost_usd,
        "staff_cost_usd": roi.staff_cost_usd,
        "training_cost_usd": roi.training_cost_usd,
        "breaches_prevented": roi.breaches_prevented,
        "avg_breach_cost_usd": roi.avg_breach_cost_usd,
        "total_avoided_loss_usd": roi.total_avoided_loss_usd,
        "net_benefit_usd": roi.net_benefit_usd,
        "roi_pct": roi.roi_pct,
        "payback_months": roi.payback_months,
        "industry": roi.industry,
        "benchmark_source": "Ponemon/IBM Cost of a Data Breach Report 2024",
    }


@router.get(
    "/objectives",
    response_model=List[Dict[str, Any]],
    summary="List all OKR objectives",
)
async def list_objectives() -> List[Dict[str, Any]]:
    objs = _get_engine().list_objectives()
    return [_objective_to_dict(o) for o in objs]


@router.post(
    "/objectives",
    response_model=Dict[str, Any],
    status_code=201,
    summary="Create an OKR objective",
)
async def create_objective(body: ObjectiveCreate) -> Dict[str, Any]:
    obj = _get_engine().create_objective(
        title=body.title,
        quarter=body.quarter,
        owner=body.owner,
    )
    return _objective_to_dict(obj)


@router.post(
    "/objectives/{obj_id}/key-results",
    response_model=Dict[str, Any],
    status_code=201,
    summary="Add a key result to an objective",
)
async def add_key_result(obj_id: str, body: KeyResultAdd) -> Dict[str, Any]:
    try:
        kr = _get_engine().add_key_result(
            obj_id=obj_id,
            title=body.title,
            target_value=body.target_value,
            current_value=body.current_value,
            unit=body.unit,
            due_date=body.due_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "kr_id": kr.kr_id,
        "title": kr.title,
        "current_value": kr.current_value,
        "target_value": kr.target_value,
        "unit": kr.unit,
        "progress_pct": kr.progress_pct,
        "due_date": kr.due_date.isoformat() if kr.due_date else None,
        "notes": kr.notes,
    }


@router.patch(
    "/objectives/{obj_id}/key-results/{kr_id}",
    response_model=Dict[str, Any],
    summary="Update key result progress",
)
async def update_key_result(
    obj_id: str, kr_id: str, body: KeyResultUpdate
) -> Dict[str, Any]:
    try:
        obj = _get_engine().update_key_result(
            obj_id=obj_id,
            kr_id=kr_id,
            current_value=body.current_value,
            notes=body.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _objective_to_dict(obj)


@router.delete(
    "/objectives/{obj_id}",
    status_code=204,
    summary="Delete an OKR objective",
)
async def delete_objective(obj_id: str) -> None:
    deleted = _get_engine().delete_objective(obj_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Objective {obj_id!r} not found")


@router.post(
    "/events",
    response_model=Dict[str, Any],
    status_code=201,
    summary="Ingest a security event",
    description="Record a security event to feed MTTD/MTTC/MTTR calculations.",
)
async def ingest_event(body: EventIngest) -> Dict[str, Any]:
    ev = SecurityEvent(
        severity=body.severity,
        detected_at=body.detected_at or datetime.now(timezone.utc),
        contained_at=body.contained_at,
        remediated_at=body.remediated_at,
        source=body.source,
        team=body.team,
        repo=body.repo,
        tags=body.tags,
        is_regression=body.is_regression,
    )
    stored = _get_engine().ingest_event(ev)
    return {
        "event_id": stored.event_id,
        "severity": stored.severity.value,
        "detected_at": stored.detected_at.isoformat(),
        "source": stored.source,
        "team": stored.team,
        "repo": stored.repo,
    }


@router.post(
    "/deployments",
    response_model=Dict[str, str],
    status_code=201,
    summary="Record a deployment",
    description="Record a deployment event for Change Failure Rate tracking.",
)
async def record_deployment(body: DeploymentRecord) -> Dict[str, str]:
    deploy_id = _get_engine().record_deployment(
        is_failure=body.is_failure,
        deployed_at=body.deployed_at,
        notes=body.notes,
    )
    return {"deploy_id": deploy_id, "status": "recorded"}


@router.post(
    "/reports",
    response_model=Dict[str, Any],
    summary="Generate a periodic security report",
    description=(
        "Generate weekly digest, monthly executive summary, quarterly board "
        "report, or annual security review. Returns report metadata and sections."
    ),
)
async def generate_report(body: ReportRequest) -> Dict[str, Any]:
    report = _get_engine().generate_report(
        report_type=body.report_type,
        industry=body.industry,
        extra_context=body.extra_context,
    )
    return {
        "report_id": report.report_id,
        "report_type": report.report_type.value,
        "generated_at": report.generated_at.isoformat(),
        "period_start": report.period_start.isoformat(),
        "period_end": report.period_end.isoformat(),
        "title": report.title,
        "sections": report.sections,
        "top_risks": report.top_risks,
        "dora_metrics": {
            "mttd_hours": report.dora_metrics.mttd_hours,
            "mttr_hours": report.dora_metrics.mttr_hours,
            "change_failure_rate": report.dora_metrics.change_failure_rate,
            "sample_size": report.dora_metrics.sample_size,
        } if report.dora_metrics else None,
        "sla_compliance": [
            {
                "severity": s.severity.value,
                "breach_rate_pct": s.breach_rate_pct,
                "total_findings": s.total_findings,
            }
            for s in report.sla_compliance
        ],
    }


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _objective_to_dict(obj: Objective) -> Dict[str, Any]:
    return {
        "obj_id": obj.obj_id,
        "title": obj.title,
        "owner": obj.owner,
        "quarter": obj.quarter,
        "overall_progress": round(obj.overall_progress, 1),
        "status": obj.status.value,
        "key_results": [
            {
                "kr_id": kr.kr_id,
                "title": kr.title,
                "current_value": kr.current_value,
                "target_value": kr.target_value,
                "unit": kr.unit,
                "progress_pct": round(kr.progress_pct, 1),
                "due_date": kr.due_date.isoformat() if kr.due_date else None,
                "notes": kr.notes,
            }
            for kr in obj.key_results
        ],
    }
