"""
Vulnerability Analytics Dashboard API endpoints — ALDECI.

Exposes time-series trend, MTTR/MTTD, severity, scanner effectiveness,
risk trajectory, recurring findings, and executive summary metrics.

Protected with API key authentication via ``_verify_api_key`` (injected via
``app.include_router`` dependencies — see app.py).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.cache_layer import TTL_STATS, cache_endpoint
from core.vulnerability_analytics import (
    ScannerEffectiveness,
    TimeGranularity,
    TrendPoint,
    VulnerabilityAnalytics,
)
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(
    prefix="/api/v1/analytics",
    tags=["analytics-dashboard"],
)

_analytics = VulnerabilityAnalytics()


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
            detail=f"Invalid date format for '{param_name}'. Use ISO 8601 (e.g. 2024-01-01 or 2024-01-01T00:00:00Z).",
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/trends", response_model=List[TrendPoint])
async def get_finding_trends(
    org_id: str = Query("default", description="Organisation identifier"),
    granularity: TimeGranularity = Query(TimeGranularity.DAILY, description="Time bucket size"),
    start: Optional[str] = Query(None, description="Start date (ISO 8601)"),
    end: Optional[str] = Query(None, description="End date (ISO 8601)"),
) -> List[TrendPoint]:
    """
    Return finding counts (new, resolved, reopened, total_open) bucketed by
    the requested granularity over the specified date range.
    """
    start_dt = _parse_date(start, "start")
    end_dt = _parse_date(end, "end")
    return _analytics.get_trend(
        org_id=org_id,
        granularity=granularity,
        start_date=start_dt,
        end_date=end_dt,
    )


@router.get("/mttr")
async def get_mttr(
    org_id: str = Query("default", description="Organisation identifier"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical/high/medium/low/info)"),
    period_days: int = Query(30, ge=1, le=365, description="Look-back window in days"),
) -> Dict[str, Any]:
    """Mean time to remediate (hours) — average time from first opened to resolved."""
    value = _analytics.get_mttr(
        org_id=org_id,
        severity_filter=severity,
        period_days=period_days,
    )
    return {
        "org_id": org_id,
        "mttr_hours": value,
        "period_days": period_days,
        "severity_filter": severity,
    }


@router.get("/mttd")
async def get_mttd(
    org_id: str = Query("default", description="Organisation identifier"),
    period_days: int = Query(30, ge=1, le=365, description="Look-back window in days"),
) -> Dict[str, Any]:
    """Mean time to detect (hours) — average time from opened to detected event."""
    value = _analytics.get_mttd(org_id=org_id, period_days=period_days)
    return {
        "org_id": org_id,
        "mttd_hours": value,
        "period_days": period_days,
    }


@router.get("/severity")
async def get_severity_distribution(
    org_id: str = Query("default", description="Organisation identifier"),
    date: Optional[str] = Query(None, description="Point-in-time cutoff (ISO 8601)"),
) -> Dict[str, Any]:
    """
    Count of open findings per severity level as of ``date`` (defaults to now).
    """
    cutoff = _parse_date(date, "date")
    distribution = _analytics.get_severity_distribution(org_id=org_id, date=cutoff)
    return {
        "org_id": org_id,
        "distribution": distribution,
        "total_open": sum(distribution.values()),
    }


@router.get("/severity-trend")
async def get_severity_trend(
    org_id: str = Query("default", description="Organisation identifier"),
    granularity: TimeGranularity = Query(TimeGranularity.DAILY, description="Time bucket size"),
    period_days: int = Query(30, ge=1, le=365, description="Look-back window in days"),
) -> List[Dict[str, Any]]:
    """New findings per severity level bucketed over time."""
    return _analytics.get_severity_trend(
        org_id=org_id,
        granularity=granularity,
        period_days=period_days,
    )


@router.get("/scanners", response_model=List[ScannerEffectiveness])
async def get_scanner_effectiveness(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[ScannerEffectiveness]:
    """Scanner effectiveness ranked by finding volume with quality metrics."""
    return _analytics.get_scanner_effectiveness(org_id=org_id)


@router.get("/risk-trajectory")
async def get_risk_trajectory(
    org_id: str = Query("default", description="Organisation identifier"),
    period_days: int = Query(30, ge=1, le=365, description="Look-back window in days"),
) -> List[Dict[str, Any]]:
    """Average risk score of newly opened findings per day."""
    return _analytics.get_risk_trajectory(org_id=org_id, period_days=period_days)


@router.get("/recurring")
async def get_top_recurring(
    org_id: str = Query("default", description="Organisation identifier"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of findings to return"),
) -> List[Dict[str, Any]]:
    """Most frequently reopened findings."""
    return _analytics.get_top_recurring(org_id=org_id, limit=limit)


@router.get("/executive-summary")
@cache_endpoint(ttl=TTL_STATS)
async def get_executive_summary(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    All key vulnerability metrics in a single call — designed for
    CISO/executive dashboards.
    """
    try:
        return _analytics.generate_executive_summary(org_id=org_id)
    except Exception:
        return {"org_id": org_id, "total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "mttr_days": 0, "risk_score": 0}


@router.get("/", summary="Analytics dashboard index", tags=["analytics-dashboard"])
async def analytics_index(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return analytics dashboard summary and severity distribution for the org."""
    try:
        summary = _analytics.generate_executive_summary(org_id=org_id)
    except Exception:
        summary = {}
    try:
        dist = _analytics.get_severity_distribution(org_id=org_id)
        items = [{"severity": k, "count": v} for k, v in dist.items()]
    except Exception:
        items = []
    return {"router": "analytics", "org_id": org_id, "summary": summary, "items": items, "count": len(items)}
