"""Security Awareness Metrics Router — ALDECI.

Track phishing click rates, training completion, quiz scores, policy
acknowledgement, incident report rates, and password strength per department.
Supports industry benchmarking and trend analysis.

Prefix: /api/v1/awareness-metrics
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/awareness-metrics/metrics           record_metric
  GET    /api/v1/awareness-metrics/metrics           list_metrics
  GET    /api/v1/awareness-metrics/metrics/latest    get_latest_metric
  GET    /api/v1/awareness-metrics/metrics/trend     get_trend
  POST   /api/v1/awareness-metrics/benchmarks        set_benchmark
  GET    /api/v1/awareness-metrics/benchmarks        list_benchmarks
  GET    /api/v1/awareness-metrics/stats             get_awareness_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/awareness-metrics",
    tags=["Security Awareness Metrics"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_awareness_metrics_engine import (
            SecurityAwarenessMetricsEngine,
        )
        _engine = SecurityAwarenessMetricsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RecordMetricRequest(BaseModel):
    metric_type: str = Field(
        ...,
        description=(
            "phishing_click_rate | training_completion | quiz_score | "
            "policy_acknowledgement | incident_report_rate | password_strength"
        ),
    )
    department: str = Field(default="all", description="Department name or 'all'")
    value: float = Field(..., description="Metric value (percentage, score, etc.)")
    period: str = Field(default="", description="Period label e.g. '2024-Q1'")
    sample_size: int = Field(default=0, ge=0, description="Number of people sampled")


class SetBenchmarkRequest(BaseModel):
    metric_type: str = Field(..., description="Metric type to benchmark")
    target_value: float = Field(..., description="Organisation target value")
    industry_average: float = Field(..., description="Industry average value")
    period: str = Field(default="", description="Benchmark period")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/metrics", dependencies=[Depends(api_key_auth)])
def record_metric(
    req: RecordMetricRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Record a new awareness metric data point."""
    try:
        return _get_engine().record_metric(
            org_id,
            {
                "metric_type": req.metric_type,
                "department": req.department,
                "value": req.value,
                "period": req.period,
                "sample_size": req.sample_size,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/metrics", dependencies=[Depends(api_key_auth)])
def list_metrics(
    org_id: str = Query(..., description="Organization ID"),
    metric_type: Optional[str] = Query(default=None),
    department: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List metrics with optional filters, newest first."""
    return _get_engine().list_metrics(org_id, metric_type=metric_type, department=department)


@router.get("/metrics/latest", dependencies=[Depends(api_key_auth)])
def get_latest_metric(
    org_id: str = Query(..., description="Organization ID"),
    metric_type: str = Query(..., description="Metric type"),
    department: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Return the most recent metric record for a given type and department."""
    result = _get_engine().get_latest_metric(org_id, metric_type, department=department)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"No metric found for type '{metric_type}'"
            + (f" department '{department}'" if department else ""),
        )
    return result


@router.get("/metrics/trend", dependencies=[Depends(api_key_auth)])
def get_trend(
    org_id: str = Query(..., description="Organization ID"),
    metric_type: str = Query(..., description="Metric type"),
    department: Optional[str] = Query(default=None),
    periods: int = Query(default=4, ge=2, le=52),
) -> Dict[str, Any]:
    """Return the trend (improving/declining/stable) for a metric type."""
    return _get_engine().get_trend(
        org_id, metric_type, department=department, periods=periods
    )


@router.post("/benchmarks", dependencies=[Depends(api_key_auth)])
def set_benchmark(
    req: SetBenchmarkRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create or update a benchmark for a metric type."""
    try:
        return _get_engine().set_benchmark(
            org_id,
            {
                "metric_type": req.metric_type,
                "target_value": req.target_value,
                "industry_average": req.industry_average,
                "period": req.period,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/benchmarks", dependencies=[Depends(api_key_auth)])
def list_benchmarks(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """List all benchmarks for the org."""
    return _get_engine().list_benchmarks(org_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_awareness_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregate awareness statistics."""
    return _get_engine().get_awareness_stats(org_id)
