"""Security Metrics Collector Router — ALDECI.

Exposes CRUD for metric definitions, readings, aggregates, alerts, and dashboard.
Prefix: /api/v1/security-metrics-collector
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-metrics-collector",
    tags=["Security Metrics Collector"],
)

# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_metrics_collector import SecurityMetricsCollector
        _engine = SecurityMetricsCollector()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class MetricDefinitionCreate(BaseModel):
    name: str
    description: str = ""
    category: str = "vulnerability"
    unit: str = ""
    target_value: Optional[float] = None
    critical_threshold: Optional[float] = None
    warning_threshold: Optional[float] = None
    enabled: int = Field(default=1, ge=0, le=1)


class ReadingCreate(BaseModel):
    value: float
    source_system: str = "manual"
    period_start: Optional[str] = None
    period_end: Optional[str] = None


class AggregateRequest(BaseModel):
    period_type: str = "daily"


# ---------------------------------------------------------------------------
# Metric definition endpoints
# ---------------------------------------------------------------------------

@router.post("/metrics", dependencies=[Depends(api_key_auth)], status_code=201)
def define_metric(body: MetricDefinitionCreate, org_id: str = Query(default="default")):
    """Define a new security metric."""
    try:
        return _get_engine().define_metric(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/metrics", dependencies=[Depends(api_key_auth)])
def list_metrics(
     org_id: str = Query(default="default"),
    category: Optional[str] = Query(None),
    enabled_only: bool = Query(default=True),
):
    """List metric definitions with optional category filter."""
    return _get_engine().list_metrics(org_id, category=category, enabled_only=enabled_only)


# ---------------------------------------------------------------------------
# Reading endpoints
# ---------------------------------------------------------------------------

@router.post("/metrics/{metric_id}/readings", dependencies=[Depends(api_key_auth)], status_code=201)
def record_reading(
    metric_id: str,
    body: ReadingCreate,
     org_id: str = Query(default="default"),
):
    """Record a new metric reading. Auto-evaluates threshold status and creates alerts."""
    try:
        return _get_engine().record_reading(
            org_id, metric_id, body.value,
            source_system=body.source_system,
            period_start=body.period_start,
            period_end=body.period_end,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/metrics/{metric_id}/readings", dependencies=[Depends(api_key_auth)])
def list_readings(
    metric_id: str,
     org_id: str = Query(default="default"),
    limit: int = Query(default=30, ge=1, le=500),
):
    """List recent readings for a metric (newest first)."""
    return _get_engine().list_readings(org_id, metric_id, limit=limit)


# ---------------------------------------------------------------------------
# Aggregate endpoints
# ---------------------------------------------------------------------------

@router.post("/metrics/{metric_id}/aggregates", dependencies=[Depends(api_key_auth)], status_code=201)
def calculate_aggregate(
    metric_id: str,
    body: AggregateRequest,
     org_id: str = Query(default="default"),
):
    """Compute and save an aggregate for a metric over the current period."""
    try:
        return _get_engine().calculate_aggregate(org_id, metric_id, body.period_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/aggregates", dependencies=[Depends(api_key_auth)])
def list_aggregates(
     org_id: str = Query(default="default"),
    metric_id: Optional[str] = Query(None),
    period_type: Optional[str] = Query(None),
):
    """List metric aggregates with optional metric_id and period_type filters."""
    return _get_engine().list_aggregates(org_id, metric_id=metric_id, period_type=period_type)


# ---------------------------------------------------------------------------
# Alert endpoints
# ---------------------------------------------------------------------------

@router.get("/alerts", dependencies=[Depends(api_key_auth)])
def list_alerts(
     org_id: str = Query(default="default"),
    acknowledged: bool = Query(default=False),
):
    """List metric alerts. Default: unacknowledged only."""
    return _get_engine().list_alerts(org_id, acknowledged=acknowledged)


@router.post("/alerts/{alert_id}/acknowledge", dependencies=[Depends(api_key_auth)])
def acknowledge_alert(alert_id: str, org_id: str = Query(default="default")):
    """Acknowledge a metric alert."""
    acked = _get_engine().acknowledge_alert(org_id, alert_id)
    if not acked:
        raise HTTPException(status_code=404, detail="Alert not found or already acknowledged")
    return {"acknowledged": True, "alert_id": alert_id}


# ---------------------------------------------------------------------------
# Dashboard endpoint
# ---------------------------------------------------------------------------

@router.get("/dashboard", dependencies=[Depends(api_key_auth)])
def get_dashboard(org_id: str = Query(default="default")):
    """Return a summary dashboard: metrics by category, alert counts, worst metrics."""
    return _get_engine().get_dashboard(org_id)
