"""Security Metrics Dashboard Router — ALDECI.

Endpoints for the Security Metrics Dashboard engine.

Prefix: /api/v1/metrics-dashboard
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/metrics-dashboard/dashboards                              create_dashboard
  GET   /api/v1/metrics-dashboard/dashboards                              list_dashboards
  GET   /api/v1/metrics-dashboard/dashboards/{dashboard_id}               get_dashboard
  POST  /api/v1/metrics-dashboard/dashboards/{dashboard_id}/widgets        add_widget
  GET   /api/v1/metrics-dashboard/dashboards/{dashboard_id}/widgets        list_widgets
  POST  /api/v1/metrics-dashboard/snapshots                               record_snapshot
  GET   /api/v1/metrics-dashboard/snapshots                               get_metric_history
  GET   /api/v1/metrics-dashboard/stats                                   get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/metrics-dashboard",
    tags=["Security Metrics Dashboard"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_metrics_dashboard_engine import (
            SecurityMetricsDashboardEngine,
        )
        _engine = SecurityMetricsDashboardEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DashboardCreate(BaseModel):
    name: str
    dashboard_type: str = "operational"
    refresh_interval: int = 60
    widgets: List[Any] = Field(default_factory=list)


class WidgetCreate(BaseModel):
    widget_type: str
    metric_name: str
    data_source: str
    config: Dict[str, Any] = Field(default_factory=dict)
    position_x: int = 0
    position_y: int = 0


class SnapshotCreate(BaseModel):
    dashboard_id: str
    metric_name: str
    metric_value: float
    metric_unit: str = ""
    tags: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------

@router.post("/dashboards", dependencies=[Depends(api_key_auth)], status_code=201)
def create_dashboard(body: DashboardCreate, org_id: str = Query(default="default")):
    """Create a new metrics dashboard."""
    try:
        return _get_engine().create_dashboard(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/dashboards", dependencies=[Depends(api_key_auth)])
def list_dashboards(
     org_id: str = Query(default="default"),
    dashboard_type: Optional[str] = Query(None),
):
    """List dashboards with optional type filter."""
    return _get_engine().list_dashboards(org_id, dashboard_type=dashboard_type)


@router.get("/dashboards/{dashboard_id}", dependencies=[Depends(api_key_auth)])
def get_dashboard(dashboard_id: str, org_id: str = Query(default="default")):
    """Get a single dashboard by ID."""
    dashboard = _get_engine().get_dashboard(org_id, dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return dashboard


# ---------------------------------------------------------------------------
# Widgets
# ---------------------------------------------------------------------------

@router.post(
    "/dashboards/{dashboard_id}/widgets",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_widget(dashboard_id: str, body: WidgetCreate, org_id: str = Query(default="default")):
    """Add a widget to a dashboard."""
    try:
        result = _get_engine().add_widget(org_id, dashboard_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return result


@router.get("/dashboards/{dashboard_id}/widgets", dependencies=[Depends(api_key_auth)])
def list_widgets(dashboard_id: str, org_id: str = Query(default="default")):
    """List all widgets for a dashboard."""
    return _get_engine().list_widgets(org_id, dashboard_id)


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

@router.post("/snapshots", dependencies=[Depends(api_key_auth)], status_code=201)
def record_snapshot(body: SnapshotCreate, org_id: str = Query(default="default")):
    """Record a metric snapshot."""
    try:
        return _get_engine().record_metric_snapshot(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/snapshots", dependencies=[Depends(api_key_auth)])
def get_metric_history(
     org_id: str = Query(default="default"),
    dashboard_id: str = Query(...),
    metric_name: str = Query(...),
    limit: int = Query(50, ge=1, le=500),
):
    """Get metric snapshot history."""
    return _get_engine().get_metric_history(
        org_id, dashboard_id, metric_name, limit=limit
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")):
    """Return aggregated dashboard statistics."""
    return _get_engine().get_dashboard_stats(org_id)
