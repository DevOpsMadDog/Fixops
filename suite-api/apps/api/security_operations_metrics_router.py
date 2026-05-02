"""Security Operations Metrics Router — ALDECI.

Endpoints for the Security Operations Metrics engine.

Prefix: /api/v1/soc-metrics
Auth:   api_key_auth dependency on ALL endpoints

Routes:
  POST /api/v1/soc-metrics/alerts                          create_alert
  PUT  /api/v1/soc-metrics/alerts/{id}/acknowledge         acknowledge_alert
  PUT  /api/v1/soc-metrics/alerts/{id}/resolve             resolve_alert
  POST /api/v1/soc-metrics/snapshots                       take_daily_snapshot
  PUT  /api/v1/soc-metrics/workload                        update_analyst_workload
  GET  /api/v1/soc-metrics/summary                         get_soc_summary
  GET  /api/v1/soc-metrics/mttd-trend                      get_mttd_trend
  GET  /api/v1/soc-metrics/analyst-performance             get_analyst_performance
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/soc-metrics",
    tags=["Security Operations Metrics"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_operations_metrics_engine import (
            SecurityOperationsMetricsEngine,
        )
        _engine = SecurityOperationsMetricsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AlertCreate(BaseModel):
    org_id: str
    alert_source: str = "SIEM"
    severity: str = "medium"
    category: str = "other"
    detected_at: Optional[str] = None


class AlertAcknowledge(BaseModel):
    org_id: str
    analyst: str


class AlertResolve(BaseModel):
    org_id: str
    false_positive: bool = False


class SnapshotCreate(BaseModel):
    org_id: str
    snapshot_date: Optional[str] = None


class WorkloadUpdate(BaseModel):
    org_id: str
    analyst_name: str
    date: str
    alerts_assigned: int = Field(default=0, ge=0)
    alerts_resolved: int = Field(default=0, ge=0)
    avg_resolution_mins: float = Field(default=0.0, ge=0.0)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_soc_metrics(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get SOC metrics summary for the org."""
    return _get_engine().get_soc_summary(org_id=org_id)


@router.post("/alerts", dependencies=[Depends(api_key_auth)])
def create_alert(body: AlertCreate) -> Dict[str, Any]:
    """Create a new SOC alert."""
    try:
        return _get_engine().create_alert(
            org_id=body.org_id,
            alert_source=body.alert_source,
            severity=body.severity,
            category=body.category,
            detected_at=body.detected_at,
        )
    except Exception as exc:
        _logger.exception("create_alert error")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/alerts/{alert_id}/acknowledge", dependencies=[Depends(api_key_auth)])
def acknowledge_alert(alert_id: str, body: AlertAcknowledge) -> Dict[str, Any]:
    """Acknowledge a SOC alert and assign it to an analyst."""
    result = _get_engine().acknowledge_alert(
        alert_id=alert_id,
        org_id=body.org_id,
        analyst=body.analyst,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.put("/alerts/{alert_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_alert(alert_id: str, body: AlertResolve) -> Dict[str, Any]:
    """Resolve a SOC alert, optionally marking as false positive."""
    result = _get_engine().resolve_alert(
        alert_id=alert_id,
        org_id=body.org_id,
        false_positive=body.false_positive,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.post("/snapshots", dependencies=[Depends(api_key_auth)])
def take_daily_snapshot(body: SnapshotCreate) -> Dict[str, Any]:
    """Compute and store a daily SOC metrics snapshot."""
    try:
        return _get_engine().take_daily_snapshot(
            org_id=body.org_id,
            snapshot_date=body.snapshot_date,
        )
    except Exception as exc:
        _logger.exception("take_daily_snapshot error")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/workload", dependencies=[Depends(api_key_auth)])
def update_analyst_workload(body: WorkloadUpdate) -> Dict[str, Any]:
    """Insert or replace analyst workload record for a given date."""
    try:
        return _get_engine().update_analyst_workload(
            org_id=body.org_id,
            analyst_name=body.analyst_name,
            date_str=body.date,
            alerts_assigned=body.alerts_assigned,
            alerts_resolved=body.alerts_resolved,
            avg_resolution_mins=body.avg_resolution_mins,
        )
    except Exception as exc:
        _logger.exception("update_analyst_workload error")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_soc_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get SOC summary: open alerts, by_severity, by_status, last 7 snapshots, top analysts."""
    return _get_engine().get_soc_summary(org_id=org_id)


@router.get("/mttd-trend", dependencies=[Depends(api_key_auth)])
def get_mttd_trend(
     org_id: str = Query(default="default"),
    days: int = Query(default=30, ge=1, le=365),
) -> List[Dict[str, Any]]:
    """Get MTTD/MTTR trend from snapshots (last N days)."""
    return _get_engine().get_mttd_trend(org_id=org_id, days=days)


@router.get("/analyst-performance", dependencies=[Depends(api_key_auth)])
def get_analyst_performance(
     org_id: str = Query(default="default"),
    date: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """Get analyst performance records, optionally filtered by date."""
    return _get_engine().get_analyst_performance(org_id=org_id, date_str=date)
