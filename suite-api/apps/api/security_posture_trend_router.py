"""Security Posture Trend Router — ALDECI.

Trend analysis of security posture over time with predictive insights.

Prefix: /api/v1/posture-trends
Auth: api_key_auth

Routes:
  POST   /api/v1/posture-trends/datapoints                      record_datapoint
  POST   /api/v1/posture-trends/analyze/{metric_name}           analyze_trend
  GET    /api/v1/posture-trends/trends                          list_trends
  GET    /api/v1/posture-trends/trends/{metric_name}            get_trend
  POST   /api/v1/posture-trends/targets                         set_target
  PUT    /api/v1/posture-trends/targets/{metric_name}/progress  update_target_progress
  GET    /api/v1/posture-trends/targets                         get_targets
  GET    /api/v1/posture-trends/stagnating                      get_stagnating_metrics
  GET    /api/v1/posture-trends/velocity-summary                get_posture_velocity_summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/posture-trends",
    tags=["Security Posture Trends"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_posture_trend_engine import SecurityPostureTrendEngine
        _engine = SecurityPostureTrendEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RecordDatapointRequest(BaseModel):
    metric_name: str = Field(..., description="Name of the security metric")
    metric_category: str = Field(
        ...,
        description=(
            "vulnerability | compliance | identity | network | "
            "endpoint | cloud | data | awareness"
        ),
    )
    value: float = Field(..., description="Metric value")
    unit: str = Field(
        default="score",
        description="score | percentage | count | days | hours",
    )
    source: str = Field(default="", description="Source system or tool")


class AnalyzeTrendRequest(BaseModel):
    period_days: int = Field(
        default=30, ge=1, description="Number of days to analyze"
    )


class SetTargetRequest(BaseModel):
    metric_name: str = Field(..., description="Metric to target")
    target_value: float = Field(..., description="Desired target value")
    current_value: float = Field(..., description="Current metric value")
    set_by: str = Field(default="", description="Who set the target")


class UpdateProgressRequest(BaseModel):
    current_value: float = Field(..., description="Updated current metric value")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_posture_trends(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get security posture velocity summary for the org."""
    return _get_engine().get_posture_velocity_summary(org_id=org_id)


@router.post("/datapoints", dependencies=[Depends(api_key_auth)])
def record_datapoint(
    req: RecordDatapointRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Record a new security posture data point."""
    try:
        return _get_engine().record_datapoint(
            org_id=org_id,
            metric_name=req.metric_name,
            metric_category=req.metric_category,
            value=req.value,
            unit=req.unit,
            source=req.source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/analyze/{metric_name}", dependencies=[Depends(api_key_auth)])
def analyze_trend(
    metric_name: str,
    req: AnalyzeTrendRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Run trend analysis for a metric over the given period."""
    try:
        return _get_engine().analyze_trend(
            org_id=org_id,
            metric_name=metric_name,
            period_days=req.period_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/trends", dependencies=[Depends(api_key_auth)])
def list_trends(
    org_id: str = Query(..., description="Organization ID"),
    trend_label: Optional[str] = Query(
        default=None,
        description="Filter by: improving | declining | stable",
    ),
) -> List[Dict[str, Any]]:
    """List latest trend analyses per metric."""
    return _get_engine().list_trends(org_id, trend_label=trend_label)


@router.get("/trends/{metric_name}", dependencies=[Depends(api_key_auth)])
def get_trend(
    metric_name: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Get the latest trend analysis for a specific metric."""
    trend = _get_engine().get_trend(org_id, metric_name)
    if trend is None:
        raise HTTPException(
            status_code=404,
            detail=f"No trend analysis found for metric '{metric_name}'",
        )
    return trend


@router.post("/targets", dependencies=[Depends(api_key_auth)])
def set_target(
    req: SetTargetRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Set or update a posture target for a metric."""
    return _get_engine().set_target(
        org_id=org_id,
        metric_name=req.metric_name,
        target_value=req.target_value,
        current_value=req.current_value,
        set_by=req.set_by,
    )


@router.put("/targets/{metric_name}/progress", dependencies=[Depends(api_key_auth)])
def update_target_progress(
    metric_name: str,
    req: UpdateProgressRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update the current value and recompute gap/ETA for a target."""
    try:
        return _get_engine().update_target_progress(
            org_id=org_id,
            metric_name=metric_name,
            current_value=req.current_value,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/targets", dependencies=[Depends(api_key_auth)])
def get_targets(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """List all posture targets with on_track boolean."""
    return _get_engine().get_targets(org_id)


@router.get("/stagnating", dependencies=[Depends(api_key_auth)])
def get_stagnating_metrics(
    org_id: str = Query(..., description="Organization ID"),
    threshold_days: int = Query(
        default=30, ge=1, description="Days without datapoints to be considered stagnating"
    ),
) -> List[str]:
    """Return metric names with no datapoints in the last threshold_days days."""
    return _get_engine().get_stagnating_metrics(org_id, threshold_days=threshold_days)


@router.get("/velocity-summary", dependencies=[Depends(api_key_auth)])
def get_posture_velocity_summary(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return avg velocity per category plus fastest improving/declining metrics."""
    return _get_engine().get_posture_velocity_summary(org_id)
