"""Metrics Timeseries Router — ALDECI (GAP-060).

Unified timeseries export across:
  - security_metrics_aggregator_engine (arbitrary metric_name series)
  - kpi_tracking_engine (registry of aggregatable keys)
  - security_posture_history_engine (fixed posture_score series)

Prefix: /api/v1/metrics-ts
Auth:   api_key_auth dependency

Endpoints:
  GET  /api/v1/metrics-ts/available?org_id=            list_available_metrics
  POST /api/v1/metrics-ts/export                        export_timeseries
  GET  /api/v1/metrics-ts/posture?org_id=&days=         posture_timeseries
  GET  /api/v1/metrics-ts/stats?org_id=                 aggregate stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/metrics-ts",
    tags=["Metrics Timeseries"],
    dependencies=[Depends(api_key_auth)],
)

_agg_engine = None
_kpi_engine = None
_posture_engine = None


def _get_aggregator():
    global _agg_engine
    if _agg_engine is None:
        from core.security_metrics_aggregator_engine import (
            SecurityMetricsAggregatorEngine,
        )
        _agg_engine = SecurityMetricsAggregatorEngine()
    return _agg_engine


def _get_kpi():
    global _kpi_engine
    if _kpi_engine is None:
        from core.kpi_tracking_engine import KPITrackingEngine
        _kpi_engine = KPITrackingEngine()
    return _kpi_engine


def _get_posture():
    global _posture_engine
    if _posture_engine is None:
        from core.security_posture_history_engine import (
            SecurityPostureHistoryEngine,
        )
        _posture_engine = SecurityPostureHistoryEngine()
    return _posture_engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ExportRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=256)
    metric_keys: List[str] = Field(..., min_length=1, max_length=20)
    days: int = Field(90, ge=1, le=365)
    bucket: str = Field("daily", pattern=r"^(daily|weekly|monthly)$")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/available")
def available_metrics(
    org_id: str = Query(..., min_length=1, max_length=256),
) -> Dict[str, Any]:
    """List all metric keys available for an org (kpi ∪ aggregator)."""
    try:
        return _get_kpi().list_available_metrics(
            org_id, aggregator=_get_aggregator()
        )
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("available_metrics failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/export")
def export_timeseries(payload: ExportRequest) -> Dict[str, Any]:
    """Export bucketed timeseries for 1..20 metric keys."""
    try:
        return _get_aggregator().export_timeseries(
            org_id=payload.org_id,
            metric_keys=payload.metric_keys,
            days=payload.days,
            bucket=payload.bucket,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("export_timeseries failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/posture")
def posture_timeseries(
    org_id: str = Query(..., min_length=1, max_length=256),
    days: int = Query(90, ge=1, le=365),
) -> Dict[str, Any]:
    """Daily posture_score timeseries for the last N days."""
    try:
        return _get_posture().posture_timeseries(org_id=org_id, days=days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("posture_timeseries failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats")
def timeseries_stats(
    org_id: str = Query(..., min_length=1, max_length=256),
) -> Dict[str, Any]:
    """Summary stats across all timeseries engines."""
    try:
        agg = _get_aggregator()
        available = _get_kpi().list_available_metrics(org_id, aggregator=agg)
        agg_stats = agg.get_aggregator_stats(org_id)
        kpi_stats = _get_kpi().get_kpi_stats(org_id)
        return {
            "org_id": org_id,
            "available_count": available.get("available_count", 0),
            "kpi_count": len(available.get("keys_by_source", {}).get("kpi_tracking", [])),
            "aggregator_count": len(
                available.get("keys_by_source", {}).get("security_metrics_aggregator", [])
            ),
            "total_metric_samples": agg_stats.get("total_metrics", 0),
            "total_kpis": kpi_stats.get("total_kpis", 0),
        }
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("timeseries_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
