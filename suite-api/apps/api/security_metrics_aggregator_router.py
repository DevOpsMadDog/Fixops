"""Security Metrics Aggregator Router — ALDECI.

Endpoints for the Security Metrics Aggregator engine.

Prefix: /api/v1/metrics-aggregator
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/metrics-aggregator/sources                       register_source
  GET    /api/v1/metrics-aggregator/sources                       list_sources
  PUT    /api/v1/metrics-aggregator/sources/{source_id}/sync      sync_source
  POST   /api/v1/metrics-aggregator/metrics                       record_metric
  GET    /api/v1/metrics-aggregator/metrics                       list_metrics
  GET    /api/v1/metrics-aggregator/metrics/latest/{metric_name}  get_latest_metric
  POST   /api/v1/metrics-aggregator/aggregations                  create_aggregation
  GET    /api/v1/metrics-aggregator/aggregations                  list_aggregations
  GET    /api/v1/metrics-aggregator/stats                         get_aggregator_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/metrics-aggregator",
    tags=["Security Metrics Aggregator"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_metrics_aggregator_engine import (
            SecurityMetricsAggregatorEngine,
        )
        _engine = SecurityMetricsAggregatorEngine()
    return _engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class SourceCreate(BaseModel):
    source_name: str
    source_type: str = "custom"
    endpoint_url: str = ""
    active: bool = True


class SourceSyncUpdate(BaseModel):
    metric_count_delta: int = Field(0, description="Increment metric_count by this value")


class MetricRecord(BaseModel):
    source_id: str
    metric_name: str
    metric_type: str = "gauge"
    value: float = 0.0
    unit: str = ""
    category: str = "security"
    tags: Dict[str, Any] = {}
    collected_at: Optional[str] = None


class AggregationCreate(BaseModel):
    aggregation_name: str
    metric_names: List[str] = []
    aggregation_type: str = "avg"
    time_window_hours: int = 24
    result_value: float = 0.0
    confidence: float = Field(100.0, ge=0.0, le=100.0)
    computed_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Source endpoints
# ---------------------------------------------------------------------------

@router.post("/sources", dependencies=[Depends(api_key_auth)])
def register_source(body: SourceCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Register a new metrics source."""
    try:
        return _get_engine().register_source(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/sources", dependencies=[Depends(api_key_auth)])
def list_sources(
    org_id: str = Query("default"),
    source_type: Optional[str] = Query(None),
    active: Optional[bool] = Query(None),
) -> List[Dict[str, Any]]:
    """List registered metrics sources."""
    return _get_engine().list_sources(org_id, source_type=source_type, active=active)


@router.put("/sources/{source_id}/sync", dependencies=[Depends(api_key_auth)])
def sync_source(
    source_id: str,
    body: SourceSyncUpdate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Sync a source — increments metric count and updates last_sync."""
    try:
        return _get_engine().sync_source(org_id, source_id, body.metric_count_delta)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Metric endpoints
# ---------------------------------------------------------------------------

@router.post("/metrics", dependencies=[Depends(api_key_auth)])
def record_metric(body: MetricRecord, org_id: str = Query("default")) -> Dict[str, Any]:
    """Record a new metric observation."""
    try:
        return _get_engine().record_metric(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/metrics", dependencies=[Depends(api_key_auth)])
def list_metrics(
    org_id: str = Query("default"),
    source_id: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    metric_type: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List recorded metrics."""
    return _get_engine().list_metrics(
        org_id, source_id=source_id, category=category, metric_type=metric_type
    )


@router.get("/metrics/latest/{metric_name}", dependencies=[Depends(api_key_auth)])
def get_latest_metric(metric_name: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Get the most recent metric by collected_at for a given metric name."""
    result = _get_engine().get_latest_metric(org_id, metric_name)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No metric found for {metric_name!r}")
    return result


# ---------------------------------------------------------------------------
# Aggregation endpoints
# ---------------------------------------------------------------------------

@router.post("/aggregations", dependencies=[Depends(api_key_auth)])
def create_aggregation(body: AggregationCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Create an aggregation computation record."""
    try:
        return _get_engine().create_aggregation(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/aggregations", dependencies=[Depends(api_key_auth)])
def list_aggregations(
    org_id: str = Query("default"),
    aggregation_type: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List aggregation records."""
    return _get_engine().list_aggregations(org_id, aggregation_type=aggregation_type)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_aggregator_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregated metrics stats."""
    return _get_engine().get_aggregator_stats(org_id)
