"""
Metrics Aggregator API — ALDECI.

Unified metrics endpoint that aggregates all security data into one API call
for dashboards.

Protected with API key authentication via ``api_key_auth`` dependency.
"""

from __future__ import annotations

from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from core.metrics_aggregator import (
    Metric,
    MetricCategory,
    MetricsAggregator,
    MetricsSnapshot,
    get_metrics_aggregator,
)
from fastapi import APIRouter, Depends, HTTPException, Query

router = APIRouter(
    prefix="/api/v1/metrics",
    tags=["metrics-aggregator"],
    dependencies=[Depends(api_key_auth)],
)

_aggregator: "MetricsAggregator | None" = None  # lazy


def _get_aggregator() -> MetricsAggregator:
    global _aggregator
    if _aggregator is None:
        _aggregator = get_metrics_aggregator()
    return _aggregator


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/all", response_model=MetricsSnapshot)
async def get_all_metrics(
    org_id: str = Query("default", description="Organisation identifier"),
) -> MetricsSnapshot:
    """
    Return a full metrics snapshot aggregating all security categories
    (posture, vulnerability, compliance, SLA, attack surface, scanner,
    operational) in a single API call.
    """
    return _get_aggregator().collect_all_metrics(org_id=org_id)


@router.get("/category/{category}", response_model=List[Metric])
async def get_metrics_by_category(
    category: MetricCategory,
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[Metric]:
    """
    Return metrics for a specific category from the latest snapshot.

    If no snapshot exists for the org, an empty list is returned.
    """
    return _get_aggregator().get_category_metrics(org_id=org_id, category=category)


@router.get("/metric/{name}", response_model=Metric)
async def get_single_metric(
    name: str,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Metric:
    """
    Return a single named metric from the latest snapshot.

    Raises 404 if the metric is not found.
    """
    metric = _get_aggregator().get_metric(org_id=org_id, metric_name=name)
    if metric is None:
        raise HTTPException(status_code=404, detail=f"Metric '{name}' not found for org '{org_id}'")
    return metric


@router.get("/history/{name}", response_model=List[Dict[str, Any]])
async def get_metric_history(
    name: str,
    org_id: str = Query("default", description="Organisation identifier"),
    days: int = Query(30, ge=1, le=365, description="Number of days of history"),
) -> List[Dict[str, Any]]:
    """
    Return historical values for a single metric over time.

    Each entry has ``timestamp`` (ISO-8601) and ``value`` (float).
    """
    return _get_aggregator().get_metrics_history(org_id=org_id, metric_name=name, days=days)


@router.get("/compare", response_model=Dict[str, Any])
async def compare_periods(
    org_id: str = Query("default", description="Organisation identifier"),
    current_days: int = Query(7, ge=1, le=90, description="Current period length in days"),
    previous_days: int = Query(7, ge=1, le=90, description="Previous period length in days"),
) -> Dict[str, Any]:
    """
    Period-over-period comparison of key security metrics.

    Returns current values vs previous period averages with change percentages.
    """
    return _get_aggregator().compare_periods(
        org_id=org_id,
        current_days=current_days,
        previous_days=previous_days,
    )


@router.get("/health", response_model=Dict[str, Any])
async def get_health_check(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    System health check.

    Reports data freshness and availability of all security subsystems.
    """
    return _get_aggregator().get_health_check(org_id=org_id)
