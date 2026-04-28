"""
API Analytics router — 6 endpoints for monitoring API usage.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.api_analytics import APIAnalytics, APICall
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/api-analytics", tags=["api-analytics"])
_analytics = APIAnalytics()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RecordCallRequest(BaseModel):
    """Request body for recording an API call."""

    endpoint: str = Field(..., min_length=1)
    method: str = Field(..., min_length=1)
    status_code: int = Field(..., ge=100, le=599)
    response_ms: float = Field(..., ge=0.0)
    api_key_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/calls", status_code=201)
async def record_call(
    body: RecordCallRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Record a single API call."""
    call = APICall(
        endpoint=body.endpoint,
        method=body.method.upper(),
        status_code=body.status_code,
        response_ms=body.response_ms,
        api_key_id=body.api_key_id,
        org_id=org_id,
    )
    saved = _analytics.record_call(call)
    return {"id": saved.id, "status": "recorded"}


@router.get("/endpoints/{endpoint:path}/stats")
async def endpoint_stats(
    endpoint: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return call count, avg/p95 response time, and error rate for one endpoint."""
    return _analytics.get_endpoint_stats(endpoint=endpoint, org_id=org_id)


@router.get("/top-endpoints")
async def top_endpoints(
    limit: int = Query(10, ge=1, le=100),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return endpoints ranked by total call count."""
    return _analytics.get_top_endpoints(limit=limit, org_id=org_id)


@router.get("/slowest-endpoints")
async def slowest_endpoints(
    limit: int = Query(10, ge=1, le=100),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return endpoints ranked by average response time (slowest first)."""
    return _analytics.get_slowest_endpoints(limit=limit, org_id=org_id)


@router.get("/error-endpoints")
async def error_endpoints(
    limit: int = Query(10, ge=1, le=100),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return endpoints with highest error rates."""
    return _analytics.get_error_endpoints(limit=limit, org_id=org_id)


@router.get("/usage-over-time")
async def usage_over_time(
    bucket: str = Query("hour", pattern="^(hour|day)$"),
    days: int = Query(7, ge=1, le=365),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return call counts bucketed by hour or day over the last N days."""
    return _analytics.get_usage_over_time(bucket=bucket, days=days, org_id=org_id)
