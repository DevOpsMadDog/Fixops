"""
User Activity Analytics API router.

Endpoints for recording user activity and querying analytics dashboards.
All endpoints require API key authentication.

Prefix: /api/v1/analytics/users
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.user_analytics import Activity, ActivityType, UserAnalyticsEngine, UserSession
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/analytics/users",
    tags=["user-analytics"],
    dependencies=[Depends(api_key_auth)],
)

# Module-level engine instance (shared across requests)
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = UserAnalyticsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class RecordActivityRequest(BaseModel):
    """Payload for recording a user activity event."""

    user_email: str = Field(..., min_length=1, description="User email address")
    activity_type: ActivityType
    endpoint: Optional[str] = Field(None, description="API endpoint path, if applicable")
    feature: Optional[str] = Field(None, description="Feature name, if applicable")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary event metadata")
    ip_address: str = Field(default="", description="Client IP address")
    org_id: str = Field(default="default", description="Organization ID for multi-tenancy")


class CleanupRequest(BaseModel):
    """Payload for triggering activity record cleanup."""

    days: int = Field(default=90, ge=1, description="Delete records older than this many days")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/activity", response_model=Activity, status_code=201)
async def record_activity(body: RecordActivityRequest) -> Activity:
    """Record a new user activity event."""
    try:
        return _get_engine().record_activity(
            user_email=body.user_email,
            activity_type=body.activity_type,
            endpoint=body.endpoint,
            feature=body.feature,
            metadata=body.metadata,
            ip=body.ip_address,
            org_id=body.org_id,
        )
    except Exception as exc:
        _logger.exception("Failed to record activity for %s", body.user_email)
        raise HTTPException(status_code=500, detail="Failed to record activity") from exc


@router.get("/activity/{user_email}", response_model=List[Activity])
async def get_user_activities(
    user_email: str,
    org_id: str = Query(default="default", description="Organization ID"),
    limit: int = Query(default=100, ge=1, le=1000, description="Max records to return"),
) -> List[Activity]:
    """Return recent activity events for a specific user."""
    return _get_engine().get_user_activities(user_email=user_email, org_id=org_id, limit=limit)


@router.get("/sessions", response_model=List[UserSession])
async def get_active_sessions(
    org_id: str = Query(default="default", description="Organization ID"),
) -> List[UserSession]:
    """Return currently active user sessions (activity within last 30 minutes)."""
    return _get_engine().get_active_sessions(org_id=org_id)


@router.get("/most-active", response_model=List[Dict[str, Any]])
async def get_most_active_users(
    org_id: str = Query(default="default"),
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=10, ge=1, le=100),
) -> List[Dict[str, Any]]:
    """Return top users by activity count over the specified period."""
    return _get_engine().get_most_active_users(org_id=org_id, days=days, limit=limit)


@router.get("/feature-usage", response_model=Dict[str, int])
async def get_feature_usage(
    org_id: str = Query(default="default"),
    days: int = Query(default=30, ge=1, le=365),
) -> Dict[str, int]:
    """Return feature usage counts over the specified period."""
    return _get_engine().get_feature_usage(org_id=org_id, days=days)


@router.get("/endpoint-usage", response_model=List[Dict[str, Any]])
async def get_endpoint_usage(
    org_id: str = Query(default="default"),
    days: int = Query(default=30, ge=1, le=365),
) -> List[Dict[str, Any]]:
    """Return most-called API endpoints over the specified period."""
    return _get_engine().get_endpoint_usage(org_id=org_id, days=days)


@router.get("/peak-hours", response_model=List[Dict[str, Any]])
async def get_peak_hours(
    org_id: str = Query(default="default"),
    days: int = Query(default=30, ge=1, le=365),
) -> List[Dict[str, Any]]:
    """Return activity distribution by hour of day (0-23)."""
    return _get_engine().get_peak_hours(org_id=org_id, days=days)


@router.get("/dau", response_model=List[Dict[str, Any]])
async def get_daily_active_users(
    org_id: str = Query(default="default"),
    days: int = Query(default=30, ge=1, le=365),
) -> List[Dict[str, Any]]:
    """Return daily active user (DAU) counts over the specified period."""
    return _get_engine().get_daily_active_users(org_id=org_id, days=days)


@router.get("/underutilized-features", response_model=List[str])
async def get_underutilized_features(
    org_id: str = Query(default="default"),
) -> List[str]:
    """Return features with fewer than 5 total uses."""
    return _get_engine().get_underutilized_features(org_id=org_id)


@router.get("/dashboard", response_model=Dict[str, Any])
async def get_usage_dashboard(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return all analytics metrics combined for dashboard display."""
    return _get_engine().get_usage_dashboard(org_id=org_id)


@router.post("/cleanup", response_model=Dict[str, Any])
async def cleanup_old_activities(body: CleanupRequest) -> Dict[str, Any]:
    """Purge activity records older than the specified number of days."""
    deleted = _get_engine().cleanup_old_activities(days=body.days)
    return {"deleted": deleted, "older_than_days": body.days}


@router.get("/health", response_model=Dict[str, Any])
async def user_analytics_health() -> Dict[str, Any]:
    """Health check for the user analytics service."""
    try:
        dashboard = _get_engine().get_usage_dashboard(org_id="default")
        return {"status": "healthy", "service": "aldeci-user-analytics", "version": "1.0.0",
                "metrics_tracked": len(dashboard)}
    except Exception as exc:
        return {"status": "degraded", "service": "aldeci-user-analytics", "error": str(exc)}


@router.get("/status", response_model=Dict[str, Any])
async def user_analytics_status() -> Dict[str, Any]:
    """Status alias — delegates to /health."""
    return await user_analytics_health()
