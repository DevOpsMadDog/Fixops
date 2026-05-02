"""
Per-tenant rate limiting endpoints.

Prefix: /api/v1/rate-limits
Tags:   tenant-rate-limiting

Route ordering: static paths (/top-consumers, /cleanup, "") must appear
before parameterized paths (/{org_id}) so FastAPI does not swallow them.

Endpoints:
  GET    /api/v1/rate-limits                       get_all_quotas  (admin)
  GET    /api/v1/rate-limits/top-consumers         get_top_consumers (admin)
  POST   /api/v1/rate-limits/cleanup               cleanup_expired_windows (admin)
  POST   /api/v1/rate-limits/{org_id}              set_quota
  GET    /api/v1/rate-limits/{org_id}              get_quota
  GET    /api/v1/rate-limits/{org_id}/check        check_limit
  POST   /api/v1/rate-limits/{org_id}/record       record_request
  POST   /api/v1/rate-limits/{org_id}/reset        reset_usage
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.tenant_rate_limiter import TenantQuota, TenantRateLimiter
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/rate-limits", tags=["tenant-rate-limiting"])


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _limiter() -> TenantRateLimiter:
    try:
        return TenantRateLimiter()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"TenantRateLimiter unavailable: {exc}",
        )


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class SetQuotaRequest(BaseModel):
    tier: str = Field("free", description="Tier: free | starter | pro | enterprise")


class QuotaResponse(BaseModel):
    org_id: str
    tier: str
    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_limit: int
    current_usage: Dict[str, Any]


class CheckLimitResponse(BaseModel):
    allowed: bool
    denied_reason: Optional[str]
    org_id: str
    tier: str
    remaining_minute: int
    remaining_hour: int
    remaining_day: int
    limit_minute: int
    limit_hour: int
    limit_day: int
    burst_limit: int


def _quota_to_response(q: TenantQuota) -> QuotaResponse:
    return QuotaResponse(
        org_id=q.org_id,
        tier=q.tier,
        requests_per_minute=q.requests_per_minute,
        requests_per_hour=q.requests_per_hour,
        requests_per_day=q.requests_per_day,
        burst_limit=q.burst_limit,
        current_usage=q.current_usage,
    )


# ---------------------------------------------------------------------------
# Endpoints — static routes FIRST, parameterized routes AFTER
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=List[QuotaResponse],
    summary="List all tenant quotas (admin)",
)
async def get_all_quotas(
    limiter: TenantRateLimiter = Depends(_limiter),
) -> List[QuotaResponse]:
    """Admin view — all configured tenant quotas with current usage."""
    return [_quota_to_response(q) for q in limiter.get_all_quotas()]


@router.get(
    "/top-consumers",
    response_model=List[Dict[str, Any]],
    summary="Top API consumers in the last 24 hours (admin)",
)
async def get_top_consumers(
    limit: int = Query(10, ge=1, le=100),
    limiter: TenantRateLimiter = Depends(_limiter),
) -> List[Dict[str, Any]]:
    """Return the heaviest API consumers over the last 24 hours."""
    return limiter.get_top_consumers(limit=limit)


@router.post(
    "/cleanup",
    response_model=Dict[str, Any],
    summary="Purge request log entries older than 24 hours (admin)",
)
async def cleanup_expired_windows(
    limiter: TenantRateLimiter = Depends(_limiter),
) -> Dict[str, Any]:
    """Delete expired sliding-window entries from the request log."""
    return limiter.cleanup_expired_windows()


@router.post(
    "/{org_id}",
    response_model=QuotaResponse,
    status_code=status.HTTP_200_OK,
    summary="Set or update quota for an org",
)
async def set_quota(
    org_id: str,
    body: SetQuotaRequest,
    limiter: TenantRateLimiter = Depends(_limiter),
) -> QuotaResponse:
    """Configure rate-limit quota for an org by tier."""
    try:
        quota = limiter.set_quota(org_id, body.tier)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return _quota_to_response(quota)


@router.get(
    "/{org_id}/check",
    response_model=CheckLimitResponse,
    summary="Check whether an org is within its rate limits",
)
async def check_limit(
    org_id: str,
    limiter: TenantRateLimiter = Depends(_limiter),
) -> CheckLimitResponse:
    """Returns allowed/denied plus remaining counts for all windows."""
    result = limiter.check_limit(org_id)
    return CheckLimitResponse(**result)


@router.post(
    "/{org_id}/record",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Record a request against an org's quota",
)
async def record_request(
    org_id: str,
    limiter: TenantRateLimiter = Depends(_limiter),
) -> Dict[str, Any]:
    """Increment sliding-window counters for org_id."""
    limiter.record_request(org_id)
    return {"org_id": org_id, "status": "recorded"}


@router.post(
    "/{org_id}/reset",
    response_model=Dict[str, Any],
    summary="Manually reset all usage counters for an org",
)
async def reset_usage(
    org_id: str,
    limiter: TenantRateLimiter = Depends(_limiter),
) -> Dict[str, Any]:
    """Delete all request log entries for the org (manual reset)."""
    return limiter.reset_usage(org_id)


@router.get(
    "/{org_id}",
    response_model=QuotaResponse,
    summary="Get quota and current usage for an org",
)
async def get_quota(
    org_id: str,
    limiter: TenantRateLimiter = Depends(_limiter),
) -> QuotaResponse:
    """Return quota configuration and current usage counters."""
    quota = limiter.get_quota(org_id)
    if quota is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No quota configured for org {org_id!r}",
        )
    return _quota_to_response(quota)
