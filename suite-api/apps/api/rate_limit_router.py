"""Rate Limit V2 API Router.

Endpoints:
    GET  /api/v1/rate-limits/config              — list current endpoint tier config
    PUT  /api/v1/rate-limits/config              — update a tier's config or add an endpoint mapping
    GET  /api/v1/rate-limits/dashboard           — usage dashboard for an org
    POST /api/v1/rate-limits/reset/{api_key_id}  — reset rate limit window for a key

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.rate_limiter_v2 import RateLimiterV2, RateLimitTier, get_rate_limiter
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rate-limits", tags=["rate-limits"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class EndpointConfigUpdate(BaseModel):
    """Body for updating an endpoint tier mapping or per-key override."""

    path_pattern: Optional[str] = Field(
        None,
        description="Regex pattern for the endpoint path (e.g. '^/api/v1/custom').",
    )
    tier: Optional[RateLimitTier] = Field(
        None,
        description="Rate limit tier to assign to the path pattern.",
    )
    api_key_id: Optional[str] = Field(
        None,
        description="API key ID to apply a per-key request-per-minute override.",
    )
    requests_per_minute: Optional[int] = Field(
        None,
        ge=0,
        description="Requests per minute for the per-key override. 0 removes override.",
    )


class EndpointConfigResponse(BaseModel):
    pattern: str
    tier: str
    requests_per_minute: int
    burst_allowance: int
    window_seconds: int


class ConfigResponse(BaseModel):
    endpoint_tiers: List[Dict[str, Any]]
    per_key_overrides: Dict[str, int]


class DashboardResponse(BaseModel):
    org_id: str
    tracked_keys: int
    top_consumers: List[Dict[str, Any]]
    endpoint_tiers: List[Dict[str, Any]]
    per_key_overrides: Dict[str, int]


class ResetResponse(BaseModel):
    status: str
    api_key_id: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/config",
    response_model=ConfigResponse,
    summary="Get current rate limit endpoint tier configuration",
)
async def get_config() -> ConfigResponse:
    """Return the current endpoint→tier mappings and per-key overrides."""
    limiter: RateLimiterV2 = get_rate_limiter()
    return ConfigResponse(
        endpoint_tiers=limiter.get_endpoint_configs(),
        per_key_overrides=dict(limiter._key_limits),
    )


@router.put(
    "/config",
    response_model=Dict[str, str],
    summary="Update endpoint tier mapping or per-key rate limit override",
)
async def update_config(body: EndpointConfigUpdate) -> Dict[str, str]:
    """Update endpoint tier mapping and/or per-key request limit.

    - Provide ``path_pattern`` + ``tier`` to register a new endpoint mapping.
    - Provide ``api_key_id`` + ``requests_per_minute`` to set a per-key override
      (set ``requests_per_minute`` to 0 to remove the override).
    """
    limiter: RateLimiterV2 = get_rate_limiter()

    if body.path_pattern and body.tier:
        limiter.configure_endpoint(body.path_pattern, body.tier)
        logger.info(
            "rate_limit_config_updated pattern=%s tier=%s",
            body.path_pattern,
            body.tier.value,
        )

    if body.api_key_id and body.requests_per_minute is not None:
        limiter.configure_key_limit(body.api_key_id, body.requests_per_minute)
        logger.info(
            "rate_limit_key_override_set api_key_id=%s rpm=%d",
            body.api_key_id,
            body.requests_per_minute,
        )

    if not (body.path_pattern and body.tier) and not (
        body.api_key_id and body.requests_per_minute is not None
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "Provide either (path_pattern + tier) to update endpoint mapping, "
                "or (api_key_id + requests_per_minute) to set a per-key override."
            ),
        )

    return {"status": "ok"}


@router.get(
    "/dashboard",
    response_model=DashboardResponse,
    summary="Rate limit usage dashboard",
)
async def dashboard(
    org_id: str = Query("default", description="Organisation ID for the dashboard"),
) -> DashboardResponse:
    """Return a usage snapshot: top consumers, endpoint tiers, per-key overrides."""
    limiter: RateLimiterV2 = get_rate_limiter()
    data = limiter.get_quota_dashboard(org_id)
    return DashboardResponse(**data)


@router.post(
    "/reset/{api_key_id}",
    response_model=ResetResponse,
    summary="Reset rate limit window for a specific API key",
)
async def reset_key(api_key_id: str) -> ResetResponse:
    """Clear all sliding window entries for the given API key ID.

    This allows the key to make requests immediately, regardless of prior usage.
    """
    if not api_key_id or not api_key_id.strip():
        raise HTTPException(status_code=422, detail="api_key_id must not be empty.")
    limiter: RateLimiterV2 = get_rate_limiter()
    limiter.reset_key(api_key_id)
    logger.info("rate_limit_reset api_key_id=%s", api_key_id)
    return ResetResponse(status="ok", api_key_id=api_key_id)


# ---------------------------------------------------------------------------
# Token-bucket middleware stats endpoints (new — uses RateLimitMiddleware)
# ---------------------------------------------------------------------------

from apps.api.rate_limit_middleware import get_rate_limit_stats  # noqa: E402


class TokenBucketStatsResponse(BaseModel):
    tracked_keys: int
    buckets: Dict[str, Any]
    config: Dict[str, Any]
    warning: Optional[str] = None


@router.get(
    "/stats",
    response_model=TokenBucketStatsResponse,
    summary="Current token-bucket rate limit usage (admin only)",
)
async def get_stats() -> TokenBucketStatsResponse:
    """Return per-bucket token counts from the RateLimitMiddleware instance."""
    data = get_rate_limit_stats()
    return TokenBucketStatsResponse(**data)
