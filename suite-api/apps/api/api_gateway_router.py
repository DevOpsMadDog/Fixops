"""
API Gateway Security Router — 8 endpoints under /api/v1/gateway

Endpoints:
  POST   /api/v1/gateway/check              — Full gateway check (IP + rate limit + validation)
  GET    /api/v1/gateway/rate-limits        — Tier config + current counters
  PUT    /api/v1/gateway/rate-limits/tiers  — Update tier configuration
  GET    /api/v1/gateway/ip-rules           — List IP allowlist/blocklist rules
  POST   /api/v1/gateway/ip-rules           — Add an IP rule
  DELETE /api/v1/gateway/ip-rules/{rule_id} — Remove an IP rule
  POST   /api/v1/gateway/throttle-policies  — Set a per-key/IP throttle policy
  GET    /api/v1/gateway/analytics          — Usage analytics summary
  GET    /api/v1/gateway/version-stats      — API version usage + deprecation alerts
  GET    /api/v1/gateway/health             — Health check
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.api_gateway import (
    APIGatewayEngine,
    IPRuleAction,
    PlanTier,
    RateLimitConfig,
    ThrottlePolicy,
    get_api_gateway_engine,
)
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/gateway", tags=["api-gateway"])


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _engine() -> APIGatewayEngine:
    try:
        return get_api_gateway_engine()
    except Exception as exc:
        _logger.exception("api_gateway_engine_unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"API Gateway Engine unavailable: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class GatewayCheckRequest(BaseModel):
    endpoint: str = Field(..., description="API endpoint path being requested")
    method: str = Field("GET", description="HTTP method")
    ip: str = Field(..., description="Client IP address")
    content_type: Optional[str] = Field(None, description="Content-Type header value")
    payload_size_bytes: int = Field(0, ge=0, description="Request body size in bytes")
    api_key_id: Optional[str] = Field(None, description="API key ID for the request")
    org_id: Optional[str] = Field(None, description="Organisation ID")
    api_version: str = Field("v1", description="API version requested")
    plan_tier: PlanTier = Field(PlanTier.FREE, description="Client plan tier")
    required_fields: Optional[List[str]] = Field(None, description="Fields to validate in payload")
    payload_dict: Optional[Dict[str, Any]] = Field(None, description="Parsed request body")


class UpdateTierConfigRequest(BaseModel):
    tier: PlanTier
    requests_per_minute: int = Field(..., ge=1, le=1_000_000)
    requests_per_hour: int = Field(..., ge=1, le=10_000_000)
    burst_limit: int = Field(..., ge=1, le=100_000)
    sustained_limit: int = Field(..., ge=1, le=1_000_000)


class AddIPRuleRequest(BaseModel):
    cidr: str = Field(..., description="IP address or CIDR block, e.g. '10.0.0.0/8' or '1.2.3.4'")
    action: IPRuleAction = Field(..., description="'allow' or 'block'")
    description: str = Field("", description="Human-readable description")
    created_by: str = Field("api", description="Who created this rule")


class ThrottlePolicyRequest(BaseModel):
    target_id: str = Field(..., description="API key ID or IP address to throttle")
    target_type: str = Field("api_key", description="'api_key' or 'ip'")
    burst_limit: int = Field(..., ge=1, description="Max requests in 10-second burst window")
    sustained_limit: int = Field(..., ge=1, description="Max requests in 60-second sustained window")
    requests_per_minute: int = Field(..., ge=1)
    requests_per_hour: int = Field(..., ge=1)
    description: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/")
async def gateway_root() -> Dict[str, Any]:
    """
    API Gateway Policy summary — capabilities, tier limits, and active subsystem status.

    Returns a structured overview of all gateway policy dimensions:
    plan tier rate limits, IP filtering, throttle policy overrides,
    request validation constraints, and supported API versions.
    This is the canonical GET / for the gateway prefix.
    """
    engine = _engine()
    try:
        tier_configs = engine.rate_limiter.get_tier_configs()
        active_policies = engine.policy_store.list_policies()
        ip_rules = engine.ip_filter.list_rules()
        version_stats = engine.version_tracker.get_version_stats()
    except Exception as exc:
        _logger.exception("gateway_root_error")
        raise HTTPException(status_code=500, detail=f"Gateway policy summary failed: {exc}") from exc

    return {
        "service": "api-gateway-policy",
        "version": "1.0.0",
        "subsystems": {
            "rate_limiter": "ok",
            "ip_filter": "ok",
            "validator": "ok",
            "version_tracker": "ok",
            "analytics": "ok",
            "policy_store": "ok",
        },
        "tier_configs": tier_configs,
        "active_throttle_policies": len(active_policies),
        "active_ip_rules": len(ip_rules),
        "supported_api_versions": list(engine.version_tracker.SUPPORTED_VERSIONS),
        "deprecated_api_versions": list(engine.version_tracker.DEPRECATED_VERSIONS),
        "clients_on_deprecated": version_stats.get("clients_on_deprecated", 0),
        "request_validation": {
            "max_payload_bytes": engine.validator._max_payload_bytes,
            "allowed_content_types": sorted(engine.validator._allowed_content_types),
        },
        "windows": {
            "burst_seconds": 10,
            "minute_seconds": 60,
            "hour_seconds": 3600,
        },
    }


@router.post("/check")
async def gateway_check(req: GatewayCheckRequest) -> Dict[str, Any]:
    """
    Full gateway security check for an incoming request.

    Performs in order:
    1. IP allowlist/blocklist check
    2. Rate limit check (sliding window per key + per IP)
    3. Request validation (content-type, payload size, required fields)
    4. API version tracking + deprecation alert

    Returns allowed=True or allowed=False with the reason and details from each check.
    """
    engine = _engine()
    try:
        result = engine.process_request(
            endpoint=req.endpoint,
            method=req.method,
            ip=req.ip,
            content_type=req.content_type,
            payload_size_bytes=req.payload_size_bytes,
            api_key_id=req.api_key_id,
            org_id=req.org_id,
            api_version=req.api_version,
            plan_tier=req.plan_tier,
            required_fields=req.required_fields,
            payload_dict=req.payload_dict,
        )
    except Exception as exc:
        _logger.exception("gateway_check_error")
        raise HTTPException(status_code=500, detail=f"Gateway check failed: {exc}") from exc

    if not result["allowed"]:
        # Return 429 for rate-limit blocks, 403 for IP/policy blocks
        rl = result.get("rate_limit")
        if rl and not rl.get("allowed", True):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=result,
                headers={"Retry-After": str(rl.get("retry_after_seconds", 60))},
            )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=result)

    return result


@router.get("/rate-limits")
async def get_rate_limits() -> Dict[str, Any]:
    """Return current tier rate limit configurations."""
    engine = _engine()
    return {
        "tier_configs": engine.rate_limiter.get_tier_configs(),
        "burst_window_seconds": 10,
        "minute_window_seconds": 60,
        "hour_window_seconds": 3600,
    }


@router.put("/rate-limits/tiers")
async def update_tier_config(req: UpdateTierConfigRequest) -> Dict[str, Any]:
    """Update the rate limit configuration for a plan tier."""
    engine = _engine()
    config = RateLimitConfig(
        tier=req.tier,
        requests_per_minute=req.requests_per_minute,
        requests_per_hour=req.requests_per_hour,
        burst_limit=req.burst_limit,
        sustained_limit=req.sustained_limit,
    )
    engine.rate_limiter.update_tier_config(req.tier, config)
    _logger.info("rate_limit_tier_updated tier=%s", req.tier.value)
    return {
        "updated": True,
        "tier": req.tier.value,
        "config": config.model_dump(),
    }


@router.get("/ip-rules")
async def list_ip_rules(
    action: Optional[str] = Query(None, description="Filter by action: 'allow' or 'block'"),
) -> Dict[str, Any]:
    """List all active IP allowlist/blocklist rules."""
    engine = _engine()
    action_enum: Optional[IPRuleAction] = None
    if action:
        try:
            action_enum = IPRuleAction(action.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid action {action!r}. Must be 'allow' or 'block'.",
            )
    rules = engine.ip_filter.list_rules(action=action_enum)
    return {
        "total": len(rules),
        "rules": [r.model_dump() for r in rules],
    }


@router.post("/ip-rules", status_code=status.HTTP_201_CREATED)
async def add_ip_rule(req: AddIPRuleRequest) -> Dict[str, Any]:
    """Add an IP allowlist or blocklist rule. Supports CIDR notation."""
    engine = _engine()
    try:
        rule = engine.ip_filter.add_rule(
            cidr=req.cidr,
            action=req.action,
            description=req.description,
            created_by=req.created_by,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    return {"created": True, "rule": rule.model_dump()}


@router.delete("/ip-rules/{rule_id}")
async def remove_ip_rule(rule_id: str) -> Dict[str, Any]:
    """Soft-delete an IP rule by ID."""
    engine = _engine()
    removed = engine.ip_filter.remove_rule(rule_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP rule not found: {rule_id!r}",
        )
    return {"removed": True, "rule_id": rule_id}


@router.post("/throttle-policies", status_code=status.HTTP_201_CREATED)
async def set_throttle_policy(req: ThrottlePolicyRequest) -> Dict[str, Any]:
    """
    Set a custom throttle policy for a specific API key or IP.

    Overrides the plan tier defaults for that target. Use this to impose
    stricter limits on abusive callers or grant higher limits to VIP keys.
    """
    engine = _engine()
    policy = ThrottlePolicy(
        target_id=req.target_id,
        target_type=req.target_type,
        burst_limit=req.burst_limit,
        sustained_limit=req.sustained_limit,
        requests_per_minute=req.requests_per_minute,
        requests_per_hour=req.requests_per_hour,
        description=req.description,
    )
    try:
        saved = engine.policy_store.upsert_policy(policy)
        engine.rate_limiter.register_policy(saved)
    except Exception as exc:
        _logger.exception("throttle_policy_save_error")
        raise HTTPException(status_code=500, detail=f"Failed to save policy: {exc}") from exc

    return {"created": True, "policy": saved.model_dump()}


@router.delete("/throttle-policies/{target_id}")
async def delete_throttle_policy(target_id: str) -> Dict[str, Any]:
    """
    Remove a custom throttle policy for a specific API key or IP.

    After removal the target reverts to its plan tier defaults.
    Returns 404 if no active policy exists for the given target_id.
    """
    engine = _engine()
    removed = engine.policy_store.delete_policy(target_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active throttle policy found for target: {target_id!r}",
        )
    engine.rate_limiter.remove_policy(target_id)
    _logger.info("throttle_policy_deleted target_id=%s", target_id)
    return {"deleted": True, "target_id": target_id}


@router.get("/analytics")
async def get_analytics(
    hours: int = Query(24, ge=1, le=720, description="Lookback window in hours"),
    limit: int = Query(10, ge=1, le=100, description="Max results for top consumers"),
) -> Dict[str, Any]:
    """
    Return API usage analytics summary:
    - Per-endpoint stats (calls, error rate, latency percentiles)
    - Top consumers by API key
    - Error rate summary
    - Overall latency percentiles
    """
    engine = _engine()
    try:
        endpoint_stats = engine.analytics.get_endpoint_stats(hours=hours)
        top_consumers = engine.analytics.get_top_consumers(limit=limit, hours=hours)
        error_summary = engine.analytics.get_error_summary(hours=hours)
        latency = engine.analytics.get_latency_percentiles(hours=hours)
    except Exception as exc:
        _logger.exception("analytics_query_error")
        raise HTTPException(status_code=500, detail=f"Analytics query failed: {exc}") from exc

    return {
        "window_hours": hours,
        "endpoint_stats": endpoint_stats,
        "top_consumers": top_consumers,
        "error_summary": error_summary,
        "latency_percentiles": latency,
    }


@router.get("/version-stats")
async def get_version_stats() -> Dict[str, Any]:
    """
    Return API version usage statistics and deprecation alerts.

    Shows which clients are still using deprecated API versions
    and the distribution of usage across all supported versions.
    """
    engine = _engine()
    try:
        stats = engine.version_tracker.get_version_stats()
        alerts = engine.version_tracker.get_deprecation_alerts()
    except Exception as exc:
        _logger.exception("version_stats_error")
        raise HTTPException(status_code=500, detail=f"Version stats failed: {exc}") from exc

    return {
        "stats": stats,
        "deprecation_alerts": alerts,
        "alert_count": len(alerts),
    }


@router.get("/health")
async def health() -> Dict[str, Any]:
    """Health check for the API Gateway engine."""
    return {
        "status": "healthy",
        "engine": "api_gateway",
        "version": "1.0.0",
        "subsystems": {
            "rate_limiter": "ok",
            "ip_filter": "ok",
            "validator": "ok",
            "version_tracker": "ok",
            "analytics": "ok",
            "policy_store": "ok",
        },
    }
