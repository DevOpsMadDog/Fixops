"""
RASP (Runtime Application Self-Protection) Router — ALDECI.

9 endpoints:
  GET  /api/v1/rasp/status                          — engine status + live metrics
  GET  /api/v1/rasp/threats                         — recent blocked/detected threats
  POST /api/v1/rasp/inspect                         — inspect an arbitrary request payload
  POST /api/v1/rasp/threats/{event_id}/false-positive — mark an event as a false positive
  GET  /api/v1/rasp/rules                           — active detection rules
  PUT  /api/v1/rasp/rules/{id}                      — enable / disable a rule
  GET  /api/v1/rasp/attackers                       — top attacker IPs with stats
  PUT  /api/v1/rasp/mode                            — switch operating mode
  GET  /api/v1/rasp/config                          — current RASP configuration
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "rasp_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.rasp_engine import (
    AttackerStats,
    DetectionPattern,
    RaspConfig,
    RaspEngine,
    RaspMode,
    ThreatCategory,
    ThreatEvent,
    get_rasp_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/rasp",
    tags=["RASP"],
    dependencies=_AUTH_DEP,
)


# ============================================================================
# Request / Response models
# ============================================================================


class RaspStatusResponse(BaseModel):
    """Combined status + metrics snapshot."""

    mode: RaspMode
    engine_uptime_seconds: float
    requests_inspected: int
    threats_detected: int
    threats_blocked: int
    threats_allowed_monitor: int
    threats_redirected: int
    false_positive_rate: float
    by_category: Dict[str, int]
    by_severity: Dict[str, int]
    top_attacker_ips: Dict[str, int]
    active_rules: int
    blocked_ips: int


class RuleToggleRequest(BaseModel):
    """Body for enabling / disabling a rule."""

    enabled: bool = Field(..., description="True to enable the rule, False to disable")


class RuleToggleResponse(BaseModel):
    rule_id: str
    enabled: bool
    found: bool


class SetModeRequest(BaseModel):
    """Body for switching RASP operating mode."""

    mode: RaspMode = Field(
        ...,
        description="New operating mode: monitor | block | redirect",
    )
    honeypot_url: Optional[str] = Field(
        None,
        description="Honeypot redirect URL (required when mode=redirect)",
    )


class SetModeResponse(BaseModel):
    mode: RaspMode
    message: str


class InspectRequest(BaseModel):
    """Payload for ad-hoc request inspection."""

    client_ip: str = Field("127.0.0.1", description="Client IP address")
    method: str = Field("GET", description="HTTP method")
    path: str = Field("/", description="Request path")
    query_params: Optional[Dict[str, str]] = Field(None, description="Query parameters")
    headers: Optional[Dict[str, str]] = Field(None, description="HTTP headers to inspect")
    body_text: Optional[str] = Field(None, description="Raw request body text")
    api_key: Optional[str] = Field(None, description="API key from the inspected request")
    org_id: str = Field("default", description="Tenant org_id")


class InspectResponse(BaseModel):
    """Result of an ad-hoc inspection."""

    blocked: bool
    threat_count: int
    threats: List[ThreatEvent]


class FalsePositiveRequest(BaseModel):
    """Body for reporting a false positive."""

    reporter: str = Field("system", description="Who is reporting the false positive")


class FalsePositiveResponse(BaseModel):
    event_id: str
    accepted: bool


# ============================================================================
# Singleton accessor
# ============================================================================


def _get_engine() -> RaspEngine:
    return get_rasp_engine()


# ============================================================================
# Endpoints
# ============================================================================


@router.get(
    "/status",
    response_model=RaspStatusResponse,
    summary="RASP engine status and live metrics",
)
def get_status() -> RaspStatusResponse:
    """
    Return a combined snapshot of the RASP engine status and runtime metrics.

    Includes:
    - Current operating mode
    - Engine uptime
    - Request and threat counters
    - Category / severity breakdown
    - Top attacker IPs (up to 10)
    - Number of active detection rules
    - Number of currently blocked IPs
    """
    engine = _get_engine()
    try:
        metrics = engine.get_metrics()
        rules = engine.get_rules()
        blocked = engine.get_blocked_ips()
        cfg = engine.config

        return RaspStatusResponse(
            mode=cfg.mode,
            engine_uptime_seconds=metrics.engine_uptime_seconds,
            requests_inspected=metrics.requests_inspected,
            threats_detected=metrics.threats_detected,
            threats_blocked=metrics.threats_blocked,
            threats_allowed_monitor=metrics.threats_allowed_monitor,
            threats_redirected=metrics.threats_redirected,
            false_positive_rate=metrics.false_positive_rate,
            by_category=metrics.by_category,
            by_severity=metrics.by_severity,
            top_attacker_ips=metrics.top_attacker_ips,
            active_rules=sum(1 for r in rules if r.enabled),
            blocked_ips=len(blocked),
        )
    except Exception as exc:
        logger.exception("rasp_router: failed to get status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/threats",
    response_model=List[ThreatEvent],
    summary="Recent detected threats",
)
def get_threats(
    limit: int = Query(50, ge=1, le=1000, description="Max results"),
    category: Optional[str] = Query(
        None,
        description="Filter by category: sqli | xss | cmdi | path_traversal | xxe | ssrf | lfi | rfi",
    ),
) -> List[ThreatEvent]:
    """
    Return recent threat events from the in-memory ring buffer (max 1000).

    Results are ordered newest-first. Filter by threat category with the
    ``category`` query parameter.
    """
    engine = _get_engine()
    cat_filter: Optional[ThreatCategory] = None
    if category:
        try:
            cat_filter = ThreatCategory(category.lower())
        except ValueError:
            valid = [c.value for c in ThreatCategory]
            raise HTTPException(
                status_code=422,
                detail=f"Invalid category '{category}'. Valid values: {valid}",
            )
    try:
        return engine.get_recent_threats(limit=limit, category=cat_filter)
    except Exception as exc:
        logger.exception("rasp_router: failed to get threats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/inspect",
    response_model=InspectResponse,
    summary="Inspect an arbitrary request payload for attack patterns",
)
def inspect_request(body: InspectRequest) -> InspectResponse:
    """
    Run the RASP engine against an arbitrary request payload and return
    detected threats plus whether the request would have been blocked.

    Useful for:
    - Testing payloads against the current rule set before deploying middleware
    - Security tooling that wants to pre-screen requests
    - Audit / forensics replay of historical traffic

    The engine honours the current operating mode (monitor / block / redirect)
    when computing the ``blocked`` flag, but this endpoint **never** actually
    blocks the caller — it only reports what *would* happen.
    """
    engine = _get_engine()
    try:
        blocked, threats = engine.inspect_request_sync(
            client_ip=body.client_ip,
            method=body.method,
            path=body.path,
            query_params=body.query_params,
            headers=body.headers,
            body_text=body.body_text,
            api_key=body.api_key,
            org_id=body.org_id,
        )
        return InspectResponse(
            blocked=blocked,
            threat_count=len(threats),
            threats=threats,
        )
    except Exception as exc:
        logger.exception("rasp_router: inspect failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/threats/{event_id}/false-positive",
    response_model=FalsePositiveResponse,
    summary="Mark a threat event as a false positive",
)
def report_false_positive(event_id: str, body: FalsePositiveRequest) -> FalsePositiveResponse:
    """
    Mark a previously recorded threat event as a false positive.

    This updates the engine's false-positive rate metric, which is used to
    calibrate confidence thresholds over time.  The ``reporter`` field can
    be set to the analyst's username or system name for audit purposes.
    """
    engine = _get_engine()
    try:
        accepted = engine.report_false_positive(event_id, reporter=body.reporter)
        if not accepted:
            raise HTTPException(
                status_code=404,
                detail=f"Event '{event_id}' not found or already marked.",
            )
        return FalsePositiveResponse(event_id=event_id, accepted=True)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("rasp_router: report_false_positive failed for %s", event_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/rules",
    response_model=List[DetectionPattern],
    summary="Active detection rules",
)
def get_rules() -> List[DetectionPattern]:
    """
    Return all detection rules (enabled and disabled).

    Each rule includes: rule_id, category, name, description, pattern,
    severity, confidence, and enabled flag.
    """
    engine = _get_engine()
    try:
        return engine.get_rules()
    except Exception as exc:
        logger.exception("rasp_router: failed to get rules")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put(
    "/rules/{rule_id}",
    response_model=RuleToggleResponse,
    summary="Enable or disable a detection rule",
)
def toggle_rule(rule_id: str, body: RuleToggleRequest) -> RuleToggleResponse:
    """
    Enable or disable a specific detection rule by its ID (e.g. ``SQLI-001``).

    Returns ``found=false`` if the rule ID does not exist.
    """
    engine = _get_engine()
    try:
        found = engine.set_rule_enabled(rule_id, body.enabled)
        if not found:
            raise HTTPException(
                status_code=404,
                detail=f"Rule '{rule_id}' not found. Use GET /api/v1/rasp/rules to list valid IDs.",
            )
        return RuleToggleResponse(rule_id=rule_id, enabled=body.enabled, found=True)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("rasp_router: failed to toggle rule %s", rule_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/attackers",
    response_model=List[AttackerStats],
    summary="Top attacker IPs with threat statistics",
)
def get_attackers(
    limit: int = Query(20, ge=1, le=100, description="Max results"),
) -> List[AttackerStats]:
    """
    Return the top attacker IPs ranked by total threat events, with a per-category
    breakdown and current block status.
    """
    engine = _get_engine()
    try:
        return engine.get_attacker_stats(limit=limit)
    except Exception as exc:
        logger.exception("rasp_router: failed to get attacker stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put(
    "/mode",
    response_model=SetModeResponse,
    summary="Switch RASP operating mode",
)
def set_mode(body: SetModeRequest) -> SetModeResponse:
    """
    Switch the RASP engine operating mode at runtime:

    - **monitor** — log threats and allow requests through (default, zero friction)
    - **block** — reject malicious requests with HTTP 403
    - **redirect** — forward malicious requests to a honeypot URL

    When switching to ``redirect`` mode you may optionally supply a
    ``honeypot_url``; if omitted the existing URL is kept.
    """
    engine = _get_engine()
    try:
        engine.set_mode(body.mode)
        if body.honeypot_url and body.mode == RaspMode.REDIRECT:
            engine.update_config(honeypot_url=body.honeypot_url)
        return SetModeResponse(
            mode=body.mode,
            message=f"RASP mode switched to '{body.mode.value}'",
        )
    except Exception as exc:
        logger.exception("rasp_router: failed to set mode")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/config",
    response_model=RaspConfig,
    summary="Current RASP configuration",
)
def get_config() -> RaspConfig:
    """
    Return the full current RASP engine configuration, including:

    - Operating mode
    - Honeypot URL
    - Rate limiting thresholds
    - Body inspection limits
    - Trusted IP list
    - Enabled threat categories
    """
    engine = _get_engine()
    try:
        return engine.config
    except Exception as exc:
        logger.exception("rasp_router: failed to get config")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
