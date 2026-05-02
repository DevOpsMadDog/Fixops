"""Integration Hub REST API router.

Endpoints (all under /api/v1/integrations):
    POST   /                           Register a new integration
    GET    /                           List all integrations
    DELETE /{name}                     Remove an integration
    GET    /health                     All integrations health summary
    GET    /{name}/health              Single integration health + circuit state
    POST   /{name}/reset-circuit       Reset circuit breaker for an integration
    POST   /webhooks                   Register a webhook (inbound or outbound)
    GET    /webhooks                   List webhooks
    DELETE /webhooks/{hook_id}         Remove a webhook
    POST   /routing-rules              Add an event routing rule
    GET    /routing-rules              List routing rules
    DELETE /routing-rules/{rule_id}    Remove a routing rule
    POST   /events/route               Route an event to matching integrations
    POST   /sync/inbound               Process an inbound status sync
    GET    /delivery-history           Recent delivery attempt history

Security:
    - API key authentication injected via auth_deps (consistent with other routers)
    - Credentials are masked in all responses
    - Input validated via Pydantic v2
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/integrations", tags=["Integration Hub"])


# ---------------------------------------------------------------------------
# Lazy hub access — avoids import-time side effects
# ---------------------------------------------------------------------------

def _hub():
    from core.integration_hub import get_hub
    return get_hub()


# ---------------------------------------------------------------------------
# Request / Response models (router-layer — thin wrappers over hub models)
# ---------------------------------------------------------------------------

class RegisterIntegrationRequest(BaseModel):
    name: str = Field(..., description="Unique slug name (lowercase, alphanumeric, dash/underscore)")
    integration_type: str = Field(..., description="One of: slack, jira, pagerduty, servicenow, teams, webhook")
    config: Dict[str, Any] = Field(..., description="Integration-specific configuration")
    tags: List[str] = Field(default_factory=list, description="Optional tags for grouping")


class RegisterWebhookRequest(BaseModel):
    integration_id: str = Field(..., description="Integration UUID this webhook belongs to")
    direction: str = Field(..., description="inbound | outbound | bidirectional")
    path: str = Field(..., description="Inbound path suffix or outbound URL")
    event_types: List[str] = Field(default_factory=list, description="Event types to filter (empty = all)")
    secret: Optional[str] = Field(None, description="HMAC-SHA256 signing secret")


class AddRoutingRuleRequest(BaseModel):
    event_type: str = Field(..., description="ALDECI event type (e.g. finding.created)")
    integration_ids: List[str] = Field(..., min_length=1, description="Target integration UUIDs")
    filter_expr: Optional[str] = Field(None, description="Optional key==value filter")
    template_name: Optional[str] = Field(None, description="Named message template override")


class RouteEventRequest(BaseModel):
    event_type: str = Field(..., description="ALDECI event type")
    payload: Dict[str, Any] = Field(..., description="Event data (id, title, severity, etc.)")


class InboundSyncRequest(BaseModel):
    integration_id: str = Field(..., description="Integration UUID that sent the sync")
    external_id: str = Field(..., description="External ticket/issue ID (e.g. SEC-42)")
    external_status: str = Field(..., description="Status from external system")
    aldeci_finding_id: Optional[str] = Field(None, description="ALDECI finding ID to update")
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="Full inbound payload")


# ---------------------------------------------------------------------------
# Connector management endpoints
# ---------------------------------------------------------------------------

@router.post("/", summary="Register a new integration")
async def register_integration(req: RegisterIntegrationRequest) -> Dict[str, Any]:
    """Register a new integration connector (Slack, Jira, PagerDuty, ServiceNow, Teams, webhook)."""
    from core.integration_hub import IntegrationType

    try:
        itype = IntegrationType(req.integration_type)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown integration_type '{req.integration_type}'. "
                   f"Valid: {[t.value for t in IntegrationType]}",
        )

    hub = _hub()
    try:
        hub.add_integration(
            name=req.name,
            integration_type=itype,
            config=req.config,
            tags=req.tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    resp = hub.get_integration(req.name)
    return {"status": "registered", "integration": resp.model_dump() if resp else {}}


@router.get("/", summary="List all integrations")
async def list_integrations(
    enabled_only: bool = Query(False, description="Return only enabled integrations"),
) -> Dict[str, Any]:
    """List all registered integration connectors."""
    hub = _hub()
    integrations = hub.list_integrations(enabled_only=enabled_only)
    return {
        "total": len(integrations),
        "integrations": [i.model_dump() for i in integrations],
    }


@router.delete("/{name}", summary="Remove an integration")
async def remove_integration(
    name: str = Path(..., description="Integration slug name"),
) -> Dict[str, Any]:
    """Deregister and remove an integration connector."""
    hub = _hub()
    removed = hub.remove_integration(name)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Integration '{name}' not found")
    return {"status": "removed", "name": name}


# ---------------------------------------------------------------------------
# Health endpoints
# ---------------------------------------------------------------------------

@router.get("/health", summary="All integrations health summary")
async def all_health() -> Dict[str, Any]:
    """Return health status for all registered integrations."""
    hub = _hub()
    summaries = hub.health_summary()
    return {
        "total": len(summaries),
        "integrations": summaries,
    }


@router.get("/{name}/health", summary="Single integration health")
async def integration_health(
    name: str = Path(..., description="Integration slug name"),
) -> Dict[str, Any]:
    """Return detailed health and circuit breaker state for one integration."""
    hub = _hub()
    hlth = hub.integration_health(name)
    if hlth is None:
        raise HTTPException(status_code=404, detail=f"Integration '{name}' not found")
    return hlth


@router.post("/{name}/reset-circuit", summary="Reset circuit breaker")
async def reset_circuit_breaker(
    name: str = Path(..., description="Integration slug name"),
) -> Dict[str, Any]:
    """Force-reset the circuit breaker for an integration back to CLOSED."""
    hub = _hub()
    reset = hub.reset_circuit_breaker(name)
    if not reset:
        raise HTTPException(status_code=404, detail=f"Integration '{name}' not found")
    return {"status": "reset", "name": name, "circuit_state": "closed"}


# ---------------------------------------------------------------------------
# Webhook endpoints
# ---------------------------------------------------------------------------

@router.post("/webhooks", summary="Register a webhook")
async def register_webhook(req: RegisterWebhookRequest) -> Dict[str, Any]:
    """Register an inbound or outbound webhook for an integration."""
    from core.integration_hub import EventType, SyncDirection

    try:
        direction = SyncDirection(req.direction)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown direction '{req.direction}'. Valid: inbound, outbound, bidirectional",
        )

    event_types = []
    for et in req.event_types:
        try:
            event_types.append(EventType(et))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Unknown event_type '{et}'")

    hub = _hub()
    hook = hub.add_webhook(
        integration_id=req.integration_id,
        direction=direction,
        path=req.path,
        event_types=event_types,
        secret=req.secret,
    )
    responses = hub.list_webhooks(integration_id=req.integration_id)
    matching = next((r for r in responses if r.id == hook.id), None)
    return {
        "status": "registered",
        "webhook": matching.model_dump() if matching else {"id": hook.id},
    }


@router.get("/webhooks", summary="List webhooks")
async def list_webhooks(
    integration_id: Optional[str] = Query(None, description="Filter by integration UUID"),
) -> Dict[str, Any]:
    """List all registered webhooks, optionally filtered by integration."""
    hub = _hub()
    hooks = hub.list_webhooks(integration_id=integration_id)
    return {
        "total": len(hooks),
        "webhooks": [h.model_dump() for h in hooks],
    }


@router.delete("/webhooks/{hook_id}", summary="Remove a webhook")
async def remove_webhook(
    hook_id: str = Path(..., description="Webhook UUID"),
) -> Dict[str, Any]:
    """Remove a registered webhook."""
    hub = _hub()
    removed = hub.remove_webhook(hook_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Webhook '{hook_id}' not found")
    return {"status": "removed", "webhook_id": hook_id}


# ---------------------------------------------------------------------------
# Routing rule endpoints
# ---------------------------------------------------------------------------

@router.post("/routing-rules", summary="Add an event routing rule")
async def add_routing_rule(req: AddRoutingRuleRequest) -> Dict[str, Any]:
    """Add a rule that routes a specific event type to one or more integrations."""
    from core.integration_hub import EventType

    try:
        event_type = EventType(req.event_type)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown event_type '{req.event_type}'. Valid: {[e.value for e in EventType]}",
        )

    hub = _hub()
    rule = hub.add_routing_rule(
        event_type=event_type,
        integration_ids=req.integration_ids,
        filter_expr=req.filter_expr,
        template_name=req.template_name,
    )
    return {"status": "created", "rule": rule.model_dump()}


@router.get("/routing-rules", summary="List routing rules")
async def list_routing_rules() -> Dict[str, Any]:
    """List all event routing rules."""
    hub = _hub()
    rules = hub.event_router.list_rules()
    return {
        "total": len(rules),
        "rules": [r.model_dump() for r in rules],
    }


@router.delete("/routing-rules/{rule_id}", summary="Remove a routing rule")
async def remove_routing_rule(
    rule_id: str = Path(..., description="Rule UUID"),
) -> Dict[str, Any]:
    """Remove an event routing rule."""
    hub = _hub()
    removed = hub.event_router.remove_rule(rule_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Routing rule '{rule_id}' not found")
    return {"status": "removed", "rule_id": rule_id}


# ---------------------------------------------------------------------------
# Event routing
# ---------------------------------------------------------------------------

@router.post("/events/route", summary="Route an event to matching integrations")
async def route_event(req: RouteEventRequest) -> Dict[str, Any]:
    """Route an event through the hub — resolves rules and delivers to all matching targets."""
    from core.integration_hub import EventType

    try:
        event_type = EventType(req.event_type)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown event_type '{req.event_type}'. Valid: {[e.value for e in EventType]}",
        )

    hub = _hub()
    results = hub.route_event(event_type=event_type, event_payload=req.payload)

    return {
        "event_type": req.event_type,
        "targets_reached": len(results),
        "successes": sum(1 for r in results if r.success),
        "failures": sum(1 for r in results if not r.success),
        "results": [r.model_dump() for r in results],
    }


# ---------------------------------------------------------------------------
# Bidirectional sync
# ---------------------------------------------------------------------------

@router.post("/sync/inbound", summary="Process an inbound status sync")
async def inbound_sync(req: InboundSyncRequest) -> Dict[str, Any]:
    """Accept a status update from an external integration and map it to an ALDECI finding."""
    hub = _hub()
    record = hub.process_inbound_sync(
        integration_id=req.integration_id,
        external_id=req.external_id,
        external_status=req.external_status,
        aldeci_finding_id=req.aldeci_finding_id,
        raw_payload=req.raw_payload,
    )
    return {"status": "synced", "sync_record": record.model_dump()}


# ---------------------------------------------------------------------------
# Delivery history
# ---------------------------------------------------------------------------

@router.get("/delivery-history", summary="Recent delivery attempt history")
async def delivery_history(
    limit: int = Query(100, ge=1, le=1000, description="Max records to return"),
) -> Dict[str, Any]:
    """Return recent delivery attempt history (successes and failures)."""
    hub = _hub()
    attempts = hub.delivery_history(limit=limit)
    return {
        "total": len(attempts),
        "attempts": [a.model_dump() for a in attempts],
    }
