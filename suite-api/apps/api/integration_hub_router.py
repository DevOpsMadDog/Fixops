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

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Path, Query
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
# Org-scoped name helpers
# The engine's ConnectorRegistry uses a flat dict keyed by `name` with no
# org_id field.  We namespace every integration name as "{org_id}__{name}"
# so that one org can never observe or mutate another org's integrations.
# The prefix is always stripped before returning responses to callers.
# ---------------------------------------------------------------------------

_SEP = "__"


def _scoped_name(org_id: str, name: str) -> str:
    """Return the internal registry key for an integration."""
    return f"{org_id}{_SEP}{name}"


def _unscoped_name(org_id: str, internal_name: str) -> str:
    """Strip the org prefix from an internal name before returning to caller."""
    prefix = org_id + _SEP
    if internal_name.startswith(prefix):
        return internal_name[len(prefix):]
    return internal_name


def _strip_prefix(org_id: str, resp: Any) -> Any:
    """Return a copy of an IntegrationRegistrationResponse with name unscoped."""
    if resp is None:
        return None
    d = resp.model_dump()
    d["name"] = _unscoped_name(org_id, d["name"])
    return d


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
async def register_integration(
    req: RegisterIntegrationRequest,
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
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

    internal_name = _scoped_name(org_id, req.name)
    hub = _hub()
    try:
        hub.add_integration(
            name=internal_name,
            integration_type=itype,
            config=req.config,
            tags=req.tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    resp = hub.get_integration(internal_name)
    return {"status": "registered", "integration": _strip_prefix(org_id, resp)}


@router.get("/", summary="List all integrations")
async def list_integrations(
    enabled_only: bool = Query(False, description="Return only enabled integrations"),
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List all registered integration connectors for the caller's org."""
    hub = _hub()
    prefix = org_id + _SEP
    integrations = [
        i for i in hub.list_integrations(enabled_only=enabled_only)
        if i.name.startswith(prefix)
    ]
    return {
        "total": len(integrations),
        "integrations": [_strip_prefix(org_id, i) for i in integrations],
    }


@router.delete("/{name}", summary="Remove an integration")
async def remove_integration(
    name: str = Path(..., description="Integration slug name"),
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Deregister and remove an integration connector owned by the caller's org."""
    internal_name = _scoped_name(org_id, name)
    hub = _hub()
    # Confirm it belongs to this org before removing
    existing = hub.get_integration(internal_name)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Integration '{name}' not found")
    removed = hub.remove_integration(internal_name)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Integration '{name}' not found")
    return {"status": "removed", "name": name}


# ---------------------------------------------------------------------------
# Health endpoints
# ---------------------------------------------------------------------------

@router.get("/health", summary="All integrations health summary")
async def all_health(
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return health status for all integrations owned by the caller's org."""
    hub = _hub()
    prefix = org_id + _SEP
    all_summaries = hub.health_summary()
    # health_summary() returns a list of dicts with an "integration_name" key
    summaries = [
        s for s in all_summaries
        if isinstance(s, dict) and s.get("integration_name", "").startswith(prefix)
    ]
    # Strip prefix from integration_name in each summary
    for s in summaries:
        s["integration_name"] = _unscoped_name(org_id, s["integration_name"])
    return {
        "total": len(summaries),
        "integrations": summaries,
    }


@router.get("/{name}/health", summary="Single integration health")
async def integration_health(
    name: str = Path(..., description="Integration slug name"),
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return detailed health and circuit breaker state for one integration."""
    internal_name = _scoped_name(org_id, name)
    hub = _hub()
    hlth = hub.integration_health(internal_name)
    if hlth is None:
        raise HTTPException(status_code=404, detail=f"Integration '{name}' not found")
    if isinstance(hlth, dict) and "integration_name" in hlth:
        hlth = dict(hlth)
        hlth["integration_name"] = _unscoped_name(org_id, hlth["integration_name"])
    return hlth


@router.post("/{name}/reset-circuit", summary="Reset circuit breaker")
async def reset_circuit_breaker(
    name: str = Path(..., description="Integration slug name"),
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Force-reset the circuit breaker for an integration back to CLOSED."""
    internal_name = _scoped_name(org_id, name)
    hub = _hub()
    # Guard: verify it belongs to this org
    if hub.get_integration(internal_name) is None:
        raise HTTPException(status_code=404, detail=f"Integration '{name}' not found")
    reset = hub.reset_circuit_breaker(internal_name)
    if not reset:
        raise HTTPException(status_code=404, detail=f"Integration '{name}' not found")
    return {"status": "reset", "name": name, "circuit_state": "closed"}


# ---------------------------------------------------------------------------
# Webhook endpoints
# ---------------------------------------------------------------------------

def _org_integration_ids(org_id: str) -> set:
    """Return the set of integration UUIDs owned by this org."""
    hub = _hub()
    prefix = org_id + _SEP
    return {
        i.id for i in hub.list_integrations()
        if i.name.startswith(prefix)
    }


@router.post("/webhooks", summary="Register a webhook")
async def register_webhook(
    req: RegisterWebhookRequest,
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Register an inbound or outbound webhook for an integration owned by the caller's org."""
    from core.integration_hub import EventType, SyncDirection

    # Guard: integration_id must belong to this org
    if req.integration_id not in _org_integration_ids(org_id):
        raise HTTPException(
            status_code=404,
            detail=f"Integration '{req.integration_id}' not found",
        )

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
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List webhooks for the caller's org (optionally filtered by integration UUID)."""
    hub = _hub()
    owned_ids = _org_integration_ids(org_id)

    if integration_id is not None:
        # Guard: the requested integration_id must belong to this org
        if integration_id not in owned_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Integration '{integration_id}' not found",
            )
        hooks = hub.list_webhooks(integration_id=integration_id)
    else:
        # Return only webhooks whose integration_id belongs to this org
        all_hooks = hub.list_webhooks()
        hooks = [h for h in all_hooks if h.integration_id in owned_ids]

    return {
        "total": len(hooks),
        "webhooks": [h.model_dump() for h in hooks],
    }


@router.delete("/webhooks/{hook_id}", summary="Remove a webhook")
async def remove_webhook(
    hook_id: str = Path(..., description="Webhook UUID"),
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Remove a registered webhook that belongs to the caller's org."""
    hub = _hub()
    owned_ids = _org_integration_ids(org_id)
    # Find the webhook and verify ownership before deletion
    all_hooks = hub.list_webhooks()
    target = next((h for h in all_hooks if h.id == hook_id), None)
    if target is None or target.integration_id not in owned_ids:
        raise HTTPException(status_code=404, detail=f"Webhook '{hook_id}' not found")
    removed = hub.remove_webhook(hook_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Webhook '{hook_id}' not found")
    return {"status": "removed", "webhook_id": hook_id}


# ---------------------------------------------------------------------------
# Routing rule endpoints
# ---------------------------------------------------------------------------

@router.post("/routing-rules", summary="Add an event routing rule")
async def add_routing_rule(
    req: AddRoutingRuleRequest,
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Add a rule routing a specific event type to one or more integrations owned by this org."""
    from core.integration_hub import EventType

    try:
        event_type = EventType(req.event_type)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown event_type '{req.event_type}'. Valid: {[e.value for e in EventType]}",
        )

    # Guard: all target integration_ids must belong to this org
    owned_ids = _org_integration_ids(org_id)
    foreign = [iid for iid in req.integration_ids if iid not in owned_ids]
    if foreign:
        raise HTTPException(
            status_code=404,
            detail=f"Integration(s) not found: {foreign}",
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
async def list_routing_rules(
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List event routing rules that reference only this org's integrations."""
    hub = _hub()
    owned_ids = _org_integration_ids(org_id)
    all_rules = hub.event_router.list_rules()
    # A rule belongs to this org if ALL of its integration_ids are org-owned
    rules = [
        r for r in all_rules
        if all(iid in owned_ids for iid in (r.integration_ids if hasattr(r, "integration_ids") else []))
    ]
    return {
        "total": len(rules),
        "rules": [r.model_dump() for r in rules],
    }


@router.delete("/routing-rules/{rule_id}", summary="Remove a routing rule")
async def remove_routing_rule(
    rule_id: str = Path(..., description="Rule UUID"),
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Remove an event routing rule that belongs to this org."""
    hub = _hub()
    owned_ids = _org_integration_ids(org_id)
    all_rules = hub.event_router.list_rules()
    target = next((r for r in all_rules if r.id == rule_id), None)
    if target is None or not all(
        iid in owned_ids
        for iid in (target.integration_ids if hasattr(target, "integration_ids") else [])
    ):
        raise HTTPException(status_code=404, detail=f"Routing rule '{rule_id}' not found")
    removed = hub.event_router.remove_rule(rule_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Routing rule '{rule_id}' not found")
    return {"status": "removed", "rule_id": rule_id}


# ---------------------------------------------------------------------------
# Event routing
# ---------------------------------------------------------------------------

@router.post("/events/route", summary="Route an event to matching integrations")
async def route_event(
    req: RouteEventRequest,
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
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
    # Inject org_id into payload so downstream rules can filter by org
    payload = {**req.payload, "_org_id": org_id}
    results = hub.route_event(event_type=event_type, event_payload=payload)

    # Filter delivery results to only this org's integrations
    owned_ids = _org_integration_ids(org_id)
    org_results = [r for r in results if getattr(r, "integration_id", None) in owned_ids]

    return {
        "event_type": req.event_type,
        "org_id": org_id,
        "targets_reached": len(org_results),
        "successes": sum(1 for r in org_results if r.success),
        "failures": sum(1 for r in org_results if not r.success),
        "results": [r.model_dump() for r in org_results],
    }


# ---------------------------------------------------------------------------
# Bidirectional sync
# ---------------------------------------------------------------------------

@router.post("/sync/inbound", summary="Process an inbound status sync")
async def inbound_sync(
    req: InboundSyncRequest,
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Accept a status update from an integration owned by the caller's org."""
    # Guard: integration_id must belong to this org
    if req.integration_id not in _org_integration_ids(org_id):
        raise HTTPException(
            status_code=404,
            detail=f"Integration '{req.integration_id}' not found",
        )
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
    org_id: str = Depends(get_org_id),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return recent delivery attempt history for this org's integrations."""
    hub = _hub()
    owned_ids = _org_integration_ids(org_id)
    all_attempts = hub.delivery_history(limit=limit * 10)  # fetch a wider window then filter
    org_attempts = [
        a for a in all_attempts
        if getattr(a, "integration_id", None) in owned_ids
    ][:limit]
    return {
        "total": len(org_attempts),
        "attempts": [a.model_dump() for a in org_attempts],
    }
