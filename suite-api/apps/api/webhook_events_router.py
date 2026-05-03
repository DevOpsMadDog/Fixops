"""Webhook Events Router — register n8n webhooks and emit security events.

Endpoints:
    POST   /api/v1/events/webhooks              -- register webhook
    GET    /api/v1/events/webhooks              -- list registered webhooks
    DELETE /api/v1/events/webhooks/{webhook_id} -- unregister webhook
    POST   /api/v1/events/test/{webhook_id}     -- send test event to webhook
    GET    /api/v1/events/types                 -- list available event types

Security:
    - All endpoints protected with API key via _verify_api_key dependency
    - HMAC-SHA256 signed payloads
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import require_role
from apps.api.dependencies import get_org_id
from core.event_emitter import EventEmitter, EventType, SecurityEvent, Severity
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_ADMIN_ROLES = ("admin", "org_admin", "super_admin")

router = APIRouter(
    prefix="/api/v1/events",
    tags=["webhook-events"],
    dependencies=[require_role(*_ADMIN_ROLES)],
)

_emitter = EventEmitter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class RegisterWebhookRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="n8n webhook URL (HTTPS recommended)")
    event_types: List[str] = Field(..., min_length=1, max_length=20, description="Event types to subscribe to")
    secret: Optional[str] = Field(default=None, max_length=256, description="HMAC secret (auto-generated if omitted)")
    description: Optional[str] = Field(default=None, max_length=512)

    @classmethod
    def validate_event_types(cls, v: List[str]) -> List[str]:
        valid = {e.value for e in EventType}
        bad = [x for x in v if x not in valid]
        if bad:
            raise ValueError(f"Invalid event types: {bad}. Valid: {sorted(valid)}")
        return list(set(v))


class WebhookResponse(BaseModel):
    webhook_id: str
    url: str
    event_types: List[str]
    active: bool
    created_at: str
    description: Optional[str] = None


class TestEventRequest(BaseModel):
    severity: str = Field(default="info")
    payload: Dict[str, Any] = Field(default_factory=dict)


class DispatchEventRequest(BaseModel):
    event_type: str = Field(..., description="One of the canonical EventType values")
    source: str = Field(default="aldeci-api", max_length=128)
    severity: str = Field(default="info")
    payload: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/webhooks", status_code=201)
async def register_webhook(
    req: RegisterWebhookRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Register an n8n webhook URL for specific security event types."""
    # Validate event types
    valid = {e.value for e in EventType}
    bad = [x for x in req.event_types if x not in valid]
    if bad:
        raise HTTPException(422, f"Invalid event types: {bad}. Valid: {sorted(valid)}")

    try:
        event_type_enums = [EventType(et) for et in req.event_types]
        webhook_id = _emitter.register_webhook(
            url=req.url,
            event_types=event_type_enums,
            secret=req.secret,
            description=req.description,
        )
    except Exception as exc:
        logger.error("Failed to register webhook: %s", exc)
        raise HTTPException(500, "Failed to register webhook") from exc

    return {
        "webhook_id": webhook_id,
        "url": req.url,
        "event_types": req.event_types,
        "active": True,
        "description": req.description,
        "message": "Webhook registered successfully",
    }


@router.get("/webhooks")
async def list_webhooks(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List all active registered webhooks."""
    try:
        webhooks = _emitter.list_webhooks()
    except Exception as exc:
        logger.error("Failed to list webhooks: %s", exc)
        raise HTTPException(500, "Failed to list webhooks") from exc
    return webhooks


@router.delete("/webhooks/{webhook_id}")
async def unregister_webhook(
    webhook_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Unregister (deactivate) a webhook by ID."""
    try:
        found = _emitter.unregister_webhook(webhook_id)
    except Exception as exc:
        logger.error("Failed to unregister webhook %s: %s", webhook_id, exc)
        raise HTTPException(500, "Failed to unregister webhook") from exc

    if not found:
        raise HTTPException(404, f"Webhook {webhook_id} not found")

    return {"webhook_id": webhook_id, "status": "deactivated"}


@router.post("/test/{webhook_id}")
async def test_webhook(
    webhook_id: str,
    req: TestEventRequest = TestEventRequest(),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Send a test SecurityEvent to a specific registered webhook."""
    # Verify webhook exists
    try:
        webhooks = _emitter.list_webhooks()
    except Exception as exc:
        raise HTTPException(500, "Failed to query webhooks") from exc

    webhook = next((w for w in webhooks if w["id"] == webhook_id), None)
    if not webhook:
        raise HTTPException(404, f"Webhook {webhook_id} not found")

    # Build test event using the first registered event type for this webhook
    event_types = webhook.get("event_types", [])
    test_event_type = EventType(event_types[0]) if event_types else EventType.FINDING_CREATED

    try:
        severity = Severity(req.severity)
    except ValueError:
        severity = Severity.INFO

    test_event = SecurityEvent(
        event_type=test_event_type,
        source="aldeci-test",
        severity=severity,
        payload={
            "test": True,
            "webhook_id": webhook_id,
            "message": "Test event from ALdeci EventEmitter",
            **req.payload,
        },
    )

    results = _emitter.emit(test_event)
    result = next((r for r in results if r.get("webhook_id") == webhook_id), None)

    if result is None:
        # emit filtered it out — send directly to this webhook
        result = _emitter._deliver_with_retry(webhook, test_event)

    return {
        "webhook_id": webhook_id,
        "event_type": test_event.event_type,
        "correlation_id": test_event.correlation_id,
        "delivery_result": result,
    }


@router.post("/dispatch", status_code=202)
async def dispatch_event(
    req: DispatchEventRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Fan-out a security event to all matching registered webhooks.

    Returns per-webhook delivery results (status, response_code, attempts).
    202 Accepted — delivery is best-effort; callers should not assume success
    even when this endpoint returns 202.
    """
    try:
        event_type = EventType(req.event_type)
    except ValueError:
        valid = sorted(e.value for e in EventType)
        raise HTTPException(422, f"Invalid event_type '{req.event_type}'. Valid: {valid}")

    try:
        severity = Severity(req.severity)
    except ValueError:
        severity = Severity.INFO

    event = SecurityEvent(
        event_type=event_type,
        source=req.source,
        severity=severity,
        payload=req.payload,
    )

    try:
        results = _emitter.emit(event)
    except Exception as exc:
        logger.error("Dispatch failed for event_type=%s: %s", req.event_type, exc)
        raise HTTPException(500, "Event dispatch failed") from exc

    delivered = sum(1 for r in results if r.get("status") == "success")
    failed = len(results) - delivered

    return {
        "correlation_id": event.correlation_id,
        "event_type": event.event_type,
        "webhooks_matched": len(results),
        "delivered": delivered,
        "failed": failed,
        "results": results,
    }


@router.get("/types")
async def list_event_types() -> Dict[str, Any]:
    """List all available security event types."""
    types = [
        {"value": e.value, "name": e.name}
        for e in EventType
    ]
    return {
        "event_types": types,
        "count": len(types),
    }
