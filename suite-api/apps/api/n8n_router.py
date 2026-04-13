"""n8n Webhook Connector Router — bidirectional bridge for workflow automation.

Endpoints:
    POST   /api/v1/n8n/webhooks                  -- Register a webhook
    DELETE /api/v1/n8n/webhooks/{webhook_id}      -- Unregister a webhook
    GET    /api/v1/n8n/webhooks                   -- List webhooks (optional ?event_type=)
    POST   /api/v1/n8n/trigger/{event_type}       -- Manually trigger an event type
    GET    /api/v1/n8n/history                    -- Event history
    GET    /api/v1/n8n/stats                      -- Statistics
    GET    /api/v1/n8n/health                     -- Connectivity test
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/n8n", tags=["n8n"])

# ---------------------------------------------------------------------------
# Lazy connector singleton
# ---------------------------------------------------------------------------

_connector: Optional[Any] = None


def _get_connector():
    global _connector
    if _connector is None:
        try:
            from connectors.n8n_connector import N8nConnector
            _connector = N8nConnector()
        except Exception as exc:
            logger.error("n8n_connector_init_failed: %s", exc)
            raise HTTPException(status_code=503, detail=f"n8n connector unavailable: {exc}")
    return _connector


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

VALID_EVENT_TYPES = {"finding", "incident", "sla_breach", "scan_complete", "alert"}


class RegisterWebhookRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Human-readable webhook name")
    event_type: str = Field(..., description="Event type to listen for")
    webhook_url: str = Field(..., min_length=10, max_length=2048, description="n8n webhook URL")

    model_config = {"str_strip_whitespace": True}


class TriggerPayload(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict, description="Custom payload to send")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/webhooks", status_code=201, summary="Register an n8n webhook")
def register_webhook(body: RegisterWebhookRequest) -> dict:
    """Register an n8n webhook URL to receive events of a given type."""
    if body.event_type not in VALID_EVENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid event_type '{body.event_type}'. Allowed: {sorted(VALID_EVENT_TYPES)}",
        )
    connector = _get_connector()
    try:
        result = connector.register_webhook(
            name=body.name,
            event_type=body.event_type,
            webhook_url=body.webhook_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return result


@router.delete("/webhooks/{webhook_id}", summary="Unregister an n8n webhook")
def unregister_webhook(
    webhook_id: str = Path(..., description="Webhook ID to remove"),
) -> dict:
    """Remove a registered webhook by ID."""
    connector = _get_connector()
    removed = connector.unregister_webhook(webhook_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Webhook '{webhook_id}' not found")
    return {"deleted": True, "webhook_id": webhook_id}


@router.get("/webhooks", summary="List registered webhooks")
def list_webhooks(
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
) -> List[dict]:
    """List all registered n8n webhooks, optionally filtered by event_type."""
    if event_type is not None and event_type not in VALID_EVENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid event_type '{event_type}'. Allowed: {sorted(VALID_EVENT_TYPES)}",
        )
    connector = _get_connector()
    return connector.list_webhooks(event_type=event_type)


@router.post("/trigger/{event_type}", summary="Manually trigger an event type")
def trigger_event(
    event_type: str = Path(..., description="Event type to trigger"),
    body: TriggerPayload = TriggerPayload(),
) -> dict:
    """Fire all webhooks registered for the given event type with a test payload."""
    if event_type not in VALID_EVENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid event_type '{event_type}'. Allowed: {sorted(VALID_EVENT_TYPES)}",
        )
    connector = _get_connector()
    results = connector.trigger_webhook(event_type=event_type, payload=body.payload)
    return {"event_type": event_type, "results": results, "total": len(results)}


@router.get("/history", summary="Event delivery history")
def get_history(
    limit: int = Query(default=50, ge=1, le=500, description="Max records to return"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
) -> List[dict]:
    """Return past webhook delivery events from the local store."""
    if event_type is not None and event_type not in VALID_EVENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid event_type '{event_type}'. Allowed: {sorted(VALID_EVENT_TYPES)}",
        )
    connector = _get_connector()
    return connector.get_event_history(limit=limit, event_type=event_type)


@router.get("/stats", summary="Webhook delivery statistics")
def get_stats() -> dict:
    """Return aggregate statistics: total webhooks, events, success rate, breakdown by type."""
    connector = _get_connector()
    return connector.get_stats()


@router.get("/health", summary="n8n connectivity check")
def health_check() -> dict:
    """Test whether the configured n8n instance is reachable."""
    connector = _get_connector()
    result = connector.test_connectivity()
    return result
