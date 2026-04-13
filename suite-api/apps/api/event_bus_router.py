"""
TrustGraph Event Bus REST API.

Endpoints:
    GET  /api/v1/event-bus/status  — Bus status + metrics
    GET  /api/v1/event-bus/queue   — Queued events count and breakdown
    POST /api/v1/event-bus/flush   — Force-flush the offline queue
    PUT  /api/v1/event-bus/config  — Enable/disable event types or master switch
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/event-bus", tags=["event-bus"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class EventBusStatusResponse(BaseModel):
    enabled: bool
    enabled_event_types: List[str]
    registered_handlers: Dict[str, int]
    metrics: Dict[str, Any]
    queue: Dict[str, Any]


class EventBusQueueResponse(BaseModel):
    queued: int
    indexed: int
    failed: int
    total: int
    max_size: int


class FlushResponse(BaseModel):
    attempted: int
    indexed: int
    failed: int


class ConfigRequest(BaseModel):
    enabled: Optional[bool] = Field(
        default=None, description="Master enable/disable switch"
    )
    enable_event_types: Optional[List[str]] = Field(
        default=None, description="Event types to enable"
    )
    disable_event_types: Optional[List[str]] = Field(
        default=None, description="Event types to disable"
    )


class ConfigResponse(BaseModel):
    enabled: bool
    enabled_event_types: List[str]
    changes_applied: List[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_bus():
    from core.trustgraph_event_bus import get_event_bus
    return get_event_bus()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/status", response_model=EventBusStatusResponse)
async def get_status() -> EventBusStatusResponse:
    """Return current EventBus status, metrics, and queue summary."""
    bus = _get_bus()
    status = bus.get_status()
    return EventBusStatusResponse(**status)


@router.get("/queue", response_model=EventBusQueueResponse)
async def get_queue() -> EventBusQueueResponse:
    """Return offline queue counts by status."""
    bus = _get_bus()
    stats = bus.queue_stats()
    return EventBusQueueResponse(
        queued=stats.get("queued", 0),
        indexed=stats.get("indexed", 0),
        failed=stats.get("failed", 0),
        total=stats.get("total", 0),
        max_size=stats.get("max_size", 10000),
    )


@router.post("/flush", response_model=FlushResponse)
async def flush_queue(batch_size: Optional[int] = None) -> FlushResponse:
    """Force-flush the offline queue through registered handlers.

    Args:
        batch_size: Max events to flush in this run (default: bus.batch_size).
    """
    bus = _get_bus()
    result = await bus.flush_queue(batch_size=batch_size)
    return FlushResponse(**result)


@router.put("/config", response_model=ConfigResponse)
async def update_config(body: ConfigRequest) -> ConfigResponse:
    """Enable or disable event types, or toggle the master switch."""
    bus = _get_bus()
    changes: List[str] = []

    if body.enabled is not None:
        bus.set_enabled(body.enabled)
        changes.append(f"master_enabled={body.enabled}")

    for et in body.enable_event_types or []:
        bus.enable_event_type(et)
        changes.append(f"enabled:{et}")

    for et in body.disable_event_types or []:
        bus.disable_event_type(et)
        changes.append(f"disabled:{et}")

    return ConfigResponse(
        enabled=bus.enabled,
        enabled_event_types=bus.get_enabled_types(),
        changes_applied=changes,
    )
