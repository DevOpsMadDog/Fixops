"""SSE (Server-Sent Events) resumable event stream router — ALDECI.

CrowdStrike-parity real-time event streaming over HTTP without WebSocket.
SIEM integrations can consume this endpoint with standard SSE clients.

Prefix: /api/v1/events
Auth:   api_key_auth dependency

Routes:
  GET /api/v1/events/stream   -- Resumable SSE stream of security events
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from typing import AsyncGenerator, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/events",
    tags=["SSE Events"],
)

# ---------------------------------------------------------------------------
# In-memory event store (ring buffer, per-org, last 1000 events)
# ---------------------------------------------------------------------------
_MAX_EVENTS = 1000

# Maximum distinct org_ids tracked simultaneously.  When exceeded the oldest
# (LRU) org entry is evicted so long-running processes don't leak memory as
# tenants connect and disconnect over time.
_MAX_ORGS = 500

# Shared across connections: org_id -> list of event dicts (OrderedDict for LRU eviction)
# Each event: {"id": int, "event_type": str, "org_id": str, "data": dict, "ts": float}
_event_store: OrderedDict[str, list[dict]] = OrderedDict()
_event_counter: OrderedDict[str, int] = OrderedDict()

# Asyncio condition per org — notified when new events arrive (also LRU-capped)
_org_conditions: OrderedDict[str, asyncio.Condition] = OrderedDict()


def _evict_org_if_needed(d: OrderedDict, max_size: int) -> None:
    """Evict the least-recently-used org entry when the dict exceeds max_size."""
    while len(d) > max_size:
        d.popitem(last=False)


def _get_condition(org_id: str) -> asyncio.Condition:
    if org_id not in _org_conditions:
        _org_conditions[org_id] = asyncio.Condition()
        _evict_org_if_needed(_org_conditions, _MAX_ORGS)
    else:
        _org_conditions.move_to_end(org_id)
    return _org_conditions[org_id]


def publish_event(org_id: str, event_type: str, data: dict) -> int:
    """Publish a security event into the in-memory store and wake SSE listeners.

    Returns the assigned event ID.  Call this from any engine or background task
    to push real-time updates to connected SIEM clients.

    Args:
        org_id:     Tenant identifier.
        event_type: E.g. "alert", "finding", "incident", "anomaly", "audit".
        data:       Arbitrary JSON-serialisable payload.

    Returns:
        Assigned monotonic event ID (org-scoped).
    """
    if org_id not in _event_store:
        _event_store[org_id] = []
        _event_counter[org_id] = 0
        _evict_org_if_needed(_event_store, _MAX_ORGS)
        _evict_org_if_needed(_event_counter, _MAX_ORGS)
    else:
        _event_store.move_to_end(org_id)
        _event_counter.move_to_end(org_id)

    _event_counter[org_id] += 1
    event_id = _event_counter[org_id]

    event = {
        "id": event_id,
        "event_type": event_type,
        "org_id": org_id,
        "data": data,
        "ts": time.time(),
    }

    store = _event_store[org_id]
    store.append(event)
    # Trim to ring-buffer size
    if len(store) > _MAX_EVENTS:
        _event_store[org_id] = store[-_MAX_EVENTS:]

    # Wake any waiting SSE generators for this org
    if org_id in _org_conditions:
        cond = _org_conditions[org_id]
        # Schedule the notify on the running event loop without blocking
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_notify_condition(cond))
        except RuntimeError:
            pass  # No event loop (e.g. called from sync test context)

    return event_id


async def _notify_condition(cond: asyncio.Condition) -> None:
    async with cond:
        cond.notify_all()


def _get_events_since(org_id: str, last_id: int, event_type: Optional[str]) -> list[dict]:
    """Return all stored events with id > last_id, optionally filtered by type."""
    store = _event_store.get(org_id, [])
    results = [e for e in store if e["id"] > last_id]
    if event_type:
        results = [e for e in results if e["event_type"] == event_type]
    return results


# ---------------------------------------------------------------------------
# SSE generator
# ---------------------------------------------------------------------------

_KEEPALIVE_INTERVAL = 15  # seconds


async def _sse_generator(
    org_id: str,
    last_event_id: int,
    event_type: Optional[str],
    request: Request,
) -> AsyncGenerator[str, None]:
    """Async generator that yields SSE-formatted text frames.

    Protocol:
      - Replay any missed events (id > Last-Event-ID) on connect/reconnect.
      - Then wait for new events, yielding each as: event/id/data triple.
      - Send a keepalive comment every 15 s to prevent proxy timeouts.
      - Stop when the client disconnects (request.is_disconnected()).
    """
    condition = _get_condition(org_id)
    cursor = last_event_id

    while True:
        # Check client disconnect
        if await request.is_disconnected():
            _logger.debug("SSE client disconnected org=%s", org_id)
            break

        # Drain any buffered events since cursor
        pending = _get_events_since(org_id, cursor, event_type)
        if pending:
            for event in pending:
                cursor = event["id"]
                data_str = json.dumps(event["data"])
                frame = (
                    f"event: {event['event_type']}\n"
                    f"id: {event['id']}\n"
                    f"data: {data_str}\n\n"
                )
                yield frame
        else:
            # Wait up to KEEPALIVE_INTERVAL seconds for a new event
            try:
                async with condition:
                    await asyncio.wait_for(
                        condition.wait(),
                        timeout=_KEEPALIVE_INTERVAL,
                    )
            except asyncio.TimeoutError:
                # Send keepalive comment so proxies don't close the connection
                yield ": keepalive\n\n"
            except asyncio.CancelledError:
                break


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/stream",
    summary="Resumable SSE security event stream",
    response_class=StreamingResponse,
    dependencies=[Depends(api_key_auth)],
)
async def stream_events(
    request: Request,
    org_id: str = Query(..., description="Organization ID"),
    event_type: Optional[str] = Query(
        default=None,
        description="Filter by event type: alert | finding | incident | anomaly | audit",
    ),
) -> StreamingResponse:
    """Stream security events as Server-Sent Events (SSE).

    CrowdStrike-parity resumable stream for SIEM integration.

    **Resuming after disconnect** — include the ``Last-Event-ID`` header with
    the last received event ID.  The server replays all missed events from that
    point before switching to live delivery.

    **Keep-alive** — a SSE comment (`: keepalive`) is sent every 15 s so
    proxies and load balancers do not close idle connections.

    **Filtering** — pass ``?event_type=alert`` to receive only alerts.

    **Example curl**:
    ```
    curl -N -H "X-API-Key: $KEY" \\
         "https://host/api/v1/events/stream?org_id=acme&event_type=alert"
    ```
    """
    # Parse Last-Event-ID header for resume support (default: 0 = all buffered)
    raw_last_id = request.headers.get("Last-Event-ID", "0")
    try:
        last_event_id = int(raw_last_id)
    except (ValueError, TypeError):
        last_event_id = 0

    _logger.info(
        "SSE stream opened org=%s event_type=%s resume_from=%d",
        org_id,
        event_type,
        last_event_id,
    )

    generator = _sse_generator(org_id, last_event_id, event_type, request)

    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering for SSE
            "Connection": "keep-alive",
        },
    )
