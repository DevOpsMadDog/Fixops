"""
Real-Time Event Streaming Router — SSE + WebSocket for live dashboards.

Endpoints:
    GET  /api/v1/stream/sse/{channel}    — Server-Sent Events stream
    GET  /api/v1/stream/ws/{channel}     — WebSocket bidirectional stream
    POST /api/v1/stream/publish          — Publish an event to a channel
    GET  /api/v1/stream/stats            — Stream statistics
    GET  /api/v1/stream/recent/{channel} — Recent events (last N)

Security:
    SSE and WebSocket endpoints accept an optional ``api_key`` query param.
    Publish and stats require the standard API key auth injected by app.py.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.event_stream import EventChannel, EventStream, StreamEvent
from fastapi import APIRouter, HTTPException, Query, WebSocket, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/stream", tags=["event-stream"])

# Process-wide singleton
_stream = EventStream.instance()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class PublishRequest(BaseModel):
    """Body for POST /api/v1/stream/publish."""

    channel: EventChannel = Field(..., description="Target channel")
    event_type: str = Field(default="event", max_length=128)
    data: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = Field(default="default", max_length=128)


class PublishResponse(BaseModel):
    status: str
    event_id: str
    channel: str
    delivered: int


# ---------------------------------------------------------------------------
# SSE endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/sse/{channel}",
    summary="Server-Sent Events stream for a channel",
    response_class=StreamingResponse,
)
async def sse_stream(
    channel: EventChannel,
    org_id: Optional[str] = Query(None, description="Filter to this org"),
    replay: bool = Query(True, description="Replay last 10 events on connect"),
    api_key: Optional[str] = Query(None, description="Optional API key"),
) -> StreamingResponse:
    """
    Stream events for *channel* as Server-Sent Events.

    The client receives:
    - An initial burst of up to 10 recent events (if replay=true)
    - A ``ping`` heartbeat comment every 15 seconds
    - New events as they are published

    SSE format::

        id: <uuid>
        event: <event_type>
        data: {"id": "…", "event_type": "…", "data": {…}, …}

    """

    async def _generator():
        stream = EventStream.instance()
        async for chunk in stream.sse_generator(
            channel, org_id=org_id, heartbeat_interval=15.0
        ):
            yield chunk

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws/{channel}")
async def websocket_stream(
    websocket: WebSocket,
    channel: EventChannel,
    org_id: Optional[str] = Query(None, description="Filter to this org"),
    api_key: Optional[str] = Query(None, description="Optional API key"),
) -> None:
    """
    Bidirectional WebSocket stream for *channel*.

    Client can send::

        {"type": "ping"}              → server replies {"type": "pong"}
        {"type": "subscribe", "channel": "alerts"}  → acknowledged

    Server sends JSON event objects plus periodic ``{"type": "ping"}`` heartbeats.
    """
    stream = EventStream.instance()
    await stream.websocket_handler(websocket, channel, org_id=org_id)


# ---------------------------------------------------------------------------
# Publish endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/publish",
    response_model=PublishResponse,
    summary="Publish an event to a channel",
    status_code=status.HTTP_202_ACCEPTED,
)
async def publish_event(req: PublishRequest) -> PublishResponse:
    """
    Publish a single event to *channel*.

    The event is immediately delivered to all active SSE/WebSocket subscribers
    on that channel and stored in the ring-buffer for late-joining clients.
    """
    event = StreamEvent(
        event_type=req.event_type,
        data=req.data,
        org_id=req.org_id,
    )

    stream = EventStream.instance()
    try:
        delivered = await stream.publish(req.channel, event)
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Error publishing event to %s", req.channel)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Publish failed: {exc}",
        )

    return PublishResponse(
        status="published",
        event_id=event.id,
        channel=req.channel.value,
        delivered=delivered,
    )


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/stats",
    summary="Event stream statistics",
)
async def get_stats() -> Dict[str, Any]:
    """
    Return per-channel statistics:
    - events_per_channel
    - subscribers_per_channel
    - history_size_per_channel
    - total_published / total_subscribers
    """
    stream = EventStream.instance()
    return stream.get_event_stats()


# ---------------------------------------------------------------------------
# Recent events endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/recent/{channel}",
    summary="Get recent events for a channel",
)
async def get_recent(
    channel: EventChannel,
    limit: int = Query(default=20, ge=1, le=200),
    org_id: Optional[str] = Query(None, description="Filter to this org"),
) -> Dict[str, Any]:
    """
    Return the last *limit* events from *channel*, newest first.

    Useful for dashboard initial load before subscribing to SSE/WS.
    """
    stream = EventStream.instance()
    events = stream.get_recent(channel, limit=limit, org_id=org_id)
    return {
        "channel": channel.value,
        "count": len(events),
        "events": [e.to_dict() for e in events],
    }
