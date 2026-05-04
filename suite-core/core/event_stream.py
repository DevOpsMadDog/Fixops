"""
Real-Time Event Streaming Engine for ALDECI.

Provides SSE + WebSocket streaming for live dashboards with:
- Pydantic StreamEvent model (id, event_type, data, timestamp, org_id)
- EventChannel enum (FINDINGS, INCIDENTS, COMPLIANCE, POSTURE, ALERTS, SYSTEM)
- EventStream class with pub/sub, SSE generator, WebSocket handler
- Thread-safe in-memory ring buffer per channel
- get_event_stats() for monitoring

Usage:
    stream = EventStream.instance()
    await stream.publish(EventChannel.FINDINGS, event)
    async for chunk in stream.sse_generator(EventChannel.FINDINGS, org_id="default"):
        yield chunk
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class EventChannel(str, Enum):
    """Logical event channels for dashboard routing."""

    FINDINGS = "findings"
    INCIDENTS = "incidents"
    COMPLIANCE = "compliance"
    POSTURE = "posture"
    ALERTS = "alerts"
    SYSTEM = "system"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class StreamEvent(BaseModel):
    """
    Real-time event published to an EventStream channel.

    Attributes:
        id: Unique event UUID (auto-generated)
        event_type: Arbitrary event type label (e.g. "finding.created")
        data: Arbitrary payload dict
        timestamp: UTC ISO-8601 creation timestamp
        org_id: Tenant/organisation identifier for multi-tenant isolation
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = Field(default="event", description="Event type label")
    data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    org_id: str = Field(default="default", description="Organisation ID")

    # Cached SSE wire-format string — computed once, reused for every subscriber
    # that receives this event (avoids redundant model_dump_json() per fan-out).
    _sse_cache: Optional[str] = None

    def to_sse(self) -> str:
        """Serialise to SSE wire format: id/event/data/blank-line.

        Result is cached so fan-out to N subscribers pays the serialisation
        cost exactly once instead of N times.
        """
        if self._sse_cache is None:
            self._sse_cache = (
                f"id: {self.id}\n"
                f"event: {self.event_type}\n"
                f"data: {self.model_dump_json()}\n"
                "\n"
            )
        return self._sse_cache

    def to_dict(self) -> Dict[str, Any]:
        """Return plain dict for JSON serialisation."""
        return self.model_dump()


# ---------------------------------------------------------------------------
# Subscriber type
# ---------------------------------------------------------------------------

# A callback is an async callable that receives a StreamEvent.
_Callback = Callable[[StreamEvent], Any]


# ---------------------------------------------------------------------------
# EventStream
# ---------------------------------------------------------------------------


class EventStream:
    """
    In-process pub/sub event stream with SSE + WebSocket support.

    Singleton: use EventStream.instance() for the process-wide default.
    Each channel maintains an independent asyncio.Queue per subscriber and
    a ring buffer of recent events for replay / stats.

    Thread safety: all mutations go through asyncio (not thread-safe across
    OS threads; use the same event loop).
    """

    _default_instance: Optional[EventStream] = None

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, history_size: int = 200) -> None:
        """
        Initialise a new EventStream.

        Args:
            history_size: Number of events to retain per channel for get_recent().
        """
        self._history_size = history_size

        # channel → {subscriber_id: asyncio.Queue}  (dict for O(1) add/remove)
        self._subscribers: Dict[EventChannel, Dict[str, asyncio.Queue]] = (
            defaultdict(dict)
        )

        # channel → callback list (fire-and-forget, no queue)
        self._callbacks: Dict[EventChannel, List[tuple[str, _Callback]]] = (
            defaultdict(list)
        )

        # channel → ring buffer of recent events
        self._history: Dict[EventChannel, deque] = {
            ch: deque(maxlen=history_size) for ch in EventChannel
        }

        # simple counters
        self._published: Dict[EventChannel, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def instance(cls) -> EventStream:
        """Return (or create) the process-wide default EventStream."""
        if cls._default_instance is None:
            cls._default_instance = cls()
        return cls._default_instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (useful in tests)."""
        cls._default_instance = None

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    async def publish(self, channel: EventChannel, event: StreamEvent) -> int:
        """
        Broadcast *event* to all subscribers on *channel*.

        Args:
            channel: Target EventChannel.
            event: StreamEvent to broadcast.

        Returns:
            Number of subscribers that received the event.
        """
        # Store in history
        self._history[channel].append(event)
        self._published[channel] += 1

        delivered = 0

        # Deliver to queue-based subscribers
        dead: List[str] = []
        for sub_id, queue in list(self._subscribers.get(channel, {}).items()):
            try:
                queue.put_nowait(event)
                delivered += 1
            except asyncio.QueueFull:
                _logger.warning("Queue full for subscriber %s on %s — dropping event", sub_id, channel)
                dead.append(sub_id)

        # Remove dead queues — O(1) per removal via dict pop
        for sub_id in dead:
            self._subscribers[channel].pop(sub_id, None)

        # Fire callbacks
        for cb_id, cb in list(self._callbacks.get(channel, [])):
            try:
                result = cb(event)
                if asyncio.iscoroutine(result):
                    await result
                delivered += 1
            except Exception:  # noqa: BLE001
                _logger.exception("Callback %s raised on channel %s", cb_id, channel)

        return delivered

    # ------------------------------------------------------------------
    # Subscribe / unsubscribe (queue-based)
    # ------------------------------------------------------------------

    def subscribe(
        self,
        channel: EventChannel,
        callback: _Callback,
        *,
        subscriber_id: Optional[str] = None,
    ) -> str:
        """
        Register an async or sync *callback* for *channel*.

        Args:
            channel: EventChannel to subscribe to.
            callback: Callable invoked per event (may be async).
            subscriber_id: Optional explicit ID; auto-generated if None.

        Returns:
            subscriber_id string (needed for unsubscribe).
        """
        sid = subscriber_id or str(uuid.uuid4())
        self._callbacks[channel].append((sid, callback))
        _logger.debug("Subscribed %s to %s", sid, channel)
        return sid

    def unsubscribe(self, channel: EventChannel, callback: _Callback) -> bool:
        """
        Remove all registrations of *callback* from *channel*.

        Args:
            channel: EventChannel.
            callback: The exact callable previously passed to subscribe().

        Returns:
            True if at least one registration was removed.
        """
        before = len(self._callbacks[channel])
        self._callbacks[channel] = [
            (sid, cb) for sid, cb in self._callbacks[channel] if cb is not callback
        ]
        removed = len(self._callbacks[channel]) < before

        # Also remove from queue subscribers (matched by object identity is not
        # possible for queues; nothing to do there — queue subscribers are
        # managed via _new_queue_subscriber / _remove_queue_subscriber).
        return removed

    # ------------------------------------------------------------------
    # Internal: queue-based subscriber lifecycle
    # ------------------------------------------------------------------

    def _new_queue_subscriber(
        self, channel: EventChannel, maxsize: int = 256
    ) -> tuple[str, asyncio.Queue]:
        """Create and register a new queue subscriber. Returns (sub_id, queue)."""
        sid = str(uuid.uuid4())
        queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._subscribers[channel][sid] = queue  # O(1) insert
        return sid, queue

    def _remove_queue_subscriber(
        self, channel: EventChannel, sub_id: str
    ) -> None:
        """Remove a queue subscriber by ID — O(1) dict pop."""
        self._subscribers[channel].pop(sub_id, None)

    # ------------------------------------------------------------------
    # History / stats
    # ------------------------------------------------------------------

    def get_recent(
        self,
        channel: EventChannel,
        limit: int = 50,
        *,
        org_id: Optional[str] = None,
    ) -> List[StreamEvent]:
        """
        Return the last *limit* events from *channel*, most-recent first.

        Args:
            channel: EventChannel to query.
            limit: Maximum number of events to return.
            org_id: If provided, filter to this org only.

        Returns:
            List of StreamEvent, newest first.
        """
        buf = self._history[channel]
        events = list(buf)  # oldest → newest order in deque
        events.reverse()  # newest first

        if org_id is not None:
            events = [e for e in events if e.org_id == org_id]

        return events[:limit]

    def get_event_stats(self) -> Dict[str, Any]:
        """
        Return summary statistics for all channels.

        Returns dict with:
            - events_per_channel: {channel_value: count}
            - subscribers_per_channel: {channel_value: count}
            - history_size_per_channel: {channel_value: count}
            - total_published: int
            - total_subscribers: int
        """
        events_per_channel: Dict[str, int] = {}
        subscribers_per_channel: Dict[str, int] = {}
        history_size_per_channel: Dict[str, int] = {}

        for ch in EventChannel:
            events_per_channel[ch.value] = self._published[ch]
            # count queue subs + callback subs
            q_count = len(self._subscribers.get(ch, {}))
            cb_count = len(self._callbacks.get(ch, []))
            subscribers_per_channel[ch.value] = q_count + cb_count
            history_size_per_channel[ch.value] = len(self._history[ch])

        return {
            "events_per_channel": events_per_channel,
            "subscribers_per_channel": subscribers_per_channel,
            "history_size_per_channel": history_size_per_channel,
            "total_published": sum(events_per_channel.values()),
            "total_subscribers": sum(subscribers_per_channel.values()),
        }

    # ------------------------------------------------------------------
    # SSE generator
    # ------------------------------------------------------------------

    async def sse_generator(
        self,
        channel: EventChannel,
        *,
        org_id: Optional[str] = None,
        heartbeat_interval: float = 15.0,
        queue_maxsize: int = 256,
    ) -> AsyncGenerator[str, None]:
        """
        Yield SSE-formatted strings for HTTP streaming.

        Sends a ``ping`` comment every *heartbeat_interval* seconds to
        keep the connection alive through proxies/load-balancers.

        Args:
            channel: EventChannel to stream.
            org_id: If set, only events for this org are yielded.
            heartbeat_interval: Seconds between heartbeat pings.
            queue_maxsize: Max queue depth before events are dropped.

        Yields:
            SSE-formatted strings (``id: …\\nevent: …\\ndata: …\\n\\n``).
        """
        sub_id, queue = self._new_queue_subscriber(channel, maxsize=queue_maxsize)
        _logger.debug("SSE subscriber %s on %s started", sub_id, channel)

        try:
            # Send any recent events as initial replay
            recent = self.get_recent(channel, limit=10, org_id=org_id)
            for ev in reversed(recent):  # oldest first
                yield ev.to_sse()

            while True:
                try:
                    event: StreamEvent = await asyncio.wait_for(
                        queue.get(), timeout=heartbeat_interval
                    )
                    if org_id is None or event.org_id == org_id:
                        yield event.to_sse()
                except asyncio.TimeoutError:
                    # Heartbeat comment to keep connection alive
                    yield ": ping\n\n"
        except asyncio.CancelledError:
            _logger.debug("SSE subscriber %s cancelled", sub_id)
        finally:
            self._remove_queue_subscriber(channel, sub_id)
            _logger.debug("SSE subscriber %s cleaned up", sub_id)

    # ------------------------------------------------------------------
    # WebSocket handler
    # ------------------------------------------------------------------

    async def websocket_handler(
        self,
        websocket: Any,
        channel: EventChannel,
        *,
        org_id: Optional[str] = None,
        heartbeat_interval: float = 30.0,
        queue_maxsize: int = 256,
    ) -> None:
        """
        Bidirectional WebSocket handler.

        Accepts *websocket* (FastAPI WebSocket), subscribes it to *channel*,
        forwards incoming events, and handles client messages:
            - ``{"type": "ping"}`` → responds with ``{"type": "pong"}``
            - ``{"type": "subscribe", "channel": "…"}`` → acknowledged
            - Any other message is logged and ignored.

        Gracefully handles disconnect and cancellation.

        Args:
            websocket: FastAPI WebSocket instance.
            channel: EventChannel to subscribe to.
            org_id: If set, only events for this org are forwarded.
            heartbeat_interval: Seconds between server-sent ping messages.
            queue_maxsize: Max queue depth before events are dropped.
        """
        from fastapi import (
            WebSocketDisconnect,  # local import to avoid hard dep at module level
        )

        await websocket.accept()

        # Send initial replay
        recent = self.get_recent(channel, limit=10, org_id=org_id)
        for ev in reversed(recent):
            try:
                await websocket.send_text(json.dumps(ev.to_dict()))
            except Exception:  # noqa: BLE001
                return

        sub_id, queue = self._new_queue_subscriber(channel, maxsize=queue_maxsize)
        _logger.debug("WebSocket subscriber %s on %s connected", sub_id, channel)

        async def _receiver() -> None:
            """Read and handle incoming client messages."""
            try:
                while True:
                    raw = await websocket.receive_text()
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    msg_type = msg.get("type", "")
                    if msg_type == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))
                    elif msg_type == "subscribe":
                        await websocket.send_text(
                            json.dumps({"type": "subscribed", "channel": channel.value})
                        )
                    else:
                        _logger.debug("WebSocket received unknown message type: %s", msg_type)
            except (WebSocketDisconnect, Exception):  # noqa: BLE001
                pass

        async def _sender() -> None:
            """Forward queued events to the client."""
            try:
                while True:
                    try:
                        event: StreamEvent = await asyncio.wait_for(
                            queue.get(), timeout=heartbeat_interval
                        )
                        if org_id is None or event.org_id == org_id:
                            await websocket.send_text(json.dumps(event.to_dict()))
                    except asyncio.TimeoutError:
                        # Heartbeat
                        await websocket.send_text(
                            json.dumps(
                                {
                                    "type": "ping",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                }
                            )
                        )
            except (WebSocketDisconnect, Exception):  # noqa: BLE001
                pass

        recv_task = asyncio.create_task(_receiver())
        send_task = asyncio.create_task(_sender())

        try:
            done, pending = await asyncio.wait(
                [recv_task, send_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
        finally:
            self._remove_queue_subscriber(channel, sub_id)
            _logger.debug("WebSocket subscriber %s disconnected", sub_id)
            try:
                await websocket.close()
            except Exception:  # noqa: BLE001
                pass
