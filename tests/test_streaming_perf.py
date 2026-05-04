"""
Performance assertions for streaming hotspot fixes.

Three fixes measured here:
1. severity_order dict no longer rebuilt per matches_filters() call (module constant).
2. StreamEvent.to_sse() result cached — N-subscriber fan-out pays serialisation once.
3. _remove_queue_subscriber() is O(1) dict pop, not O(N) list comprehension.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import asyncio
import sys
import os
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.event_streaming import StreamEvent as BusStreamEvent, EventSeverity, _SEVERITY_ORDER
from core.event_stream import EventStream, EventChannel, StreamEvent


# ---------------------------------------------------------------------------
# Fix 1: _SEVERITY_ORDER is a module-level constant (not rebuilt each call)
# ---------------------------------------------------------------------------

def test_severity_order_is_module_constant():
    """_SEVERITY_ORDER must be a dict defined at module level, not inside the method."""
    assert isinstance(_SEVERITY_ORDER, dict)
    assert _SEVERITY_ORDER == {"info": 0, "warning": 1, "critical": 2}


def test_matches_filters_severity_performance():
    """matches_filters() with min_severity runs 50k iterations under 300ms."""
    event = BusStreamEvent(severity=EventSeverity.CRITICAL)
    start = time.perf_counter()
    for _ in range(50_000):
        event.matches_filters(min_severity="warning")
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 300, f"matches_filters x50k took {elapsed_ms:.1f}ms — expected <300ms"


# ---------------------------------------------------------------------------
# Fix 2: to_sse() caches its output — second call returns same object
# ---------------------------------------------------------------------------

def test_to_sse_caches_result():
    """to_sse() must return the identical string object on repeated calls."""
    event = StreamEvent(event_type="finding.scored", data={"score": 9.1})
    first = event.to_sse()
    second = event.to_sse()
    # Same content
    assert first == second
    # Same object (cached)
    assert first is second


def test_to_sse_fan_out_performance():
    """to_sse() x10k calls on the same event completes under 50ms (cached)."""
    event = StreamEvent(event_type="finding.scored", data={"score": 9.1})
    # Prime the cache
    event.to_sse()
    start = time.perf_counter()
    for _ in range(10_000):
        _ = event.to_sse()
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 50, f"to_sse() x10k took {elapsed_ms:.1f}ms — expected <50ms (cached)"


# ---------------------------------------------------------------------------
# Fix 3: _remove_queue_subscriber is O(1) — dict pop, not list comprehension
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_remove_subscriber_o1():
    """Remove 200 subscribers from a channel of 200; total wall time under 20ms."""
    stream = EventStream(history_size=10)
    channel = EventChannel.FINDINGS

    # Register 200 queue subscribers
    sub_ids = []
    for _ in range(200):
        sid, _ = stream._new_queue_subscriber(channel)
        sub_ids.append(sid)

    assert len(stream._subscribers[channel]) == 200

    start = time.perf_counter()
    for sid in sub_ids:
        stream._remove_queue_subscriber(channel, sid)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert len(stream._subscribers[channel]) == 0
    assert elapsed_ms < 20, f"200 removals took {elapsed_ms:.1f}ms — expected <20ms"


@pytest.mark.asyncio
async def test_publish_fan_out_does_not_leak_dead_subscribers():
    """Dead (full) queue subscribers are pruned via O(1) dict pop after publish."""
    stream = EventStream(history_size=10)
    channel = EventChannel.ALERTS

    # Create two subscribers with tiny queues
    sid1, q1 = stream._new_queue_subscriber(channel, maxsize=1)
    sid2, q2 = stream._new_queue_subscriber(channel, maxsize=1)

    # Fill both queues so they'll be dead on next publish
    event = StreamEvent(event_type="test")
    q1.put_nowait(event)
    q2.put_nowait(event)

    # Publish to full queues — both should be pruned
    await stream.publish(channel, StreamEvent(event_type="overflow"))

    assert sid1 not in stream._subscribers[channel]
    assert sid2 not in stream._subscribers[channel]


# ---------------------------------------------------------------------------
# Regression guard: SSE generator still works end-to-end after refactor
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sse_generator_delivers_events():
    """SSE generator yields properly formatted SSE chunks after the dict refactor."""
    EventStream.reset_instance()
    stream = EventStream.instance()
    channel = EventChannel.SYSTEM

    chunks: list[str] = []

    async def collect():
        async for chunk in stream.sse_generator(channel, heartbeat_interval=0.05):
            chunks.append(chunk)
            if len(chunks) >= 1:
                break

    task = asyncio.create_task(collect())
    await asyncio.sleep(0.02)

    await stream.publish(channel, StreamEvent(event_type="system.alert", data={"msg": "ok"}))
    await asyncio.wait_for(task, timeout=2)

    assert len(chunks) >= 1
    assert "event: system.alert" in chunks[-1]
    assert chunks[-1].endswith("\n\n")

    EventStream.reset_instance()
