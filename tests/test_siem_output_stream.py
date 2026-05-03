"""Tests for SIEM output audit-log streaming endpoint.

Covers:
  - GET /api/v1/siem-output/stream returns text/event-stream
  - SSE ping heartbeat emitted when no deliveries exist
  - Delivery rows emitted as SSE events after record_delivery()
  - after_id cursor returns only newer rows (ascending order)
  - target_id filter scopes stream to one target
  - get_delivery_history backward compat (positional target_id, no after_id)
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.siem_output_engine import SIEMOutputEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path: Path) -> SIEMOutputEngine:
    db = str(tmp_path / "siem_stream_test.db")
    return SIEMOutputEngine(db_path=db)


@pytest.fixture()
def org_target(engine: SIEMOutputEngine):
    """Returns (org_id, target_id) with one pre-configured Splunk target."""
    t = engine.configure_target(
        org_id="org-stream-1",
        name="Test Splunk",
        siem_type="splunk_hec",
        config={"url": "https://splunk.example.com:8088", "token": "test-tok"},
    )
    return "org-stream-1", t["target_id"]


# ---------------------------------------------------------------------------
# Engine unit tests (no HTTP)
# ---------------------------------------------------------------------------

def test_get_delivery_history_empty(engine: SIEMOutputEngine, org_target):
    org_id, target_id = org_target
    rows = engine.get_delivery_history(org_id, target_id)
    assert rows == []


def test_get_delivery_history_returns_records(engine: SIEMOutputEngine, org_target):
    org_id, target_id = org_target
    engine.record_delivery(
        org_id=org_id,
        target_id=target_id,
        batch_size=10,
        events_sent=10,
        events_failed=0,
        success=True,
        status_code=200,
        duration_ms=42.0,
    )
    rows = engine.get_delivery_history(org_id, target_id)
    assert len(rows) == 1
    assert rows[0]["events_sent"] == 10
    assert rows[0]["success"] == 1


def test_get_delivery_history_after_id_cursor(engine: SIEMOutputEngine, org_target):
    """after_id should return only rows created strictly after the cursor."""
    org_id, target_id = org_target

    # Insert first delivery
    d1 = engine.record_delivery(
        org_id=org_id, target_id=target_id,
        batch_size=1, events_sent=1, events_failed=0,
        success=True, status_code=200, duration_ms=10.0,
    )
    # Tiny sleep to guarantee distinct created_at timestamps
    time.sleep(0.01)
    # Insert second delivery
    d2 = engine.record_delivery(
        org_id=org_id, target_id=target_id,
        batch_size=2, events_sent=2, events_failed=0,
        success=True, status_code=200, duration_ms=20.0,
    )

    rows = engine.get_delivery_history(org_id, target_id, after_id=d1["delivery_id"])
    assert len(rows) == 1
    assert rows[0]["delivery_id"] == d2["delivery_id"]


def test_get_delivery_history_target_filter(engine: SIEMOutputEngine, org_target):
    """Without target_id arg, all org deliveries returned; with it, filtered."""
    org_id, target_id = org_target

    # Create a second target
    t2 = engine.configure_target(
        org_id=org_id,
        name="Sentinel Target",
        siem_type="sentinel",
        config={"tenant_id": "tid", "client_id": "cid", "dcr_endpoint": "https://ep"},
    )
    target_id_2 = t2["target_id"]

    engine.record_delivery(org_id=org_id, target_id=target_id,
                           batch_size=1, events_sent=1, events_failed=0,
                           success=True, status_code=200, duration_ms=5.0)
    engine.record_delivery(org_id=org_id, target_id=target_id_2,
                           batch_size=1, events_sent=1, events_failed=0,
                           success=True, status_code=200, duration_ms=5.0)

    # No target_id filter: both rows
    all_rows = engine.get_delivery_history(org_id)
    assert len(all_rows) == 2

    # target_id filter: only one row
    filtered = engine.get_delivery_history(org_id, target_id)
    assert len(filtered) == 1
    assert filtered[0]["target_id"] == target_id


# ---------------------------------------------------------------------------
# SSE generator unit tests (avoid infinite-loop TestClient hang)
# ---------------------------------------------------------------------------

import asyncio as _asyncio


def _run(coro):
    """Run a coroutine synchronously inside a fresh event loop."""
    return _asyncio.get_event_loop().run_until_complete(coro)


async def _collect_sse_chunks(engine: SIEMOutputEngine, org_id: str,
                               target_id: str = "", max_chunks: int = 3) -> list[str]:
    """Drive the SSE generator for at most *max_chunks* yields, then stop.

    We monkey-patch asyncio.sleep so the generator never actually waits.
    """
    import apps.api.siem_output_router as mod

    # Inject test engine
    mod._engine = engine

    # Patch sleep to be a no-op so the generator is driven synchronously
    orig_sleep = _asyncio.sleep

    async def _fast_sleep(_delay):
        return

    _asyncio.sleep = _fast_sleep  # type: ignore[assignment]
    try:
        # Build a one-shot generator that stops after max_chunks iterations
        collected: list[str] = []
        response = mod.stream_audit_log.__wrapped__ if hasattr(mod.stream_audit_log, "__wrapped__") else None

        # Call the endpoint function directly
        sr = await mod.stream_audit_log(
            org_id=org_id,
            target_id=target_id or None,
            poll_interval=60.0,  # large — sleep is patched to no-op
            last_seen_id=None,
        )

        # Consume the generator up to max_chunks chunks
        gen = sr.body_iterator
        count = 0
        async for chunk in gen:
            collected.append(chunk if isinstance(chunk, str) else chunk.decode())
            count += 1
            if count >= max_chunks:
                break
        return collected
    finally:
        _asyncio.sleep = orig_sleep  # type: ignore[assignment]


def test_sse_generator_content_type(engine: SIEMOutputEngine, org_target):
    """stream_audit_log() must return a StreamingResponse with text/event-stream."""
    import apps.api.siem_output_router as mod
    mod._engine = engine

    async def _check():
        sr = await mod.stream_audit_log(
            org_id="org-stream-1", target_id=None, poll_interval=60.0, last_seen_id=None
        )
        return sr.media_type

    media_type = _run(_check())
    assert media_type == "text/event-stream"


def test_sse_generator_emits_ping_when_empty(engine: SIEMOutputEngine, org_target):
    """With no deliveries the generator must yield a ping heartbeat."""
    org_id, _ = org_target
    chunks = _run(_collect_sse_chunks(engine, org_id, max_chunks=1))
    assert any(": ping" in c for c in chunks), f"Expected ping, got: {chunks}"


def test_sse_generator_emits_delivery_event(engine: SIEMOutputEngine, org_target):
    """With a delivery present, generator must emit an SSE delivery event."""
    org_id, target_id = org_target
    engine.record_delivery(
        org_id=org_id, target_id=target_id,
        batch_size=7, events_sent=7, events_failed=0,
        success=True, status_code=200, duration_ms=55.0,
    )
    chunks = _run(_collect_sse_chunks(engine, org_id, max_chunks=2))
    combined = "".join(chunks)
    assert "event: delivery" in combined
    assert '"events_sent": 7' in combined or "\"events_sent\":7" in combined
