"""Tests for SSE event stream router.

Covers:
  1. Stream returns text/event-stream content type
  2. Last-Event-ID resume header replays only missed events
"""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("FIXOPS_MODE", "dev")


@pytest.fixture()
def client():
    # Import app after env is set
    from apps.api.app import app
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def sse_module():
    from apps.api import sse_router
    # Reset per-test state
    sse_router._event_store.clear()
    sse_router._event_counter.clear()
    sse_router._org_conditions.clear()
    return sse_router


# ---------------------------------------------------------------------------
# Test 1: Stream endpoint returns text/event-stream content type
# ---------------------------------------------------------------------------

def test_stream_content_type(client, sse_module):
    """GET /api/v1/events/stream must return Content-Type: text/event-stream."""
    # Pre-publish one event so the generator yields immediately and the
    # TestClient (which reads a sync response) doesn't block forever.
    sse_module.publish_event("org_ct", "alert", {"msg": "test"})

    with client.stream("GET", "/api/v1/events/stream?org_id=org_ct") as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]

        # Read one chunk and verify SSE format
        raw = next(resp.iter_lines())
        # First line of a real SSE frame starts with "event:" or ": keepalive"
        assert raw.startswith("event:") or raw.startswith(": keepalive") or raw.startswith("id:")


# ---------------------------------------------------------------------------
# Test 2: Last-Event-ID header replays only events after that ID
# ---------------------------------------------------------------------------

def test_resume_with_last_event_id(client, sse_module):
    """Events published before Last-Event-ID must NOT be replayed; newer ones must be."""
    # Publish 3 events
    id1 = sse_module.publish_event("org_resume", "alert", {"seq": 1})
    id2 = sse_module.publish_event("org_resume", "finding", {"seq": 2})
    id3 = sse_module.publish_event("org_resume", "alert", {"seq": 3})

    # Resume from after event 2 — only event 3 should appear
    headers = {"Last-Event-ID": str(id2)}
    with client.stream(
        "GET",
        "/api/v1/events/stream?org_id=org_resume",
        headers=headers,
    ) as resp:
        assert resp.status_code == 200

        lines = []
        for line in resp.iter_lines():
            lines.append(line)
            if len(lines) >= 3:  # event: / id: / data: for one event
                break

        raw = "\n".join(lines)
        # Must contain id3
        assert f"id: {id3}" in raw
        # Must NOT replay id1 or id2
        assert f"id: {id1}" not in raw
        assert f"id: {id2}" not in raw
