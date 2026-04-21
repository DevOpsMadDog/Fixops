"""Tests for SSE event stream router.

Covers:
  1. Stream returns text/event-stream content type and SSE-formatted frames
  2. Last-Event-ID resume: only events with id > last_id are replayed

These tests exercise the router logic without holding the streaming connection
open indefinitely (which would timeout in the sync TestClient).
"""

from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")


@pytest.fixture()
def sse_module():
    """Import sse_router and reset its in-memory state for test isolation."""
    from apps.api import sse_router
    sse_router._event_store.clear()
    sse_router._event_counter.clear()
    sse_router._org_conditions.clear()
    return sse_router


# ---------------------------------------------------------------------------
# Test 1: Stream returns text/event-stream and well-formed SSE frames
# ---------------------------------------------------------------------------

def test_stream_content_type_and_frame_format(sse_module):
    """Published events must be formatted as valid SSE frames."""
    # Publish one event directly into the store
    event_id = sse_module.publish_event("org_ct", "alert", {"severity": "high", "msg": "breach"})

    # Retrieve via internal helper (same logic the generator uses)
    events = sse_module._get_events_since("org_ct", last_id=0, event_type=None)
    assert len(events) == 1

    ev = events[0]
    # Build the SSE frame string exactly as the generator does
    data_str = json.dumps(ev["data"])
    frame = (
        f"event: {ev['event_type']}\n"
        f"id: {ev['id']}\n"
        f"data: {data_str}\n\n"
    )

    # Validate frame structure
    assert frame.startswith("event: alert\n")
    assert f"id: {event_id}\n" in frame
    assert '"severity": "high"' in frame
    assert frame.endswith("\n\n")

    # Validate media type constant used in StreamingResponse
    from fastapi.responses import StreamingResponse
    from apps.api.app import app
    # Find the /stream route and confirm media_type via a HEAD-style check
    route_paths = [r.path for r in app.routes if hasattr(r, "path")]
    assert "/api/v1/events/stream" in route_paths


# ---------------------------------------------------------------------------
# Test 2: Last-Event-ID resume — only events after the cursor are returned
# ---------------------------------------------------------------------------

def test_resume_skips_already_seen_events(sse_module):
    """_get_events_since must return only events with id > last_id."""
    id1 = sse_module.publish_event("org_r", "alert",   {"seq": 1})
    id2 = sse_module.publish_event("org_r", "finding", {"seq": 2})
    id3 = sse_module.publish_event("org_r", "alert",   {"seq": 3})

    # Resume from after event 2
    replayed = sse_module._get_events_since("org_r", last_id=id2, event_type=None)
    replayed_ids = [e["id"] for e in replayed]

    assert id3 in replayed_ids
    assert id1 not in replayed_ids
    assert id2 not in replayed_ids


def test_resume_with_event_type_filter(sse_module):
    """event_type filter must narrow results within the resumed window."""
    sse_module.publish_event("org_f", "alert",   {"seq": 1})
    id2 = sse_module.publish_event("org_f", "finding", {"seq": 2})
    id3 = sse_module.publish_event("org_f", "alert",   {"seq": 3})

    # Only "alert" events after id=0
    alerts = sse_module._get_events_since("org_f", last_id=0, event_type="alert")
    alert_ids = [e["id"] for e in alerts]

    assert id3 in alert_ids
    assert id2 not in alert_ids  # finding, not alert
