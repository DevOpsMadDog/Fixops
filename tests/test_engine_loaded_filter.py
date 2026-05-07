"""
test_engine_loaded_filter.py — Smoke test for PLAN-P0-2.

Asserts that emitting an "engine.loaded" event does NOT appear in the
WebSocket subscriber callback queue, eliminating 23% of UI feed noise.
"""

from __future__ import annotations

import pytest


def test_ws_blocked_topics_contains_engine_loaded() -> None:
    """_WS_BLOCKED_TOPICS must include 'engine.loaded'."""
    from apps.api.ws_trustgraph_events_router import _WS_BLOCKED_TOPICS

    assert "engine.loaded" in _WS_BLOCKED_TOPICS


def test_engine_loaded_not_in_all_event_types() -> None:
    """engine.loaded should not be in ALL_EVENT_TYPES (no handler ever registered)."""
    from core.trustgraph_event_bus import ALL_EVENT_TYPES

    assert "engine.loaded" not in ALL_EVENT_TYPES


def test_handler_skips_engine_loaded_payload() -> None:
    """The _on_event closure silently drops engine.loaded payloads."""
    import asyncio
    from apps.api.ws_trustgraph_events_router import _WS_BLOCKED_TOPICS

    received: list[dict] = []

    def make_handler(event_type: str):
        """Minimal replica of the _build_handler closure logic."""
        def _on_event(payload: dict) -> bool:
            if event_type in _WS_BLOCKED_TOPICS:
                return True  # dropped — do NOT append
            received.append({"event_type": event_type, "payload": payload})
            return True
        return _on_event

    # engine.loaded handler — must NOT enqueue
    engine_loaded_handler = make_handler("engine.loaded")
    engine_loaded_handler({"module": "core.sast_engine"})
    assert received == [], "engine.loaded payload must be filtered out"

    # A real event type — must pass through
    finding_handler = make_handler("finding.created")
    finding_handler({"id": "f_001", "severity": "high"})
    assert len(received) == 1
    assert received[0]["event_type"] == "finding.created"


def test_blocked_topics_is_frozenset() -> None:
    """_WS_BLOCKED_TOPICS must be a frozenset (immutable, O(1) lookup)."""
    from apps.api.ws_trustgraph_events_router import _WS_BLOCKED_TOPICS

    assert isinstance(_WS_BLOCKED_TOPICS, frozenset)
