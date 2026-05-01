"""
FEATURE-3 — pytest for /ws/events TrustGraph WebSocket event stream.

Covers:
  * connect → emit TrustGraph event → WS receives event JSON within ~1 s
  * heartbeat ping arrives within FIXOPS_WS_HEARTBEAT seconds
  * disconnect doesn't leak handlers from the singleton TrustGraphEventBus
  * welcome/connected frame includes subscribed event types

The router (suite-api/apps/api/ws_trustgraph_events_router.py) registers one
handler per ALL_EVENT_TYPES on the singleton TrustGraphEventBus on connect and
removes them on disconnect.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Env bootstrap MUST happen before any apps.api / core import — auth_deps
# captures FIXOPS_MODE / FIXOPS_API_TOKEN at module import time.
# ---------------------------------------------------------------------------
import os

os.environ["FIXOPS_MODE"] = "dev"             # opt-in to dev pass-through
os.environ["FIXOPS_WS_HEARTBEAT"] = "1"       # snappy heartbeat for the test
os.environ.pop("FIXOPS_TEST_MODE", None)      # do NOT disable the bus
os.environ["TRUSTGRAPH_EVENT_BUS_ENABLED"] = "1"
os.environ.pop("FIXOPS_API_TOKEN", None)      # ensure no token wall

import asyncio
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap (mirrors other phase tests so the suite imports work)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "suite-core"))
sys.path.insert(0, str(_REPO_ROOT / "suite-api"))

from fastapi import FastAPI
from fastapi.testclient import TestClient

# Force-reload auth_deps so it re-evaluates _DEV_MODE under our env.
import importlib
import apps.api.auth_deps as _auth_deps  # noqa: F401
importlib.reload(_auth_deps)
_auth_deps._DEV_MODE = True  # belt-and-braces; tests run without tokens

from core.trustgraph_event_bus import (  # noqa: E402
    EVENT_FINDING_CREATED,
    EventBus,
    get_event_bus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ws_app() -> FastAPI:
    """Return a fresh FastAPI app with /ws/events mounted.

    Minimal app (not the full create_app()) so the test is fast and isolated
    from the production 590-router boot.
    """
    # Re-import the router module fresh so it picks up the patched _DEV_MODE.
    if "apps.api.ws_trustgraph_events_router" in sys.modules:
        del sys.modules["apps.api.ws_trustgraph_events_router"]
    from apps.api.ws_trustgraph_events_router import router as ws_router

    app = FastAPI()
    app.include_router(ws_router)
    return app


@pytest.fixture()
def bus() -> EventBus:
    """Return the singleton TrustGraphEventBus."""
    return get_event_bus()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _ws_url() -> str:
    """Return /ws/events with the conftest API token if one is configured.

    conftest.py sets FIXOPS_API_TOKEN session-wide, so when this test runs
    after another phase test it must include the token to pass auth. When
    only FIXOPS_MODE=dev is set, an empty query string still passes via
    the dev pass-through.
    """
    token = os.getenv("FIXOPS_API_TOKEN", "").strip()
    return f"/ws/events?api_key={token}" if token else "/ws/events"


def test_connect_emits_welcome_frame(ws_app: FastAPI) -> None:
    """A successful WS connect should send a {'type':'connected', ...} envelope."""
    client = TestClient(ws_app)
    with client.websocket_connect(_ws_url()) as ws:
        welcome = ws.receive_json()
        assert welcome["type"] == "connected"
        assert "connection_id" in welcome
        assert "subscribed_event_types" in welcome
        assert EVENT_FINDING_CREATED in welcome["subscribed_event_types"]
        assert welcome["heartbeat_seconds"] == 1


def test_emit_event_is_received_over_ws(ws_app: FastAPI, bus: EventBus) -> None:
    """Emit a TrustGraph finding.created event → WS receives it within a few frames."""
    client = TestClient(ws_app)
    with client.websocket_connect(_ws_url()) as ws:
        # Drain welcome frame
        welcome = ws.receive_json()
        assert welcome["type"] == "connected"

        # Emit synchronously via a fresh event loop — the bus's emit() is async
        # but its handlers (our WS handler) are sync and push into the queue
        # without needing an awaited dispatch.
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                bus.emit(
                    EVENT_FINDING_CREATED,
                    {
                        "finding_id": "test-finding-001",
                        "engine": "pytest",
                        "severity": "high",
                        "title": "feature-3 ws round-trip test",
                        "org_id": "default",
                    },
                )
            )
        finally:
            loop.close()

        # Receive frames until we get our event (skip pings).
        received_event = None
        for _ in range(10):
            frame = ws.receive_json()
            if frame.get("type") == "event" and frame.get("event_type") == EVENT_FINDING_CREATED:
                received_event = frame
                break
        assert received_event is not None, "Did not receive event frame within 10 polls"
        assert received_event["payload"]["finding_id"] == "test-finding-001"
        assert "timestamp" in received_event


def test_heartbeat_ping_arrives(ws_app: FastAPI) -> None:
    """Server should send a {'type':'ping', ...} every FIXOPS_WS_HEARTBEAT seconds."""
    client = TestClient(ws_app)
    with client.websocket_connect(_ws_url()) as ws:
        welcome = ws.receive_json()
        assert welcome["type"] == "connected"

        # Heartbeat is 1 s in the test env; allow up to ~5 frames to see one.
        ping_seen = False
        for _ in range(6):
            frame = ws.receive_json()
            if frame.get("type") == "ping":
                ping_seen = True
                assert "ts" in frame
                break
        assert ping_seen, "Expected at least one heartbeat ping frame"


def test_disconnect_unregisters_handlers(ws_app: FastAPI, bus: EventBus) -> None:
    """After disconnect, the bus should hold no extra handlers from this client."""
    before = {et: len(handlers) for et, handlers in bus._handlers.items()}

    client = TestClient(ws_app)
    with client.websocket_connect(_ws_url()) as ws:
        welcome = ws.receive_json()
        assert welcome["type"] == "connected"
        # While connected, EVENT_FINDING_CREATED should have +1 handler.
        during = {et: len(handlers) for et, handlers in bus._handlers.items()}
        assert during.get(EVENT_FINDING_CREATED, 0) > before.get(EVENT_FINDING_CREATED, 0)

    # After context exit, handlers must be removed.
    after = {et: len(handlers) for et, handlers in bus._handlers.items()}
    leaked = {
        et: after.get(et, 0) - before.get(et, 0)
        for et in after
        if after.get(et, 0) > before.get(et, 0)
    }
    assert not leaked, f"Handler leak after disconnect: {leaked}"
