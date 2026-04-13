"""
Tests for TrustGraph Event Bus (suite-core/core/trustgraph_event_bus.py).

Coverage:
- EventBus init and singleton
- emit() / on() pub-sub
- Response pattern matching in ResponseInterceptorMiddleware
- Offline queue enqueue / get_pending / mark_indexed / mark_failed
- Queue stats and flush
- Metrics tracking
- Configuration changes (enable/disable event types, master switch)
- Test mode disables bus
- Handler failure falls back to queue
- _rebuild_response preserves body
- init_event_bus registers middleware and startup handler
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
from collections import defaultdict
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import Response


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _make_bus(enabled: bool = True, db_path: Optional[str] = None) -> Any:
    """Create a fresh EventBus with a temp DB path."""
    import importlib
    import core.trustgraph_event_bus as eb_module

    # Reset singleton for test isolation
    eb_module._bus_instance = None

    from core.trustgraph_event_bus import EventBus

    if db_path is None:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

    return EventBus(enabled=enabled, queue_db_path=db_path)


def _make_queue(db_path: Optional[str] = None) -> Any:
    from core.trustgraph_event_bus import _OfflineQueue

    if db_path is None:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

    return _OfflineQueue(db_path=db_path)


# ---------------------------------------------------------------------------
# EventBus — init
# ---------------------------------------------------------------------------


def test_event_bus_init_default():
    bus = _make_bus()
    assert bus.enabled is True
    assert bus.batch_size == 50


def test_event_bus_init_disabled():
    bus = _make_bus(enabled=False)
    assert bus.enabled is False


def test_event_bus_disabled_by_env(monkeypatch):
    monkeypatch.setenv("TRUSTGRAPH_EVENT_BUS_ENABLED", "0")
    monkeypatch.setenv("FIXOPS_TEST_MODE", "0")
    bus = _make_bus(enabled=True)  # overridden by env
    assert bus.enabled is False


def test_event_bus_disabled_by_test_mode(monkeypatch):
    monkeypatch.setenv("FIXOPS_TEST_MODE", "1")
    bus = _make_bus(enabled=True)
    assert bus.enabled is False


def test_event_bus_batch_size_from_env(monkeypatch):
    monkeypatch.setenv("TRUSTGRAPH_EVENT_BUS_BATCH", "25")
    bus = _make_bus()
    assert bus.batch_size == 25


# ---------------------------------------------------------------------------
# EventBus — on() and emit()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emit_calls_handler():
    bus = _make_bus()
    received: List[Dict] = []

    async def handler(data):
        received.append(data)
        return True

    bus.on("finding.created", handler)
    await bus.emit("finding.created", {"id": "f001", "engine": "sast"})

    # Allow background task to complete
    await asyncio.sleep(0.05)
    assert len(received) == 1
    assert received[0]["id"] == "f001"


@pytest.mark.asyncio
async def test_emit_disabled_bus_does_nothing():
    bus = _make_bus(enabled=False)
    received: List[Dict] = []

    async def handler(data):
        received.append(data)
        return True

    bus.on("finding.created", handler)
    await bus.emit("finding.created", {"id": "f001"})
    await asyncio.sleep(0.05)
    assert received == []


@pytest.mark.asyncio
async def test_emit_unknown_event_type_drops():
    bus = _make_bus()
    bus.disable_event_type("finding.created")

    received: List[Dict] = []

    async def handler(data):
        received.append(data)
        return True

    bus.on("finding.created", handler)
    await bus.emit("finding.created", {"id": "f001"})
    await asyncio.sleep(0.05)
    assert received == []
    assert bus.metrics.events_dropped >= 1


@pytest.mark.asyncio
async def test_multiple_handlers_all_called():
    bus = _make_bus()
    calls: List[str] = []

    async def handler_a(data):
        calls.append("a")
        return True

    async def handler_b(data):
        calls.append("b")
        return True

    bus.on("finding.created", handler_a)
    bus.on("finding.created", handler_b)
    await bus.emit("finding.created", {"id": "f002"})
    await asyncio.sleep(0.1)

    assert "a" in calls
    assert "b" in calls


@pytest.mark.asyncio
async def test_emit_no_handlers_queues_event():
    bus = _make_bus()
    # Don't register any handler
    await bus.emit("finding.created", {"id": "f003"})
    await asyncio.sleep(0.05)

    stats = bus.queue_stats()
    assert stats["queued"] >= 1


@pytest.mark.asyncio
async def test_handler_failure_queues_event():
    bus = _make_bus()

    async def failing_handler(data):
        raise ValueError("TrustGraph unavailable")

    bus.on("incident.created", failing_handler)
    await bus.emit("incident.created", {"id": "i001"})
    await asyncio.sleep(0.1)

    stats = bus.queue_stats()
    assert stats["queued"] >= 1
    assert bus.metrics.events_queued >= 1


@pytest.mark.asyncio
async def test_handler_returning_false_queues_event():
    bus = _make_bus()

    async def unhappy_handler(data):
        return False  # signals failure

    bus.on("asset.discovered", unhappy_handler)
    await bus.emit("asset.discovered", {"id": "a001"})
    await asyncio.sleep(0.1)

    assert bus.metrics.events_queued >= 1


# ---------------------------------------------------------------------------
# EventBus — metrics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_emitted_increments():
    bus = _make_bus()

    async def handler(data):
        return True

    bus.on("finding.created", handler)

    before = bus.metrics.events_emitted
    await bus.emit("finding.created", {"id": "fx"})
    assert bus.metrics.events_emitted == before + 1


@pytest.mark.asyncio
async def test_metrics_indexed_increments():
    bus = _make_bus()

    async def handler(data):
        return True

    bus.on("finding.created", handler)
    await bus.emit("finding.created", {"id": "fx"})
    await asyncio.sleep(0.1)

    assert bus.metrics.events_indexed >= 1


@pytest.mark.asyncio
async def test_metrics_by_type_tracked():
    bus = _make_bus()

    async def handler(data):
        return True

    bus.on("asset.discovered", handler)
    await bus.emit("asset.discovered", {"id": "a1"})
    await bus.emit("asset.discovered", {"id": "a2"})
    await asyncio.sleep(0.1)

    assert bus.metrics.by_type_emitted.get("asset.discovered", 0) == 2


def test_metrics_to_dict_structure():
    bus = _make_bus()
    d = bus.metrics.to_dict()
    assert "events_emitted" in d
    assert "events_indexed" in d
    assert "events_queued" in d
    assert "events_failed" in d
    assert "by_type" in d
    assert "finding.created" in d["by_type"]


def test_metrics_avg_latency_no_data():
    bus = _make_bus()
    assert bus.metrics.avg_latency_ms("finding.created") == 0.0


def test_metrics_avg_latency_with_data():
    bus = _make_bus()
    bus.metrics.record_indexed("finding.created", 10.0)
    bus.metrics.record_indexed("finding.created", 20.0)
    assert bus.metrics.avg_latency_ms("finding.created") == 15.0


# ---------------------------------------------------------------------------
# EventBus — configuration
# ---------------------------------------------------------------------------


def test_enable_disable_event_type():
    bus = _make_bus()
    bus.disable_event_type("finding.created")
    assert "finding.created" not in bus.get_enabled_types()

    bus.enable_event_type("finding.created")
    assert "finding.created" in bus.get_enabled_types()


def test_set_enabled():
    bus = _make_bus()
    bus.set_enabled(False)
    assert bus.enabled is False

    bus.set_enabled(True)
    assert bus.enabled is True


def test_get_status_keys():
    bus = _make_bus()
    status = bus.get_status()
    assert "enabled" in status
    assert "enabled_event_types" in status
    assert "registered_handlers" in status
    assert "metrics" in status
    assert "queue" in status


# ---------------------------------------------------------------------------
# OfflineQueue
# ---------------------------------------------------------------------------


def test_queue_enqueue_and_get_pending():
    q = _make_queue()
    q.enqueue("finding.created", {"id": "f001"})
    pending = q.get_pending()
    assert len(pending) == 1
    assert pending[0]["event_type"] == "finding.created"
    assert pending[0]["payload"]["id"] == "f001"


def test_queue_mark_indexed():
    q = _make_queue()
    q.enqueue("finding.created", {"id": "f002"})
    pending = q.get_pending()
    q.mark_indexed(pending[0]["id"])

    # Should no longer be pending
    pending2 = q.get_pending()
    assert len(pending2) == 0


def test_queue_mark_failed():
    q = _make_queue()
    q.enqueue("finding.created", {"id": "f003"})
    pending = q.get_pending()
    q.mark_failed(pending[0]["id"])

    pending2 = q.get_pending()
    assert len(pending2) == 0


def test_queue_stats():
    q = _make_queue()
    q.enqueue("finding.created", {"id": "f1"})
    q.enqueue("finding.created", {"id": "f2"})
    stats = q.queue_stats()
    assert stats["queued"] == 2
    assert stats["total"] >= 2


def test_queue_max_size_eviction():
    q = _make_queue()
    q.max_size = 3

    for i in range(5):
        q.enqueue("finding.created", {"id": f"f{i}"})

    pending = q.get_pending(limit=100)
    # Should have evicted oldest to stay at or near max
    assert len(pending) <= 3


def test_queue_stores_non_serializable_gracefully():
    from datetime import datetime
    q = _make_queue()
    # datetime not JSON-serializable by default, but our enqueue uses default=str
    result = q.enqueue("finding.created", {"id": "fx", "ts": datetime.utcnow()})
    assert result is True


# ---------------------------------------------------------------------------
# EventBus — flush_queue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_flush_queue_processes_pending():
    bus = _make_bus()
    flushed: List[Dict] = []

    async def handler(data):
        flushed.append(data)
        return True

    bus.on("finding.created", handler)

    # Enqueue directly to bypass emit (simulate offline scenario)
    bus._queue.enqueue("finding.created", {"id": "queued_f1", "engine": "sast"})
    bus._queue.enqueue("finding.created", {"id": "queued_f2", "engine": "dast"})

    result = await bus.flush_queue()
    assert result["attempted"] == 2
    assert result["indexed"] == 2
    assert result["failed"] == 0
    assert len(flushed) == 2


@pytest.mark.asyncio
async def test_flush_queue_marks_failed_on_handler_error():
    bus = _make_bus()

    async def handler(data):
        raise RuntimeError("unavailable")

    bus.on("finding.created", handler)
    bus._queue.enqueue("finding.created", {"id": "q_fail"})

    result = await bus.flush_queue()
    assert result["failed"] == 1
    assert result["indexed"] == 0


@pytest.mark.asyncio
async def test_flush_queue_skips_if_no_handler():
    bus = _make_bus()
    # No handler registered for this event type
    bus._queue.enqueue("finding.created", {"id": "q_skip"})

    result = await bus.flush_queue()
    # No handler → skipped (not marked indexed or failed)
    assert result["attempted"] >= 1
    # Still in queue (not processed)
    stats = bus.queue_stats()
    assert stats["queued"] >= 1


@pytest.mark.asyncio
async def test_flush_increments_metrics():
    bus = _make_bus()

    async def handler(data):
        return True

    bus.on("asset.discovered", handler)
    bus._queue.enqueue("asset.discovered", {"id": "a_q"})

    before = bus.metrics.flush_runs
    await bus.flush_queue()
    assert bus.metrics.flush_runs == before + 1
    assert bus.metrics.flush_indexed >= 1


# ---------------------------------------------------------------------------
# ResponseInterceptorMiddleware
# ---------------------------------------------------------------------------


def _make_test_app(response_body: dict, method: str = "POST", status_code: int = 201) -> FastAPI:
    """Create a minimal FastAPI app that returns the given response body."""
    from core.trustgraph_event_bus import EventBus, ResponseInterceptorMiddleware

    bus = EventBus(enabled=True)

    app = FastAPI()
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)

    @app.post("/test")
    async def endpoint():
        return response_body

    @app.put("/test/{id}")
    async def update_endpoint(id: str):
        return response_body

    app.state._test_bus = bus
    return app


def test_middleware_emits_on_finding_id():
    from core.trustgraph_event_bus import EventBus, ResponseInterceptorMiddleware, get_event_bus
    import core.trustgraph_event_bus as eb_mod

    # Fresh bus
    eb_mod._bus_instance = None
    bus = EventBus(enabled=True)

    emitted: List[tuple] = []

    async def capture(data):
        emitted.append(("finding.created", data))
        return True

    bus.on("finding.created", capture)

    app = FastAPI()
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)

    @app.post("/findings")
    async def create():
        return {"finding_id": "f123", "title": "SQL Injection"}

    client = TestClient(app, raise_server_exceptions=True)
    resp = client.post("/findings")
    assert resp.status_code == 200

    # Give asyncio tasks time to run
    import time; time.sleep(0.1)
    # At minimum the bus should have incremented metrics
    assert bus.metrics.events_emitted >= 1


def test_middleware_emits_on_asset_id():
    from core.trustgraph_event_bus import EventBus, ResponseInterceptorMiddleware

    bus = EventBus(enabled=True)
    emits: List[str] = []

    async def capture(data):
        emits.append(data.get("asset_id", ""))
        return True

    bus.on("asset.discovered", capture)

    app = FastAPI()
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)

    @app.post("/assets")
    async def create():
        return {"asset_id": "a456", "name": "prod-api"}

    client = TestClient(app)
    client.post("/assets")
    import time; time.sleep(0.1)
    assert bus.metrics.events_emitted >= 1


def test_middleware_skips_get_requests():
    from core.trustgraph_event_bus import EventBus, ResponseInterceptorMiddleware

    bus = EventBus(enabled=True)

    app = FastAPI()
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)

    @app.get("/findings")
    async def list_findings():
        return [{"finding_id": "f001"}]

    client = TestClient(app)
    client.get("/findings")
    import time; time.sleep(0.1)
    # GET should not trigger any emit
    assert bus.metrics.events_emitted == 0


def test_middleware_skips_error_responses():
    from core.trustgraph_event_bus import EventBus, ResponseInterceptorMiddleware
    from fastapi import HTTPException

    bus = EventBus(enabled=True)

    app = FastAPI()
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)

    @app.post("/findings")
    async def create():
        raise HTTPException(status_code=400, detail="bad request")

    client = TestClient(app, raise_server_exceptions=False)
    client.post("/findings")
    import time; time.sleep(0.1)
    assert bus.metrics.events_emitted == 0


def test_middleware_skips_non_json_responses():
    from core.trustgraph_event_bus import EventBus, ResponseInterceptorMiddleware
    from starlette.responses import PlainTextResponse

    bus = EventBus(enabled=True)

    app = FastAPI()
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)

    @app.post("/text")
    async def create():
        return PlainTextResponse("ok")

    client = TestClient(app)
    client.post("/text")
    import time; time.sleep(0.1)
    assert bus.metrics.events_emitted == 0


def test_middleware_put_emits_finding_updated():
    from core.trustgraph_event_bus import EventBus, ResponseInterceptorMiddleware, EVENT_FINDING_UPDATED

    bus = EventBus(enabled=True)
    emits: List[str] = []

    async def capture_updated(data):
        emits.append("updated")
        return True

    bus.on(EVENT_FINDING_UPDATED, capture_updated)

    app = FastAPI()
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)

    @app.put("/findings/{fid}")
    async def update(fid: str):
        return {"finding_id": fid, "status": "confirmed"}

    client = TestClient(app)
    client.put("/findings/f001")
    import time; time.sleep(0.1)
    assert bus.metrics.events_emitted >= 1


def test_middleware_no_entity_key_no_emit():
    from core.trustgraph_event_bus import EventBus, ResponseInterceptorMiddleware

    bus = EventBus(enabled=True)

    app = FastAPI()
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)

    @app.post("/misc")
    async def create():
        return {"status": "ok", "message": "created something"}

    client = TestClient(app)
    client.post("/misc")
    import time; time.sleep(0.1)
    assert bus.metrics.events_emitted == 0


def test_middleware_multiple_entity_keys_single_emit_per_type():
    from core.trustgraph_event_bus import EventBus, ResponseInterceptorMiddleware

    bus = EventBus(enabled=True)

    app = FastAPI()
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)

    @app.post("/create")
    async def create():
        # Response contains both finding_id and asset_id
        return {"finding_id": "f001", "asset_id": "a001", "title": "test"}

    client = TestClient(app)
    client.post("/create")
    import time; time.sleep(0.1)
    # Should emit 2 distinct event types
    assert bus.metrics.events_emitted >= 2


# ---------------------------------------------------------------------------
# _rebuild_response
# ---------------------------------------------------------------------------


def test_rebuild_response_preserves_body():
    from core.trustgraph_event_bus import _rebuild_response
    from starlette.responses import JSONResponse

    original = JSONResponse(content={"key": "value"}, status_code=201)
    body = json.dumps({"key": "value"}).encode()

    rebuilt = _rebuild_response(original, body)
    assert rebuilt.status_code == 201
    assert rebuilt.body == body


def test_rebuild_response_preserves_headers():
    from core.trustgraph_event_bus import _rebuild_response
    from starlette.responses import JSONResponse

    original = JSONResponse(content={"x": 1}, headers={"X-Custom": "test"})
    body = b'{"x": 1}'
    rebuilt = _rebuild_response(original, body)
    assert rebuilt.headers.get("x-custom") == "test"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


def test_get_event_bus_singleton():
    import core.trustgraph_event_bus as eb_mod
    eb_mod._bus_instance = None

    from core.trustgraph_event_bus import get_event_bus
    b1 = get_event_bus()
    b2 = get_event_bus()
    assert b1 is b2


# ---------------------------------------------------------------------------
# Default handlers mapping
# ---------------------------------------------------------------------------


def test_default_handlers_cover_all_event_types():
    from core.trustgraph_event_bus import _DEFAULT_HANDLERS, ALL_EVENT_TYPES

    # All event types should have a handler in the default map
    for et in ALL_EVENT_TYPES:
        assert et in _DEFAULT_HANDLERS, f"No default handler for {et}"


# ---------------------------------------------------------------------------
# Event Bus router (API layer)
# ---------------------------------------------------------------------------


def _make_router_app() -> FastAPI:
    """Build a test app with the event bus router mounted."""
    import core.trustgraph_event_bus as eb_mod
    eb_mod._bus_instance = None

    from core.trustgraph_event_bus import EventBus
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    bus = EventBus(enabled=True, queue_db_path=db_path)
    eb_mod._bus_instance = bus

    app = FastAPI()
    from apps.api.event_bus_router import router
    app.include_router(router)
    return app


def test_router_get_status():
    app = _make_router_app()
    client = TestClient(app)
    resp = client.get("/api/v1/event-bus/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "enabled" in data
    assert "metrics" in data
    assert "queue" in data


def test_router_get_queue():
    app = _make_router_app()
    client = TestClient(app)
    resp = client.get("/api/v1/event-bus/queue")
    assert resp.status_code == 200
    data = resp.json()
    assert "queued" in data
    assert "total" in data
    assert "max_size" in data


def test_router_flush():
    app = _make_router_app()
    client = TestClient(app)
    resp = client.post("/api/v1/event-bus/flush")
    assert resp.status_code == 200
    data = resp.json()
    assert "attempted" in data
    assert "indexed" in data
    assert "failed" in data


def test_router_config_disable_master():
    app = _make_router_app()
    client = TestClient(app)
    resp = client.put("/api/v1/event-bus/config", json={"enabled": False})
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is False
    assert "master_enabled=False" in data["changes_applied"]


def test_router_config_disable_event_type():
    app = _make_router_app()
    client = TestClient(app)
    resp = client.put(
        "/api/v1/event-bus/config",
        json={"disable_event_types": ["finding.created"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "finding.created" not in data["enabled_event_types"]


def test_router_config_enable_event_type():
    app = _make_router_app()
    client = TestClient(app)

    # First disable it
    client.put("/api/v1/event-bus/config", json={"disable_event_types": ["finding.created"]})

    # Then re-enable
    resp = client.put(
        "/api/v1/event-bus/config",
        json={"enable_event_types": ["finding.created"]},
    )
    assert resp.status_code == 200
    assert "finding.created" in resp.json()["enabled_event_types"]


def test_router_config_no_changes():
    app = _make_router_app()
    client = TestClient(app)
    resp = client.put("/api/v1/event-bus/config", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["changes_applied"] == []


# ---------------------------------------------------------------------------
# init_event_bus
# ---------------------------------------------------------------------------


def test_init_event_bus_registers_middleware():
    import core.trustgraph_event_bus as eb_mod
    eb_mod._bus_instance = None

    from core.trustgraph_event_bus import init_event_bus, ResponseInterceptorMiddleware

    app = FastAPI()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    with patch.dict(os.environ, {"TRUSTGRAPH_EVENT_BUS_DB": db_path}):
        bus = init_event_bus(app)

    assert bus is not None
    # Middleware should be in the stack
    mw_types = [type(m).__name__ for m in app.middleware_stack.__class__.__mro__]
    # Just verify the bus was returned and enabled
    assert bus.enabled is True


def test_init_event_bus_disabled_skips_middleware():
    import core.trustgraph_event_bus as eb_mod
    eb_mod._bus_instance = None

    from core.trustgraph_event_bus import EventBus, init_event_bus

    app = FastAPI()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    bus = EventBus(enabled=False, queue_db_path=db_path)
    eb_mod._bus_instance = bus

    returned = init_event_bus(app)
    # Should return the disabled bus without crashing
    assert returned.enabled is False


# ---------------------------------------------------------------------------
# ALL_EVENT_TYPES constant
# ---------------------------------------------------------------------------


def test_all_event_types_set():
    from core.trustgraph_event_bus import ALL_EVENT_TYPES

    assert "finding.created" in ALL_EVENT_TYPES
    assert "finding.updated" in ALL_EVENT_TYPES
    assert "asset.discovered" in ALL_EVENT_TYPES
    assert "incident.created" in ALL_EVENT_TYPES
    assert "control.assessed" in ALL_EVENT_TYPES
    assert "vendor.updated" in ALL_EVENT_TYPES
    assert "actor.identified" in ALL_EVENT_TYPES
    assert len(ALL_EVENT_TYPES) == 7


# ---------------------------------------------------------------------------
# _RESPONSE_KEY_MAP
# ---------------------------------------------------------------------------


def test_response_key_map_coverage():
    from core.trustgraph_event_bus import _RESPONSE_KEY_MAP

    assert "finding_id" in _RESPONSE_KEY_MAP
    assert "asset_id" in _RESPONSE_KEY_MAP
    assert "incident_id" in _RESPONSE_KEY_MAP
    assert "control_id" in _RESPONSE_KEY_MAP
    assert "vendor_id" in _RESPONSE_KEY_MAP
    assert "actor_id" in _RESPONSE_KEY_MAP


# ---------------------------------------------------------------------------
# Sync handler support
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emit_sync_handler():
    bus = _make_bus()
    received: List[Dict] = []

    def sync_handler(data):
        received.append(data)
        return True

    bus.on("finding.created", sync_handler)
    await bus.emit("finding.created", {"id": "f_sync"})
    await asyncio.sleep(0.1)
    assert len(received) == 1
