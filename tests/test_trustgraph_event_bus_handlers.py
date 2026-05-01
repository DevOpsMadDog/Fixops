"""
Tests for TrustGraph event-bus default handler wiring (Wave 2b).

Validates that:
- finding.created routes to UniversalFindingIndexer.index()
- asset.discovered routes to TrustGraphBackbone.index_asset()
- handlers swallow exceptions and never propagate
- init_event_bus() registers handlers for all default event types
- module load registers handlers on the singleton bus (CLI mode)
"""

from __future__ import annotations

import asyncio
import importlib
import os
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI


def _fresh_event_bus(enabled: bool = True) -> Any:
    """Reset and return a fresh EventBus singleton for test isolation."""
    import core.trustgraph_event_bus as eb
    eb._bus_instance = None
    bus = eb.EventBus(enabled=enabled)
    eb._bus_instance = bus
    return bus


@pytest.mark.asyncio
async def test_finding_created_calls_indexer():
    """finding.created event should invoke UniversalFindingIndexer.index() with the payload."""
    bus = _fresh_event_bus()
    from core.trustgraph_event_bus import (
        EVENT_FINDING_CREATED,
        register_default_handlers,
    )

    captured: Dict[str, Any] = {}

    class FakeIndexer:
        def __init__(self, *args, **kwargs):
            captured["init_kwargs"] = kwargs

        def index(self, payload):
            captured["payload"] = payload
            return "finding_test_001"

    with patch("core.trustgraph_integrations.UniversalFindingIndexer", FakeIndexer):
        register_default_handlers(bus)
        payload = {
            "id": "f001",
            "engine": "sast",
            "severity": "high",
            "title": "SQL injection",
            "org_id": "test_org",
        }
        await bus.emit(EVENT_FINDING_CREATED, payload)
        # Allow background task to run
        await asyncio.sleep(0.1)

    assert captured.get("payload") is not None, "Indexer.index() was not called"
    assert captured["payload"]["id"] == "f001"
    assert captured["payload"]["engine"] == "sast"
    assert captured["init_kwargs"].get("org_id") == "test_org"


@pytest.mark.asyncio
async def test_asset_discovered_calls_index_asset():
    """asset.discovered event should invoke TrustGraphBackbone.index_asset() with the payload."""
    bus = _fresh_event_bus()
    from core.trustgraph_event_bus import (
        EVENT_ASSET_DISCOVERED,
        register_default_handlers,
    )

    captured: Dict[str, Any] = {}

    class FakeBackbone:
        def __init__(self, *args, **kwargs):
            captured["init_kwargs"] = kwargs

        def index_asset(self, payload):
            captured["payload"] = payload
            return "asset_test_001"

    with patch("core.trustgraph_backbone.TrustGraphBackbone", FakeBackbone):
        register_default_handlers(bus)
        payload = {
            "asset_id": "a001",
            "name": "prod-api",
            "asset_type": "container",
            "org_id": "tenant_42",
        }
        await bus.emit(EVENT_ASSET_DISCOVERED, payload)
        await asyncio.sleep(0.1)

    assert captured.get("payload") is not None, "index_asset() was not called"
    assert captured["payload"]["asset_id"] == "a001"
    assert captured["init_kwargs"].get("org_id") == "tenant_42"


@pytest.mark.asyncio
async def test_handler_swallows_exceptions():
    """Handlers must NEVER raise — bus.emit() must remain safe even on indexer failure."""
    bus = _fresh_event_bus()
    from core.trustgraph_event_bus import (
        EVENT_FINDING_CREATED,
        EVENT_ASSET_DISCOVERED,
        EVENT_INCIDENT_CREATED,
        EVENT_CVE_DISCOVERED,
        EVENT_RISK_ASSESSED,
        register_default_handlers,
    )

    class ExplodingIndexer:
        def __init__(self, *args, **kwargs):
            pass

        def index(self, payload):
            raise RuntimeError("simulated TrustGraph failure")

    class ExplodingBackbone:
        def __init__(self, *args, **kwargs):
            pass

        def index_asset(self, payload):
            raise RuntimeError("simulated backbone failure")

        def index_incident(self, payload):
            raise RuntimeError("simulated backbone failure")

        def index_compliance_control(self, payload):
            raise RuntimeError("simulated backbone failure")

    with patch("core.trustgraph_integrations.UniversalFindingIndexer", ExplodingIndexer), \
         patch("core.trustgraph_backbone.TrustGraphBackbone", ExplodingBackbone):
        register_default_handlers(bus)
        # All five emits must complete without raising
        for event_type, payload in [
            (EVENT_FINDING_CREATED, {"id": "f1", "engine": "sast"}),
            (EVENT_ASSET_DISCOVERED, {"asset_id": "a1"}),
            (EVENT_INCIDENT_CREATED, {"incident_id": "i1"}),
            (EVENT_CVE_DISCOVERED, {"cve_id": "CVE-2024-1234"}),
            (EVENT_RISK_ASSESSED, {"risk_id": "r1", "score": 8.5}),
        ]:
            # Must not raise
            await bus.emit(event_type, payload)
        await asyncio.sleep(0.15)

    # Bus is still alive and handlers were dispatched
    assert bus.metrics.events_emitted >= 5


def test_handlers_registered_on_init():
    """init_event_bus(app) must register all 6 default handlers (idempotently)."""
    import core.trustgraph_event_bus as eb
    eb._bus_instance = None

    from core.trustgraph_event_bus import (
        init_event_bus,
        EVENT_FINDING_CREATED,
        EVENT_FINDING_UPDATED,
        EVENT_ASSET_DISCOVERED,
        EVENT_INCIDENT_CREATED,
        EVENT_CVE_DISCOVERED,
        EVENT_RISK_ASSESSED,
    )

    app = FastAPI()
    bus = init_event_bus(app)

    required = [
        EVENT_FINDING_CREATED,
        EVENT_FINDING_UPDATED,
        EVENT_ASSET_DISCOVERED,
        EVENT_INCIDENT_CREATED,
        EVENT_CVE_DISCOVERED,
        EVENT_RISK_ASSESSED,
    ]
    for event_type in required:
        handlers = bus._handlers.get(event_type, [])
        assert len(handlers) >= 1, f"No handler registered for {event_type}"


def test_handlers_registered_at_module_load():
    """Module-load auto-registration must wire handlers on the singleton bus (CLI mode)."""
    import core.trustgraph_event_bus as eb

    # Simulate CLI mode: clear test-mode flag so eager registration runs
    prior_test_mode = os.environ.get("FIXOPS_TEST_MODE")
    prior_enabled = os.environ.get("TRUSTGRAPH_EVENT_BUS_ENABLED")
    os.environ["FIXOPS_TEST_MODE"] = "0"
    os.environ["TRUSTGRAPH_EVENT_BUS_ENABLED"] = "1"

    try:
        # Reset singleton then re-import to trigger module-load hook
        eb._bus_instance = None
        importlib.reload(eb)
        bus = eb.get_event_bus()

        # Default handlers should be wired even though no FastAPI app exists
        required = [
            eb.EVENT_FINDING_CREATED,
            eb.EVENT_ASSET_DISCOVERED,
            eb.EVENT_INCIDENT_CREATED,
            eb.EVENT_CVE_DISCOVERED,
            eb.EVENT_RISK_ASSESSED,
        ]
        for event_type in required:
            handlers = bus._handlers.get(event_type, [])
            assert len(handlers) >= 1, f"Module-load did not register {event_type}"
    finally:
        # Restore env and reset singleton so other tests are unaffected
        if prior_test_mode is None:
            os.environ.pop("FIXOPS_TEST_MODE", None)
        else:
            os.environ["FIXOPS_TEST_MODE"] = prior_test_mode
        if prior_enabled is None:
            os.environ.pop("TRUSTGRAPH_EVENT_BUS_ENABLED", None)
        else:
            os.environ["TRUSTGRAPH_EVENT_BUS_ENABLED"] = prior_enabled
        eb._bus_instance = None
        importlib.reload(eb)
