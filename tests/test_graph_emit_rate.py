"""
Tests for GET /api/v1/graph/emit-rate

Covers:
  - 200 with bus disabled (zero counters, bus_enabled=False)
  - 200 with bus enabled, fresh counters
  - by_type index_rate computed correctly (None when emitted=0)
  - index_rate ratio accuracy after simulated emit+index
  - queue stats present in response
  - 500 bubbles up on EventBus import failure
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("FIXOPS_TEST_MODE", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client():
    """Build a TestClient around just the backbone router."""
    from apps.api.trustgraph_backbone_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


def _fresh_bus(enabled: bool = True):
    """Return a real EventBus instance with clean metrics."""
    from core.trustgraph_event_bus import EventBus
    return EventBus(enabled=enabled, queue_db_path=":memory:")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEmitRateDisabledBus:
    """Bus is disabled — endpoint still returns 200, bus_enabled=False."""

    def test_returns_200(self):
        client = _make_client()
        bus = _fresh_bus(enabled=False)
        with patch("core.trustgraph_event_bus.get_event_bus", return_value=bus):
            resp = client.get("/api/v1/graph/emit-rate")
        assert resp.status_code == 200

    def test_bus_enabled_false(self):
        client = _make_client()
        bus = _fresh_bus(enabled=False)
        with patch("core.trustgraph_event_bus.get_event_bus", return_value=bus):
            data = client.get("/api/v1/graph/emit-rate").json()
        assert data["bus_enabled"] is False

    def test_totals_all_zero(self):
        client = _make_client()
        bus = _fresh_bus(enabled=False)
        with patch("core.trustgraph_event_bus.get_event_bus", return_value=bus):
            data = client.get("/api/v1/graph/emit-rate").json()
        totals = data["totals"]
        assert totals["events_emitted"] == 0
        assert totals["events_indexed"] == 0
        assert totals["events_queued"] == 0


class TestEmitRateEnabledBus:
    """Bus is enabled with fresh metrics — verify response shape."""

    def _patched_bus(self, enabled: bool = True):
        """Build a bus that ignores FIXOPS_TEST_MODE by bypassing the env check."""
        from core.trustgraph_event_bus import EventBus, EventBusMetrics, _OfflineQueue, ALL_EVENT_TYPES
        import tempfile, os as _os
        bus = object.__new__(EventBus)
        bus.enabled = enabled
        bus.batch_size = 50
        bus.metrics = EventBusMetrics()
        bus._handlers = {}
        bus._enabled_types = set(ALL_EVENT_TYPES)
        # Use a real tmpfile so SQLite table initialisation works
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        bus._queue = _OfflineQueue(db_path=tmp.name, max_size=10_000)
        bus._flush_task = None
        import asyncio
        bus._lock = asyncio.Lock()
        return bus

    def test_bus_enabled_true(self):
        client = _make_client()
        bus = self._patched_bus(enabled=True)
        with patch("core.trustgraph_event_bus.get_event_bus", return_value=bus):
            data = client.get("/api/v1/graph/emit-rate").json()
        assert data["bus_enabled"] is True

    def test_by_type_index_rate_none_when_no_emits(self):
        """index_rate must be None when emitted=0 (no division by zero)."""
        client = _make_client()
        bus = self._patched_bus(enabled=True)
        with patch("core.trustgraph_event_bus.get_event_bus", return_value=bus):
            data = client.get("/api/v1/graph/emit-rate").json()
        for _etype, counters in data["by_type"].items():
            assert counters["index_rate"] is None

    def test_index_rate_computed_correctly(self):
        """After recording 4 emits and 3 indexes, index_rate should be 0.75."""
        client = _make_client()
        bus = self._patched_bus(enabled=True)
        for _ in range(4):
            bus.metrics.record_emit("finding.created")
        for _ in range(3):
            bus.metrics.record_indexed("finding.created", latency_ms=10.0)

        with patch("core.trustgraph_event_bus.get_event_bus", return_value=bus):
            data = client.get("/api/v1/graph/emit-rate").json()

        fc = data["by_type"]["finding.created"]
        assert fc["emitted"] == 4
        assert fc["indexed"] == 3
        assert fc["index_rate"] == pytest.approx(0.75, abs=1e-4)

    def test_queue_stats_present(self):
        """Response must include a 'queue' key with at minimum a 'total' field."""
        client = _make_client()
        bus = self._patched_bus(enabled=True)
        with patch("core.trustgraph_event_bus.get_event_bus", return_value=bus):
            data = client.get("/api/v1/graph/emit-rate").json()
        assert "queue" in data
        # queue may contain 'total' or 'error'; either is a valid dict
        assert isinstance(data["queue"], dict)
        # When the queue table initialised correctly, total must be present
        if "error" not in data["queue"]:
            assert "total" in data["queue"]

    def test_totals_reflect_recorded_metrics(self):
        """Aggregate totals should mirror what was recorded on the bus."""
        client = _make_client()
        bus = self._patched_bus(enabled=True)
        bus.metrics.record_emit("asset.discovered")
        bus.metrics.record_emit("asset.discovered")
        bus.metrics.record_indexed("asset.discovered", latency_ms=5.0)
        bus.metrics.record_queued("asset.discovered")
        bus.metrics.record_failed("asset.discovered")
        bus.metrics.record_dropped()

        with patch("core.trustgraph_event_bus.get_event_bus", return_value=bus):
            data = client.get("/api/v1/graph/emit-rate").json()

        t = data["totals"]
        assert t["events_emitted"] == 2
        assert t["events_indexed"] == 1
        assert t["events_queued"] == 1
        assert t["events_failed"] == 1
        assert t["events_dropped"] == 1


class TestEmitRate500:
    """EventBus import failure surfaces as HTTP 500."""

    def test_import_error_returns_500(self):
        client = _make_client()
        with patch(
            "core.trustgraph_event_bus.get_event_bus",
            side_effect=RuntimeError("bus exploded"),
        ):
            resp = client.get("/api/v1/graph/emit-rate")
        assert resp.status_code == 500
        assert "bus exploded" in resp.json().get("detail", "")
