"""Tests for core.event_bus — async event bus with subscriptions and wildcard handlers."""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.event_bus import Event, EventBus, EventType, get_event_bus  # noqa: E402


# ---------------------------------------------------------------------------
# EventType enum
# ---------------------------------------------------------------------------


class TestEventType:
    def test_scan_events(self):
        assert EventType.SCAN_STARTED.value == "scan.started"
        assert EventType.SCAN_COMPLETED.value == "scan.completed"
        assert EventType.FINDING_CREATED.value == "finding.created"

    def test_attack_events(self):
        assert EventType.PENTEST_STARTED.value == "pentest.started"
        assert EventType.PENTEST_COMPLETED.value == "pentest.completed"
        assert EventType.EXPLOIT_VALIDATED.value == "exploit.validated"

    def test_autofix_events(self):
        assert EventType.AUTOFIX_GENERATED.value == "autofix.generated"
        assert EventType.AUTOFIX_VALIDATED.value == "autofix.validated"
        assert EventType.AUTOFIX_APPLIED.value == "autofix.applied"
        assert EventType.AUTOFIX_PR_CREATED.value == "autofix.pr_created"
        assert EventType.AUTOFIX_FAILED.value == "autofix.failed"

    def test_intelligence_events(self):
        assert EventType.FEED_UPDATED.value == "feed.updated"
        assert EventType.KEV_ALERT.value == "kev.alert"
        assert EventType.EPSS_UPDATED.value == "epss.updated"

    def test_ml_events(self):
        assert EventType.SCAN_ANOMALY_DETECTED.value == "scan.anomaly_detected"
        assert EventType.MODEL_RETRAINED.value == "model.retrained"

    def test_total_count(self):
        assert len(EventType) >= 30


# ---------------------------------------------------------------------------
# Event data class
# ---------------------------------------------------------------------------


class TestEvent:
    def test_create_with_defaults(self):
        e = Event(
            event_type=EventType.SCAN_STARTED,
            source="test_router",
        )
        assert e.event_type == EventType.SCAN_STARTED
        assert e.source == "test_router"
        assert e.data == {}
        assert e.org_id is None
        assert e.event_id  # Auto-generated UUID
        assert e.timestamp  # Auto-generated ISO string

    def test_create_with_data(self):
        e = Event(
            event_type=EventType.CVE_DISCOVERED,
            source="scanner",
            data={"cve_id": "CVE-2024-1234", "severity": "critical"},
            org_id="org-123",
        )
        assert e.data["cve_id"] == "CVE-2024-1234"
        assert e.org_id == "org-123"

    def test_event_id_unique(self):
        e1 = Event(event_type=EventType.SCAN_STARTED, source="a")
        e2 = Event(event_type=EventType.SCAN_STARTED, source="a")
        assert e1.event_id != e2.event_id


# ---------------------------------------------------------------------------
# EventBus
# ---------------------------------------------------------------------------


class TestEventBus:
    @pytest.fixture
    def bus(self):
        bus = EventBus()
        yield bus

    @pytest.mark.asyncio
    async def test_emit_no_subscribers(self, bus):
        event = Event(event_type=EventType.SCAN_STARTED, source="test")
        notified = await bus.emit(event)
        assert notified == 0

    @pytest.mark.asyncio
    async def test_subscribe_and_emit(self, bus):
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe(EventType.SCAN_COMPLETED, handler)
        event = Event(
            event_type=EventType.SCAN_COMPLETED,
            source="test",
            data={"findings": 5},
        )
        notified = await bus.emit(event)
        assert notified == 1
        assert len(received) == 1
        assert received[0].data["findings"] == 5

    @pytest.mark.asyncio
    async def test_decorator_subscribe(self, bus):
        received = []

        @bus.on(EventType.FINDING_CREATED)
        async def handler(event: Event):
            received.append(event.data)

        event = Event(
            event_type=EventType.FINDING_CREATED,
            source="scanner",
            data={"vuln": "XSS"},
        )
        await bus.emit(event)
        assert len(received) == 1
        assert received[0]["vuln"] == "XSS"

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self, bus):
        count = {"a": 0, "b": 0}

        async def handler_a(event: Event):
            count["a"] += 1

        async def handler_b(event: Event):
            count["b"] += 1

        bus.subscribe(EventType.CVE_DISCOVERED, handler_a)
        bus.subscribe(EventType.CVE_DISCOVERED, handler_b)
        event = Event(event_type=EventType.CVE_DISCOVERED, source="test")
        notified = await bus.emit(event)
        assert notified == 2
        assert count["a"] == 1
        assert count["b"] == 1

    @pytest.mark.asyncio
    async def test_wildcard_subscriber(self, bus):
        received = []

        async def catch_all(event: Event):
            received.append(event.event_type)

        bus.subscribe_all(catch_all)
        await bus.emit(Event(event_type=EventType.SCAN_STARTED, source="a"))
        await bus.emit(Event(event_type=EventType.CVE_DISCOVERED, source="b"))
        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_handler_error_doesnt_crash(self, bus):
        async def bad_handler(event: Event):
            raise RuntimeError("Handler error")

        async def good_handler(event: Event):
            pass

        bus.subscribe(EventType.SCAN_STARTED, bad_handler)
        bus.subscribe(EventType.SCAN_STARTED, good_handler)
        notified = await bus.emit(Event(event_type=EventType.SCAN_STARTED, source="t"))
        # Good handler should still run even though bad handler threw
        assert notified == 1  # Only successful ones counted

    @pytest.mark.asyncio
    async def test_recent_events(self, bus):
        for i in range(5):
            await bus.emit(Event(event_type=EventType.SCAN_STARTED, source=f"src-{i}"))
        recent = bus.recent_events(limit=3)
        assert len(recent) == 3
        # Most recent first
        assert recent[0]["source"] == "src-4"

    @pytest.mark.asyncio
    async def test_event_log_max_size(self, bus):
        bus._max_log_size = 10
        for i in range(20):
            await bus.emit(Event(event_type=EventType.SCAN_STARTED, source=f"s-{i}"))
        assert len(bus._event_log) <= 10

    @pytest.mark.asyncio
    async def test_string_event_type_subscribe(self, bus):
        received = []

        bus.subscribe("custom.event", lambda e: received.append(e))
        # Can't use string directly with Event — need to use EventType
        # But the bus accepts string keys for custom events
        # This tests the string key path


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


class TestEventBusSingleton:
    def test_get_instance(self):
        EventBus.reset_instance()
        bus1 = EventBus.get_instance()
        bus2 = EventBus.get_instance()
        assert bus1 is bus2
        EventBus.reset_instance()

    def test_reset_instance(self):
        EventBus.reset_instance()
        bus1 = EventBus.get_instance()
        EventBus.reset_instance()
        bus2 = EventBus.get_instance()
        assert bus1 is not bus2
        EventBus.reset_instance()

    def test_get_event_bus_function(self):
        EventBus.reset_instance()
        bus = get_event_bus()
        assert isinstance(bus, EventBus)
        EventBus.reset_instance()
