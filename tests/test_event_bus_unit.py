"""Unit tests for core.event_bus — V3 Decision Intelligence infrastructure.

Tests the EventBus async event system that enables cross-suite communication
for the brain pipeline, AutoFix, MPTE, and all other engines.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock


class TestEventType:
    """Test EventType enum values."""

    def test_scan_events_exist(self):
        from core.event_bus import EventType
        assert EventType.SCAN_STARTED.value == "scan.started"
        assert EventType.SCAN_COMPLETED.value == "scan.completed"
        assert EventType.FINDING_CREATED.value == "finding.created"
        assert EventType.FINDING_UPDATED.value == "finding.updated"

    def test_cve_events_exist(self):
        from core.event_bus import EventType
        assert EventType.CVE_DISCOVERED.value == "cve.discovered"
        assert EventType.CVE_ENRICHED.value == "cve.enriched"

    def test_pentest_events_exist(self):
        from core.event_bus import EventType
        assert EventType.PENTEST_STARTED.value == "pentest.started"
        assert EventType.PENTEST_COMPLETED.value == "pentest.completed"
        assert EventType.EXPLOIT_VALIDATED.value == "exploit.validated"

    def test_remediation_events_exist(self):
        from core.event_bus import EventType
        assert EventType.REMEDIATION_CREATED.value == "remediation.created"
        assert EventType.REMEDIATION_COMPLETED.value == "remediation.completed"
        assert EventType.REMEDIATION_FAILED.value == "remediation.failed"

    def test_autofix_events_exist(self):
        from core.event_bus import EventType
        assert EventType.AUTOFIX_GENERATED.value == "autofix.generated"
        assert EventType.AUTOFIX_VALIDATED.value == "autofix.validated"
        assert EventType.AUTOFIX_APPLIED.value == "autofix.applied"
        assert EventType.AUTOFIX_PR_CREATED.value == "autofix.pr_created"
        assert EventType.AUTOFIX_MERGED.value == "autofix.merged"
        assert EventType.AUTOFIX_FAILED.value == "autofix.failed"
        assert EventType.AUTOFIX_ROLLED_BACK.value == "autofix.rolled_back"

    def test_evidence_events_exist(self):
        from core.event_bus import EventType
        assert EventType.EVIDENCE_COLLECTED.value == "evidence.collected"
        assert EventType.RISK_CALCULATED.value == "risk.calculated"
        assert EventType.RISK_CHANGED.value == "risk.changed"

    def test_intelligence_events_exist(self):
        from core.event_bus import EventType
        assert EventType.FEED_UPDATED.value == "feed.updated"
        assert EventType.THREAT_DETECTED.value == "threat.detected"
        assert EventType.KEV_ALERT.value == "kev.alert"
        assert EventType.EPSS_UPDATED.value == "epss.updated"

    def test_collaboration_events_exist(self):
        from core.event_bus import EventType
        assert EventType.COMMENT_ADDED.value == "comment.added"
        assert EventType.TASK_ASSIGNED.value == "task.assigned"
        assert EventType.WORKFLOW_TRIGGERED.value == "workflow.triggered"

    def test_system_events_exist(self):
        from core.event_bus import EventType
        assert EventType.GRAPH_UPDATED.value == "graph.updated"
        assert EventType.DEDUP_COMPLETED.value == "dedup.completed"
        assert EventType.POLICY_VIOLATED.value == "policy.violated"
        assert EventType.AUDIT_LOGGED.value == "audit.logged"

    def test_copilot_events_exist(self):
        from core.event_bus import EventType
        assert EventType.COPILOT_QUERY.value == "copilot.query"
        assert EventType.COPILOT_RESPONSE.value == "copilot.response"
        assert EventType.DECISION_MADE.value == "decision.made"

    def test_event_type_is_string_enum(self):
        from core.event_bus import EventType
        assert isinstance(EventType.SCAN_STARTED, str)
        assert EventType.SCAN_STARTED == "scan.started"

    def test_total_event_type_count(self):
        from core.event_bus import EventType
        # At least 30+ event types
        assert len(EventType) >= 30


class TestEvent:
    """Test Event dataclass."""

    def test_event_creation_basic(self):
        from core.event_bus import Event, EventType
        event = Event(event_type=EventType.CVE_DISCOVERED, source="test_router")
        assert event.event_type == EventType.CVE_DISCOVERED
        assert event.source == "test_router"
        assert event.data == {}
        assert event.org_id is None

    def test_event_auto_id(self):
        from core.event_bus import Event, EventType
        event = Event(event_type=EventType.SCAN_STARTED, source="test")
        assert event.event_id != ""
        assert len(event.event_id) == 36  # UUID format

    def test_event_auto_timestamp(self):
        from core.event_bus import Event, EventType
        event = Event(event_type=EventType.SCAN_STARTED, source="test")
        assert event.timestamp != ""
        assert "T" in event.timestamp  # ISO format

    def test_event_preserves_explicit_id(self):
        from core.event_bus import Event, EventType
        event = Event(event_type=EventType.SCAN_STARTED, source="test", event_id="custom-123")
        assert event.event_id == "custom-123"

    def test_event_preserves_explicit_timestamp(self):
        from core.event_bus import Event, EventType
        event = Event(event_type=EventType.SCAN_STARTED, source="test", timestamp="2026-01-01T00:00:00Z")
        assert event.timestamp == "2026-01-01T00:00:00Z"

    def test_event_with_data(self):
        from core.event_bus import Event, EventType
        data = {"cve_id": "CVE-2024-1234", "severity": "CRITICAL"}
        event = Event(event_type=EventType.CVE_DISCOVERED, source="scanner", data=data)
        assert event.data["cve_id"] == "CVE-2024-1234"
        assert event.data["severity"] == "CRITICAL"

    def test_event_with_org_id(self):
        from core.event_bus import Event, EventType
        event = Event(event_type=EventType.SCAN_STARTED, source="test", org_id="org_123")
        assert event.org_id == "org_123"

    def test_event_with_string_event_type(self):
        from core.event_bus import Event
        event = Event(event_type="custom.event", source="test")
        assert event.event_type == "custom.event"


class TestEventBus:
    """Test EventBus class."""

    def setup_method(self):
        from core.event_bus import EventBus
        EventBus.reset_instance()

    def teardown_method(self):
        from core.event_bus import EventBus
        EventBus.reset_instance()

    def test_singleton_instance(self):
        from core.event_bus import EventBus
        bus1 = EventBus.get_instance()
        bus2 = EventBus.get_instance()
        assert bus1 is bus2

    def test_reset_instance(self):
        from core.event_bus import EventBus
        bus1 = EventBus.get_instance()
        EventBus.reset_instance()
        bus2 = EventBus.get_instance()
        assert bus1 is not bus2

    def test_subscribe_decorator(self):
        from core.event_bus import EventBus, EventType
        bus = EventBus()

        @bus.on(EventType.CVE_DISCOVERED)
        async def handler(event):
            pass

        assert "cve.discovered" in bus._subscribers
        assert len(bus._subscribers["cve.discovered"]) == 1

    def test_subscribe_programmatic(self):
        from core.event_bus import EventBus, EventType
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe(EventType.SCAN_STARTED, handler)
        assert "scan.started" in bus._subscribers
        assert handler in bus._subscribers["scan.started"]

    def test_subscribe_with_string_key(self):
        from core.event_bus import EventBus
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe("custom.event", handler)
        assert "custom.event" in bus._subscribers

    def test_subscribe_all_wildcard(self):
        from core.event_bus import EventBus
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe_all(handler)
        assert handler in bus._wildcard_subscribers

    @pytest.mark.asyncio
    async def test_emit_notifies_subscribers(self):
        from core.event_bus import Event, EventBus, EventType
        bus = EventBus()
        bus._brain = MagicMock()
        handler = AsyncMock()
        bus.subscribe(EventType.CVE_DISCOVERED, handler)
        event = Event(event_type=EventType.CVE_DISCOVERED, source="test")
        count = await bus.emit(event)
        assert count == 1
        handler.assert_awaited_once_with(event)

    @pytest.mark.asyncio
    async def test_emit_notifies_wildcard_subscribers(self):
        from core.event_bus import Event, EventBus, EventType
        bus = EventBus()
        bus._brain = MagicMock()
        wildcard = AsyncMock()
        bus.subscribe_all(wildcard)
        event = Event(event_type=EventType.SCAN_STARTED, source="test")
        count = await bus.emit(event)
        assert count == 1
        wildcard.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_emit_handles_handler_exception(self):
        from core.event_bus import Event, EventBus, EventType
        bus = EventBus()
        bus._brain = MagicMock()
        bad_handler = AsyncMock(side_effect=RuntimeError("boom"))
        good_handler = AsyncMock()
        bus.subscribe(EventType.SCAN_STARTED, bad_handler)
        bus.subscribe(EventType.SCAN_STARTED, good_handler)
        event = Event(event_type=EventType.SCAN_STARTED, source="test")
        count = await bus.emit(event)
        # bad_handler fails, good_handler succeeds
        assert count == 1

    @pytest.mark.asyncio
    async def test_emit_logs_event(self):
        from core.event_bus import Event, EventBus, EventType
        bus = EventBus()
        bus._brain = MagicMock()
        event = Event(event_type=EventType.SCAN_STARTED, source="test", org_id="org1")
        await bus.emit(event)
        assert len(bus._event_log) == 1
        log_entry = bus._event_log[0]
        assert log_entry["event_type"] == "scan.started"
        assert log_entry["source"] == "test"
        assert log_entry["org_id"] == "org1"

    @pytest.mark.asyncio
    async def test_emit_truncates_log_at_max_size(self):
        from core.event_bus import Event, EventBus, EventType
        bus = EventBus()
        bus._brain = MagicMock()
        bus._max_log_size = 5
        for i in range(10):
            event = Event(event_type=EventType.SCAN_STARTED, source=f"test-{i}")
            await bus.emit(event)
        assert len(bus._event_log) == 5

    @pytest.mark.asyncio
    async def test_emit_returns_zero_with_no_subscribers(self):
        from core.event_bus import Event, EventBus, EventType
        bus = EventBus()
        bus._brain = MagicMock()
        event = Event(event_type=EventType.SCAN_STARTED, source="test")
        count = await bus.emit(event)
        assert count == 0

    def test_recent_events_empty(self):
        from core.event_bus import EventBus
        bus = EventBus()
        events = bus.recent_events()
        assert events == []

    @pytest.mark.asyncio
    async def test_recent_events_returns_reversed(self):
        from core.event_bus import Event, EventBus, EventType
        bus = EventBus()
        bus._brain = MagicMock()
        for i in range(3):
            event = Event(event_type=EventType.SCAN_STARTED, source=f"src-{i}")
            await bus.emit(event)
        events = bus.recent_events()
        assert len(events) == 3
        assert events[0]["source"] == "src-2"
        assert events[2]["source"] == "src-0"

    @pytest.mark.asyncio
    async def test_recent_events_respects_limit(self):
        from core.event_bus import Event, EventBus, EventType
        bus = EventBus()
        bus._brain = MagicMock()
        for i in range(10):
            await bus.emit(Event(event_type=EventType.SCAN_STARTED, source=f"s-{i}"))
        events = bus.recent_events(limit=3)
        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_emit_with_string_event_type(self):
        from core.event_bus import Event, EventBus
        bus = EventBus()
        bus._brain = MagicMock()
        handler = AsyncMock()
        bus.subscribe("custom.type", handler)
        event = Event(event_type="custom.type", source="test")
        count = await bus.emit(event)
        assert count == 1


class TestGetEventBus:
    """Test module-level get_event_bus function."""

    def setup_method(self):
        from core.event_bus import EventBus
        EventBus.reset_instance()

    def teardown_method(self):
        from core.event_bus import EventBus
        EventBus.reset_instance()

    def test_get_event_bus_returns_singleton(self):
        from core.event_bus import get_event_bus
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2

    def test_get_event_bus_returns_event_bus_type(self):
        from core.event_bus import EventBus, get_event_bus
        bus = get_event_bus()
        assert isinstance(bus, EventBus)
