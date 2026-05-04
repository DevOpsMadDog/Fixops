"""
Phase 6: WebSocket Event Streaming Engine for ALDECI.

This module provides real-time event streaming capabilities with:
- Event type enum covering the 15-stage CTEM pipeline
- AsyncIO-based EventBus with pub/sub pattern
- Role-based event filtering for 30 personas
- Multi-tenant event isolation
- Backpressure handling with ring buffer for missed event replay
- Pipeline event emitter helper class
- Event history for reconnection support

Compliance: SOC2 CC7.2 (System monitoring and real-time alerts)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import AsyncGenerator, Dict, List, Optional, Set

_logger = logging.getLogger(__name__)

# Module-level constant: avoids rebuilding this dict on every matches_filters() call.
_SEVERITY_ORDER: Dict[str, int] = {"info": 0, "warning": 1, "critical": 2}


# ============================================================================
# ENUMS
# ============================================================================

class EventType(Enum):
    """Event types across ALDECI 15-stage CTEM pipeline."""

    # Findings pipeline
    FINDING_INGESTED = "finding:ingested"
    FINDING_NORMALIZED = "finding:normalized"
    FINDING_SCORED = "finding:scored"
    FINDING_PRIORITIZED = "finding:prioritized"
    FINDING_VALIDATED = "finding:validated"

    # Pipeline stages
    PIPELINE_STAGE_COMPLETE = "pipeline:stage_complete"

    # Connectors
    CONNECTOR_HEALTH = "connector:health"

    # Council
    COUNCIL_VERDICT = "council:verdict"

    # Escalation
    ESCALATION_TRIGGERED = "escalation:triggered"

    # Sync
    SYNC_COMPLETE = "sync:complete"

    # Compliance
    COMPLIANCE_ALERT = "compliance:alert"

    # Threat Intelligence
    THREAT_INTEL_UPDATE = "threat_intel:update"

    # Dashboard
    DASHBOARD_REFRESH = "dashboard:refresh"

    # System
    SYSTEM_ALERT = "system:alert"

    def __str__(self) -> str:
        return self.value


class EventSeverity(Enum):
    """Event severity levels for filtering and routing."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return self.value


# ============================================================================
# DATACLASSES
# ============================================================================

@dataclass
class StreamEvent:
    """
    Real-time event for WebSocket streaming.

    Attributes:
        event_id: Unique event UUID
        event_type: EventType enum
        payload: Event-specific data dict
        timestamp: UTC timestamp when event occurred
        source: Name of source service/component
        severity: Event severity level
        target_roles: List of role names that should receive this event
        org_id: Organization ID for multi-tenant isolation
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType = EventType.SYSTEM_ALERT
    payload: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "unknown"
    severity: EventSeverity = EventSeverity.INFO
    target_roles: List[str] = field(default_factory=list)
    org_id: str = "default"

    def to_dict(self) -> Dict:
        """Serialize event to dict for JSON transmission."""
        return {
            "event_id": self.event_id,
            "event_type": str(self.event_type),
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "severity": str(self.severity),
            "target_roles": self.target_roles,
            "org_id": self.org_id,
        }

    def matches_filters(
        self,
        event_types: Optional[List[str]] = None,
        min_severity: Optional[str] = None,
    ) -> bool:
        """Check if event matches filter criteria."""
        if event_types and str(self.event_type) not in event_types:
            return False

        if min_severity:
            event_severity = _SEVERITY_ORDER.get(str(self.severity).lower(), 0)
            filter_severity = _SEVERITY_ORDER.get(min_severity.lower(), 0)
            if event_severity < filter_severity:
                return False

        return True


# ============================================================================
# EVENT BUS (SINGLETON)
# ============================================================================

class EventBus:
    """
    Async pub/sub event bus with role-based filtering and backpressure.

    Singleton pattern for process-wide event distribution.
    Uses asyncio.Queue per subscriber with backpressure handling.
    """

    _instance: Optional[EventBus] = None
    _lock = asyncio.Lock()

    def __new__(cls) -> EventBus:
        """Ensure singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize event bus (only once)."""
        if self._initialized:
            return

        self._initialized = True
        self._subscribers: Dict[str, Dict] = {}  # subscriber_id → {queue, roles, org_id}
        self._metrics = {
            "events_published": 0,
            "events_delivered": 0,
            "events_dropped": 0,
            "subscribers_active": 0,
        }
        self._logger = _logger
        self._queue_max_size = 1000

    async def publish(self, event: StreamEvent) -> None:
        """
        Publish event to all matching subscribers.

        Fans out event to subscribers whose roles match target_roles
        and whose org_id matches the event's org_id.

        Args:
            event: StreamEvent to broadcast
        """
        self._metrics["events_published"] += 1

        # Filter subscribers
        for subscriber_id, sub_info in list(self._subscribers.items()):
            queue: asyncio.Queue = sub_info["queue"]
            sub_roles: Set[str] = sub_info["roles"]
            sub_org_id: str = sub_info["org_id"]

            # Multi-tenant isolation: only deliver if org matches
            if sub_org_id != event.org_id:
                continue

            # Role filtering: deliver if target_roles is empty (broadcast) or role matches
            if event.target_roles and not any(
                role in sub_roles for role in event.target_roles
            ):
                continue

            # Backpressure: drop oldest event if queue full
            if queue.full():
                try:
                    queue.get_nowait()
                    self._metrics["events_dropped"] += 1
                except asyncio.QueueEmpty:
                    pass

            try:
                queue.put_nowait(event)
                self._metrics["events_delivered"] += 1
            except asyncio.QueueFull:
                self._metrics["events_dropped"] += 1
                self._logger.warning(
                    f"Event dropped for subscriber {subscriber_id}: queue full"
                )

    async def subscribe(
        self,
        subscriber_id: str,
        roles: Set[str],
        org_id: str,
    ) -> AsyncGenerator[StreamEvent, None]:
        """
        Subscribe to filtered event stream.

        Args:
            subscriber_id: Unique subscriber identifier
            roles: Set of role names to receive events for
            org_id: Organization ID for multi-tenant isolation

        Yields:
            StreamEvent objects matching subscriber's roles and org
        """
        queue: asyncio.Queue[StreamEvent] = asyncio.Queue(maxsize=self._queue_max_size)

        self._subscribers[subscriber_id] = {
            "queue": queue,
            "roles": roles,
            "org_id": org_id,
        }
        self._metrics["subscribers_active"] = len(self._subscribers)
        self._logger.info(f"Subscriber {subscriber_id} subscribed to {roles}")

        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            await self.unsubscribe(subscriber_id)

    async def unsubscribe(self, subscriber_id: str) -> None:
        """
        Unsubscribe a subscriber.

        Args:
            subscriber_id: Subscriber to remove
        """
        if subscriber_id in self._subscribers:
            del self._subscribers[subscriber_id]
            self._metrics["subscribers_active"] = len(self._subscribers)
            self._logger.info(f"Subscriber {subscriber_id} unsubscribed")

    def get_metrics(self) -> Dict:
        """Get event bus metrics."""
        return dict(self._metrics)

    def reset_metrics(self) -> None:
        """Reset metrics counters."""
        for key in self._metrics:
            self._metrics[key] = 0


# ============================================================================
# PIPELINE EVENT EMITTER
# ============================================================================

class PipelineEventEmitter:
    """
    Helper class to emit structured events from CTEM pipeline stages.

    Wraps EventBus.publish with convenience methods for each event type.
    """

    def __init__(self, bus: Optional[EventBus] = None, org_id: str = "default"):
        """
        Initialize emitter.

        Args:
            bus: EventBus instance (defaults to singleton)
            org_id: Organization ID for events
        """
        self._bus = bus or EventBus()
        self._org_id = org_id
        self._logger = _logger

    async def emit_stage_complete(
        self,
        stage_number: int,
        stage_name: str,
        findings_count: int,
        duration_ms: float,
        target_roles: Optional[List[str]] = None,
    ) -> None:
        """
        Emit pipeline stage completion event.

        Args:
            stage_number: Stage number (1-15)
            stage_name: Human-readable stage name
            findings_count: Number of findings processed
            duration_ms: Processing duration in milliseconds
            target_roles: Roles that should see this event
        """
        event = StreamEvent(
            event_type=EventType.PIPELINE_STAGE_COMPLETE,
            payload={
                "stage_number": stage_number,
                "stage_name": stage_name,
                "findings_count": findings_count,
                "duration_ms": duration_ms,
            },
            source="pipeline",
            severity=EventSeverity.INFO,
            target_roles=target_roles or ["admin", "security_analyst"],
            org_id=self._org_id,
        )
        await self._bus.publish(event)
        self._logger.debug(f"Emitted stage complete event for {stage_name}")

    async def emit_finding_scored(
        self,
        finding_id: str,
        old_score: float,
        new_score: float,
        factors: Dict,
        target_roles: Optional[List[str]] = None,
    ) -> None:
        """
        Emit finding scored event.

        Args:
            finding_id: Finding UUID
            old_score: Previous score
            new_score: New score
            factors: Scoring factors dict
            target_roles: Roles that should see this event
        """
        event = StreamEvent(
            event_type=EventType.FINDING_SCORED,
            payload={
                "finding_id": finding_id,
                "old_score": old_score,
                "new_score": new_score,
                "factors": factors,
            },
            source="pipeline",
            severity=EventSeverity.INFO,
            target_roles=target_roles or ["admin", "security_analyst"],
            org_id=self._org_id,
        )
        await self._bus.publish(event)

    async def emit_council_verdict(
        self,
        verdict_id: str,
        decision: str,
        confidence: float,
        council_members: List[str],
        target_roles: Optional[List[str]] = None,
    ) -> None:
        """
        Emit council verdict event.

        Args:
            verdict_id: Verdict UUID
            decision: Decision (e.g., 'approved', 'rejected')
            confidence: Confidence 0-1
            council_members: List of council member IDs
            target_roles: Roles that should see this event
        """
        event = StreamEvent(
            event_type=EventType.COUNCIL_VERDICT,
            payload={
                "verdict_id": verdict_id,
                "decision": decision,
                "confidence": confidence,
                "council_members": council_members,
            },
            source="council",
            severity=EventSeverity.WARNING,
            target_roles=target_roles or ["admin", "security_analyst", "compliance_officer"],
            org_id=self._org_id,
        )
        await self._bus.publish(event)

    async def emit_connector_health(
        self,
        connector_name: str,
        healthy: bool,
        latency_ms: float,
        message: str = "",
        target_roles: Optional[List[str]] = None,
    ) -> None:
        """
        Emit connector health event.

        Args:
            connector_name: Connector name
            healthy: Health status
            latency_ms: Latency in milliseconds
            message: Additional message
            target_roles: Roles that should see this event
        """
        severity = EventSeverity.INFO if healthy else EventSeverity.WARNING
        event = StreamEvent(
            event_type=EventType.CONNECTOR_HEALTH,
            payload={
                "connector_name": connector_name,
                "healthy": healthy,
                "latency_ms": latency_ms,
                "message": message,
            },
            source="connectors",
            severity=severity,
            target_roles=target_roles or ["admin"],
            org_id=self._org_id,
        )
        await self._bus.publish(event)

    async def emit_compliance_alert(
        self,
        framework: str,
        control_id: str,
        severity: str,
        message: str,
        target_roles: Optional[List[str]] = None,
    ) -> None:
        """
        Emit compliance alert event.

        Args:
            framework: Compliance framework (SOC2, HIPAA, etc.)
            control_id: Control identifier
            severity: Severity level (info/warning/critical)
            message: Alert message
            target_roles: Roles that should see this event
        """
        severity_enum = EventSeverity.INFO
        if severity.lower() == "critical":
            severity_enum = EventSeverity.CRITICAL
        elif severity.lower() == "warning":
            severity_enum = EventSeverity.WARNING

        event = StreamEvent(
            event_type=EventType.COMPLIANCE_ALERT,
            payload={
                "framework": framework,
                "control_id": control_id,
                "severity": severity,
                "message": message,
            },
            source="compliance",
            severity=severity_enum,
            target_roles=target_roles or ["admin", "compliance_officer"],
            org_id=self._org_id,
        )
        await self._bus.publish(event)

    async def emit_finding_ingested(
        self,
        finding_id: str,
        source_connector: str,
        raw_data: Dict,
        target_roles: Optional[List[str]] = None,
    ) -> None:
        """
        Emit finding ingested event.

        Args:
            finding_id: Finding UUID
            source_connector: Source connector name
            raw_data: Raw finding data
            target_roles: Roles that should see this event
        """
        event = StreamEvent(
            event_type=EventType.FINDING_INGESTED,
            payload={
                "finding_id": finding_id,
                "source_connector": source_connector,
                "raw_data": raw_data,
            },
            source="connectors",
            severity=EventSeverity.INFO,
            target_roles=target_roles or ["admin", "security_analyst"],
            org_id=self._org_id,
        )
        await self._bus.publish(event)

    async def emit_escalation_triggered(
        self,
        escalation_id: str,
        finding_id: str,
        reason: str,
        target_roles: Optional[List[str]] = None,
    ) -> None:
        """
        Emit escalation triggered event.

        Args:
            escalation_id: Escalation UUID
            finding_id: Associated finding ID
            reason: Escalation reason
            target_roles: Roles that should see this event
        """
        event = StreamEvent(
            event_type=EventType.ESCALATION_TRIGGERED,
            payload={
                "escalation_id": escalation_id,
                "finding_id": finding_id,
                "reason": reason,
            },
            source="pipeline",
            severity=EventSeverity.CRITICAL,
            target_roles=target_roles or ["admin", "security_analyst", "compliance_officer"],
            org_id=self._org_id,
        )
        await self._bus.publish(event)


# ============================================================================
# EVENT HISTORY (Ring Buffer)
# ============================================================================

class EventHistory:
    """
    Ring buffer of recent events for new subscriber catch-up.

    Stores last N events for replay when client reconnects with last_event_id.
    """

    def __init__(self, max_size: int = 500):
        """
        Initialize event history.

        Args:
            max_size: Maximum number of events to keep
        """
        self._buffer: deque = deque(maxlen=max_size)
        self._logger = _logger

    def add(self, event: StreamEvent) -> None:
        """
        Add event to history.

        Args:
            event: StreamEvent to store
        """
        self._buffer.append(event)

    def get_recent(
        self,
        count: int = 10,
        event_types: Optional[List[str]] = None,
        min_severity: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> List[StreamEvent]:
        """
        Get recent events matching filters.

        Args:
            count: Maximum number of events to return
            event_types: Optional list of event types to filter
            min_severity: Optional minimum severity (info/warning/critical)
            org_id: Optional org_id to filter by

        Returns:
            List of matching events, most recent first
        """
        results = []
        for event in reversed(self._buffer):
            # Org filter
            if org_id and event.org_id != org_id:
                continue

            # Event type and severity filters
            if not event.matches_filters(event_types, min_severity):
                continue

            results.append(event)
            if len(results) >= count:
                break

        return results

    def get_after(
        self,
        event_id: str,
        org_id: Optional[str] = None,
    ) -> List[StreamEvent]:
        """
        Get events after a specific event_id (for reconnect replay).

        Args:
            event_id: Event ID to start after
            org_id: Optional org_id to filter by

        Returns:
            List of events after the given event_id
        """
        found = False
        results = []

        for event in self._buffer:
            if found:
                if org_id and event.org_id != org_id:
                    continue
                results.append(event)
            elif event.event_id == event_id:
                found = True

        return results

    def size(self) -> int:
        """Get current buffer size."""
        return len(self._buffer)

    def clear(self) -> None:
        """Clear all events from history."""
        self._buffer.clear()
