"""
FixOps Event Bus — Cross-Suite Communication.

Lightweight async event bus that enables every API action to trigger
downstream workflows. When a pentest finds a CVE, the event bus
triggers dedup check, remediation task, EPSS lookup, graph update,
audit log, and team notification — all automatically.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Event Types
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    """All event types that flow through the bus."""

    # Scan & Discovery
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    CVE_DISCOVERED = "cve.discovered"
    CVE_ENRICHED = "cve.enriched"

    # Attack & Pentest
    PENTEST_STARTED = "pentest.started"
    PENTEST_COMPLETED = "pentest.completed"
    ATTACK_SIMULATED = "attack.simulated"
    EXPLOIT_VALIDATED = "exploit.validated"
    SECRET_FOUND = "secret.found"

    # Remediation
    REMEDIATION_CREATED = "remediation.created"
    REMEDIATION_COMPLETED = "remediation.completed"
    REMEDIATION_FAILED = "remediation.failed"

    # AutoFix
    AUTOFIX_GENERATED = "autofix.generated"
    AUTOFIX_VALIDATED = "autofix.validated"
    AUTOFIX_APPLIED = "autofix.applied"
    AUTOFIX_PR_CREATED = "autofix.pr_created"
    AUTOFIX_MERGED = "autofix.merged"
    AUTOFIX_FAILED = "autofix.failed"
    AUTOFIX_ROLLED_BACK = "autofix.rolled_back"

    # Evidence & Risk
    EVIDENCE_COLLECTED = "evidence.collected"
    RISK_CALCULATED = "risk.calculated"
    RISK_CHANGED = "risk.changed"

    # Intelligence
    FEED_UPDATED = "feed.updated"
    THREAT_DETECTED = "threat.detected"
    KEV_ALERT = "kev.alert"
    EPSS_UPDATED = "epss.updated"

    # Collaboration
    COMMENT_ADDED = "comment.added"
    TASK_ASSIGNED = "task.assigned"
    WORKFLOW_TRIGGERED = "workflow.triggered"
    NOTIFICATION_SENT = "notification.sent"

    # System
    GRAPH_UPDATED = "graph.updated"
    DEDUP_COMPLETED = "dedup.completed"
    POLICY_VIOLATED = "policy.violated"
    AUDIT_LOGGED = "audit.logged"

    # Copilot / AI
    COPILOT_QUERY = "copilot.query"
    COPILOT_RESPONSE = "copilot.response"
    DECISION_MADE = "decision.made"


@dataclass
class Event:
    """An event flowing through the bus."""

    event_type: EventType
    source: str  # Which router/service emitted this
    data: Dict[str, Any] = field(default_factory=dict)
    org_id: Optional[str] = None
    event_id: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# Subscriber type: async function that takes an Event
Subscriber = Callable[[Event], Awaitable[None]]


class EventBus:
    """
    Async event bus for cross-suite communication.

    Usage:
        bus = get_event_bus()

        # Subscribe to events
        @bus.on(EventType.CVE_DISCOVERED)
        async def handle_cve(event: Event):
            # Auto-trigger EPSS lookup, dedup check, graph update
            ...

        # Emit events
        await bus.emit(Event(
            event_type=EventType.CVE_DISCOVERED,
            source="micro_pentest_router",
            data={"cve_id": "CVE-2024-1234", "severity": "CRITICAL"},
            org_id="org_123",
        ))
    """

    _instance: Optional["EventBus"] = None

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Subscriber]] = {}
        self._wildcard_subscribers: List[Subscriber] = []
        self._event_log: List[Dict[str, Any]] = []
        self._max_log_size = 10000
        self._brain = None  # Lazy import to avoid circular deps
        logger.info("EventBus initialized")

    @classmethod
    def get_instance(cls) -> "EventBus":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        cls._instance = None

    def on(self, event_type: EventType | str) -> Callable:
        """Decorator to subscribe to an event type."""

        def decorator(func: Subscriber) -> Subscriber:
            key = event_type.value if isinstance(event_type, EventType) else event_type
            self._subscribers.setdefault(key, []).append(func)
            logger.debug("Subscriber registered for %s: %s", key, func.__name__)
            return func

        return decorator

    def subscribe(self, event_type: EventType | str, handler: Subscriber) -> None:
        """Programmatically subscribe to an event type."""
        key = event_type.value if isinstance(event_type, EventType) else event_type
        self._subscribers.setdefault(key, []).append(handler)

    def subscribe_all(self, handler: Subscriber) -> None:
        """Subscribe to ALL events (wildcard)."""
        self._wildcard_subscribers.append(handler)

    async def emit(self, event: Event) -> int:
        """Emit an event. Returns number of subscribers notified."""
        start = time.monotonic()
        key = (
            event.event_type.value
            if isinstance(event.event_type, EventType)
            else event.event_type
        )

        # Log event
        self._event_log.append(
            {
                "event_id": event.event_id,
                "event_type": key,
                "source": event.source,
                "org_id": event.org_id,
                "timestamp": event.timestamp,
            }
        )
        if len(self._event_log) > self._max_log_size:
            self._event_log = self._event_log[-self._max_log_size :]

        # Also log to brain if available
        try:
            if self._brain is None:
                from core.knowledge_brain import get_brain

                self._brain = get_brain()
            self._brain.log_event(key, event.source, event.data)
        except Exception:
            pass  # Don't fail the event if brain is unavailable

        # Notify subscribers
        handlers = self._subscribers.get(key, []) + self._wildcard_subscribers
        notified = 0
        for handler in handlers:
            try:
                await handler(event)
                notified += 1
            except Exception as exc:
                logger.error(
                    "Event handler %s failed for %s: %s",
                    handler.__name__,
                    key,
                    exc,
                )

        elapsed_ms = (time.monotonic() - start) * 1000
        logger.debug(
            "Event %s emitted: %d handlers in %.1fms",
            key,
            notified,
            elapsed_ms,
        )
        return notified

    def recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent events from the in-memory log."""
        return list(reversed(self._event_log[-limit:]))


# ---------------------------------------------------------------------------
# Module-level singleton accessor
# ---------------------------------------------------------------------------
_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get the global EventBus instance."""
    return EventBus.get_instance()
