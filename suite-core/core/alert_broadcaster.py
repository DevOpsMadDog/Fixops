"""
AlertBroadcaster — singleton pub/sub broadcaster for real-time security alerts.

Maintains an asyncio.Queue per connected subscriber. Callers push alerts via
broadcast() or broadcast_to_tenant(); subscribers drain their own queue.

Alert schema:
    {
        "id":          str (uuid4),
        "type":        str  (see ALERT_TYPES),
        "severity":    str  ("critical" | "high" | "medium" | "low" | "info"),
        "title":       str,
        "message":     str,
        "timestamp":   str  (ISO-8601 UTC),
        "tenant_id":   str | None,
        "metadata":    dict,
    }

Alert types:
    finding_created, incident_opened, sla_breach, policy_violation,
    new_cve, threat_detected
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import structlog

logger = structlog.get_logger("core.alert_broadcaster")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALERT_TYPES: Set[str] = {
    "finding_created",
    "incident_opened",
    "sla_breach",
    "policy_violation",
    "new_cve",
    "threat_detected",
}

SEVERITY_LEVELS: List[str] = ["info", "low", "medium", "high", "critical"]

# Maximum number of queued alerts per subscriber before oldest are dropped
_DEFAULT_QUEUE_MAX = 256


# ---------------------------------------------------------------------------
# Alert schema helper
# ---------------------------------------------------------------------------


def build_alert(
    *,
    alert_type: str,
    severity: str,
    title: str,
    message: str,
    tenant_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    alert_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct a validated alert dict.

    Args:
        alert_type: One of ALERT_TYPES.
        severity: One of SEVERITY_LEVELS.
        title: Short human-readable title.
        message: Full alert message.
        tenant_id: Optional tenant scoping.
        metadata: Arbitrary extra data.
        alert_id: Override auto-generated UUID.

    Returns:
        Validated alert dict.

    Raises:
        ValueError: If alert_type or severity is invalid.
    """
    if alert_type not in ALERT_TYPES:
        raise ValueError(f"Invalid alert type '{alert_type}'. Must be one of {sorted(ALERT_TYPES)}")
    if severity not in SEVERITY_LEVELS:
        raise ValueError(f"Invalid severity '{severity}'. Must be one of {SEVERITY_LEVELS}")

    return {
        "id": alert_id or str(uuid.uuid4()),
        "type": alert_type,
        "severity": severity,
        "title": title,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "metadata": metadata or {},
    }


# ---------------------------------------------------------------------------
# AlertBroadcaster
# ---------------------------------------------------------------------------


class AlertBroadcaster:
    """Singleton pub/sub broadcaster for real-time security alerts.

    Each subscriber gets its own asyncio.Queue. Broadcast pushes an alert
    to every subscriber's queue (or to matching tenants only). Queues are
    bounded; when full, the oldest alert is dropped and the new one appended
    so consumers always receive the most recent events.

    Thread-safety: subscribe/unsubscribe are protected by a threading.Lock
    so they can be called from sync contexts. broadcast() is async and
    designed to be awaited from async request handlers.
    """

    def __init__(self, queue_max: int = _DEFAULT_QUEUE_MAX) -> None:
        self._queue_max = queue_max
        # connection_id → asyncio.Queue
        self._queues: Dict[str, asyncio.Queue] = {}
        # connection_id → tenant_id (None means no tenant filter)
        self._tenants: Dict[str, Optional[str]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Subscriber lifecycle
    # ------------------------------------------------------------------

    def subscribe(self, connection_id: str, tenant_id: Optional[str] = None) -> asyncio.Queue:
        """Register a new subscriber.

        Args:
            connection_id: Unique identifier for this WebSocket connection.
            tenant_id: If set, this subscriber only receives alerts for that tenant.

        Returns:
            A per-subscriber asyncio.Queue to drain from.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_max)
        with self._lock:
            self._queues[connection_id] = q
            self._tenants[connection_id] = tenant_id
        logger.debug("AlertBroadcaster.subscribe", connection_id=connection_id, tenant_id=tenant_id)
        return q

    def unsubscribe(self, connection_id: str) -> None:
        """Remove a subscriber.

        Args:
            connection_id: ID returned from subscribe().
        """
        with self._lock:
            self._queues.pop(connection_id, None)
            self._tenants.pop(connection_id, None)
        logger.debug("AlertBroadcaster.unsubscribe", connection_id=connection_id)

    @property
    def subscriber_count(self) -> int:
        """Number of active subscribers."""
        with self._lock:
            return len(self._queues)

    # ------------------------------------------------------------------
    # Broadcast
    # ------------------------------------------------------------------

    async def broadcast(self, alert: Dict[str, Any]) -> int:
        """Push alert to ALL active subscribers.

        If a subscriber queue is full, the oldest item is dropped so the
        new alert can be appended (best-effort delivery).

        Args:
            alert: Alert dict (use build_alert() to construct one).

        Returns:
            Number of subscribers the alert was pushed to.
        """
        with self._lock:
            snapshot = list(self._queues.items())

        delivered = 0
        for connection_id, q in snapshot:
            self._enqueue(q, alert)
            delivered += 1

        if snapshot:
            logger.debug(
                "AlertBroadcaster.broadcast",
                alert_type=alert.get("type"),
                severity=alert.get("severity"),
                delivered=delivered,
            )
        return delivered

    async def broadcast_to_tenant(self, tenant_id: str, alert: Dict[str, Any]) -> int:
        """Push alert only to subscribers registered for the given tenant_id.

        Subscribers registered without a tenant_id (None) also receive the
        alert (they receive all events by default).

        Args:
            tenant_id: Target tenant identifier.
            alert: Alert dict.

        Returns:
            Number of subscribers the alert was pushed to.
        """
        with self._lock:
            snapshot = [
                (cid, q)
                for cid, q in self._queues.items()
                if self._tenants.get(cid) in (None, tenant_id)
            ]

        delivered = 0
        for connection_id, q in snapshot:
            self._enqueue(q, alert)
            delivered += 1

        logger.debug(
            "AlertBroadcaster.broadcast_to_tenant",
            tenant_id=tenant_id,
            alert_type=alert.get("type"),
            delivered=delivered,
        )
        return delivered

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _enqueue(q: asyncio.Queue, alert: Dict[str, Any]) -> None:
        """Put alert into queue, evicting oldest if full."""
        if q.full():
            try:
                q.get_nowait()  # drop oldest
            except asyncio.QueueEmpty:
                pass
        try:
            q.put_nowait(alert)
        except asyncio.QueueFull:
            pass  # race condition — skip silently


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_broadcaster_instance: Optional[AlertBroadcaster] = None
_broadcaster_lock = threading.Lock()


def get_alert_broadcaster() -> AlertBroadcaster:
    """Return the process-wide AlertBroadcaster singleton."""
    global _broadcaster_instance
    if _broadcaster_instance is None:
        with _broadcaster_lock:
            if _broadcaster_instance is None:
                _broadcaster_instance = AlertBroadcaster()
    return _broadcaster_instance
