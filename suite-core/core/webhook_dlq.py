"""Webhook Dead Letter Queue (DLQ) — retry policies and manual replay for failed webhook deliveries.

Provides:
- DeliveryStatus enum: delivery lifecycle states
- RetryPolicy Pydantic model: exponential backoff configuration
- WebhookDelivery Pydantic model: per-delivery record
- WebhookDLQ class: SQLite-backed DLQ with enqueue, retry, replay, analytics

Usage:
    from core.webhook_dlq import WebhookDLQ, RetryPolicy

    dlq = WebhookDLQ()
    delivery = dlq.enqueue("wh-123", "evt-456", {"finding_id": "F-001"}, "https://n8n.example.com/hook", "org-1")
    dlq.record_attempt(delivery.id, success=False, error="Timeout")
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DB_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "..",
        "data",
        "webhook_dlq.db",
    )
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY,
    webhook_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_retry_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    org_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dlq_status ON webhook_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_dlq_org ON webhook_deliveries(org_id);
CREATE INDEX IF NOT EXISTS idx_dlq_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_dlq_next_retry ON webhook_deliveries(next_retry_at);
"""


# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------


class DeliveryStatus(str, Enum):
    """Lifecycle states for a webhook delivery."""

    PENDING = "pending"
    RETRYING = "retrying"
    DELIVERED = "delivered"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


class RetryPolicy(BaseModel):
    """Exponential backoff retry configuration."""

    max_retries: int = Field(default=5, ge=0, le=20)
    initial_delay_seconds: int = Field(default=30, ge=1)
    backoff_multiplier: float = Field(default=2.0, ge=1.0)
    max_delay_seconds: int = Field(default=3600, ge=1)


class WebhookDelivery(BaseModel):
    """A single webhook delivery record tracked in the DLQ."""

    id: str
    webhook_id: str
    event_id: str
    payload: Dict[str, Any]
    url: str
    status: DeliveryStatus = DeliveryStatus.PENDING
    attempts: int = 0
    next_retry_at: Optional[datetime] = None
    last_error: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    org_id: str

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------


def _get_db(db_path: str = _DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def _row_to_delivery(row: sqlite3.Row) -> WebhookDelivery:
    d = dict(row)
    d["payload"] = json.loads(d["payload"]) if d.get("payload") else {}
    return WebhookDelivery(**d)


# ---------------------------------------------------------------------------
# WebhookDLQ
# ---------------------------------------------------------------------------


class WebhookDLQ:
    """SQLite-backed Dead Letter Queue for webhook deliveries.

    Thread-safe. Supports exponential backoff, manual replay, bulk replay,
    and failure analytics.
    """

    def __init__(self, db_path: str = _DB_PATH, policy: Optional[RetryPolicy] = None) -> None:
        self._db_path = db_path
        self._policy = policy or RetryPolicy()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def enqueue(
        self,
        webhook_id: str,
        event_id: str,
        payload: Dict[str, Any],
        url: str,
        org_id: str,
    ) -> WebhookDelivery:
        """Create and persist a new delivery record in PENDING state.

        Returns the newly created WebhookDelivery.
        """
        delivery_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        next_retry_at = self.calculate_next_retry(0, self._policy)
        payload_json = json.dumps(payload, default=str)

        delivery = WebhookDelivery(
            id=delivery_id,
            webhook_id=webhook_id,
            event_id=event_id,
            payload=payload,
            url=url,
            status=DeliveryStatus.PENDING,
            attempts=0,
            next_retry_at=next_retry_at,
            last_error=None,
            created_at=now,
            completed_at=None,
            org_id=org_id,
        )

        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    conn.execute(
                        """INSERT INTO webhook_deliveries
                           (id, webhook_id, event_id, payload, url, status, attempts,
                            next_retry_at, last_error, created_at, completed_at, org_id)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            delivery_id,
                            webhook_id,
                            event_id,
                            payload_json,
                            url,
                            DeliveryStatus.PENDING.value,
                            0,
                            next_retry_at.isoformat() if next_retry_at else None,
                            None,
                            now.isoformat(),
                            None,
                            org_id,
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to enqueue delivery: {exc}") from exc

        logger.info("Enqueued delivery %s for webhook %s event %s", delivery_id, webhook_id, event_id)
        return delivery

    def record_attempt(self, delivery_id: str, success: bool, error: Optional[str] = None) -> None:
        """Record a delivery attempt result.

        Increments attempts counter, updates status:
        - success=True  → DELIVERED, sets completed_at
        - success=False → RETRYING if attempts < max_retries else DEAD_LETTER
        Schedules next_retry_at using exponential backoff when retrying.
        """
        now = datetime.now(timezone.utc)
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    row = conn.execute(
                        "SELECT * FROM webhook_deliveries WHERE id=?", (delivery_id,)
                    ).fetchone()
                    if not row:
                        logger.warning("record_attempt: delivery %s not found", delivery_id)
                        return

                    new_attempts = row["attempts"] + 1

                    if success:
                        conn.execute(
                            """UPDATE webhook_deliveries
                               SET attempts=?, status=?, last_error=NULL,
                                   completed_at=?, next_retry_at=NULL
                               WHERE id=?""",
                            (new_attempts, DeliveryStatus.DELIVERED.value, now.isoformat(), delivery_id),
                        )
                    else:
                        if new_attempts >= self._policy.max_retries:
                            new_status = DeliveryStatus.DEAD_LETTER.value
                            next_retry_at = None
                        else:
                            new_status = DeliveryStatus.RETRYING.value
                            next_retry_at = self.calculate_next_retry(new_attempts, self._policy)

                        conn.execute(
                            """UPDATE webhook_deliveries
                               SET attempts=?, status=?, last_error=?, next_retry_at=?
                               WHERE id=?""",
                            (
                                new_attempts,
                                new_status,
                                error,
                                next_retry_at.isoformat() if next_retry_at else None,
                                delivery_id,
                            ),
                        )

                    conn.commit()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to record attempt for {delivery_id}: {exc}") from exc

        logger.debug(
            "Recorded attempt for delivery %s: success=%s attempts=%d",
            delivery_id,
            success,
            1,
        )

    def get_pending(self, limit: int = 100) -> List[WebhookDelivery]:
        """Return deliveries ready for retry (status PENDING or RETRYING, next_retry_at <= now)."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    rows = conn.execute(
                        """SELECT * FROM webhook_deliveries
                           WHERE status IN (?, ?) AND (next_retry_at IS NULL OR next_retry_at <= ?)
                           ORDER BY next_retry_at ASC
                           LIMIT ?""",
                        (DeliveryStatus.PENDING.value, DeliveryStatus.RETRYING.value, now, limit),
                    ).fetchall()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to get pending deliveries: {exc}") from exc

        return [_row_to_delivery(r) for r in rows]

    def get_dead_letters(self, org_id: str) -> List[WebhookDelivery]:
        """Return all dead-lettered deliveries for an organization."""
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    rows = conn.execute(
                        """SELECT * FROM webhook_deliveries
                           WHERE status=? AND org_id=?
                           ORDER BY created_at DESC""",
                        (DeliveryStatus.DEAD_LETTER.value, org_id),
                    ).fetchall()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to get dead letters for org {org_id}: {exc}") from exc

        return [_row_to_delivery(r) for r in rows]

    def replay(self, delivery_id: str) -> WebhookDelivery:
        """Reset a dead-lettered delivery for manual retry.

        Resets status to PENDING, clears attempts and last_error,
        sets next_retry_at to now.
        """
        now = datetime.now(timezone.utc)
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    row = conn.execute(
                        "SELECT * FROM webhook_deliveries WHERE id=?", (delivery_id,)
                    ).fetchone()
                    if not row:
                        raise ValueError(f"Delivery {delivery_id} not found")

                    conn.execute(
                        """UPDATE webhook_deliveries
                           SET status=?, attempts=0, last_error=NULL,
                               next_retry_at=?, completed_at=NULL
                           WHERE id=?""",
                        (DeliveryStatus.PENDING.value, now.isoformat(), delivery_id),
                    )
                    conn.commit()
                    row = conn.execute(
                        "SELECT * FROM webhook_deliveries WHERE id=?", (delivery_id,)
                    ).fetchone()
                finally:
                    conn.close()
        except (sqlite3.Error, ValueError) as exc:
            raise RuntimeError(f"Failed to replay delivery {delivery_id}: {exc}") from exc

        logger.info("Replayed delivery %s", delivery_id)
        return _row_to_delivery(row)

    def replay_batch(self, delivery_ids: List[str]) -> int:
        """Bulk reset deliveries for manual replay.

        Returns the count of deliveries successfully reset.
        """
        if not delivery_ids:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        placeholders = ",".join("?" * len(delivery_ids))
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    cur = conn.execute(
                        f"""UPDATE webhook_deliveries SET status=?, attempts=0, last_error=NULL,
                                next_retry_at=?, completed_at=NULL
                            WHERE id IN ({placeholders})""",  # nosec B608
                        [DeliveryStatus.PENDING.value, now, *delivery_ids],
                    )
                    conn.commit()
                    count = cur.rowcount
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to replay batch: {exc}") from exc

        logger.info("Replayed batch of %d deliveries", count)
        return count

    def purge_delivered(self, days: int = 30) -> int:
        """Delete DELIVERED records older than `days` days.

        Returns the count of deleted records.
        """
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    cur = conn.execute(
                        "DELETE FROM webhook_deliveries WHERE status=? AND completed_at < ?",
                        (DeliveryStatus.DELIVERED.value, cutoff),
                    )
                    conn.commit()
                    count = cur.rowcount
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to purge delivered: {exc}") from exc

        logger.info("Purged %d delivered deliveries older than %d days", count, days)
        return count

    def purge_dead_letters(self, org_id: str) -> int:
        """Delete all dead-lettered deliveries for an organization.

        Returns the count of deleted records.
        """
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    cur = conn.execute(
                        "DELETE FROM webhook_deliveries WHERE status=? AND org_id=?",
                        (DeliveryStatus.DEAD_LETTER.value, org_id),
                    )
                    conn.commit()
                    count = cur.rowcount
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to purge dead letters for org {org_id}: {exc}") from exc

        logger.info("Purged %d dead letters for org %s", count, org_id)
        return count

    def get_delivery(self, delivery_id: str) -> WebhookDelivery:
        """Fetch a single delivery by ID."""
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    row = conn.execute(
                        "SELECT * FROM webhook_deliveries WHERE id=?", (delivery_id,)
                    ).fetchone()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to get delivery {delivery_id}: {exc}") from exc

        if not row:
            raise ValueError(f"Delivery {delivery_id} not found")
        return _row_to_delivery(row)

    def list_deliveries(
        self,
        org_id: str,
        status_filter: Optional[str] = None,
        webhook_id: Optional[str] = None,
    ) -> List[WebhookDelivery]:
        """List deliveries for an org with optional status and webhook_id filters."""
        query = "SELECT * FROM webhook_deliveries WHERE org_id=?"
        params: List[Any] = [org_id]

        if status_filter:
            query += " AND status=?"
            params.append(status_filter)
        if webhook_id:
            query += " AND webhook_id=?"
            params.append(webhook_id)

        query += " ORDER BY created_at DESC"

        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    rows = conn.execute(query, params).fetchall()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to list deliveries for org {org_id}: {exc}") from exc

        return [_row_to_delivery(r) for r in rows]

    def replay_by_event_id(self, event_id: str, org_id: str) -> int:
        """Reset all deliveries for a given event_id (org-scoped) for manual replay.

        Resets status to PENDING, clears attempts and last_error,
        sets next_retry_at to now for every delivery tied to event_id
        that belongs to org_id.

        Returns the count of deliveries reset.
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    cur = conn.execute(
                        """UPDATE webhook_deliveries
                               SET status=?, attempts=0, last_error=NULL,
                                   next_retry_at=?, completed_at=NULL
                             WHERE event_id=? AND org_id=?""",
                        (DeliveryStatus.PENDING.value, now, event_id, org_id),
                    )
                    conn.commit()
                    count = cur.rowcount
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to replay event {event_id} for org {org_id}: {exc}") from exc

        logger.info("Replayed %d deliveries for event_id=%s org=%s", count, event_id, org_id)
        return count

    # ------------------------------------------------------------------
    # Backoff calculation
    # ------------------------------------------------------------------

    def calculate_next_retry(self, attempts: int, policy: RetryPolicy) -> datetime:
        """Calculate next retry datetime using exponential backoff.

        delay = min(initial_delay * multiplier^attempts, max_delay)
        """
        delay = min(
            policy.initial_delay_seconds * (policy.backoff_multiplier ** attempts),
            policy.max_delay_seconds,
        )
        from datetime import timedelta

        return datetime.now(timezone.utc) + timedelta(seconds=delay)

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_failure_analytics(self, org_id: str) -> Dict[str, Any]:
        """Return failure analytics for an organization.

        Includes:
        - failure_rate_by_webhook: {webhook_id: rate 0-1}
        - top_errors: [{"error": str, "count": int}]
        - avg_retries: float
        - total_deliveries: int
        - total_failed: int
        """
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    # Per-webhook failure counts
                    wh_rows = conn.execute(
                        """SELECT webhook_id,
                                  COUNT(*) as total,
                                  SUM(CASE WHEN status IN (?, ?) THEN 1 ELSE 0 END) as failed
                           FROM webhook_deliveries
                           WHERE org_id=?
                           GROUP BY webhook_id""",
                        (DeliveryStatus.FAILED.value, DeliveryStatus.DEAD_LETTER.value, org_id),
                    ).fetchall()

                    # Top errors
                    err_rows = conn.execute(
                        """SELECT last_error, COUNT(*) as cnt
                           FROM webhook_deliveries
                           WHERE org_id=? AND last_error IS NOT NULL
                           GROUP BY last_error
                           ORDER BY cnt DESC
                           LIMIT 10""",
                        (org_id,),
                    ).fetchall()

                    # Avg retries
                    avg_row = conn.execute(
                        """SELECT AVG(attempts) as avg_attempts, COUNT(*) as total,
                                  SUM(CASE WHEN status IN (?, ?) THEN 1 ELSE 0 END) as total_failed
                           FROM webhook_deliveries
                           WHERE org_id=?""",
                        (DeliveryStatus.FAILED.value, DeliveryStatus.DEAD_LETTER.value, org_id),
                    ).fetchone()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to get failure analytics for org {org_id}: {exc}") from exc

        failure_rate_by_webhook: Dict[str, float] = {}
        for r in wh_rows:
            total = r["total"] or 0
            failed = r["failed"] or 0
            failure_rate_by_webhook[r["webhook_id"]] = round(failed / total, 4) if total > 0 else 0.0

        top_errors = [{"error": r["last_error"], "count": r["cnt"]} for r in err_rows]

        return {
            "failure_rate_by_webhook": failure_rate_by_webhook,
            "top_errors": top_errors,
            "avg_retries": round(avg_row["avg_attempts"] or 0.0, 2),
            "total_deliveries": avg_row["total"] or 0,
            "total_failed": avg_row["total_failed"] or 0,
        }

    def get_dlq_stats(self, org_id: str) -> Dict[str, Any]:
        """Return DLQ status counts for an organization.

        Returns:
        - pending: int
        - retrying: int
        - delivered: int
        - dead: int
        - by_webhook: {webhook_id: {status: count}}
        """
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    status_rows = conn.execute(
                        """SELECT status, COUNT(*) as cnt
                           FROM webhook_deliveries
                           WHERE org_id=?
                           GROUP BY status""",
                        (org_id,),
                    ).fetchall()

                    by_wh_rows = conn.execute(
                        """SELECT webhook_id, status, COUNT(*) as cnt
                           FROM webhook_deliveries
                           WHERE org_id=?
                           GROUP BY webhook_id, status""",
                        (org_id,),
                    ).fetchall()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to get DLQ stats for org {org_id}: {exc}") from exc

        counts: Dict[str, int] = {s.value: 0 for s in DeliveryStatus}
        for r in status_rows:
            counts[r["status"]] = r["cnt"]

        by_webhook: Dict[str, Dict[str, int]] = {}
        for r in by_wh_rows:
            wid = r["webhook_id"]
            if wid not in by_webhook:
                by_webhook[wid] = {}
            by_webhook[wid][r["status"]] = r["cnt"]

        return {
            "pending": counts.get(DeliveryStatus.PENDING.value, 0),
            "retrying": counts.get(DeliveryStatus.RETRYING.value, 0),
            "delivered": counts.get(DeliveryStatus.DELIVERED.value, 0),
            "dead": counts.get(DeliveryStatus.DEAD_LETTER.value, 0),
            "by_webhook": by_webhook,
        }
