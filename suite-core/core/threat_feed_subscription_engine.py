"""Threat Feed Subscription Engine — ALDECI.

Manages subscriptions to threat intelligence feeds, tracks ingestion,
filters by relevance, and delivers IOCs to downstream consumers.

Capabilities:
  - Feed subscription lifecycle (active/paused/error/disabled)
  - API key storage as SHA-256 hash (never plaintext)
  - Ingestion log with ioc_count / error_count tracking
  - Delivery channel management (webhook/email/siem/soar/api-push/file-export)
  - Due-subscription detection based on refresh_interval_minutes
  - Per-org ingestion stats aggregation

Compliance: MITRE ATT&CK, STIX 2.1, TLP, NIST SP 800-150
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_FEED_TYPES = {"commercial", "osint", "isac", "government", "community", "internal", "vendor"}
_VALID_DELIVERY_TYPES = {"webhook", "email", "siem", "soar", "api-push", "file-export"}
_VALID_FILTER_SEVERITY = {"critical", "high", "medium", "low", "all"}
_VALID_STATUSES = {"active", "paused", "error", "disabled"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ThreatFeedSubscriptionEngine:
    """SQLite WAL-backed Threat Feed Subscription engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path:
            self._db_dir = Path(db_path).parent
            self._single_path: Optional[str] = db_path
        else:
            self._db_dir = _DEFAULT_DB_DIR
            self._single_path = None
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._locks: Dict[str, threading.RLock] = {}
        self._lock_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_lock(self, org_id: str) -> threading.RLock:
        with self._lock_lock:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _db_path(self, org_id: str) -> str:
        if self._single_path:
            return self._single_path
        return str(self._db_dir / f"{org_id}_threat_feed_subscription.db")

    @contextlib.contextmanager
    def _conn(self, org_id: str):
        conn = sqlite3.connect(self._db_path(org_id), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self, org_id: str) -> None:
        with self._conn(org_id) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS feed_subscriptions (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    feed_name               TEXT NOT NULL,
                    feed_type               TEXT NOT NULL DEFAULT 'osint',
                    feed_url                TEXT NOT NULL DEFAULT '',
                    api_key_hash            TEXT NOT NULL DEFAULT '',
                    status                  TEXT NOT NULL DEFAULT 'active',
                    refresh_interval_minutes INTEGER NOT NULL DEFAULT 60,
                    last_fetched            TEXT,
                    ioc_count               INTEGER NOT NULL DEFAULT 0,
                    error_count             INTEGER NOT NULL DEFAULT 0,
                    offline_mode            INTEGER NOT NULL DEFAULT 0,
                    offline_bundle_source   TEXT NOT NULL DEFAULT '',
                    created_at              TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_fs_org ON feed_subscriptions (org_id, status);

                CREATE TABLE IF NOT EXISTS feed_deliveries (
                    id                TEXT PRIMARY KEY,
                    subscription_id   TEXT NOT NULL,
                    org_id            TEXT NOT NULL,
                    delivery_type     TEXT NOT NULL DEFAULT 'webhook',
                    endpoint          TEXT NOT NULL DEFAULT '',
                    filter_severity   TEXT NOT NULL DEFAULT 'all',
                    filter_categories TEXT NOT NULL DEFAULT '',
                    enabled           INTEGER NOT NULL DEFAULT 1,
                    delivery_count    INTEGER NOT NULL DEFAULT 0,
                    last_delivered    TEXT,
                    created_at        TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_fd_sub ON feed_deliveries (subscription_id, org_id);

                CREATE TABLE IF NOT EXISTS feed_ingestion_log (
                    id              TEXT PRIMARY KEY,
                    subscription_id TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    fetched_at      TEXT NOT NULL,
                    iocs_fetched    INTEGER NOT NULL DEFAULT 0,
                    iocs_new        INTEGER NOT NULL DEFAULT 0,
                    iocs_updated    INTEGER NOT NULL DEFAULT 0,
                    status          TEXT NOT NULL DEFAULT 'success',
                    error_message   TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_fil_sub ON feed_ingestion_log (subscription_id, org_id);
            """)

    def _ensure_db(self, org_id: str) -> None:
        self._init_db(org_id)
        # Back-compat: ALTER TABLE for existing DBs missing offline_mode columns.
        with self._conn(org_id) as conn:
            cols = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(feed_subscriptions)").fetchall()
            }
            if "offline_mode" not in cols:
                try:
                    conn.execute(
                        "ALTER TABLE feed_subscriptions ADD COLUMN offline_mode INTEGER NOT NULL DEFAULT 0"
                    )
                except sqlite3.OperationalError:
                    pass
            if "offline_bundle_source" not in cols:
                try:
                    conn.execute(
                        "ALTER TABLE feed_subscriptions ADD COLUMN offline_bundle_source TEXT NOT NULL DEFAULT ''"
                    )
                except sqlite3.OperationalError:
                    pass

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------

    def create_subscription(
        self,
        org_id: str,
        feed_name: str,
        feed_type: str,
        feed_url: str,
        api_key: str,
        refresh_interval_minutes: int = 60,
    ) -> Dict[str, Any]:
        """Create a new feed subscription. api_key is stored as SHA-256 hash."""
        self._ensure_db(org_id)
        if feed_type not in _VALID_FEED_TYPES:
            raise ValueError(f"Invalid feed_type '{feed_type}'. Must be one of {_VALID_FEED_TYPES}")
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "feed_name": feed_name,
            "feed_type": feed_type,
            "feed_url": feed_url,
            "api_key_hash": _sha256(api_key) if api_key else "",
            "status": "active",
            "refresh_interval_minutes": max(1, int(refresh_interval_minutes)),
            "last_fetched": None,
            "ioc_count": 0,
            "error_count": 0,
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO feed_subscriptions
                       (id, org_id, feed_name, feed_type, feed_url, api_key_hash,
                        status, refresh_interval_minutes, last_fetched, ioc_count, error_count, created_at)
                       VALUES (:id, :org_id, :feed_name, :feed_type, :feed_url, :api_key_hash,
                               :status, :refresh_interval_minutes, :last_fetched, :ioc_count, :error_count, :created_at)""",
                    record,
                )
        return record

    def update_subscription_status(
        self, subscription_id: str, org_id: str, status: str
    ) -> Dict[str, Any]:
        """Update subscription status."""
        self._ensure_db(org_id)
        if status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Must be one of {_VALID_STATUSES}")
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                cursor = conn.execute(
                    "UPDATE feed_subscriptions SET status = ? WHERE id = ? AND org_id = ?",
                    (status, subscription_id, org_id),
                )
                if cursor.rowcount == 0:
                    raise ValueError(f"Subscription '{subscription_id}' not found.")
                row = conn.execute(
                    "SELECT * FROM feed_subscriptions WHERE id = ? AND org_id = ?",
                    (subscription_id, org_id),
                ).fetchone()
        return self._row(row)

    def record_ingestion(
        self,
        subscription_id: str,
        org_id: str,
        iocs_fetched: int,
        iocs_new: int,
        iocs_updated: int,
        status: str,
        error_message: str = "",
    ) -> Dict[str, Any]:
        """Log an ingestion run and update subscription counters."""
        self._ensure_db(org_id)
        now = _now()
        log_id = str(uuid.uuid4())
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO feed_ingestion_log
                       (id, subscription_id, org_id, fetched_at, iocs_fetched, iocs_new, iocs_updated, status, error_message)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (log_id, subscription_id, org_id, now, iocs_fetched, iocs_new, iocs_updated, status, error_message),
                )
                # Update subscription last_fetched always
                if status == "success":
                    conn.execute(
                        """UPDATE feed_subscriptions
                           SET last_fetched = ?, ioc_count = ioc_count + ?
                           WHERE id = ? AND org_id = ?""",
                        (now, iocs_new, subscription_id, org_id),
                    )
                else:
                    conn.execute(
                        """UPDATE feed_subscriptions
                           SET last_fetched = ?, error_count = error_count + 1
                           WHERE id = ? AND org_id = ?""",
                        (now, subscription_id, org_id),
                    )
                row = conn.execute(
                    "SELECT * FROM feed_ingestion_log WHERE id = ?", (log_id,)
                ).fetchone()
        return self._row(row)

    def create_delivery(
        self,
        subscription_id: str,
        org_id: str,
        delivery_type: str,
        endpoint: str,
        filter_severity: str = "all",
        filter_categories: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a delivery channel for a subscription."""
        self._ensure_db(org_id)
        if delivery_type not in _VALID_DELIVERY_TYPES:
            raise ValueError(f"Invalid delivery_type '{delivery_type}'. Must be one of {_VALID_DELIVERY_TYPES}")
        if filter_severity not in _VALID_FILTER_SEVERITY:
            raise ValueError(f"Invalid filter_severity '{filter_severity}'. Must be one of {_VALID_FILTER_SEVERITY}")
        cats_str = ",".join(filter_categories) if filter_categories else ""
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "subscription_id": subscription_id,
            "org_id": org_id,
            "delivery_type": delivery_type,
            "endpoint": endpoint,
            "filter_severity": filter_severity,
            "filter_categories": cats_str,
            "enabled": 1,
            "delivery_count": 0,
            "last_delivered": None,
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO feed_deliveries
                       (id, subscription_id, org_id, delivery_type, endpoint, filter_severity,
                        filter_categories, enabled, delivery_count, last_delivered, created_at)
                       VALUES (:id, :subscription_id, :org_id, :delivery_type, :endpoint, :filter_severity,
                               :filter_categories, :enabled, :delivery_count, :last_delivered, :created_at)""",
                    record,
                )
        record["enabled"] = True
        return record

    def record_delivery(self, delivery_id: str, org_id: str, count: int) -> Dict[str, Any]:
        """Increment delivery_count and update last_delivered timestamp."""
        self._ensure_db(org_id)
        now = _now()
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                cursor = conn.execute(
                    """UPDATE feed_deliveries
                       SET delivery_count = delivery_count + ?, last_delivered = ?
                       WHERE id = ? AND org_id = ?""",
                    (count, now, delivery_id, org_id),
                )
                if cursor.rowcount == 0:
                    raise ValueError(f"Delivery '{delivery_id}' not found.")
                row = conn.execute(
                    "SELECT * FROM feed_deliveries WHERE id = ?", (delivery_id,)
                ).fetchone()
        return self._row(row)

    def get_subscription(self, subscription_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Get a subscription with the last 10 ingestion log entries."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM feed_subscriptions WHERE id = ? AND org_id = ?",
                (subscription_id, org_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            logs = conn.execute(
                """SELECT * FROM feed_ingestion_log
                   WHERE subscription_id = ? AND org_id = ?
                   ORDER BY fetched_at DESC LIMIT 10""",
                (subscription_id, org_id),
            ).fetchall()
            result["recent_ingestion_logs"] = [self._row(r) for r in logs]
        return result

    def list_subscriptions(
        self,
        org_id: str,
        status: Optional[str] = None,
        feed_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List subscriptions with optional status/feed_type filters."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM feed_subscriptions WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if feed_type:
            sql += " AND feed_type = ?"
            params.append(feed_type)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_due_subscriptions(self, org_id: str) -> List[Dict[str, Any]]:
        """Return active subscriptions that are due for a fetch.

        Due = last_fetched IS NULL  OR  (now - last_fetched) > refresh_interval_minutes.
        """
        self._ensure_db(org_id)
        now_dt = datetime.now(timezone.utc)
        now_dt.isoformat()
        with self._conn(org_id) as conn:
            rows = conn.execute(
                "SELECT * FROM feed_subscriptions WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchall()

        due = []
        for row in rows:
            sub = self._row(row)
            last = sub.get("last_fetched")
            if last is None:
                due.append(sub)
            else:
                try:
                    last_dt = datetime.fromisoformat(last)
                    # Make aware if naive
                    if last_dt.tzinfo is None:
                        last_dt = last_dt.replace(tzinfo=timezone.utc)
                    interval = timedelta(minutes=sub["refresh_interval_minutes"])
                    if now_dt - last_dt > interval:
                        due.append(sub)
                except (ValueError, TypeError):
                    due.append(sub)
        return due

    # ------------------------------------------------------------------
    # Offline mode (GAP-002 — air-gapped bundle ingestion)
    # ------------------------------------------------------------------

    def enable_offline_mode(
        self,
        org_id: str,
        bundle_source_path: str,
        subscription_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Flip a subscription (or all active subs for the org) to offline mode.

        When offline_mode=1, the subscription is fed from a local air-gapped
        bundle directory instead of an HTTP feed. Returns updated rows.
        """
        self._ensure_db(org_id)
        if not bundle_source_path or not str(bundle_source_path).strip():
            raise ValueError("bundle_source_path is required")
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                if subscription_id:
                    cursor = conn.execute(
                        """UPDATE feed_subscriptions
                              SET offline_mode = 1, offline_bundle_source = ?
                            WHERE id = ? AND org_id = ?""",
                        (bundle_source_path, subscription_id, org_id),
                    )
                    if cursor.rowcount == 0:
                        raise ValueError(f"Subscription '{subscription_id}' not found.")
                else:
                    conn.execute(
                        """UPDATE feed_subscriptions
                              SET offline_mode = 1, offline_bundle_source = ?
                            WHERE org_id = ?""",
                        (bundle_source_path, org_id),
                    )
                rows = conn.execute(
                    "SELECT * FROM feed_subscriptions WHERE org_id = ? AND offline_mode = 1",
                    (org_id,),
                ).fetchall()
        return {
            "org_id": org_id,
            "bundle_source_path": bundle_source_path,
            "updated": [self._row(r) for r in rows],
            "count": len(rows),
        }

    def disable_offline_mode(
        self,
        org_id: str,
        subscription_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return a subscription (or all offline subs) to online mode."""
        self._ensure_db(org_id)
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                if subscription_id:
                    cursor = conn.execute(
                        """UPDATE feed_subscriptions
                              SET offline_mode = 0, offline_bundle_source = ''
                            WHERE id = ? AND org_id = ?""",
                        (subscription_id, org_id),
                    )
                    if cursor.rowcount == 0:
                        raise ValueError(f"Subscription '{subscription_id}' not found.")
                else:
                    conn.execute(
                        """UPDATE feed_subscriptions
                              SET offline_mode = 0, offline_bundle_source = ''
                            WHERE org_id = ?""",
                        (org_id,),
                    )
                rows = conn.execute(
                    "SELECT * FROM feed_subscriptions WHERE org_id = ?",
                    (org_id,),
                ).fetchall()
        return {
            "org_id": org_id,
            "remaining_offline": sum(1 for r in rows if r["offline_mode"] == 1),
            "count": len(rows),
        }

    def list_offline_subscriptions(self, org_id: str) -> List[Dict[str, Any]]:
        """Return subscriptions currently configured for offline ingestion."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            rows = conn.execute(
                "SELECT * FROM feed_subscriptions WHERE org_id = ? AND offline_mode = 1 ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_ingestion_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate ingestion statistics for an org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            total_iocs = conn.execute(
                "SELECT COALESCE(SUM(ioc_count), 0) FROM feed_subscriptions WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            total_subs = conn.execute(
                "SELECT COUNT(*) FROM feed_subscriptions WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            success_count = conn.execute(
                "SELECT COUNT(*) FROM feed_ingestion_log WHERE org_id = ? AND status = 'success'",
                (org_id,),
            ).fetchone()[0]
            error_count = conn.execute(
                "SELECT COUNT(*) FROM feed_ingestion_log WHERE org_id = ? AND status = 'error'",
                (org_id,),
            ).fetchone()[0]
            high_error_feeds = conn.execute(
                "SELECT * FROM feed_subscriptions WHERE org_id = ? AND error_count > 5",
                (org_id,),
            ).fetchall()
            total_deliveries = conn.execute(
                "SELECT COALESCE(SUM(delivery_count), 0) FROM feed_deliveries WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
        return {
            "org_id": org_id,
            "total_subscriptions": total_subs,
            "total_iocs": total_iocs,
            "ingestion_success_count": success_count,
            "ingestion_error_count": error_count,
            "high_error_feeds": [self._row(r) for r in high_error_feeds],
            "total_deliveries": total_deliveries,
        }
