"""SIEM Output Delivery Engine — ALDECI.

SQLite WAL-backed engine for tracking SIEM output connector
configurations, delivery attempts, and statistics.

Thread-safe via RLock. Multi-tenant via org_id.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "siem_output.db"
)

_VALID_SIEM_TYPES = {"splunk_hec", "sentinel", "generic", "chronicle", "datadog"}
_VALID_STATUSES = {"active", "inactive", "error"}


class SIEMOutputEngine:
    """SQLite WAL-backed SIEM output delivery tracking engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tracks configured SIEM targets and delivery statistics.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS siem_targets (
                    target_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL DEFAULT '',
                    siem_type       TEXT NOT NULL DEFAULT 'generic',
                    config_json     TEXT NOT NULL DEFAULT '{}',
                    status          TEXT NOT NULL DEFAULT 'active',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_siem_targets_org
                    ON siem_targets (org_id, status);

                CREATE TABLE IF NOT EXISTS siem_deliveries (
                    delivery_id     TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    target_id       TEXT NOT NULL,
                    batch_size      INTEGER NOT NULL DEFAULT 0,
                    events_sent     INTEGER NOT NULL DEFAULT 0,
                    events_failed   INTEGER NOT NULL DEFAULT 0,
                    success         INTEGER NOT NULL DEFAULT 0,
                    status_code     INTEGER NOT NULL DEFAULT 0,
                    error           TEXT NOT NULL DEFAULT '',
                    duration_ms     REAL NOT NULL DEFAULT 0.0,
                    retries_used    INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_siem_deliveries_org
                    ON siem_deliveries (org_id, target_id, created_at);

                CREATE TABLE IF NOT EXISTS siem_delivery_stats (
                    stat_id         TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    target_id       TEXT NOT NULL,
                    total_sent      INTEGER NOT NULL DEFAULT 0,
                    total_failed    INTEGER NOT NULL DEFAULT 0,
                    total_batches   INTEGER NOT NULL DEFAULT 0,
                    total_retries   INTEGER NOT NULL DEFAULT 0,
                    last_success_at TEXT NOT NULL DEFAULT '',
                    last_error_at   TEXT NOT NULL DEFAULT '',
                    last_error      TEXT NOT NULL DEFAULT '',
                    updated_at      TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_siem_stats_org_target
                    ON siem_delivery_stats (org_id, target_id);
                """
            )

    # ------------------------------------------------------------------
    # Targets CRUD
    # ------------------------------------------------------------------

    def configure_target(
        self,
        org_id: str,
        name: str,
        siem_type: str,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create or update a SIEM output target configuration."""
        siem_type = siem_type.lower()
        if siem_type not in _VALID_SIEM_TYPES:
            raise ValueError(f"Invalid siem_type: {siem_type}. Must be one of {_VALID_SIEM_TYPES}")

        now = datetime.now(timezone.utc).isoformat()
        target_id = f"siem-out-{uuid.uuid4().hex[:8]}"

        # Hash any sensitive fields (token, client_secret)
        safe_config = dict(config)
        for key in ("token", "client_secret", "api_key"):
            if key in safe_config and safe_config[key]:
                safe_config[f"{key}_hash"] = hashlib.sha256(
                    safe_config[key].encode()
                ).hexdigest()

        config_json = json.dumps(safe_config, default=str)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO siem_targets
                       (target_id, org_id, name, siem_type, config_json, status, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, 'active', ?, ?)""",
                    (target_id, org_id, name, siem_type, config_json, now, now),
                )
                # Initialise stats row
                stat_id = f"stat-{uuid.uuid4().hex[:8]}"
                conn.execute(
                    """INSERT OR IGNORE INTO siem_delivery_stats
                       (stat_id, org_id, target_id, updated_at)
                       VALUES (?, ?, ?, ?)""",
                    (stat_id, org_id, target_id, now),
                )

        self._emit_event("SIEM_TARGET_CONFIGURED", org_id, {
            "target_id": target_id,
            "siem_type": siem_type,
            "name": name,
        })

        return {
            "target_id": target_id,
            "org_id": org_id,
            "name": name,
            "siem_type": siem_type,
            "status": "active",
            "created_at": now,
        }

    def get_targets(self, org_id: str) -> List[Dict[str, Any]]:
        """List all configured SIEM targets for an org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT target_id, org_id, name, siem_type, config_json,
                              status, created_at, updated_at
                       FROM siem_targets WHERE org_id = ?
                       ORDER BY created_at DESC""",
                    (org_id,),
                ).fetchall()

        results = []
        for r in rows:
            cfg = json.loads(r["config_json"]) if r["config_json"] else {}
            # Strip raw secrets from returned config
            for key in ("token", "client_secret", "api_key"):
                cfg.pop(key, None)
            results.append({
                "target_id": r["target_id"],
                "org_id": r["org_id"],
                "name": r["name"],
                "siem_type": r["siem_type"],
                "config": cfg,
                "status": r["status"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })
        return results

    def get_target(self, org_id: str, target_id: str) -> Optional[Dict[str, Any]]:
        """Get a single SIEM target by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    """SELECT target_id, org_id, name, siem_type, config_json,
                              status, created_at, updated_at
                       FROM siem_targets WHERE org_id = ? AND target_id = ?""",
                    (org_id, target_id),
                ).fetchone()

        if not row:
            return None

        cfg = json.loads(row["config_json"]) if row["config_json"] else {}
        for key in ("token", "client_secret", "api_key"):
            cfg.pop(key, None)

        return {
            "target_id": row["target_id"],
            "org_id": row["org_id"],
            "name": row["name"],
            "siem_type": row["siem_type"],
            "config": cfg,
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def update_target_status(
        self, org_id: str, target_id: str, status: str
    ) -> Optional[Dict[str, Any]]:
        """Update a target's status (active/inactive/error)."""
        status = status.lower()
        if status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_STATUSES}")

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE siem_targets SET status = ?, updated_at = ?
                       WHERE org_id = ? AND target_id = ?""",
                    (status, now, org_id, target_id),
                )
                if cur.rowcount == 0:
                    return None

        return self.get_target(org_id, target_id)

    def delete_target(self, org_id: str, target_id: str) -> bool:
        """Delete a SIEM target."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "DELETE FROM siem_targets WHERE org_id = ? AND target_id = ?",
                    (org_id, target_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Delivery tracking
    # ------------------------------------------------------------------

    def record_delivery(
        self,
        org_id: str,
        target_id: str,
        batch_size: int,
        events_sent: int,
        events_failed: int,
        success: bool,
        status_code: int = 0,
        error: str = "",
        duration_ms: float = 0.0,
        retries_used: int = 0,
    ) -> Dict[str, Any]:
        """Record a delivery attempt and update running statistics."""
        now = datetime.now(timezone.utc).isoformat()
        delivery_id = f"del-{uuid.uuid4().hex[:8]}"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO siem_deliveries
                       (delivery_id, org_id, target_id, batch_size, events_sent,
                        events_failed, success, status_code, error, duration_ms,
                        retries_used, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        delivery_id, org_id, target_id, batch_size,
                        events_sent, events_failed, 1 if success else 0,
                        status_code, error, duration_ms, retries_used, now,
                    ),
                )

                # Update running stats
                if success:
                    conn.execute(
                        """UPDATE siem_delivery_stats
                           SET total_sent = total_sent + ?,
                               total_batches = total_batches + 1,
                               total_retries = total_retries + ?,
                               last_success_at = ?,
                               updated_at = ?
                           WHERE org_id = ? AND target_id = ?""",
                        (events_sent, retries_used, now, now, org_id, target_id),
                    )
                else:
                    conn.execute(
                        """UPDATE siem_delivery_stats
                           SET total_failed = total_failed + ?,
                               total_batches = total_batches + 1,
                               total_retries = total_retries + ?,
                               last_error_at = ?,
                               last_error = ?,
                               updated_at = ?
                           WHERE org_id = ? AND target_id = ?""",
                        (events_failed, retries_used, now, error[:500], now, org_id, target_id),
                    )

        return {
            "delivery_id": delivery_id,
            "target_id": target_id,
            "events_sent": events_sent,
            "events_failed": events_failed,
            "success": success,
            "status_code": status_code,
            "duration_ms": round(duration_ms, 2),
        }

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str, target_id: Optional[str] = None) -> Dict[str, Any]:
        """Get delivery statistics, optionally filtered by target."""
        with self._lock:
            with self._conn() as conn:
                if target_id:
                    row = conn.execute(
                        """SELECT * FROM siem_delivery_stats
                           WHERE org_id = ? AND target_id = ?""",
                        (org_id, target_id),
                    ).fetchone()
                    if not row:
                        return {"targets": [], "totals": {}}
                    stats = [dict(row)]
                else:
                    rows = conn.execute(
                        "SELECT * FROM siem_delivery_stats WHERE org_id = ?",
                        (org_id,),
                    ).fetchall()
                    stats = [dict(r) for r in rows]

                # Compute totals
                total_sent = sum(s.get("total_sent", 0) for s in stats)
                total_failed = sum(s.get("total_failed", 0) for s in stats)
                total_batches = sum(s.get("total_batches", 0) for s in stats)

                # Recent deliveries
                recent_q = (
                    "SELECT * FROM siem_deliveries WHERE org_id = ?"
                )
                params: list = [org_id]
                if target_id:
                    recent_q += " AND target_id = ?"
                    params.append(target_id)
                recent_q += " ORDER BY created_at DESC LIMIT 20"

                recent = [dict(r) for r in conn.execute(recent_q, params).fetchall()]

        success_rate = (
            round(total_sent / (total_sent + total_failed) * 100, 1)
            if (total_sent + total_failed) > 0
            else 0.0
        )

        return {
            "targets": stats,
            "totals": {
                "total_sent": total_sent,
                "total_failed": total_failed,
                "total_batches": total_batches,
                "success_rate_pct": success_rate,
            },
            "recent_deliveries": recent,
        }

    def get_delivery_history(
        self,
        org_id: str,
        target_id: str = "",
        limit: int = 50,
        after_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get delivery history for an org, optionally filtered by target.

        If *after_id* is given, only rows whose ``created_at`` is strictly
        after the row with that delivery_id are returned (SSE cursor support).
        Rows are returned in ascending ``created_at`` order when after_id is
        used so the caller can emit them chronologically.
        """
        with self._lock:
            with self._conn() as conn:
                params: list = [org_id]
                where = "org_id = ?"

                if target_id:
                    where += " AND target_id = ?"
                    params.append(target_id)

                if after_id:
                    # Resolve the created_at timestamp of the cursor row
                    cursor_row = conn.execute(
                        "SELECT created_at FROM siem_deliveries WHERE delivery_id = ?",
                        (after_id,),
                    ).fetchone()
                    if cursor_row:
                        where += " AND created_at > ?"
                        params.append(cursor_row["created_at"])

                order = "ASC" if after_id else "DESC"
                params.append(limit)
                rows = conn.execute(
                    f"SELECT * FROM siem_deliveries WHERE {where} ORDER BY created_at {order} LIMIT ?",
                    params,
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # TrustGraph event bus
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, org_id: str, data: Dict[str, Any]) -> None:
        """Emit to TrustGraph event bus if available."""
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            bus.emit(event_type, {"org_id": org_id, **data})
        except Exception:  # noqa: BLE001
            pass


# ======================================================================
# GAP-035 — Mirror SIEM adapter registry (re-exports from siem_integration_engine)
# ======================================================================

try:
    from core.siem_integration_engine import (  # type: ignore[import]
        SIEM_ADAPTERS as _INTEG_ADAPTERS,
    )
    from core.siem_integration_engine import (
        ChronicleAdapter,  # noqa: F401
        DatadogAdapter,  # noqa: F401
        forward_to_siem,  # noqa: F401
    )

    # Expose the same registry reference so both modules agree.
    SIEM_ADAPTERS: Dict[str, type] = dict(_INTEG_ADAPTERS)
except ImportError:
    SIEM_ADAPTERS = {}
