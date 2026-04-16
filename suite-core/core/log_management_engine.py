"""Log Management Engine — ALDECI.

Centralised log ingestion, querying, and retention policy management.

Features:
- Log source registration with type and format metadata
- Log entry storage with level-based filtering and full-text search
- Retention policy CRUD with apply() to delete expired logs
- Stats: total entries, by_log_type, by_level breakdown

Compliance: NIST CSF PR.PT-1, ISO/IEC 27001 A.12.4, SOC 2 CC7.2,
            GDPR Article 30 (records of processing activities)
"""

from __future__ import annotations

import json
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "log_management.db"
)

_VALID_LOG_TYPES = {"application", "system", "security", "network", "database", "audit"}
_VALID_FORMATS = {"json", "syslog", "csv", "plain"}
_VALID_LEVELS = {"debug", "info", "warn", "error", "fatal"}
_VALID_ACTIONS = {"archive", "delete"}


class LogManagementEngine:
    """SQLite WAL-backed Log Management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS log_sources (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL,
                    log_type       TEXT NOT NULL,
                    format         TEXT NOT NULL DEFAULT 'json',
                    retention_days INTEGER NOT NULL DEFAULT 90,
                    status         TEXT NOT NULL DEFAULT 'active',
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_log_sources_org
                    ON log_sources (org_id);

                CREATE TABLE IF NOT EXISTS log_entries (
                    id         TEXT PRIMARY KEY,
                    org_id     TEXT NOT NULL,
                    source_id  TEXT NOT NULL,
                    level      TEXT NOT NULL,
                    message    TEXT NOT NULL,
                    metadata   TEXT,
                    timestamp  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_log_entries_org
                    ON log_entries (org_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_log_entries_src
                    ON log_entries (org_id, source_id);
                CREATE INDEX IF NOT EXISTS idx_log_entries_level
                    ON log_entries (org_id, level);

                CREATE TABLE IF NOT EXISTS log_retention_policies (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL,
                    log_type       TEXT NOT NULL,
                    retention_days INTEGER NOT NULL,
                    action         TEXT NOT NULL DEFAULT 'archive',
                    status         TEXT NOT NULL DEFAULT 'active',
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_log_ret_policies_org
                    ON log_retention_policies (org_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Log Sources
    # ------------------------------------------------------------------

    def create_log_source(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new log source. Validates name and log_type."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")
        log_type = data.get("log_type", "")
        if log_type not in _VALID_LOG_TYPES:
            raise ValueError(
                f"log_type must be one of {sorted(_VALID_LOG_TYPES)}, got '{log_type}'"
            )
        fmt = data.get("format", "json")
        if fmt not in _VALID_FORMATS:
            fmt = "json"
        retention_days = int(data.get("retention_days", 90))

        source_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO log_sources
                   (id, org_id, name, log_type, format, retention_days, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (source_id, org_id, name, log_type, fmt, retention_days, "active", now),
            )
        _logger.info("log.source_created org=%s id=%s type=%s", org_id, source_id, log_type)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "log_management", "org_id": org_id, "source_engine": "log_management"})
            except Exception:
                pass

        return self._get_source(org_id, source_id)

    def list_log_sources(
        self, org_id: str, log_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List log sources for org, optionally filtered by log_type."""
        query = "SELECT * FROM log_sources WHERE org_id=?"
        params: List[Any] = [org_id]
        if log_type:
            query += " AND log_type=?"
            params.append(log_type)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def _get_source(self, org_id: str, source_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM log_sources WHERE org_id=? AND id=?",
                (org_id, source_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Log source {source_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # Log Entries
    # ------------------------------------------------------------------

    def store_log_entry(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Store a log entry. source_id, level, and message are required."""
        source_id = data.get("source_id", "")
        level = data.get("level", "info")
        if level not in _VALID_LEVELS:
            raise ValueError(f"level must be one of {sorted(_VALID_LEVELS)}, got '{level}'")
        message = data.get("message", "")

        metadata = data.get("metadata")
        metadata_str = json.dumps(metadata) if metadata is not None else None

        entry_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO log_entries
                   (id, org_id, source_id, level, message, metadata, timestamp)
                   VALUES (?,?,?,?,?,?,?)""",
                (entry_id, org_id, source_id, level, message, metadata_str, now),
            )
        _logger.info("log.entry_stored org=%s id=%s level=%s", org_id, entry_id, level)
        return {
            "id": entry_id,
            "org_id": org_id,
            "source_id": source_id,
            "level": level,
            "message": message,
            "metadata": metadata,
            "timestamp": now,
        }

    def query_logs(
        self,
        org_id: str,
        source_id: Optional[str] = None,
        level: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Query log entries with optional filters. Uses LIKE for search on message."""
        query = "SELECT * FROM log_entries WHERE org_id=?"
        params: List[Any] = [org_id]
        if source_id:
            query += " AND source_id=?"
            params.append(source_id)
        if level:
            query += " AND level=?"
            params.append(level)
        if search:
            query += " AND message LIKE ?"
            params.append(f"%{search}%")
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(max(1, int(limit)))

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            row = dict(r)
            if isinstance(row.get("metadata"), str):
                try:
                    row["metadata"] = json.loads(row["metadata"])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(row)
        return results

    # ------------------------------------------------------------------
    # Retention Policies
    # ------------------------------------------------------------------

    def create_retention_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a log retention policy. retention_days is clamped to 1-3650."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")
        log_type = data.get("log_type", "")
        if log_type not in _VALID_LOG_TYPES:
            raise ValueError(
                f"log_type must be one of {sorted(_VALID_LOG_TYPES)}, got '{log_type}'"
            )
        retention_days = max(1, min(3650, int(data.get("retention_days", 90))))
        action = data.get("action", "archive")
        if action not in _VALID_ACTIONS:
            action = "archive"

        policy_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO log_retention_policies
                   (id, org_id, name, log_type, retention_days, action, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (policy_id, org_id, name, log_type, retention_days, action, "active", now),
            )
        _logger.info("log.policy_created org=%s id=%s name=%s", org_id, policy_id, name)
        return self._get_policy(org_id, policy_id)

    def list_retention_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List all retention policies for org_id."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM log_retention_policies WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def apply_retention_policy(self, org_id: str, policy_id: str) -> Dict[str, Any]:
        """Apply retention policy: delete log entries older than retention_days for matching log_type.

        Returns {"deleted": N, "policy_id": policy_id}.
        """
        policy = self._get_policy(org_id, policy_id)
        log_type = policy["log_type"]
        retention_days = policy["retention_days"]

        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=retention_days)
        ).isoformat()

        # Find source IDs for this log_type under org
        with self._connect() as conn:
            source_rows = conn.execute(
                "SELECT id FROM log_sources WHERE org_id=? AND log_type=?",
                (org_id, log_type),
            ).fetchall()

        source_ids = [r["id"] for r in source_rows]
        if not source_ids:
            return {"deleted": 0, "policy_id": policy_id}

        placeholders = ",".join("?" * len(source_ids))
        with self._lock, self._connect() as conn:
            result = conn.execute(
                f"""DELETE FROM log_entriesWHERE org_id=? AND source_id IN ({placeholders}) AND timestamp < ?""",  # nosec B608
                [org_id, *source_ids, cutoff],
            )
            deleted = result.rowcount

        _logger.info(
            "log.policy_applied org=%s policy_id=%s deleted=%d log_type=%s",
            org_id, policy_id, deleted, log_type,
        )
        return {"deleted": deleted, "policy_id": policy_id}

    def _get_policy(self, org_id: str, policy_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM log_retention_policies WHERE org_id=? AND id=?",
                (org_id, policy_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Retention policy {policy_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_log_stats(self, org_id: str) -> Dict[str, Any]:
        """Return log management stats for org_id."""
        with self._connect() as conn:
            total_sources = conn.execute(
                "SELECT COUNT(*) FROM log_sources WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT log_type, COUNT(*) as cnt FROM log_sources WHERE org_id=? GROUP BY log_type",
                (org_id,),
            ).fetchall()
            by_log_type = {r["log_type"]: r["cnt"] for r in type_rows}

            total_entries = conn.execute(
                "SELECT COUNT(*) FROM log_entries WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            level_rows = conn.execute(
                "SELECT level, COUNT(*) as cnt FROM log_entries WHERE org_id=? GROUP BY level",
                (org_id,),
            ).fetchall()
            entries_by_level = {r["level"]: r["cnt"] for r in level_rows}

            retention_policies_count = conn.execute(
                "SELECT COUNT(*) FROM log_retention_policies WHERE org_id=?", (org_id,)
            ).fetchone()[0]

        return {
            "total_sources": total_sources,
            "by_log_type": by_log_type,
            "total_entries": total_entries,
            "entries_by_level": entries_by_level,
            "retention_policies_count": retention_policies_count,
        }
