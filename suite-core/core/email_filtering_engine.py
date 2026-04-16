"""Email Filtering Engine — Email security filtering and event tracking for ALDECI.

Manages email filter rules (spam/malware/phishing/dmarc/spf/dkim/blacklist/whitelist),
email event logging, and threat statistics.

Capabilities:
  - Filter rule CRUD with type/action/priority/status management
  - Email event logging with threat scoring
  - Stats aggregation: 24h events, by filter result, threat score avg, blocked count

Compliance: DMARC, SPF, DKIM, anti-phishing, anti-spam
"""

from __future__ import annotations

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "email_filtering.db"
)

_VALID_RULE_TYPES = {"spam", "malware", "phishing", "dmarc", "spf", "dkim", "blacklist", "whitelist"}
_VALID_ACTIONS = {"allow", "block", "quarantine", "tag"}
_VALID_FILTER_RESULTS = {"clean", "spam", "malware", "phishing", "quarantined", "blocked"}
_VALID_STATUSES = {"active", "inactive"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EmailFilteringEngine:
    """SQLite WAL-backed email filtering engine.

    Thread-safe via RLock. Multi-tenant via org_id filtering on a shared DB.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS filter_rules (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    rule_type   TEXT NOT NULL,
                    action      TEXT NOT NULL DEFAULT 'quarantine',
                    priority    INTEGER NOT NULL DEFAULT 50,
                    pattern     TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    status      TEXT NOT NULL DEFAULT 'active',
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_filter_rules_org
                    ON filter_rules (org_id, rule_type, status);

                CREATE TABLE IF NOT EXISTS email_events (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    sender          TEXT NOT NULL,
                    recipient       TEXT NOT NULL,
                    subject         TEXT NOT NULL DEFAULT '',
                    filter_result   TEXT NOT NULL,
                    rule_id         TEXT NOT NULL DEFAULT '',
                    threat_score    INTEGER NOT NULL DEFAULT 0,
                    processed_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_email_events_org_time
                    ON email_events (org_id, processed_at);

                CREATE INDEX IF NOT EXISTS idx_email_events_result
                    ON email_events (org_id, filter_result);
                """
            )

    # ------------------------------------------------------------------
    # Filter Rules
    # ------------------------------------------------------------------

    def create_filter_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a filter rule for the given org."""
        name = data.get("name", "")
        if not name:
            raise ValueError("name is required")

        rule_type = data.get("rule_type", "")
        if rule_type not in _VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule_type: {rule_type!r}. Valid: {_VALID_RULE_TYPES}")

        action = data.get("action", "quarantine")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"Invalid action: {action!r}. Valid: {_VALID_ACTIONS}")

        priority = int(data.get("priority", 50))
        priority = max(1, min(100, priority))

        status = data.get("status", "active")
        if status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status: {status!r}. Valid: {_VALID_STATUSES}")

        rule_id = str(uuid.uuid4())
        now = _now_iso()

        row = {
            "id": rule_id,
            "org_id": org_id,
            "name": name,
            "rule_type": rule_type,
            "action": action,
            "priority": priority,
            "pattern": data.get("pattern", ""),
            "description": data.get("description", ""),
            "status": status,
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO filter_rules
                   (id, org_id, name, rule_type, action, priority, pattern,
                    description, status, created_at)
                   VALUES (:id, :org_id, :name, :rule_type, :action, :priority,
                           :pattern, :description, :status, :created_at)""",
                row,
            )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "email_filtering", "org_id": org_id, "source_engine": "email_filtering"})
            except Exception:
                pass

        return self._row_to_rule(row)

    def list_filter_rules(
        self,
        org_id: str,
        rule_type: Optional[str] = None,
        action: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List filter rules for the org, optionally filtered by rule_type and action."""
        query = "SELECT * FROM filter_rules WHERE org_id = ?"
        params: List[Any] = [org_id]
        if rule_type is not None:
            query += " AND rule_type = ?"
            params.append(rule_type)
        if action is not None:
            query += " AND action = ?"
            params.append(action)
        query += " ORDER BY priority, name"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_rule(dict(r)) for r in rows]

    def get_filter_rule(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a single filter rule by ID for the org."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM filter_rules WHERE id = ? AND org_id = ?",
                (rule_id, org_id),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_rule(dict(row))

    def _row_to_rule(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "name": row["name"],
            "rule_type": row["rule_type"],
            "action": row["action"],
            "priority": row["priority"],
            "pattern": row["pattern"],
            "description": row["description"],
            "status": row["status"],
            "created_at": row["created_at"],
        }

    # ------------------------------------------------------------------
    # Email Events
    # ------------------------------------------------------------------

    def log_email_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log an email processing event."""
        sender = data.get("sender", "")
        if not sender:
            raise ValueError("sender is required")

        recipient = data.get("recipient", "")
        if not recipient:
            raise ValueError("recipient is required")

        filter_result = data.get("filter_result", "")
        if filter_result not in _VALID_FILTER_RESULTS:
            raise ValueError(f"Invalid filter_result: {filter_result!r}. Valid: {_VALID_FILTER_RESULTS}")

        threat_score = int(data.get("threat_score", 0))
        threat_score = max(0, min(100, threat_score))

        event_id = str(uuid.uuid4())
        now = _now_iso()

        row = {
            "id": event_id,
            "org_id": org_id,
            "sender": sender,
            "recipient": recipient,
            "subject": data.get("subject", ""),
            "filter_result": filter_result,
            "rule_id": data.get("rule_id", ""),
            "threat_score": threat_score,
            "processed_at": data.get("processed_at", now),
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO email_events
                   (id, org_id, sender, recipient, subject, filter_result,
                    rule_id, threat_score, processed_at)
                   VALUES (:id, :org_id, :sender, :recipient, :subject, :filter_result,
                           :rule_id, :threat_score, :processed_at)""",
                row,
            )
        return self._row_to_event(row)

    def list_email_events(
        self,
        org_id: str,
        filter_result: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List email events for the org, optionally filtered by filter_result."""
        query = "SELECT * FROM email_events WHERE org_id = ?"
        params: List[Any] = [org_id]
        if filter_result is not None:
            query += " AND filter_result = ?"
            params.append(filter_result)
        query += " ORDER BY processed_at DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_event(dict(r)) for r in rows]

    def _row_to_event(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "sender": row["sender"],
            "recipient": row["recipient"],
            "subject": row["subject"],
            "filter_result": row["filter_result"],
            "rule_id": row["rule_id"],
            "threat_score": row["threat_score"],
            "processed_at": row["processed_at"],
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_email_stats(self, org_id: str) -> Dict[str, Any]:
        """Return email filtering statistics for the org."""
        cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        with self._lock, self._conn() as conn:
            total_rules = conn.execute(
                "SELECT COUNT(*) FROM filter_rules WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_rules = conn.execute(
                "SELECT COUNT(*) FROM filter_rules WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            by_rule_type_rows = conn.execute(
                """SELECT rule_type, COUNT(*) AS cnt
                   FROM filter_rules WHERE org_id = ?
                   GROUP BY rule_type""",
                (org_id,),
            ).fetchall()

            total_events_24h = conn.execute(
                "SELECT COUNT(*) FROM email_events WHERE org_id = ? AND processed_at >= ?",
                (org_id, cutoff_24h),
            ).fetchone()[0]

            by_result_rows = conn.execute(
                """SELECT filter_result, COUNT(*) AS cnt
                   FROM email_events WHERE org_id = ?
                   GROUP BY filter_result""",
                (org_id,),
            ).fetchall()

            threat_score_row = conn.execute(
                "SELECT AVG(threat_score) FROM email_events WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            threat_score_avg = round(threat_score_row[0] or 0.0, 2)

            blocked_count = conn.execute(
                """SELECT COUNT(*) FROM email_events
                   WHERE org_id = ? AND filter_result IN ('blocked', 'quarantined')""",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_rules": total_rules,
            "active_rules": active_rules,
            "by_rule_type": {r["rule_type"]: r["cnt"] for r in by_rule_type_rows},
            "total_events_24h": total_events_24h,
            "by_filter_result": {r["filter_result"]: r["cnt"] for r in by_result_rows},
            "threat_score_avg": threat_score_avg,
            "blocked_count": blocked_count,
        }
