"""API Threat Protection Engine — ALDECI. SQLite WAL + RLock + org_id isolation."""
from __future__ import annotations

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "api_threat_protection.db"
)

VALID_THREAT_TYPES = frozenset({
    "injection", "auth_bypass", "rate_abuse", "data_scraping",
    "bot_attack", "credential_stuffing", "parameter_tampering", "mass_assignment",
})
VALID_ACTIONS = frozenset({"block", "rate_limit", "challenge", "monitor", "allow"})
VALID_RULE_STATUSES = frozenset({"active", "disabled", "testing"})


class APIThreatProtectionEngine:
    """SQLite-backed API threat protection rule and event engine.

    All public methods are thread-safe via RLock.
    Multi-tenant via org_id isolation.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS atp_rules (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    threat_type TEXT NOT NULL DEFAULT 'injection',
                    pattern TEXT NOT NULL DEFAULT '',
                    action TEXT NOT NULL DEFAULT 'block',
                    threshold INTEGER NOT NULL DEFAULT 10,
                    window_seconds INTEGER NOT NULL DEFAULT 60,
                    status TEXT NOT NULL DEFAULT 'active',
                    triggered_count INTEGER NOT NULL DEFAULT 0,
                    created_at DATETIME
                );
                CREATE TABLE IF NOT EXISTS atp_events (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL DEFAULT '',
                    threat_type TEXT NOT NULL DEFAULT 'injection',
                    source_ip TEXT NOT NULL DEFAULT '',
                    endpoint TEXT NOT NULL DEFAULT '',
                    method TEXT NOT NULL DEFAULT 'GET',
                    payload_hash TEXT NOT NULL DEFAULT '',
                    action_taken TEXT NOT NULL DEFAULT 'monitor',
                    severity TEXT NOT NULL DEFAULT 'medium',
                    detected_at DATETIME
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def create_protection_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new API threat protection rule."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")
        threat_type = data.get("threat_type", "injection")
        if threat_type not in VALID_THREAT_TYPES:
            raise ValueError(f"threat_type must be one of {sorted(VALID_THREAT_TYPES)}")
        action = data.get("action", "block")
        if action not in VALID_ACTIONS:
            raise ValueError(f"action must be one of {sorted(VALID_ACTIONS)}")

        now = datetime.now(timezone.utc).isoformat()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "threat_type": threat_type,
            "pattern": data.get("pattern", ""),
            "action": action,
            "threshold": int(data.get("threshold", 10)),
            "window_seconds": int(data.get("window_seconds", 60)),
            "status": "active",
            "triggered_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO atp_rules
                       (id, org_id, name, threat_type, pattern, action, threshold,
                        window_seconds, status, triggered_count, created_at)
                       VALUES (:id, :org_id, :name, :threat_type, :pattern, :action, :threshold,
                               :window_seconds, :status, :triggered_count, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "api_threat_protection", "org_id": org_id, "source_engine": "api_threat_protection"})
            except Exception:
                pass

        return record

    def list_rules(
        self,
        org_id: str,
        threat_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List protection rules, optionally filtered by threat_type and status."""
        query = "SELECT * FROM atp_rules WHERE org_id = ?"
        params: List[Any] = [org_id]
        if threat_type:
            query += " AND threat_type = ?"
            params.append(threat_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_rule(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a single rule by id, org-isolated."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM atp_rules WHERE id = ? AND org_id = ?",
                    (rule_id, org_id),
                ).fetchone()
        return self._row(row) if row else None

    def update_rule_status(self, org_id: str, rule_id: str, status: str) -> Dict[str, Any]:
        """Update a rule's status."""
        if status not in VALID_RULE_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_RULE_STATUSES)}")
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM atp_rules WHERE id = ? AND org_id = ?",
                    (rule_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Rule {rule_id} not found")
                conn.execute(
                    "UPDATE atp_rules SET status = ? WHERE id = ? AND org_id = ?",
                    (status, rule_id, org_id),
                )
        rule = self._row(row)
        rule["status"] = status
        return rule

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def record_threat_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a threat event and increment triggered_count on the associated rule."""
        threat_type = data.get("threat_type", "injection")
        if threat_type not in VALID_THREAT_TYPES:
            raise ValueError(f"threat_type must be one of {sorted(VALID_THREAT_TYPES)}")

        now = datetime.now(timezone.utc).isoformat()
        rule_id = data.get("rule_id", "")
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "rule_id": rule_id,
            "threat_type": threat_type,
            "source_ip": data.get("source_ip", ""),
            "endpoint": data.get("endpoint", ""),
            "method": data.get("method", "GET"),
            "payload_hash": data.get("payload_hash", ""),
            "action_taken": data.get("action_taken", "monitor"),
            "severity": data.get("severity", "medium"),
            "detected_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO atp_events
                       (id, org_id, rule_id, threat_type, source_ip, endpoint, method,
                        payload_hash, action_taken, severity, detected_at)
                       VALUES (:id, :org_id, :rule_id, :threat_type, :source_ip, :endpoint,
                               :method, :payload_hash, :action_taken, :severity, :detected_at)""",
                    record,
                )
                # Increment triggered_count for the associated rule
                if rule_id:
                    conn.execute(
                        """UPDATE atp_rules
                           SET triggered_count = triggered_count + 1
                           WHERE id = ? AND org_id = ?""",
                        (rule_id, org_id),
                    )
        return record

    def list_threat_events(
        self,
        org_id: str,
        threat_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threat events with optional filters, ordered by detected_at DESC."""
        query = "SELECT * FROM atp_events WHERE org_id = ?"
        params: List[Any] = [org_id]
        if threat_type:
            query += " AND threat_type = ?"
            params.append(threat_type)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id)
        query += " ORDER BY detected_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_protection_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate protection statistics for the org."""
        today_prefix = datetime.now(timezone.utc).date().isoformat()
        with self._lock:
            with self._conn() as conn:
                total_rules = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM atp_rules WHERE org_id = ?",
                    (org_id,),
                ).fetchone()["cnt"]

                active_rules = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM atp_rules WHERE org_id = ? AND status = 'active'",
                    (org_id,),
                ).fetchone()["cnt"]

                total_events = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM atp_events WHERE org_id = ?",
                    (org_id,),
                ).fetchone()["cnt"]

                events_today = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM atp_events WHERE org_id = ? AND detected_at LIKE ?",
                    (org_id, f"{today_prefix}%"),
                ).fetchone()["cnt"]

                blocked_count = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM atp_events WHERE org_id = ? AND action_taken = 'block'",
                    (org_id,),
                ).fetchone()["cnt"]

                type_rows = conn.execute(
                    "SELECT threat_type, COUNT(*) AS cnt FROM atp_events WHERE org_id = ? GROUP BY threat_type",
                    (org_id,),
                ).fetchall()
                by_threat_type = {r["threat_type"]: r["cnt"] for r in type_rows}

                # Top attacker: most frequent source_ip
                top_row = conn.execute(
                    """SELECT source_ip, COUNT(*) AS cnt FROM atp_events
                       WHERE org_id = ? AND source_ip != ''
                       GROUP BY source_ip ORDER BY cnt DESC LIMIT 1""",
                    (org_id,),
                ).fetchone()
                top_attacker_ip = top_row["source_ip"] if top_row else None

        return {
            "total_rules": total_rules,
            "active_rules": active_rules,
            "total_events": total_events,
            "events_today": events_today,
            "blocked_count": blocked_count,
            "by_threat_type": by_threat_type,
            "top_attacker_ip": top_attacker_ip,
        }
