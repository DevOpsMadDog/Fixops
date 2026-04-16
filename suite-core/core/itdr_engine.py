"""ITDR Engine — ALDECI (Identity Threat Detection and Response).

Detects and responds to identity-based attacks: credential stuffing,
account takeover, privilege abuse, lateral movement via compromised identities.

Capabilities:
  - Threat detection: 8 threat types with confidence scoring
  - Behavior recording: user activity anomaly tracking
  - Response actions: 7 action types with execution lifecycle
  - Stats: totals, by type/severity, active threats, high-risk users

Compliance: NIST SP 800-63B, ISO 27001 A.9 (Access Control), MITRE ATT&CK TA0006
"""

from __future__ import annotations

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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_THREAT_TYPES = {
    "credential_stuffing",
    "account_takeover",
    "privilege_abuse",
    "lateral_movement",
    "impossible_travel",
    "mfa_bypass",
    "session_hijacking",
    "password_spray",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_VALID_THREAT_STATUSES = {
    "detected",
    "investigating",
    "confirmed",
    "false_positive",
    "contained",
}

_VALID_BEHAVIOR_TYPES = {
    "login_attempt",
    "failed_login",
    "mfa_challenge",
    "privilege_escalation",
    "data_access",
    "lateral_move",
    "anomalous_time",
    "new_location",
}

_VALID_ACTION_TYPES = {
    "block_ip",
    "force_mfa",
    "disable_account",
    "revoke_session",
    "alert_security",
    "reset_password",
    "notify_user",
}

_VALID_ACTION_STATUSES = {"pending", "executed", "failed", "cancelled"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ITDREngine:
    """SQLite WAL-backed Identity Threat Detection and Response engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/itdr.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "itdr.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS identity_threats (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    user_id     TEXT NOT NULL,
                    source_ip   TEXT NOT NULL DEFAULT '',
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    confidence  REAL NOT NULL DEFAULT 50.0,
                    status      TEXT NOT NULL DEFAULT 'detected',
                    indicators  TEXT NOT NULL DEFAULT '[]',
                    detected_at TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_threats_org
                    ON identity_threats (org_id, threat_type, status, severity, detected_at DESC);

                CREATE TABLE IF NOT EXISTS identity_behaviors (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    user_id       TEXT NOT NULL,
                    behavior_type TEXT NOT NULL,
                    risk_score    INTEGER NOT NULL DEFAULT 50,
                    details       TEXT NOT NULL DEFAULT '{}',
                    recorded_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_behaviors_org
                    ON identity_behaviors (org_id, user_id, behavior_type, recorded_at DESC);

                CREATE TABLE IF NOT EXISTS response_actions (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    threat_id   TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'pending',
                    executed_at TEXT,
                    notes       TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_actions_org
                    ON response_actions (org_id, threat_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Parse JSON fields
        for field in ("indicators", "details"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    # ------------------------------------------------------------------
    # Threats
    # ------------------------------------------------------------------

    def detect_threat(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new identity threat detection."""
        threat_type = data.get("threat_type", "")
        if threat_type not in _VALID_THREAT_TYPES:
            raise ValueError(
                f"Invalid threat_type: {threat_type!r}. "
                f"Must be one of {sorted(_VALID_THREAT_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        user_id = (data.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required.")

        try:
            confidence = float(data.get("confidence", 50.0))
        except (TypeError, ValueError):
            raise ValueError("confidence must be a number between 0 and 100.")
        confidence = max(0.0, min(100.0, confidence))

        indicators = data.get("indicators", [])
        if not isinstance(indicators, list):
            indicators = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "threat_type": threat_type,
            "user_id": user_id,
            "source_ip": data.get("source_ip", ""),
            "severity": severity,
            "confidence": confidence,
            "status": "detected",
            "indicators": json.dumps(indicators),
            "detected_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO identity_threats
                       (id, org_id, threat_type, user_id, source_ip, severity,
                        confidence, status, indicators, detected_at, updated_at)
                       VALUES (:id, :org_id, :threat_type, :user_id, :source_ip, :severity,
                               :confidence, :status, :indicators, :detected_at, :updated_at)""",
                    record,
                )
        # Return with parsed indicators
        record["indicators"] = indicators
        return record

    def list_threats(
        self,
        org_id: str,
        threat_type: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List identity threats with optional filters."""
        sql = "SELECT * FROM identity_threats WHERE org_id = ?"
        params: list = [org_id]
        if threat_type:
            sql += " AND threat_type = ?"
            params.append(threat_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_threat(self, org_id: str, threat_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single threat by ID. Returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM identity_threats WHERE org_id = ? AND id = ?",
                (org_id, threat_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_threat_status(
        self, org_id: str, threat_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update the status of a threat. Raises KeyError if not found."""
        if new_status not in _VALID_THREAT_STATUSES:
            raise ValueError(
                f"Invalid status: {new_status!r}. "
                f"Must be one of {sorted(_VALID_THREAT_STATUSES)}"
            )
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE identity_threats SET status = ?, updated_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (new_status, now, org_id, threat_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Threat not found: {threat_id}")
                row = conn.execute(
                    "SELECT * FROM identity_threats WHERE org_id = ? AND id = ?",
                    (org_id, threat_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Behaviors
    # ------------------------------------------------------------------

    def record_behavior(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an identity behavior event."""
        user_id = (data.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required.")

        behavior_type = data.get("behavior_type", "")
        if behavior_type not in _VALID_BEHAVIOR_TYPES:
            raise ValueError(
                f"Invalid behavior_type: {behavior_type!r}. "
                f"Must be one of {sorted(_VALID_BEHAVIOR_TYPES)}"
            )

        try:
            risk_score = int(data.get("risk_score", 50))
        except (TypeError, ValueError):
            raise ValueError("risk_score must be an integer between 0 and 100.")
        risk_score = max(0, min(100, risk_score))

        details = data.get("details", {})
        if not isinstance(details, dict):
            details = {}

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "user_id": user_id,
            "behavior_type": behavior_type,
            "risk_score": risk_score,
            "details": json.dumps(details),
            "recorded_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO identity_behaviors
                       (id, org_id, user_id, behavior_type, risk_score, details, recorded_at)
                       VALUES (:id, :org_id, :user_id, :behavior_type, :risk_score,
                               :details, :recorded_at)""",
                    record,
                )
        record["details"] = details
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "itdr", "org_id": org_id, "source_engine": "itdr"})
            except Exception:
                pass

        return record

    def list_behaviors(
        self,
        org_id: str,
        user_id: Optional[str] = None,
        behavior_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List identity behaviors with optional filters."""
        sql = "SELECT * FROM identity_behaviors WHERE org_id = ?"
        params: list = [org_id]
        if user_id:
            sql += " AND user_id = ?"
            params.append(user_id)
        if behavior_type:
            sql += " AND behavior_type = ?"
            params.append(behavior_type)
        sql += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Response Actions
    # ------------------------------------------------------------------

    def create_response_action(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a response action for a threat."""
        threat_id = (data.get("threat_id") or "").strip()
        if not threat_id:
            raise ValueError("threat_id is required.")

        # Validate threat exists in org
        threat = self.get_threat(org_id, threat_id)
        if not threat:
            raise ValueError(f"Threat not found: {threat_id}")

        action_type = data.get("action_type", "")
        if action_type not in _VALID_ACTION_TYPES:
            raise ValueError(
                f"Invalid action_type: {action_type!r}. "
                f"Must be one of {sorted(_VALID_ACTION_TYPES)}"
            )

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "threat_id": threat_id,
            "action_type": action_type,
            "status": "pending",
            "executed_at": None,
            "notes": data.get("notes", ""),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO response_actions
                       (id, org_id, threat_id, action_type, status, executed_at, notes)
                       VALUES (:id, :org_id, :threat_id, :action_type, :status,
                               :executed_at, :notes)""",
                    record,
                )
        return record

    def execute_response_action(
        self, org_id: str, action_id: str
    ) -> Dict[str, Any]:
        """Mark a response action as executed. Raises KeyError if not found or wrong org."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE response_actions SET status = 'executed', executed_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (now, org_id, action_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Response action not found: {action_id}")
                row = conn.execute(
                    "SELECT * FROM response_actions WHERE org_id = ? AND id = ?",
                    (org_id, action_id),
                ).fetchone()
        return self._row(row)

    def list_response_actions(
        self,
        org_id: str,
        threat_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List response actions with optional filters."""
        sql = "SELECT * FROM response_actions WHERE org_id = ?"
        params: list = [org_id]
        if threat_id:
            sql += " AND threat_id = ?"
            params.append(threat_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY rowid DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_itdr_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated ITDR statistics for an org."""
        with self._conn() as conn:
            total_threats = conn.execute(
                "SELECT COUNT(*) FROM identity_threats WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT threat_type, COUNT(*) as cnt FROM identity_threats "
                "WHERE org_id = ? GROUP BY threat_type",
                (org_id,),
            ).fetchall()
            by_type = {r["threat_type"]: r["cnt"] for r in type_rows}

            active_threats = conn.execute(
                "SELECT COUNT(*) FROM identity_threats "
                "WHERE org_id = ? AND status IN ('detected', 'investigating', 'confirmed')",
                (org_id,),
            ).fetchone()[0]

            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM identity_threats "
                "WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            total_behaviors = conn.execute(
                "SELECT COUNT(*) FROM identity_behaviors WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            pending_actions = conn.execute(
                "SELECT COUNT(*) FROM response_actions WHERE org_id = ? AND status = 'pending'",
                (org_id,),
            ).fetchone()[0]

            high_risk_users = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM identity_behaviors "
                "WHERE org_id = ? AND risk_score >= 80",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_threats": total_threats,
            "by_type": by_type,
            "active_threats": active_threats,
            "by_severity": by_severity,
            "total_behaviors": total_behaviors,
            "pending_actions": pending_actions,
            "high_risk_users": high_risk_users,
        }
