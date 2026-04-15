"""Privileged Access Governance Engine — ALDECI.

Manages privileged accounts, access sessions, and behavioral anomaly
detection for service, admin, root, service-account, and break-glass accounts.

Capabilities:
  - Privileged account registration with type and owner
  - Access session recording with command and duration tracking
  - Anomaly flagging with severity classification
  - Stats: active accounts, sessions today, open anomalies, high-risk accounts

Compliance: CyberArk PAM model, NIST SP 800-53 AC-17, PCI-DSS 10.2.2
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_ACCOUNT_TYPES = {"service", "admin", "root", "sa", "break_glass"}
_VALID_ANOMALY_TYPES = {
    "off_hours",
    "unusual_commands",
    "excessive_access",
    "unauthorized_system",
    "policy_violation",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class PrivilegedAccessGovernanceEngine:
    """SQLite WAL-backed Privileged Access Governance engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/privileged_access_governance.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "privileged_access_governance.db")
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
                CREATE TABLE IF NOT EXISTS pag_accounts (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    username     TEXT NOT NULL DEFAULT '',
                    account_type TEXT NOT NULL DEFAULT 'service',
                    system       TEXT NOT NULL DEFAULT '',
                    owner        TEXT NOT NULL DEFAULT '',
                    justification TEXT NOT NULL DEFAULT '',
                    last_used    DATETIME,
                    status       TEXT NOT NULL DEFAULT 'active',
                    risk_score   REAL NOT NULL DEFAULT 50.0,
                    created_at   DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_pag_accounts_org
                    ON pag_accounts (org_id, account_type, status);

                CREATE TABLE IF NOT EXISTS pag_sessions (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    account_id        TEXT NOT NULL,
                    accessed_by       TEXT NOT NULL DEFAULT '',
                    system            TEXT NOT NULL DEFAULT '',
                    duration_minutes  INTEGER NOT NULL DEFAULT 0,
                    commands_executed INTEGER NOT NULL DEFAULT 0,
                    justification     TEXT NOT NULL DEFAULT '',
                    approved_by       TEXT NOT NULL DEFAULT '',
                    session_at        DATETIME,
                    status            TEXT NOT NULL DEFAULT 'completed'
                );

                CREATE INDEX IF NOT EXISTS idx_pag_sessions_org
                    ON pag_sessions (org_id, account_id, status);

                CREATE TABLE IF NOT EXISTS pag_anomalies (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    account_id   TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL DEFAULT 'off_hours',
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    description  TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT 'open',
                    detected_at  DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_pag_anomalies_org
                    ON pag_anomalies (org_id, account_id, severity, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Privileged Accounts
    # ------------------------------------------------------------------

    def register_privileged_account(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Register a new privileged account."""
        username = (data.get("username") or "").strip()
        if not username:
            raise ValueError("username is required")

        account_type = data.get("account_type", "service")
        if account_type not in _VALID_ACCOUNT_TYPES:
            raise ValueError(
                f"Invalid account_type: {account_type}. "
                f"Must be one of {sorted(_VALID_ACCOUNT_TYPES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "username": username,
            "account_type": account_type,
            "system": data.get("system", ""),
            "owner": data.get("owner", ""),
            "justification": data.get("justification", ""),
            "last_used": None,
            "status": "active",
            "risk_score": 50.0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO pag_accounts
                       (id, org_id, username, account_type, system, owner, justification,
                        last_used, status, risk_score, created_at)
                       VALUES
                       (:id, :org_id, :username, :account_type, :system, :owner, :justification,
                        :last_used, :status, :risk_score, :created_at)""",
                    record,
                )
        return record

    def list_privileged_accounts(
        self,
        org_id: str,
        account_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List privileged accounts with optional filters."""
        sql = "SELECT * FROM pag_accounts WHERE org_id = ?"
        params: list = [org_id]
        if account_type is not None:
            sql += " AND account_type = ?"
            params.append(account_type)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_privileged_account(
        self, org_id: str, account_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get a single privileged account by id, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM pag_accounts WHERE id = ? AND org_id = ?",
                (account_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def record_access_session(
        self, org_id: str, account_id: str, session_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a privileged access session and update account last_used."""
        now = _now_iso()
        session_at = session_data.get("session_at", now)
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id,
            "accessed_by": session_data.get("accessed_by", ""),
            "system": session_data.get("system", ""),
            "duration_minutes": int(session_data.get("duration_minutes", 0)),
            "commands_executed": int(session_data.get("commands_executed", 0)),
            "justification": session_data.get("justification", ""),
            "approved_by": session_data.get("approved_by", ""),
            "session_at": session_at,
            "status": "completed",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO pag_sessions
                       (id, org_id, account_id, accessed_by, system, duration_minutes,
                        commands_executed, justification, approved_by, session_at, status)
                       VALUES
                       (:id, :org_id, :account_id, :accessed_by, :system, :duration_minutes,
                        :commands_executed, :justification, :approved_by, :session_at, :status)""",
                    record,
                )
                # Update account last_used
                conn.execute(
                    "UPDATE pag_accounts SET last_used = ? WHERE id = ? AND org_id = ?",
                    (session_at, account_id, org_id),
                )
        return record

    def list_sessions(
        self,
        org_id: str,
        account_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List access sessions with optional filters."""
        sql = "SELECT * FROM pag_sessions WHERE org_id = ?"
        params: list = [org_id]
        if account_id is not None:
            sql += " AND account_id = ?"
            params.append(account_id)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY session_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Anomalies
    # ------------------------------------------------------------------

    def flag_anomaly(
        self, org_id: str, account_id: str, anomaly_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Flag a behavioral anomaly on a privileged account."""
        anomaly_type = anomaly_data.get("anomaly_type", "off_hours")
        if anomaly_type not in _VALID_ANOMALY_TYPES:
            raise ValueError(
                f"Invalid anomaly_type: {anomaly_type}. "
                f"Must be one of {sorted(_VALID_ANOMALY_TYPES)}"
            )

        severity = anomaly_data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id,
            "anomaly_type": anomaly_type,
            "severity": severity,
            "description": anomaly_data.get("description", ""),
            "status": "open",
            "detected_at": anomaly_data.get("detected_at", now),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO pag_anomalies
                       (id, org_id, account_id, anomaly_type, severity,
                        description, status, detected_at)
                       VALUES
                       (:id, :org_id, :account_id, :anomaly_type, :severity,
                        :description, :status, :detected_at)""",
                    record,
                )
        return record

    def list_anomalies(
        self,
        org_id: str,
        account_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List anomalies with optional filters."""
        sql = "SELECT * FROM pag_anomalies WHERE org_id = ?"
        params: list = [org_id]
        if account_id is not None:
            sql += " AND account_id = ?"
            params.append(account_id)
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_pag_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregated privileged access governance statistics for an org."""
        today = _today_str()
        with self._conn() as conn:
            total_accounts = conn.execute(
                "SELECT COUNT(*) FROM pag_accounts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_accounts = conn.execute(
                "SELECT COUNT(*) FROM pag_accounts WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            sessions_today = conn.execute(
                "SELECT COUNT(*) FROM pag_sessions WHERE org_id = ? AND session_at LIKE ?",
                (org_id, f"{today}%"),
            ).fetchone()[0]

            anomalies_open = conn.execute(
                "SELECT COUNT(*) FROM pag_anomalies WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                """SELECT account_type, COUNT(*) as cnt
                   FROM pag_accounts WHERE org_id = ?
                   GROUP BY account_type""",
                (org_id,),
            ).fetchall()
            by_account_type = {r["account_type"]: r["cnt"] for r in type_rows}

            high_risk_accounts = conn.execute(
                "SELECT COUNT(*) FROM pag_accounts WHERE org_id = ? AND risk_score > 70",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_accounts": total_accounts,
            "active_accounts": active_accounts,
            "sessions_today": sessions_today,
            "anomalies_open": anomalies_open,
            "by_account_type": by_account_type,
            "high_risk_accounts": high_risk_accounts,
        }
