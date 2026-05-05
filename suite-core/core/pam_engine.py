"""Privileged Access Management (PAM) Engine — ALDECI.

Tracks privileged accounts, session lifecycle, approval workflows, policies,
and vault status for zero-standing-privilege enforcement.

Compliance: NIST SP 800-53 AC-2/AC-6, CIS Controls v8 5.4, PCI DSS 7.2
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

# Thread-local storage for persistent per-thread SQLite connections.
# Avoids the overhead of sqlite3.connect() on every read call (~0.3ms each).
_tls = threading.local()

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "pam.db"
)


class PAMEngine:
    """SQLite WAL-backed Privileged Access Management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        # Unique key per db_path so multiple PAMEngine instances sharing the
        # same thread-local namespace don't clobber each other's connections.
        self._tls_key = db_path.replace("/", "_").replace(".", "_")
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS privileged_accounts (
                    account_id       TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    username         TEXT NOT NULL,
                    account_type     TEXT NOT NULL DEFAULT 'admin',
                    system           TEXT NOT NULL DEFAULT '',
                    department       TEXT NOT NULL DEFAULT '',
                    owner            TEXT NOT NULL DEFAULT '',
                    is_vaulted       INTEGER NOT NULL DEFAULT 0,
                    rotation_days    INTEGER NOT NULL DEFAULT 90,
                    last_rotated     TEXT,
                    risk_score       INTEGER NOT NULL DEFAULT 50,
                    status           TEXT NOT NULL DEFAULT 'active',
                    created_at       TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pam_acct_org
                    ON privileged_accounts (org_id, status);

                CREATE TABLE IF NOT EXISTS pam_sessions (
                    session_id               TEXT PRIMARY KEY,
                    org_id                   TEXT NOT NULL,
                    account_id               TEXT NOT NULL,
                    requester                TEXT NOT NULL DEFAULT '',
                    justification            TEXT NOT NULL DEFAULT '',
                    approval_status          TEXT NOT NULL DEFAULT 'pending',
                    approver                 TEXT,
                    session_type             TEXT NOT NULL DEFAULT 'interactive',
                    target_system            TEXT NOT NULL DEFAULT '',
                    requested_duration_minutes INTEGER NOT NULL DEFAULT 60,
                    started_at               TEXT,
                    ended_at                 TEXT,
                    recording_enabled        INTEGER NOT NULL DEFAULT 1,
                    created_at               TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pam_sess_org
                    ON pam_sessions (org_id, approval_status);

                CREATE TABLE IF NOT EXISTS pam_policies (
                    policy_id               TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    name                    TEXT NOT NULL,
                    require_approval        INTEGER NOT NULL DEFAULT 1,
                    max_session_minutes     INTEGER NOT NULL DEFAULT 60,
                    allowed_hours           TEXT NOT NULL DEFAULT '[]',
                    mfa_required            INTEGER NOT NULL DEFAULT 1,
                    recording_required      INTEGER NOT NULL DEFAULT 1,
                    created_at              TEXT NOT NULL,
                    updated_at              TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pam_pol_org
                    ON pam_policies (org_id);

                CREATE TABLE IF NOT EXISTS vault_entries (
                    entry_id     TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    account_id   TEXT NOT NULL,
                    secret_ref   TEXT NOT NULL DEFAULT '',
                    rotated_at   TEXT NOT NULL,
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vault_org
                    ON vault_entries (org_id, account_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        """Return a persistent per-thread SQLite connection.

        Re-using the same connection object eliminates the ~0.3 ms overhead of
        sqlite3.connect() that was previously paid on every read call.  WAL mode
        is set once at __init__ time via _init_db(); subsequent calls just reuse
        the open handle.  Each thread gets its own connection (sqlite3 objects
        are not safe to share across threads).
        """
        conn: sqlite3.Connection | None = getattr(_tls, "conn_" + self._tls_key, None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            setattr(_tls, "conn_" + self._tls_key, conn)
        return conn

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def register_account(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a privileged account. Returns the full account record."""
        account_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        account_type = data.get("account_type", "admin")
        if account_type not in ("service", "admin", "root", "sa", "shared", "emergency"):
            account_type = "admin"

        status = data.get("status", "active")
        if status not in ("active", "disabled", "expired"):
            status = "active"

        is_vaulted = 1 if data.get("is_vaulted") else 0
        rotation_days = int(data.get("rotation_days", 90))
        risk_score = max(0, min(100, int(data.get("risk_score", 50))))
        last_rotated = data.get("last_rotated", now)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO privileged_accounts
                        (account_id, org_id, username, account_type, system, department,
                         owner, is_vaulted, rotation_days, last_rotated, risk_score,
                         status, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        account_id, org_id,
                        data.get("username", ""),
                        account_type,
                        data.get("system", ""),
                        data.get("department", ""),
                        data.get("owner", ""),
                        is_vaulted, rotation_days, last_rotated,
                        risk_score, status, now, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "pam", "org_id": org_id, "source_engine": "pam"})
            except Exception:
                pass

        return self._account_row_dict({
            "account_id": account_id,
            "org_id": org_id,
            "username": data.get("username", ""),
            "account_type": account_type,
            "system": data.get("system", ""),
            "department": data.get("department", ""),
            "owner": data.get("owner", ""),
            "is_vaulted": is_vaulted,
            "rotation_days": rotation_days,
            "last_rotated": last_rotated,
            "risk_score": risk_score,
            "status": status,
            "created_at": now,
            "updated_at": now,
        })

    def _account_row_dict(self, row: Any) -> Dict[str, Any]:
        d = dict(row)
        d["is_vaulted"] = bool(d.get("is_vaulted", 0))
        return d

    def list_accounts(
        self,
        org_id: str,
        account_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List privileged accounts for an org with optional filters."""
        query = "SELECT * FROM privileged_accounts WHERE org_id=?"
        params: list = [org_id]
        if account_type:
            query += " AND account_type=?"
            params.append(account_type)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._account_row_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def create_session(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a PAM session request. Returns the full session record."""
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        session_type = data.get("session_type", "interactive")
        if session_type not in ("interactive", "api", "scheduled"):
            session_type = "interactive"

        recording_enabled = 1 if data.get("recording_enabled", True) else 0
        duration = int(data.get("requested_duration_minutes", 60))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO pam_sessions
                        (session_id, org_id, account_id, requester, justification,
                         approval_status, approver, session_type, target_system,
                         requested_duration_minutes, started_at, ended_at,
                         recording_enabled, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        session_id, org_id,
                        data.get("account_id", ""),
                        data.get("requester", ""),
                        data.get("justification", ""),
                        "pending",
                        None,
                        session_type,
                        data.get("target_system", ""),
                        duration,
                        data.get("started_at"),
                        None,
                        recording_enabled,
                        now,
                    ),
                )

        return {
            "session_id": session_id,
            "org_id": org_id,
            "account_id": data.get("account_id", ""),
            "requester": data.get("requester", ""),
            "justification": data.get("justification", ""),
            "approval_status": "pending",
            "approver": None,
            "session_type": session_type,
            "target_system": data.get("target_system", ""),
            "requested_duration_minutes": duration,
            "started_at": data.get("started_at"),
            "ended_at": None,
            "recording_enabled": bool(recording_enabled),
            "created_at": now,
        }

    def _session_row_dict(self, row: Any) -> Dict[str, Any]:
        d = dict(row)
        d["recording_enabled"] = bool(d.get("recording_enabled", 1))
        return d

    def list_sessions(
        self,
        org_id: str,
        approval_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List PAM sessions for an org."""
        query = "SELECT * FROM pam_sessions WHERE org_id=?"
        params: list = [org_id]
        if approval_status:
            query += " AND approval_status=?"
            params.append(approval_status)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._session_row_dict(r) for r in rows]

    def approve_session(
        self,
        org_id: str,
        session_id: str,
        approver: str,
        approved: bool,
    ) -> bool:
        """Approve or deny a pending PAM session. Returns True if updated."""
        new_status = "approved" if approved else "denied"
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE pam_sessions
                    SET approval_status=?, approver=?, started_at=CASE
                        WHEN ? = 'approved' AND started_at IS NULL THEN ?
                        ELSE started_at END
                    WHERE session_id=? AND org_id=? AND approval_status='pending'
                    """,
                    (new_status, approver, new_status, now, session_id, org_id),
                )
        return cur.rowcount > 0

    def end_session(self, org_id: str, session_id: str) -> bool:
        """End an active PAM session by setting ended_at to now. Returns True if updated."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE pam_sessions SET ended_at=?
                    WHERE session_id=? AND org_id=? AND ended_at IS NULL
                    """,
                    (now, session_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a PAM policy. Returns the full policy record."""
        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        allowed_hours = json.dumps(data.get("allowed_hours", []))
        require_approval = 1 if data.get("require_approval", True) else 0
        mfa_required = 1 if data.get("mfa_required", True) else 0
        recording_required = 1 if data.get("recording_required", True) else 0
        max_session_minutes = int(data.get("max_session_minutes", 60))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO pam_policies
                        (policy_id, org_id, name, require_approval, max_session_minutes,
                         allowed_hours, mfa_required, recording_required, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        policy_id, org_id,
                        data.get("name", "Default PAM Policy"),
                        require_approval, max_session_minutes,
                        allowed_hours, mfa_required, recording_required,
                        now, now,
                    ),
                )

        return {
            "policy_id": policy_id,
            "org_id": org_id,
            "name": data.get("name", "Default PAM Policy"),
            "require_approval": bool(require_approval),
            "max_session_minutes": max_session_minutes,
            "allowed_hours": data.get("allowed_hours", []),
            "mfa_required": bool(mfa_required),
            "recording_required": bool(recording_required),
            "created_at": now,
            "updated_at": now,
        }

    def _policy_row_dict(self, row: Any) -> Dict[str, Any]:
        d = dict(row)
        d["require_approval"] = bool(d.get("require_approval", 1))
        d["mfa_required"] = bool(d.get("mfa_required", 1))
        d["recording_required"] = bool(d.get("recording_required", 1))
        d["allowed_hours"] = json.loads(d.get("allowed_hours") or "[]")
        return d

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List PAM policies for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM pam_policies WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._policy_row_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_pam_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary statistics for PAM inventory.

        Collapsed from 6 separate SELECT statements to 2 (one per table) using
        conditional aggregation.  This eliminates 4 round-trips to SQLite per call.
        """
        conn = self._conn()
        acct_row = conn.execute(
            """
            SELECT
                COUNT(*)                                      AS total_accounts,
                SUM(CASE WHEN is_vaulted=1   THEN 1 ELSE 0 END) AS vaulted,
                SUM(CASE WHEN status='expired' THEN 1 ELSE 0 END) AS accounts_expired,
                AVG(risk_score)                               AS avg_risk_score
            FROM privileged_accounts
            WHERE org_id=?
            """,
            (org_id,),
        ).fetchone()

        sess_row = conn.execute(
            """
            SELECT
                SUM(CASE WHEN approval_status='approved' AND ended_at IS NULL THEN 1 ELSE 0 END) AS active_sessions,
                SUM(CASE WHEN approval_status='pending'                        THEN 1 ELSE 0 END) AS pending_approvals
            FROM pam_sessions
            WHERE org_id=?
            """,
            (org_id,),
        ).fetchone()

        return {
            "total_accounts":    acct_row[0] or 0,
            "vaulted":           acct_row[1] or 0,
            "accounts_expired":  acct_row[2] or 0,
            "avg_risk_score":    round(acct_row[3] or 0.0, 1),
            "active_sessions":   sess_row[0] or 0,
            "pending_approvals": sess_row[1] or 0,
        }
