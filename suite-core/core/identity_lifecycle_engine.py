"""Identity Lifecycle Engine — ALDECI.

Manages the full lifecycle of digital identities: provisioning, deprovisioning,
suspension, reactivation, entitlement grants/revocations, and orphan account detection.

Features:
- Account lifecycle: active → suspended / deprovisioned
- Entitlement management with expiry tracking
- Full audit trail via identity_events
- Orphan detection: active accounts inactive for N days (julianday arithmetic)
- Entitlement summary with by_account_type and by_department breakdowns

Compliance: NIST SP 800-53 AC-2 (Account Management), ISO 27001 A.9.2,
            CIS Control 5 (Account Management), NIST SP 800-63 (Digital Identity)
"""

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "identity_lifecycle.db"
)

_VALID_ACCOUNT_TYPES = {"employee", "contractor", "service", "system", "bot", "vendor", "temp"}
_VALID_STATUSES = {"active", "suspended", "deprovisioned"}
_VALID_ACCESS_LEVELS = {"read", "write", "admin", "owner"}
_VALID_EVENT_TYPES = {
    "provisioned", "deprovisioned", "suspended", "reactivated",
    "access_granted", "access_revoked", "password_reset", "mfa_enrolled",
}


class IdentityLifecycleEngine:
    """Engine for managing identity provisioning and lifecycle."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS identity_accounts (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    username          TEXT NOT NULL,
                    display_name      TEXT NOT NULL DEFAULT '',
                    email             TEXT NOT NULL DEFAULT '',
                    account_type      TEXT NOT NULL DEFAULT 'employee',
                    department        TEXT NOT NULL DEFAULT '',
                    manager           TEXT NOT NULL DEFAULT '',
                    status            TEXT NOT NULL DEFAULT 'active',
                    last_active       TEXT,
                    provisioned_at    TEXT,
                    deprovisioned_at  TEXT,
                    created_at        TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ia_org    ON identity_accounts(org_id);
                CREATE INDEX IF NOT EXISTS idx_ia_status ON identity_accounts(org_id, status);
                CREATE INDEX IF NOT EXISTS idx_ia_dept   ON identity_accounts(org_id, department);

                CREATE TABLE IF NOT EXISTS identity_events (
                    id           TEXT PRIMARY KEY,
                    account_id   TEXT NOT NULL,
                    org_id       TEXT NOT NULL,
                    event_type   TEXT NOT NULL,
                    performed_by TEXT NOT NULL DEFAULT '',
                    details      TEXT NOT NULL DEFAULT '',
                    event_time   TEXT,
                    created_at   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ie_org     ON identity_events(org_id);
                CREATE INDEX IF NOT EXISTS idx_ie_account ON identity_events(account_id);

                CREATE TABLE IF NOT EXISTS access_entitlements (
                    id           TEXT PRIMARY KEY,
                    account_id   TEXT NOT NULL,
                    org_id       TEXT NOT NULL,
                    system_name  TEXT NOT NULL DEFAULT '',
                    role         TEXT NOT NULL DEFAULT '',
                    access_level TEXT NOT NULL DEFAULT 'read',
                    granted_at   TEXT,
                    expires_at   TEXT NOT NULL DEFAULT '',
                    granted_by   TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT 'active',
                    created_at   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ae_org     ON access_entitlements(org_id);
                CREATE INDEX IF NOT EXISTS idx_ae_account ON access_entitlements(account_id);
                CREATE INDEX IF NOT EXISTS idx_ae_status  ON access_entitlements(org_id, status);
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # INTERNAL HELPERS
    # ------------------------------------------------------------------

    def _insert_event(
        self,
        conn: sqlite3.Connection,
        account_id: str,
        org_id: str,
        event_type: str,
        performed_by: str = "",
        details: str = "",
    ) -> None:
        now = self._now()
        conn.execute(
            """INSERT INTO identity_events
               (id, account_id, org_id, event_type, performed_by, details, event_time, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), account_id, org_id, event_type, performed_by, details, now, now),
        )

    # ------------------------------------------------------------------
    # ACCOUNT LIFECYCLE
    # ------------------------------------------------------------------

    def provision_account(
        self,
        org_id: str,
        username: str,
        display_name: str = "",
        email: str = "",
        account_type: str = "employee",
        department: str = "",
        manager: str = "",
    ) -> Dict[str, Any]:
        """Create and activate a new identity account."""
        if not username:
            raise ValueError("username is required")
        if account_type not in _VALID_ACCOUNT_TYPES:
            raise ValueError(
                f"Invalid account_type '{account_type}'. Must be one of {sorted(_VALID_ACCOUNT_TYPES)}"
            )

        account_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO identity_accounts
                   (id, org_id, username, display_name, email, account_type,
                    department, manager, status, last_active, provisioned_at,
                    deprovisioned_at, created_at)
                   VALUES (?,?,?,?,?,?,?,?,'active',NULL,?,NULL,?)""",
                (
                    account_id, org_id, username, display_name, email,
                    account_type, department, manager, now, now,
                ),
            )
            self._insert_event(conn, account_id, org_id, "provisioned", manager, "Account provisioned")
        _logger.info("identity.provisioned org=%s account_id=%s username=%s", org_id, account_id, username)
        return self.get_account(account_id, org_id)

    def deprovision_account(
        self,
        account_id: str,
        org_id: str,
        performed_by: str = "",
    ) -> Dict[str, Any]:
        """Deprovision account and revoke all entitlements."""
        account = self._get_raw_account(account_id, org_id)
        if account is None:
            raise ValueError(f"Account '{account_id}' not found for org '{org_id}'")

        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE identity_accounts
                   SET status='deprovisioned', deprovisioned_at=?
                   WHERE org_id=? AND id=?""",
                (now, org_id, account_id),
            )
            conn.execute(
                """UPDATE access_entitlements
                   SET status='revoked'
                   WHERE org_id=? AND account_id=? AND status='active'""",
                (org_id, account_id),
            )
            self._insert_event(conn, account_id, org_id, "deprovisioned", performed_by, "Account deprovisioned; all entitlements revoked")
        _logger.info("identity.deprovisioned org=%s account_id=%s by=%s", org_id, account_id, performed_by)
        return self.get_account(account_id, org_id)

    def suspend_account(
        self,
        account_id: str,
        org_id: str,
        performed_by: str = "",
    ) -> Dict[str, Any]:
        """Suspend an active account."""
        account = self._get_raw_account(account_id, org_id)
        if account is None:
            raise ValueError(f"Account '{account_id}' not found for org '{org_id}'")

        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE identity_accounts SET status='suspended' WHERE org_id=? AND id=?",
                (org_id, account_id),
            )
            self._insert_event(conn, account_id, org_id, "suspended", performed_by, "Account suspended")
        _logger.info("identity.suspended org=%s account_id=%s by=%s", org_id, account_id, performed_by)
        return self.get_account(account_id, org_id)

    def reactivate_account(
        self,
        account_id: str,
        org_id: str,
        performed_by: str = "",
    ) -> Dict[str, Any]:
        """Reactivate a suspended or deprovisioned account."""
        account = self._get_raw_account(account_id, org_id)
        if account is None:
            raise ValueError(f"Account '{account_id}' not found for org '{org_id}'")

        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE identity_accounts SET status='active' WHERE org_id=? AND id=?",
                (org_id, account_id),
            )
            self._insert_event(conn, account_id, org_id, "reactivated", performed_by, "Account reactivated")
        _logger.info("identity.reactivated org=%s account_id=%s by=%s", org_id, account_id, performed_by)
        return self.get_account(account_id, org_id)

    def update_last_active(self, account_id: str, org_id: str) -> None:
        """Update last_active timestamp for an account."""
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE identity_accounts SET last_active=? WHERE org_id=? AND id=?",
                (now, org_id, account_id),
            )

    # ------------------------------------------------------------------
    # ENTITLEMENTS
    # ------------------------------------------------------------------

    def grant_access(
        self,
        account_id: str,
        org_id: str,
        system_name: str,
        role: str,
        access_level: str = "read",
        expires_at: str = "",
        granted_by: str = "",
    ) -> Dict[str, Any]:
        """Grant system access entitlement to an account."""
        account = self._get_raw_account(account_id, org_id)
        if account is None:
            raise ValueError(f"Account '{account_id}' not found for org '{org_id}'")
        if access_level not in _VALID_ACCESS_LEVELS:
            raise ValueError(
                f"Invalid access_level '{access_level}'. Must be one of {sorted(_VALID_ACCESS_LEVELS)}"
            )

        ent_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO access_entitlements
                   (id, account_id, org_id, system_name, role, access_level,
                    granted_at, expires_at, granted_by, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,'active',?)""",
                (ent_id, account_id, org_id, system_name, role, access_level,
                 now, expires_at, granted_by, now),
            )
            self._insert_event(
                conn, account_id, org_id, "access_granted", granted_by,
                f"Access granted: {system_name}/{role} ({access_level})",
            )
        _logger.info("identity.access_granted org=%s account_id=%s system=%s", org_id, account_id, system_name)

        with self._conn() as conn:
            row = conn.execute("SELECT * FROM access_entitlements WHERE id=?", (ent_id,)).fetchone()
        return self._row(row)

    def revoke_access(
        self,
        entitlement_id: str,
        org_id: str,
        performed_by: str = "",
    ) -> Dict[str, Any]:
        """Revoke a specific entitlement."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM access_entitlements WHERE id=? AND org_id=?",
                (entitlement_id, org_id),
            ).fetchone()
        if row is None:
            raise ValueError(f"Entitlement '{entitlement_id}' not found for org '{org_id}'")

        ent = self._row(row)
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE access_entitlements SET status='revoked' WHERE id=? AND org_id=?",
                (entitlement_id, org_id),
            )
            self._insert_event(
                conn, ent["account_id"], org_id, "access_revoked", performed_by,
                f"Entitlement revoked: {ent.get('system_name','')}/{ent.get('role','')}",
            )
        _logger.info("identity.access_revoked org=%s entitlement_id=%s by=%s", org_id, entitlement_id, performed_by)

        with self._conn() as conn:
            row = conn.execute("SELECT * FROM access_entitlements WHERE id=?", (entitlement_id,)).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # QUERIES
    # ------------------------------------------------------------------

    def _get_raw_account(self, account_id: str, org_id: str) -> Optional[sqlite3.Row]:
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM identity_accounts WHERE id=? AND org_id=?",
                (account_id, org_id),
            ).fetchone()

    def get_account(self, account_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Fetch account with its events and active entitlements."""
        row = self._get_raw_account(account_id, org_id)
        if row is None:
            return None
        account = self._row(row)

        with self._conn() as conn:
            events = conn.execute(
                "SELECT * FROM identity_events WHERE account_id=? AND org_id=? ORDER BY event_time ASC",
                (account_id, org_id),
            ).fetchall()
            entitlements = conn.execute(
                "SELECT * FROM access_entitlements WHERE account_id=? AND org_id=? AND status='active' ORDER BY granted_at DESC",
                (account_id, org_id),
            ).fetchall()

        account["events"] = [self._row(e) for e in events]
        account["active_entitlements"] = [self._row(e) for e in entitlements]
        return account

    def list_accounts(
        self,
        org_id: str,
        status: Optional[str] = None,
        department: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List accounts for org, optionally filtered by status and department."""
        query = "SELECT * FROM identity_accounts WHERE org_id=?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if department:
            query += " AND department=?"
            params.append(department)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_orphan_accounts(
        self,
        org_id: str,
        days_inactive: int = 90,
    ) -> List[Dict[str, Any]]:
        """Return active non-service accounts inactive for >= days_inactive days."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM identity_accounts
                   WHERE org_id=?
                     AND status='active'
                     AND account_type != 'service'
                     AND (
                         last_active IS NULL
                         OR (julianday('now') - julianday(last_active)) >= ?
                     )
                   ORDER BY last_active ASC NULLS FIRST""",
                (org_id, days_inactive),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_entitlement_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate summary for the org."""
        with self._conn() as conn:
            total_accounts = conn.execute(
                "SELECT COUNT(*) FROM identity_accounts WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_accounts = conn.execute(
                "SELECT COUNT(*) FROM identity_accounts WHERE org_id=? AND status='active'", (org_id,)
            ).fetchone()[0]

            deprovisioned_count = conn.execute(
                "SELECT COUNT(*) FROM identity_accounts WHERE org_id=? AND status='deprovisioned'", (org_id,)
            ).fetchone()[0]

            total_entitlements = conn.execute(
                "SELECT COUNT(*) FROM access_entitlements WHERE org_id=? AND status='active'", (org_id,)
            ).fetchone()[0]

            by_type_rows = conn.execute(
                """SELECT account_type, COUNT(*) AS cnt
                   FROM identity_accounts WHERE org_id=?
                   GROUP BY account_type""",
                (org_id,),
            ).fetchall()

            by_dept_rows = conn.execute(
                """SELECT department, COUNT(*) AS cnt
                   FROM identity_accounts WHERE org_id=?
                   GROUP BY department""",
                (org_id,),
            ).fetchall()

        orphans = self.get_orphan_accounts(org_id)

        return {
            "total_accounts": total_accounts,
            "active_accounts": active_accounts,
            "orphan_count": len(orphans),
            "deprovisioned_count": deprovisioned_count,
            "total_entitlements": total_entitlements,
            "by_account_type": {r["account_type"]: r["cnt"] for r in by_type_rows},
            "by_department": {r["department"]: r["cnt"] for r in by_dept_rows},
        }
