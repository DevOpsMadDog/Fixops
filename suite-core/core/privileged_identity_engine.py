"""Privileged Identity Management Engine — ALDECI.

Manages PAM accounts, privileged sessions, and access certifications.

Features:
- Account lifecycle with risk_level auto-computation (service_account+no-MFA=high,
  admin+no-MFA=critical, else medium)
- INSERT OR IGNORE dedup on (org_id, username, system_name)
- Session open/close with duration_mins and anomaly_score clamping (0-10)
- Certification workflow: revoked → account.status=revoked, suspended → suspended
- 90-day rotation/certification overdue detection
- Summary: total, by_risk_level, active_sessions, accounts_needing_rotation, uncertified

Compliance: NIST SP 800-53 AC-2, AC-6, AU-9; CIS Control 4 (Controlled Use of Admin Privileges)
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "privileged_identity.db"
)

_VALID_ACCOUNT_TYPES = {
    "service_account", "admin", "root", "domain_admin",
    "database_admin", "application_account", "shared",
}
_VALID_SESSION_TYPES = {"ssh", "rdp", "database", "api", "console", "jump_host"}
_VALID_DECISIONS = {"approved", "revoked", "suspended"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"active", "revoked", "suspended", "inactive"}

_HIGH_RISK_ACCOUNT_TYPES = {"service_account"}
_CRITICAL_RISK_ACCOUNT_TYPES = {"admin", "root", "domain_admin", "database_admin"}


def _compute_risk_level(account_type: str, mfa_enabled: bool) -> str:
    """Auto-compute risk level based on account_type and MFA status."""
    if not mfa_enabled:
        if account_type in _CRITICAL_RISK_ACCOUNT_TYPES:
            return "critical"
        if account_type in _HIGH_RISK_ACCOUNT_TYPES:
            return "high"
    return "medium"


class PrivilegedIdentityEngine:
    """Engine for Privileged Identity Management (PIM/PAM)."""

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
                CREATE TABLE IF NOT EXISTS privileged_accounts (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    username                TEXT NOT NULL DEFAULT '',
                    account_type            TEXT NOT NULL DEFAULT 'admin',
                    system_name             TEXT NOT NULL DEFAULT '',
                    department              TEXT NOT NULL DEFAULT '',
                    owner                   TEXT NOT NULL DEFAULT '',
                    risk_level              TEXT NOT NULL DEFAULT 'medium',
                    last_used               TEXT,
                    password_last_rotated   TEXT,
                    mfa_enabled             INTEGER NOT NULL DEFAULT 0,
                    status                  TEXT NOT NULL DEFAULT 'active',
                    created_at              TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_pa_dedup
                    ON privileged_accounts(org_id, username, system_name);
                CREATE INDEX IF NOT EXISTS idx_pa_org
                    ON privileged_accounts(org_id);
                CREATE INDEX IF NOT EXISTS idx_pa_risk
                    ON privileged_accounts(org_id, risk_level);

                CREATE TABLE IF NOT EXISTS privileged_sessions (
                    id                  TEXT PRIMARY KEY,
                    account_id          TEXT NOT NULL,
                    org_id              TEXT NOT NULL,
                    session_type        TEXT NOT NULL DEFAULT 'ssh',
                    target_system       TEXT NOT NULL DEFAULT '',
                    started_at          TEXT NOT NULL,
                    ended_at            TEXT,
                    duration_mins       REAL NOT NULL DEFAULT 0.0,
                    commands_executed   INTEGER NOT NULL DEFAULT 0,
                    anomaly_score       REAL NOT NULL DEFAULT 0.0,
                    recorded            INTEGER NOT NULL DEFAULT 1,
                    status              TEXT NOT NULL DEFAULT 'active',
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ps_org
                    ON privileged_sessions(org_id);
                CREATE INDEX IF NOT EXISTS idx_ps_account
                    ON privileged_sessions(account_id, org_id);
                CREATE INDEX IF NOT EXISTS idx_ps_status
                    ON privileged_sessions(org_id, status);

                CREATE TABLE IF NOT EXISTS access_certifications (
                    id                  TEXT PRIMARY KEY,
                    account_id          TEXT NOT NULL,
                    org_id              TEXT NOT NULL,
                    certified_by        TEXT NOT NULL DEFAULT '',
                    decision            TEXT NOT NULL DEFAULT 'approved',
                    certification_date  TEXT NOT NULL,
                    next_certification  TEXT NOT NULL DEFAULT '',
                    justification       TEXT NOT NULL DEFAULT '',
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ac_account
                    ON access_certifications(account_id, org_id);
                CREATE INDEX IF NOT EXISTS idx_ac_org
                    ON access_certifications(org_id);
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
    # ACCOUNTS
    # ------------------------------------------------------------------

    def register_account(
        self,
        org_id: str,
        username: str,
        account_type: str,
        system_name: str,
        department: str,
        owner: str,
        mfa_enabled: bool = False,
    ) -> Dict[str, Any]:
        """Register a privileged account. Deduped on (org_id, username, system_name).

        Risk level auto-computed:
          - service_account + no MFA → high
          - admin/root/domain_admin/database_admin + no MFA → critical
          - else → medium
        """
        if account_type not in _VALID_ACCOUNT_TYPES:
            raise ValueError(
                f"Invalid account_type '{account_type}'. "
                f"Must be one of {sorted(_VALID_ACCOUNT_TYPES)}"
            )

        account_id = str(uuid.uuid4())
        now = self._now()
        risk_level = _compute_risk_level(account_type, mfa_enabled)
        mfa_int = 1 if mfa_enabled else 0

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO privileged_accounts
                   (id, org_id, username, account_type, system_name, department,
                    owner, risk_level, mfa_enabled, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,'active',?)""",
                (
                    account_id, org_id, username, account_type, system_name,
                    department, owner, risk_level, mfa_int, now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM privileged_accounts WHERE org_id=? AND username=? AND system_name=?",
                (org_id, username, system_name),
            ).fetchone()

        _logger.info(
            "pi.account_registered org=%s username=%s system=%s risk=%s",
            org_id, username, system_name, risk_level,
        )
        return self._row(row)

    def update_risk_level(
        self, account_id: str, org_id: str, risk_level: str
    ) -> Dict[str, Any]:
        """Manually override an account's risk level."""
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{risk_level}'. Must be one of {sorted(_VALID_RISK_LEVELS)}"
            )
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE privileged_accounts SET risk_level=? WHERE id=? AND org_id=?",
                (risk_level, account_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM privileged_accounts WHERE id=? AND org_id=?",
                (account_id, org_id),
            ).fetchone()
        if row is None:
            raise ValueError(f"Account '{account_id}' not found for org '{org_id}'")
        return self._row(row)

    def rotate_password(self, account_id: str, org_id: str) -> Dict[str, Any]:
        """Record a password rotation event."""
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE privileged_accounts SET password_last_rotated=? WHERE id=? AND org_id=?",
                (now, account_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM privileged_accounts WHERE id=? AND org_id=?",
                (account_id, org_id),
            ).fetchone()
        if row is None:
            raise ValueError(f"Account '{account_id}' not found for org '{org_id}'")
        _logger.info("pi.password_rotated org=%s account_id=%s", org_id, account_id)
        return self._row(row)

    def get_account(self, account_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single account scoped to org_id."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM privileged_accounts WHERE id=? AND org_id=?",
                (account_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def list_accounts(self, org_id: str) -> List[Dict[str, Any]]:
        """List all accounts for the org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM privileged_accounts WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_high_risk_accounts(self, org_id: str) -> List[Dict[str, Any]]:
        """Return accounts with risk_level in (critical, high), critical first."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM privileged_accounts
                   WHERE org_id=? AND risk_level IN ('critical','high')
                   ORDER BY CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 END,
                            created_at DESC""",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # SESSIONS
    # ------------------------------------------------------------------

    def open_session(
        self,
        account_id: str,
        org_id: str,
        session_type: str,
        target_system: str,
    ) -> Dict[str, Any]:
        """Open a new privileged session."""
        if session_type not in _VALID_SESSION_TYPES:
            raise ValueError(
                f"Invalid session_type '{session_type}'. Must be one of {sorted(_VALID_SESSION_TYPES)}"
            )
        session_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO privileged_sessions
                   (id, account_id, org_id, session_type, target_system,
                    started_at, status, created_at)
                   VALUES (?,?,?,?,?,?,'active',?)""",
                (session_id, account_id, org_id, session_type, target_system, now, now),
            )
            row = conn.execute(
                "SELECT * FROM privileged_sessions WHERE id=?", (session_id,)
            ).fetchone()
        _logger.info(
            "pi.session_opened org=%s account_id=%s session_id=%s type=%s",
            org_id, account_id, session_id, session_type,
        )
        return self._row(row)

    def close_session(
        self,
        session_id: str,
        org_id: str,
        commands_executed: int = 0,
        anomaly_score: float = 0.0,
    ) -> Dict[str, Any]:
        """Close a privileged session.

        Computes duration_mins from started_at to now.
        Clamps anomaly_score to [0.0, 10.0].
        Updates account.last_used to now.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM privileged_sessions WHERE id=? AND org_id=?",
                (session_id, org_id),
            ).fetchone()
        if row is None:
            raise ValueError(f"Session '{session_id}' not found for org '{org_id}'")

        session = self._row(row)
        now_dt = datetime.now(timezone.utc)
        ended_at = now_dt.isoformat()

        try:
            started_dt = datetime.fromisoformat(session["started_at"])
            if started_dt.tzinfo is None:
                started_dt = started_dt.replace(tzinfo=timezone.utc)
            duration_mins = (now_dt - started_dt).total_seconds() / 60.0
        except Exception:
            duration_mins = 0.0

        clamped_anomaly = max(0.0, min(10.0, float(anomaly_score)))

        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE privileged_sessions
                   SET ended_at=?, duration_mins=?, commands_executed=?,
                       anomaly_score=?, status='completed'
                   WHERE id=? AND org_id=?""",
                (ended_at, duration_mins, commands_executed,
                 clamped_anomaly, session_id, org_id),
            )
            # Update account last_used
            conn.execute(
                "UPDATE privileged_accounts SET last_used=? WHERE id=? AND org_id=?",
                (ended_at, session["account_id"], org_id),
            )
            updated = conn.execute(
                "SELECT * FROM privileged_sessions WHERE id=?", (session_id,)
            ).fetchone()

        _logger.info(
            "pi.session_closed org=%s session_id=%s duration_mins=%.2f anomaly=%.2f",
            org_id, session_id, duration_mins, clamped_anomaly,
        )
        return self._row(updated)

    def get_active_sessions(self, org_id: str) -> List[Dict[str, Any]]:
        """Return active sessions with account details via JOIN."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT ps.*, pa.username, pa.account_type, pa.risk_level
                   FROM privileged_sessions ps
                   JOIN privileged_accounts pa ON pa.id=ps.account_id AND pa.org_id=ps.org_id
                   WHERE ps.org_id=? AND ps.status='active'
                   ORDER BY ps.started_at DESC""",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_session_history(
        self, account_id: str, org_id: str, limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Return session history for an account, most recent first."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM privileged_sessions
                   WHERE account_id=? AND org_id=?
                   ORDER BY started_at DESC LIMIT ?""",
                (account_id, org_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # CERTIFICATIONS
    # ------------------------------------------------------------------

    def certify_account(
        self,
        account_id: str,
        org_id: str,
        certified_by: str,
        decision: str,
        justification: str,
        next_certification: str,
    ) -> Dict[str, Any]:
        """Certify a privileged account.

        Decision effects:
          - revoked   → account.status = revoked
          - suspended → account.status = suspended
          - approved  → no status change
        """
        if decision not in _VALID_DECISIONS:
            raise ValueError(
                f"Invalid decision '{decision}'. Must be one of {sorted(_VALID_DECISIONS)}"
            )

        cert_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO access_certifications
                   (id, account_id, org_id, certified_by, decision,
                    certification_date, next_certification, justification, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    cert_id, account_id, org_id, certified_by, decision,
                    now, next_certification, justification, now,
                ),
            )
            if decision == "revoked":
                conn.execute(
                    "UPDATE privileged_accounts SET status='revoked' WHERE id=? AND org_id=?",
                    (account_id, org_id),
                )
            elif decision == "suspended":
                conn.execute(
                    "UPDATE privileged_accounts SET status='suspended' WHERE id=? AND org_id=?",
                    (account_id, org_id),
                )

            row = conn.execute(
                "SELECT * FROM access_certifications WHERE id=?", (cert_id,)
            ).fetchone()

        _logger.info(
            "pi.account_certified org=%s account_id=%s decision=%s by=%s",
            org_id, account_id, decision, certified_by,
        )
        return self._row(row)

    def get_certifications(
        self, account_id: str, org_id: str
    ) -> List[Dict[str, Any]]:
        """Return all certifications for an account."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM access_certifications
                   WHERE account_id=? AND org_id=?
                   ORDER BY certification_date DESC""",
                (account_id, org_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------------

    def get_privileged_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate summary for the org.

        - accounts_needing_rotation: password_last_rotated < 90 days ago OR NULL
        - uncertified: no certification record in the last 90 days
        - active_sessions: sessions with status=active
        - by_risk_level: count per risk level
        """
        cutoff_90 = (
            datetime.now(timezone.utc) - timedelta(days=90)
        ).isoformat()

        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM privileged_accounts WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            by_risk = conn.execute(
                """SELECT risk_level, COUNT(*) AS cnt
                   FROM privileged_accounts WHERE org_id=?
                   GROUP BY risk_level""",
                (org_id,),
            ).fetchall()

            active_sessions = conn.execute(
                "SELECT COUNT(*) FROM privileged_sessions WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]

            # Needs rotation: rotated > 90 days ago OR never rotated
            needs_rotation = conn.execute(
                """SELECT COUNT(*) FROM privileged_accounts
                   WHERE org_id=?
                     AND (password_last_rotated IS NULL OR password_last_rotated < ?)""",
                (org_id, cutoff_90),
            ).fetchone()[0]

            # Uncertified: no certification in past 90 days
            uncertified = conn.execute(
                """SELECT COUNT(*) FROM privileged_accounts pa
                   WHERE pa.org_id=?
                     AND NOT EXISTS (
                         SELECT 1 FROM access_certifications ac
                         WHERE ac.account_id=pa.id AND ac.org_id=pa.org_id
                           AND ac.certification_date >= ?
                     )""",
                (org_id, cutoff_90),
            ).fetchone()[0]

        return {
            "total": total,
            "by_risk_level": {r["risk_level"]: r["cnt"] for r in by_risk},
            "active_sessions": active_sessions,
            "accounts_needing_rotation": needs_rotation,
            "uncertified": uncertified,
        }
