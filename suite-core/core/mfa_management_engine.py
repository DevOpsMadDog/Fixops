"""MFA Management Engine — ALDECI.

Manage MFA enrollments, events, and policies across multiple authentication
factor types (TOTP, SMS, email, hardware keys, push).

Compliance: NIST SP 800-63B, FIDO2/WebAuthn, PCI DSS 4.0 req 8.5
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "mfa_management.db"
)

_VALID_MFA_TYPES = {"totp", "sms", "email", "hardware_key", "push"}
_VALID_STATUSES = {"active", "disabled", "pending"}
_VALID_EVENT_TYPES = {"enrollment", "verification", "bypass", "failure", "reset"}
_VALID_ENFORCEMENTS = {"mandatory", "optional", "disabled"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MFAManagementEngine:
    """SQLite WAL-backed MFA management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._local = threading.local()  # thread-local connection cache
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
                CREATE TABLE IF NOT EXISTS mfa_enrollments (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    user_id             TEXT NOT NULL,
                    mfa_type            TEXT NOT NULL,
                    status              TEXT NOT NULL DEFAULT 'pending',
                    enrolled_at         TEXT,
                    last_used           TEXT,
                    backup_codes_count  INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS mfa_events (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    user_id     TEXT NOT NULL,
                    event_type  TEXT NOT NULL,
                    mfa_type    TEXT NOT NULL DEFAULT '',
                    success     INTEGER NOT NULL DEFAULT 0,
                    ip_address  TEXT NOT NULL DEFAULT '',
                    created_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS mfa_policies (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    policy_name         TEXT NOT NULL,
                    required_mfa_types  TEXT NOT NULL DEFAULT '[]',
                    enforcement         TEXT NOT NULL DEFAULT 'optional',
                    grace_period_days   INTEGER NOT NULL DEFAULT 7,
                    created_at          TEXT NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        """Return a thread-local persistent connection (13x faster than per-call connect)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for f in ("required_mfa_types",):
            if f in d and isinstance(d[f], str):
                try:
                    d[f] = json.loads(d[f])
                except Exception:
                    d[f] = []
        # Convert SQLite integers back to bool for success field
        if "success" in d:
            d["success"] = bool(d["success"])
        return d

    # ------------------------------------------------------------------
    # Enrollments
    # ------------------------------------------------------------------

    def enroll_user(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new MFA enrollment in pending state."""
        user_id = data.get("user_id", "").strip()
        if not user_id:
            raise ValueError("user_id is required")
        mfa_type = data.get("mfa_type", "").strip()
        if mfa_type not in _VALID_MFA_TYPES:
            raise ValueError(f"mfa_type must be one of {sorted(_VALID_MFA_TYPES)}")

        now = _now_iso()
        rec_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO mfa_enrollments
                        (id, org_id, user_id, mfa_type, status, enrolled_at,
                         last_used, backup_codes_count, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        rec_id,
                        org_id,
                        user_id,
                        mfa_type,
                        "pending",
                        None,
                        None,
                        int(data.get("backup_codes_count", 0)),
                        now,
                    ),
                )
        return self.get_enrollment(org_id, rec_id)  # type: ignore[return-value]

    def activate_enrollment(self, org_id: str, enrollment_id: str) -> Optional[Dict[str, Any]]:
        """Set enrollment status to active and record enrolled_at timestamp."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE mfa_enrollments
                    SET status = 'active', enrolled_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (now, enrollment_id, org_id),
                )
        return self.get_enrollment(org_id, enrollment_id)

    def list_enrollments(
        self,
        org_id: str,
        user_id: Optional[str] = None,
        mfa_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List enrollments with optional filters."""
        query = "SELECT * FROM mfa_enrollments WHERE org_id = ?"
        params: list = [org_id]
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if mfa_type:
            query += " AND mfa_type = ?"
            params.append(mfa_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_enrollment(self, org_id: str, enrollment_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single enrollment, returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM mfa_enrollments WHERE id = ? AND org_id = ?",
                (enrollment_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def disable_enrollment(self, org_id: str, enrollment_id: str) -> Optional[Dict[str, Any]]:
        """Set enrollment status to disabled."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE mfa_enrollments
                    SET status = 'disabled'
                    WHERE id = ? AND org_id = ?
                    """,
                    (enrollment_id, org_id),
                )
        return self.get_enrollment(org_id, enrollment_id)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def record_mfa_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an MFA authentication event."""
        user_id = data.get("user_id", "").strip()
        if not user_id:
            raise ValueError("user_id is required")
        event_type = data.get("event_type", "").strip()
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(f"event_type must be one of {sorted(_VALID_EVENT_TYPES)}")
        success = data.get("success")
        if not isinstance(success, bool):
            raise ValueError("success must be a boolean")

        now = _now_iso()
        rec_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO mfa_events
                        (id, org_id, user_id, event_type, mfa_type, success,
                         ip_address, created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        rec_id,
                        org_id,
                        user_id,
                        event_type,
                        data.get("mfa_type", ""),
                        1 if success else 0,
                        data.get("ip_address", ""),
                        now,
                    ),
                )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM mfa_events WHERE id = ?", (rec_id,)
            ).fetchone()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("IDENTITY_UPDATED", {"entity_type": "mfa_management", "org_id": org_id, "source_engine": "mfa_management"})
            except Exception:
                pass

        return self._row(row)

    def get_mfa_events(
        self,
        org_id: str,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List MFA events with optional filters."""
        query = "SELECT * FROM mfa_events WHERE org_id = ?"
        params: list = [org_id]
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an MFA enforcement policy."""
        policy_name = data.get("policy_name", "").strip()
        if not policy_name:
            raise ValueError("policy_name is required")
        enforcement = data.get("enforcement", "optional")
        if enforcement not in _VALID_ENFORCEMENTS:
            raise ValueError(f"enforcement must be one of {sorted(_VALID_ENFORCEMENTS)}")

        required_mfa_types = data.get("required_mfa_types", [])
        now = _now_iso()
        rec_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO mfa_policies
                        (id, org_id, policy_name, required_mfa_types,
                         enforcement, grace_period_days, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        rec_id,
                        org_id,
                        policy_name,
                        json.dumps(required_mfa_types),
                        enforcement,
                        int(data.get("grace_period_days", 7)),
                        now,
                    ),
                )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM mfa_policies WHERE id = ?", (rec_id,)
            ).fetchone()
        return self._row(row)

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List all MFA policies for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM mfa_policies WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def enforce_policy(self, org_id: str, policy_id: str, user_id: str) -> Dict[str, Any]:
        """Evaluate whether a user satisfies an MFA enforcement policy.

        Returns a compliance result dict:
          - compliant (bool): True if the user meets every required MFA type in the policy
          - policy: the policy record
          - active_types: list of mfa_type values the user has active enrollments for
          - missing_types: required types the user is not yet enrolled in
          - grace_period_days: days remaining in the grace window (from policy)
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM mfa_policies WHERE id = ? AND org_id = ?",
                (policy_id, org_id),
            ).fetchone()
        if row is None:
            raise ValueError(f"Policy {policy_id!r} not found for org {org_id!r}")

        policy = self._row(row)
        required_types: List[str] = policy.get("required_mfa_types") or []

        # Fetch the user's active enrollments
        active_rows = self.list_enrollments(org_id, user_id=user_id, status="active")
        active_types: List[str] = [r["mfa_type"] for r in active_rows]

        if policy["enforcement"] == "disabled":
            # Policy is switched off — everyone is compliant trivially
            missing_types: List[str] = []
            compliant = True
        else:
            missing_types = [t for t in required_types if t not in active_types]
            if policy["enforcement"] == "mandatory":
                compliant = len(missing_types) == 0
            else:
                # optional: compliant if at least one required type is active, or no types required
                compliant = (not required_types) or bool(set(required_types) & set(active_types))

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "IDENTITY_UPDATED",
                        {
                            "entity_type": "mfa_enforce_policy",
                            "org_id": org_id,
                            "policy_id": policy_id,
                            "user_id": user_id,
                            "compliant": compliant,
                            "source_engine": "mfa_management",
                        },
                    )
            except Exception:
                pass

        return {
            "compliant": compliant,
            "policy": policy,
            "active_types": active_types,
            "missing_types": missing_types,
            "grace_period_days": policy.get("grace_period_days", 7),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_mfa_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated MFA statistics for an org."""
        with self._conn() as conn:
            # Total active enrollments
            total_enrolled = conn.execute(
                "SELECT COUNT(*) FROM mfa_enrollments WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            # By type (active only)
            by_type_rows = conn.execute(
                """
                SELECT mfa_type, COUNT(*) AS cnt
                FROM mfa_enrollments
                WHERE org_id = ? AND status = 'active'
                GROUP BY mfa_type
                """,
                (org_id,),
            ).fetchall()
            by_type = {r["mfa_type"]: r["cnt"] for r in by_type_rows}

            # Total events
            total_events = conn.execute(
                "SELECT COUNT(*) FROM mfa_events WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            # Failed events
            failed_events = conn.execute(
                "SELECT COUNT(*) FROM mfa_events WHERE org_id = ? AND success = 0",
                (org_id,),
            ).fetchone()[0]

            # Compliance rate: active / total attempted users
            total_attempts = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM mfa_enrollments WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            active_users = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM mfa_enrollments WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

        compliance_rate = (
            round(active_users / total_attempts, 4) if total_attempts > 0 else 0.0
        )

        return {
            "total_enrolled": total_enrolled,
            "by_type": by_type,
            "total_events": total_events,
            "failed_events": failed_events,
            "compliance_rate": compliance_rate,
        }
