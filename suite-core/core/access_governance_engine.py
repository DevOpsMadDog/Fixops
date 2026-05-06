"""Access Governance Engine — ALDECI.

Identity Governance and Administration (IGA): entitlements, segregation of
duties (SoD), role management, and certification campaigns.

Compliance: NIST SP 800-53 AC-2/AC-6, ISO/IEC 27001 A.9.2, SOC 2 CC6.3
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "access_governance.db"
)

_VALID_RESOURCE_TYPES = {
    "application", "database", "server", "network",
    "cloud-service", "api", "data-store", "vault",
}
_VALID_ACCESS_LEVELS = {
    "read", "write", "admin", "execute", "delete", "full-control",
}
_VALID_ROLE_TYPES = {
    "business", "technical", "privileged", "service-account", "emergency",
}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_SOD_SEVERITIES = {"critical", "high", "medium"}
_VALID_ENTITLEMENT_STATUSES = {"active", "revoked", "expired"}
_VALID_VIOLATION_STATUSES = {"open", "acknowledged", "resolved"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AccessGovernanceEngine:
    """SQLite WAL-backed Access Governance (IGA) engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
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
                CREATE TABLE IF NOT EXISTS entitlements (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    user_id       TEXT NOT NULL,
                    resource_id   TEXT NOT NULL,
                    resource_type TEXT NOT NULL DEFAULT 'application',
                    access_level  TEXT NOT NULL DEFAULT 'read',
                    granted_by    TEXT NOT NULL DEFAULT '',
                    granted_at    TEXT NOT NULL,
                    expires_at    TEXT,
                    status        TEXT NOT NULL DEFAULT 'active',
                    last_reviewed TEXT,
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ent_org_user
                    ON entitlements (org_id, user_id, status);

                CREATE INDEX IF NOT EXISTS idx_ent_org_status
                    ON entitlements (org_id, status);

                CREATE TABLE IF NOT EXISTS sod_violations (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    user_id          TEXT NOT NULL,
                    rule_name        TEXT NOT NULL,
                    entitlement_ids  TEXT NOT NULL DEFAULT '[]',
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    detected_at      TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'open',
                    acknowledged_by  TEXT,
                    acknowledged_at  TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_sod_org_user
                    ON sod_violations (org_id, user_id);

                CREATE INDEX IF NOT EXISTS idx_sod_org_status
                    ON sod_violations (org_id, status);

                CREATE TABLE IF NOT EXISTS role_definitions (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    role_name   TEXT NOT NULL,
                    role_type   TEXT NOT NULL DEFAULT 'business',
                    permissions TEXT NOT NULL DEFAULT '[]',
                    user_count  INTEGER NOT NULL DEFAULT 0,
                    risk_level  TEXT NOT NULL DEFAULT 'medium',
                    owner       TEXT NOT NULL DEFAULT '',
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_role_org
                    ON role_definitions (org_id);
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
    # Entitlements
    # ------------------------------------------------------------------

    def grant_entitlement(
        self,
        org_id: str,
        user_id: str,
        resource_id: str,
        resource_type: str,
        access_level: str,
        granted_by: str = "",
        expires_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Grant an entitlement to a user for a resource."""
        if resource_type not in _VALID_RESOURCE_TYPES:
            raise ValueError(
                f"Invalid resource_type '{resource_type}'. "
                f"Valid: {sorted(_VALID_RESOURCE_TYPES)}"
            )
        if access_level not in _VALID_ACCESS_LEVELS:
            raise ValueError(
                f"Invalid access_level '{access_level}'. "
                f"Valid: {sorted(_VALID_ACCESS_LEVELS)}"
            )

        ent_id = str(uuid.uuid4())
        now = _now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO entitlements
                        (id, org_id, user_id, resource_id, resource_type,
                         access_level, granted_by, granted_at, expires_at,
                         status, last_reviewed, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ent_id, org_id, user_id, resource_id, resource_type,
                        access_level, granted_by, now, expires_at,
                        "active", None, now,
                    ),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM entitlements WHERE id = ?", (ent_id,)
            ).fetchone()
        return self._row(row)

    def revoke_entitlement(
        self, entitlement_id: str, org_id: str
    ) -> Dict[str, Any]:
        """Revoke an entitlement (org-scoped)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM entitlements WHERE id = ? AND org_id = ?",
                (entitlement_id, org_id),
            ).fetchone()
        if row is None:
            raise KeyError(
                f"Entitlement '{entitlement_id}' not found for org '{org_id}'"
            )

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE entitlements SET status = 'revoked' WHERE id = ? AND org_id = ?",
                    (entitlement_id, org_id),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM entitlements WHERE id = ?", (entitlement_id,)
            ).fetchone()
        return self._row(row)

    def get_user_entitlements(
        self,
        org_id: str,
        user_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return entitlements for a user, optionally filtered by status."""
        query = (
            "SELECT * FROM entitlements WHERE org_id = ? AND user_id = ?"
        )
        params: List[Any] = [org_id, user_id]

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_expiring_entitlements(
        self, org_id: str, days_ahead: int
    ) -> List[Dict[str, Any]]:
        """Return active entitlements expiring within days_ahead days."""
        now_dt = datetime.now(timezone.utc)
        future = (now_dt + timedelta(days=days_ahead)).isoformat()
        now_str = now_dt.isoformat()

        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM entitlements
                WHERE org_id = ?
                  AND status = 'active'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                  AND expires_at >= ?
                ORDER BY expires_at ASC
                """,
                (org_id, future, now_str),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # SoD Violations
    # ------------------------------------------------------------------

    def detect_sod_violations(
        self,
        org_id: str,
        user_id: str,
        sod_rules: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Detect SoD violations for a user against a list of rules.

        sod_rules: list of {rule_name: str, entitlement_ids: list[str], severity: str}
        A violation fires only when the user has ALL entitlement_ids in a rule (active).
        """
        # Fetch user's active entitlement IDs
        user_entitlements = self.get_user_entitlements(org_id, user_id, status="active")
        user_ent_ids = {e["id"] for e in user_entitlements}

        new_violations: List[Dict[str, Any]] = []

        for rule in sod_rules:
            rule_name = rule.get("rule_name", "unnamed_rule")
            required_ids = set(rule.get("entitlement_ids", []))
            severity = rule.get("severity", "medium")

            if severity not in _VALID_SOD_SEVERITIES:
                severity = "medium"

            # Only trigger if user has ALL required entitlements
            if not required_ids:
                continue
            if not required_ids.issubset(user_ent_ids):
                continue

            # Check if already open violation for same org+user+rule
            with self._conn() as conn:
                existing = conn.execute(
                    """
                    SELECT id FROM sod_violations
                    WHERE org_id = ? AND user_id = ? AND rule_name = ? AND status = 'open'
                    """,
                    (org_id, user_id, rule_name),
                ).fetchone()
            if existing:
                continue  # Don't duplicate

            viol_id = str(uuid.uuid4())
            now = _now()

            with self._lock:
                with self._conn() as conn:
                    conn.execute(
                        """
                        INSERT INTO sod_violations
                            (id, org_id, user_id, rule_name, entitlement_ids,
                             severity, detected_at, status, acknowledged_by, acknowledged_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            viol_id, org_id, user_id, rule_name,
                            json.dumps(sorted(required_ids)),
                            severity, now, "open", None, None,
                        ),
                    )

            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM sod_violations WHERE id = ?", (viol_id,)
                ).fetchone()
            new_violations.append(self._row(row))

        return new_violations

    def acknowledge_violation(
        self, violation_id: str, org_id: str, acknowledged_by: str
    ) -> Dict[str, Any]:
        """Acknowledge a SoD violation."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sod_violations WHERE id = ? AND org_id = ?",
                (violation_id, org_id),
            ).fetchone()
        if row is None:
            raise KeyError(
                f"Violation '{violation_id}' not found for org '{org_id}'"
            )

        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE sod_violations
                    SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (acknowledged_by, now, violation_id, org_id),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sod_violations WHERE id = ?", (violation_id,)
            ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Role Definitions
    # ------------------------------------------------------------------

    def create_role(
        self,
        org_id: str,
        role_name: str,
        role_type: str,
        permissions: List[str],
        owner: str = "",
        risk_level: str = "medium",
    ) -> Dict[str, Any]:
        """Create a new role definition."""
        if role_type not in _VALID_ROLE_TYPES:
            raise ValueError(
                f"Invalid role_type '{role_type}'. Valid: {sorted(_VALID_ROLE_TYPES)}"
            )
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{risk_level}'. Valid: {sorted(_VALID_RISK_LEVELS)}"
            )

        role_id = str(uuid.uuid4())
        now = _now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO role_definitions
                        (id, org_id, role_name, role_type, permissions,
                         user_count, risk_level, owner, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        role_id, org_id, role_name, role_type,
                        json.dumps(permissions), 0, risk_level, owner, now,
                    ),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM role_definitions WHERE id = ?", (role_id,)
            ).fetchone()
        return self._row(row)

    def assign_role_to_user(
        self, role_id: str, org_id: str, user_id: str
    ) -> Dict[str, Any]:
        """Assign a role to a user: increments user_count, grants per-permission entitlements."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM role_definitions WHERE id = ? AND org_id = ?",
                (role_id, org_id),
            ).fetchone()
        if row is None:
            raise KeyError(
                f"Role '{role_id}' not found for org '{org_id}'"
            )

        role = self._row(row)
        permissions = json.loads(role["permissions"]) if role["permissions"] else []

        # Increment user_count
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE role_definitions SET user_count = user_count + 1 "
                    "WHERE id = ? AND org_id = ?",
                    (role_id, org_id),
                )

        # Grant one entitlement per permission (resource_type=application, access_level=read by default)
        for permission in permissions:
            try:
                self.grant_entitlement(
                    org_id=org_id,
                    user_id=user_id,
                    resource_id=f"role:{role_id}:{permission}",
                    resource_type="application",
                    access_level="read",
                    granted_by=f"role:{role['role_name']}",
                )
            except ValueError:
                pass  # Skip invalid permission entries

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM role_definitions WHERE id = ?", (role_id,)
            ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_access_summary(self, org_id: str) -> Dict[str, Any]:
        """Return access governance summary statistics.

        Perf: collapsed 3 per-status COUNT(*) queries on entitlements into a
        single CASE-aggregate scan (3 queries → 1 for that table), reducing
        total round-trips from 5 to 3.
        """
        with self._conn() as conn:
            ent_row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'active'  THEN 1 ELSE 0 END) AS active,
                    SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END) AS revoked
                FROM entitlements
                WHERE org_id = ?
                """,
                (org_id,),
            ).fetchone()

            violations_open = conn.execute(
                "SELECT COUNT(*) FROM sod_violations WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            high_risk_roles = conn.execute(
                """
                SELECT COUNT(*) FROM role_definitions
                WHERE org_id = ? AND risk_level IN ('critical', 'high')
                """,
                (org_id,),
            ).fetchone()[0]

        return {
            "total_entitlements": ent_row[0] or 0,
            "active_entitlements": ent_row[1] or 0,
            "revoked_entitlements": ent_row[2] or 0,
            "violations_open": violations_open,
            "high_risk_roles": high_risk_roles,
        }
