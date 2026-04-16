"""Access Control Engine — ALDECI.

Manages access policies, grants, revocations, and access checks.

Features:
- Policy lifecycle (create/list/get) per resource type and action
- Grant management: grant access with optional expiry, revoke with audit trail
- Access check: list active grants for subject+resource with policy details
- Stats: by resource type, effect, grant status

Compliance: NIST SP 800-53 AC controls, ISO 27001 A.9 (Access Control),
            CIS Control 6 (Access Control Management)
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

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "access_control.db"
)

_VALID_RESOURCE_TYPES = {"file", "api", "database", "network", "application", "service"}
_VALID_ACTIONS = {"read", "write", "execute", "delete", "admin"}
_VALID_EFFECTS = {"allow", "deny"}


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class AccessPolicyCreate(BaseModel):
    name: str
    resource_type: str  # file/api/database/network/application/service
    action: str  # read/write/execute/delete/admin
    effect: str = "allow"
    conditions: Optional[Dict[str, Any]] = Field(default_factory=dict)


class GrantCreate(BaseModel):
    subject_id: str
    resource_id: str
    policy_id: str
    granted_by: str
    expires_at: Optional[str] = None


class RevokeRequest(BaseModel):
    revoked_by: str
    reason: str = ""


# ============================================================================
# ACCESS CONTROL ENGINE
# ============================================================================


class AccessControlEngine:
    """Access control engine — policies, grants, revocations, and checks."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS policies (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    name          TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    action        TEXT NOT NULL,
                    effect        TEXT NOT NULL DEFAULT 'allow',
                    conditions    TEXT NOT NULL DEFAULT '{}',
                    status        TEXT NOT NULL DEFAULT 'active',
                    created_at    TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS grants (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    subject_id   TEXT NOT NULL,
                    resource_id  TEXT NOT NULL,
                    policy_id    TEXT NOT NULL,
                    granted_by   TEXT NOT NULL,
                    granted_at   TEXT NOT NULL,
                    expires_at   TEXT,
                    status       TEXT NOT NULL DEFAULT 'active',
                    revoked_at   TEXT,
                    revoked_by   TEXT,
                    revoke_reason TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_policies_org      ON policies(org_id);
                CREATE INDEX IF NOT EXISTS idx_grants_org        ON grants(org_id);
                CREATE INDEX IF NOT EXISTS idx_grants_subject    ON grants(subject_id);
                CREATE INDEX IF NOT EXISTS idx_grants_resource   ON grants(resource_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # POLICY MANAGEMENT
    # ------------------------------------------------------------------

    def create_access_policy(self, org_id: str, data: AccessPolicyCreate) -> Dict[str, Any]:
        """Create a new access policy. Returns the policy record."""
        if data.resource_type not in _VALID_RESOURCE_TYPES:
            raise ValueError(
                f"Invalid resource_type '{data.resource_type}'. "
                f"Must be one of {sorted(_VALID_RESOURCE_TYPES)}"
            )
        if data.action not in _VALID_ACTIONS:
            raise ValueError(
                f"Invalid action '{data.action}'. "
                f"Must be one of {sorted(_VALID_ACTIONS)}"
            )
        if data.effect not in _VALID_EFFECTS:
            raise ValueError(
                f"Invalid effect '{data.effect}'. "
                f"Must be one of {sorted(_VALID_EFFECTS)}"
            )

        policy_id = str(uuid.uuid4())
        now = self._now()
        conditions_json = json.dumps(data.conditions or {})
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO policies
                   (id, org_id, name, resource_type, action, effect,
                    conditions, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    policy_id, org_id, data.name, data.resource_type,
                    data.action, data.effect, conditions_json, "active", now,
                ),
            )
        _logger.info(
            "access_control.policy_created org=%s policy_id=%s name=%s",
            org_id, policy_id, data.name,
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("IDENTITY_UPDATED", {"entity_type": "access_control", "org_id": org_id, "source_engine": "access_control"})
            except Exception:
                pass

        return self.get_access_policy(org_id, policy_id)

    def list_access_policies(
        self,
        org_id: str,
        resource_type: Optional[str] = None,
        effect: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List policies for org, optionally filtered by resource_type or effect."""
        query = "SELECT * FROM policies WHERE org_id=?"
        params: List[Any] = [org_id]
        if resource_type:
            query += " AND resource_type=?"
            params.append(resource_type)
        if effect:
            query += " AND effect=?"
            params.append(effect)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._deserialize_policy(dict(r)) for r in rows]

    def get_access_policy(self, org_id: str, policy_id: str) -> Dict[str, Any]:
        """Fetch a single policy, scoped to org_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM policies WHERE org_id=? AND id=?",
                (org_id, policy_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Policy {policy_id} not found for org {org_id}")
        return self._deserialize_policy(dict(row))

    @staticmethod
    def _deserialize_policy(row: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(row.get("conditions"), str):
            try:
                row["conditions"] = json.loads(row["conditions"])
            except (json.JSONDecodeError, TypeError):
                row["conditions"] = {}
        return row

    # ------------------------------------------------------------------
    # GRANT MANAGEMENT
    # ------------------------------------------------------------------

    def grant_access(self, org_id: str, data: GrantCreate) -> Dict[str, Any]:
        """Grant access to a subject for a resource under a policy."""
        # Verify policy belongs to org
        self.get_access_policy(org_id, data.policy_id)

        grant_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO grants
                   (id, org_id, subject_id, resource_id, policy_id,
                    granted_by, granted_at, expires_at, status)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    grant_id, org_id, data.subject_id, data.resource_id,
                    data.policy_id, data.granted_by, now,
                    data.expires_at, "active",
                ),
            )
        _logger.info(
            "access_control.grant_created org=%s grant_id=%s subject=%s resource=%s",
            org_id, grant_id, data.subject_id, data.resource_id,
        )
        return self._get_grant(org_id, grant_id)

    def list_grants(
        self,
        org_id: str,
        subject_id: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List grants for org, optionally filtered by subject or resource."""
        query = "SELECT * FROM grants WHERE org_id=?"
        params: List[Any] = [org_id]
        if subject_id:
            query += " AND subject_id=?"
            params.append(subject_id)
        if resource_id:
            query += " AND resource_id=?"
            params.append(resource_id)
        query += " ORDER BY granted_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def revoke_access(
        self,
        org_id: str,
        grant_id: str,
        revoked_by: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Revoke an active grant."""
        # Verify grant belongs to org
        self._get_grant(org_id, grant_id)

        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE grants
                   SET status='revoked', revoked_at=?, revoked_by=?, revoke_reason=?
                   WHERE org_id=? AND id=?""",
                (now, revoked_by, reason, org_id, grant_id),
            )
        _logger.info(
            "access_control.grant_revoked org=%s grant_id=%s by=%s",
            org_id, grant_id, revoked_by,
        )
        return self._get_grant(org_id, grant_id)

    def _get_grant(self, org_id: str, grant_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM grants WHERE org_id=? AND id=?",
                (org_id, grant_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Grant {grant_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # ACCESS CHECK
    # ------------------------------------------------------------------

    def check_access(
        self,
        org_id: str,
        subject_id: str,
        resource_id: str,
    ) -> List[Dict[str, Any]]:
        """Return list of active grants for subject+resource with policy details."""
        now = self._now()
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT g.*, p.name as policy_name, p.resource_type,
                          p.action, p.effect, p.conditions
                   FROM grants g
                   JOIN policies p ON g.policy_id = p.id AND g.org_id = p.org_id
                   WHERE g.org_id=? AND g.subject_id=? AND g.resource_id=?
                     AND g.status='active'
                     AND (g.expires_at IS NULL OR g.expires_at > ?)""",
                (org_id, subject_id, resource_id, now),
            ).fetchall()

        results = []
        for r in rows:
            row = dict(r)
            if isinstance(row.get("conditions"), str):
                try:
                    row["conditions"] = json.loads(row["conditions"])
                except (json.JSONDecodeError, TypeError):
                    row["conditions"] = {}
            results.append(row)
        return results

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_access_stats(self, org_id: str) -> Dict[str, Any]:
        """Return access control overview stats for org_id."""
        now = self._now()

        with self._connect() as conn:
            total_policies = conn.execute(
                "SELECT COUNT(*) FROM policies WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT resource_type, COUNT(*) as cnt FROM policies "
                "WHERE org_id=? GROUP BY resource_type",
                (org_id,),
            ).fetchall()
            by_resource_type = {r["resource_type"]: r["cnt"] for r in type_rows}

            effect_rows = conn.execute(
                "SELECT effect, COUNT(*) as cnt FROM policies "
                "WHERE org_id=? GROUP BY effect",
                (org_id,),
            ).fetchall()
            by_effect = {r["effect"]: r["cnt"] for r in effect_rows}

            total_grants = conn.execute(
                "SELECT COUNT(*) FROM grants WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_grants = conn.execute(
                "SELECT COUNT(*) FROM grants WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]

            revoked_grants = conn.execute(
                "SELECT COUNT(*) FROM grants WHERE org_id=? AND status='revoked'",
                (org_id,),
            ).fetchone()[0]

            expired_grants = conn.execute(
                "SELECT COUNT(*) FROM grants "
                "WHERE org_id=? AND status='active' AND expires_at IS NOT NULL AND expires_at < ?",
                (org_id, now),
            ).fetchone()[0]

        return {
            "total_policies": total_policies,
            "by_resource_type": by_resource_type,
            "by_effect": by_effect,
            "total_grants": total_grants,
            "active_grants": active_grants,
            "revoked_grants": revoked_grants,
            "expired_grants": expired_grants,
        }
