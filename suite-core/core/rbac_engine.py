"""Multi-tenant RBAC engine — role-based access control with tenant isolation."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# The 6 ALDECI roles with inheritance and scopes
# ---------------------------------------------------------------------------

ROLES: Dict[str, Dict[str, Any]] = {
    "super_admin": {
        "inherits": [],
        "scopes": ["admin:all", "read:*", "write:*", "attack:execute"],
    },
    "org_admin": {
        "inherits": ["security_engineer"],
        "scopes": ["admin:org", "read:*", "write:*"],
    },
    "security_engineer": {
        "inherits": ["analyst"],
        "scopes": ["write:findings", "write:integrations", "read:*"],
    },
    "analyst": {
        "inherits": ["viewer"],
        "scopes": ["read:findings", "read:feeds", "read:evidence", "write:comments"],
    },
    "viewer": {
        "inherits": [],
        "scopes": ["read:findings", "read:feeds"],
    },
    "auditor": {
        "inherits": ["viewer"],
        "scopes": ["read:findings", "read:evidence", "read:audit"],
    },
}

# Data classification hierarchy for wildcard resolution
_WILDCARD_PREFIXES = {"admin:all", "read:*", "write:*"}


def _scope_matches(user_scope: str, required_scope: str) -> bool:
    """Check if user_scope satisfies required_scope (handles wildcards)."""
    if user_scope == required_scope:
        return True
    if user_scope == "admin:all":
        return True
    if user_scope == "read:*" and required_scope.startswith("read:"):
        return True
    if user_scope == "write:*" and required_scope.startswith("write:"):
        return True
    return False


# ---------------------------------------------------------------------------
# RBACEngine
# ---------------------------------------------------------------------------


class RBACEngine:
    """
    Multi-tenant RBAC engine with SQLite persistence, role hierarchy,
    scope inheritance, tenant isolation, and audit trail.
    """

    def __init__(self, db_path: str = "data/rbac.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS user_roles (
                    id          TEXT PRIMARY KEY,
                    user_id     TEXT NOT NULL,
                    role        TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    assigned_by TEXT NOT NULL DEFAULT 'system',
                    assigned_at TEXT NOT NULL,
                    UNIQUE(user_id, role, org_id)
                );

                CREATE INDEX IF NOT EXISTS idx_user_roles_user_org
                    ON user_roles(user_id, org_id);

                CREATE INDEX IF NOT EXISTS idx_user_roles_org
                    ON user_roles(org_id);

                CREATE TABLE IF NOT EXISTS audit_trail (
                    id            TEXT PRIMARY KEY,
                    ts            REAL NOT NULL,
                    user_id       TEXT NOT NULL,
                    action        TEXT NOT NULL,
                    resource      TEXT NOT NULL,
                    org_id        TEXT NOT NULL,
                    allowed       INTEGER NOT NULL,
                    scope_checked TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_audit_user
                    ON audit_trail(user_id);

                CREATE INDEX IF NOT EXISTS idx_audit_org
                    ON audit_trail(org_id);
                """
            )

    # ------------------------------------------------------------------
    # Role assignment
    # ------------------------------------------------------------------

    def assign_role(
        self,
        user_id: str,
        role: str,
        org_id: str,
        assigned_by: str = "system",
    ) -> dict:
        """Assign a role to a user in an org. Returns assignment record."""
        if role not in ROLES:
            raise ValueError(f"Unknown role '{role}'. Valid roles: {list(ROLES)}")

        assignment_id = str(uuid.uuid4())
        assigned_at = _now_iso()

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO user_roles
                    (id, user_id, role, org_id, assigned_by, assigned_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (assignment_id, user_id, role, org_id, assigned_by, assigned_at),
            )

        _logger.info(
            "rbac.assign_role",
            user_id=user_id,
            role=role,
            org_id=org_id,
            assigned_by=assigned_by,
        )

        return {
            "id": assignment_id,
            "user_id": user_id,
            "role": role,
            "org_id": org_id,
            "assigned_by": assigned_by,
            "assigned_at": assigned_at,
        }

    def revoke_role(self, user_id: str, role: str, org_id: str) -> bool:
        """Revoke a role. Returns True if found and revoked."""
        with self._get_conn() as conn:
            cur = conn.execute(
                "DELETE FROM user_roles WHERE user_id=? AND role=? AND org_id=?",
                (user_id, role, org_id),
            )
        revoked = cur.rowcount > 0
        if revoked:
            _logger.info(
                "rbac.revoke_role", user_id=user_id, role=role, org_id=org_id
            )
        return revoked

    # ------------------------------------------------------------------
    # Role queries
    # ------------------------------------------------------------------

    def get_user_roles(self, user_id: str, org_id: str) -> list[str]:
        """Get all roles for a user in an org."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT role FROM user_roles WHERE user_id=? AND org_id=?",
                (user_id, org_id),
            ).fetchall()
        return [r["role"] for r in rows]

    def get_user_scopes(self, user_id: str, org_id: str) -> list[str]:
        """Get all effective scopes including inherited. Returns deduplicated list."""
        roles = self.get_user_roles(user_id, org_id)
        return self.get_effective_scopes(roles)

    # ------------------------------------------------------------------
    # Permission / tenant checks
    # ------------------------------------------------------------------

    def check_permission(
        self, user_id: str, org_id: str, required_scope: str
    ) -> bool:
        """Check if user has a specific scope. Handles wildcards (admin:all, read:*)."""
        scopes = self.get_user_scopes(user_id, org_id)
        allowed = any(_scope_matches(s, required_scope) for s in scopes)
        self.audit_log(
            user_id=user_id,
            action="check_permission",
            resource=required_scope,
            org_id=org_id,
            allowed=allowed,
            scope_checked=required_scope,
        )
        return allowed

    def check_tenant_access(
        self,
        user_id: str,
        requesting_org_id: str,
        target_org_id: str,
    ) -> bool:
        """Check if user can access data from target_org. super_admin can cross orgs."""
        if requesting_org_id == target_org_id:
            return True
        # super_admin has admin:all which grants cross-tenant access
        scopes = self.get_user_scopes(user_id, requesting_org_id)
        return "admin:all" in scopes

    # ------------------------------------------------------------------
    # Org user listing
    # ------------------------------------------------------------------

    def list_users_in_org(self, org_id: str) -> list[dict]:
        """List all users with roles in an org."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT user_id, role, assigned_by, assigned_at
                FROM user_roles WHERE org_id=?
                ORDER BY user_id, role
                """,
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Hierarchy / scope helpers
    # ------------------------------------------------------------------

    def get_role_hierarchy(self, role: str) -> list[str]:
        """Get role + all inherited roles (depth-first, deduped)."""
        seen: list[str] = []
        self._collect_hierarchy(role, seen)
        return seen

    def _collect_hierarchy(self, role: str, acc: list[str]) -> None:
        if role in acc:
            return
        acc.append(role)
        for parent in ROLES.get(role, {}).get("inherits", []):
            self._collect_hierarchy(parent, acc)

    def get_effective_scopes(self, roles: list[str]) -> list[str]:
        """Compute effective scopes for a set of roles including inheritance."""
        all_roles: list[str] = []
        for role in roles:
            for r in self.get_role_hierarchy(role):
                if r not in all_roles:
                    all_roles.append(r)

        seen: set[str] = set()
        scopes: list[str] = []
        for r in all_roles:
            for scope in ROLES.get(r, {}).get("scopes", []):
                if scope not in seen:
                    seen.add(scope)
                    scopes.append(scope)
        return scopes

    # ------------------------------------------------------------------
    # Audit trail
    # ------------------------------------------------------------------

    def audit_log(
        self,
        user_id: str,
        action: str,
        resource: str,
        org_id: str,
        allowed: bool,
        scope_checked: Optional[str] = None,
    ) -> None:
        """Log an access check to audit trail."""
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO audit_trail
                    (id, ts, user_id, action, resource, org_id, allowed, scope_checked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    time.time(),
                    user_id,
                    action,
                    resource,
                    org_id,
                    int(allowed),
                    scope_checked,
                ),
            )

    def get_audit_log(
        self,
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return audit log entries, optionally filtered by user_id and/or org_id."""
        clauses: list[str] = []
        params: list[Any] = []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if org_id is not None:
            clauses.append("org_id = ?")
            params.append(org_id)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._get_conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_trail {where} ORDER BY ts DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


__all__ = ["ROLES", "RBACEngine"]
