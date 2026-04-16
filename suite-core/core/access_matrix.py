"""
Access Control Matrix for ALDECI.

Maps who can access what — SQLite-backed, fine-grained resource-level
access control on top of the existing RBAC layer.

Compliance: SOC2 CC6.1, CC6.3 (Logical and physical access controls)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================


class AccessLevel(str, Enum):
    """Ordered access levels (higher ordinal = more privilege)."""

    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    OWNER = "owner"

    @property
    def ordinal(self) -> int:
        _ord = {"none": 0, "read": 1, "write": 2, "admin": 3, "owner": 4}
        return _ord[self.value]

    def __ge__(self, other: "AccessLevel") -> bool:  # type: ignore[override]
        return self.ordinal >= other.ordinal

    def __gt__(self, other: "AccessLevel") -> bool:  # type: ignore[override]
        return self.ordinal > other.ordinal

    def __le__(self, other: "AccessLevel") -> bool:  # type: ignore[override]
        return self.ordinal <= other.ordinal

    def __lt__(self, other: "AccessLevel") -> bool:  # type: ignore[override]
        return self.ordinal < other.ordinal


class ResourceType(str, Enum):
    """Resource types managed by the access matrix."""

    FINDING = "finding"
    ASSET = "asset"
    REPORT = "report"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"
    CONFIG = "config"
    AUDIT_LOG = "audit_log"
    DASHBOARD = "dashboard"


# ============================================================================
# MODELS
# ============================================================================


class AccessRule(BaseModel):
    """A single access-control rule stored in the matrix."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: str
    resource_type: ResourceType
    resource_id: Optional[str] = None  # None means "all resources of this type"
    access_level: AccessLevel
    conditions: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = "default"
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "role": self.role,
            "resource_type": self.resource_type.value,
            "resource_id": self.resource_id,
            "access_level": self.access_level.value,
            "conditions": self.conditions,
            "org_id": self.org_id,
            "created_at": self.created_at,
        }


class AccessCheckResult(BaseModel):
    """Result of a single access-check decision."""

    user_role: str
    resource_type: str
    resource_id: Optional[str]
    access_level: AccessLevel
    granted: bool
    rule_id: Optional[str] = None
    checked_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ============================================================================
# DEFAULT RULES
# ============================================================================

# Built-in access rules for the 6 ALDECI roles.
# Rules with resource_id=None apply to ALL resources of that type.
_DEFAULT_RULES: List[Dict[str, Any]] = [
    # ── viewer ──────────────────────────────────────────────────────────────
    {"role": "viewer", "resource_type": "finding",    "access_level": "read"},
    {"role": "viewer", "resource_type": "asset",      "access_level": "read"},
    {"role": "viewer", "resource_type": "report",     "access_level": "read"},
    {"role": "viewer", "resource_type": "compliance", "access_level": "read"},
    {"role": "viewer", "resource_type": "dashboard",  "access_level": "read"},
    {"role": "viewer", "resource_type": "incident",   "access_level": "none"},
    {"role": "viewer", "resource_type": "config",     "access_level": "none"},
    {"role": "viewer", "resource_type": "audit_log",  "access_level": "none"},

    # ── developer ────────────────────────────────────────────────────────────
    {"role": "developer", "resource_type": "finding",    "access_level": "write"},
    {"role": "developer", "resource_type": "asset",      "access_level": "read"},
    {"role": "developer", "resource_type": "report",     "access_level": "read"},
    {"role": "developer", "resource_type": "compliance", "access_level": "read"},
    {"role": "developer", "resource_type": "dashboard",  "access_level": "read"},
    {"role": "developer", "resource_type": "incident",   "access_level": "read"},
    {"role": "developer", "resource_type": "config",     "access_level": "none"},
    {"role": "developer", "resource_type": "audit_log",  "access_level": "none"},

    # ── security_analyst ─────────────────────────────────────────────────────
    {"role": "security_analyst", "resource_type": "finding",    "access_level": "write"},
    {"role": "security_analyst", "resource_type": "asset",      "access_level": "write"},
    {"role": "security_analyst", "resource_type": "report",     "access_level": "write"},
    {"role": "security_analyst", "resource_type": "compliance", "access_level": "read"},
    {"role": "security_analyst", "resource_type": "dashboard",  "access_level": "read"},
    {"role": "security_analyst", "resource_type": "incident",   "access_level": "write"},
    {"role": "security_analyst", "resource_type": "config",     "access_level": "read"},
    {"role": "security_analyst", "resource_type": "audit_log",  "access_level": "read"},

    # ── compliance_officer ───────────────────────────────────────────────────
    {"role": "compliance_officer", "resource_type": "finding",    "access_level": "read"},
    {"role": "compliance_officer", "resource_type": "asset",      "access_level": "read"},
    {"role": "compliance_officer", "resource_type": "report",     "access_level": "write"},
    {"role": "compliance_officer", "resource_type": "compliance", "access_level": "admin"},
    {"role": "compliance_officer", "resource_type": "dashboard",  "access_level": "read"},
    {"role": "compliance_officer", "resource_type": "incident",   "access_level": "read"},
    {"role": "compliance_officer", "resource_type": "config",     "access_level": "read"},
    {"role": "compliance_officer", "resource_type": "audit_log",  "access_level": "read"},

    # ── admin ─────────────────────────────────────────────────────────────────
    {"role": "admin", "resource_type": "finding",    "access_level": "admin"},
    {"role": "admin", "resource_type": "asset",      "access_level": "admin"},
    {"role": "admin", "resource_type": "report",     "access_level": "admin"},
    {"role": "admin", "resource_type": "compliance", "access_level": "admin"},
    {"role": "admin", "resource_type": "dashboard",  "access_level": "admin"},
    {"role": "admin", "resource_type": "incident",   "access_level": "admin"},
    {"role": "admin", "resource_type": "config",     "access_level": "admin"},
    {"role": "admin", "resource_type": "audit_log",  "access_level": "admin"},

    # ── super_admin ───────────────────────────────────────────────────────────
    {"role": "super_admin", "resource_type": "finding",    "access_level": "owner"},
    {"role": "super_admin", "resource_type": "asset",      "access_level": "owner"},
    {"role": "super_admin", "resource_type": "report",     "access_level": "owner"},
    {"role": "super_admin", "resource_type": "compliance", "access_level": "owner"},
    {"role": "super_admin", "resource_type": "dashboard",  "access_level": "owner"},
    {"role": "super_admin", "resource_type": "incident",   "access_level": "owner"},
    {"role": "super_admin", "resource_type": "config",     "access_level": "owner"},
    {"role": "super_admin", "resource_type": "audit_log",  "access_level": "owner"},
]


# ============================================================================
# ACCESS MATRIX
# ============================================================================


class AccessMatrix:
    """
    SQLite-backed access control matrix.

    Stores fine-grained rules that map (role, resource_type, resource_id)
    to an AccessLevel.  Every access check is logged to an audit table so
    security teams can review who accessed what.
    """

    def __init__(self, db_path: str = "data/access_matrix.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()
        self._seed_defaults()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_tables(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS access_rules (
                    id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT,
                    access_level TEXT NOT NULL,
                    conditions TEXT NOT NULL DEFAULT '{}',
                    org_id TEXT NOT NULL DEFAULT 'default',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_audit (
                    id TEXT PRIMARY KEY,
                    user_role TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT,
                    access_level TEXT NOT NULL,
                    granted INTEGER NOT NULL,
                    rule_id TEXT,
                    checked_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rules_role
                    ON access_rules(role);
                CREATE INDEX IF NOT EXISTS idx_rules_resource_type
                    ON access_rules(resource_type);
                CREATE INDEX IF NOT EXISTS idx_rules_org
                    ON access_rules(org_id);
                CREATE INDEX IF NOT EXISTS idx_audit_role
                    ON access_audit(user_role);
                CREATE INDEX IF NOT EXISTS idx_audit_resource
                    ON access_audit(resource_type, resource_id);
                CREATE INDEX IF NOT EXISTS idx_audit_checked_at
                    ON access_audit(checked_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _seed_defaults(self) -> None:
        """Insert built-in rules if the table is empty."""
        conn = self._connect()
        try:
            count = conn.execute("SELECT COUNT(*) FROM access_rules").fetchone()[0]
            if count > 0:
                return
            now = datetime.now(timezone.utc).isoformat()
            for r in _DEFAULT_RULES:
                conn.execute(
                    """INSERT OR IGNORE INTO access_rules
                       (id, role, resource_type, resource_id, access_level,
                        conditions, org_id, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()),
                        r["role"],
                        r["resource_type"],
                        r.get("resource_id"),
                        r["access_level"],
                        json.dumps(r.get("conditions", {})),
                        r.get("org_id", "default"),
                        now,
                    ),
                )
            conn.commit()
            _logger.info("Seeded %d default access rules", len(_DEFAULT_RULES))
        finally:
            conn.close()

    def _row_to_rule(self, row: sqlite3.Row) -> AccessRule:
        return AccessRule(
            id=row["id"],
            role=row["role"],
            resource_type=ResourceType(row["resource_type"]),
            resource_id=row["resource_id"],
            access_level=AccessLevel(row["access_level"]),
            conditions=json.loads(row["conditions"]) if row["conditions"] else {},
            org_id=row["org_id"],
            created_at=row["created_at"],
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def grant_access(
        self,
        role: str,
        resource_type: ResourceType,
        access_level: AccessLevel,
        resource_id: Optional[str] = None,
        conditions: Optional[Dict[str, Any]] = None,
        org_id: str = "default",
    ) -> AccessRule:
        """Create (or replace) an access rule."""
        rule = AccessRule(
            role=role,
            resource_type=resource_type,
            resource_id=resource_id,
            access_level=access_level,
            conditions=conditions or {},
            org_id=org_id,
        )
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO access_rules
                   (id, role, resource_type, resource_id, access_level,
                    conditions, org_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rule.id,
                    rule.role,
                    rule.resource_type.value,
                    rule.resource_id,
                    rule.access_level.value,
                    json.dumps(rule.conditions),
                    rule.org_id,
                    rule.created_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        _logger.info(
            "Granted %s → %s/%s = %s",
            role,
            resource_type.value,
            resource_id or "*",
            access_level.value,
        )
        return rule

    def revoke_access(self, rule_id: str) -> bool:
        """Remove an access rule by ID. Returns True if a rule was deleted."""
        conn = self._connect()
        try:
            cur = conn.execute("DELETE FROM access_rules WHERE id = ?", (rule_id,))
            conn.commit()
            deleted = cur.rowcount > 0
        finally:
            conn.close()
        if deleted:
            _logger.info("Revoked access rule %s", rule_id)
        return deleted

    def check_access(
        self,
        user_role: str,
        resource_type: ResourceType,
        resource_id: Optional[str] = None,
        org_id: str = "default",
        audit: bool = True,
    ) -> AccessLevel:
        """
        Return the effective AccessLevel for a (role, resource_type, resource_id).

        Resolution order (highest wins):
        1. Specific rule: role + resource_type + resource_id
        2. Wildcard rule: role + resource_type + resource_id=NULL
        3. NONE (no matching rule)
        """
        conn = self._connect()
        try:
            # Specific rule first
            specific: Optional[sqlite3.Row] = None
            if resource_id is not None:
                specific = conn.execute(
                    """SELECT * FROM access_rules
                       WHERE role = ? AND resource_type = ? AND resource_id = ?
                         AND org_id = ?
                       ORDER BY access_level DESC LIMIT 1""",
                    (user_role, resource_type.value, resource_id, org_id),
                ).fetchone()

            # Wildcard rule
            wildcard = conn.execute(
                """SELECT * FROM access_rules
                   WHERE role = ? AND resource_type = ? AND resource_id IS NULL
                     AND org_id = ?
                   ORDER BY access_level DESC LIMIT 1""",
                (user_role, resource_type.value, org_id),
            ).fetchone()
        finally:
            conn.close()

        # Pick the more permissive of specific vs wildcard
        best_row: Optional[sqlite3.Row] = None
        if specific and wildcard:
            sl = AccessLevel(specific["access_level"])
            wl = AccessLevel(wildcard["access_level"])
            best_row = specific if sl >= wl else wildcard
        elif specific:
            best_row = specific
        elif wildcard:
            best_row = wildcard

        if best_row is not None:
            level = AccessLevel(best_row["access_level"])
            rule_id: Optional[str] = best_row["id"]
        else:
            level = AccessLevel.NONE
            rule_id = None

        if audit:
            self.audit_access_check(
                user_role=user_role,
                resource_type=resource_type,
                resource_id=resource_id,
                access_level=level,
                granted=(level != AccessLevel.NONE),
                rule_id=rule_id,
            )

        return level

    def list_rules(
        self,
        role: Optional[str] = None,
        resource_type: Optional[ResourceType] = None,
        org_id: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[AccessRule]:
        """List rules, optionally filtered by role or resource type."""
        clauses: List[str] = []
        params: List[Any] = []

        if role:
            clauses.append("role = ?")
            params.append(role)
        if resource_type:
            clauses.append("resource_type = ?")
            params.append(resource_type.value)
        if org_id:
            clauses.append("org_id = ?")
            params.append(org_id)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.extend([limit, offset])

        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM access_rules {where} "  # nosec B608
                f"ORDER BY role, resource_type LIMIT ? OFFSET ?",
                params,
            ).fetchall()
            return [self._row_to_rule(r) for r in rows]
        finally:
            conn.close()

    def get_effective_permissions(
        self, user_role: str, org_id: str = "default"
    ) -> Dict[str, str]:
        """
        Return all effective permissions for a role.

        Returns a dict of resource_type -> access_level (wildcard rules only).
        """
        rules = self.list_rules(role=user_role, org_id=org_id)
        perms: Dict[str, str] = {}
        for rule in rules:
            key = rule.resource_type.value
            if rule.resource_id is None:
                # Keep the highest level seen
                current = AccessLevel(perms.get(key, "none"))
                if rule.access_level >= current:
                    perms[key] = rule.access_level.value
        return perms

    def get_resource_acl(
        self,
        resource_type: ResourceType,
        resource_id: Optional[str] = None,
        org_id: str = "default",
    ) -> List[Dict[str, Any]]:
        """
        Return the ACL for a resource — who can access it and at what level.
        """
        conn = self._connect()
        try:
            if resource_id is not None:
                rows = conn.execute(
                    """SELECT * FROM access_rules
                       WHERE resource_type = ?
                         AND (resource_id = ? OR resource_id IS NULL)
                         AND org_id = ?
                       ORDER BY role""",
                    (resource_type.value, resource_id, org_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM access_rules
                       WHERE resource_type = ? AND resource_id IS NULL
                         AND org_id = ?
                       ORDER BY role""",
                    (resource_type.value, org_id),
                ).fetchall()
            return [self._row_to_rule(r).to_dict() for r in rows]
        finally:
            conn.close()

    def audit_access_check(
        self,
        user_role: str,
        resource_type: ResourceType,
        resource_id: Optional[str],
        access_level: AccessLevel,
        granted: bool,
        rule_id: Optional[str] = None,
    ) -> None:
        """Persist an access-check decision to the audit log."""
        entry_id = str(uuid.uuid4())
        checked_at = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO access_audit
                   (id, user_role, resource_type, resource_id,
                    access_level, granted, rule_id, checked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry_id,
                    user_role,
                    resource_type.value,
                    resource_id,
                    access_level.value,
                    1 if granted else 0,
                    rule_id,
                    checked_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_access_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Aggregate statistics about access decisions.

        Returns:
            - grants_by_role: dict of role -> grant count
            - denials_by_role: dict of role -> denial count
            - most_accessed_resources: top 10 resource types by access count
            - total_checks: total audit entries
            - total_grants: granted decisions
            - total_denials: denied decisions
        """
        conn = self._connect()
        try:
            total_row = conn.execute(
                "SELECT COUNT(*) as n, SUM(granted) as g FROM access_audit"
            ).fetchone()
            total_checks: int = total_row["n"] or 0
            total_grants: int = int(total_row["g"] or 0)
            total_denials: int = total_checks - total_grants

            grants_rows = conn.execute(
                """SELECT user_role, COUNT(*) as n FROM access_audit
                   WHERE granted = 1 GROUP BY user_role ORDER BY n DESC"""
            ).fetchall()
            grants_by_role = {r["user_role"]: r["n"] for r in grants_rows}

            denials_rows = conn.execute(
                """SELECT user_role, COUNT(*) as n FROM access_audit
                   WHERE granted = 0 GROUP BY user_role ORDER BY n DESC"""
            ).fetchall()
            denials_by_role = {r["user_role"]: r["n"] for r in denials_rows}

            resource_rows = conn.execute(
                """SELECT resource_type, COUNT(*) as n FROM access_audit
                   GROUP BY resource_type ORDER BY n DESC LIMIT 10"""
            ).fetchall()
            most_accessed_resources = [
                {"resource_type": r["resource_type"], "count": r["n"]}
                for r in resource_rows
            ]

            rules_by_role_rows = conn.execute(
                """SELECT role, COUNT(*) as n FROM access_rules
                   WHERE org_id = ? GROUP BY role ORDER BY n DESC""",
                (org_id,),
            ).fetchall()
            rules_by_role = {r["role"]: r["n"] for r in rules_by_role_rows}

        finally:
            conn.close()

        return {
            "total_checks": total_checks,
            "total_grants": total_grants,
            "total_denials": total_denials,
            "grants_by_role": grants_by_role,
            "denials_by_role": denials_by_role,
            "most_accessed_resources": most_accessed_resources,
            "rules_by_role": rules_by_role,
        }


# ============================================================================
# SINGLETON FACTORY
# ============================================================================

_matrix_instance: Optional[AccessMatrix] = None


def get_access_matrix(db_path: str = "data/access_matrix.db") -> AccessMatrix:
    """Return a shared AccessMatrix instance (lazy singleton)."""
    global _matrix_instance
    if _matrix_instance is None:
        _matrix_instance = AccessMatrix(db_path=db_path)
    return _matrix_instance


__all__ = [
    "AccessLevel",
    "ResourceType",
    "AccessRule",
    "AccessCheckResult",
    "AccessMatrix",
    "get_access_matrix",
]
