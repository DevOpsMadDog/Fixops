"""Cloud Identity Engine — ALDECI.

Manages cloud identities, federated access, and cross-cloud permission analysis.

Capabilities:
  - Cloud identity registry (user/service_account/role/group/machine) with org_id isolation
  - Permission management with automatic privilege_level recalculation
  - Access review lifecycle (periodic/triggered/certification)
  - Permission change audit trail
  - Stats: by type, by provider, admin count, MFA disabled, federated count

Compliance: CIS Cloud Benchmarks, NIST SP 800-207 (Zero Trust), SOC2 CC6
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

_VALID_IDENTITY_TYPES = {"user", "service_account", "role", "group", "machine"}
_VALID_CLOUD_PROVIDERS = {"aws", "azure", "gcp", "multi_cloud"}
_VALID_PRIVILEGE_LEVELS = {"admin", "write", "read", "none"}
_VALID_REVIEW_TYPES = {"periodic", "triggered", "certification"}
_VALID_OUTCOMES = {"approved", "revoked", "modified", "no_action"}
_VALID_CHANGE_TYPES = {"grant", "revoke", "modify"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_privilege_level(permissions: List[str]) -> str:
    """Compute privilege level from a list of permission strings.

    Rules:
      - Any perm starting with 'Admin' → admin
      - Any perm starting with 'Write' → write
      - Any perms at all → read
      - Empty list → none
    """
    if not permissions:
        return "none"
    for perm in permissions:
        if perm.startswith("Admin"):
            return "admin"
    for perm in permissions:
        if perm.startswith("Write"):
            return "write"
    return "read"


class CloudIdentityEngine:
    """SQLite WAL-backed Cloud Identity engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/cloud_identity.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "cloud_identity.db")
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
                CREATE TABLE IF NOT EXISTS cloud_identities (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    identity_name   TEXT NOT NULL,
                    identity_type   TEXT NOT NULL DEFAULT 'user',
                    cloud_provider  TEXT NOT NULL DEFAULT 'aws',
                    account_id      TEXT NOT NULL DEFAULT '',
                    permissions     TEXT NOT NULL DEFAULT '[]',
                    privilege_level TEXT NOT NULL DEFAULT 'none',
                    is_federated    INTEGER NOT NULL DEFAULT 0,
                    mfa_enabled     INTEGER NOT NULL DEFAULT 0,
                    last_activity   TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ci_org
                    ON cloud_identities (org_id, identity_type, cloud_provider, privilege_level);

                CREATE TABLE IF NOT EXISTS access_reviews (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    identity_id TEXT NOT NULL,
                    reviewer    TEXT NOT NULL DEFAULT '',
                    review_type TEXT NOT NULL DEFAULT 'periodic',
                    outcome     TEXT NOT NULL DEFAULT 'no_action',
                    findings    TEXT NOT NULL DEFAULT '[]',
                    reviewed_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ar_org
                    ON access_reviews (org_id, identity_id, outcome, reviewed_at DESC);

                CREATE TABLE IF NOT EXISTS permission_changes (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    identity_id     TEXT NOT NULL,
                    change_type     TEXT NOT NULL DEFAULT 'grant',
                    permission_name TEXT NOT NULL,
                    changed_by      TEXT NOT NULL DEFAULT '',
                    changed_at      TEXT NOT NULL,
                    approved        INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_pc_org
                    ON permission_changes (org_id, identity_id, approved, changed_at DESC);
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
        for field in ("permissions", "findings"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        # Coerce booleans
        for col in ("is_federated", "mfa_enabled", "approved"):
            if col in d and d[col] is not None:
                d[col] = bool(d[col])
        return d

    # ------------------------------------------------------------------
    # Cloud Identities
    # ------------------------------------------------------------------

    def register_identity(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new cloud identity."""
        identity_name = (data.get("identity_name") or "").strip()
        if not identity_name:
            raise ValueError("identity_name is required.")

        identity_type = data.get("identity_type", "user")
        if identity_type not in _VALID_IDENTITY_TYPES:
            raise ValueError(
                f"Invalid identity_type: {identity_type!r}. "
                f"Must be one of {sorted(_VALID_IDENTITY_TYPES)}"
            )

        cloud_provider = data.get("cloud_provider", "aws")
        if cloud_provider not in _VALID_CLOUD_PROVIDERS:
            raise ValueError(
                f"Invalid cloud_provider: {cloud_provider!r}. "
                f"Must be one of {sorted(_VALID_CLOUD_PROVIDERS)}"
            )

        privilege_level = data.get("privilege_level", "none")
        if privilege_level not in _VALID_PRIVILEGE_LEVELS:
            raise ValueError(
                f"Invalid privilege_level: {privilege_level!r}. "
                f"Must be one of {sorted(_VALID_PRIVILEGE_LEVELS)}"
            )

        permissions = data.get("permissions", [])
        if not isinstance(permissions, list):
            permissions = []

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "identity_name": identity_name,
            "identity_type": identity_type,
            "cloud_provider": cloud_provider,
            "account_id": data.get("account_id", ""),
            "permissions": json.dumps(permissions),
            "privilege_level": privilege_level,
            "is_federated": int(bool(data.get("is_federated", False))),
            "mfa_enabled": int(bool(data.get("mfa_enabled", False))),
            "last_activity": data.get("last_activity"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_identities
                       (id, org_id, identity_name, identity_type, cloud_provider,
                        account_id, permissions, privilege_level, is_federated,
                        mfa_enabled, last_activity, created_at)
                       VALUES (:id, :org_id, :identity_name, :identity_type,
                               :cloud_provider, :account_id, :permissions,
                               :privilege_level, :is_federated, :mfa_enabled,
                               :last_activity, :created_at)""",
                    record,
                )
        record["permissions"] = permissions
        record["is_federated"] = bool(record["is_federated"])
        record["mfa_enabled"] = bool(record["mfa_enabled"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_identity", "org_id": org_id, "source_engine": "cloud_identity"})
            except Exception:
                pass

        return record

    def list_identities(
        self,
        org_id: str,
        identity_type: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        privilege_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List cloud identities with optional filters."""
        sql = "SELECT * FROM cloud_identities WHERE org_id = ?"
        params: list = [org_id]
        if identity_type is not None:
            sql += " AND identity_type = ?"
            params.append(identity_type)
        if cloud_provider is not None:
            sql += " AND cloud_provider = ?"
            params.append(cloud_provider)
        if privilege_level is not None:
            sql += " AND privilege_level = ?"
            params.append(privilege_level)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_identity(
        self, org_id: str, identity_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a single identity; None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM cloud_identities WHERE org_id = ? AND id = ?",
                (org_id, identity_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_permissions(
        self, org_id: str, identity_id: str, new_permissions: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Update an identity's permissions and recalculate privilege_level.

        Returns the updated identity, or None if not found.
        """
        if not isinstance(new_permissions, list):
            new_permissions = []

        privilege_level = _compute_privilege_level(new_permissions)
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE cloud_identities SET permissions = ?, privilege_level = ?, "
                    "last_activity = ? WHERE org_id = ? AND id = ?",
                    (
                        json.dumps(new_permissions),
                        privilege_level,
                        now,
                        org_id,
                        identity_id,
                    ),
                )
                if cur.rowcount == 0:
                    return None

        return self.get_identity(org_id, identity_id)

    # ------------------------------------------------------------------
    # Access Reviews
    # ------------------------------------------------------------------

    def record_access_review(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record an access review for an identity."""
        identity_id = (data.get("identity_id") or "").strip()
        if not identity_id:
            raise ValueError("identity_id is required.")

        existing = self.get_identity(org_id, identity_id)
        if existing is None:
            raise ValueError(
                f"Identity {identity_id!r} not found in org {org_id!r}."
            )

        review_type = data.get("review_type", "periodic")
        if review_type not in _VALID_REVIEW_TYPES:
            raise ValueError(
                f"Invalid review_type: {review_type!r}. "
                f"Must be one of {sorted(_VALID_REVIEW_TYPES)}"
            )

        outcome = data.get("outcome", "no_action")
        if outcome not in _VALID_OUTCOMES:
            raise ValueError(
                f"Invalid outcome: {outcome!r}. "
                f"Must be one of {sorted(_VALID_OUTCOMES)}"
            )

        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        now = _now_iso()
        review: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "identity_id": identity_id,
            "reviewer": data.get("reviewer", ""),
            "review_type": review_type,
            "outcome": outcome,
            "findings": json.dumps(findings),
            "reviewed_at": data.get("reviewed_at", now),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO access_reviews
                       (id, org_id, identity_id, reviewer, review_type,
                        outcome, findings, reviewed_at)
                       VALUES (:id, :org_id, :identity_id, :reviewer,
                               :review_type, :outcome, :findings, :reviewed_at)""",
                    review,
                )
        review["findings"] = findings
        return review

    def list_access_reviews(
        self,
        org_id: str,
        identity_id: Optional[str] = None,
        outcome: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List access reviews with optional filters."""
        sql = "SELECT * FROM access_reviews WHERE org_id = ?"
        params: list = [org_id]
        if identity_id is not None:
            sql += " AND identity_id = ?"
            params.append(identity_id)
        if outcome is not None:
            sql += " AND outcome = ?"
            params.append(outcome)
        sql += " ORDER BY reviewed_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Permission Changes
    # ------------------------------------------------------------------

    def record_permission_change(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a permission change for an identity."""
        identity_id = (data.get("identity_id") or "").strip()
        if not identity_id:
            raise ValueError("identity_id is required.")

        existing = self.get_identity(org_id, identity_id)
        if existing is None:
            raise ValueError(
                f"Identity {identity_id!r} not found in org {org_id!r}."
            )

        change_type = data.get("change_type", "grant")
        if change_type not in _VALID_CHANGE_TYPES:
            raise ValueError(
                f"Invalid change_type: {change_type!r}. "
                f"Must be one of {sorted(_VALID_CHANGE_TYPES)}"
            )

        permission_name = (data.get("permission_name") or "").strip()
        if not permission_name:
            raise ValueError("permission_name is required.")

        now = _now_iso()
        change: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "identity_id": identity_id,
            "change_type": change_type,
            "permission_name": permission_name,
            "changed_by": data.get("changed_by", ""),
            "changed_at": data.get("changed_at", now),
            "approved": int(bool(data.get("approved", False))),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO permission_changes
                       (id, org_id, identity_id, change_type, permission_name,
                        changed_by, changed_at, approved)
                       VALUES (:id, :org_id, :identity_id, :change_type,
                               :permission_name, :changed_by, :changed_at, :approved)""",
                    change,
                )
        change["approved"] = bool(change["approved"])
        return change

    def list_permission_changes(
        self,
        org_id: str,
        identity_id: Optional[str] = None,
        approved: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List permission changes with optional filters."""
        sql = "SELECT * FROM permission_changes WHERE org_id = ?"
        params: list = [org_id]
        if identity_id is not None:
            sql += " AND identity_id = ?"
            params.append(identity_id)
        if approved is not None:
            sql += " AND approved = ?"
            params.append(int(approved))
        sql += " ORDER BY changed_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_cloud_identity_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated cloud identity statistics for an org."""
        with self._conn() as conn:
            total_identities = conn.execute(
                "SELECT COUNT(*) FROM cloud_identities WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT identity_type, COUNT(*) as cnt FROM cloud_identities "
                "WHERE org_id = ? GROUP BY identity_type",
                (org_id,),
            ).fetchall()
            by_type = {r["identity_type"]: r["cnt"] for r in type_rows}

            provider_rows = conn.execute(
                "SELECT cloud_provider, COUNT(*) as cnt FROM cloud_identities "
                "WHERE org_id = ? GROUP BY cloud_provider",
                (org_id,),
            ).fetchall()
            by_provider = {r["cloud_provider"]: r["cnt"] for r in provider_rows}

            admin_count = conn.execute(
                "SELECT COUNT(*) FROM cloud_identities "
                "WHERE org_id = ? AND privilege_level = 'admin'",
                (org_id,),
            ).fetchone()[0]

            mfa_disabled_count = conn.execute(
                "SELECT COUNT(*) FROM cloud_identities "
                "WHERE org_id = ? AND mfa_enabled = 0",
                (org_id,),
            ).fetchone()[0]

            federated_count = conn.execute(
                "SELECT COUNT(*) FROM cloud_identities "
                "WHERE org_id = ? AND is_federated = 1",
                (org_id,),
            ).fetchone()[0]

            total_reviews = conn.execute(
                "SELECT COUNT(*) FROM access_reviews WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            revoked_in_reviews = conn.execute(
                "SELECT COUNT(*) FROM access_reviews "
                "WHERE org_id = ? AND outcome = 'revoked'",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_identities": total_identities,
            "by_type": by_type,
            "by_provider": by_provider,
            "admin_count": admin_count,
            "mfa_disabled_count": mfa_disabled_count,
            "federated_count": federated_count,
            "total_reviews": total_reviews,
            "revoked_in_reviews": revoked_in_reviews,
        }
