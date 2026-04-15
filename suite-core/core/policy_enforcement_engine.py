"""Policy Enforcement Engine — ALDECI.

Manages security policies across domains, tracks version history,
and handles exception workflows with approval lifecycle.

Compliance: NIST CSF PR.IP-1, ISO/IEC 27001 A.5, SOC 2 CC9.1
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

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "policy_enforcement.db"
)

_VALID_POLICY_DOMAINS = {"network", "identity", "data", "endpoint", "cloud", "application", "physical"}
_VALID_POLICY_TYPES = {"mandatory", "recommended", "prohibited"}
_VALID_ENFORCEMENT_MECHANISMS = {"automated", "manual", "hybrid"}
_VALID_EXCEPTION_TYPES = {"permanent", "temporary", "conditional"}
_VALID_EXCEPTION_STATUSES = {"pending", "approved", "rejected", "expired"}


class PolicyEnforcementEngine:
    """SQLite WAL-backed Policy Enforcement Engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
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
                CREATE TABLE IF NOT EXISTS enforcement_policies (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    name                 TEXT NOT NULL,
                    policy_domain        TEXT NOT NULL,
                    policy_type          TEXT NOT NULL DEFAULT 'mandatory',
                    enforcement_mechanism TEXT NOT NULL DEFAULT 'manual',
                    content              TEXT NOT NULL DEFAULT '',
                    version              TEXT NOT NULL DEFAULT '1.0',
                    version_history      TEXT NOT NULL DEFAULT '[]',
                    status               TEXT NOT NULL DEFAULT 'active',
                    created_at           TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_enf_pol_org
                    ON enforcement_policies (org_id, status);

                CREATE TABLE IF NOT EXISTS policy_exceptions (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    policy_id      TEXT NOT NULL,
                    exception_type TEXT NOT NULL DEFAULT 'temporary',
                    justification  TEXT NOT NULL DEFAULT '',
                    requested_by   TEXT NOT NULL DEFAULT '',
                    approver       TEXT,
                    status         TEXT NOT NULL DEFAULT 'pending',
                    approved_by    TEXT,
                    approved_at    TEXT,
                    expiry_date    TEXT,
                    notes          TEXT NOT NULL DEFAULT '',
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_enf_exc_org
                    ON policy_exceptions (org_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a policy. Validates name, policy_domain, policy_type, enforcement_mechanism."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        policy_domain = data.get("policy_domain", "")
        if policy_domain not in _VALID_POLICY_DOMAINS:
            raise ValueError(
                f"Invalid policy_domain {policy_domain!r}. Valid: {sorted(_VALID_POLICY_DOMAINS)}"
            )

        policy_type = data.get("policy_type", "mandatory")
        if policy_type not in _VALID_POLICY_TYPES:
            policy_type = "mandatory"

        enforcement_mechanism = data.get("enforcement_mechanism", "manual")
        if enforcement_mechanism not in _VALID_ENFORCEMENT_MECHANISMS:
            enforcement_mechanism = "manual"

        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        version = "1.0"
        content = data.get("content", "")

        initial_history = json.dumps([
            {
                "version": version,
                "content": content,
                "change_summary": "Initial version",
                "created_at": now,
            }
        ])

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO enforcement_policies
                        (id, org_id, name, policy_domain, policy_type, enforcement_mechanism,
                         content, version, version_history, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        policy_id, org_id, name, policy_domain, policy_type,
                        enforcement_mechanism, content, version, initial_history,
                        "active", now,
                    ),
                )

        return {
            "id": policy_id,
            "org_id": org_id,
            "name": name,
            "policy_domain": policy_domain,
            "policy_type": policy_type,
            "enforcement_mechanism": enforcement_mechanism,
            "content": content,
            "version": version,
            "version_history": json.loads(initial_history),
            "status": "active",
            "created_at": now,
        }

    def list_policies(
        self,
        org_id: str,
        policy_domain: Optional[str] = None,
        policy_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List policies for an org with optional filters."""
        query = "SELECT * FROM enforcement_policies WHERE org_id=?"
        params: List[Any] = [org_id]

        if policy_domain:
            query += " AND policy_domain=?"
            params.append(policy_domain)
        if policy_type:
            query += " AND policy_type=?"
            params.append(policy_type)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._policy_row_dict(r) for r in rows]

    def get_policy(self, org_id: str, policy_id: str) -> Optional[Dict[str, Any]]:
        """Return a single policy or None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM enforcement_policies WHERE org_id=? AND id=?",
                (org_id, policy_id),
            ).fetchone()
        return self._policy_row_dict(row) if row else None

    def _policy_row_dict(self, row: Any) -> Dict[str, Any]:
        d = dict(row)
        d["version_history"] = json.loads(d.get("version_history") or "[]")
        return d

    def create_policy_version(
        self,
        org_id: str,
        policy_id: str,
        content: str,
        change_summary: str,
    ) -> Optional[Dict[str, Any]]:
        """Create a new version of a policy. Increments major.minor version number."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM enforcement_policies WHERE org_id=? AND id=?",
                    (org_id, policy_id),
                ).fetchone()
                if row is None:
                    return None

                current_version = row["version"]
                history = json.loads(row["version_history"] or "[]")

                # Increment minor version (major.minor)
                try:
                    parts = current_version.split(".")
                    major = int(parts[0])
                    minor = int(parts[1]) if len(parts) > 1 else 0
                    new_version = f"{major}.{minor + 1}"
                except (ValueError, IndexError):
                    new_version = "1.1"

                now = datetime.now(timezone.utc).isoformat()
                history.append({
                    "version": new_version,
                    "content": content,
                    "change_summary": change_summary,
                    "created_at": now,
                })

                conn.execute(
                    """
                    UPDATE enforcement_policies
                       SET version=?, content=?, version_history=?
                     WHERE org_id=? AND id=?
                    """,
                    (new_version, content, json.dumps(history), org_id, policy_id),
                )

                updated = conn.execute(
                    "SELECT * FROM enforcement_policies WHERE org_id=? AND id=?",
                    (org_id, policy_id),
                ).fetchone()

        return self._policy_row_dict(updated) if updated else None

    # ------------------------------------------------------------------
    # Exceptions
    # ------------------------------------------------------------------

    def record_exception(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a policy exception request."""
        policy_id = data.get("policy_id", "").strip()
        if not policy_id:
            raise ValueError("policy_id is required")

        exception_type = data.get("exception_type", "temporary")
        if exception_type not in _VALID_EXCEPTION_TYPES:
            exception_type = "temporary"

        justification = data.get("justification", "").strip()
        if not justification:
            raise ValueError("justification is required")

        requested_by = data.get("requested_by", "").strip()
        if not requested_by:
            raise ValueError("requested_by is required")

        exception_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO policy_exceptions
                        (id, org_id, policy_id, exception_type, justification, requested_by,
                         approver, status, approved_by, approved_at, expiry_date, notes, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        exception_id, org_id, policy_id, exception_type, justification,
                        requested_by,
                        data.get("approver"),
                        "pending",
                        None, None,
                        data.get("expiry_date"),
                        data.get("notes", ""),
                        now,
                    ),
                )

        return {
            "id": exception_id,
            "org_id": org_id,
            "policy_id": policy_id,
            "exception_type": exception_type,
            "justification": justification,
            "requested_by": requested_by,
            "approver": data.get("approver"),
            "status": "pending",
            "approved_by": None,
            "approved_at": None,
            "expiry_date": data.get("expiry_date"),
            "notes": data.get("notes", ""),
            "created_at": now,
        }

    def approve_exception(
        self,
        org_id: str,
        exception_id: str,
        approved_by: str,
        notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Approve a pending exception."""
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                cursor = conn.execute(
                    """
                    UPDATE policy_exceptions
                       SET status='approved', approved_by=?, approved_at=?, notes=?
                     WHERE org_id=? AND id=?
                    """,
                    (approved_by, now, notes, org_id, exception_id),
                )
                if cursor.rowcount == 0:
                    return None
                row = conn.execute(
                    "SELECT * FROM policy_exceptions WHERE org_id=? AND id=?",
                    (org_id, exception_id),
                ).fetchone()
        return dict(row) if row else None

    def list_exceptions(
        self,
        org_id: str,
        policy_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List exceptions for an org with optional filters."""
        query = "SELECT * FROM policy_exceptions WHERE org_id=?"
        params: List[Any] = [org_id]

        if policy_id:
            query += " AND policy_id=?"
            params.append(policy_id)
        if status:
            query += " AND status=?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_enforcement_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated enforcement statistics for an org."""
        now = datetime.now(timezone.utc).isoformat()

        with self._conn() as conn:
            total_policies = conn.execute(
                "SELECT COUNT(*) FROM enforcement_policies WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            active_policies = conn.execute(
                "SELECT COUNT(*) FROM enforcement_policies WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]

            pol_rows = conn.execute(
                "SELECT policy_domain, policy_type, COUNT(*) as cnt "
                "FROM enforcement_policies WHERE org_id=? GROUP BY policy_domain, policy_type",
                (org_id,),
            ).fetchall()

            total_exceptions = conn.execute(
                "SELECT COUNT(*) FROM policy_exceptions WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            pending_exceptions = conn.execute(
                "SELECT COUNT(*) FROM policy_exceptions WHERE org_id=? AND status='pending'",
                (org_id,),
            ).fetchone()[0]

            approved_exceptions = conn.execute(
                "SELECT COUNT(*) FROM policy_exceptions WHERE org_id=? AND status='approved'",
                (org_id,),
            ).fetchone()[0]

            # Expired: approved + expiry_date is set and in the past
            expired_exceptions = conn.execute(
                "SELECT COUNT(*) FROM policy_exceptions "
                "WHERE org_id=? AND status='approved' AND expiry_date IS NOT NULL AND expiry_date < ?",
                (org_id, now),
            ).fetchone()[0]

        by_domain: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for row in pol_rows:
            domain = row["policy_domain"]
            ptype = row["policy_type"]
            cnt = row["cnt"]
            by_domain[domain] = by_domain.get(domain, 0) + cnt
            by_type[ptype] = by_type.get(ptype, 0) + cnt

        return {
            "total_policies": total_policies,
            "by_domain": by_domain,
            "by_type": by_type,
            "active_policies": active_policies,
            "total_exceptions": total_exceptions,
            "pending_exceptions": pending_exceptions,
            "approved_exceptions": approved_exceptions,
            "expired_exceptions": expired_exceptions,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_instances: Dict[str, PolicyEnforcementEngine] = {}
_instances_lock = threading.Lock()


def _db_path_for_org(org_id: str) -> str:
    base = Path(__file__).resolve().parents[2] / ".fixops_data"
    return str(base / f"policy_enforcement_{org_id}.db")


def get_engine(org_id: str) -> PolicyEnforcementEngine:
    with _instances_lock:
        if org_id not in _instances:
            _instances[org_id] = PolicyEnforcementEngine(db_path=_db_path_for_org(org_id))
        return _instances[org_id]
