"""Identity Governance Engine — ALDECI.

User access reviews and entitlement management.

Capabilities:
  - Access review lifecycle (draft → in_progress → completed/overdue)
  - Review item decisions (approved/revoked/pending) per identity
  - Entitlement registry with orphan/excessive flagging
  - Access policy management (SoD, least privilege, recertification)
  - Stats aggregation per org

Compliance: SOX, SOC2 CC6.2, ISO 27001 A.9, NIST SP 800-53 (AC-2, AC-6)
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

_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_REVIEW_TYPES = {"quarterly", "annual", "triggered", "ad_hoc"}
_VALID_REVIEW_STATUSES = {"draft", "in_progress", "completed", "overdue"}
_VALID_IDENTITY_TYPES = {"user", "service_account", "api_key", "role"}
_VALID_ENTITLEMENT_LEVELS = {"read", "write", "admin", "owner"}
_VALID_DECISIONS = {"approved", "revoked", "pending"}
_VALID_POLICY_TYPES = {
    "separation_of_duties", "least_privilege", "recertification", "max_entitlements"
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path_for_org(org_id: str) -> str:
    return str(_DEFAULT_DATA_DIR / f"{org_id}_identity_governance.db")


class IdentityGovernanceEngine:
    """SQLite WAL-backed identity governance engine.

    Thread-safe via per-org RLock. Multi-tenant via org_id.
    Each org gets its own database file.
    """

    def __init__(self) -> None:
        self._locks: Dict[str, threading.RLock] = {}
        self._locks_meta = threading.Lock()
        self._dbs: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_lock(self, org_id: str) -> threading.RLock:
        with self._locks_meta:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _db_path(self, org_id: str) -> str:
        if org_id not in self._dbs:
            self._dbs[org_id] = _db_path_for_org(org_id)
        return self._dbs[org_id]

    def _conn(self, org_id: str) -> sqlite3.Connection:
        db_path = self._db_path(org_id)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _ensure_schema(self, org_id: str) -> None:
        with self._conn(org_id) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS access_reviews (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    review_type         TEXT NOT NULL DEFAULT 'quarterly',
                    status              TEXT NOT NULL DEFAULT 'draft',
                    reviewer_id         TEXT NOT NULL DEFAULT '',
                    total_identities    INTEGER NOT NULL DEFAULT 0,
                    reviewed_count      INTEGER NOT NULL DEFAULT 0,
                    approved_count      INTEGER NOT NULL DEFAULT 0,
                    revoked_count       INTEGER NOT NULL DEFAULT 0,
                    start_date          TEXT NOT NULL DEFAULT '',
                    due_date            TEXT NOT NULL DEFAULT '',
                    completed_date      TEXT,
                    created_at          TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ar_org_status
                    ON access_reviews (org_id, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS review_items (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    review_id           TEXT NOT NULL,
                    identity_id         TEXT NOT NULL,
                    identity_name       TEXT NOT NULL DEFAULT '',
                    identity_type       TEXT NOT NULL DEFAULT 'user',
                    entitlement         TEXT NOT NULL DEFAULT '',
                    entitlement_level   TEXT NOT NULL DEFAULT 'read',
                    last_used           TEXT,
                    risk_score          REAL NOT NULL DEFAULT 0.0,
                    reviewer_decision   TEXT,
                    reviewer_notes      TEXT NOT NULL DEFAULT '',
                    reviewed_at         TEXT,
                    created_at          TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ri_org_review
                    ON review_items (org_id, review_id);
                CREATE INDEX IF NOT EXISTS idx_ri_org_identity
                    ON review_items (org_id, identity_id);

                CREATE TABLE IF NOT EXISTS identity_entitlements (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    identity_id     TEXT NOT NULL,
                    identity_name   TEXT NOT NULL DEFAULT '',
                    identity_type   TEXT NOT NULL DEFAULT 'user',
                    entitlement     TEXT NOT NULL DEFAULT '',
                    system          TEXT NOT NULL DEFAULT '',
                    granted_date    TEXT NOT NULL DEFAULT '',
                    last_used       TEXT,
                    is_orphaned     INTEGER NOT NULL DEFAULT 0,
                    is_excessive    INTEGER NOT NULL DEFAULT 0,
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    created_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ie_org_identity
                    ON identity_entitlements (org_id, identity_id);
                CREATE INDEX IF NOT EXISTS idx_ie_org_orphaned
                    ON identity_entitlements (org_id, is_orphaned);

                CREATE TABLE IF NOT EXISTS access_policies (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    policy_name      TEXT NOT NULL,
                    policy_type      TEXT NOT NULL DEFAULT 'least_privilege',
                    conditions       TEXT NOT NULL DEFAULT '{}',
                    auto_remediate   INTEGER NOT NULL DEFAULT 0,
                    enabled          INTEGER NOT NULL DEFAULT 1,
                    violation_count  INTEGER NOT NULL DEFAULT 0,
                    created_at       TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ap_org
                    ON access_policies (org_id, policy_type);
                """
            )

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Access Reviews
    # ------------------------------------------------------------------

    def create_review(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new access review. Returns the created record."""
        self._ensure_schema(org_id)
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")
        review_type = data.get("review_type", "quarterly")
        if review_type not in _VALID_REVIEW_TYPES:
            raise ValueError(f"Invalid review_type: {review_type}. Must be one of {_VALID_REVIEW_TYPES}")

        now = _now_iso()
        review: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "review_type": review_type,
            "status": "draft",
            "reviewer_id": data.get("reviewer_id", ""),
            "total_identities": 0,
            "reviewed_count": 0,
            "approved_count": 0,
            "revoked_count": 0,
            "start_date": data.get("start_date", now),
            "due_date": data.get("due_date", ""),
            "completed_date": None,
            "created_at": now,
        }
        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO access_reviews
                       (id, org_id, name, review_type, status, reviewer_id,
                        total_identities, reviewed_count, approved_count, revoked_count,
                        start_date, due_date, completed_date, created_at)
                       VALUES (:id, :org_id, :name, :review_type, :status, :reviewer_id,
                               :total_identities, :reviewed_count, :approved_count, :revoked_count,
                               :start_date, :due_date, :completed_date, :created_at)""",
                    review,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "identity_governance", "org_id": org_id, "source_engine": "identity_governance"})
            except Exception:
                pass

        return review

    def list_reviews(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List access reviews, optionally filtered by status."""
        self._ensure_schema(org_id)
        sql = "SELECT * FROM access_reviews WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_review(self, org_id: str, review_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a review with item summary."""
        self._ensure_schema(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM access_reviews WHERE org_id = ? AND id = ?",
                (org_id, review_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            # Item summary
            items_total = conn.execute(
                "SELECT COUNT(*) FROM review_items WHERE org_id = ? AND review_id = ?",
                (org_id, review_id),
            ).fetchone()[0]
            items_decided = conn.execute(
                """SELECT COUNT(*) FROM review_items
                   WHERE org_id = ? AND review_id = ? AND reviewer_decision IS NOT NULL
                     AND reviewer_decision != 'pending'""",
                (org_id, review_id),
            ).fetchone()[0]
            result["items_total"] = items_total
            result["items_decided"] = items_decided
        return result

    # ------------------------------------------------------------------
    # Review Items
    # ------------------------------------------------------------------

    def add_review_item(
        self, org_id: str, review_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add an identity/entitlement item to a review."""
        self._ensure_schema(org_id)
        identity_id = (data.get("identity_id") or "").strip()
        if not identity_id:
            raise ValueError("identity_id is required.")
        identity_type = data.get("identity_type", "user")
        if identity_type not in _VALID_IDENTITY_TYPES:
            raise ValueError(f"Invalid identity_type: {identity_type}")
        entitlement_level = data.get("entitlement_level", "read")
        if entitlement_level not in _VALID_ENTITLEMENT_LEVELS:
            raise ValueError(f"Invalid entitlement_level: {entitlement_level}")

        now = _now_iso()
        item: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "review_id": review_id,
            "identity_id": identity_id,
            "identity_name": data.get("identity_name", ""),
            "identity_type": identity_type,
            "entitlement": data.get("entitlement", ""),
            "entitlement_level": entitlement_level,
            "last_used": data.get("last_used"),
            "risk_score": float(data.get("risk_score", 0.0)),
            "reviewer_decision": None,
            "reviewer_notes": "",
            "reviewed_at": None,
            "created_at": now,
        }
        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO review_items
                       (id, org_id, review_id, identity_id, identity_name, identity_type,
                        entitlement, entitlement_level, last_used, risk_score,
                        reviewer_decision, reviewer_notes, reviewed_at, created_at)
                       VALUES (:id, :org_id, :review_id, :identity_id, :identity_name, :identity_type,
                               :entitlement, :entitlement_level, :last_used, :risk_score,
                               :reviewer_decision, :reviewer_notes, :reviewed_at, :created_at)""",
                    item,
                )
                # Increment total_identities on review
                conn.execute(
                    "UPDATE access_reviews SET total_identities = total_identities + 1 WHERE org_id = ? AND id = ?",
                    (org_id, review_id),
                )
        return item

    def submit_decision(
        self,
        org_id: str,
        item_id: str,
        decision: str,
        reviewer_id: str,
        notes: str = "",
    ) -> bool:
        """Record a reviewer decision for a review item. Returns True if found."""
        self._ensure_schema(org_id)
        if decision not in _VALID_DECISIONS:
            raise ValueError(f"Invalid decision: {decision}. Must be one of {_VALID_DECISIONS}")
        now = _now_iso()
        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                # Fetch item to get review_id and previous decision
                row = conn.execute(
                    "SELECT review_id, reviewer_decision FROM review_items WHERE org_id = ? AND id = ?",
                    (org_id, item_id),
                ).fetchone()
                if not row:
                    return False
                review_id = row["review_id"]
                prev_decision = row["reviewer_decision"]

                conn.execute(
                    """UPDATE review_items
                       SET reviewer_decision = ?, reviewer_notes = ?, reviewed_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (decision, notes, now, org_id, item_id),
                )
                # Update review counts
                if prev_decision != decision:
                    # Only count transitions from no-decision or pending → decided
                    if decision in ("approved", "revoked"):
                        if prev_decision not in ("approved", "revoked"):
                            # First real decision on this item
                            conn.execute(
                                "UPDATE access_reviews SET reviewed_count = reviewed_count + 1 WHERE org_id = ? AND id = ?",
                                (org_id, review_id),
                            )
                        if decision == "approved":
                            conn.execute(
                                "UPDATE access_reviews SET approved_count = approved_count + 1 WHERE org_id = ? AND id = ?",
                                (org_id, review_id),
                            )
                        elif decision == "revoked":
                            conn.execute(
                                "UPDATE access_reviews SET revoked_count = revoked_count + 1 WHERE org_id = ? AND id = ?",
                                (org_id, review_id),
                            )
        return True

    def complete_review(self, org_id: str, review_id: str) -> Optional[Dict[str, Any]]:
        """Mark a review as completed and compute final metrics."""
        self._ensure_schema(org_id)
        now = _now_iso()
        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                # Recount from items
                approved = conn.execute(
                    "SELECT COUNT(*) FROM review_items WHERE org_id = ? AND review_id = ? AND reviewer_decision = 'approved'",
                    (org_id, review_id),
                ).fetchone()[0]
                revoked = conn.execute(
                    "SELECT COUNT(*) FROM review_items WHERE org_id = ? AND review_id = ? AND reviewer_decision = 'revoked'",
                    (org_id, review_id),
                ).fetchone()[0]
                reviewed = conn.execute(
                    "SELECT COUNT(*) FROM review_items WHERE org_id = ? AND review_id = ? AND reviewer_decision IN ('approved','revoked')",
                    (org_id, review_id),
                ).fetchone()[0]

                conn.execute(
                    """UPDATE access_reviews
                       SET status = 'completed', completed_date = ?,
                           approved_count = ?, revoked_count = ?, reviewed_count = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, approved, revoked, reviewed, org_id, review_id),
                )
        return self.get_review(org_id, review_id)

    # ------------------------------------------------------------------
    # Entitlements
    # ------------------------------------------------------------------

    def add_entitlement(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register an entitlement for an identity."""
        self._ensure_schema(org_id)
        identity_id = (data.get("identity_id") or "").strip()
        if not identity_id:
            raise ValueError("identity_id is required.")
        identity_type = data.get("identity_type", "user")
        if identity_type not in _VALID_IDENTITY_TYPES:
            raise ValueError(f"Invalid identity_type: {identity_type}")

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "identity_id": identity_id,
            "identity_name": data.get("identity_name", ""),
            "identity_type": identity_type,
            "entitlement": data.get("entitlement", ""),
            "system": data.get("system", ""),
            "granted_date": data.get("granted_date", now),
            "last_used": data.get("last_used"),
            "is_orphaned": 1 if data.get("is_orphaned", False) else 0,
            "is_excessive": 1 if data.get("is_excessive", False) else 0,
            "risk_score": float(data.get("risk_score", 0.0)),
            "created_at": now,
        }
        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO identity_entitlements
                       (id, org_id, identity_id, identity_name, identity_type,
                        entitlement, system, granted_date, last_used,
                        is_orphaned, is_excessive, risk_score, created_at)
                       VALUES (:id, :org_id, :identity_id, :identity_name, :identity_type,
                               :entitlement, :system, :granted_date, :last_used,
                               :is_orphaned, :is_excessive, :risk_score, :created_at)""",
                    record,
                )
        return record

    def list_entitlements(
        self,
        org_id: str,
        identity_id: Optional[str] = None,
        is_orphaned: Optional[bool] = None,
        is_excessive: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List entitlements with optional filters."""
        self._ensure_schema(org_id)
        sql = "SELECT * FROM identity_entitlements WHERE org_id = ?"
        params: list = [org_id]
        if identity_id:
            sql += " AND identity_id = ?"
            params.append(identity_id)
        if is_orphaned is not None:
            sql += " AND is_orphaned = ?"
            params.append(1 if is_orphaned else 0)
        if is_excessive is not None:
            sql += " AND is_excessive = ?"
            params.append(1 if is_excessive else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def flag_orphaned(self, org_id: str, identity_id: str) -> int:
        """Mark all entitlements for identity_id as orphaned. Returns count updated."""
        self._ensure_schema(org_id)
        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    "UPDATE identity_entitlements SET is_orphaned = 1 WHERE org_id = ? AND identity_id = ?",
                    (org_id, identity_id),
                )
                return cur.rowcount

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an access policy. Returns created record."""
        self._ensure_schema(org_id)
        policy_name = (data.get("policy_name") or "").strip()
        if not policy_name:
            raise ValueError("policy_name is required.")
        policy_type = data.get("policy_type", "least_privilege")
        if policy_type not in _VALID_POLICY_TYPES:
            raise ValueError(f"Invalid policy_type: {policy_type}. Must be one of {_VALID_POLICY_TYPES}")

        now = _now_iso()
        conditions = data.get("conditions", {})
        if isinstance(conditions, dict):
            conditions_str = json.dumps(conditions)
        else:
            conditions_str = str(conditions)

        policy: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "policy_name": policy_name,
            "policy_type": policy_type,
            "conditions": conditions_str,
            "auto_remediate": 1 if data.get("auto_remediate", False) else 0,
            "enabled": 1 if data.get("enabled", True) else 0,
            "violation_count": 0,
            "created_at": now,
        }
        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO access_policies
                       (id, org_id, policy_name, policy_type, conditions,
                        auto_remediate, enabled, violation_count, created_at)
                       VALUES (:id, :org_id, :policy_name, :policy_type, :conditions,
                               :auto_remediate, :enabled, :violation_count, :created_at)""",
                    policy,
                )
        return policy

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List all access policies for an org."""
        self._ensure_schema(org_id)
        with self._conn(org_id) as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM access_policies WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_governance_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated governance stats for org."""
        self._ensure_schema(org_id)
        with self._conn(org_id) as conn:
            total_reviews = conn.execute(
                "SELECT COUNT(*) FROM access_reviews WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_status_rows = conn.execute(
                """SELECT status, COUNT(*) as cnt
                   FROM access_reviews WHERE org_id = ?
                   GROUP BY status""",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in by_status_rows}

            total_entitlements = conn.execute(
                "SELECT COUNT(*) FROM identity_entitlements WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            orphaned_count = conn.execute(
                "SELECT COUNT(*) FROM identity_entitlements WHERE org_id = ? AND is_orphaned = 1",
                (org_id,),
            ).fetchone()[0]

            excessive_count = conn.execute(
                "SELECT COUNT(*) FROM identity_entitlements WHERE org_id = ? AND is_excessive = 1",
                (org_id,),
            ).fetchone()[0]

            avg_risk = conn.execute(
                "SELECT AVG(risk_score) FROM identity_entitlements WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0] or 0.0

            overdue_reviews = conn.execute(
                "SELECT COUNT(*) FROM access_reviews WHERE org_id = ? AND status = 'overdue'",
                (org_id,),
            ).fetchone()[0]

            # Revocation rate across completed reviews
            total_revoked = conn.execute(
                "SELECT SUM(revoked_count) FROM access_reviews WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()[0] or 0
            total_reviewed = conn.execute(
                "SELECT SUM(reviewed_count) FROM access_reviews WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()[0] or 0

        revocation_rate = round(total_revoked / total_reviewed, 4) if total_reviewed > 0 else 0.0

        return {
            "total_reviews": total_reviews,
            "by_status": by_status,
            "total_entitlements": total_entitlements,
            "orphaned_count": orphaned_count,
            "excessive_count": excessive_count,
            "revocation_rate": revocation_rate,
            "avg_risk_score": round(avg_risk, 4),
            "overdue_reviews": overdue_reviews,
        }
