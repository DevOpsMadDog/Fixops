"""Data Retention Engine — ALDECI.

Manages data retention policies, lifecycle tracking, and deletion scheduling
for compliance with GDPR, CCPA, HIPAA, SOC2, and custom regulations.

Compliance: GDPR Art.5(1)(e), CCPA §1798.100, HIPAA §164.530(j), SOC 2 CC6.5
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "data_retention.db"
)

_VALID_DATA_CATEGORIES = {"logs", "pii", "financial", "audit", "backup"}
_VALID_ACTIONS = {"delete", "archive", "anonymize"}
_VALID_REGULATIONS = {"GDPR", "CCPA", "HIPAA", "SOC2", "custom"}
_VALID_EXPIRY_STATUSES = {"current", "expiring_soon", "expired"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DataRetentionEngine:
    """SQLite WAL-backed Data Retention lifecycle engine.

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
                CREATE TABLE IF NOT EXISTS retention_policies (
                    policy_id        TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    policy_name      TEXT NOT NULL,
                    data_category    TEXT NOT NULL DEFAULT 'logs',
                    retention_days   INTEGER NOT NULL DEFAULT 365,
                    action_on_expiry TEXT NOT NULL DEFAULT 'delete',
                    legal_hold       INTEGER NOT NULL DEFAULT 0,
                    regulation       TEXT NOT NULL DEFAULT 'custom',
                    created_at       TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rp_org
                    ON retention_policies (org_id, regulation);

                CREATE TABLE IF NOT EXISTS datasets (
                    dataset_id       TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    dataset_name     TEXT NOT NULL,
                    policy_id        TEXT NOT NULL,
                    location         TEXT NOT NULL DEFAULT '',
                    size_bytes       INTEGER NOT NULL DEFAULT 0,
                    record_count     INTEGER NOT NULL DEFAULT 0,
                    created_at       TEXT NOT NULL,
                    data_owner       TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'active',
                    legal_hold       INTEGER NOT NULL DEFAULT 0,
                    held_by          TEXT NOT NULL DEFAULT '',
                    hold_reason      TEXT NOT NULL DEFAULT '',
                    hold_applied_at  TEXT NOT NULL DEFAULT '',
                    scheduled_at     TEXT NOT NULL DEFAULT '',
                    scheduled_by     TEXT NOT NULL DEFAULT '',
                    deletion_notes   TEXT NOT NULL DEFAULT '',
                    deleted_at       TEXT NOT NULL DEFAULT '',
                    deleted_by       TEXT NOT NULL DEFAULT '',
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ds_org
                    ON datasets (org_id, policy_id, status);

                CREATE TABLE IF NOT EXISTS deletion_audit (
                    audit_id         TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    dataset_id       TEXT NOT NULL,
                    dataset_name     TEXT NOT NULL,
                    action           TEXT NOT NULL,
                    performed_by     TEXT NOT NULL DEFAULT '',
                    notes            TEXT NOT NULL DEFAULT '',
                    timestamp        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_da_org
                    ON deletion_audit (org_id, timestamp);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for bool_field in ("legal_hold",):
            if bool_field in d:
                d[bool_field] = bool(d[bool_field])
        return d

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a retention policy."""
        policy_id = str(uuid.uuid4())
        now = _now()

        data_category = data.get("data_category", "logs")
        if data_category not in _VALID_DATA_CATEGORIES:
            data_category = "logs"

        action_on_expiry = data.get("action_on_expiry", "delete")
        if action_on_expiry not in _VALID_ACTIONS:
            action_on_expiry = "delete"

        regulation = data.get("regulation", "custom")
        if regulation not in _VALID_REGULATIONS:
            regulation = "custom"

        legal_hold = bool(data.get("legal_hold", False))
        retention_days = int(data.get("retention_days", 365))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO retention_policies
                       (policy_id, org_id, policy_name, data_category,
                        retention_days, action_on_expiry, legal_hold,
                        regulation, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        policy_id, org_id,
                        data.get("policy_name", ""),
                        data_category, retention_days, action_on_expiry,
                        int(legal_hold), regulation, now, now,
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "data_retention", "org_id": org_id, "source_engine": "data_retention"})
            except Exception:
                pass

        return self.get_policy(org_id, policy_id)

    def list_policies(
        self, org_id: str, regulation: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List retention policies, optionally filtered by regulation."""
        with self._lock:
            with self._conn() as conn:
                if regulation:
                    rows = conn.execute(
                        "SELECT * FROM retention_policies WHERE org_id=? AND regulation=? ORDER BY created_at",
                        (org_id, regulation),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM retention_policies WHERE org_id=? ORDER BY created_at",
                        (org_id,),
                    ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_policy(self, org_id: str, policy_id: str) -> Optional[Dict[str, Any]]:
        """Get a single policy by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM retention_policies WHERE org_id=? AND policy_id=?",
                    (org_id, policy_id),
                ).fetchone()
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Datasets
    # ------------------------------------------------------------------

    def register_dataset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a dataset under a retention policy."""
        dataset_id = str(uuid.uuid4())
        now = _now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO datasets
                       (dataset_id, org_id, dataset_name, policy_id,
                        location, size_bytes, record_count, created_at,
                        data_owner, status, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        dataset_id, org_id,
                        data.get("dataset_name", ""),
                        data.get("policy_id", ""),
                        data.get("location", ""),
                        int(data.get("size_bytes", 0)),
                        int(data.get("record_count", 0)),
                        data.get("created_at", now),
                        data.get("data_owner", ""),
                        "active",
                        now,
                    ),
                )
        return self._get_dataset(org_id, dataset_id)

    def _get_dataset(self, org_id: str, dataset_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM datasets WHERE org_id=? AND dataset_id=?",
                    (org_id, dataset_id),
                ).fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        # Compute expiry_date from policy
        d["expiry_date"] = self._compute_expiry(org_id, d)
        return d

    def _compute_expiry(self, org_id: str, dataset: Dict[str, Any]) -> str:
        """Compute expiry date based on policy retention_days."""
        policy = self.get_policy(org_id, dataset.get("policy_id", ""))
        if not policy:
            return ""
        try:
            created = datetime.fromisoformat(dataset["created_at"])
            expiry = created + timedelta(days=policy["retention_days"])
            return expiry.isoformat()
        except (KeyError, ValueError):
            return ""

    def list_datasets(
        self,
        org_id: str,
        policy_id: Optional[str] = None,
        expiry_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List datasets, optionally filtered by policy_id or expiry_status."""
        with self._lock:
            with self._conn() as conn:
                if policy_id:
                    rows = conn.execute(
                        "SELECT * FROM datasets WHERE org_id=? AND policy_id=? ORDER BY created_at",
                        (org_id, policy_id),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM datasets WHERE org_id=? ORDER BY created_at",
                        (org_id,),
                    ).fetchall()

        now = datetime.now(timezone.utc)
        results = []
        for row in rows:
            d = self._row_to_dict(row)
            expiry_str = self._compute_expiry(org_id, d)
            d["expiry_date"] = expiry_str

            if expiry_status and expiry_str:
                try:
                    expiry_dt = datetime.fromisoformat(expiry_str)
                    if expiry_dt.tzinfo is None:
                        expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                    days_left = (expiry_dt - now).days
                    if expiry_status == "expired" and days_left >= 0:
                        continue
                    if expiry_status == "current" and days_left < 30:
                        continue
                    if expiry_status == "expiring_soon" and (days_left < 0 or days_left >= 30):
                        continue
                except ValueError:
                    pass
            elif expiry_status and not expiry_str:
                continue

            results.append(d)
        return results

    # ------------------------------------------------------------------
    # Legal Hold
    # ------------------------------------------------------------------

    def mark_legal_hold(
        self,
        org_id: str,
        dataset_id: str,
        held_by: str,
        reason: str,
    ) -> Optional[Dict[str, Any]]:
        """Place a legal hold on a dataset."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE datasets SET legal_hold=1, held_by=?, hold_reason=?,
                       hold_applied_at=?, updated_at=?
                       WHERE org_id=? AND dataset_id=?""",
                    (held_by, reason, now, now, org_id, dataset_id),
                )
        return self._get_dataset(org_id, dataset_id)

    def release_legal_hold(
        self,
        org_id: str,
        dataset_id: str,
        released_by: str,
    ) -> Optional[Dict[str, Any]]:
        """Release a legal hold from a dataset."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE datasets SET legal_hold=0, held_by='', hold_reason='',
                       hold_applied_at='', updated_at=?
                       WHERE org_id=? AND dataset_id=?""",
                    (now, org_id, dataset_id),
                )
        return self._get_dataset(org_id, dataset_id)

    # ------------------------------------------------------------------
    # Deletion Lifecycle
    # ------------------------------------------------------------------

    def schedule_deletion(
        self,
        org_id: str,
        dataset_id: str,
        scheduled_by: str,
        notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Schedule a dataset for deletion."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE datasets SET status='scheduled_for_deletion',
                       scheduled_at=?, scheduled_by=?, deletion_notes=?, updated_at=?
                       WHERE org_id=? AND dataset_id=?""",
                    (now, scheduled_by, notes, now, org_id, dataset_id),
                )
                # Audit
                conn.execute(
                    """INSERT INTO deletion_audit
                       (audit_id, org_id, dataset_id, dataset_name, action,
                        performed_by, notes, timestamp)
                       SELECT ?,?,dataset_id,dataset_name,'scheduled_for_deletion',?,?,?
                       FROM datasets WHERE org_id=? AND dataset_id=?""",
                    (str(uuid.uuid4()), org_id, scheduled_by, notes, now,
                     org_id, dataset_id),
                )
        return self._get_dataset(org_id, dataset_id)

    def complete_deletion(
        self,
        org_id: str,
        dataset_id: str,
        deleted_by: str,
    ) -> Optional[Dict[str, Any]]:
        """Mark a dataset as deleted and record in audit trail."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE datasets SET status='deleted',
                       deleted_at=?, deleted_by=?, updated_at=?
                       WHERE org_id=? AND dataset_id=?""",
                    (now, deleted_by, now, org_id, dataset_id),
                )
                # Audit
                conn.execute(
                    """INSERT INTO deletion_audit
                       (audit_id, org_id, dataset_id, dataset_name, action,
                        performed_by, notes, timestamp)
                       SELECT ?,?,dataset_id,dataset_name,'deleted',?,'',?
                       FROM datasets WHERE org_id=? AND dataset_id=?""",
                    (str(uuid.uuid4()), org_id, deleted_by, now,
                     org_id, dataset_id),
                )
        return self._get_dataset(org_id, dataset_id)

    def get_deletion_audit(self, org_id: str) -> List[Dict[str, Any]]:
        """Return the complete deletion audit trail for an org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM deletion_audit WHERE org_id=? ORDER BY timestamp",
                    (org_id,),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_retention_stats(self, org_id: str) -> Dict[str, Any]:
        """Return retention compliance statistics for an org."""
        with self._lock:
            with self._conn() as conn:
                total_policies = conn.execute(
                    "SELECT COUNT(*) FROM retention_policies WHERE org_id=?",
                    (org_id,),
                ).fetchone()[0]

                reg_rows = conn.execute(
                    """SELECT regulation, COUNT(*) as cnt
                       FROM retention_policies WHERE org_id=?
                       GROUP BY regulation""",
                    (org_id,),
                ).fetchall()
                by_regulation = {r["regulation"]: r["cnt"] for r in reg_rows}

                total_datasets = conn.execute(
                    "SELECT COUNT(*) FROM datasets WHERE org_id=? AND status != 'deleted'",
                    (org_id,),
                ).fetchone()[0]

                legal_hold_count = conn.execute(
                    "SELECT COUNT(*) FROM datasets WHERE org_id=? AND legal_hold=1",
                    (org_id,),
                ).fetchone()[0]

                scheduled_for_deletion = conn.execute(
                    "SELECT COUNT(*) FROM datasets WHERE org_id=? AND status='scheduled_for_deletion'",
                    (org_id,),
                ).fetchone()[0]

                # Load all active datasets to compute expired count
                ds_rows = conn.execute(
                    """SELECT d.created_at, p.retention_days
                       FROM datasets d
                       JOIN retention_policies p ON d.policy_id = p.policy_id
                       WHERE d.org_id=? AND d.status='active'""",
                    (org_id,),
                ).fetchall()

        now = datetime.now(timezone.utc)
        expired_count = 0
        for row in ds_rows:
            try:
                created = datetime.fromisoformat(row["created_at"])
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                expiry = created + timedelta(days=row["retention_days"])
                if expiry < now:
                    expired_count += 1
            except (ValueError, TypeError):
                pass

        # Compliance score: penalize for expired and unscheduled datasets
        total_active = total_datasets - legal_hold_count
        if total_active <= 0:
            compliance_score = 100
        else:
            non_compliant = expired_count + scheduled_for_deletion
            compliance_score = max(0, int(100 - (non_compliant / total_active) * 100))

        return {
            "total_policies": total_policies,
            "by_regulation": by_regulation,
            "total_datasets": total_datasets,
            "expired_count": expired_count,
            "legal_hold_count": legal_hold_count,
            "scheduled_for_deletion": scheduled_for_deletion,
            "compliance_score": compliance_score,
        }
