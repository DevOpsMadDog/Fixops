"""
VulnExceptionEngine — ALDECI.

Manages vulnerability exceptions: false positives, accepted risks,
compensating controls, deferred fixes, and not-applicable findings.

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: NIST SP 800-53 RA-5, PCI-DSS 6.3.3 (risk acceptance).
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "vuln_exceptions.db"
)

VALID_EXCEPTION_TYPES = frozenset(
    {
        "false_positive",
        "accepted_risk",
        "compensating_control",
        "deferred",
        "not_applicable",
    }
)

VALID_STATUSES = frozenset({"pending", "approved", "rejected", "expired"})


class VulnExceptionEngine:
    """
    SQLite-backed vulnerability exception management engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to .fixops_data/vuln_exceptions.db.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS vuln_exceptions (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    cve_id           TEXT NOT NULL,
                    asset_id         TEXT NOT NULL,
                    reason           TEXT NOT NULL,
                    exception_type   TEXT NOT NULL,
                    requested_by     TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'pending',
                    expiry_date      DATETIME,
                    approved_by      TEXT DEFAULT '',
                    approved_at      DATETIME,
                    approval_notes   TEXT DEFAULT '',
                    rejected_by      TEXT DEFAULT '',
                    rejected_at      DATETIME,
                    rejection_reason TEXT DEFAULT '',
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vexc_org
                    ON vuln_exceptions (org_id);

                CREATE INDEX IF NOT EXISTS idx_vexc_org_status
                    ON vuln_exceptions (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_vexc_org_type
                    ON vuln_exceptions (org_id, exception_type);

                CREATE TABLE IF NOT EXISTS auto_waiver_rules (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    rule_key          TEXT NOT NULL,
                    conditions_json   TEXT NOT NULL DEFAULT '{}',
                    max_active_count  INTEGER NOT NULL DEFAULT 100,
                    approvers_json    TEXT NOT NULL DEFAULT '[]',
                    expires_days      INTEGER NOT NULL DEFAULT 30,
                    enabled           INTEGER NOT NULL DEFAULT 1,
                    created_at        TEXT NOT NULL,
                    UNIQUE(org_id, rule_key)
                );

                CREATE INDEX IF NOT EXISTS idx_awr_org_enabled
                    ON auto_waiver_rules (org_id, enabled);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "cve_id": row["cve_id"],
            "asset_id": row["asset_id"],
            "reason": row["reason"],
            "exception_type": row["exception_type"],
            "requested_by": row["requested_by"],
            "status": row["status"],
            "expiry_date": row["expiry_date"],
            "approved_by": row["approved_by"],
            "approved_at": row["approved_at"],
            "approval_notes": row["approval_notes"],
            "rejected_by": row["rejected_by"],
            "rejected_at": row["rejected_at"],
            "rejection_reason": row["rejection_reason"],
            "created_at": row["created_at"],
        }

    # ------------------------------------------------------------------
    # Exception Management
    # ------------------------------------------------------------------

    def create_exception(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new vulnerability exception request.

        data keys: cve_id (required), asset_id (required), reason (required),
        exception_type (required), requested_by, expiry_date.
        Returns the created exception record with status=pending.
        """
        cve_id = data.get("cve_id", "").strip()
        if not cve_id:
            raise ValueError("cve_id is required")

        asset_id = data.get("asset_id", "").strip()
        if not asset_id:
            raise ValueError("asset_id is required")

        reason = data.get("reason", "").strip()
        if not reason:
            raise ValueError("reason is required")

        exception_type = data.get("exception_type", "")
        if exception_type not in VALID_EXCEPTION_TYPES:
            raise ValueError(
                f"exception_type must be one of {sorted(VALID_EXCEPTION_TYPES)}, got '{exception_type}'"
            )

        now = datetime.now(timezone.utc).isoformat()
        exc_id = str(uuid.uuid4())
        requested_by = data.get("requested_by", "")
        expiry_date = data.get("expiry_date")

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vuln_exceptions
                        (id, org_id, cve_id, asset_id, reason, exception_type,
                         requested_by, status, expiry_date, approved_by, approved_at,
                         approval_notes, rejected_by, rejected_at, rejection_reason,
                         created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, '', NULL, '', '', NULL, '', ?)
                    """,
                    (
                        exc_id, org_id, cve_id, asset_id, reason, exception_type,
                        requested_by, expiry_date, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "vuln_exception", "org_id": org_id, "source_engine": "vuln_exception"})
            except Exception:
                pass

        return {
            "id": exc_id,
            "org_id": org_id,
            "cve_id": cve_id,
            "asset_id": asset_id,
            "reason": reason,
            "exception_type": exception_type,
            "requested_by": requested_by,
            "status": "pending",
            "expiry_date": expiry_date,
            "approved_by": "",
            "approved_at": None,
            "approval_notes": "",
            "rejected_by": "",
            "rejected_at": None,
            "rejection_reason": "",
            "created_at": now,
        }

    def list_exceptions(
        self,
        org_id: str,
        exception_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List exceptions for an org with optional filters."""
        query = "SELECT * FROM vuln_exceptions WHERE org_id = ?"
        params: List[Any] = [org_id]

        if exception_type:
            query += " AND exception_type = ?"
            params.append(exception_type)
        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [self._row_to_dict(r) for r in rows]

    def get_exception(self, org_id: str, exception_id: str) -> Dict[str, Any]:
        """
        Retrieve a single exception by ID.

        Returns the exception dict or empty dict if not found / wrong org.
        """
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM vuln_exceptions WHERE org_id = ? AND id = ?",
                    (org_id, exception_id),
                ).fetchone()

        if not row:
            return {}
        return self._row_to_dict(row)

    def approve_exception(
        self,
        org_id: str,
        exception_id: str,
        approved_by: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Approve a pending exception.

        Sets status=approved, records approver and timestamp.
        Raises ValueError if not found.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT id FROM vuln_exceptions WHERE org_id = ? AND id = ?",
                    (org_id, exception_id),
                ).fetchone()

                if not row:
                    raise ValueError(
                        f"Exception '{exception_id}' not found for org '{org_id}'"
                    )

                conn.execute(
                    """
                    UPDATE vuln_exceptions
                    SET status = 'approved', approved_by = ?, approved_at = ?,
                        approval_notes = ?
                    WHERE org_id = ? AND id = ?
                    """,
                    (approved_by, now, notes, org_id, exception_id),
                )

        return self.get_exception(org_id, exception_id)

    def reject_exception(
        self,
        org_id: str,
        exception_id: str,
        rejected_by: str,
        reason: str,
    ) -> Dict[str, Any]:
        """
        Reject a pending exception.

        Sets status=rejected, records rejector and reason.
        Raises ValueError if not found.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT id FROM vuln_exceptions WHERE org_id = ? AND id = ?",
                    (org_id, exception_id),
                ).fetchone()

                if not row:
                    raise ValueError(
                        f"Exception '{exception_id}' not found for org '{org_id}'"
                    )

                conn.execute(
                    """
                    UPDATE vuln_exceptions
                    SET status = 'rejected', rejected_by = ?, rejected_at = ?,
                        rejection_reason = ?
                    WHERE org_id = ? AND id = ?
                    """,
                    (rejected_by, now, reason, org_id, exception_id),
                )

        return self.get_exception(org_id, exception_id)

    def expire_exceptions(self, org_id: str) -> Dict[str, Any]:
        """
        Expire approved exceptions whose expiry_date has passed.

        Returns dict with expired_count.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                result = conn.execute(
                    """
                    UPDATE vuln_exceptions
                    SET status = 'expired'
                    WHERE org_id = ?
                      AND status = 'approved'
                      AND expiry_date IS NOT NULL
                      AND expiry_date < ?
                    """,
                    (org_id, now),
                )
                count = result.rowcount

        return {"expired_count": count}

    def get_exception_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Return aggregated exception statistics for the org.

        Includes total_exceptions, by_type, by_status, pending_count,
        approved_count, expired_count, and acceptance_rate.
        """
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT exception_type, status FROM vuln_exceptions WHERE org_id = ?",
                    (org_id,),
                ).fetchall()

        total = len(rows)
        by_type: Dict[str, int] = {}
        by_status: Dict[str, int] = {}

        for r in rows:
            by_type[r["exception_type"]] = by_type.get(r["exception_type"], 0) + 1
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1

        pending_count = by_status.get("pending", 0)
        approved_count = by_status.get("approved", 0)
        rejected_count = by_status.get("rejected", 0)
        expired_count = by_status.get("expired", 0)

        decided = approved_count + rejected_count
        acceptance_rate = (approved_count / decided * 100.0) if decided > 0 else 0.0

        return {
            "total_exceptions": total,
            "by_type": by_type,
            "by_status": by_status,
            "pending_count": pending_count,
            "approved_count": approved_count,
            "expired_count": expired_count,
            "acceptance_rate": round(acceptance_rate, 2),
        }

    # ------------------------------------------------------------------
    # Auto-Waiver Rules (GAP-006)
    # ------------------------------------------------------------------

    _SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": 0}

    def register_auto_waiver_rule(
        self,
        org_id: str,
        rule_key: str,
        conditions: Dict[str, Any],
        max_active_count: int = 100,
        approvers: Optional[List[str]] = None,
        expires_days: int = 30,
    ) -> Dict[str, Any]:
        """Register (or replace) an auto-waiver rule for an org.

        Conditions supported: reachable (bool), severity_max (str: critical/high/medium/low),
        cve_age_days_min (int), kev (bool). UNIQUE(org_id, rule_key).
        """
        if not rule_key or not rule_key.strip():
            raise ValueError("rule_key is required")
        if not isinstance(conditions, dict):
            raise ValueError("conditions must be a dict")
        if max_active_count < 0:
            raise ValueError("max_active_count must be >= 0")
        if expires_days < 0:
            raise ValueError("expires_days must be >= 0")

        approvers = approvers or []
        now = datetime.now(timezone.utc).isoformat()
        rid = str(uuid.uuid4())

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO auto_waiver_rules
                        (id, org_id, rule_key, conditions_json, max_active_count,
                         approvers_json, expires_days, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                    ON CONFLICT(org_id, rule_key) DO UPDATE SET
                        conditions_json  = excluded.conditions_json,
                        max_active_count = excluded.max_active_count,
                        approvers_json   = excluded.approvers_json,
                        expires_days     = excluded.expires_days,
                        enabled          = 1
                    """,
                    (
                        rid, org_id, rule_key.strip(),
                        json.dumps(conditions),
                        int(max_active_count),
                        json.dumps(approvers),
                        int(expires_days),
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM auto_waiver_rules WHERE org_id = ? AND rule_key = ?",
                    (org_id, rule_key.strip()),
                ).fetchone()

        return self._rule_row_to_dict(row)

    def list_auto_waiver_rules(
        self,
        org_id: str,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List auto-waiver rules for an org, optionally filtered by enabled flag."""
        query = "SELECT * FROM auto_waiver_rules WHERE org_id = ?"
        params: List[Any] = [org_id]
        if enabled is not None:
            query += " AND enabled = ?"
            params.append(1 if enabled else 0)
        query += " ORDER BY created_at ASC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [self._rule_row_to_dict(r) for r in rows]

    def delete_auto_waiver_rule(self, org_id: str, rule_key: str) -> Dict[str, Any]:
        """Delete (disable) an auto-waiver rule."""
        with self._lock:
            with self._get_conn() as conn:
                result = conn.execute(
                    "DELETE FROM auto_waiver_rules WHERE org_id = ? AND rule_key = ?",
                    (org_id, rule_key),
                )
                deleted = result.rowcount
        return {"deleted": deleted, "rule_key": rule_key, "org_id": org_id}

    def _rule_row_to_dict(self, row: Optional[sqlite3.Row]) -> Dict[str, Any]:
        if not row:
            return {}
        try:
            conditions = json.loads(row["conditions_json"] or "{}")
        except (ValueError, TypeError):
            conditions = {}
        try:
            approvers = json.loads(row["approvers_json"] or "[]")
        except (ValueError, TypeError):
            approvers = []
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "rule_key": row["rule_key"],
            "conditions": conditions,
            "max_active_count": row["max_active_count"],
            "approvers": approvers,
            "expires_days": row["expires_days"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
        }

    def _finding_matches_conditions(
        self, finding: Dict[str, Any], conditions: Dict[str, Any]
    ) -> bool:
        """Evaluate whether a finding matches a rule's conditions.

        All specified conditions must match. Missing finding fields treated
        conservatively (fail-closed when condition asserts a value).
        """
        # reachable: bool — if condition sets reachable=False, finding.reachable must be False.
        if "reachable" in conditions:
            want = bool(conditions["reachable"])
            got = finding.get("reachable")
            if got is None or bool(got) != want:
                return False

        # severity_max: finding severity must be <= specified level
        if "severity_max" in conditions:
            max_sev = str(conditions["severity_max"]).lower()
            finding_sev = str(finding.get("severity", "")).lower()
            if max_sev not in self._SEVERITY_ORDER:
                return False
            if finding_sev not in self._SEVERITY_ORDER:
                return False
            if self._SEVERITY_ORDER[finding_sev] > self._SEVERITY_ORDER[max_sev]:
                return False

        # cve_age_days_min: finding cve_age_days must be >= specified
        if "cve_age_days_min" in conditions:
            min_age = int(conditions["cve_age_days_min"])
            got_age = finding.get("cve_age_days")
            if got_age is None or int(got_age) < min_age:
                return False

        # kev: finding must match kev flag exactly
        if "kev" in conditions:
            want = bool(conditions["kev"])
            got = bool(finding.get("kev", False))
            if got != want:
                return False

        return True

    def apply_auto_waivers(
        self, org_id: str, finding: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Evaluate all enabled rules against finding; create exception on first match.

        Returns the created exception dict, or None if no rule matched.
        Deterministic: rules are evaluated in created_at order.
        """
        if not isinstance(finding, dict):
            return None

        rules = self.list_auto_waiver_rules(org_id, enabled=True)
        if not rules:
            return None

        for rule in rules:
            # Respect max_active_count: count pending+approved autowaiver exceptions for this rule.
            if not self._finding_matches_conditions(finding, rule["conditions"]):
                continue

            # enforce cap
            active = self._count_active_for_rule(org_id, rule["rule_key"])
            if active >= rule["max_active_count"]:
                continue

            # Create the exception
            cve_id = str(finding.get("cve_id") or finding.get("id") or "UNKNOWN-CVE")
            asset_id = str(finding.get("asset_id") or finding.get("asset") or "unknown")
            reason = f"auto-waiver:{rule['rule_key']}"

            expiry_date = (
                datetime.now(timezone.utc) + timedelta(days=rule["expires_days"])
            ).isoformat()

            exc_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()

            with self._lock:
                with self._get_conn() as conn:
                    conn.execute(
                        """
                        INSERT INTO vuln_exceptions
                            (id, org_id, cve_id, asset_id, reason, exception_type,
                             requested_by, status, expiry_date, approved_by, approved_at,
                             approval_notes, rejected_by, rejected_at, rejection_reason,
                             created_at)
                        VALUES (?, ?, ?, ?, ?, 'accepted_risk', 'auto-waiver', 'pending',
                                ?, '', NULL, ?, '', NULL, '', ?)
                        """,
                        (
                            exc_id, org_id, cve_id, asset_id, reason,
                            expiry_date,
                            json.dumps({"rule_key": rule["rule_key"], "approvers": rule["approvers"]}),
                            now,
                        ),
                    )

            return {
                "id": exc_id,
                "org_id": org_id,
                "cve_id": cve_id,
                "asset_id": asset_id,
                "reason": reason,
                "exception_type": "accepted_risk",
                "requested_by": "auto-waiver",
                "status": "pending",
                "expiry_date": expiry_date,
                "approved_by": "",
                "approved_at": None,
                "approval_notes": json.dumps(
                    {"rule_key": rule["rule_key"], "approvers": rule["approvers"]}
                ),
                "rejected_by": "",
                "rejected_at": None,
                "rejection_reason": "",
                "created_at": now,
                "rule_key": rule["rule_key"],
                "approvers": rule["approvers"],
            }

        return None

    def _count_active_for_rule(self, org_id: str, rule_key: str) -> int:
        """Count pending+approved auto-waiver exceptions whose reason tags this rule."""
        pattern = f"auto-waiver:{rule_key}"
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    """
                    SELECT COUNT(*) AS cnt FROM vuln_exceptions
                    WHERE org_id = ?
                      AND reason = ?
                      AND status IN ('pending', 'approved')
                    """,
                    (org_id, pattern),
                ).fetchone()
        return int(row["cnt"]) if row else 0

    def auto_waiver_stats(self, org_id: str) -> Dict[str, Any]:
        """Return stats on auto-waiver rules and generated exceptions for the org."""
        with self._lock:
            with self._get_conn() as conn:
                total_rules = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM auto_waiver_rules WHERE org_id = ?",
                    (org_id,),
                ).fetchone()["cnt"]

                enabled_rules = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM auto_waiver_rules WHERE org_id = ? AND enabled = 1",
                    (org_id,),
                ).fetchone()["cnt"]

                auto_waived = conn.execute(
                    """
                    SELECT COUNT(*) AS cnt FROM vuln_exceptions
                    WHERE org_id = ? AND requested_by = 'auto-waiver'
                    """,
                    (org_id,),
                ).fetchone()["cnt"]

                pending_approval = conn.execute(
                    """
                    SELECT COUNT(*) AS cnt FROM vuln_exceptions
                    WHERE org_id = ? AND requested_by = 'auto-waiver' AND status = 'pending'
                    """,
                    (org_id,),
                ).fetchone()["cnt"]

        return {
            "org_id": org_id,
            "total_rules": int(total_rules),
            "enabled_rules": int(enabled_rules),
            "auto_waived_findings": int(auto_waived),
            "pending_approval": int(pending_approval),
        }
