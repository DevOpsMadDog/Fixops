"""Software License Security Engine — ALDECI.

Tracks software license compliance and open-source security risks.

Capabilities:
  - License record management with org_id isolation
  - License violation lifecycle (open/waived/remediated)
  - License policy management (allowed/blocked lists)
  - Stats: by license type, by risk, unapproved count, open violations

Compliance: OSPO best practices, SPDX, CycloneDX license component tracking
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

_VALID_LICENSE_TYPES = {
    "MIT", "Apache-2.0", "GPL-2.0", "GPL-3.0", "LGPL",
    "BSD-2-Clause", "BSD-3-Clause", "proprietary", "unknown",
}
_VALID_LICENSE_RISKS = {"low", "medium", "high", "critical"}
_VALID_VIOLATION_TYPES = {
    "copyleft_conflict", "proprietary_restriction",
    "dual_license", "gpl_contamination", "unknown",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_VIOLATION_STATUSES = {"open", "waived", "remediated"}
_VALID_RESOLUTION_TYPES = {"waived", "remediated"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SoftwareLicenseSecurityEngine:
    """SQLite WAL-backed Software License Security engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/software_license_security.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(
                Path(_DEFAULT_DB_DIR) / "software_license_security.db"
            )
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
                CREATE TABLE IF NOT EXISTS license_records (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    package_name       TEXT NOT NULL,
                    package_version    TEXT NOT NULL DEFAULT '',
                    license_type       TEXT NOT NULL DEFAULT 'unknown',
                    license_risk       TEXT NOT NULL DEFAULT 'low',
                    is_oss             INTEGER NOT NULL DEFAULT 1,
                    has_vulnerabilities INTEGER NOT NULL DEFAULT 0,
                    vuln_count         INTEGER NOT NULL DEFAULT 0,
                    approved           INTEGER NOT NULL DEFAULT 0,
                    created_at         TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_lr_org
                    ON license_records (org_id, license_type, license_risk, created_at DESC);

                CREATE TABLE IF NOT EXISTS license_violations (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    record_id      TEXT NOT NULL,
                    violation_type TEXT NOT NULL DEFAULT 'unknown',
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    description    TEXT NOT NULL DEFAULT '',
                    status         TEXT NOT NULL DEFAULT 'open',
                    created_at     TEXT NOT NULL,
                    resolved_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_lv_org
                    ON license_violations (org_id, severity, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS license_policies (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    policy_name       TEXT NOT NULL,
                    allowed_licenses  TEXT NOT NULL DEFAULT '[]',
                    blocked_licenses  TEXT NOT NULL DEFAULT '[]',
                    require_approval  INTEGER NOT NULL DEFAULT 1,
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_lp_org
                    ON license_policies (org_id, created_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Coerce SQLite integers to Python bools for boolean columns
        for col in ("is_oss", "has_vulnerabilities", "approved", "require_approval"):
            if col in d and d[col] is not None:
                d[col] = bool(d[col])
        return d

    @staticmethod
    def _policy_row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("allowed_licenses", "blocked_licenses"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        if "require_approval" in d and d["require_approval"] is not None:
            d["require_approval"] = bool(d["require_approval"])
        return d

    # ------------------------------------------------------------------
    # License Records
    # ------------------------------------------------------------------

    def add_license_record(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a license record for a package."""
        package_name = (data.get("package_name") or "").strip()
        if not package_name:
            raise ValueError("package_name is required.")

        package_version = (data.get("package_version") or "").strip()

        license_type = data.get("license_type", "unknown")
        if license_type not in _VALID_LICENSE_TYPES:
            raise ValueError(
                f"Invalid license_type: {license_type!r}. "
                f"Must be one of {sorted(_VALID_LICENSE_TYPES)}"
            )

        license_risk = data.get("license_risk", "low")
        if license_risk not in _VALID_LICENSE_RISKS:
            raise ValueError(
                f"Invalid license_risk: {license_risk!r}. "
                f"Must be one of {sorted(_VALID_LICENSE_RISKS)}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "package_name": package_name,
            "package_version": package_version,
            "license_type": license_type,
            "license_risk": license_risk,
            "is_oss": int(bool(data.get("is_oss", True))),
            "has_vulnerabilities": int(bool(data.get("has_vulnerabilities", False))),
            "vuln_count": int(data.get("vuln_count", 0)),
            "approved": int(bool(data.get("approved", False))),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO license_records
                       (id, org_id, package_name, package_version, license_type,
                        license_risk, is_oss, has_vulnerabilities, vuln_count,
                        approved, created_at)
                       VALUES (:id, :org_id, :package_name, :package_version,
                               :license_type, :license_risk, :is_oss,
                               :has_vulnerabilities, :vuln_count, :approved,
                               :created_at)""",
                    record,
                )
        # Return with bool values
        record["is_oss"] = bool(record["is_oss"])
        record["has_vulnerabilities"] = bool(record["has_vulnerabilities"])
        record["approved"] = bool(record["approved"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "software_license_security", "org_id": org_id, "source_engine": "software_license_security"})
            except Exception:
                pass

        return record

    def list_license_records(
        self,
        org_id: str,
        license_type: Optional[str] = None,
        license_risk: Optional[str] = None,
        approved: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List license records with optional filters."""
        sql = "SELECT * FROM license_records WHERE org_id = ?"
        params: list = [org_id]
        if license_type is not None:
            sql += " AND license_type = ?"
            params.append(license_type)
        if license_risk is not None:
            sql += " AND license_risk = ?"
            params.append(license_risk)
        if approved is not None:
            sql += " AND approved = ?"
            params.append(int(approved))
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_license_record(
        self, org_id: str, record_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a single license record; None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM license_records WHERE org_id = ? AND id = ?",
                (org_id, record_id),
            ).fetchone()
        return self._row(row) if row else None

    def approve_license(self, org_id: str, record_id: str) -> Dict[str, Any]:
        """Approve a license record. Raises KeyError if not found."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE license_records SET approved = 1 "
                    "WHERE org_id = ? AND id = ?",
                    (org_id, record_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"License record {record_id!r} not found in org {org_id!r}."
                    )
        record = self.get_license_record(org_id, record_id)
        return record  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Violations
    # ------------------------------------------------------------------

    def record_violation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a license violation. Validates that record_id exists in org."""
        record_id = (data.get("record_id") or "").strip()
        if not record_id:
            raise ValueError("record_id is required.")

        # Verify the referenced record belongs to this org
        existing = self.get_license_record(org_id, record_id)
        if existing is None:
            raise ValueError(
                f"License record {record_id!r} not found in org {org_id!r}."
            )

        violation_type = data.get("violation_type", "unknown")
        if violation_type not in _VALID_VIOLATION_TYPES:
            raise ValueError(
                f"Invalid violation_type: {violation_type!r}. "
                f"Must be one of {sorted(_VALID_VIOLATION_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        now = _now_iso()
        violation: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "record_id": record_id,
            "violation_type": violation_type,
            "severity": severity,
            "description": data.get("description", ""),
            "status": "open",
            "created_at": now,
            "resolved_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO license_violations
                       (id, org_id, record_id, violation_type, severity,
                        description, status, created_at, resolved_at)
                       VALUES (:id, :org_id, :record_id, :violation_type,
                               :severity, :description, :status, :created_at,
                               :resolved_at)""",
                    violation,
                )
        return violation

    def resolve_violation(
        self, org_id: str, violation_id: str, resolution_type: str
    ) -> Dict[str, Any]:
        """Resolve a violation (waived/remediated). Raises KeyError if not found."""
        if resolution_type not in _VALID_RESOLUTION_TYPES:
            raise ValueError(
                f"Invalid resolution_type: {resolution_type!r}. "
                f"Must be one of {sorted(_VALID_RESOLUTION_TYPES)}"
            )
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE license_violations SET status = ?, resolved_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (resolution_type, now, org_id, violation_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Violation {violation_id!r} not found in org {org_id!r}."
                    )
                row = conn.execute(
                    "SELECT * FROM license_violations WHERE id = ?",
                    (violation_id,),
                ).fetchone()
        return dict(row) if row else {}

    def list_violations(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List violations with optional severity/status filters."""
        sql = "SELECT * FROM license_violations WHERE org_id = ?"
        params: list = [org_id]
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a license policy."""
        policy_name = (data.get("policy_name") or "").strip()
        if not policy_name:
            raise ValueError("policy_name is required.")

        allowed = data.get("allowed_licenses", [])
        if not isinstance(allowed, list):
            allowed = []
        blocked = data.get("blocked_licenses", [])
        if not isinstance(blocked, list):
            blocked = []

        now = _now_iso()
        policy: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "policy_name": policy_name,
            "allowed_licenses": json.dumps(allowed),
            "blocked_licenses": json.dumps(blocked),
            "require_approval": int(bool(data.get("require_approval", True))),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO license_policies
                       (id, org_id, policy_name, allowed_licenses, blocked_licenses,
                        require_approval, created_at)
                       VALUES (:id, :org_id, :policy_name, :allowed_licenses,
                               :blocked_licenses, :require_approval, :created_at)""",
                    policy,
                )
        # Return with parsed JSON lists
        policy["allowed_licenses"] = allowed
        policy["blocked_licenses"] = blocked
        policy["require_approval"] = bool(policy["require_approval"])
        return policy

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List all license policies for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM license_policies WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._policy_row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_license_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated license statistics for an org."""
        with self._conn() as conn:
            total_packages = conn.execute(
                "SELECT COUNT(*) FROM license_records WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT license_type, COUNT(*) as cnt FROM license_records "
                "WHERE org_id = ? GROUP BY license_type",
                (org_id,),
            ).fetchall()
            by_license_type = {r["license_type"]: r["cnt"] for r in type_rows}

            risk_rows = conn.execute(
                "SELECT license_risk, COUNT(*) as cnt FROM license_records "
                "WHERE org_id = ? GROUP BY license_risk",
                (org_id,),
            ).fetchall()
            by_risk = {r["license_risk"]: r["cnt"] for r in risk_rows}

            unapproved_count = conn.execute(
                "SELECT COUNT(*) FROM license_records WHERE org_id = ? AND approved = 0",
                (org_id,),
            ).fetchone()[0]

            open_violations = conn.execute(
                "SELECT COUNT(*) FROM license_violations WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            critical_violations = conn.execute(
                "SELECT COUNT(*) FROM license_violations "
                "WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            oss_packages = conn.execute(
                "SELECT COUNT(*) FROM license_records WHERE org_id = ? AND is_oss = 1",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_packages": total_packages,
            "by_license_type": by_license_type,
            "by_risk": by_risk,
            "unapproved_count": unapproved_count,
            "open_violations": open_violations,
            "critical_violations": critical_violations,
            "oss_packages": oss_packages,
        }
