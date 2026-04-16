"""Vendor Compliance Engine — ALDECI.

Tracks vendors, compliance checks, and compliance requirements.
Multi-tenant via org_id.  SQLite WAL + threading.RLock for concurrency safety.
"""

from __future__ import annotations

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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "vendor_compliance.db"
)

_VALID_VENDOR_CATEGORIES = {
    "saas", "paas", "iaas", "professional_services", "hardware", "support"
}
_VALID_CONTRACT_TYPES = {"annual", "multi_year", "month_to_month", "one_time"}
_VALID_REQUIREMENT_TYPES = {
    "documentation", "certification", "audit", "training", "technical"
}
_VALID_REQ_STATUSES = {"pending", "in_progress", "completed", "waived"}


class VendorComplianceEngine:
    """SQLite WAL-backed Vendor Compliance engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS vc_vendors (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL DEFAULT '',
                    vendor_category   TEXT NOT NULL DEFAULT 'saas',
                    contract_type     TEXT NOT NULL DEFAULT 'annual',
                    compliance_score  REAL NOT NULL DEFAULT 0.0,
                    compliance_status TEXT NOT NULL DEFAULT 'non_compliant',
                    contact_name      TEXT NOT NULL DEFAULT '',
                    contact_email     TEXT NOT NULL DEFAULT '',
                    contract_start    TEXT,
                    contract_end      TEXT,
                    checked_at        DATETIME,
                    status            TEXT NOT NULL DEFAULT 'active',
                    created_at        DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_vcv_org
                    ON vc_vendors (org_id);

                CREATE TABLE IF NOT EXISTS vc_requirements (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    vendor_id        TEXT NOT NULL,
                    requirement_name TEXT NOT NULL DEFAULT '',
                    requirement_type TEXT NOT NULL DEFAULT 'documentation',
                    due_date         TEXT NOT NULL DEFAULT '',
                    mandatory        INTEGER NOT NULL DEFAULT 1,
                    status           TEXT NOT NULL DEFAULT 'pending',
                    notes            TEXT NOT NULL DEFAULT '',
                    completed_at     DATETIME,
                    created_at       DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_vcr_org
                    ON vc_requirements (org_id, vendor_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Vendors
    # ------------------------------------------------------------------

    def register_vendor(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new vendor. Validates name, vendor_category, and contract_type."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        vendor_category = data.get("vendor_category", "")
        if vendor_category not in _VALID_VENDOR_CATEGORIES:
            raise ValueError(
                f"vendor_category must be one of {sorted(_VALID_VENDOR_CATEGORIES)}, "
                f"got {vendor_category!r}"
            )

        contract_type = data.get("contract_type", "annual")
        if contract_type not in _VALID_CONTRACT_TYPES:
            raise ValueError(
                f"contract_type must be one of {sorted(_VALID_CONTRACT_TYPES)}, "
                f"got {contract_type!r}"
            )

        vendor_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vc_vendors
                        (id, org_id, name, vendor_category, contract_type,
                         compliance_score, compliance_status,
                         contact_name, contact_email,
                         contract_start, contract_end,
                         checked_at, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        vendor_id, org_id, name, vendor_category, contract_type,
                        0.0, "non_compliant",
                        data.get("contact_name", ""),
                        data.get("contact_email", ""),
                        data.get("contract_start", None),
                        data.get("contract_end", None),
                        None,
                        "active",
                        now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "vendor_compliance", "org_id": org_id, "source_engine": "vendor_compliance"})
            except Exception:
                pass

        return {
            "id": vendor_id,
            "org_id": org_id,
            "name": name,
            "vendor_category": vendor_category,
            "contract_type": contract_type,
            "compliance_score": 0.0,
            "compliance_status": "non_compliant",
            "contact_name": data.get("contact_name", ""),
            "contact_email": data.get("contact_email", ""),
            "contract_start": data.get("contract_start", None),
            "contract_end": data.get("contract_end", None),
            "checked_at": None,
            "status": "active",
            "created_at": now,
        }

    def list_vendors(
        self,
        org_id: str,
        vendor_category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List vendors for an org with optional category/status filters."""
        query = "SELECT * FROM vc_vendors WHERE org_id=?"
        params: list = [org_id]
        if vendor_category:
            query += " AND vendor_category=?"
            params.append(vendor_category)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY name"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_vendor(self, org_id: str, vendor_id: str) -> Optional[Dict[str, Any]]:
        """Return a single vendor or None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM vc_vendors WHERE org_id=? AND id=?",
                (org_id, vendor_id),
            ).fetchone()
        return self._row(row) if row else None

    def run_compliance_check(
        self, org_id: str, vendor_id: str, check_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Run a 6-item compliance check against a vendor.

        compliance_score = (count of True items) / 6 * 100 rounded to int.
        compliance_status: >=80=compliant, 50-79=partial, <50=non_compliant.
        """
        items = [
            "data_processing_agreement",
            "security_questionnaire",
            "pen_test_report",
            "soc2_report",
            "gdpr_compliance",
            "insurance_certificate",
        ]
        passed = sum(1 for item in items if bool(check_data.get(item, False)))
        compliance_score = round(passed / len(items) * 100)

        if compliance_score >= 80:
            compliance_status = "compliant"
        elif compliance_score >= 50:
            compliance_status = "partial"
        else:
            compliance_status = "non_compliant"

        checked_at = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE vc_vendors
                       SET compliance_score=?, compliance_status=?, checked_at=?
                     WHERE org_id=? AND id=?
                    """,
                    (compliance_score, compliance_status, checked_at, org_id, vendor_id),
                )

        return {
            "vendor_id": vendor_id,
            "org_id": org_id,
            "compliance_score": compliance_score,
            "compliance_status": compliance_status,
            "checked_at": checked_at,
            "items": {item: bool(check_data.get(item, False)) for item in items},
        }

    # ------------------------------------------------------------------
    # Requirements
    # ------------------------------------------------------------------

    def create_compliance_requirement(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a compliance requirement for a vendor."""
        vendor_id = data.get("vendor_id", "")
        if not vendor_id:
            raise ValueError("vendor_id is required")

        requirement_name = data.get("requirement_name", "").strip()
        if not requirement_name:
            raise ValueError("requirement_name is required")

        requirement_type = data.get("requirement_type", "")
        if requirement_type not in _VALID_REQUIREMENT_TYPES:
            raise ValueError(
                f"requirement_type must be one of {sorted(_VALID_REQUIREMENT_TYPES)}, "
                f"got {requirement_type!r}"
            )

        due_date = data.get("due_date", "")
        if not due_date:
            raise ValueError("due_date is required")

        req_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        mandatory = bool(data.get("mandatory", True))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vc_requirements
                        (id, org_id, vendor_id, requirement_name, requirement_type,
                         due_date, mandatory, status, notes, completed_at, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        req_id, org_id, vendor_id, requirement_name, requirement_type,
                        due_date, int(mandatory), "pending", "", None, now,
                    ),
                )

        return {
            "id": req_id,
            "org_id": org_id,
            "vendor_id": vendor_id,
            "requirement_name": requirement_name,
            "requirement_type": requirement_type,
            "due_date": due_date,
            "mandatory": mandatory,
            "status": "pending",
            "notes": "",
            "completed_at": None,
            "created_at": now,
        }

    def update_requirement_status(
        self, org_id: str, req_id: str, status: str, notes: str = ""
    ) -> Dict[str, Any]:
        """Update the status of a compliance requirement."""
        if status not in _VALID_REQ_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(_VALID_REQ_STATUSES)}, got {status!r}"
            )

        completed_at = None
        if status == "completed":
            completed_at = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE vc_requirements
                       SET status=?, notes=?, completed_at=?
                     WHERE org_id=? AND id=?
                    """,
                    (status, notes, completed_at, org_id, req_id),
                )

        return {
            "req_id": req_id,
            "org_id": org_id,
            "status": status,
            "notes": notes,
            "completed_at": completed_at,
        }

    def list_requirements(
        self,
        org_id: str,
        vendor_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List compliance requirements with optional filters."""
        query = "SELECT * FROM vc_requirements WHERE org_id=?"
        params: list = [org_id]
        if vendor_id:
            query += " AND vendor_id=?"
            params.append(vendor_id)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY due_date"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_vendor_compliance_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate vendor compliance stats for an org."""
        with self._conn() as conn:
            total_vendors = conn.execute(
                "SELECT COUNT(*) FROM vc_vendors WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            avg_compliance_score = conn.execute(
                "SELECT COALESCE(AVG(compliance_score), 0) FROM vc_vendors WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            compliant_vendors = conn.execute(
                "SELECT COUNT(*) FROM vc_vendors WHERE org_id=? AND compliance_score >= 80",
                (org_id,),
            ).fetchone()[0]

            non_compliant_vendors = conn.execute(
                "SELECT COUNT(*) FROM vc_vendors WHERE org_id=? AND compliance_score < 50",
                (org_id,),
            ).fetchone()[0]

            total_requirements = conn.execute(
                "SELECT COUNT(*) FROM vc_requirements WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            overdue_requirements = conn.execute(
                """
                SELECT COUNT(*) FROM vc_requirements
                 WHERE org_id=?
                   AND due_date < datetime('now')
                   AND status IN ('pending', 'in_progress')
                """,
                (org_id,),
            ).fetchone()[0]

            # by_category
            cat_rows = conn.execute(
                "SELECT vendor_category, COUNT(*) AS cnt FROM vc_vendors WHERE org_id=? GROUP BY vendor_category",
                (org_id,),
            ).fetchall()
            by_category = {r["vendor_category"]: r["cnt"] for r in cat_rows}

        return {
            "org_id": org_id,
            "total_vendors": total_vendors,
            "by_category": by_category,
            "avg_compliance_score": round(float(avg_compliance_score), 2),
            "compliant_vendors": compliant_vendors,
            "non_compliant_vendors": non_compliant_vendors,
            "total_requirements": total_requirements,
            "overdue_requirements": overdue_requirements,
        }
