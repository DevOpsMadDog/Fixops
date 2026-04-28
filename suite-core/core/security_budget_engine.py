"""Security Budget Engine — ALDECI.

Tracks security spend, budget allocations, and ROI across fiscal years.
Supports category-level budgeting, spend transaction approval workflows,
and simplified ROI calculations.

Compliance: NIST CSF, ISO/IEC 27001 A.5.36, SOC 2 CC1.3
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_budget.db"
)

_VALID_CATEGORIES = {
    "tools",
    "personnel",
    "training",
    "consulting",
    "infrastructure",
    "compliance",
    "incident_response",
}

_VALID_APPROVAL_STATUSES = {"pending", "approved", "rejected"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityBudgetEngine:
    """SQLite WAL-backed Security Budget engine.

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
                CREATE TABLE IF NOT EXISTS budget_allocations (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    fiscal_year      INTEGER NOT NULL,
                    category         TEXT NOT NULL,
                    allocated_amount REAL NOT NULL,
                    spent_amount     REAL NOT NULL DEFAULT 0.0,
                    currency         TEXT NOT NULL DEFAULT 'USD',
                    notes            TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS spend_transactions (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    allocation_id    TEXT NOT NULL,
                    vendor_name      TEXT NOT NULL,
                    description      TEXT NOT NULL DEFAULT '',
                    amount           REAL NOT NULL,
                    transaction_date TEXT NOT NULL,
                    approval_status  TEXT NOT NULL DEFAULT 'pending',
                    approved_by      TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS roi_assessments (
                    id                       TEXT PRIMARY KEY,
                    org_id                   TEXT NOT NULL,
                    category                 TEXT NOT NULL DEFAULT '',
                    initiative_name          TEXT NOT NULL,
                    investment_amount        REAL NOT NULL,
                    estimated_risk_reduction REAL NOT NULL,
                    calculated_roi           REAL NOT NULL,
                    assessment_date          TEXT NOT NULL,
                    notes                    TEXT NOT NULL DEFAULT ''
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Allocations
    # ------------------------------------------------------------------

    def create_allocation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new budget allocation for a category."""
        fiscal_year = data.get("fiscal_year")
        if fiscal_year is None or not isinstance(fiscal_year, int) or fiscal_year <= 0:
            raise ValueError("fiscal_year must be a positive integer")
        category = data.get("category", "")
        if category not in _VALID_CATEGORIES:
            raise ValueError(
                f"category must be one of: {sorted(_VALID_CATEGORIES)}"
            )
        allocated_amount = data.get("allocated_amount")
        try:
            allocated_amount = float(allocated_amount)
        except (TypeError, ValueError):
            raise ValueError("allocated_amount must be a number")
        if allocated_amount <= 0:
            raise ValueError("allocated_amount must be > 0")

        allocation_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": allocation_id,
            "org_id": org_id,
            "fiscal_year": fiscal_year,
            "category": category,
            "allocated_amount": allocated_amount,
            "spent_amount": 0.0,
            "currency": data.get("currency", "USD"),
            "notes": data.get("notes", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO budget_allocations
                       (id, org_id, fiscal_year, category, allocated_amount,
                        spent_amount, currency, notes, created_at)
                       VALUES (:id, :org_id, :fiscal_year, :category,
                               :allocated_amount, :spent_amount, :currency,
                               :notes, :created_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_budget", "org_id": org_id, "source_engine": "security_budget"})
            except Exception:
                pass

        return row

    def list_allocations(
        self,
        org_id: str,
        fiscal_year: Optional[int] = None,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List allocations, optionally filtered by fiscal_year or category."""
        sql = "SELECT * FROM budget_allocations WHERE org_id = ?"
        params: list = [org_id]
        if fiscal_year is not None:
            sql += " AND fiscal_year = ?"
            params.append(fiscal_year)
        if category is not None:
            sql += " AND category = ?"
            params.append(category)
        sql += " ORDER BY fiscal_year DESC, category"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_allocation(
        self, org_id: str, allocation_id: str
    ) -> Optional[Dict[str, Any]]:
        """Return a single allocation or None if not found / wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM budget_allocations WHERE id = ? AND org_id = ?",
                (allocation_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Spend transactions
    # ------------------------------------------------------------------

    def record_spend(
        self, org_id: str, allocation_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a spend transaction and increment allocation.spent_amount."""
        # Verify allocation belongs to org
        allocation = self.get_allocation(org_id, allocation_id)
        if allocation is None:
            raise ValueError(f"Allocation {allocation_id} not found for org {org_id}")

        vendor_name = data.get("vendor_name", "").strip()
        if not vendor_name:
            raise ValueError("vendor_name is required")

        amount = data.get("amount")
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            raise ValueError("amount must be a number")
        if amount <= 0:
            raise ValueError("amount must be > 0")

        transaction_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": transaction_id,
            "org_id": org_id,
            "allocation_id": allocation_id,
            "vendor_name": vendor_name,
            "description": data.get("description", ""),
            "amount": amount,
            "transaction_date": data.get("transaction_date", now),
            "approval_status": "pending",
            "approved_by": "",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO spend_transactions
                       (id, org_id, allocation_id, vendor_name, description,
                        amount, transaction_date, approval_status, approved_by,
                        created_at)
                       VALUES (:id, :org_id, :allocation_id, :vendor_name,
                               :description, :amount, :transaction_date,
                               :approval_status, :approved_by, :created_at)""",
                    row,
                )
                conn.execute(
                    """UPDATE budget_allocations
                       SET spent_amount = spent_amount + ?
                       WHERE id = ? AND org_id = ?""",
                    (amount, allocation_id, org_id),
                )
        return row

    def approve_spend(
        self, org_id: str, transaction_id: str, approver: str
    ) -> Dict[str, Any]:
        """Approve a spend transaction."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM spend_transactions WHERE id = ? AND org_id = ?",
                    (transaction_id, org_id),
                ).fetchone()
                if row is None:
                    raise ValueError(
                        f"Transaction {transaction_id} not found for org {org_id}"
                    )
                conn.execute(
                    """UPDATE spend_transactions
                       SET approval_status = 'approved', approved_by = ?
                       WHERE id = ? AND org_id = ?""",
                    (approver, transaction_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM spend_transactions WHERE id = ?",
                    (transaction_id,),
                ).fetchone()
        return self._row(updated)

    def list_transactions(
        self,
        org_id: str,
        allocation_id: Optional[str] = None,
        approval_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List spend transactions with optional filters."""
        sql = "SELECT * FROM spend_transactions WHERE org_id = ?"
        params: list = [org_id]
        if allocation_id is not None:
            sql += " AND allocation_id = ?"
            params.append(allocation_id)
        if approval_status is not None:
            sql += " AND approval_status = ?"
            params.append(approval_status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # ROI Assessments
    # ------------------------------------------------------------------

    def record_roi_assessment(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record an ROI assessment for a security initiative."""
        initiative_name = data.get("initiative_name", "").strip()
        if not initiative_name:
            raise ValueError("initiative_name is required")

        investment_amount = data.get("investment_amount")
        try:
            investment_amount = float(investment_amount)
        except (TypeError, ValueError):
            raise ValueError("investment_amount must be a number")
        if investment_amount <= 0:
            raise ValueError("investment_amount must be > 0")

        estimated_risk_reduction = data.get("estimated_risk_reduction")
        try:
            estimated_risk_reduction = float(estimated_risk_reduction)
        except (TypeError, ValueError):
            raise ValueError("estimated_risk_reduction must be a number")
        if not (0 <= estimated_risk_reduction <= 100):
            raise ValueError("estimated_risk_reduction must be between 0 and 100")

        # Simplified formula: (risk_reduction * investment * 0.5) / investment * 100
        # = risk_reduction * 0.5 * 100 = risk_reduction * 50, clamped 0-500
        calculated_roi = min(500.0, max(0.0, estimated_risk_reduction * 50.0))

        assessment_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": assessment_id,
            "org_id": org_id,
            "category": data.get("category", ""),
            "initiative_name": initiative_name,
            "investment_amount": investment_amount,
            "estimated_risk_reduction": estimated_risk_reduction,
            "calculated_roi": calculated_roi,
            "assessment_date": data.get("assessment_date", now),
            "notes": data.get("notes", ""),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO roi_assessments
                       (id, org_id, category, initiative_name, investment_amount,
                        estimated_risk_reduction, calculated_roi, assessment_date,
                        notes)
                       VALUES (:id, :org_id, :category, :initiative_name,
                               :investment_amount, :estimated_risk_reduction,
                               :calculated_roi, :assessment_date, :notes)""",
                    row,
                )
        return row

    def list_roi_assessments(self, org_id: str) -> List[Dict[str, Any]]:
        """List all ROI assessments for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM roi_assessments WHERE org_id = ? ORDER BY assessment_date DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_budget_stats(
        self, org_id: str, fiscal_year: Optional[int] = None
    ) -> Dict[str, Any]:
        """Return budget summary: totals, by_category, utilization, pending count."""
        sql_filter = "WHERE org_id = ?"
        params: list = [org_id]
        if fiscal_year is not None:
            sql_filter += " AND fiscal_year = ?"
            params.append(fiscal_year)

        with self._conn() as conn:
            totals = conn.execute(
                f"""SELECT COALESCE(SUM(allocated_amount), 0.0) AS total_allocated,
                       COALESCE(SUM(spent_amount), 0.0)     AS total_spent
                    FROM budget_allocations {sql_filter}""",  # nosec B608
                params,
            ).fetchone()

            by_cat_rows = conn.execute(
                f"""SELECT category,COALESCE(SUM(allocated_amount), 0.0) AS allocated,
                       COALESCE(SUM(spent_amount), 0.0)     AS spent
                    FROM budget_allocations {sql_filter}
                    GROUP BY category""",  # nosec B608
                params,
            ).fetchall()

            # Pending transactions — always org-scoped, no fiscal_year filter here
            pending_count = conn.execute(
                """SELECT COUNT(*) FROM spend_transactions
                   WHERE org_id = ? AND approval_status = 'pending'""",
                (org_id,),
            ).fetchone()[0]

        total_allocated = totals["total_allocated"]
        total_spent = totals["total_spent"]
        remaining = total_allocated - total_spent
        utilization_pct = (
            (total_spent / total_allocated * 100) if total_allocated > 0 else 0.0
        )

        by_category: Dict[str, Any] = {}
        for r in by_cat_rows:
            by_category[r["category"]] = {
                "allocated": r["allocated"],
                "spent": r["spent"],
            }

        return {
            "total_allocated": total_allocated,
            "total_spent": total_spent,
            "remaining": remaining,
            "by_category": by_category,
            "utilization_pct": round(utilization_pct, 2),
            "pending_transactions": pending_count,
        }
