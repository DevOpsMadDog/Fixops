"""Security Investment Engine — ALDECI.

Tracks security budget investments, ROI, and business value across the
full investment lifecycle (planned → active → completed/cancelled).

Supports:
- Investment portfolio management with ROI tracking
- Outcome recording with verified value quantification
- Budget allocation and spend tracking per fiscal year
- Portfolio summary with top-ROI rankings
- Multi-tenant isolation via org_id

Compliance: NIST CSF PR.IP-10, ISO/IEC 27001 A.5.36, SOC 2 CC1.3
"""
from __future__ import annotations

import contextlib
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_investment.db"
)

_VALID_CATEGORIES = {
    "tools", "personnel", "training", "compliance",
    "infrastructure", "consulting", "insurance", "R&D",
}
_VALID_OUTCOME_TYPES = {
    "cost-avoidance", "incident-reduction", "efficiency",
    "compliance", "risk-reduction", "revenue-protection",
}
_VALID_STATUSES = {"planned", "active", "completed", "cancelled"}
_VALID_CURRENCIES = {"USD", "EUR", "GBP", "AUD", "CAD"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityInvestmentEngine:
    """SQLite WAL-backed Security Investment engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS investments (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    investment_name     TEXT NOT NULL,
                    investment_category TEXT NOT NULL,
                    vendor              TEXT NOT NULL DEFAULT '',
                    amount              REAL NOT NULL,
                    currency            TEXT NOT NULL DEFAULT 'USD',
                    start_date          TEXT NOT NULL DEFAULT '',
                    end_date            TEXT NOT NULL DEFAULT '',
                    status              TEXT NOT NULL DEFAULT 'planned',
                    roi_score           REAL NOT NULL DEFAULT 0.0,
                    risk_reduction      REAL NOT NULL DEFAULT 0.0,
                    compliance_value    REAL NOT NULL DEFAULT 0.0,
                    created_at          TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS investment_outcomes (
                    id               TEXT PRIMARY KEY,
                    investment_id    TEXT NOT NULL,
                    org_id           TEXT NOT NULL,
                    outcome_type     TEXT NOT NULL,
                    description      TEXT NOT NULL DEFAULT '',
                    quantified_value REAL NOT NULL DEFAULT 0.0,
                    measurement_date TEXT NOT NULL DEFAULT '',
                    verified         INTEGER NOT NULL DEFAULT 0,
                    created_at       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS budget_allocations (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    fiscal_year  TEXT NOT NULL,
                    category     TEXT NOT NULL,
                    allocated    REAL NOT NULL DEFAULT 0.0,
                    spent        REAL NOT NULL DEFAULT 0.0,
                    committed    REAL NOT NULL DEFAULT 0.0,
                    currency     TEXT NOT NULL DEFAULT 'USD',
                    created_at   TEXT NOT NULL,
                    UNIQUE(org_id, fiscal_year, category)
                );

                CREATE INDEX IF NOT EXISTS idx_investments_org
                    ON investments(org_id);
                CREATE INDEX IF NOT EXISTS idx_outcomes_investment
                    ON investment_outcomes(investment_id);
                CREATE INDEX IF NOT EXISTS idx_budget_org_year
                    ON budget_allocations(org_id, fiscal_year);
            """)

    def _row_to_dict(self, row) -> Dict[str, Any]:
        return dict(row) if row else {}

    def _recompute_roi(self, conn, investment_id: str, org_id: str) -> float:
        """Recompute ROI score = sum(verified outcome values) / investment.amount * 100."""
        inv_row = conn.execute(
            "SELECT amount FROM investments WHERE id=? AND org_id=?",
            (investment_id, org_id),
        ).fetchone()
        if not inv_row or inv_row["amount"] == 0:
            return 0.0
        result = conn.execute(
            "SELECT SUM(quantified_value) FROM investment_outcomes "
            "WHERE investment_id=? AND org_id=? AND verified=1",
            (investment_id, org_id),
        ).fetchone()
        total_value = result[0] or 0.0
        roi = (total_value / inv_row["amount"]) * 100.0
        conn.execute(
            "UPDATE investments SET roi_score=? WHERE id=? AND org_id=?",
            (roi, investment_id, org_id),
        )
        return roi

    # ------------------------------------------------------------------
    # Investment lifecycle
    # ------------------------------------------------------------------

    def create_investment(
        self,
        org_id: str,
        investment_name: str,
        investment_category: str,
        vendor: str = "",
        amount: float = 0.0,
        currency: str = "USD",
        start_date: str = "",
        end_date: str = "",
    ) -> Dict[str, Any]:
        """Create a new investment record (status=planned)."""
        if investment_category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid investment_category: {investment_category!r}. "
                             f"Valid: {_VALID_CATEGORIES}")
        if currency not in _VALID_CURRENCIES:
            raise ValueError(f"Invalid currency: {currency!r}. Valid: {_VALID_CURRENCIES}")
        inv_id = str(uuid.uuid4())
        now = _now()
        row = {
            "id": inv_id,
            "org_id": org_id,
            "investment_name": investment_name,
            "investment_category": investment_category,
            "vendor": vendor,
            "amount": amount,
            "currency": currency,
            "start_date": start_date,
            "end_date": end_date,
            "status": "planned",
            "roi_score": 0.0,
            "risk_reduction": 0.0,
            "compliance_value": 0.0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO investments
                       (id, org_id, investment_name, investment_category, vendor, amount,
                        currency, start_date, end_date, status, roi_score, risk_reduction,
                        compliance_value, created_at)
                       VALUES (:id,:org_id,:investment_name,:investment_category,:vendor,
                               :amount,:currency,:start_date,:end_date,:status,:roi_score,
                               :risk_reduction,:compliance_value,:created_at)""",
                    row,
                )
        return row

    def record_outcome(
        self,
        investment_id: str,
        org_id: str,
        outcome_type: str,
        description: str = "",
        quantified_value: float = 0.0,
        measurement_date: str = "",
        verified: bool = False,
    ) -> Dict[str, Any]:
        """Record an outcome and recompute ROI if verified."""
        if outcome_type not in _VALID_OUTCOME_TYPES:
            raise ValueError(f"Invalid outcome_type: {outcome_type!r}. "
                             f"Valid: {_VALID_OUTCOME_TYPES}")
        outcome_id = str(uuid.uuid4())
        now = _now()
        row = {
            "id": outcome_id,
            "investment_id": investment_id,
            "org_id": org_id,
            "outcome_type": outcome_type,
            "description": description,
            "quantified_value": quantified_value,
            "measurement_date": measurement_date,
            "verified": 1 if verified else 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                # Validate investment belongs to org
                inv = conn.execute(
                    "SELECT id FROM investments WHERE id=? AND org_id=?",
                    (investment_id, org_id),
                ).fetchone()
                if not inv:
                    raise ValueError(f"Investment {investment_id!r} not found for org {org_id!r}")
                conn.execute(
                    """INSERT INTO investment_outcomes
                       (id, investment_id, org_id, outcome_type, description,
                        quantified_value, measurement_date, verified, created_at)
                       VALUES (:id,:investment_id,:org_id,:outcome_type,:description,
                               :quantified_value,:measurement_date,:verified,:created_at)""",
                    row,
                )
                roi = self._recompute_roi(conn, investment_id, org_id)
        result = dict(row)
        result["roi_score_after"] = roi
        return result

    def activate_investment(self, investment_id: str, org_id: str) -> Dict[str, Any]:
        """Transition investment status to active."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE investments SET status='active' WHERE id=? AND org_id=?",
                    (investment_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM investments WHERE id=? AND org_id=?",
                    (investment_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Investment {investment_id!r} not found")
                if _get_tg_bus:
                    try:
                        bus = _get_tg_bus()
                        if bus and getattr(bus, "enabled", False):
                            bus.emit("FINDING_CREATED", {"entity_type": "security_investment_engine", "org_id": org_id, "source_engine": "security_investment_engine"})
                    except Exception:
                        pass
                return self._row_to_dict(row)

    def complete_investment(self, investment_id: str, org_id: str) -> Dict[str, Any]:
        """Transition investment status to completed."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE investments SET status='completed' WHERE id=? AND org_id=?",
                    (investment_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM investments WHERE id=? AND org_id=?",
                    (investment_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Investment {investment_id!r} not found")
                return self._row_to_dict(row)

    # ------------------------------------------------------------------
    # Budget management
    # ------------------------------------------------------------------

    def set_budget(
        self,
        org_id: str,
        fiscal_year: str,
        category: str,
        allocated: float,
        currency: str = "USD",
    ) -> Dict[str, Any]:
        """Insert or replace a budget allocation for org/year/category."""
        if category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid category: {category!r}")
        if currency not in _VALID_CURRENCIES:
            raise ValueError(f"Invalid currency: {currency!r}")
        alloc_id = str(uuid.uuid4())
        now = _now()
        with self._lock:
            with self._conn() as conn:
                # Check if exists
                existing = conn.execute(
                    "SELECT id, spent, committed FROM budget_allocations "
                    "WHERE org_id=? AND fiscal_year=? AND category=?",
                    (org_id, fiscal_year, category),
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE budget_allocations SET allocated=?, currency=? "
                        "WHERE org_id=? AND fiscal_year=? AND category=?",
                        (allocated, currency, org_id, fiscal_year, category),
                    )
                    row = conn.execute(
                        "SELECT * FROM budget_allocations "
                        "WHERE org_id=? AND fiscal_year=? AND category=?",
                        (org_id, fiscal_year, category),
                    ).fetchone()
                else:
                    conn.execute(
                        """INSERT INTO budget_allocations
                           (id, org_id, fiscal_year, category, allocated, spent, committed,
                            currency, created_at)
                           VALUES (?,?,?,?,?,0.0,0.0,?,?)""",
                        (alloc_id, org_id, fiscal_year, category, allocated, currency, now),
                    )
                    row = conn.execute(
                        "SELECT * FROM budget_allocations "
                        "WHERE org_id=? AND fiscal_year=? AND category=?",
                        (org_id, fiscal_year, category),
                    ).fetchone()
                return self._row_to_dict(row)

    def record_spend(
        self,
        org_id: str,
        fiscal_year: str,
        category: str,
        amount: float,
    ) -> Dict[str, Any]:
        """Increment spent for an allocation. Returns dict with over_budget flag."""
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT * FROM budget_allocations "
                    "WHERE org_id=? AND fiscal_year=? AND category=?",
                    (org_id, fiscal_year, category),
                ).fetchone()
                if not existing:
                    raise ValueError(
                        f"No budget allocation for org={org_id!r} "
                        f"year={fiscal_year!r} category={category!r}"
                    )
                new_spent = existing["spent"] + amount
                conn.execute(
                    "UPDATE budget_allocations SET spent=? "
                    "WHERE org_id=? AND fiscal_year=? AND category=?",
                    (new_spent, org_id, fiscal_year, category),
                )
                row = conn.execute(
                    "SELECT * FROM budget_allocations "
                    "WHERE org_id=? AND fiscal_year=? AND category=?",
                    (org_id, fiscal_year, category),
                ).fetchone()
                result = self._row_to_dict(row)
                result["over_budget"] = new_spent > existing["allocated"]
                return result

    # ------------------------------------------------------------------
    # Portfolio / reporting
    # ------------------------------------------------------------------

    def get_portfolio_summary(self, org_id: str) -> Dict[str, Any]:
        """Return portfolio-level summary including top-5 ROI investments."""
        with self._lock:
            with self._conn() as conn:
                # Totals
                totals = conn.execute(
                    """SELECT COUNT(*) as cnt,
                              SUM(amount) as total_invested,
                              AVG(roi_score) as total_roi_avg,
                              SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active_count,
                              SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed_count
                       FROM investments WHERE org_id=?""",
                    (org_id,),
                ).fetchone()

                # By category
                cat_rows = conn.execute(
                    """SELECT investment_category,
                              COUNT(*) as count,
                              SUM(amount) as total_amount,
                              AVG(roi_score) as avg_roi
                       FROM investments WHERE org_id=?
                       GROUP BY investment_category""",
                    (org_id,),
                ).fetchall()

                # Top 5 ROI
                top_roi = conn.execute(
                    """SELECT id, investment_name, investment_category, amount,
                              roi_score, status
                       FROM investments WHERE org_id=?
                       ORDER BY roi_score DESC LIMIT 5""",
                    (org_id,),
                ).fetchall()

                if _get_tg_bus:
                    try:
                        bus = _get_tg_bus()
                        if bus and getattr(bus, "enabled", False):
                            bus.emit("FINDING_CREATED", {"entity_type": "security_investment_engine", "org_id": org_id, "source_engine": "security_investment_engine"})
                    except Exception:
                        pass
                return {
                    "org_id": org_id,
                    "total_investments": totals["cnt"] or 0,
                    "total_invested": totals["total_invested"] or 0.0,
                    "total_roi_avg": round(totals["total_roi_avg"] or 0.0, 2),
                    "active_count": totals["active_count"] or 0,
                    "completed_count": totals["completed_count"] or 0,
                    "by_category": [dict(r) for r in cat_rows],
                    "top_roi_investments": [dict(r) for r in top_roi],
                }

    def get_budget_utilization(self, org_id: str, fiscal_year: str) -> List[Dict[str, Any]]:
        """Return all budget allocations for a year with remaining and over_budget flags."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM budget_allocations "
                    "WHERE org_id=? AND fiscal_year=? ORDER BY category",
                    (org_id, fiscal_year),
                ).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    d["remaining"] = d["allocated"] - d["spent"]
                    d["over_budget"] = d["spent"] > d["allocated"]
                    result.append(d)
                return result

    def list_investments(
        self,
        org_id: str,
        status: Optional[str] = None,
        investment_category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List investments with optional status/category filters."""
        with self._lock:
            with self._conn() as conn:
                sql = "SELECT * FROM investments WHERE org_id=?"
                params: list = [org_id]
                if status:
                    sql += " AND status=?"
                    params.append(status)
                if investment_category:
                    sql += " AND investment_category=?"
                    params.append(investment_category)
                sql += " ORDER BY created_at DESC"
                rows = conn.execute(sql, params).fetchall()
                return [dict(r) for r in rows]
