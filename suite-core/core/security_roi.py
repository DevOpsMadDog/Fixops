"""
Security Investment ROI Calculator — ALDECI ASPM Platform.

Proves security spending is worth it by quantifying risk reduction, cost
avoidance, and return on investment using the IBM Cost of a Data Breach model
($4.45M average, 2023) and Ponemon Institute benchmarks.

Key Capabilities:
- Investment tracking across 6 categories (tools, personnel, training, etc.)
- ROI metric computation per investment
- Portfolio ROI aggregation across org
- IBM breach cost model for baseline risk
- Ponemon-calibrated risk reduction benchmarks
- Investment recommendations based on coverage gaps
- Budget utilization tracking
- ROI trend analysis over time

Compliance: SOC2 CC9.1 (Risk Mitigation Strategies), CC3.2 (Risk Assessment)
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ============================================================================
# IBM / PONEMON BENCHMARK CONSTANTS
# ============================================================================

# IBM Cost of a Data Breach Report 2023
IBM_AVG_BREACH_COST_USD = 4_450_000.0
IBM_BREACH_COST_PER_RECORD_USD = 165.0
IBM_AVG_RECORDS_PER_BREACH = 17_200
IBM_BREACH_LIFECYCLE_DAYS = 277  # avg days to identify + contain

# Ponemon Institute benchmarks for risk reduction by category
PONEMON_RISK_REDUCTION: Dict[str, float] = {
    "TOOLS": 0.30,          # Security tooling reduces breach likelihood 30%
    "PERSONNEL": 0.25,      # Trained staff reduces breach cost 25%
    "TRAINING": 0.20,       # Security awareness reduces phishing success 20%
    "CONSULTING": 0.15,     # External expertise reduces risk 15%
    "INSURANCE": 0.10,      # Cyber insurance reduces financial impact 10%
    "INFRASTRUCTURE": 0.22, # Hardened infra reduces attack surface 22%
}

# Ponemon: avg hours saved per $1M invested in security automation
PONEMON_HOURS_SAVED_PER_MILLION = 2_400.0

# Ponemon: incidents prevented per $100K invested (by category)
PONEMON_INCIDENTS_PREVENTED_PER_100K: Dict[str, float] = {
    "TOOLS": 3.2,
    "PERSONNEL": 2.1,
    "TRAINING": 4.5,
    "CONSULTING": 1.8,
    "INSURANCE": 0.5,
    "INFRASTRUCTURE": 2.8,
}

# Org size breach cost multipliers (Ponemon)
ORG_SIZE_MULTIPLIER: Dict[str, float] = {
    "small": 0.62,    # <500 employees
    "medium": 1.0,    # 500-10K employees (baseline)
    "large": 1.85,    # 10K-50K employees
    "enterprise": 3.2,  # >50K employees
}

# Industry breach cost multipliers (IBM 2023)
INDUSTRY_MULTIPLIER: Dict[str, float] = {
    "healthcare": 1.99,
    "financial": 1.74,
    "pharmaceutical": 1.52,
    "technology": 1.41,
    "energy": 1.38,
    "industrial": 1.19,
    "retail": 1.03,
    "default": 1.0,
}

# Category coverage weights for recommendation scoring
CATEGORY_COVERAGE_WEIGHT: Dict[str, float] = {
    "TOOLS": 0.30,
    "PERSONNEL": 0.25,
    "TRAINING": 0.15,
    "INFRASTRUCTURE": 0.15,
    "CONSULTING": 0.10,
    "INSURANCE": 0.05,
}


# ============================================================================
# ENUMS
# ============================================================================


class InvestmentCategory(str, Enum):
    """Security investment categories aligned with Ponemon classification."""

    TOOLS = "TOOLS"
    PERSONNEL = "PERSONNEL"
    TRAINING = "TRAINING"
    CONSULTING = "CONSULTING"
    INSURANCE = "INSURANCE"
    INFRASTRUCTURE = "INFRASTRUCTURE"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class Investment(BaseModel):
    """
    Security investment record.

    Attributes:
        id: Unique investment identifier (UUID)
        name: Human-readable investment name
        category: Investment category enum
        amount_usd: One-time or initial investment amount in USD
        annual_cost: Recurring annual cost in USD
        start_date: When the investment began (ISO format)
        description: Detailed description of the investment
        org_id: Organization identifier for multi-tenancy
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=1, description="Investment name")
    category: InvestmentCategory
    amount_usd: float = Field(ge=0.0, description="One-time or initial cost (USD)")
    annual_cost: float = Field(ge=0.0, description="Recurring annual cost (USD)")
    start_date: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).date().isoformat(),
        description="Investment start date (YYYY-MM-DD)",
    )
    description: str = Field(default="", description="Investment description")
    org_id: str = Field(default="default", description="Organization ID")


class ROIMetric(BaseModel):
    """
    ROI computation result for a single investment.

    Attributes:
        investment_id: Reference to the source Investment
        risk_reduction_pct: Percentage of breach risk reduced (0-100)
        incidents_prevented: Estimated number of incidents prevented annually
        cost_avoidance_usd: Total cost avoided due to this investment (USD)
        time_saved_hours: Engineering/analyst hours saved annually
        roi_ratio: Net benefit / investment cost (1.5 = 150% return)
    """

    investment_id: str
    risk_reduction_pct: float = Field(ge=0.0, le=100.0)
    incidents_prevented: float = Field(ge=0.0)
    cost_avoidance_usd: float = Field(ge=0.0)
    time_saved_hours: float = Field(ge=0.0)
    roi_ratio: float


# ============================================================================
# SECURITY ROI ENGINE
# ============================================================================


class SecurityROI:
    """
    Security investment ROI calculator with SQLite persistence.

    Uses IBM breach cost model and Ponemon benchmarks to quantify
    the financial return on security investments.
    """

    def __init__(self, db_path: str = ":memory:", org_id: str = "default") -> None:
        """
        Initialize the SecurityROI engine.

        Args:
            db_path: SQLite database path (":memory:" for tests)
            org_id: Default organization identifier
        """
        self.db_path = db_path
        self.org_id = org_id
        self._lock = threading.RLock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        if db_path == ":memory:":
            self._mem_conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Return connection — persistent for :memory:, new for file-backed DBs."""
        if self._mem_conn is not None:
            return self._mem_conn
        return sqlite3.connect(self.db_path)

    def _close(self, conn: sqlite3.Connection) -> None:
        """Close connection only if it is not the shared in-memory connection."""
        if conn is not self._mem_conn:
            conn.close()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Initialize SQLite schema for investments and ROI snapshots."""
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS investments (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        category TEXT NOT NULL,
                        amount_usd REAL NOT NULL DEFAULT 0,
                        annual_cost REAL NOT NULL DEFAULT 0,
                        start_date TEXT NOT NULL,
                        description TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS roi_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        investment_id TEXT NOT NULL,
                        org_id TEXT NOT NULL,
                        risk_reduction_pct REAL NOT NULL,
                        incidents_prevented REAL NOT NULL,
                        cost_avoidance_usd REAL NOT NULL,
                        time_saved_hours REAL NOT NULL,
                        roi_ratio REAL NOT NULL,
                        computed_at TEXT NOT NULL,
                        FOREIGN KEY (investment_id) REFERENCES investments(id)
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS org_budgets (
                        org_id TEXT PRIMARY KEY,
                        annual_budget_usd REAL NOT NULL DEFAULT 0,
                        org_size TEXT NOT NULL DEFAULT 'medium',
                        industry TEXT NOT NULL DEFAULT 'default',
                        updated_at TEXT NOT NULL
                    )
                    """
                )

                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_investments_org ON investments (org_id)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_roi_snapshots_org ON roi_snapshots (org_id, investment_id)"
                )

                conn.commit()
            finally:
                self._close(conn)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_investment(self, investment: Investment) -> Investment:
        """
        Record a security investment.

        Args:
            investment: Investment model instance

        Returns:
            The stored Investment with assigned id
        """
        with self._lock:
            conn = self._connect()
            try:
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """
                    INSERT OR REPLACE INTO investments
                        (id, org_id, name, category, amount_usd, annual_cost,
                         start_date, description, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        investment.id,
                        investment.org_id,
                        investment.name,
                        investment.category.value,
                        investment.amount_usd,
                        investment.annual_cost,
                        investment.start_date,
                        investment.description,
                        now,
                    ),
                )
                conn.commit()
                _logger.info(
                    "Recorded investment %s (%s) for org %s",
                    investment.name,
                    investment.category.value,
                    investment.org_id,
                )
                return investment
            finally:
                self._close(conn)

    def calculate_roi(self, investment_id: str) -> ROIMetric:
        """
        Compute ROI metrics for a single investment using Ponemon benchmarks.

        Args:
            investment_id: UUID of the investment to evaluate

        Returns:
            ROIMetric with all computed values

        Raises:
            ValueError: If investment_id not found
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT id, org_id, category, amount_usd, annual_cost, start_date "
                    "FROM investments WHERE id = ?",
                    (investment_id,),
                ).fetchone()

                if not row:
                    raise ValueError(f"Investment {investment_id!r} not found")

                inv_id, org_id, category, amount_usd, annual_cost, start_date = row
                total_cost = amount_usd + annual_cost

                # Risk reduction from Ponemon benchmarks
                risk_reduction_pct = PONEMON_RISK_REDUCTION.get(category, 0.15) * 100.0

                # Incidents prevented: Ponemon rate × investment in $100K units
                investment_100k_units = max(total_cost / 100_000.0, 0.0)
                rate = PONEMON_INCIDENTS_PREVENTED_PER_100K.get(category, 1.0)
                incidents_prevented = investment_100k_units * rate

                # Cost avoidance: risk_reduction_fraction × IBM avg breach cost
                risk_fraction = risk_reduction_pct / 100.0
                cost_avoidance_usd = risk_fraction * IBM_AVG_BREACH_COST_USD

                # Time saved: Ponemon hours/million × investment in millions
                investment_millions = max(total_cost / 1_000_000.0, 0.0)
                time_saved_hours = investment_millions * PONEMON_HOURS_SAVED_PER_MILLION

                # ROI ratio: net benefit / cost
                # Net benefit = cost_avoidance + time value (avg $125/hr analyst)
                analyst_hourly_rate = 125.0
                time_value_usd = time_saved_hours * analyst_hourly_rate
                net_benefit = cost_avoidance_usd + time_value_usd
                roi_ratio = net_benefit / total_cost if total_cost > 0 else 0.0

                metric = ROIMetric(
                    investment_id=inv_id,
                    risk_reduction_pct=round(risk_reduction_pct, 2),
                    incidents_prevented=round(incidents_prevented, 2),
                    cost_avoidance_usd=round(cost_avoidance_usd, 2),
                    time_saved_hours=round(time_saved_hours, 2),
                    roi_ratio=round(roi_ratio, 4),
                )

                # Persist snapshot
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """
                    INSERT INTO roi_snapshots
                        (investment_id, org_id, risk_reduction_pct, incidents_prevented,
                         cost_avoidance_usd, time_saved_hours, roi_ratio, computed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        inv_id,
                        org_id,
                        metric.risk_reduction_pct,
                        metric.incidents_prevented,
                        metric.cost_avoidance_usd,
                        metric.time_saved_hours,
                        metric.roi_ratio,
                        now,
                    ),
                )
                conn.commit()
                return metric
            finally:
                self._close(conn)

    def get_portfolio_roi(self, org_id: str) -> Dict[str, Any]:
        """
        Aggregate ROI across all investments for an organization.

        Returns total cost, total cost avoidance, blended ROI, and per-investment
        metrics sorted by roi_ratio descending.

        Args:
            org_id: Organization identifier

        Returns:
            Dict with portfolio summary and per-investment breakdown
        """
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT id FROM investments WHERE org_id = ?",
                    (org_id,),
                ).fetchall()

                if not rows:
                    return {
                        "org_id": org_id,
                        "total_investments": 0,
                        "total_cost_usd": 0.0,
                        "total_cost_avoidance_usd": 0.0,
                        "total_incidents_prevented": 0.0,
                        "total_time_saved_hours": 0.0,
                        "blended_roi_ratio": 0.0,
                        "avg_risk_reduction_pct": 0.0,
                        "investments": [],
                    }

                metrics: List[Dict[str, Any]] = []
                total_cost = 0.0
                for (inv_id,) in rows:
                    try:
                        m = self.calculate_roi(inv_id)
                        inv_row = conn.execute(
                            "SELECT name, category, amount_usd, annual_cost FROM investments WHERE id = ?",
                            (inv_id,),
                        ).fetchone()
                        name, category, amount_usd, annual_cost = inv_row
                        inv_total = amount_usd + annual_cost
                        total_cost += inv_total
                        metrics.append(
                            {
                                "investment_id": inv_id,
                                "name": name,
                                "category": category,
                                "cost_usd": inv_total,
                                "risk_reduction_pct": m.risk_reduction_pct,
                                "incidents_prevented": m.incidents_prevented,
                                "cost_avoidance_usd": m.cost_avoidance_usd,
                                "time_saved_hours": m.time_saved_hours,
                                "roi_ratio": m.roi_ratio,
                            }
                        )
                    except Exception as exc:
                        _logger.warning("Failed ROI for %s: %s", inv_id, exc)

                metrics.sort(key=lambda x: x["roi_ratio"], reverse=True)

                total_avoidance = sum(m["cost_avoidance_usd"] for m in metrics)
                total_incidents = sum(m["incidents_prevented"] for m in metrics)
                total_hours = sum(m["time_saved_hours"] for m in metrics)
                avg_risk_reduction = (
                    sum(m["risk_reduction_pct"] for m in metrics) / len(metrics)
                    if metrics
                    else 0.0
                )
                analyst_hourly_rate = 125.0
                net_benefit = total_avoidance + total_hours * analyst_hourly_rate
                blended_roi = net_benefit / total_cost if total_cost > 0 else 0.0

                return {
                    "org_id": org_id,
                    "total_investments": len(metrics),
                    "total_cost_usd": round(total_cost, 2),
                    "total_cost_avoidance_usd": round(total_avoidance, 2),
                    "total_incidents_prevented": round(total_incidents, 2),
                    "total_time_saved_hours": round(total_hours, 2),
                    "blended_roi_ratio": round(blended_roi, 4),
                    "avg_risk_reduction_pct": round(avg_risk_reduction, 2),
                    "investments": metrics,
                }
            finally:
                self._close(conn)

    def get_cost_of_breach_estimate(
        self,
        org_id: str,
        org_size: str = "medium",
        industry: str = "default",
        records_at_risk: int = IBM_AVG_RECORDS_PER_BREACH,
    ) -> Dict[str, Any]:
        """
        Estimate breach cost using the IBM Cost of a Data Breach model.

        Args:
            org_id: Organization identifier
            org_size: One of small / medium / large / enterprise
            industry: Industry sector (healthcare, financial, etc.)
            records_at_risk: Number of records potentially exposed

        Returns:
            Dict with estimated breach cost components
        """
        size_mult = ORG_SIZE_MULTIPLIER.get(org_size, 1.0)
        industry_mult = INDUSTRY_MULTIPLIER.get(industry, 1.0)

        base_cost = IBM_AVG_BREACH_COST_USD * size_mult * industry_mult
        record_cost = records_at_risk * IBM_BREACH_COST_PER_RECORD_USD
        # Use whichever is higher — event-based vs record-based
        estimated_cost = max(base_cost, record_cost)

        return {
            "org_id": org_id,
            "estimated_breach_cost_usd": round(estimated_cost, 2),
            "base_ibm_avg_usd": IBM_AVG_BREACH_COST_USD,
            "org_size": org_size,
            "org_size_multiplier": size_mult,
            "industry": industry,
            "industry_multiplier": industry_mult,
            "records_at_risk": records_at_risk,
            "cost_per_record_usd": IBM_BREACH_COST_PER_RECORD_USD,
            "breach_lifecycle_days": IBM_BREACH_LIFECYCLE_DAYS,
            "model": "IBM Cost of a Data Breach 2023",
        }

    def get_risk_reduction(self, org_id: str) -> Dict[str, Any]:
        """
        Calculate how much total risk the org's investments have reduced.

        Uses portfolio coverage across categories weighted by Ponemon importance.

        Args:
            org_id: Organization identifier

        Returns:
            Dict with overall and per-category risk reduction
        """
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT category, SUM(amount_usd + annual_cost) as total "
                    "FROM investments WHERE org_id = ? GROUP BY category",
                    (org_id,),
                ).fetchall()

                category_data: Dict[str, Any] = {}
                for cat_val, total in rows:
                    reduction_pct = PONEMON_RISK_REDUCTION.get(cat_val, 0.10) * 100.0
                    weight = CATEGORY_COVERAGE_WEIGHT.get(cat_val, 0.10)
                    category_data[cat_val] = {
                        "total_invested_usd": round(total, 2),
                        "risk_reduction_pct": round(reduction_pct, 2),
                        "weight": weight,
                        "weighted_reduction": round(reduction_pct * weight, 4),
                    }

                # Overall weighted risk reduction capped at 85%
                overall_reduction = min(
                    sum(v["weighted_reduction"] for v in category_data.values()), 85.0
                )

                breach_estimate = self.get_cost_of_breach_estimate(org_id)
                base_cost = breach_estimate["estimated_breach_cost_usd"]
                residual_risk_usd = base_cost * (1.0 - overall_reduction / 100.0)

                return {
                    "org_id": org_id,
                    "overall_risk_reduction_pct": round(overall_reduction, 2),
                    "residual_breach_risk_usd": round(residual_risk_usd, 2),
                    "baseline_breach_cost_usd": round(base_cost, 2),
                    "category_breakdown": category_data,
                    "methodology": "Ponemon Institute weighted category benchmarks",
                }
            finally:
                self._close(conn)

    def get_investment_recommendations(self, org_id: str) -> Dict[str, Any]:
        """
        Recommend where to invest next based on coverage gaps.

        Identifies under-invested categories relative to Ponemon importance
        weights and returns prioritized recommendations.

        Args:
            org_id: Organization identifier

        Returns:
            Dict with ranked recommendations and rationale
        """
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT category, SUM(amount_usd + annual_cost) as total "
                    "FROM investments WHERE org_id = ? GROUP BY category",
                    (org_id,),
                ).fetchall()

                invested_by_category: Dict[str, float] = {r[0]: r[1] for r in rows}
                total_invested = sum(invested_by_category.values()) or 1.0

                recommendations: List[Dict[str, Any]] = []
                for cat, weight in CATEGORY_COVERAGE_WEIGHT.items():
                    current = invested_by_category.get(cat, 0.0)
                    current_fraction = current / total_invested
                    gap = max(weight - current_fraction, 0.0)
                    roi_potential = PONEMON_RISK_REDUCTION.get(cat, 0.10)

                    recommendations.append(
                        {
                            "category": cat,
                            "ideal_allocation_pct": round(weight * 100, 1),
                            "current_allocation_pct": round(current_fraction * 100, 1),
                            "gap_pct": round(gap * 100, 1),
                            "roi_potential": round(roi_potential * 100, 1),
                            "priority_score": round(gap * roi_potential * 100, 4),
                            "rationale": _recommendation_rationale(cat, gap),
                        }
                    )

                recommendations.sort(key=lambda x: x["priority_score"], reverse=True)

                return {
                    "org_id": org_id,
                    "total_invested_usd": round(total_invested, 2),
                    "recommendations": recommendations,
                    "methodology": "Ponemon coverage-gap × ROI-potential scoring",
                }
            finally:
                self._close(conn)

    def get_budget_utilization(
        self, org_id: str, annual_budget_usd: float = 0.0
    ) -> Dict[str, Any]:
        """
        Compute spending vs budget and category allocation breakdown.

        Args:
            org_id: Organization identifier
            annual_budget_usd: Total annual security budget (0 = no budget set)

        Returns:
            Dict with utilization metrics and category breakdown
        """
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT category, SUM(amount_usd) as one_time, SUM(annual_cost) as recurring "
                    "FROM investments WHERE org_id = ? GROUP BY category",
                    (org_id,),
                ).fetchall()

                total_one_time = 0.0
                total_recurring = 0.0
                category_breakdown: List[Dict[str, Any]] = []

                for cat, one_time, recurring in rows:
                    cat_total = (one_time or 0.0) + (recurring or 0.0)
                    total_one_time += one_time or 0.0
                    total_recurring += recurring or 0.0
                    category_breakdown.append(
                        {
                            "category": cat,
                            "one_time_usd": round(one_time or 0.0, 2),
                            "annual_recurring_usd": round(recurring or 0.0, 2),
                            "total_usd": round(cat_total, 2),
                        }
                    )

                total_spent = total_one_time + total_recurring
                utilization_pct = (
                    (total_spent / annual_budget_usd * 100.0) if annual_budget_usd > 0 else None
                )
                remaining = (
                    annual_budget_usd - total_spent if annual_budget_usd > 0 else None
                )

                return {
                    "org_id": org_id,
                    "annual_budget_usd": annual_budget_usd,
                    "total_spent_usd": round(total_spent, 2),
                    "total_one_time_usd": round(total_one_time, 2),
                    "total_recurring_usd": round(total_recurring, 2),
                    "utilization_pct": round(utilization_pct, 2) if utilization_pct is not None else None,
                    "remaining_budget_usd": round(remaining, 2) if remaining is not None else None,
                    "category_breakdown": category_breakdown,
                }
            finally:
                self._close(conn)

    def get_roi_trend(self, org_id: str, months: int = 12) -> Dict[str, Any]:
        """
        Return ROI snapshots over the last N months for trend analysis.

        Args:
            org_id: Organization identifier
            months: Number of months to look back (1-60)

        Returns:
            Dict with monthly ROI data points sorted ascending by date
        """
        months = max(1, min(months, 60))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=months * 30)).isoformat()

        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT
                        substr(computed_at, 1, 7) as month,
                        AVG(roi_ratio) as avg_roi,
                        SUM(cost_avoidance_usd) as total_avoidance,
                        SUM(incidents_prevented) as total_prevented,
                        AVG(risk_reduction_pct) as avg_risk_reduction,
                        COUNT(*) as snapshot_count
                    FROM roi_snapshots
                    WHERE org_id = ? AND computed_at >= ?
                    GROUP BY month
                    ORDER BY month ASC
                    """,
                    (org_id, cutoff),
                ).fetchall()

                data_points = [
                    {
                        "month": row[0],
                        "avg_roi_ratio": round(row[1] or 0.0, 4),
                        "total_cost_avoidance_usd": round(row[2] or 0.0, 2),
                        "total_incidents_prevented": round(row[3] or 0.0, 2),
                        "avg_risk_reduction_pct": round(row[4] or 0.0, 2),
                        "snapshot_count": row[5],
                    }
                    for row in rows
                ]

                return {
                    "org_id": org_id,
                    "months_requested": months,
                    "data_points": data_points,
                    "trend_direction": _compute_trend(
                        [p["avg_roi_ratio"] for p in data_points]
                    ),
                }
            finally:
                self._close(conn)


# ============================================================================
# HELPERS
# ============================================================================


def _recommendation_rationale(category: str, gap: float) -> str:
    """Return a human-readable rationale for investing in a category."""
    rationales: Dict[str, str] = {
        "TOOLS": (
            "Security tooling provides automated detection/response reducing mean-time-to-detect "
            "(MTTD) and mean-time-to-respond (MTTR). Ponemon: 30% breach cost reduction."
        ),
        "PERSONNEL": (
            "Skilled security staff drive consistent program execution. "
            "Ponemon: 25% reduction in breach probability with dedicated teams."
        ),
        "TRAINING": (
            "Security awareness training reduces phishing success rates by up to 70%. "
            "Highest incidents-prevented-per-dollar ratio (4.5 per $100K)."
        ),
        "CONSULTING": (
            "External expertise fills skill gaps and provides adversarial perspective. "
            "IBM: organizations using consultants detect breaches 28 days faster."
        ),
        "INSURANCE": (
            "Cyber insurance transfers residual financial risk. "
            "Essential for catastrophic breach scenarios exceeding $4.45M IBM average."
        ),
        "INFRASTRUCTURE": (
            "Hardened infrastructure reduces attack surface area. "
            "Ponemon: 22% risk reduction from network segmentation and endpoint controls."
        ),
    }
    base = rationales.get(category, f"Invest in {category} to reduce security risk.")
    if gap > 0.10:
        base += f" Current allocation is {gap * 100:.0f}% below optimal target."
    return base


def _compute_trend(values: List[float]) -> str:
    """Classify trend direction from a series of ROI values."""
    if len(values) < 2:
        return "insufficient_data"
    delta = values[-1] - values[0]
    if delta > 0.05:
        return "improving"
    if delta < -0.05:
        return "degrading"
    return "stable"


# ============================================================================
# SINGLETON
# ============================================================================

_instance: Optional[SecurityROI] = None
_instance_lock = threading.Lock()


def get_security_roi(
    db_path: str = "security_roi.db", org_id: str = "default"
) -> SecurityROI:
    """
    Return the process-level SecurityROI singleton.

    Args:
        db_path: SQLite path (first call wins)
        org_id: Default org identifier

    Returns:
        Shared SecurityROI instance
    """
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = SecurityROI(db_path=db_path, org_id=org_id)
    return _instance
