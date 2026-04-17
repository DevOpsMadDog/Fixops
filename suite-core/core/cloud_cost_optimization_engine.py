"""Cloud Cost Optimization Engine — ALDECI.

Tracks security tool costs, ROI analysis, and cost-per-risk-reduced analytics
to help organizations optimize their security spend.

Capabilities:
  - Register and track security tool costs (monthly/annual)
  - Record utilization and risk coverage per tool
  - Identify and implement cost optimizations
  - ROI assessment: (incidents_prevented * avg_cost - annual_cost) / annual_cost
  - Portfolio summary with by-category breakdown
  - Multi-tenant org_id isolation

Compliance: ISO 27001 A.5.36, NIST CSF ID.AM-6
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

_VALID_TOOL_CATEGORIES = {
    "detection",
    "prevention",
    "response",
    "compliance",
    "identity",
    "network",
    "endpoint",
    "cloud",
    "data",
    "governance",
}

_VALID_OPTIMIZATION_TYPES = {
    "right-sizing",
    "license-reduction",
    "contract-renegotiation",
    "consolidation",
    "elimination",
    "migration",
}

_VALID_CLOUD_PROVIDERS = {
    "aws",
    "azure",
    "gcp",
    "multi-cloud",
    "on-prem",
    "saas",
}

_VALID_STATUSES = {"identified", "in-progress", "implemented", "rejected"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


class CloudCostOptimizationEngine:
    """SQLite WAL-backed Cloud Cost Optimization engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/cloud_cost_optimization.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(
                Path(_DEFAULT_DB_DIR) / "cloud_cost_optimization.db"
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
                CREATE TABLE IF NOT EXISTS security_tools (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    tool_name        TEXT NOT NULL,
                    tool_category    TEXT NOT NULL DEFAULT 'detection',
                    vendor           TEXT NOT NULL DEFAULT '',
                    cloud_provider   TEXT NOT NULL DEFAULT 'multi-cloud',
                    monthly_cost     REAL NOT NULL DEFAULT 0.0,
                    annual_cost      REAL NOT NULL DEFAULT 0.0,
                    licenses         INTEGER NOT NULL DEFAULT 0,
                    utilization_pct  REAL NOT NULL DEFAULT 0.0,
                    risk_coverage    TEXT NOT NULL DEFAULT '[]',
                    status           TEXT NOT NULL DEFAULT 'active',
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_st_org
                    ON security_tools (org_id, tool_category);

                CREATE INDEX IF NOT EXISTS idx_st_org_status
                    ON security_tools (org_id, status);

                CREATE TABLE IF NOT EXISTS cost_optimizations (
                    id                TEXT PRIMARY KEY,
                    tool_id           TEXT NOT NULL,
                    org_id            TEXT NOT NULL,
                    optimization_type TEXT NOT NULL,
                    description       TEXT NOT NULL DEFAULT '',
                    estimated_savings REAL NOT NULL DEFAULT 0.0,
                    actual_savings    REAL NOT NULL DEFAULT 0.0,
                    status            TEXT NOT NULL DEFAULT 'identified',
                    identified_at     TEXT NOT NULL,
                    implemented_at    TEXT,
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_co_tool_org
                    ON cost_optimizations (tool_id, org_id);

                CREATE INDEX IF NOT EXISTS idx_co_org_status
                    ON cost_optimizations (org_id, status);

                CREATE TABLE IF NOT EXISTS roi_assessments (
                    id                  TEXT PRIMARY KEY,
                    tool_id             TEXT NOT NULL,
                    org_id              TEXT NOT NULL,
                    assessment_period   TEXT NOT NULL,
                    incidents_prevented INTEGER NOT NULL DEFAULT 0,
                    avg_incident_cost   REAL NOT NULL DEFAULT 0.0,
                    risk_reduction_pct  REAL NOT NULL DEFAULT 0.0,
                    roi_pct             REAL NOT NULL DEFAULT 0.0,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ra_tool_org
                    ON roi_assessments (tool_id, org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _get_tool(self, tool_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM security_tools WHERE id=? AND org_id=?",
                (tool_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def register_tool(
        self,
        org_id: str,
        tool_name: str,
        tool_category: str = "detection",
        vendor: str = "",
        cloud_provider: str = "multi-cloud",
        monthly_cost: float = 0.0,
        licenses: int = 0,
    ) -> Dict[str, Any]:
        """Register a new security tool with cost tracking."""
        if tool_category not in _VALID_TOOL_CATEGORIES:
            raise ValueError(
                f"tool_category must be one of {sorted(_VALID_TOOL_CATEGORIES)}"
            )
        if cloud_provider not in _VALID_CLOUD_PROVIDERS:
            raise ValueError(
                f"cloud_provider must be one of {sorted(_VALID_CLOUD_PROVIDERS)}"
            )
        if monthly_cost < 0:
            raise ValueError("monthly_cost must be >= 0")
        annual_cost = monthly_cost * 12
        row_id = str(uuid.uuid4())
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO security_tools
                        (id, org_id, tool_name, tool_category, vendor, cloud_provider,
                         monthly_cost, annual_cost, licenses, utilization_pct,
                         risk_coverage, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,0.0,'[]','active',?)
                    """,
                    (
                        row_id, org_id, tool_name, tool_category, vendor,
                        cloud_provider, monthly_cost, annual_cost, licenses, now,
                    ),
                )
        return self._get_tool(row_id, org_id)

    def update_utilization(
        self,
        tool_id: str,
        org_id: str,
        utilization_pct: float,
        risk_coverage: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Update tool utilization and risk coverage."""
        utilization_pct = _clamp(utilization_pct)
        risk_json = json.dumps(risk_coverage if risk_coverage is not None else [])
        with self._lock:
            tool = self._get_tool(tool_id, org_id)
            if not tool:
                raise KeyError(f"Tool {tool_id} not found")
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE security_tools
                    SET utilization_pct=?, risk_coverage=?
                    WHERE id=? AND org_id=?
                    """,
                    (utilization_pct, risk_json, tool_id, org_id),
                )
        return self._get_tool(tool_id, org_id)

    def list_tools(self, org_id: str) -> List[Dict[str, Any]]:
        """List all tools for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM security_tools WHERE org_id=? ORDER BY monthly_cost DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Optimizations
    # ------------------------------------------------------------------

    def add_optimization(
        self,
        tool_id: str,
        org_id: str,
        optimization_type: str,
        description: str = "",
        estimated_savings: float = 0.0,
    ) -> Dict[str, Any]:
        """Identify a cost optimization opportunity."""
        if optimization_type not in _VALID_OPTIMIZATION_TYPES:
            raise ValueError(
                f"optimization_type must be one of {sorted(_VALID_OPTIMIZATION_TYPES)}"
            )
        if estimated_savings < 0:
            raise ValueError("estimated_savings must be >= 0")
        with self._lock:
            tool = self._get_tool(tool_id, org_id)
            if not tool:
                raise KeyError(f"Tool {tool_id} not found")
            row_id = str(uuid.uuid4())
            now = _now()
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO cost_optimizations
                        (id, tool_id, org_id, optimization_type, description,
                         estimated_savings, actual_savings, status,
                         identified_at, implemented_at, created_at)
                    VALUES (?,?,?,?,?,?,0.0,'identified',?,NULL,?)
                    """,
                    (
                        row_id, tool_id, org_id, optimization_type,
                        description, estimated_savings, now, now,
                    ),
                )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM cost_optimizations WHERE id=?", (row_id,)
            ).fetchone()
        return self._row(row)

    def implement_optimization(
        self,
        optimization_id: str,
        org_id: str,
        actual_savings: float,
    ) -> Dict[str, Any]:
        """Mark an optimization as implemented with actual savings."""
        if actual_savings < 0:
            raise ValueError("actual_savings must be >= 0")
        now = _now()
        with self._lock:
            with self._conn() as conn:
                result = conn.execute(
                    """
                    UPDATE cost_optimizations
                    SET status='implemented', implemented_at=?, actual_savings=?
                    WHERE id=? AND org_id=?
                    """,
                    (now, actual_savings, optimization_id, org_id),
                )
                if result.rowcount == 0:
                    raise KeyError(f"Optimization {optimization_id} not found")
                row = conn.execute(
                    "SELECT * FROM cost_optimizations WHERE id=?",
                    (optimization_id,),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # ROI assessments
    # ------------------------------------------------------------------

    def add_roi_assessment(
        self,
        tool_id: str,
        org_id: str,
        assessment_period: str,
        incidents_prevented: int,
        avg_incident_cost: float,
        risk_reduction_pct: float,
    ) -> Dict[str, Any]:
        """Add a ROI assessment for a security tool."""
        risk_reduction_pct = _clamp(risk_reduction_pct)
        tool = self._get_tool(tool_id, org_id)
        if not tool:
            raise KeyError(f"Tool {tool_id} not found")
        annual_cost = tool["annual_cost"]
        roi_pct = (
            (incidents_prevented * avg_incident_cost - annual_cost)
            / max(1.0, annual_cost)
            * 100
        )
        row_id = str(uuid.uuid4())
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO roi_assessments
                        (id, tool_id, org_id, assessment_period,
                         incidents_prevented, avg_incident_cost,
                         risk_reduction_pct, roi_pct, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        row_id, tool_id, org_id, assessment_period,
                        incidents_prevented, avg_incident_cost,
                        risk_reduction_pct, roi_pct, now,
                    ),
                )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM roi_assessments WHERE id=?", (row_id,)
            ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def get_tool_roi(self, tool_id: str, org_id: str) -> Dict[str, Any]:
        """Return tool details, assessments, optimizations, and total realized savings."""
        tool = self._get_tool(tool_id, org_id)
        if not tool:
            raise KeyError(f"Tool {tool_id} not found")
        with self._conn() as conn:
            assessments = conn.execute(
                "SELECT * FROM roi_assessments WHERE tool_id=? AND org_id=? ORDER BY created_at DESC",
                (tool_id, org_id),
            ).fetchall()
            optimizations = conn.execute(
                "SELECT * FROM cost_optimizations WHERE tool_id=? AND org_id=? ORDER BY created_at DESC",
                (tool_id, org_id),
            ).fetchall()
            savings_row = conn.execute(
                """
                SELECT COALESCE(SUM(actual_savings), 0.0) AS total_savings
                FROM cost_optimizations
                WHERE tool_id=? AND org_id=? AND status='implemented'
                """,
                (tool_id, org_id),
            ).fetchone()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "cloud_cost_optimization_engine", "org_id": org_id, "source_engine": "cloud_cost_optimization_engine"})
            except Exception:
                pass
        return {
            **tool,
            "assessments": [self._row(r) for r in assessments],
            "optimizations": [self._row(r) for r in optimizations],
            "total_savings": savings_row["total_savings"],
        }

    def get_underutilized_tools(
        self, org_id: str, max_utilization: float = 30.0
    ) -> List[Dict[str, Any]]:
        """Return active tools with utilization <= max_utilization, ordered by monthly_cost DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM security_tools
                WHERE org_id=? AND status='active' AND utilization_pct <= ?
                ORDER BY monthly_cost DESC
                """,
                (org_id, max_utilization),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_portfolio_summary(self, org_id: str) -> Dict[str, Any]:
        """Aggregate portfolio summary with per-category breakdown."""
        with self._conn() as conn:
            agg = conn.execute(
                """
                SELECT COUNT(*) AS total_tools,
                       COALESCE(SUM(monthly_cost), 0.0) AS total_monthly_cost,
                       COALESCE(SUM(annual_cost), 0.0) AS total_annual_cost,
                       COALESCE(AVG(utilization_pct), 0.0) AS avg_utilization
                FROM security_tools
                WHERE org_id=?
                """,
                (org_id,),
            ).fetchone()

            potential_savings = conn.execute(
                """
                SELECT COALESCE(SUM(estimated_savings), 0.0) AS ps
                FROM cost_optimizations
                WHERE org_id=? AND status='identified'
                """,
                (org_id,),
            ).fetchone()["ps"]

            realized_savings = conn.execute(
                """
                SELECT COALESCE(SUM(actual_savings), 0.0) AS rs
                FROM cost_optimizations
                WHERE org_id=? AND status='implemented'
                """,
                (org_id,),
            ).fetchone()["rs"]

            cat_rows = conn.execute(
                """
                SELECT tool_category, COALESCE(SUM(monthly_cost), 0.0) AS monthly_cost
                FROM security_tools
                WHERE org_id=?
                GROUP BY tool_category
                """,
                (org_id,),
            ).fetchall()
            by_category = {r["tool_category"]: r["monthly_cost"] for r in cat_rows}

            # Count tools with roi_pct > 100 from latest assessment per tool
            high_roi = conn.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM (
                    SELECT tool_id, MAX(created_at) AS latest
                    FROM roi_assessments
                    WHERE org_id=?
                    GROUP BY tool_id
                ) AS latest_ra
                JOIN roi_assessments ra ON ra.tool_id = latest_ra.tool_id
                    AND ra.created_at = latest_ra.latest
                    AND ra.org_id=?
                WHERE ra.roi_pct > 100
                """,
                (org_id, org_id),
            ).fetchone()["cnt"]

        return {
            "total_tools": agg["total_tools"] or 0,
            "total_monthly_cost": agg["total_monthly_cost"],
            "total_annual_cost": agg["total_annual_cost"],
            "avg_utilization": agg["avg_utilization"],
            "potential_savings": potential_savings,
            "realized_savings": realized_savings,
            "by_category": by_category,
            "high_roi_tools": high_roi or 0,
        }

    def get_cost_per_risk(self, org_id: str) -> List[Dict[str, Any]]:
        """Return cost_per_risk_pct = annual_cost / max(1, risk_reduction_pct) per tool, ASC."""
        with self._conn() as conn:
            # Get the latest ROI assessment per tool
            rows = conn.execute(
                """
                SELECT st.id AS tool_id,
                       st.tool_name,
                       st.tool_category,
                       st.annual_cost,
                       ra.risk_reduction_pct,
                       ra.roi_pct
                FROM security_tools st
                LEFT JOIN (
                    SELECT tool_id, MAX(created_at) AS latest
                    FROM roi_assessments
                    WHERE org_id=?
                    GROUP BY tool_id
                ) latest_ra ON latest_ra.tool_id = st.id
                LEFT JOIN roi_assessments ra
                    ON ra.tool_id = latest_ra.tool_id
                    AND ra.created_at = latest_ra.latest
                    AND ra.org_id=?
                WHERE st.org_id=?
                ORDER BY st.annual_cost / MAX(1.0, COALESCE(ra.risk_reduction_pct, 0)) ASC
                """,
                (org_id, org_id, org_id),
            ).fetchall()

        result = []
        for r in rows:
            annual_cost = r["annual_cost"] or 0.0
            risk_reduction_pct = r["risk_reduction_pct"] or 0.0
            cost_per_risk_pct = annual_cost / max(1.0, risk_reduction_pct)
            result.append({
                "tool_id": r["tool_id"],
                "tool_name": r["tool_name"],
                "tool_category": r["tool_category"],
                "annual_cost": annual_cost,
                "risk_reduction_pct": risk_reduction_pct,
                "roi_pct": r["roi_pct"] or 0.0,
                "cost_per_risk_pct": cost_per_risk_pct,
            })
        return result
