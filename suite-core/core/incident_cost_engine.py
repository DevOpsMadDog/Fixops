"""Incident Cost Engine — ALDECI.

Tracks financial impact of security incidents — response costs, business
impact, regulatory fines, recovery costs, and reputation damage.

Capabilities:
  - Record cost line-items per incident (estimated vs actual)
  - Finalize incidents with totals and category breakdowns
  - Benchmark comparisons (above/below/within-range vs industry avg)
  - Analytics: by type, by category, most expensive incident
  - Multi-tenant org_id isolation

Compliance: ISO 27001 A.5.29, NIST CSF RC.CO-1
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

_VALID_COST_CATEGORIES = {
    "personnel",
    "tools",
    "forensics",
    "legal",
    "regulatory-fine",
    "customer-notification",
    "PR",
    "business-interruption",
    "recovery",
    "insurance",
}

_VALID_INCIDENT_TYPES = {
    "ransomware",
    "data-breach",
    "ddos",
    "phishing",
    "insider",
    "supply-chain",
    "misconfiguration",
    "zero-day",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_VALID_CURRENCIES = {"USD", "EUR", "GBP", "AUD", "CAD"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IncidentCostEngine:
    """SQLite WAL-backed Incident Cost engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/incident_cost.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "incident_cost.db")
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
                CREATE TABLE IF NOT EXISTS incident_costs (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    incident_id     TEXT NOT NULL,
                    incident_name   TEXT NOT NULL,
                    incident_type   TEXT NOT NULL,
                    cost_category   TEXT NOT NULL,
                    amount          REAL NOT NULL DEFAULT 0,
                    currency        TEXT NOT NULL DEFAULT 'USD',
                    estimated       INTEGER NOT NULL DEFAULT 0,
                    description     TEXT NOT NULL DEFAULT '',
                    recorded_by     TEXT NOT NULL DEFAULT '',
                    recorded_at     TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ic_org_inc
                    ON incident_costs (org_id, incident_id);

                CREATE INDEX IF NOT EXISTS idx_ic_org_type
                    ON incident_costs (org_id, incident_type);

                CREATE TABLE IF NOT EXISTS incident_summaries (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    incident_id     TEXT NOT NULL,
                    incident_name   TEXT NOT NULL,
                    total_cost      REAL NOT NULL DEFAULT 0,
                    estimated_total REAL NOT NULL DEFAULT 0,
                    actual_total    REAL NOT NULL DEFAULT 0,
                    cost_categories TEXT NOT NULL DEFAULT '{}',
                    duration_hours  REAL NOT NULL DEFAULT 0,
                    severity        TEXT NOT NULL DEFAULT '',
                    closed_at       TEXT,
                    created_at      TEXT NOT NULL,
                    UNIQUE(org_id, incident_id)
                );

                CREATE INDEX IF NOT EXISTS idx_is_org
                    ON incident_summaries (org_id, severity);

                CREATE TABLE IF NOT EXISTS cost_benchmarks (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    incident_type  TEXT NOT NULL,
                    avg_cost       REAL NOT NULL DEFAULT 0,
                    median_cost    REAL NOT NULL DEFAULT 0,
                    p90_cost       REAL NOT NULL DEFAULT 0,
                    sample_size    INTEGER NOT NULL DEFAULT 0,
                    source         TEXT NOT NULL DEFAULT '',
                    published_year INTEGER NOT NULL DEFAULT 0,
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cb_org_type
                    ON cost_benchmarks (org_id, incident_type);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Cost recording
    # ------------------------------------------------------------------

    def record_cost(
        self,
        org_id: str,
        incident_id: str,
        incident_name: str,
        incident_type: str,
        cost_category: str,
        amount: float,
        currency: str = "USD",
        estimated: bool = False,
        description: str = "",
        recorded_by: str = "",
    ) -> Dict[str, Any]:
        """Record a cost line-item for a security incident."""
        if amount < 0:
            raise ValueError("amount must be >= 0")
        if incident_type not in _VALID_INCIDENT_TYPES:
            raise ValueError(
                f"Invalid incident_type: {incident_type!r}. "
                f"Must be one of {sorted(_VALID_INCIDENT_TYPES)}"
            )
        if cost_category not in _VALID_COST_CATEGORIES:
            raise ValueError(
                f"Invalid cost_category: {cost_category!r}. "
                f"Must be one of {sorted(_VALID_COST_CATEGORIES)}"
            )
        if currency not in _VALID_CURRENCIES:
            raise ValueError(
                f"Invalid currency: {currency!r}. "
                f"Must be one of {sorted(_VALID_CURRENCIES)}"
            )

        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_id": incident_id,
            "incident_name": incident_name,
            "incident_type": incident_type,
            "cost_category": cost_category,
            "amount": float(amount),
            "currency": currency,
            "estimated": 1 if estimated else 0,
            "description": description,
            "recorded_by": recorded_by,
            "recorded_at": now,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO incident_costs
                       (id, org_id, incident_id, incident_name, incident_type,
                        cost_category, amount, currency, estimated, description,
                        recorded_by, recorded_at, created_at)
                       VALUES (:id, :org_id, :incident_id, :incident_name, :incident_type,
                               :cost_category, :amount, :currency, :estimated, :description,
                               :recorded_by, :recorded_at, :created_at)""",
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Incident finalization
    # ------------------------------------------------------------------

    def finalize_incident(
        self,
        org_id: str,
        incident_id: str,
        duration_hours: float,
        severity: str,
    ) -> Dict[str, Any]:
        """Compute totals and save/update an incident summary."""
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM incident_costs WHERE org_id=? AND incident_id=?",
                (org_id, incident_id),
            ).fetchall()

        costs = [self._row(r) for r in rows]
        if not costs:
            # Allow finalizing with no costs recorded yet
            incident_name = incident_id
        else:
            incident_name = costs[0]["incident_name"]
            costs[0]["incident_type"]

        total_cost = sum(c["amount"] for c in costs)
        estimated_total = sum(c["amount"] for c in costs if c["estimated"] == 1)
        actual_total = sum(c["amount"] for c in costs if c["estimated"] == 0)

        # category breakdown
        category_breakdown: Dict[str, float] = {}
        for c in costs:
            cat = c["cost_category"]
            category_breakdown[cat] = category_breakdown.get(cat, 0.0) + c["amount"]

        now = _now()
        summary = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_id": incident_id,
            "incident_name": incident_name,
            "total_cost": total_cost,
            "estimated_total": estimated_total,
            "actual_total": actual_total,
            "cost_categories": json.dumps(category_breakdown),
            "duration_hours": float(duration_hours),
            "severity": severity,
            "closed_at": now,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO incident_summaries
                       (id, org_id, incident_id, incident_name, total_cost,
                        estimated_total, actual_total, cost_categories,
                        duration_hours, severity, closed_at, created_at)
                       VALUES (:id, :org_id, :incident_id, :incident_name, :total_cost,
                               :estimated_total, :actual_total, :cost_categories,
                               :duration_hours, :severity, :closed_at, :created_at)
                       ON CONFLICT(org_id, incident_id) DO UPDATE SET
                           incident_name=excluded.incident_name,
                           total_cost=excluded.total_cost,
                           estimated_total=excluded.estimated_total,
                           actual_total=excluded.actual_total,
                           cost_categories=excluded.cost_categories,
                           duration_hours=excluded.duration_hours,
                           severity=excluded.severity,
                           closed_at=excluded.closed_at""",
                    summary,
                )

        result = dict(summary)
        result["cost_categories"] = category_breakdown
        return result

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_incident_costs(
        self, org_id: str, incident_id: str
    ) -> List[Dict[str, Any]]:
        """Return all cost records for an incident."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM incident_costs
                   WHERE org_id=? AND incident_id=?
                   ORDER BY recorded_at ASC""",
                (org_id, incident_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_incident_summary(
        self, org_id: str, incident_id: str
    ) -> Optional[Dict[str, Any]]:
        """Return the summary for a finalized incident, with parsed cost_categories."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM incident_summaries WHERE org_id=? AND incident_id=?",
                (org_id, incident_id),
            ).fetchone()
        if not row:
            return None
        result = self._row(row)
        try:
            result["cost_categories"] = json.loads(result["cost_categories"])
        except Exception:
            result["cost_categories"] = {}
        return result

    # ------------------------------------------------------------------
    # Benchmarks
    # ------------------------------------------------------------------

    def add_benchmark(
        self,
        org_id: str,
        incident_type: str,
        avg_cost: float,
        median_cost: float,
        p90_cost: float,
        sample_size: int,
        source: str,
        published_year: int,
    ) -> Dict[str, Any]:
        """Add an industry cost benchmark for an incident type."""
        if incident_type not in _VALID_INCIDENT_TYPES:
            raise ValueError(
                f"Invalid incident_type: {incident_type!r}. "
                f"Must be one of {sorted(_VALID_INCIDENT_TYPES)}"
            )
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_type": incident_type,
            "avg_cost": float(avg_cost),
            "median_cost": float(median_cost),
            "p90_cost": float(p90_cost),
            "sample_size": int(sample_size),
            "source": source,
            "published_year": int(published_year),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cost_benchmarks
                       (id, org_id, incident_type, avg_cost, median_cost, p90_cost,
                        sample_size, source, published_year, created_at)
                       VALUES (:id, :org_id, :incident_type, :avg_cost, :median_cost,
                               :p90_cost, :sample_size, :source, :published_year, :created_at)""",
                    record,
                )
        return record

    def compare_to_benchmark(
        self, org_id: str, incident_id: str
    ) -> Dict[str, Any]:
        """Compare incident total cost to industry benchmark.

        Determination:
          - within-range: total_cost within 20% of benchmark avg_cost
          - above: total_cost > avg_cost * 1.20
          - below: total_cost < avg_cost * 0.80
        """
        # Get the incident costs to find incident_type
        with self._conn() as conn:
            cost_row = conn.execute(
                "SELECT incident_type FROM incident_costs WHERE org_id=? AND incident_id=? LIMIT 1",
                (org_id, incident_id),
            ).fetchone()

            # Also check summaries
            if not cost_row:
                summary_row = conn.execute(
                    "SELECT incident_id FROM incident_summaries WHERE org_id=? AND incident_id=?",
                    (org_id, incident_id),
                ).fetchone()
                if not summary_row:
                    raise KeyError(f"Incident {incident_id!r} not found.")
                # No costs recorded yet
                total_cost = 0.0
                incident_type = None
            else:
                incident_type = cost_row["incident_type"]
                total_row = conn.execute(
                    "SELECT COALESCE(SUM(amount), 0) as total FROM incident_costs WHERE org_id=? AND incident_id=?",
                    (org_id, incident_id),
                ).fetchone()
                total_cost = total_row["total"]

            if incident_type:
                benchmark_row = conn.execute(
                    """SELECT * FROM cost_benchmarks
                       WHERE org_id=? AND incident_type=?
                       ORDER BY published_year DESC LIMIT 1""",
                    (org_id, incident_type),
                ).fetchone()
            else:
                benchmark_row = None

        result: Dict[str, Any] = {
            "incident_id": incident_id,
            "incident_type": incident_type,
            "total_cost": total_cost,
            "benchmark": None,
            "determination": "no-benchmark",
        }

        if benchmark_row:
            bm = self._row(benchmark_row)
            avg = bm["avg_cost"]
            if avg > 0:
                lower = avg * 0.80
                upper = avg * 1.20
                if total_cost < lower:
                    determination = "below"
                elif total_cost > upper:
                    determination = "above"
                else:
                    determination = "within-range"
            else:
                determination = "within-range" if total_cost == 0 else "above"
            result["benchmark"] = bm
            result["determination"] = determination

        return result

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_cost_analytics(self, org_id: str) -> Dict[str, Any]:
        """Return cost analytics: totals, by type, by category, avg per incident, most expensive."""
        with self._conn() as conn:
            total_row = conn.execute(
                "SELECT COALESCE(SUM(amount), 0) as total FROM incident_costs WHERE org_id=?",
                (org_id,),
            ).fetchone()
            total_spent = total_row["total"]

            type_rows = conn.execute(
                """SELECT incident_type, COALESCE(SUM(amount), 0) as total
                   FROM incident_costs WHERE org_id=?
                   GROUP BY incident_type""",
                (org_id,),
            ).fetchall()
            by_incident_type = {r["incident_type"]: r["total"] for r in type_rows}

            cat_rows = conn.execute(
                """SELECT cost_category, COALESCE(SUM(amount), 0) as total
                   FROM incident_costs WHERE org_id=?
                   GROUP BY cost_category""",
                (org_id,),
            ).fetchall()
            by_cost_category = {r["cost_category"]: r["total"] for r in cat_rows}

            # avg per incident
            inc_rows = conn.execute(
                """SELECT incident_id, COALESCE(SUM(amount), 0) as total
                   FROM incident_costs WHERE org_id=?
                   GROUP BY incident_id""",
                (org_id,),
            ).fetchall()
            inc_totals = [(r["incident_id"], r["total"]) for r in inc_rows]
            avg_per_incident = (
                sum(t for _, t in inc_totals) / len(inc_totals) if inc_totals else 0.0
            )
            most_expensive_incident = (
                max(inc_totals, key=lambda x: x[1])[0] if inc_totals else None
            )

        return {
            "total_spent": total_spent,
            "by_incident_type": by_incident_type,
            "by_cost_category": by_cost_category,
            "avg_per_incident": avg_per_incident,
            "most_expensive_incident": most_expensive_incident,
        }

    def list_summaries(
        self,
        org_id: str,
        incident_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List finalized incident summaries with optional filters."""
        # Join with costs to get incident_type since summaries don't store it
        query = "SELECT * FROM incident_summaries WHERE org_id=?"
        params: List[Any] = [org_id]
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY closed_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for row in rows:
            item = self._row(row)
            try:
                item["cost_categories"] = json.loads(item["cost_categories"])
            except Exception:
                item["cost_categories"] = {}
            results.append(item)

        # Filter by incident_type if requested (via costs table join)
        if incident_type:
            with self._conn() as conn:
                type_inc_rows = conn.execute(
                    """SELECT DISTINCT incident_id FROM incident_costs
                       WHERE org_id=? AND incident_type=?""",
                    (org_id, incident_type),
                ).fetchall()
            valid_ids = {r["incident_id"] for r in type_inc_rows}
            results = [r for r in results if r["incident_id"] in valid_ids]

        return results
