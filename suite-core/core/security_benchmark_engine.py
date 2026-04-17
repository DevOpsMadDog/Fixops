"""Security Benchmark Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Compares an org's security posture against industry benchmarks and sector peers:
  - Industry benchmark definitions (Gartner, Verizon DBIR, SANS, NIST, CIS, IBM, custom)
  - Org metric recording
  - Percentile-rank comparison with performance labelling
  - Summary dashboards and metric trends

Standards: Gartner Security Score, NIST SP 800-55, CIS Controls Metrics
"""
from __future__ import annotations

import contextlib
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_benchmark_engine.db"
)

_VALID_SOURCES = {
    "Gartner", "Verizon-DBIR", "SANS", "NIST", "CIS", "IBM", "custom",
}
_VALID_SECTORS = {
    "finance", "healthcare", "retail", "technology",
    "government", "energy", "manufacturing", "education",
}
_VALID_CATEGORIES = {
    "vulnerability", "compliance", "incident-response", "access",
    "training", "patch", "detection", "recovery",
}
_VALID_PERFORMANCE = {"above-average", "average", "below-average", "lagging"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _interpolate_percentile(
    value: float,
    p25: float,
    p50: float,
    p75: float,
    p90: float,
    higher_is_better: bool,
) -> float:
    """Return an interpolated percentile rank (0–100) for a given value."""
    # Build anchor points: (value, percentile)
    anchors = sorted([
        (p25, 25.0),
        (p50, 50.0),
        (p75, 75.0),
        (p90, 90.0),
    ])

    if not higher_is_better:
        # Invert: lower value → higher percentile
        anchors = [(a_v, 100.0 - a_p) for a_v, a_p in anchors]
        anchors = sorted(anchors, key=lambda x: x[0])

    # Clamp to edges
    if value <= anchors[0][0]:
        return anchors[0][1]
    if value >= anchors[-1][0]:
        return anchors[-1][1]

    # Linear interpolation between bracketing anchors
    for i in range(len(anchors) - 1):
        lo_v, lo_p = anchors[i]
        hi_v, hi_p = anchors[i + 1]
        if lo_v <= value <= hi_v:
            if hi_v == lo_v:
                return lo_p
            frac = (value - lo_v) / (hi_v - lo_v)
            return lo_p + frac * (hi_p - lo_p)

    return anchors[-1][1]


def _performance_label(
    value: float,
    p25: float,
    p50: float,
    p75: float,
    higher_is_better: bool,
) -> str:
    """Map value to performance label."""
    if higher_is_better:
        if value >= p75:
            return "above-average"
        if value >= p50:
            return "average"
        if value >= p25:
            return "below-average"
        return "lagging"
    else:
        # Lower is better: good means low value
        if value <= p25:
            return "above-average"
        if value <= p50:
            return "average"
        if value <= p75:
            return "below-average"
        return "lagging"


class SecurityBenchmarkEngine:
    """SQLite WAL-backed Security Benchmark engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_benchmark_engine.db
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS benchmark_definitions (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    benchmark_name   TEXT NOT NULL,
                    benchmark_source TEXT NOT NULL,
                    sector           TEXT NOT NULL,
                    metric_name      TEXT NOT NULL,
                    metric_category  TEXT NOT NULL,
                    p25_value        REAL DEFAULT 0.0,
                    p50_value        REAL DEFAULT 0.0,
                    p75_value        REAL DEFAULT 0.0,
                    p90_value        REAL DEFAULT 0.0,
                    unit             TEXT DEFAULT '',
                    higher_is_better INTEGER DEFAULT 1,
                    published_date   TEXT DEFAULT '',
                    created_at       TEXT
                );

                CREATE TABLE IF NOT EXISTS org_metrics (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    metric_name      TEXT NOT NULL,
                    metric_category  TEXT NOT NULL,
                    value            REAL DEFAULT 0.0,
                    unit             TEXT DEFAULT '',
                    measurement_date TEXT,
                    source           TEXT DEFAULT '',
                    created_at       TEXT
                );

                CREATE TABLE IF NOT EXISTS benchmark_comparisons (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    benchmark_id         TEXT NOT NULL,
                    org_metric_id        TEXT NOT NULL,
                    percentile_rank      REAL DEFAULT 0.0,
                    performance          TEXT DEFAULT 'lagging',
                    gap_to_median        REAL DEFAULT 0.0,
                    gap_to_top_quartile  REAL DEFAULT 0.0,
                    compared_at          TEXT
                );
                """
            )

    # ------------------------------------------------------------------
    # Benchmarks
    # ------------------------------------------------------------------

    def create_benchmark(
        self,
        org_id: str,
        benchmark_name: str,
        benchmark_source: str,
        sector: str,
        metric_name: str,
        metric_category: str,
        p25: float,
        p50: float,
        p75: float,
        p90: float,
        unit: str = "",
        higher_is_better: bool = True,
        published_date: str = "",
    ) -> Dict[str, Any]:
        """Create an industry benchmark definition."""
        if benchmark_source not in _VALID_SOURCES:
            raise ValueError(f"Invalid benchmark_source: {benchmark_source}. Valid: {_VALID_SOURCES}")
        if sector not in _VALID_SECTORS:
            raise ValueError(f"Invalid sector: {sector}. Valid: {_VALID_SECTORS}")
        if metric_category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid metric_category: {metric_category}. Valid: {_VALID_CATEGORIES}")

        bm_id = str(uuid.uuid4())
        now = _now_iso()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO benchmark_definitions
                   (id, org_id, benchmark_name, benchmark_source, sector, metric_name,
                    metric_category, p25_value, p50_value, p75_value, p90_value,
                    unit, higher_is_better, published_date, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    bm_id, org_id, benchmark_name, benchmark_source, sector,
                    metric_name, metric_category, p25, p50, p75, p90,
                    unit, int(higher_is_better), published_date, now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM benchmark_definitions WHERE id=?", (bm_id,)
            ).fetchone()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "security_benchmark_engine", "org_id": org_id, "source_engine": "security_benchmark_engine"})
            except Exception:
                pass
        return dict(row)

    def list_benchmarks(
        self,
        org_id: str,
        sector: Optional[str] = None,
        metric_category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List benchmarks with optional sector and category filters."""
        query = "SELECT * FROM benchmark_definitions WHERE org_id=?"
        params: list = [org_id]
        if sector:
            query += " AND sector=?"
            params.append(sector)
        if metric_category:
            query += " AND metric_category=?"
            params.append(metric_category)
        query += " ORDER BY created_at DESC"

        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Org Metrics
    # ------------------------------------------------------------------

    def record_org_metric(
        self,
        org_id: str,
        metric_name: str,
        metric_category: str,
        value: float,
        unit: str = "",
        source: str = "",
    ) -> Dict[str, Any]:
        """Record an org security metric measurement."""
        if metric_category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid metric_category: {metric_category}. Valid: {_VALID_CATEGORIES}")

        metric_id = str(uuid.uuid4())
        now = _now_iso()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO org_metrics
                   (id, org_id, metric_name, metric_category, value, unit,
                    measurement_date, source, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (metric_id, org_id, metric_name, metric_category, value, unit, now, source, now),
            )
            row = conn.execute(
                "SELECT * FROM org_metrics WHERE id=?", (metric_id,)
            ).fetchone()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "security_benchmark_engine", "org_id": org_id, "source_engine": "security_benchmark_engine"})
            except Exception:
                pass
        return dict(row)

    def get_metric_trend(
        self,
        org_id: str,
        metric_name: str,
        days: int = 90,
    ) -> List[Dict[str, Any]]:
        """Return org_metrics for a metric over the past N days, ordered by date."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM org_metrics
                   WHERE org_id=? AND metric_name=? AND measurement_date >= ?
                   ORDER BY measurement_date ASC""",
                (org_id, metric_name, cutoff),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Comparisons
    # ------------------------------------------------------------------

    def compare_to_benchmark(
        self,
        org_id: str,
        benchmark_id: str,
        org_metric_id: str,
    ) -> Dict[str, Any]:
        """Compare an org metric to a benchmark and compute percentile rank."""
        cmp_id = str(uuid.uuid4())
        now = _now_iso()

        with self._lock, self._conn() as conn:
            bm = conn.execute(
                "SELECT * FROM benchmark_definitions WHERE id=? AND org_id=?",
                (benchmark_id, org_id),
            ).fetchone()
            if bm is None:
                raise ValueError(f"Benchmark {benchmark_id} not found for org {org_id}")

            om = conn.execute(
                "SELECT * FROM org_metrics WHERE id=? AND org_id=?",
                (org_metric_id, org_id),
            ).fetchone()
            if om is None:
                raise ValueError(f"Org metric {org_metric_id} not found for org {org_id}")

            value = om["value"]
            p25 = bm["p25_value"]
            p50 = bm["p50_value"]
            p75 = bm["p75_value"]
            p90 = bm["p90_value"]
            hib = bool(bm["higher_is_better"])

            percentile_rank = round(
                _interpolate_percentile(value, p25, p50, p75, p90, hib), 2
            )
            performance = _performance_label(value, p25, p50, p75, hib)
            gap_to_median = round(p50 - value, 4)
            gap_to_top_quartile = round(p75 - value, 4)

            conn.execute(
                """INSERT INTO benchmark_comparisons
                   (id, org_id, benchmark_id, org_metric_id, percentile_rank,
                    performance, gap_to_median, gap_to_top_quartile, compared_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    cmp_id, org_id, benchmark_id, org_metric_id,
                    percentile_rank, performance,
                    gap_to_median, gap_to_top_quartile, now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM benchmark_comparisons WHERE id=?", (cmp_id,)
            ).fetchone()
        return dict(row)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_org_benchmark_summary(self, org_id: str) -> Dict[str, Any]:
        """Return all comparisons with performance counts, best/worst metric, overall percentile avg."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT bc.*, bd.metric_name, bd.metric_category
                   FROM benchmark_comparisons bc
                   JOIN benchmark_definitions bd ON bc.benchmark_id = bd.id
                   WHERE bc.org_id=?
                   ORDER BY bc.compared_at DESC""",
                (org_id,),
            ).fetchall()

        if not rows:
            return {
                "total": 0,
                "performance_counts": {},
                "best_metric": None,
                "worst_metric": None,
                "overall_percentile_avg": 0.0,
                "comparisons": [],
            }

        comparisons = [dict(r) for r in rows]
        perf_counts: Dict[str, int] = {}
        for c in comparisons:
            perf_counts[c["performance"]] = perf_counts.get(c["performance"], 0) + 1

        sorted_by_rank = sorted(comparisons, key=lambda x: x["percentile_rank"])
        worst = sorted_by_rank[0]["metric_name"] if sorted_by_rank else None
        best = sorted_by_rank[-1]["metric_name"] if sorted_by_rank else None

        avg_rank = round(
            sum(c["percentile_rank"] for c in comparisons) / len(comparisons), 2
        )

        return {
            "total": len(comparisons),
            "performance_counts": perf_counts,
            "best_metric": best,
            "worst_metric": worst,
            "overall_percentile_avg": avg_rank,
            "comparisons": comparisons,
        }
