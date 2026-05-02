"""Security KPI metrics tracker — track, trend, and benchmark security performance."""
import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import structlog

_logger = structlog.get_logger()

KPI_NAMES = [
    "mttd_hours",           # Mean Time To Detect
    "mttr_hours",           # Mean Time To Respond/Remediate
    "mttr_critical_hours",  # MTTR for critical severity
    "patch_compliance_pct", # % of systems patched within SLA
    "vuln_density",         # vulnerabilities per 1000 lines of code
    "sla_compliance_pct",   # % of findings meeting SLA
    "false_positive_rate",  # % of alerts that are false positives
    "open_critical_count",  # current open critical vulnerabilities
    "incidents_per_month",  # incident count
    "posture_score",        # 0-100 overall security posture
]

INDUSTRY_BENCHMARKS = {
    "mttd_hours": {"good": 1, "average": 24, "poor": 168},
    "mttr_hours": {"good": 4, "average": 72, "poor": 720},
    "patch_compliance_pct": {"good": 95, "average": 80, "poor": 60},
    "sla_compliance_pct": {"good": 95, "average": 85, "poor": 70},
    "false_positive_rate": {"good": 5, "average": 20, "poor": 40},
    "posture_score": {"good": 80, "average": 60, "poor": 40},
}

# KPIs where lower is better (invert benchmark comparison)
_LOWER_IS_BETTER = {
    "mttd_hours", "mttr_hours", "mttr_critical_hours",
    "false_positive_rate", "open_critical_count", "vuln_density",
    "incidents_per_month",
}

# Category groupings for scorecard
_CATEGORY_MAP = {
    "detection": ["mttd_hours", "false_positive_rate"],
    "response": ["mttr_hours", "mttr_critical_hours", "sla_compliance_pct"],
    "prevention": ["patch_compliance_pct", "vuln_density", "posture_score",
                   "open_critical_count", "incidents_per_month"],
}


class SecurityKPITracker:
    """Track and trend key security KPIs over time."""

    def __init__(self, db_path: str = "data/security_kpi.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_tables(self) -> None:
        conn = self._connect()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS kpi_records (
                    kpi_id      TEXT PRIMARY KEY,
                    kpi_name    TEXT NOT NULL,
                    value       REAL NOT NULL,
                    org_id      TEXT NOT NULL DEFAULT 'default',
                    period      TEXT NOT NULL,
                    metadata    TEXT,
                    recorded_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_kpi_org_name
                    ON kpi_records (org_id, kpi_name, recorded_at);

                CREATE TABLE IF NOT EXISTS kpi_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL DEFAULT 'default',
                    data        TEXT NOT NULL,
                    taken_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_snapshot_org
                    ON kpi_snapshots (org_id, taken_at);

                CREATE TABLE IF NOT EXISTS kpi_targets (
                    target_id   TEXT PRIMARY KEY,
                    kpi_name    TEXT NOT NULL,
                    target_value REAL NOT NULL,
                    target_date TEXT NOT NULL,
                    org_id      TEXT NOT NULL DEFAULT 'default',
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_target_org_name
                    ON kpi_targets (org_id, kpi_name);
            """)
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Core recording
    # ------------------------------------------------------------------

    def record_kpi(
        self,
        kpi_name: str,
        value: float,
        org_id: str = "default",
        period: str = None,
        metadata: dict = None,
    ) -> dict:
        """Record a KPI measurement.

        period: 'daily'|'weekly'|'monthly' (auto-detected if None)
        Returns: {kpi_id, kpi_name, value, recorded_at, period}
        """
        if kpi_name not in KPI_NAMES:
            raise ValueError(
                f"Unknown KPI '{kpi_name}'. Valid names: {KPI_NAMES}"
            )

        now = datetime.utcnow()
        if period is None:
            period = "daily"

        kpi_id = str(uuid.uuid4())
        recorded_at = now.isoformat()
        meta_json = json.dumps(metadata) if metadata else None

        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO kpi_records
                   (kpi_id, kpi_name, value, org_id, period, metadata, recorded_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (kpi_id, kpi_name, value, org_id, period, meta_json, recorded_at),
            )
            conn.commit()
        finally:
            conn.close()

        _logger.info("kpi.recorded", kpi_name=kpi_name, value=value, org_id=org_id)
        return {
            "kpi_id": kpi_id,
            "kpi_name": kpi_name,
            "value": value,
            "recorded_at": recorded_at,
            "period": period,
        }

    # ------------------------------------------------------------------
    # Current state
    # ------------------------------------------------------------------

    def get_current_kpis(self, org_id: str = "default") -> dict:
        """Get the most recent value for each KPI.

        Returns: {kpi_name: {value, recorded_at, trend, vs_benchmark}}
        """
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT kpi_name, value, recorded_at
                   FROM kpi_records
                   WHERE org_id = ?
                     AND recorded_at = (
                         SELECT MAX(r2.recorded_at)
                         FROM kpi_records r2
                         WHERE r2.org_id = kpi_records.org_id
                           AND r2.kpi_name = kpi_records.kpi_name
                     )
                   GROUP BY kpi_name""",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        result: dict = {}
        for row in rows:
            name = row["kpi_name"]
            value = row["value"]
            trend = self._compute_trend(name, value, org_id)
            vs_benchmark = self._benchmark_status(name, value)
            result[name] = {
                "value": value,
                "recorded_at": row["recorded_at"],
                "trend": trend,
                "vs_benchmark": vs_benchmark,
            }
        return result

    # ------------------------------------------------------------------
    # Trend history
    # ------------------------------------------------------------------

    def get_kpi_trend(
        self,
        kpi_name: str,
        days: int = 30,
        org_id: str = "default",
    ) -> list:
        """Get historical values for a KPI over time period.

        Returns: [{value, recorded_at, period}] sorted chronologically.
        """
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT value, recorded_at, period
                   FROM kpi_records
                   WHERE org_id = ? AND kpi_name = ? AND recorded_at >= ?
                   ORDER BY recorded_at ASC""",
                (org_id, kpi_name, cutoff),
            ).fetchall()
        finally:
            conn.close()

        return [
            {"value": r["value"], "recorded_at": r["recorded_at"], "period": r["period"]}
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Benchmark comparison
    # ------------------------------------------------------------------

    def get_benchmark_comparison(self, org_id: str = "default") -> dict:
        """Compare all KPIs against industry benchmarks.

        Returns: {kpis: [{kpi_name, current_value, benchmark_good,
                          benchmark_avg, status, percentile}]}
        """
        current = self.get_current_kpis(org_id)
        kpis: list = []

        for name in KPI_NAMES:
            benchmarks = INDUSTRY_BENCHMARKS.get(name)
            entry: dict = {
                "kpi_name": name,
                "current_value": None,
                "benchmark_good": benchmarks["good"] if benchmarks else None,
                "benchmark_avg": benchmarks["average"] if benchmarks else None,
                "status": "unknown",
                "percentile": None,
            }

            if name in current:
                val = current[name]["value"]
                entry["current_value"] = val
                entry["status"] = self._benchmark_status(name, val)
                entry["percentile"] = self._estimate_percentile(name, val)

            kpis.append(entry)

        return {"kpis": kpis}

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def record_snapshot(self, org_id: str = "default") -> dict:
        """Take a point-in-time snapshot of all current KPIs."""
        current = self.get_current_kpis(org_id)
        now = datetime.utcnow().isoformat()
        snapshot_id = str(uuid.uuid4())

        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO kpi_snapshots (snapshot_id, org_id, data, taken_at)
                   VALUES (?, ?, ?, ?)""",
                (snapshot_id, org_id, json.dumps(current), now),
            )
            conn.commit()
        finally:
            conn.close()

        return {"snapshot_id": snapshot_id, "org_id": org_id, "taken_at": now, "data": current}

    def get_snapshots(self, org_id: str = "default", limit: int = 30) -> list:
        """Get historical snapshots."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT snapshot_id, org_id, data, taken_at
                   FROM kpi_snapshots
                   WHERE org_id = ?
                   ORDER BY taken_at DESC
                   LIMIT ?""",
                (org_id, limit),
            ).fetchall()
        finally:
            conn.close()

        return [
            {
                "snapshot_id": r["snapshot_id"],
                "org_id": r["org_id"],
                "data": json.loads(r["data"]),
                "taken_at": r["taken_at"],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Score card
    # ------------------------------------------------------------------

    def calculate_score_card(self, org_id: str = "default") -> dict:
        """Generate security score card.

        Returns: {overall_grade, overall_score, by_category, top_strengths, top_weaknesses}
        """
        current = self.get_current_kpis(org_id)

        category_scores: dict = {}
        kpi_scores: dict = {}

        for name, info in current.items():
            score = self._kpi_score(name, info["value"])
            kpi_scores[name] = score

        for cat, kpi_list in _CATEGORY_MAP.items():
            cat_vals = [kpi_scores[k] for k in kpi_list if k in kpi_scores]
            category_scores[cat] = round(sum(cat_vals) / len(cat_vals), 1) if cat_vals else 0.0

        all_scores = list(kpi_scores.values())
        overall_score = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0

        overall_grade = self._score_to_grade(overall_score)

        # Top 3 strengths (highest scores) and weaknesses (lowest scores)
        sorted_kpis = sorted(kpi_scores.items(), key=lambda x: x[1], reverse=True)
        top_strengths = [k for k, _ in sorted_kpis[:3]]
        top_weaknesses = [k for k, _ in sorted_kpis[-3:] if _ < 70]

        return {
            "overall_grade": overall_grade,
            "overall_score": overall_score,
            "by_category": category_scores,
            "top_strengths": top_strengths,
            "top_weaknesses": top_weaknesses,
        }

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    def get_targets(self, org_id: str = "default") -> list:
        """Get KPI targets set for the org."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT target_id, kpi_name, target_value, target_date, org_id, created_at
                   FROM kpi_targets
                   WHERE org_id = ?
                   ORDER BY target_date ASC""",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        return [dict(r) for r in rows]

    def set_target(
        self,
        kpi_name: str,
        target_value: float,
        target_date: str,
        org_id: str = "default",
    ) -> dict:
        """Set a target value for a KPI by a date."""
        if kpi_name not in KPI_NAMES:
            raise ValueError(f"Unknown KPI '{kpi_name}'.")

        target_id = str(uuid.uuid4())
        created_at = datetime.utcnow().isoformat()

        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO kpi_targets
                   (target_id, kpi_name, target_value, target_date, org_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (target_id, kpi_name, target_value, target_date, org_id, created_at),
            )
            conn.commit()
        finally:
            conn.close()

        return {
            "target_id": target_id,
            "kpi_name": kpi_name,
            "target_value": target_value,
            "target_date": target_date,
            "org_id": org_id,
            "created_at": created_at,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _compute_trend(self, kpi_name: str, current_value: float, org_id: str) -> str:
        """Compute trend direction over the last 7 days vs prior 7 days."""
        now = datetime.utcnow()
        week_ago = (now - timedelta(days=7)).isoformat()
        two_weeks_ago = (now - timedelta(days=14)).isoformat()

        conn = self._connect()
        try:
            recent = conn.execute(
                """SELECT AVG(value) as avg FROM kpi_records
                   WHERE org_id=? AND kpi_name=? AND recorded_at >= ?""",
                (org_id, kpi_name, week_ago),
            ).fetchone()["avg"]

            prior = conn.execute(
                """SELECT AVG(value) as avg FROM kpi_records
                   WHERE org_id=? AND kpi_name=? AND recorded_at >= ? AND recorded_at < ?""",
                (org_id, kpi_name, two_weeks_ago, week_ago),
            ).fetchone()["avg"]
        finally:
            conn.close()

        if recent is None or prior is None:
            return "stable"

        delta = (recent - prior) / (abs(prior) + 1e-9)
        lower_better = kpi_name in _LOWER_IS_BETTER

        if abs(delta) < 0.02:
            return "stable"
        if delta < 0:
            return "improving" if lower_better else "degrading"
        return "degrading" if lower_better else "improving"

    def _benchmark_status(self, kpi_name: str, value: float) -> str:
        """Classify a KPI value against industry benchmarks."""
        bm = INDUSTRY_BENCHMARKS.get(kpi_name)
        if not bm:
            return "unknown"

        lower_better = kpi_name in _LOWER_IS_BETTER
        if lower_better:
            if value <= bm["good"]:
                return "good"
            if value <= bm["average"]:
                return "average"
            return "poor"
        else:
            if value >= bm["good"]:
                return "good"
            if value >= bm["average"]:
                return "average"
            return "poor"

    def _kpi_score(self, kpi_name: str, value: float) -> float:
        """Convert a KPI value to a 0-100 score."""
        if kpi_name == "posture_score":
            return float(max(0, min(100, value)))

        bm = INDUSTRY_BENCHMARKS.get(kpi_name)
        if not bm:
            return 50.0

        good, _avg, poor = bm["good"], bm["average"], bm["poor"]
        lower_better = kpi_name in _LOWER_IS_BETTER

        if lower_better:
            if value <= good:
                return 100.0
            if value >= poor:
                return 0.0
            # Linear interpolation between good(100) and poor(0)
            return round(100.0 * (poor - value) / (poor - good + 1e-9), 1)
        else:
            if value >= good:
                return 100.0
            if value <= poor:
                return 0.0
            return round(100.0 * (value - poor) / (good - poor + 1e-9), 1)

    def _estimate_percentile(self, kpi_name: str, value: float) -> int:
        """Rough percentile estimate vs industry benchmarks."""
        status = self._benchmark_status(kpi_name, value)
        return {"good": 80, "average": 50, "poor": 20, "unknown": 50}.get(status, 50)

    @staticmethod
    def _score_to_grade(score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"
