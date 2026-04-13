"""
Security Posture Benchmarking Engine — ALDECI.

Compares an organisation's security posture against industry-vertical benchmarks
across 15 metrics. Stores reports in SQLite and supports trend queries and
improvement-priority rankings.

Benchmark data is derived from industry research (Verizon DBIR, IBM Cost of a
Data Breach, MITRE ATT&CK prevalence stats, CIS Benchmark adoption surveys).

Compliance: SOC2 CC9.2 (Risk assessment and benchmarking)
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

_logger = structlog.get_logger(__name__)

_DEFAULT_DB_PATH = "data/posture_benchmark.db"

# ============================================================================
# ENUMS
# ============================================================================


class IndustryVertical(str, Enum):
    """Industry verticals for benchmark comparison."""

    FINTECH = "fintech"
    HEALTHCARE = "healthcare"
    SAAS = "saas"
    GOVERNMENT = "government"
    RETAIL = "retail"
    MANUFACTURING = "manufacturing"
    EDUCATION = "education"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class BenchmarkMetric(BaseModel):
    """A single metric with org value vs. industry benchmarks."""

    name: str = Field(..., description="Metric identifier (e.g. 'mttr_days')")
    org_value: float = Field(..., description="Organisation's measured value")
    industry_avg: float = Field(..., description="Industry average for this vertical")
    industry_p90: float = Field(
        ..., description="Industry 90th-percentile (top performers) for this vertical"
    )
    percentile_rank: float = Field(
        ..., ge=0.0, le=100.0, description="Org's percentile rank vs. industry (higher = better)"
    )
    gap: float = Field(
        ..., description="Difference between org value and industry average (positive = org is better)"
    )


class BenchmarkReport(BaseModel):
    """Full benchmark report for an organisation at a point in time."""

    id: str = Field(default_factory=lambda: f"br-{uuid.uuid4().hex[:12]}")
    org_id: str = Field(..., description="Organisation identifier")
    vertical: IndustryVertical = Field(..., description="Industry vertical used for comparison")
    metrics: List[BenchmarkMetric] = Field(default_factory=list)
    overall_percentile: float = Field(
        ..., ge=0.0, le=100.0, description="Weighted average percentile rank across all metrics"
    )
    strengths: List[str] = Field(
        default_factory=list, description="Metrics where org outperforms the industry average"
    )
    weaknesses: List[str] = Field(
        default_factory=list, description="Metrics where org underperforms the industry average"
    )
    recommendations: List[str] = Field(
        default_factory=list, description="Prioritised improvement recommendations"
    )
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp",
    )


# ============================================================================
# BUILT-IN BENCHMARK DATA
# ============================================================================

# Structure: metric_name -> vertical -> {"avg": float, "p90": float, "higher_is_better": bool}
# higher_is_better=True  → higher org value is good (e.g. patch coverage %)
# higher_is_better=False → lower org value is good (e.g. mttr_days)
_BENCHMARK_DATA: Dict[str, Dict[str, Dict[str, Any]]] = {
    # Mean Time To Remediate critical vulns (days) — lower is better
    "mttr_days": {
        "fintech": {"avg": 14.0, "p90": 4.0, "higher_is_better": False},
        "healthcare": {"avg": 28.0, "p90": 10.0, "higher_is_better": False},
        "saas": {"avg": 10.0, "p90": 3.0, "higher_is_better": False},
        "government": {"avg": 45.0, "p90": 15.0, "higher_is_better": False},
        "retail": {"avg": 21.0, "p90": 7.0, "higher_is_better": False},
        "manufacturing": {"avg": 35.0, "p90": 12.0, "higher_is_better": False},
        "education": {"avg": 38.0, "p90": 14.0, "higher_is_better": False},
    },
    # Vulnerability density per 1000 LOC — lower is better
    "vuln_density_per_kloc": {
        "fintech": {"avg": 2.1, "p90": 0.6, "higher_is_better": False},
        "healthcare": {"avg": 3.4, "p90": 1.0, "higher_is_better": False},
        "saas": {"avg": 1.8, "p90": 0.5, "higher_is_better": False},
        "government": {"avg": 4.2, "p90": 1.4, "higher_is_better": False},
        "retail": {"avg": 2.8, "p90": 0.9, "higher_is_better": False},
        "manufacturing": {"avg": 3.6, "p90": 1.2, "higher_is_better": False},
        "education": {"avg": 3.9, "p90": 1.3, "higher_is_better": False},
    },
    # Patch coverage % (assets patched within SLA) — higher is better
    "patch_coverage_pct": {
        "fintech": {"avg": 82.0, "p90": 96.0, "higher_is_better": True},
        "healthcare": {"avg": 68.0, "p90": 88.0, "higher_is_better": True},
        "saas": {"avg": 88.0, "p90": 97.0, "higher_is_better": True},
        "government": {"avg": 61.0, "p90": 80.0, "higher_is_better": True},
        "retail": {"avg": 73.0, "p90": 90.0, "higher_is_better": True},
        "manufacturing": {"avg": 64.0, "p90": 83.0, "higher_is_better": True},
        "education": {"avg": 59.0, "p90": 78.0, "higher_is_better": True},
    },
    # MFA adoption % — higher is better
    "mfa_adoption_pct": {
        "fintech": {"avg": 91.0, "p90": 99.0, "higher_is_better": True},
        "healthcare": {"avg": 72.0, "p90": 93.0, "higher_is_better": True},
        "saas": {"avg": 88.0, "p90": 98.0, "higher_is_better": True},
        "government": {"avg": 76.0, "p90": 95.0, "higher_is_better": True},
        "retail": {"avg": 65.0, "p90": 86.0, "higher_is_better": True},
        "manufacturing": {"avg": 58.0, "p90": 80.0, "higher_is_better": True},
        "education": {"avg": 54.0, "p90": 76.0, "higher_is_better": True},
    },
    # Critical open findings (count) — lower is better
    "critical_open_findings": {
        "fintech": {"avg": 12.0, "p90": 2.0, "higher_is_better": False},
        "healthcare": {"avg": 22.0, "p90": 5.0, "higher_is_better": False},
        "saas": {"avg": 9.0, "p90": 1.0, "higher_is_better": False},
        "government": {"avg": 35.0, "p90": 8.0, "higher_is_better": False},
        "retail": {"avg": 18.0, "p90": 4.0, "higher_is_better": False},
        "manufacturing": {"avg": 28.0, "p90": 7.0, "higher_is_better": False},
        "education": {"avg": 30.0, "p90": 8.0, "higher_is_better": False},
    },
    # Compliance framework coverage % — higher is better
    "compliance_coverage_pct": {
        "fintech": {"avg": 84.0, "p90": 97.0, "higher_is_better": True},
        "healthcare": {"avg": 78.0, "p90": 94.0, "higher_is_better": True},
        "saas": {"avg": 80.0, "p90": 95.0, "higher_is_better": True},
        "government": {"avg": 72.0, "p90": 91.0, "higher_is_better": True},
        "retail": {"avg": 68.0, "p90": 88.0, "higher_is_better": True},
        "manufacturing": {"avg": 62.0, "p90": 84.0, "higher_is_better": True},
        "education": {"avg": 58.0, "p90": 80.0, "higher_is_better": True},
    },
    # Secret detection coverage % (repos scanned) — higher is better
    "secret_detection_coverage_pct": {
        "fintech": {"avg": 78.0, "p90": 97.0, "higher_is_better": True},
        "healthcare": {"avg": 55.0, "p90": 82.0, "higher_is_better": True},
        "saas": {"avg": 82.0, "p90": 98.0, "higher_is_better": True},
        "government": {"avg": 60.0, "p90": 85.0, "higher_is_better": True},
        "retail": {"avg": 52.0, "p90": 78.0, "higher_is_better": True},
        "manufacturing": {"avg": 44.0, "p90": 70.0, "higher_is_better": True},
        "education": {"avg": 40.0, "p90": 66.0, "higher_is_better": True},
    },
    # Privileged access review cycle (days between reviews) — lower is better
    "privileged_access_review_days": {
        "fintech": {"avg": 30.0, "p90": 7.0, "higher_is_better": False},
        "healthcare": {"avg": 60.0, "p90": 14.0, "higher_is_better": False},
        "saas": {"avg": 25.0, "p90": 7.0, "higher_is_better": False},
        "government": {"avg": 90.0, "p90": 30.0, "higher_is_better": False},
        "retail": {"avg": 45.0, "p90": 14.0, "higher_is_better": False},
        "manufacturing": {"avg": 75.0, "p90": 21.0, "higher_is_better": False},
        "education": {"avg": 80.0, "p90": 30.0, "higher_is_better": False},
    },
    # Attack surface score (exposed assets * severity weight) — lower is better
    "attack_surface_score": {
        "fintech": {"avg": 320.0, "p90": 80.0, "higher_is_better": False},
        "healthcare": {"avg": 480.0, "p90": 130.0, "higher_is_better": False},
        "saas": {"avg": 260.0, "p90": 60.0, "higher_is_better": False},
        "government": {"avg": 600.0, "p90": 180.0, "higher_is_better": False},
        "retail": {"avg": 410.0, "p90": 110.0, "higher_is_better": False},
        "manufacturing": {"avg": 520.0, "p90": 150.0, "higher_is_better": False},
        "education": {"avg": 540.0, "p90": 160.0, "higher_is_better": False},
    },
    # Incident response drill frequency (drills per year) — higher is better
    "ir_drills_per_year": {
        "fintech": {"avg": 4.0, "p90": 12.0, "higher_is_better": True},
        "healthcare": {"avg": 2.0, "p90": 6.0, "higher_is_better": True},
        "saas": {"avg": 5.0, "p90": 12.0, "higher_is_better": True},
        "government": {"avg": 2.0, "p90": 6.0, "higher_is_better": True},
        "retail": {"avg": 2.0, "p90": 6.0, "higher_is_better": True},
        "manufacturing": {"avg": 1.5, "p90": 4.0, "higher_is_better": True},
        "education": {"avg": 1.0, "p90": 3.0, "higher_is_better": True},
    },
    # Scanner coverage % (assets covered by at least one scanner) — higher is better
    "scanner_coverage_pct": {
        "fintech": {"avg": 88.0, "p90": 99.0, "higher_is_better": True},
        "healthcare": {"avg": 72.0, "p90": 92.0, "higher_is_better": True},
        "saas": {"avg": 91.0, "p90": 99.0, "higher_is_better": True},
        "government": {"avg": 65.0, "p90": 87.0, "higher_is_better": True},
        "retail": {"avg": 76.0, "p90": 93.0, "higher_is_better": True},
        "manufacturing": {"avg": 60.0, "p90": 82.0, "higher_is_better": True},
        "education": {"avg": 55.0, "p90": 78.0, "higher_is_better": True},
    },
    # Third-party risk assessment coverage % (vendors assessed) — higher is better
    "third_party_risk_coverage_pct": {
        "fintech": {"avg": 76.0, "p90": 96.0, "higher_is_better": True},
        "healthcare": {"avg": 58.0, "p90": 84.0, "higher_is_better": True},
        "saas": {"avg": 70.0, "p90": 92.0, "higher_is_better": True},
        "government": {"avg": 64.0, "p90": 88.0, "higher_is_better": True},
        "retail": {"avg": 52.0, "p90": 78.0, "higher_is_better": True},
        "manufacturing": {"avg": 44.0, "p90": 68.0, "higher_is_better": True},
        "education": {"avg": 38.0, "p90": 62.0, "higher_is_better": True},
    },
    # Data encryption at rest % (classified data stores encrypted) — higher is better
    "encryption_at_rest_pct": {
        "fintech": {"avg": 94.0, "p90": 100.0, "higher_is_better": True},
        "healthcare": {"avg": 85.0, "p90": 98.0, "higher_is_better": True},
        "saas": {"avg": 92.0, "p90": 100.0, "higher_is_better": True},
        "government": {"avg": 80.0, "p90": 97.0, "higher_is_better": True},
        "retail": {"avg": 76.0, "p90": 95.0, "higher_is_better": True},
        "manufacturing": {"avg": 65.0, "p90": 88.0, "higher_is_better": True},
        "education": {"avg": 60.0, "p90": 84.0, "higher_is_better": True},
    },
    # Security training completion % — higher is better
    "security_training_completion_pct": {
        "fintech": {"avg": 88.0, "p90": 100.0, "higher_is_better": True},
        "healthcare": {"avg": 82.0, "p90": 98.0, "higher_is_better": True},
        "saas": {"avg": 85.0, "p90": 99.0, "higher_is_better": True},
        "government": {"avg": 79.0, "p90": 97.0, "higher_is_better": True},
        "retail": {"avg": 70.0, "p90": 92.0, "higher_is_better": True},
        "manufacturing": {"avg": 65.0, "p90": 88.0, "higher_is_better": True},
        "education": {"avg": 62.0, "p90": 85.0, "higher_is_better": True},
    },
    # Log retention days — higher is better
    "log_retention_days": {
        "fintech": {"avg": 365.0, "p90": 730.0, "higher_is_better": True},
        "healthcare": {"avg": 365.0, "p90": 730.0, "higher_is_better": True},
        "saas": {"avg": 180.0, "p90": 365.0, "higher_is_better": True},
        "government": {"avg": 365.0, "p90": 730.0, "higher_is_better": True},
        "retail": {"avg": 180.0, "p90": 365.0, "higher_is_better": True},
        "manufacturing": {"avg": 180.0, "p90": 365.0, "higher_is_better": True},
        "education": {"avg": 90.0, "p90": 180.0, "higher_is_better": True},
    },
}

_ALL_METRICS = list(_BENCHMARK_DATA.keys())

# Recommendation templates per metric (used when org underperforms industry avg)
_RECOMMENDATIONS: Dict[str, str] = {
    "mttr_days": "Implement automated remediation workflows to reduce mean time to remediate critical vulnerabilities.",
    "vuln_density_per_kloc": "Integrate SAST/DAST into CI pipelines to catch vulnerabilities earlier in the development lifecycle.",
    "patch_coverage_pct": "Enforce automated patch management policies with shorter SLA windows for critical/high severity.",
    "mfa_adoption_pct": "Mandate MFA for all user accounts and service accounts with privileged access.",
    "critical_open_findings": "Triage and remediate critical open findings; consider temporary compensating controls for blocked items.",
    "compliance_coverage_pct": "Map existing controls to compliance framework requirements and close evidence gaps.",
    "secret_detection_coverage_pct": "Deploy secret scanning across all code repositories and add pre-commit hooks to block new secrets.",
    "privileged_access_review_days": "Implement quarterly (or more frequent) privileged access reviews with automated de-provisioning.",
    "attack_surface_score": "Reduce internet-exposed services and enforce network segmentation to minimise attack surface.",
    "ir_drills_per_year": "Schedule regular tabletop exercises and full incident response simulations.",
    "scanner_coverage_pct": "Expand scanner deployment to cover all asset types (cloud, containers, on-prem).",
    "third_party_risk_coverage_pct": "Assess all critical and high-risk third-party vendors with standardised security questionnaires.",
    "encryption_at_rest_pct": "Enable encryption at rest for all classified data stores and enforce via policy.",
    "security_training_completion_pct": "Run mandatory annual security awareness training with role-specific advanced modules.",
    "log_retention_days": "Extend log retention to meet regulatory requirements and support forensic investigations.",
}


# ============================================================================
# PERCENTILE CALCULATION
# ============================================================================


def _compute_percentile(org_value: float, avg: float, p90: float, higher_is_better: bool) -> float:
    """
    Estimate the org's percentile rank (0-100) given benchmark statistics.

    We model the distribution as roughly normal between 0-100 percentile,
    anchored at avg (50th pct) and p90 (90th pct), then linearly interpolate.
    """
    if higher_is_better:
        # org_value >= p90 → >= 90th percentile (capped at 99)
        # org_value == avg → ~50th percentile
        # org_value <= 0  → 0th percentile (floor)
        if p90 <= avg:
            return 50.0  # degenerate data guard
        if org_value >= p90:
            # Scale 90-99 for values above p90
            excess = org_value - p90
            range_above = p90 * 0.5  # rough upper tail
            extra = min(9.0, (excess / max(range_above, 1.0)) * 9.0)
            return min(99.0, 90.0 + extra)
        if org_value >= avg:
            # Linear interpolation: avg → 50, p90 → 90
            return 50.0 + 40.0 * (org_value - avg) / (p90 - avg)
        # Below average: linear from 0 to 50
        return max(0.0, 50.0 * org_value / max(avg, 1.0))
    else:
        # Lower is better: flip the logic
        # org_value <= p90 → >= 90th percentile
        # org_value == avg → ~50th percentile
        if p90 >= avg:
            return 50.0  # degenerate data guard
        if org_value <= p90:
            excess = p90 - org_value
            range_below = p90 * 0.5
            extra = min(9.0, (excess / max(range_below, 1.0)) * 9.0)
            return min(99.0, 90.0 + extra)
        if org_value <= avg:
            return 50.0 + 40.0 * (avg - org_value) / (avg - p90)
        # Above average (worse): linear from 0 to 50
        return max(0.0, 50.0 * (2.0 * avg - org_value) / max(avg, 1.0))


# ============================================================================
# SQLITE PERSISTENCE
# ============================================================================


class _BenchmarkDB:
    """Thin SQLite wrapper for benchmark report storage."""

    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS benchmark_reports (
                        id                  TEXT PRIMARY KEY,
                        org_id              TEXT NOT NULL,
                        vertical            TEXT NOT NULL,
                        metrics             TEXT NOT NULL DEFAULT '[]',
                        overall_percentile  REAL NOT NULL,
                        strengths           TEXT NOT NULL DEFAULT '[]',
                        weaknesses          TEXT NOT NULL DEFAULT '[]',
                        recommendations     TEXT NOT NULL DEFAULT '[]',
                        generated_at        TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_br_org_ts
                        ON benchmark_reports (org_id, generated_at);

                    CREATE TABLE IF NOT EXISTS org_metrics (
                        org_id      TEXT NOT NULL,
                        metric_name TEXT NOT NULL,
                        value       REAL NOT NULL,
                        recorded_at TEXT NOT NULL,
                        PRIMARY KEY (org_id, metric_name)
                    );
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def save_report(self, report: BenchmarkReport) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO benchmark_reports
                        (id, org_id, vertical, metrics, overall_percentile,
                         strengths, weaknesses, recommendations, generated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report.id,
                        report.org_id,
                        report.vertical.value,
                        json.dumps([m.model_dump() for m in report.metrics]),
                        report.overall_percentile,
                        json.dumps(report.strengths),
                        json.dumps(report.weaknesses),
                        json.dumps(report.recommendations),
                        report.generated_at,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def save_org_metrics(self, org_id: str, metrics: Dict[str, float]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                for name, value in metrics.items():
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO org_metrics
                            (org_id, metric_name, value, recorded_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (org_id, name, value, now),
                    )
                conn.commit()
            finally:
                conn.close()

    def get_org_metrics(self, org_id: str) -> Dict[str, float]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT metric_name, value FROM org_metrics WHERE org_id = ?",
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
        return {row["metric_name"]: row["value"] for row in rows}

    def get_history(self, org_id: str) -> List[BenchmarkReport]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT id, org_id, vertical, metrics, overall_percentile,
                           strengths, weaknesses, recommendations, generated_at
                    FROM benchmark_reports
                    WHERE org_id = ?
                    ORDER BY generated_at ASC
                    """,
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
        return [self._row_to_report(r) for r in rows]

    def get_latest_report(self, org_id: str) -> Optional[BenchmarkReport]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT id, org_id, vertical, metrics, overall_percentile,
                           strengths, weaknesses, recommendations, generated_at
                    FROM benchmark_reports
                    WHERE org_id = ?
                    ORDER BY generated_at DESC
                    LIMIT 1
                    """,
                    (org_id,),
                ).fetchone()
            finally:
                conn.close()
        return self._row_to_report(row) if row else None

    @staticmethod
    def _row_to_report(row: sqlite3.Row) -> BenchmarkReport:
        metrics_raw = json.loads(row["metrics"])
        return BenchmarkReport(
            id=row["id"],
            org_id=row["org_id"],
            vertical=IndustryVertical(row["vertical"]),
            metrics=[BenchmarkMetric(**m) for m in metrics_raw],
            overall_percentile=row["overall_percentile"],
            strengths=json.loads(row["strengths"]),
            weaknesses=json.loads(row["weaknesses"]),
            recommendations=json.loads(row["recommendations"]),
            generated_at=row["generated_at"],
        )


# ============================================================================
# POSTURE BENCHMARK ENGINE
# ============================================================================


class PostureBenchmark:
    """
    Security posture benchmarking engine.

    Compares an organisation's metric values against industry-vertical benchmarks
    and generates actionable reports.
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self._db = _BenchmarkDB(db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_benchmark(
        self,
        org_id: str,
        vertical: IndustryVertical,
        org_metrics: Optional[Dict[str, float]] = None,
    ) -> BenchmarkReport:
        """
        Compare the org's posture against the given industry vertical.

        If org_metrics is not provided, previously stored metric values are
        used. Any metrics not supplied default to the industry average (50th pct).

        Args:
            org_id: Organisation identifier.
            vertical: Industry vertical for benchmark comparison.
            org_metrics: Optional dict of metric_name -> measured value.

        Returns:
            A persisted BenchmarkReport.
        """
        stored = self._db.get_org_metrics(org_id)
        effective = {**stored, **(org_metrics or {})}

        if org_metrics:
            self._db.save_org_metrics(org_id, org_metrics)

        industry_data = self.get_industry_averages(vertical)
        benchmark_metrics: List[BenchmarkMetric] = []

        for metric_name in _ALL_METRICS:
            ref = industry_data[metric_name]
            avg = ref["avg"]
            p90 = ref["p90"]
            higher_is_better = ref["higher_is_better"]

            org_value = effective.get(metric_name, avg)  # default to avg → 50th pct
            percentile = _compute_percentile(org_value, avg, p90, higher_is_better)

            if higher_is_better:
                gap = org_value - avg
            else:
                gap = avg - org_value  # positive gap means org is better (lower value)

            benchmark_metrics.append(
                BenchmarkMetric(
                    name=metric_name,
                    org_value=org_value,
                    industry_avg=avg,
                    industry_p90=p90,
                    percentile_rank=round(percentile, 1),
                    gap=round(gap, 2),
                )
            )

        overall_percentile = round(
            sum(m.percentile_rank for m in benchmark_metrics) / len(benchmark_metrics), 1
        )

        strengths = [m.name for m in benchmark_metrics if m.percentile_rank >= 60.0]
        weaknesses = [m.name for m in benchmark_metrics if m.percentile_rank < 40.0]

        # Recommendations ordered by percentile rank (worst first)
        sorted_weak = sorted(
            [m for m in benchmark_metrics if m.name in weaknesses],
            key=lambda m: m.percentile_rank,
        )
        recommendations = [
            _RECOMMENDATIONS[m.name]
            for m in sorted_weak
            if m.name in _RECOMMENDATIONS
        ]

        report = BenchmarkReport(
            org_id=org_id,
            vertical=vertical,
            metrics=benchmark_metrics,
            overall_percentile=overall_percentile,
            strengths=strengths,
            weaknesses=weaknesses,
            recommendations=recommendations,
        )
        self._db.save_report(report)
        _logger.info(
            "benchmark_generated",
            org_id=org_id,
            vertical=vertical.value,
            overall_percentile=overall_percentile,
        )
        return report

    def get_industry_averages(self, vertical: IndustryVertical) -> Dict[str, Dict[str, Any]]:
        """
        Return benchmark statistics for every metric in the given vertical.

        Returns:
            Dict mapping metric_name to {"avg", "p90", "higher_is_better"}.
        """
        result: Dict[str, Dict[str, Any]] = {}
        for metric_name, vertical_data in _BENCHMARK_DATA.items():
            result[metric_name] = vertical_data[vertical.value]
        return result

    def get_percentile_rank(self, org_id: str, metric_name: str) -> Optional[float]:
        """
        Return the org's current percentile rank for a specific metric.

        Looks up the most recent benchmark report to find the metric.

        Returns:
            Percentile rank (0-100) or None if no data is available.
        """
        report = self._db.get_latest_report(org_id)
        if report is None:
            return None
        for m in report.metrics:
            if m.name == metric_name:
                return m.percentile_rank
        return None

    def get_improvement_priorities(self, org_id: str) -> List[Dict[str, Any]]:
        """
        Return metrics ranked by improvement opportunity (worst percentile first).

        Each item contains metric name, current percentile, industry average,
        org value, and the relevant recommendation.

        Returns:
            List of priority dicts sorted by percentile_rank ascending.
        """
        report = self._db.get_latest_report(org_id)
        if report is None:
            return []

        priorities = []
        for m in sorted(report.metrics, key=lambda x: x.percentile_rank):
            priorities.append(
                {
                    "metric": m.name,
                    "percentile_rank": m.percentile_rank,
                    "org_value": m.org_value,
                    "industry_avg": m.industry_avg,
                    "industry_p90": m.industry_p90,
                    "gap": m.gap,
                    "recommendation": _RECOMMENDATIONS.get(m.name, ""),
                }
            )
        return priorities

    def get_benchmark_history(self, org_id: str) -> List[BenchmarkReport]:
        """
        Return all historical benchmark reports for an org, ordered chronologically.

        Returns:
            List of BenchmarkReport objects (oldest first).
        """
        return self._db.get_history(org_id)

    def get_latest_report(self, org_id: str) -> Optional[BenchmarkReport]:
        """Return the most recent benchmark report for an org."""
        return self._db.get_latest_report(org_id)


# ============================================================================
# SINGLETON FACTORY
# ============================================================================

_instance: Optional[PostureBenchmark] = None
_instance_lock = threading.Lock()


def get_posture_benchmark(db_path: str = _DEFAULT_DB_PATH) -> PostureBenchmark:
    """Return a process-wide singleton PostureBenchmark instance."""
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = PostureBenchmark(db_path=db_path)
    return _instance
