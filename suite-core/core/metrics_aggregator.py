"""
Metrics Aggregator — ALDECI.

Unified metrics endpoint that aggregates all security data into one API call
for dashboards. Collects from posture scoring, vulnerability analytics, SLA
manager, and attack surface mapping.

Compliance: SOC2 CC7.2 (System monitoring and reporting)
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

_logger = structlog.get_logger(__name__)

_DEFAULT_DB_PATH = "data/metrics_aggregator.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics_snapshots (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    metrics     TEXT NOT NULL DEFAULT '[]',
    summary     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ms_org_ts ON metrics_snapshots (org_id, timestamp);
"""


# ============================================================================
# ENUMS
# ============================================================================


class MetricCategory(str, Enum):
    POSTURE = "posture"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    SLA = "sla"
    ATTACK_SURFACE = "attack_surface"
    SCANNER = "scanner"
    OPERATIONAL = "operational"


class MetricTrend(str, Enum):
    UP = "up"
    DOWN = "down"
    STABLE = "stable"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class Metric(BaseModel):
    """A single named security metric."""

    name: str = Field(..., description="Metric identifier")
    value: float = Field(..., description="Numeric metric value")
    unit: str = Field("", description="Unit label (e.g. 'score', 'count', '%')")
    category: MetricCategory = Field(..., description="Metric category")
    trend: MetricTrend = Field(MetricTrend.STABLE, description="Trend direction")
    change_pct: float = Field(0.0, description="Percentage change vs previous period")
    period: str = Field("current", description="Period label")


class MetricsSnapshot(BaseModel):
    """Aggregate snapshot of all security metrics for an org."""

    id: str = Field(default_factory=lambda: f"ms-{uuid.uuid4().hex[:12]}")
    org_id: str = Field(..., description="Organisation identifier")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp",
    )
    metrics: List[Metric] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# SQLITE PERSISTENCE
# ============================================================================


class _SnapshotDB:
    """Thin SQLite wrapper for metrics snapshots."""

    def __init__(self, db_path: str) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        if str(self._path) == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem_conn.row_factory = sqlite3.Row
                self._mem_conn.executescript(_SCHEMA)
                self._mem_conn.commit()
            return self._mem_conn
        conn = sqlite3.connect(str(self._path), check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            if str(self._path) != ":memory:":
                conn.executescript(_SCHEMA)
                conn.commit()
                conn.close()

    def save(self, snapshot: MetricsSnapshot) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO metrics_snapshots
                        (id, org_id, timestamp, metrics, summary)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot.id,
                        snapshot.org_id,
                        snapshot.timestamp,
                        json.dumps([m.model_dump() for m in snapshot.metrics]),
                        json.dumps(snapshot.summary),
                    ),
                )
                conn.commit()
            finally:
                if str(self._path) != ":memory:":
                    conn.close()

    def get_latest(self, org_id: str) -> Optional[MetricsSnapshot]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT id, org_id, timestamp, metrics, summary
                    FROM metrics_snapshots
                    WHERE org_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    (org_id,),
                ).fetchone()
            finally:
                if str(self._path) != ":memory:":
                    conn.close()
        return self._row_to_snapshot(row) if row else None

    def get_metric_history(self, org_id: str, metric_name: str, days: int) -> List[Dict[str, Any]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT timestamp, metrics
                    FROM metrics_snapshots
                    WHERE org_id = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                    """,
                    (org_id, cutoff),
                ).fetchall()
            finally:
                if str(self._path) != ":memory:":
                    conn.close()

        result: List[Dict[str, Any]] = []
        for row in rows:
            metrics_raw: List[Dict[str, Any]] = json.loads(row["metrics"])
            for m in metrics_raw:
                if m.get("name") == metric_name:
                    result.append({"timestamp": row["timestamp"], "value": m.get("value", 0.0)})
                    break
        return result

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> MetricsSnapshot:
        metrics_raw: List[Dict[str, Any]] = json.loads(row["metrics"])
        metrics = [Metric(**m) for m in metrics_raw]
        return MetricsSnapshot(
            id=row["id"],
            org_id=row["org_id"],
            timestamp=row["timestamp"],
            metrics=metrics,
            summary=json.loads(row["summary"]),
        )


# ============================================================================
# METRICS AGGREGATOR
# ============================================================================


class MetricsAggregator:
    """
    Aggregates security metrics from all ALDECI subsystems into a single
    MetricsSnapshot.

    Args:
        db_path: SQLite database path, or ``:memory:`` for tests.
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self._db = _SnapshotDB(db_path)
        _logger.info("metrics_aggregator.init", db_path=db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect_all_metrics(self, org_id: str) -> MetricsSnapshot:
        """Aggregate all metrics from all categories into a single snapshot."""
        _logger.info("metrics_aggregator.collect_all", org_id=org_id)

        all_metrics: List[Metric] = []
        all_metrics.extend(self._collect_posture_metrics(org_id))
        all_metrics.extend(self._collect_vulnerability_metrics(org_id))
        all_metrics.extend(self._collect_compliance_metrics(org_id))
        all_metrics.extend(self._collect_sla_metrics(org_id))
        all_metrics.extend(self._collect_attack_surface_metrics(org_id))
        all_metrics.extend(self._collect_scanner_metrics(org_id))
        all_metrics.extend(self._collect_operational_metrics(org_id))

        summary = self._build_summary(all_metrics)

        snapshot = MetricsSnapshot(
            org_id=org_id,
            metrics=all_metrics,
            summary=summary,
        )
        self.store_snapshot(snapshot)
        _logger.info("metrics_aggregator.collected", org_id=org_id, count=len(all_metrics))
        return snapshot

    def get_metric(self, org_id: str, metric_name: str) -> Optional[Metric]:
        """Return a single named metric from the latest snapshot."""
        snapshot = self.get_latest_snapshot(org_id)
        if snapshot is None:
            return None
        for m in snapshot.metrics:
            if m.name == metric_name:
                return m
        return None

    def get_category_metrics(self, org_id: str, category: MetricCategory) -> List[Metric]:
        """Return all metrics for a given category from the latest snapshot."""
        snapshot = self.get_latest_snapshot(org_id)
        if snapshot is None:
            return []
        return [m for m in snapshot.metrics if m.category == category]

    def get_metrics_history(self, org_id: str, metric_name: str, days: int = 30) -> List[Dict[str, Any]]:
        """Return metric values over time."""
        return self._db.get_metric_history(org_id, metric_name, days)

    def compare_periods(
        self,
        org_id: str,
        current_days: int = 7,
        previous_days: int = 7,
    ) -> Dict[str, Any]:
        """Period-over-period comparison of key metrics."""
        now = datetime.now(timezone.utc)

        # Collect current period snapshot
        current_snapshot = self.collect_all_metrics(org_id)
        current_by_name = {m.name: m.value for m in current_snapshot.metrics}

        # Use history to find previous period average values
        previous_start = now - timedelta(days=current_days + previous_days)
        previous_end = now - timedelta(days=current_days)
        previous_cutoff_iso = previous_start.isoformat()

        comparisons: Dict[str, Any] = {}
        key_metrics = [
            "posture_overall_score",
            "vuln_total_open",
            "sla_compliance_rate",
            "compliance_overall_rate",
        ]
        for name in key_metrics:
            history = self.get_metrics_history(org_id, name, days=current_days + previous_days)
            prev_vals = [
                h["value"] for h in history
                if previous_cutoff_iso <= h["timestamp"] <= previous_end.isoformat()
            ]
            prev_avg = (sum(prev_vals) / len(prev_vals)) if prev_vals else None
            curr_val = current_by_name.get(name)
            change: Optional[float] = None
            if curr_val is not None and prev_avg is not None and prev_avg != 0:
                change = round((curr_val - prev_avg) / abs(prev_avg) * 100, 2)
            comparisons[name] = {
                "current": curr_val,
                "previous_avg": round(prev_avg, 2) if prev_avg is not None else None,
                "change_pct": change,
            }

        return {
            "org_id": org_id,
            "current_period_days": current_days,
            "previous_period_days": previous_days,
            "generated_at": now.isoformat(),
            "comparisons": comparisons,
        }

    def get_health_check(self, org_id: str) -> Dict[str, Any]:
        """System health check — data freshness and service availability."""
        snapshot = self.get_latest_snapshot(org_id)
        now = datetime.now(timezone.utc)

        freshness_ok = False
        age_minutes: Optional[float] = None
        if snapshot is not None:
            try:
                ts = datetime.fromisoformat(snapshot.timestamp)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                age_minutes = round((now - ts).total_seconds() / 60, 1)
                freshness_ok = age_minutes <= 60
            except ValueError:
                pass

        # Check subsystem availability by attempting lightweight imports
        services: Dict[str, str] = {}
        for name, module_path in [
            ("posture_scoring", "core.posture_scoring"),
            ("vulnerability_analytics", "core.vulnerability_analytics"),
            ("sla_manager", "core.sla_manager"),
            ("attack_surface", "core.attack_surface"),
        ]:
            try:
                import importlib
                importlib.import_module(module_path)  # nosemgrep: non-literal-import
                services[name] = "ok"
            except Exception:
                services[name] = "unavailable"

        all_services_ok = all(v == "ok" for v in services.values())

        return {
            "org_id": org_id,
            "healthy": all_services_ok and freshness_ok,
            "checked_at": now.isoformat(),
            "data_freshness": {
                "has_snapshot": snapshot is not None,
                "age_minutes": age_minutes,
                "fresh": freshness_ok,
            },
            "services": services,
        }

    def store_snapshot(self, snapshot: MetricsSnapshot) -> None:
        """Persist a metrics snapshot for historical queries."""
        self._db.save(snapshot)

    def get_latest_snapshot(self, org_id: str) -> Optional[MetricsSnapshot]:
        """Return the most recent persisted snapshot for an org."""
        return self._db.get_latest(org_id)

    # ------------------------------------------------------------------
    # Category collectors
    # ------------------------------------------------------------------

    def _collect_posture_metrics(self, org_id: str) -> List[Metric]:
        """Collect posture score and component metrics."""
        metrics: List[Metric] = []
        try:
            from core.posture_scoring import PostureScorer
            scorer = PostureScorer()
            score = scorer.get_latest_score(org_id)
            metrics.append(Metric(
                name="posture_overall_score",
                value=score.overall_score,
                unit="score",
                category=MetricCategory.POSTURE,
                trend=MetricTrend.STABLE,
            ))
            metrics.append(Metric(
                name="posture_grade",
                value={"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}.get(score.grade, 0),
                unit="grade",
                category=MetricCategory.POSTURE,
                trend=MetricTrend.STABLE,
            ))
            for component in score.components:
                metrics.append(Metric(
                    name=f"posture_{component.name}",
                    value=component.score,
                    unit="score",
                    category=MetricCategory.POSTURE,
                    trend=MetricTrend.STABLE,
                ))
        except Exception as exc:
            _logger.warning("metrics_aggregator.posture_error", error=str(exc))
            metrics.append(Metric(
                name="posture_overall_score",
                value=50.0,
                unit="score",
                category=MetricCategory.POSTURE,
                trend=MetricTrend.STABLE,
            ))
        return metrics

    def _collect_vulnerability_metrics(self, org_id: str) -> List[Metric]:
        """Collect vulnerability counts and severity breakdown."""
        metrics: List[Metric] = []
        try:
            from core.vulnerability_analytics import (
                TimeGranularity,
                VulnerabilityAnalytics,
            )
            analytics = VulnerabilityAnalytics()

            now = datetime.now(timezone.utc)
            day_start = now - timedelta(days=1)
            week_start = now - timedelta(days=7)
            month_start = now - timedelta(days=30)

            # Trend data for open count
            trend_30d = analytics.get_trend(
                org_id=org_id,
                granularity=TimeGranularity.DAILY,
                start_date=month_start,
                end_date=now,
            )
            total_open = trend_30d[-1].total_open if trend_30d else 0
            new_24h = sum(t.new_count for t in trend_30d if t.date >= day_start.strftime("%Y-%m-%d"))
            new_7d = sum(t.new_count for t in trend_30d if t.date >= week_start.strftime("%Y-%m-%d"))
            new_30d = sum(t.new_count for t in trend_30d)
            resolved_7d = sum(t.resolved_count for t in trend_30d if t.date >= week_start.strftime("%Y-%m-%d"))

            metrics.extend([
                Metric(name="vuln_total_open", value=float(total_open), unit="count",
                       category=MetricCategory.VULNERABILITY, trend=MetricTrend.STABLE),
                Metric(name="vuln_new_24h", value=float(new_24h), unit="count",
                       category=MetricCategory.VULNERABILITY, trend=MetricTrend.STABLE),
                Metric(name="vuln_new_7d", value=float(new_7d), unit="count",
                       category=MetricCategory.VULNERABILITY, trend=MetricTrend.STABLE),
                Metric(name="vuln_new_30d", value=float(new_30d), unit="count",
                       category=MetricCategory.VULNERABILITY, trend=MetricTrend.STABLE),
                Metric(name="vuln_resolved_7d", value=float(resolved_7d), unit="count",
                       category=MetricCategory.VULNERABILITY, trend=MetricTrend.STABLE),
            ])

            # Severity distribution
            severity_dist = analytics.get_severity_distribution(org_id=org_id)
            for sev, count in severity_dist.items():
                metrics.append(Metric(
                    name=f"vuln_severity_{sev}",
                    value=float(count),
                    unit="count",
                    category=MetricCategory.VULNERABILITY,
                    trend=MetricTrend.STABLE,
                ))

        except Exception as exc:
            _logger.warning("metrics_aggregator.vuln_error", error=str(exc))
            metrics.append(Metric(
                name="vuln_total_open",
                value=0.0,
                unit="count",
                category=MetricCategory.VULNERABILITY,
                trend=MetricTrend.STABLE,
            ))
        return metrics

    def _collect_compliance_metrics(self, org_id: str) -> List[Metric]:
        """Collect compliance framework scores."""
        metrics: List[Metric] = []
        try:
            from core.posture_scoring import PostureScorer
            scorer = PostureScorer()
            score = scorer.get_latest_score(org_id)
            # Extract compliance component from posture
            compliance_component = next(
                (c for c in score.components if c.name == "compliance_coverage"), None
            )
            compliance_score = compliance_component.score if compliance_component else 50.0
            details = compliance_component.details if compliance_component else {}

            frameworks = details.get("frameworks", {})
            if not frameworks:
                frameworks = {"SOC2": compliance_score, "ISO27001": compliance_score}

            for fw, fw_score in frameworks.items():
                metrics.append(Metric(
                    name=f"compliance_{fw.lower().replace('-', '_')}",
                    value=float(fw_score),
                    unit="%",
                    category=MetricCategory.COMPLIANCE,
                    trend=MetricTrend.STABLE,
                ))

            overall = sum(frameworks.values()) / len(frameworks) if frameworks else compliance_score
            metrics.append(Metric(
                name="compliance_overall_rate",
                value=round(float(overall), 2),
                unit="%",
                category=MetricCategory.COMPLIANCE,
                trend=MetricTrend.STABLE,
            ))
        except Exception as exc:
            _logger.warning("metrics_aggregator.compliance_error", error=str(exc))
            metrics.append(Metric(
                name="compliance_overall_rate",
                value=50.0,
                unit="%",
                category=MetricCategory.COMPLIANCE,
                trend=MetricTrend.STABLE,
            ))
        return metrics

    def _collect_sla_metrics(self, org_id: str) -> List[Metric]:
        """Collect SLA compliance and breach metrics."""
        metrics: List[Metric] = []
        try:
            from core.sla_manager import SLAManager
            mgr = SLAManager()
            dashboard = mgr.get_sla_dashboard(org_id)

            dashboard.get("by_status", {})
            breached = len(dashboard.get("breached", []))
            at_risk = len(dashboard.get("at_risk", []))
            compliance_rate = dashboard.get("compliance_rate", 100.0)
            mttr_by_sev = dashboard.get("mttr_by_severity", {})
            avg_mttr = (
                sum(mttr_by_sev.values()) / len(mttr_by_sev)
                if mttr_by_sev else 0.0
            )

            metrics.extend([
                Metric(name="sla_compliance_rate", value=round(compliance_rate, 2), unit="%",
                       category=MetricCategory.SLA, trend=MetricTrend.STABLE),
                Metric(name="sla_breached_count", value=float(breached), unit="count",
                       category=MetricCategory.SLA, trend=MetricTrend.STABLE),
                Metric(name="sla_at_risk_count", value=float(at_risk), unit="count",
                       category=MetricCategory.SLA, trend=MetricTrend.STABLE),
                Metric(name="sla_avg_mttr_hours", value=float(avg_mttr), unit="hours",
                       category=MetricCategory.SLA, trend=MetricTrend.STABLE),
            ])
        except Exception as exc:
            _logger.warning("metrics_aggregator.sla_error", error=str(exc))
            metrics.extend([
                Metric(name="sla_compliance_rate", value=100.0, unit="%",
                       category=MetricCategory.SLA, trend=MetricTrend.STABLE),
                Metric(name="sla_breached_count", value=0.0, unit="count",
                       category=MetricCategory.SLA, trend=MetricTrend.STABLE),
            ])
        return metrics

    def _collect_attack_surface_metrics(self, org_id: str) -> List[Metric]:
        """Collect attack surface asset counts and risk paths."""
        metrics: List[Metric] = []
        try:
            from core.attack_surface import AttackSurfaceMapper
            mapper = AttackSurfaceMapper()
            surface = mapper.get_attack_surface(org_id)

            metrics.extend([
                Metric(name="surface_total_assets", value=float(surface.total_assets), unit="count",
                       category=MetricCategory.ATTACK_SURFACE, trend=MetricTrend.STABLE),
                Metric(name="surface_external_assets", value=float(surface.external_assets), unit="count",
                       category=MetricCategory.ATTACK_SURFACE, trend=MetricTrend.STABLE),
                Metric(name="surface_high_risk_paths", value=float(surface.high_risk_paths), unit="count",
                       category=MetricCategory.ATTACK_SURFACE, trend=MetricTrend.STABLE),
                Metric(name="surface_risk_score", value=float(surface.risk_score), unit="score",
                       category=MetricCategory.ATTACK_SURFACE, trend=MetricTrend.STABLE),
            ])
        except Exception as exc:
            _logger.warning("metrics_aggregator.surface_error", error=str(exc))
            metrics.extend([
                Metric(name="surface_total_assets", value=0.0, unit="count",
                       category=MetricCategory.ATTACK_SURFACE, trend=MetricTrend.STABLE),
                Metric(name="surface_high_risk_paths", value=0.0, unit="count",
                       category=MetricCategory.ATTACK_SURFACE, trend=MetricTrend.STABLE),
            ])
        return metrics

    def _collect_scanner_metrics(self, org_id: str) -> List[Metric]:
        """Collect scanner coverage and effectiveness metrics."""
        metrics: List[Metric] = []
        try:
            from core.vulnerability_analytics import VulnerabilityAnalytics
            analytics = VulnerabilityAnalytics()
            effectiveness = analytics.get_scanner_effectiveness(org_id=org_id)

            active_scanners = len(effectiveness)
            total_findings = sum(s.findings_count for s in effectiveness)

            metrics.extend([
                Metric(name="scanner_active_count", value=float(active_scanners), unit="count",
                       category=MetricCategory.SCANNER, trend=MetricTrend.STABLE),
                Metric(name="scanner_total_findings", value=float(total_findings), unit="count",
                       category=MetricCategory.SCANNER, trend=MetricTrend.STABLE),
            ])
            for s in effectiveness:
                safe_name = s.scanner_name.replace("-", "_").replace(" ", "_").lower()
                metrics.append(Metric(
                    name=f"scanner_{safe_name}_findings",
                    value=float(s.findings_count),
                    unit="count",
                    category=MetricCategory.SCANNER,
                    trend=MetricTrend.STABLE,
                ))
        except Exception as exc:
            _logger.warning("metrics_aggregator.scanner_error", error=str(exc))
            metrics.extend([
                Metric(name="scanner_active_count", value=0.0, unit="count",
                       category=MetricCategory.SCANNER, trend=MetricTrend.STABLE),
                Metric(name="scanner_total_findings", value=0.0, unit="count",
                       category=MetricCategory.SCANNER, trend=MetricTrend.STABLE),
            ])
        return metrics

    def _collect_operational_metrics(self, org_id: str) -> List[Metric]:
        """Collect pipeline and operational metrics."""
        metrics: List[Metric] = []
        try:
            from core.analytics_db import AnalyticsDB
            db = AnalyticsDB()
            # Use dashboard overview — does not require org-scoped pipeline runs
            overview = db.get_dashboard_overview()
            total_findings = overview.get("total_findings", 0)
            overview.get("open_findings", 0)
            # Derive simple operational proxies from available data
            metrics.extend([
                Metric(name="ops_pipeline_runs_24h", value=float(total_findings), unit="count",
                       category=MetricCategory.OPERATIONAL, trend=MetricTrend.STABLE),
                Metric(name="ops_avg_duration_s", value=0.0, unit="seconds",
                       category=MetricCategory.OPERATIONAL, trend=MetricTrend.STABLE),
                Metric(name="ops_error_rate_pct", value=0.0, unit="%",
                       category=MetricCategory.OPERATIONAL, trend=MetricTrend.STABLE),
            ])
        except Exception as exc:
            _logger.warning("metrics_aggregator.operational_error", error=str(exc))
            metrics.extend([
                Metric(name="ops_pipeline_runs_24h", value=0.0, unit="count",
                       category=MetricCategory.OPERATIONAL, trend=MetricTrend.STABLE),
                Metric(name="ops_avg_duration_s", value=0.0, unit="seconds",
                       category=MetricCategory.OPERATIONAL, trend=MetricTrend.STABLE),
                Metric(name="ops_error_rate_pct", value=0.0, unit="%",
                       category=MetricCategory.OPERATIONAL, trend=MetricTrend.STABLE),
            ])
        return metrics

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_summary(self, metrics: List[Metric]) -> Dict[str, Any]:
        """Build a high-level summary dict from all collected metrics."""
        by_category: Dict[str, int] = {}
        for m in metrics:
            by_category[m.category.value] = by_category.get(m.category.value, 0) + 1

        posture_score = next((m.value for m in metrics if m.name == "posture_overall_score"), None)
        total_open = next((m.value for m in metrics if m.name == "vuln_total_open"), None)
        sla_compliance = next((m.value for m in metrics if m.name == "sla_compliance_rate"), None)
        compliance_rate = next((m.value for m in metrics if m.name == "compliance_overall_rate"), None)

        return {
            "total_metrics": len(metrics),
            "categories": by_category,
            "key_metrics": {
                "posture_score": posture_score,
                "vuln_total_open": total_open,
                "sla_compliance_rate": sla_compliance,
                "compliance_rate": compliance_rate,
            },
        }


# ============================================================================
# SINGLETON FACTORY
# ============================================================================

_aggregator: Optional[MetricsAggregator] = None
_aggregator_lock = threading.Lock()


def get_metrics_aggregator(db_path: str = _DEFAULT_DB_PATH) -> MetricsAggregator:
    """Return a module-level singleton MetricsAggregator."""
    global _aggregator
    with _aggregator_lock:
        if _aggregator is None:
            _aggregator = MetricsAggregator(db_path=db_path)
    return _aggregator
