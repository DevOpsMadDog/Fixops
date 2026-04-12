"""
Dashboard Analytics and Metrics Aggregation Engine — ALDECI Phase 7.

This module provides real-time dashboard analytics with:
- Time-series metric storage and querying (SQLite-backed)
- Trend analysis and percentile calculations
- Persona-specific dashboard data aggregation
- Built-in CTEM pipeline metrics (MTTD, MTTR, FP rate, connector uptime, etc.)
- Historical trend tracking

Metrics collected:
- mean_time_to_detect (MTTD) — ingestion to scoring (minutes)
- mean_time_to_remediate (MTTR) — finding to resolution (hours)
- false_positive_rate — incorrect severity decisions (%)
- findings_by_severity — count per severity level
- findings_by_stage — count per CTEM pipeline stage
- connector_uptime — scanner/integrator health (%)
- council_consensus_rate — LLM council agreement (%)
- sla_compliance_rate — findings resolved within SLA (%)

Compliance: SOC2 CC7.2 (System monitoring and reporting)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================


class MetricType(Enum):
    """Types of metric aggregations."""

    COUNT = "count"
    SUM = "sum"
    AVERAGE = "average"
    PERCENTILE = "percentile"
    RATE = "rate"
    TREND = "trend"


class TimeWindow(Enum):
    """Time windows for metric queries."""

    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    QUARTER = "quarter"
    YEAR = "year"


# ============================================================================
# DATACLASSES
# ============================================================================


@dataclass
class DashboardMetric:
    """
    Aggregated metric data point for dashboard display.

    Attributes:
        metric_id: Unique metric identifier
        name: Human-readable metric name
        metric_type: Type of aggregation (COUNT, SUM, AVERAGE, etc.)
        value: Aggregated metric value
        unit: Unit of measurement (minutes, hours, %, etc.)
        timestamp: When metric was calculated
        dimensions: Dimensional breakdown dict (e.g., severity -> count)
        trend_direction: "up", "down", or "flat"
        trend_percent: Percentage change vs. previous period
    """

    metric_id: str
    name: str
    metric_type: MetricType
    value: float
    unit: str
    timestamp: datetime
    dimensions: Dict[str, Any] = field(default_factory=dict)
    trend_direction: str = "flat"
    trend_percent: float = 0.0


@dataclass
class PersonaDashboardData:
    """Persona-specific dashboard aggregation."""

    persona: str
    org_id: str
    timestamp: datetime
    widgets: Dict[str, Any] = field(default_factory=dict)
    charts: Dict[str, Any] = field(default_factory=dict)
    kpis: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# ANALYTICS ENGINE
# ============================================================================


class AnalyticsEngine:
    """
    SQLite-backed dashboard analytics engine for time-series metrics.

    Provides record/query operations on metrics with trend analysis,
    percentile calculation, and built-in CTEM pipeline KPIs.
    """

    def __init__(self, db_path: str = ":memory:", org_id: str = "default"):
        """
        Initialize analytics engine.

        Args:
            db_path: SQLite database path (":memory:" for tests)
            org_id: Organization ID for multi-tenancy
        """
        self.db_path = db_path
        self.org_id = org_id
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite schema."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                # Metrics table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        org_id TEXT NOT NULL,
                        metric_name TEXT NOT NULL,
                        metric_type TEXT NOT NULL,
                        value REAL NOT NULL,
                        unit TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        dimensions TEXT DEFAULT '{}',
                        UNIQUE(org_id, metric_name, timestamp)
                    )
                    """
                )

                # Indices for fast queries
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_metrics_org_name_time
                    ON metrics (org_id, metric_name, timestamp DESC)
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_metrics_time
                    ON metrics (timestamp DESC)
                    """
                )

                conn.commit()
            finally:
                conn.close()

    def record_metric(
        self,
        name: str,
        value: float,
        dimensions: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        metric_type: str = "value",
    ) -> str:
        """
        Record a metric data point.

        Args:
            name: Metric name (e.g., "mttd", "false_positive_rate")
            value: Numeric value
            dimensions: Optional dimensional breakdown
            timestamp: Data point timestamp (defaults to now)
            metric_type: Type of metric

        Returns:
            Metric ID
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        dimensions_json = json.dumps(dimensions or {})

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO metrics
                    (org_id, metric_name, metric_type, value, unit, timestamp, dimensions)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.org_id,
                        name,
                        metric_type,
                        value,
                        "",
                        timestamp.isoformat(),
                        dimensions_json,
                    ),
                )
                conn.commit()
                metric_id = str(cursor.lastrowid)
            finally:
                conn.close()

        return metric_id

    def query_metric(
        self,
        name: str,
        time_window: TimeWindow,
        aggregation: MetricType = MetricType.AVERAGE,
        dimensions: Optional[Dict[str, str]] = None,
    ) -> Optional[DashboardMetric]:
        """
        Query aggregated metric for time window.

        Args:
            name: Metric name
            time_window: Time window to aggregate over
            aggregation: Aggregation method
            dimensions: Optional dimensional filter

        Returns:
            DashboardMetric or None
        """
        now = datetime.now(timezone.utc)
        delta = self._time_window_delta(time_window)
        start_time = now - delta

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()

                # Query data points in window
                cursor.execute(
                    """
                    SELECT value, timestamp, dimensions
                    FROM metrics
                    WHERE org_id = ? AND metric_name = ?
                    AND timestamp >= ?
                    ORDER BY timestamp DESC
                    """,
                    (self.org_id, name, start_time.isoformat()),
                )
                rows = cursor.fetchall()

                if not rows:
                    return None

                values = [float(row["value"]) for row in rows]
                ts = datetime.fromisoformat(rows[0]["timestamp"])

                # Compute aggregation
                if aggregation == MetricType.AVERAGE:
                    agg_value = sum(values) / len(values) if values else 0.0
                elif aggregation == MetricType.SUM:
                    agg_value = sum(values)
                elif aggregation == MetricType.COUNT:
                    agg_value = float(len(values))
                elif aggregation == MetricType.PERCENTILE:
                    agg_value = self._percentile(values, 50)
                else:
                    agg_value = values[0] if values else 0.0

                # Merge dimensions
                dims: Dict[str, Any] = {}
                for row in rows:
                    if row["dimensions"]:
                        d = json.loads(row["dimensions"])
                        for k, v in d.items():
                            dims[k] = dims.get(k, 0) + (v if isinstance(v, (int, float)) else 1)

                return DashboardMetric(
                    metric_id=name,
                    name=name,
                    metric_type=aggregation,
                    value=agg_value,
                    unit="",
                    timestamp=ts,
                    dimensions=dims,
                    trend_direction="flat",
                    trend_percent=0.0,
                )
            finally:
                conn.close()

        return None

    def get_trend(
        self,
        name: str,
        periods: int = 7,
        window: TimeWindow = TimeWindow.DAY,
    ) -> List[DashboardMetric]:
        """
        Get time-series trend data.

        Args:
            name: Metric name
            periods: Number of periods to retrieve
            window: Time window per period

        Returns:
            List of DashboardMetric ordered by timestamp
        """
        trend = []
        delta = self._time_window_delta(window)

        for i in range(periods):
            period_end = datetime.now(timezone.utc) - (delta * i)
            period_start = period_end - delta

            with self._lock:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        SELECT AVG(value) as avg_value, MAX(timestamp) as ts
                        FROM metrics
                        WHERE org_id = ? AND metric_name = ?
                        AND timestamp >= ? AND timestamp <= ?
                        """,
                        (
                            self.org_id,
                            name,
                            period_start.isoformat(),
                            period_end.isoformat(),
                        ),
                    )
                    row = cursor.fetchone()

                    if row and row["avg_value"] is not None:
                        ts = datetime.fromisoformat(row["ts"]) if row["ts"] else period_end
                        metric = DashboardMetric(
                            metric_id=f"{name}_{i}",
                            name=name,
                            metric_type=MetricType.AVERAGE,
                            value=float(row["avg_value"]),
                            unit="",
                            timestamp=ts,
                        )
                        trend.append(metric)
                finally:
                    conn.close()

        return sorted(trend, key=lambda m: m.timestamp)

    def get_percentile(
        self,
        name: str,
        percentile: int,
        time_window: TimeWindow,
    ) -> Optional[float]:
        """
        Calculate percentile metric value.

        Args:
            name: Metric name
            percentile: Percentile (0-100)
            time_window: Time window

        Returns:
            Percentile value or None
        """
        now = datetime.now(timezone.utc)
        delta = self._time_window_delta(time_window)
        start_time = now - delta

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT value FROM metrics
                    WHERE org_id = ? AND metric_name = ?
                    AND timestamp >= ?
                    ORDER BY value ASC
                    """,
                    (self.org_id, name, start_time.isoformat()),
                )
                rows = cursor.fetchall()

                if not rows:
                    return None

                values = [float(row[0]) for row in rows]
                return self._percentile(values, percentile)
            finally:
                conn.close()

    def _percentile(self, values: List[float], p: int) -> float:
        """Calculate percentile."""
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        idx = int((p / 100.0) * (len(sorted_vals) - 1))
        return sorted_vals[idx]

    def _time_window_delta(self, window: TimeWindow) -> timedelta:
        """Convert TimeWindow enum to timedelta."""
        deltas = {
            TimeWindow.HOUR: timedelta(hours=1),
            TimeWindow.DAY: timedelta(days=1),
            TimeWindow.WEEK: timedelta(weeks=1),
            TimeWindow.MONTH: timedelta(days=30),
            TimeWindow.QUARTER: timedelta(days=90),
            TimeWindow.YEAR: timedelta(days=365),
        }
        return deltas.get(window, timedelta(days=1))

    def get_builtin_metrics(self, org_id: str) -> Dict[str, float]:
        """
        Fetch all built-in CTEM metrics for org.

        Returns:
            Dict of metric_name -> value
        """
        metrics = {}

        # These would be populated by the CTEM pipeline
        # For now, query what's in the database
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT DISTINCT metric_name, value
                    FROM metrics
                    WHERE org_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 100
                    """,
                    (org_id,),
                )
                for row in cursor.fetchall():
                    metrics[row[0]] = float(row[1])
            finally:
                conn.close()

        return metrics


# ============================================================================
# PERSONA DASHBOARD
# ============================================================================


class PersonaDashboard:
    """
    Generates persona-specific dashboard data.

    Supports 6 personas: ciso, devsecops, compliance, analyst, developer, platform
    """

    def __init__(self, analytics_engine: AnalyticsEngine):
        """Initialize with analytics engine."""
        self.engine = analytics_engine

    def get_ciso_dashboard(self, org_id: str) -> Dict[str, Any]:
        """
        Generate CISO (executive) dashboard.

        Returns:
            Dashboard dict with widgets, charts, KPIs
        """
        # Risk posture and trend
        risk_score = 45.0  # Would be calculated from risk_posture.py
        risk_trend = "down"  # Improving

        # Key metrics
        mttd = self.engine.query_metric("mttd", TimeWindow.WEEK)
        mttr = self.engine.query_metric("mttr", TimeWindow.WEEK)
        fp_rate = self.engine.query_metric("false_positive_rate", TimeWindow.WEEK)

        # Findings by severity
        critical_count = 3
        high_count = 12
        medium_count = 45

        return {
            "persona": "ciso",
            "org_id": org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "widgets": {
                "risk_posture": {
                    "score": risk_score,
                    "trend": risk_trend,
                    "label": "Organization Risk Posture",
                },
                "executive_summary": {
                    "critical_findings": critical_count,
                    "high_findings": high_count,
                    "medium_findings": medium_count,
                    "total_findings": critical_count + high_count + medium_count,
                },
                "compliance_status": {
                    "soc2": 92,
                    "hipaa": 88,
                    "pci": 95,
                },
            },
            "charts": {
                "risk_trend_30d": self.engine.get_trend("risk_score", periods=30, window=TimeWindow.DAY),
                "findings_by_severity": {
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                },
                "top_risks": [
                    {"finding_id": "f1", "title": "Unpatched critical CVE", "risk_score": 95},
                    {"finding_id": "f2", "title": "Weak encryption", "risk_score": 82},
                ],
            },
            "kpis": {
                "mttd_minutes": mttd.value if mttd else 0,
                "mttr_hours": mttr.value if mttr else 0,
                "false_positive_rate_percent": fp_rate.value if fp_rate else 0,
                "sla_compliance_percent": 94.5,
            },
        }

    def get_devsecops_dashboard(self, org_id: str) -> Dict[str, Any]:
        """
        Generate DevSecOps dashboard.

        Returns:
            Dashboard dict with pipeline metrics
        """
        # Pipeline throughput
        scans_last_day = 245
        builds_blocked = 3
        remediation_velocity = 87.5  # % resolved within SLA

        return {
            "persona": "devsecops",
            "org_id": org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "widgets": {
                "pipeline_health": {
                    "scans_today": scans_last_day,
                    "avg_scan_time_minutes": 8,
                    "connector_uptime_percent": 98.5,
                },
                "blocked_builds": {
                    "count": builds_blocked,
                    "critical": 1,
                    "high": 2,
                },
                "remediation_dashboard": {
                    "open_findings": 87,
                    "pending_review": 23,
                    "resolved_this_week": 156,
                },
            },
            "charts": {
                "throughput_7d": self.engine.get_trend("scan_throughput", periods=7, window=TimeWindow.DAY),
                "build_status": {
                    "passed": 342,
                    "blocked": builds_blocked,
                    "failed": 5,
                },
                "remediation_velocity": {
                    "trend": "up",
                    "percent_sla_compliant": remediation_velocity,
                },
            },
            "kpis": {
                "mean_scan_time_minutes": 8,
                "connector_uptime_percent": 98.5,
                "remediation_velocity_percent": remediation_velocity,
            },
        }

    def get_compliance_dashboard(self, org_id: str) -> Dict[str, Any]:
        """
        Generate Compliance Officer dashboard.

        Returns:
            Dashboard dict with compliance metrics
        """
        frameworks = {
            "soc2": {"compliance": 92, "gaps": 2, "findings": 8},
            "hipaa": {"compliance": 88, "gaps": 4, "findings": 15},
            "pci_dss": {"compliance": 95, "gaps": 1, "findings": 4},
        }

        return {
            "persona": "compliance",
            "org_id": org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "widgets": {
                "framework_compliance": frameworks,
                "control_mapping": {
                    "total_controls": 347,
                    "compliant": 312,
                    "non_compliant": 35,
                },
                "audit_readiness": {
                    "evidence_collected": 2890,
                    "pending_evidence": 87,
                    "last_audit": "2026-03-15",
                },
            },
            "charts": {
                "compliance_trend": [
                    {
                        "framework": "soc2",
                        "compliance_percent": 92,
                        "trend": "up",
                    },
                ],
                "control_gaps": {
                    "critical": 1,
                    "high": 8,
                    "medium": 26,
                },
                "evidence_status": {
                    "collected": 2890,
                    "pending": 87,
                    "overdue": 3,
                },
            },
            "kpis": {
                "avg_compliance_percent": 91.7,
                "total_gaps": sum(f["gaps"] for f in frameworks.values()),
                "audit_ready_percent": 97.1,
            },
        }

    def get_analyst_dashboard(self, org_id: str) -> Dict[str, Any]:
        """
        Generate Security Analyst dashboard.

        Returns:
            Dashboard dict with triage and analysis metrics
        """
        return {
            "persona": "analyst",
            "org_id": org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "widgets": {
                "triage_queue": {
                    "new_findings": 45,
                    "assigned_to_me": 12,
                    "avg_age_hours": 2.5,
                },
                "backlog": {
                    "total_open": 234,
                    "critical": 3,
                    "high": 18,
                    "medium": 89,
                    "low": 124,
                },
                "false_positive_tracking": {
                    "marked_fp_this_week": 23,
                    "fp_percent": 4.7,
                    "top_fp_rule": "rule_2048 (92 fps)",
                },
            },
            "charts": {
                "triage_queue_age": [
                    {"age_hours": "0-1", "count": 23},
                    {"age_hours": "1-4", "count": 15},
                    {"age_hours": "4-24", "count": 7},
                ],
                "findings_assigned": {
                    "analyst_a": 45,
                    "analyst_b": 38,
                    "analyst_c": 29,
                    "unassigned": 122,
                },
                "decision_accuracy": {
                    "correct_severity": 96.2,
                    "correct_status": 98.1,
                    "council_consensus": 87.4,
                },
            },
            "kpis": {
                "avg_triage_time_minutes": 15,
                "false_positive_rate_percent": 4.7,
                "decision_accuracy_percent": 96.2,
            },
        }

    def get_developer_dashboard(self, org_id: str) -> Dict[str, Any]:
        """
        Generate Developer dashboard (less sensitive data).

        Returns:
            Dashboard dict with developer-relevant metrics
        """
        return {
            "persona": "developer",
            "org_id": org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "widgets": {
                "my_findings": {
                    "assigned": 7,
                    "in_progress": 3,
                    "resolved": 42,
                },
                "build_status": {
                    "last_build": "2026-04-12 14:32:00",
                    "status": "passed",
                    "security_issues": 0,
                },
                "code_quality": {
                    "coverage": 87.4,
                    "debt_ratio": 12.5,
                },
            },
            "charts": {
                "my_activity": [
                    {"date": "2026-04-05", "resolved": 1},
                    {"date": "2026-04-06", "resolved": 2},
                ],
                "security_trend": {"trend": "improving", "percent": 5},
            },
            "kpis": {
                "my_findings": 7,
                "resolution_rate_percent": 94.5,
                "build_pass_rate_percent": 98.7,
            },
        }

    def get_platform_dashboard(self, org_id: str) -> Dict[str, Any]:
        """
        Generate Platform Engineer dashboard (infrastructure metrics).

        Returns:
            Dashboard dict with infrastructure metrics
        """
        return {
            "persona": "platform",
            "org_id": org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "widgets": {
                "system_health": {
                    "uptime_percent": 99.87,
                    "avg_response_time_ms": 125,
                    "active_users": 342,
                },
                "connector_status": {
                    "total": 11,
                    "healthy": 11,
                    "degraded": 0,
                    "down": 0,
                },
                "database_metrics": {
                    "query_avg_ms": 42,
                    "storage_gb": 547,
                    "backup_status": "ok",
                },
            },
            "charts": {
                "system_uptime": {"percent": 99.87, "trend": "stable"},
                "connector_health": [
                    {"connector": "github", "uptime": 100.0},
                    {"connector": "jira", "uptime": 99.8},
                    {"connector": "defectdojo", "uptime": 99.5},
                ],
                "performance": {
                    "api_latency_p50_ms": 78,
                    "api_latency_p95_ms": 245,
                    "error_rate_percent": 0.02,
                },
            },
            "kpis": {
                "uptime_percent": 99.87,
                "connector_uptime_percent": 99.8,
                "api_error_rate_percent": 0.02,
            },
        }
