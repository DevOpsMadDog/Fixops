"""
Security Metrics KPI Engine — ALDECI CISO Dashboard.

Tracks the security KPIs that CISOs care about:
- MTTD, MTTR, SLA compliance, patch rate, scan coverage, false positive rate,
  vulnerability density, compliance score, and 15+ more.

SQLite-backed with trend analysis, threshold alerting (green/yellow/red),
multi-org support, and auto-calculation from platform data.

Compliance: SOC2 CC7.2, ISO 27001 A.16
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================


class KPICategory(str, Enum):
    """Category grouping for security KPIs."""

    DETECTION = "detection"
    RESPONSE = "response"
    PREVENTION = "prevention"
    COMPLIANCE = "compliance"
    COVERAGE = "coverage"
    EFFICIENCY = "efficiency"


class KPITrend(str, Enum):
    """Directional trend for a KPI value."""

    UP = "up"
    DOWN = "down"
    STABLE = "stable"


class KPIHealth(str, Enum):
    """RAG health status for a KPI."""

    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"
    UNKNOWN = "unknown"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class KPI(BaseModel):
    """A security KPI data point."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Machine-readable KPI name (e.g. mttd_minutes)")
    value: float = Field(..., description="Current KPI value")
    target: Optional[float] = Field(None, description="Target value for this KPI")
    unit: str = Field("", description="Unit of measure (minutes, %, count, etc.)")
    trend: KPITrend = Field(KPITrend.STABLE, description="Direction of change vs. prior period")
    category: KPICategory = Field(..., description="KPI category")
    period: str = Field("", description="Reporting period (e.g. 2026-04, daily, weekly)")
    org_id: str = Field("default", description="Organisation identifier")
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KPITarget(BaseModel):
    """Threshold configuration for a KPI."""

    kpi_name: str = Field(..., description="KPI name this target applies to")
    target_value: float = Field(..., description="Ideal / goal value")
    threshold_yellow: float = Field(..., description="Value at which KPI turns yellow")
    threshold_red: float = Field(..., description="Value at which KPI turns red")
    higher_is_better: bool = Field(
        True,
        description="True = higher values are better (e.g. coverage). "
        "False = lower values are better (e.g. MTTD).",
    )


class KPIHealthStatus(BaseModel):
    """RAG health status for a single KPI."""

    name: str
    value: float
    target: Optional[float]
    health: KPIHealth
    trend: KPITrend
    category: KPICategory
    unit: str


class ExecutiveKPISummary(BaseModel):
    """CISO-facing executive summary of top KPIs."""

    org_id: str
    generated_at: datetime
    overall_health: KPIHealth
    kpis: List[KPIHealthStatus]
    green_count: int
    yellow_count: int
    red_count: int
    unknown_count: int


# ============================================================================
# BUILT-IN KPI DEFINITIONS
# ============================================================================

# Maps kpi_name -> (display_name, unit, category, higher_is_better, default_target)
_KPI_DEFINITIONS: Dict[str, Tuple[str, str, KPICategory, bool, float]] = {
    # Detection
    "mttd_minutes": (
        "Mean Time to Detect",
        "minutes",
        KPICategory.DETECTION,
        False,   # lower is better
        60.0,    # target: detect within 1 hour
    ),
    "alert_volume": (
        "Alert Volume",
        "count",
        KPICategory.DETECTION,
        False,   # lower (less noise) is better
        500.0,
    ),
    "detection_coverage_pct": (
        "Detection Coverage",
        "%",
        KPICategory.DETECTION,
        True,
        95.0,
    ),
    "threat_intel_freshness_hours": (
        "Threat Intel Freshness",
        "hours",
        KPICategory.DETECTION,
        False,
        24.0,
    ),
    # Response
    "mttr_hours": (
        "Mean Time to Remediate",
        "hours",
        KPICategory.RESPONSE,
        False,
        24.0,
    ),
    "sla_compliance_rate_pct": (
        "SLA Compliance Rate",
        "%",
        KPICategory.RESPONSE,
        True,
        95.0,
    ),
    "critical_open_findings": (
        "Open Critical Findings",
        "count",
        KPICategory.RESPONSE,
        False,
        0.0,
    ),
    "escalation_rate_pct": (
        "Escalation Rate",
        "%",
        KPICategory.RESPONSE,
        False,
        5.0,
    ),
    "reopen_rate_pct": (
        "Finding Reopen Rate",
        "%",
        KPICategory.RESPONSE,
        False,
        10.0,
    ),
    # Prevention
    "patch_rate_pct": (
        "Patch Application Rate",
        "%",
        KPICategory.PREVENTION,
        True,
        90.0,
    ),
    "vuln_density": (
        "Vulnerability Density (per 1K LOC)",
        "vulns/KLoC",
        KPICategory.PREVENTION,
        False,
        2.0,
    ),
    "critical_patch_lag_days": (
        "Critical Patch Lag",
        "days",
        KPICategory.PREVENTION,
        False,
        7.0,
    ),
    "exploitable_vuln_count": (
        "Exploitable Vulnerability Count",
        "count",
        KPICategory.PREVENTION,
        False,
        0.0,
    ),
    # Compliance
    "compliance_score_pct": (
        "Overall Compliance Score",
        "%",
        KPICategory.COMPLIANCE,
        True,
        90.0,
    ),
    "policy_violation_count": (
        "Policy Violation Count",
        "count",
        KPICategory.COMPLIANCE,
        False,
        0.0,
    ),
    "audit_finding_count": (
        "Audit Finding Count",
        "count",
        KPICategory.COMPLIANCE,
        False,
        0.0,
    ),
    "control_effectiveness_pct": (
        "Security Control Effectiveness",
        "%",
        KPICategory.COMPLIANCE,
        True,
        85.0,
    ),
    # Coverage
    "scan_coverage_pct": (
        "Scan Coverage",
        "%",
        KPICategory.COVERAGE,
        True,
        95.0,
    ),
    "asset_inventory_accuracy_pct": (
        "Asset Inventory Accuracy",
        "%",
        KPICategory.COVERAGE,
        True,
        99.0,
    ),
    "connector_uptime_pct": (
        "Connector / Integration Uptime",
        "%",
        KPICategory.COVERAGE,
        True,
        99.0,
    ),
    # Efficiency
    "false_positive_rate_pct": (
        "False Positive Rate",
        "%",
        KPICategory.EFFICIENCY,
        False,
        5.0,
    ),
    "automation_rate_pct": (
        "Automation Rate",
        "%",
        KPICategory.EFFICIENCY,
        True,
        60.0,
    ),
    "analyst_productivity": (
        "Findings Closed per Analyst per Day",
        "count/analyst/day",
        KPICategory.EFFICIENCY,
        True,
        10.0,
    ),
}

# Default threshold bands (as % deviation from target).
# Individual targets override these.
_DEFAULT_YELLOW_DEVIATION = 0.20   # 20% off target → yellow
_DEFAULT_RED_DEVIATION = 0.40      # 40% off target → red


# ============================================================================
# ENGINE
# ============================================================================


class KPIEngine:
    """
    SQLite-backed security KPI engine.

    Thread-safe; uses a per-connection model with a lock.
    """

    def __init__(self, db_path: str = "data/kpi_engine.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()
        self._seed_default_targets()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS kpi_records (
                        id          TEXT PRIMARY KEY,
                        name        TEXT NOT NULL,
                        value       REAL NOT NULL,
                        unit        TEXT NOT NULL DEFAULT '',
                        category    TEXT NOT NULL,
                        period      TEXT NOT NULL DEFAULT '',
                        org_id      TEXT NOT NULL DEFAULT 'default',
                        recorded_at TEXT NOT NULL,
                        metadata    TEXT NOT NULL DEFAULT '{}'
                    );

                    CREATE INDEX IF NOT EXISTS idx_kpi_records_org_name
                        ON kpi_records (org_id, name, recorded_at);

                    CREATE TABLE IF NOT EXISTS kpi_targets (
                        kpi_name           TEXT NOT NULL,
                        target_value       REAL NOT NULL,
                        threshold_yellow   REAL NOT NULL,
                        threshold_red      REAL NOT NULL,
                        higher_is_better   INTEGER NOT NULL DEFAULT 1,
                        PRIMARY KEY (kpi_name)
                    );
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def _seed_default_targets(self) -> None:
        """Insert default targets for all built-in KPIs (skip if already present)."""
        with self._lock:
            conn = self._get_conn()
            try:
                for name, (_, unit, category, higher_is_better, target) in _KPI_DEFINITIONS.items():
                    # Compute simple yellow/red thresholds from target
                    if higher_is_better:
                        yellow = target * (1 - _DEFAULT_YELLOW_DEVIATION)
                        red = target * (1 - _DEFAULT_RED_DEVIATION)
                    else:
                        yellow = target * (1 + _DEFAULT_YELLOW_DEVIATION)
                        red = target * (1 + _DEFAULT_RED_DEVIATION)

                    conn.execute(
                        """
                        INSERT OR IGNORE INTO kpi_targets
                            (kpi_name, target_value, threshold_yellow, threshold_red, higher_is_better)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (name, target, yellow, red, int(higher_is_better)),
                    )
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_kpi(
        self,
        name: str,
        value: float,
        category: KPICategory,
        org_id: str = "default",
        period: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> KPI:
        """
        Store a KPI data point.

        Args:
            name:     KPI name (e.g. "mttd_minutes").
            value:    Numeric value.
            category: KPI category enum.
            org_id:   Organisation identifier for multi-tenancy.
            period:   Optional period label (e.g. "2026-04").
            metadata: Optional extra context.

        Returns:
            The stored KPI model.
        """
        defn = _KPI_DEFINITIONS.get(name)
        unit = defn[1] if defn else ""
        if not period:
            period = datetime.now(timezone.utc).strftime("%Y-%m")

        kpi = KPI(
            name=name,
            value=value,
            unit=unit,
            category=category,
            period=period,
            org_id=org_id,
            metadata=metadata or {},
        )

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO kpi_records
                        (id, name, value, unit, category, period, org_id, recorded_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        kpi.id,
                        kpi.name,
                        kpi.value,
                        kpi.unit,
                        kpi.category.value,
                        kpi.period,
                        kpi.org_id,
                        kpi.recorded_at.isoformat(),
                        json.dumps(kpi.metadata),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        _logger.info("kpi.recorded name=%s value=%s org=%s", name, value, org_id)
        return kpi

    def get_current_kpis(self, org_id: str = "default") -> List[KPI]:
        """
        Return the most-recent value for every KPI recorded for this org,
        enriched with target and trend information.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                # Latest value per KPI name
                rows = conn.execute(
                    """
                    SELECT r.name, r.value, r.unit, r.category, r.period,
                           r.org_id, r.recorded_at, r.metadata, r.id,
                           t.target_value
                    FROM kpi_records r
                    LEFT JOIN kpi_targets t ON t.kpi_name = r.name
                    WHERE r.org_id = ?
                      AND r.recorded_at = (
                          SELECT MAX(r2.recorded_at)
                          FROM kpi_records r2
                          WHERE r2.org_id = r.org_id AND r2.name = r.name
                      )
                    ORDER BY r.name
                    """,
                    (org_id,),
                ).fetchall()

                result: List[KPI] = []
                for row in rows:
                    trend = self._compute_trend(conn, row["name"], org_id, row["value"])
                    result.append(
                        KPI(
                            id=row["id"],
                            name=row["name"],
                            value=row["value"],
                            target=row["target_value"],
                            unit=row["unit"],
                            trend=trend,
                            category=KPICategory(row["category"]),
                            period=row["period"],
                            org_id=row["org_id"],
                            recorded_at=datetime.fromisoformat(row["recorded_at"]),
                            metadata=json.loads(row["metadata"] or "{}"),
                        )
                    )
                return result
            finally:
                conn.close()

    def get_kpi_trend(
        self,
        name: str,
        org_id: str = "default",
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """
        Return KPI values over time for trend charting.

        Args:
            name:   KPI name.
            org_id: Organisation identifier.
            days:   How many days back to look.

        Returns:
            List of {timestamp, value} dicts ordered by timestamp ascending.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT recorded_at, value
                    FROM kpi_records
                    WHERE org_id = ? AND name = ? AND recorded_at >= ?
                    ORDER BY recorded_at ASC
                    """,
                    (org_id, name, cutoff),
                ).fetchall()
                return [{"timestamp": row["recorded_at"], "value": row["value"]} for row in rows]
            finally:
                conn.close()

    def set_target(
        self,
        name: str,
        target: float,
        yellow: float,
        red: float,
        higher_is_better: bool = True,
    ) -> KPITarget:
        """
        Configure thresholds for a KPI.

        Args:
            name:              KPI name.
            target:            Ideal target value.
            yellow:            Threshold at which KPI turns yellow.
            red:               Threshold at which KPI turns red.
            higher_is_better:  True for metrics like coverage; False for MTTD.

        Returns:
            The stored KPITarget.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO kpi_targets
                        (kpi_name, target_value, threshold_yellow, threshold_red, higher_is_better)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(kpi_name) DO UPDATE SET
                        target_value     = excluded.target_value,
                        threshold_yellow = excluded.threshold_yellow,
                        threshold_red    = excluded.threshold_red,
                        higher_is_better = excluded.higher_is_better
                    """,
                    (name, target, yellow, red, int(higher_is_better)),
                )
                conn.commit()
            finally:
                conn.close()

        return KPITarget(
            kpi_name=name,
            target_value=target,
            threshold_yellow=yellow,
            threshold_red=red,
            higher_is_better=higher_is_better,
        )

    def get_kpi_health(self, org_id: str = "default") -> List[KPIHealthStatus]:
        """
        Return RAG health status for all KPIs for this org.

        Returns:
            List of KPIHealthStatus with green/yellow/red classification.
        """
        kpis = self.get_current_kpis(org_id)
        with self._lock:
            conn = self._get_conn()
            try:
                targets_rows = conn.execute(
                    "SELECT kpi_name, target_value, threshold_yellow, threshold_red, higher_is_better "
                    "FROM kpi_targets"
                ).fetchall()
            finally:
                conn.close()

        targets: Dict[str, sqlite3.Row] = {row["kpi_name"]: row for row in targets_rows}

        result: List[KPIHealthStatus] = []
        for kpi in kpis:
            health = self._classify_health(kpi.value, targets.get(kpi.name))
            result.append(
                KPIHealthStatus(
                    name=kpi.name,
                    value=kpi.value,
                    target=kpi.target,
                    health=health,
                    trend=kpi.trend,
                    category=kpi.category,
                    unit=kpi.unit,
                )
            )
        return result

    def get_executive_kpis(self, org_id: str = "default") -> ExecutiveKPISummary:
        """
        Return top 10 KPIs for the CISO executive dashboard.

        Prioritises: critical findings, MTTD, MTTR, SLA compliance,
        compliance score, scan coverage, patch rate, false positive rate,
        connector uptime, and vuln density.

        Returns:
            ExecutiveKPISummary with overall health and per-KPI breakdown.
        """
        _PRIORITY_KPIS = [
            "critical_open_findings",
            "mttd_minutes",
            "mttr_hours",
            "sla_compliance_rate_pct",
            "compliance_score_pct",
            "scan_coverage_pct",
            "patch_rate_pct",
            "false_positive_rate_pct",
            "connector_uptime_pct",
            "vuln_density",
        ]

        health_statuses = self.get_kpi_health(org_id)
        by_name = {h.name: h for h in health_statuses}

        selected: List[KPIHealthStatus] = []
        for kpi_name in _PRIORITY_KPIS:
            if kpi_name in by_name:
                selected.append(by_name[kpi_name])

        # Fill remaining slots with whatever we have (up to 10 total)
        seen = {h.name for h in selected}
        for h in health_statuses:
            if len(selected) >= 10:
                break
            if h.name not in seen:
                selected.append(h)
                seen.add(h.name)

        counts = {KPIHealth.GREEN: 0, KPIHealth.YELLOW: 0, KPIHealth.RED: 0, KPIHealth.UNKNOWN: 0}
        for h in selected:
            counts[h.health] += 1

        # Overall health = worst of constituent KPIs
        if counts[KPIHealth.RED] > 0:
            overall = KPIHealth.RED
        elif counts[KPIHealth.YELLOW] > 0:
            overall = KPIHealth.YELLOW
        elif counts[KPIHealth.GREEN] > 0:
            overall = KPIHealth.GREEN
        else:
            overall = KPIHealth.UNKNOWN

        return ExecutiveKPISummary(
            org_id=org_id,
            generated_at=datetime.now(timezone.utc),
            overall_health=overall,
            kpis=selected,
            green_count=counts[KPIHealth.GREEN],
            yellow_count=counts[KPIHealth.YELLOW],
            red_count=counts[KPIHealth.RED],
            unknown_count=counts[KPIHealth.UNKNOWN],
        )

    def auto_calculate_kpis(self, org_id: str = "default") -> List[KPI]:
        """
        Compute all KPIs that can be derived from platform data.

        Queries the analytics and findings databases (if available) to
        populate KPI values automatically. Falls back gracefully if
        dependent data sources are unavailable.

        Returns:
            List of KPI records that were recorded.
        """
        recorded: List[KPI] = []

        # --- MTTD from analytics engine ---
        try:
            from core.analytics_engine import AnalyticsEngine, MetricType, TimeWindow

            ae = AnalyticsEngine(org_id=org_id)
            mttd_metric = ae.query_metric("mttd", TimeWindow.DAY, MetricType.AVERAGE)
            if mttd_metric is not None:
                recorded.append(
                    self.record_kpi(
                        "mttd_minutes",
                        mttd_metric.value,
                        KPICategory.DETECTION,
                        org_id=org_id,
                    )
                )
        except Exception as exc:
            _logger.debug("auto_calculate: mttd skipped (%s)", exc)

        # --- MTTR from analytics engine ---
        try:
            from core.analytics_engine import AnalyticsEngine, MetricType, TimeWindow

            ae = AnalyticsEngine(org_id=org_id)
            mttr_metric = ae.query_metric("mttr", TimeWindow.DAY, MetricType.AVERAGE)
            if mttr_metric is not None:
                recorded.append(
                    self.record_kpi(
                        "mttr_hours",
                        mttr_metric.value,
                        KPICategory.RESPONSE,
                        org_id=org_id,
                    )
                )
        except Exception as exc:
            _logger.debug("auto_calculate: mttr skipped (%s)", exc)

        # --- SLA compliance from analytics engine ---
        try:
            from core.analytics_engine import AnalyticsEngine, MetricType, TimeWindow

            ae = AnalyticsEngine(org_id=org_id)
            sla_metric = ae.query_metric("sla_compliance_rate", TimeWindow.DAY, MetricType.AVERAGE)
            if sla_metric is not None:
                recorded.append(
                    self.record_kpi(
                        "sla_compliance_rate_pct",
                        sla_metric.value,
                        KPICategory.RESPONSE,
                        org_id=org_id,
                    )
                )
        except Exception as exc:
            _logger.debug("auto_calculate: sla_compliance skipped (%s)", exc)

        # --- False positive rate from analytics engine ---
        try:
            from core.analytics_engine import AnalyticsEngine, MetricType, TimeWindow

            ae = AnalyticsEngine(org_id=org_id)
            fp_metric = ae.query_metric("false_positive_rate", TimeWindow.DAY, MetricType.AVERAGE)
            if fp_metric is not None:
                recorded.append(
                    self.record_kpi(
                        "false_positive_rate_pct",
                        fp_metric.value,
                        KPICategory.EFFICIENCY,
                        org_id=org_id,
                    )
                )
        except Exception as exc:
            _logger.debug("auto_calculate: false_positive_rate skipped (%s)", exc)

        # --- Critical open findings from analytics DB ---
        try:
            from core.analytics_db import AnalyticsDB
            from core.analytics_models import FindingSeverity, FindingStatus

            adb = AnalyticsDB()
            findings = adb.get_findings(org_id=org_id, limit=10000)
            critical_open = sum(
                1
                for f in findings
                if f.severity == FindingSeverity.CRITICAL
                and f.status == FindingStatus.OPEN
            )
            recorded.append(
                self.record_kpi(
                    "critical_open_findings",
                    float(critical_open),
                    KPICategory.RESPONSE,
                    org_id=org_id,
                )
            )
        except Exception as exc:
            _logger.debug("auto_calculate: critical_open_findings skipped (%s)", exc)

        _logger.info(
            "auto_calculate_kpis: recorded %d KPIs for org=%s",
            len(recorded),
            org_id,
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "kpi", "org_id": org_id, "source_engine": "kpi"})
            except Exception:
                pass

        return recorded

    def list_kpi_definitions(self) -> List[Dict[str, Any]]:
        """Return all built-in KPI definitions with their metadata."""
        result = []
        for name, (display, unit, category, higher_is_better, target) in _KPI_DEFINITIONS.items():
            result.append(
                {
                    "name": name,
                    "display_name": display,
                    "unit": unit,
                    "category": category.value,
                    "higher_is_better": higher_is_better,
                    "default_target": target,
                }
            )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_trend(
        self,
        conn: sqlite3.Connection,
        name: str,
        org_id: str,
        current_value: float,
    ) -> KPITrend:
        """Compare current value with the previous recorded value."""
        row = conn.execute(
            """
            SELECT value FROM kpi_records
            WHERE org_id = ? AND name = ?
            ORDER BY recorded_at DESC
            LIMIT 1 OFFSET 1
            """,
            (org_id, name),
        ).fetchone()

        if row is None:
            return KPITrend.STABLE

        previous = row["value"]
        if previous == 0:
            return KPITrend.STABLE

        change_pct = abs(current_value - previous) / abs(previous)
        if change_pct < 0.02:
            return KPITrend.STABLE
        return KPITrend.UP if current_value > previous else KPITrend.DOWN

    def _classify_health(
        self,
        value: float,
        target_row: Optional[sqlite3.Row],
    ) -> KPIHealth:
        """Classify a KPI value as green/yellow/red based on its target thresholds."""
        if target_row is None:
            return KPIHealth.UNKNOWN

        higher_is_better = bool(target_row["higher_is_better"])
        yellow_threshold = target_row["threshold_yellow"]
        red_threshold = target_row["threshold_red"]

        if higher_is_better:
            # e.g. coverage: 95% target → red < 57%, yellow < 76%
            if value >= yellow_threshold:
                return KPIHealth.GREEN
            if value >= red_threshold:
                return KPIHealth.YELLOW
            return KPIHealth.RED
        else:
            # e.g. MTTD: 60 min target → yellow > 72 min, red > 84 min
            if value <= yellow_threshold:
                return KPIHealth.GREEN
            if value <= red_threshold:
                return KPIHealth.YELLOW
            return KPIHealth.RED
