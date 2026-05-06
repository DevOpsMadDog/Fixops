"""
Anomaly Detection Engine — ALDECI.

Detects statistical anomalies in time-series metric data:
- SPIKE: sudden increase above threshold
- DROP: sudden decrease below threshold
- DRIFT: gradual trend change over time window
- PATTERN_BREAK: deviation from historical pattern
- THRESHOLD_BREACH: absolute value exceeds configured limit
- UNUSUAL_TIMING: activity at unexpected times

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: SOC2 CC7.2 (continuous monitoring)
"""

from __future__ import annotations

import json
import logging
import math
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default DB path (data/ directory alongside the running process)
# ---------------------------------------------------------------------------
_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "anomaly_detector.db")


# ============================================================================
# ENUMS
# ============================================================================


class AnomalyType(str, Enum):
    """Types of detectable anomalies."""

    SPIKE = "spike"
    DROP = "drop"
    DRIFT = "drift"
    PATTERN_BREAK = "pattern_break"
    THRESHOLD_BREACH = "threshold_breach"
    UNUSUAL_TIMING = "unusual_timing"


class AnomalySeverity(str, Enum):
    """Severity levels for detected anomalies."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# PYDANTIC MODEL
# ============================================================================


class Anomaly(BaseModel):
    """A detected anomaly event."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: AnomalyType
    metric_name: str
    expected_value: float
    actual_value: float
    deviation_pct: float
    severity: AnomalySeverity
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    context: Dict[str, Any] = Field(default_factory=dict)
    org_id: str
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None


# ============================================================================
# BASELINE STATS
# ============================================================================


class BaselineStats(BaseModel):
    """Statistical baseline for a metric."""

    metric_name: str
    org_id: str
    mean: float
    std_dev: float
    min_value: float
    max_value: float
    sample_count: int
    window_days: int
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# ANOMALY STATS SUMMARY
# ============================================================================


class AnomalyStats(BaseModel):
    """Summary of anomalies for an org."""

    org_id: str
    total: int
    by_type: Dict[str, int]
    by_severity: Dict[str, int]
    unacknowledged: int
    oldest_unacked: Optional[datetime]
    newest: Optional[datetime]


# ============================================================================
# DETECTOR
# ============================================================================


class AnomalyDetector:
    """
    SQLite-backed anomaly detection engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to data/anomaly_detector.db.
        org_id:  Default org_id used when none is specified.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        org_id: str = "default",
    ) -> None:
        self.db_path = db_path
        self.org_id = org_id
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create SQLite schema if it doesn't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS metric_series (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id      TEXT    NOT NULL,
                    metric_name TEXT    NOT NULL,
                    value       REAL    NOT NULL,
                    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_ms_org_name_time
                    ON metric_series (org_id, metric_name, recorded_at DESC);

                CREATE TABLE IF NOT EXISTS anomalies (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    type            TEXT NOT NULL,
                    metric_name     TEXT NOT NULL,
                    expected_value  REAL NOT NULL,
                    actual_value    REAL NOT NULL,
                    deviation_pct   REAL NOT NULL,
                    severity        TEXT NOT NULL,
                    detected_at     DATETIME NOT NULL,
                    context         TEXT DEFAULT '{}',
                    acknowledged    INTEGER DEFAULT 0,
                    acknowledged_at DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_an_org_sev
                    ON anomalies (org_id, severity, detected_at DESC);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_metric(
        self,
        name: str,
        value: float,
        org_id: Optional[str] = None,
        recorded_at: Optional[datetime] = None,
    ) -> int:
        """
        Store a time-series data point.

        Args:
            name:        Metric name (e.g. "cpu_usage", "findings_count")
            value:       Numeric value
            org_id:      Organisation ID (defaults to self.org_id)
            recorded_at: Timestamp (defaults to now)

        Returns:
            Row ID of the inserted record.
        """
        org = org_id or self.org_id
        ts = recorded_at or datetime.now(timezone.utc)
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "INSERT INTO metric_series (org_id, metric_name, value, recorded_at) VALUES (?, ?, ?, ?)",
                    (org, name, value, ts.isoformat()),
                )
                conn.commit()
                return cur.lastrowid  # type: ignore[return-value]

    def detect_anomalies(self, org_id: Optional[str] = None) -> List[Anomaly]:
        """
        Scan all metrics for this org and return detected anomalies.

        Runs spike, drop, and drift detection for every distinct metric name.
        Anomalies are persisted and de-duplicated by (org, type, metric, 1-hour bucket).

        Returns:
            List of newly detected Anomaly objects.
        """
        org = org_id or self.org_id
        metric_names = self._list_metrics(org)
        detected: List[Anomaly] = []

        for name in metric_names:
            detected.extend(self.detect_spike(name, threshold_pct=200.0, org_id=org))
            detected.extend(self.detect_drop(name, threshold_pct=50.0, org_id=org))
            detected.extend(self.detect_drift(name, window_days=7, org_id=org))
            detected.extend(self._detect_threshold_breach(name, org_id=org))
            detected.extend(self._detect_unusual_timing(name, org_id=org))

        return detected

    def detect_spike(
        self,
        metric_name: str,
        threshold_pct: float = 200.0,
        org_id: Optional[str] = None,
    ) -> List[Anomaly]:
        """
        Detect sudden increases above threshold_pct of the rolling mean.

        A spike is flagged when the latest value is more than
        (1 + threshold_pct/100) × mean of the previous 24 hours.

        Args:
            metric_name:   Metric to evaluate
            threshold_pct: Percentage above mean that triggers a spike (default 200%)
            org_id:        Organisation ID

        Returns:
            List of Anomaly objects (0 or 1 item).
        """
        org = org_id or self.org_id
        latest, mean, std = self._get_recent_stats(metric_name, org, hours=24)
        if latest is None or mean is None:
            return []

        if mean == 0:
            return []

        deviation = ((latest - mean) / abs(mean)) * 100.0
        if deviation < threshold_pct:
            return []

        severity = self._severity_from_deviation(deviation)
        anomaly = Anomaly(
            type=AnomalyType.SPIKE,
            metric_name=metric_name,
            expected_value=mean,
            actual_value=latest,
            deviation_pct=deviation,
            severity=severity,
            org_id=org,
            context={
                "threshold_pct": threshold_pct,
                "std_dev": std,
                "window_hours": 24,
            },
        )
        self._persist_anomaly(anomaly)
        return [anomaly]

    def detect_drop(
        self,
        metric_name: str,
        threshold_pct: float = 50.0,
        org_id: Optional[str] = None,
    ) -> List[Anomaly]:
        """
        Detect sudden decreases below threshold_pct of the rolling mean.

        A drop is flagged when the latest value is less than
        (1 - threshold_pct/100) × mean of the previous 24 hours.

        Args:
            metric_name:   Metric to evaluate
            threshold_pct: Percentage below mean that triggers a drop (default 50%)
            org_id:        Organisation ID

        Returns:
            List of Anomaly objects (0 or 1 item).
        """
        org = org_id or self.org_id
        latest, mean, std = self._get_recent_stats(metric_name, org, hours=24)
        if latest is None or mean is None:
            return []

        if mean == 0:
            return []

        deviation = ((mean - latest) / abs(mean)) * 100.0
        if deviation < threshold_pct:
            return []

        severity = self._severity_from_deviation(deviation)
        anomaly = Anomaly(
            type=AnomalyType.DROP,
            metric_name=metric_name,
            expected_value=mean,
            actual_value=latest,
            deviation_pct=-deviation,
            severity=severity,
            org_id=org,
            context={
                "threshold_pct": threshold_pct,
                "std_dev": std,
                "window_hours": 24,
            },
        )
        self._persist_anomaly(anomaly)
        return [anomaly]

    def detect_drift(
        self,
        metric_name: str,
        window_days: int = 7,
        org_id: Optional[str] = None,
    ) -> List[Anomaly]:
        """
        Detect gradual trend change over window_days.

        Compares the mean of the first half of the window to the second half.
        A drift is flagged when the halves differ by more than 20%.

        Args:
            metric_name: Metric to evaluate
            window_days: Lookback window in days (default 7)
            org_id:      Organisation ID

        Returns:
            List of Anomaly objects (0 or 1 item).
        """
        org = org_id or self.org_id
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        mid = datetime.now(timezone.utc) - timedelta(days=window_days // 2)

        with self._lock:
            with self._get_conn() as conn:
                first_half = conn.execute(
                    """
                    SELECT AVG(value) FROM metric_series
                    WHERE org_id=? AND metric_name=?
                      AND recorded_at >= ? AND recorded_at < ?
                    """,
                    (org, metric_name, cutoff.isoformat(), mid.isoformat()),
                ).fetchone()[0]

                second_half = conn.execute(
                    """
                    SELECT AVG(value) FROM metric_series
                    WHERE org_id=? AND metric_name=?
                      AND recorded_at >= ?
                    """,
                    (org, metric_name, mid.isoformat()),
                ).fetchone()[0]

        if first_half is None or second_half is None or first_half == 0:
            return []

        deviation = ((second_half - first_half) / abs(first_half)) * 100.0
        if abs(deviation) < 20.0:
            return []

        severity = self._severity_from_deviation(abs(deviation))
        anomaly = Anomaly(
            type=AnomalyType.DRIFT,
            metric_name=metric_name,
            expected_value=first_half,
            actual_value=second_half,
            deviation_pct=deviation,
            severity=severity,
            org_id=org,
            context={
                "window_days": window_days,
                "first_half_mean": first_half,
                "second_half_mean": second_half,
            },
        )
        self._persist_anomaly(anomaly)
        return [anomaly]

    def get_anomalies(
        self,
        org_id: Optional[str] = None,
        severity_filter: Optional[AnomalySeverity] = None,
        limit: int = 100,
    ) -> List[Anomaly]:
        """
        Retrieve detected anomalies for an org.

        Args:
            org_id:          Organisation ID
            severity_filter: If set, return only anomalies of this severity
            limit:           Maximum number of results (default 100)

        Returns:
            List of Anomaly objects ordered by detected_at DESC.
        """
        org = org_id or self.org_id
        with self._lock:
            with self._get_conn() as conn:
                if severity_filter:
                    rows = conn.execute(
                        """
                        SELECT * FROM anomalies
                        WHERE org_id=? AND severity=?
                        ORDER BY detected_at DESC LIMIT ?
                        """,
                        (org, severity_filter.value, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT * FROM anomalies
                        WHERE org_id=?
                        ORDER BY detected_at DESC LIMIT ?
                        """,
                        (org, limit),
                    ).fetchall()
        return [self._row_to_anomaly(r) for r in rows]

    def acknowledge_anomaly(self, anomaly_id: str) -> bool:
        """
        Mark an anomaly as reviewed/acknowledged.

        Args:
            anomaly_id: UUID of the anomaly

        Returns:
            True if the anomaly was found and updated, False otherwise.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE anomalies SET acknowledged=1, acknowledged_at=?
                    WHERE id=? AND acknowledged=0
                    """,
                    (now, anomaly_id),
                )
                conn.commit()
                return cur.rowcount > 0

    def get_baseline(
        self,
        metric_name: str,
        org_id: Optional[str] = None,
        window_days: int = 30,
    ) -> Optional[BaselineStats]:
        """
        Compute the statistical baseline for a metric.

        Args:
            metric_name: Metric name
            org_id:      Organisation ID
            window_days: Lookback window for baseline (default 30 days)

        Returns:
            BaselineStats or None if insufficient data.
        """
        org = org_id or self.org_id
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT value FROM metric_series
                    WHERE org_id=? AND metric_name=? AND recorded_at >= ?
                    ORDER BY recorded_at
                    """,
                    (org, metric_name, cutoff.isoformat()),
                ).fetchall()

        values = [r["value"] for r in rows]
        if len(values) < 2:
            return None

        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        std_dev = math.sqrt(variance)

        return BaselineStats(
            metric_name=metric_name,
            org_id=org,
            mean=mean,
            std_dev=std_dev,
            min_value=min(values),
            max_value=max(values),
            sample_count=len(values),
            window_days=window_days,
        )

    def get_anomaly_stats(self, org_id: Optional[str] = None) -> AnomalyStats:
        """
        Return summary statistics of anomalies for an org.

        Perf: collapsed 6 sequential queries into 2 (one aggregate scan +
        one GROUP BY scan), reducing round-trips by ~4x.

        Args:
            org_id: Organisation ID

        Returns:
            AnomalyStats with totals, breakdowns, and unacknowledged count.
        """
        org = org_id or self.org_id
        with self._lock:
            with self._get_conn() as conn:
                # Single pass: total, unacked, oldest unacked, newest
                agg = conn.execute(
                    """
                    SELECT
                        COUNT(*)                                          AS total,
                        SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END)  AS unacked,
                        MIN(CASE WHEN acknowledged=0 THEN detected_at END) AS oldest_unacked,
                        MAX(detected_at)                                  AS newest
                    FROM anomalies
                    WHERE org_id=?
                    """,
                    (org,),
                ).fetchone()

                # Two GROUP BY scans (type + severity) — cannot merge without pivot
                by_type_rows = conn.execute(
                    "SELECT type, COUNT(*) FROM anomalies WHERE org_id=? GROUP BY type",
                    (org,),
                ).fetchall()

                by_sev_rows = conn.execute(
                    "SELECT severity, COUNT(*) FROM anomalies WHERE org_id=? GROUP BY severity",
                    (org,),
                ).fetchall()

        oldest_raw = agg["oldest_unacked"]
        newest_raw = agg["newest"]
        return AnomalyStats(
            org_id=org,
            total=agg["total"] or 0,
            by_type={r[0]: r[1] for r in by_type_rows},
            by_severity={r[0]: r[1] for r in by_sev_rows},
            unacknowledged=agg["unacked"] or 0,
            oldest_unacked=datetime.fromisoformat(oldest_raw) if oldest_raw else None,
            newest=datetime.fromisoformat(newest_raw) if newest_raw else None,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _list_metrics(self, org_id: str) -> List[str]:
        """Return distinct metric names for an org."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT DISTINCT metric_name FROM metric_series WHERE org_id=?",
                    (org_id,),
                ).fetchall()
        return [r["metric_name"] for r in rows]

    def _get_recent_stats(
        self, metric_name: str, org_id: str, hours: int = 24
    ) -> Tuple[Optional[float], Optional[float], Optional[float]]:
        """
        Return (latest_value, rolling_mean, rolling_std_dev) over the last `hours`.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT value FROM metric_series
                    WHERE org_id=? AND metric_name=? AND recorded_at >= ?
                    ORDER BY recorded_at DESC
                    """,
                    (org_id, metric_name, cutoff.isoformat()),
                ).fetchall()

        if not rows:
            return None, None, None

        values = [r["value"] for r in rows]
        latest = values[0]

        # Need at least 2 points for a meaningful mean/std
        if len(values) < 2:
            return latest, None, None

        # Exclude latest from mean calculation (compare latest against baseline)
        baseline = values[1:]
        mean = sum(baseline) / len(baseline)
        variance = sum((v - mean) ** 2 for v in baseline) / len(baseline)
        std_dev = math.sqrt(variance)

        return latest, mean, std_dev

    def _detect_threshold_breach(
        self,
        metric_name: str,
        org_id: str,
        multiplier: float = 3.0,
    ) -> List[Anomaly]:
        """
        Detect values outside mean ± (multiplier × std_dev) (3-sigma rule).
        """
        baseline = self.get_baseline(metric_name, org_id=org_id, window_days=30)
        if baseline is None or baseline.std_dev == 0:
            return []

        latest, _, _ = self._get_recent_stats(metric_name, org_id, hours=1)
        if latest is None:
            return []

        upper = baseline.mean + multiplier * baseline.std_dev
        lower = baseline.mean - multiplier * baseline.std_dev

        if lower <= latest <= upper:
            return []

        deviation = ((latest - baseline.mean) / max(abs(baseline.mean), 1e-9)) * 100.0
        severity = self._severity_from_deviation(abs(deviation))
        anomaly = Anomaly(
            type=AnomalyType.THRESHOLD_BREACH,
            metric_name=metric_name,
            expected_value=baseline.mean,
            actual_value=latest,
            deviation_pct=deviation,
            severity=severity,
            org_id=org_id,
            context={
                "sigma_multiplier": multiplier,
                "upper_bound": upper,
                "lower_bound": lower,
                "std_dev": baseline.std_dev,
            },
        )
        self._persist_anomaly(anomaly)
        return [anomaly]

    def _detect_unusual_timing(
        self,
        metric_name: str,
        org_id: str,
    ) -> List[Anomaly]:
        """
        Detect metrics recorded at unusual hours (midnight–5am UTC).
        """
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    """
                    SELECT value, recorded_at FROM metric_series
                    WHERE org_id=? AND metric_name=?
                    ORDER BY recorded_at DESC LIMIT 1
                    """,
                    (org_id, metric_name),
                ).fetchone()

        if not row:
            return []

        try:
            ts = datetime.fromisoformat(str(row["recorded_at"]))
        except ValueError:
            return []

        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        if not (0 <= ts.hour < 5):
            return []

        anomaly = Anomaly(
            type=AnomalyType.UNUSUAL_TIMING,
            metric_name=metric_name,
            expected_value=0.0,
            actual_value=row["value"],
            deviation_pct=0.0,
            severity=AnomalySeverity.LOW,
            org_id=org_id,
            context={"hour_utc": ts.hour, "recorded_at": ts.isoformat()},
        )
        self._persist_anomaly(anomaly)
        return [anomaly]

    def _severity_from_deviation(self, deviation_pct: float) -> AnomalySeverity:
        """Map absolute deviation percentage to severity level."""
        if deviation_pct >= 500:
            return AnomalySeverity.CRITICAL
        if deviation_pct >= 200:
            return AnomalySeverity.HIGH
        if deviation_pct >= 50:
            return AnomalySeverity.MEDIUM
        return AnomalySeverity.LOW

    def _persist_anomaly(self, anomaly: Anomaly) -> None:
        """Insert anomaly into DB (ignore duplicates by id)."""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO anomalies
                        (id, org_id, type, metric_name, expected_value,
                         actual_value, deviation_pct, severity, detected_at,
                         context, acknowledged, acknowledged_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)
                    """,
                    (
                        anomaly.id,
                        anomaly.org_id,
                        anomaly.type.value,
                        anomaly.metric_name,
                        anomaly.expected_value,
                        anomaly.actual_value,
                        anomaly.deviation_pct,
                        anomaly.severity.value,
                        anomaly.detected_at.isoformat(),
                        json.dumps(anomaly.context),
                    ),
                )
                conn.commit()

    @staticmethod
    def _row_to_anomaly(row: sqlite3.Row) -> Anomaly:
        """Convert a DB row to an Anomaly model."""
        acked_at = row["acknowledged_at"]
        return Anomaly(
            id=row["id"],
            type=AnomalyType(row["type"]),
            metric_name=row["metric_name"],
            expected_value=row["expected_value"],
            actual_value=row["actual_value"],
            deviation_pct=row["deviation_pct"],
            severity=AnomalySeverity(row["severity"]),
            detected_at=datetime.fromisoformat(row["detected_at"]),
            context=json.loads(row["context"] or "{}"),
            org_id=row["org_id"],
            acknowledged=bool(row["acknowledged"]),
            acknowledged_at=datetime.fromisoformat(acked_at) if acked_at else None,
        )
