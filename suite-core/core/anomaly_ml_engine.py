"""
Anomaly Detection / ML Engine — ALDECI.

Behavioral analytics for threat detection:
- Behavioral Baseline: per-user/service statistical profiles
- Z-Score Detection: flag events > 3 sigma
- Isolation Forest (Simplified): lightweight 0-1 anomaly scorer
- Time-Series Analysis: spikes, drops, trends, seasonality violations
- UEBA: composite user risk score 0-100
- Alert Grouping: reduce alert fatigue via clustering
- Feedback Loop: analyst feedback adjusts thresholds

SQLite-backed, thread-safe, pure Python (math/statistics stdlib only).

Compliance: SOC2 CC7.2 (continuous monitoring), NIST 800-53 AU-6
"""

from __future__ import annotations

import json
import math
import sqlite3
import statistics
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


def _emit_event(event_type: str, payload) -> None:  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / "data" / "anomaly_ml_engine.db"
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AnomalyCategory(str, Enum):
    BEHAVIORAL = "behavioral"
    TIME_SERIES = "time_series"
    UEBA = "ueba"
    ISOLATION = "isolation"


class FeedbackLabel(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_INVESTIGATION = "needs_investigation"


class TimeSeriesPattern(str, Enum):
    SPIKE = "spike"
    DROP = "drop"
    TREND_UP = "trend_up"
    TREND_DOWN = "trend_down"
    SEASONALITY_VIOLATION = "seasonality_violation"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class BehavioralProfile(BaseModel):
    """Statistical baseline profile for a user or service."""

    entity_id: str
    entity_type: str  # "user" | "service"
    metric_name: str
    mean: float
    std_dev: float
    min_value: float
    max_value: float
    sample_count: int
    z_threshold: float = 3.0
    computed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    org_id: str = "default"


class MLAnomaly(BaseModel):
    """A detected ML/behavioral anomaly."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str
    entity_type: str
    metric_name: str
    category: AnomalyCategory
    pattern: Optional[TimeSeriesPattern] = None
    observed_value: float
    expected_value: float
    z_score: Optional[float] = None
    isolation_score: Optional[float] = None
    risk_level: RiskLevel
    description: str
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    context: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = "default"
    feedback: Optional[FeedbackLabel] = None
    feedback_at: Optional[datetime] = None


class UserRiskScore(BaseModel):
    """Composite UEBA risk score for a user."""

    user_id: str
    risk_score: float  # 0-100
    risk_level: RiskLevel
    login_anomaly_score: float
    access_pattern_score: float
    data_volume_score: float
    travel_anomaly_score: float
    contributing_anomalies: List[str]  # anomaly IDs
    computed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    org_id: str = "default"


class AlertGroup(BaseModel):
    """A cluster of related anomalies."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    label: str
    anomaly_ids: List[str]
    grouping_reason: str  # "same_user", "same_service", "temporal"
    entity_id: Optional[str] = None
    anomaly_count: int
    highest_risk: RiskLevel
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    org_id: str = "default"


class FeedbackRequest(BaseModel):
    """Analyst feedback for a detected anomaly."""

    anomaly_id: str
    label: FeedbackLabel
    analyst_id: str = "unknown"
    notes: str = ""


class TimeSeriesPoint(BaseModel):
    """A single time-series observation."""

    entity_id: str
    metric_name: str
    value: float
    recorded_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Isolation Forest (pure Python)
# ---------------------------------------------------------------------------


class _IsolationTree:
    """A single isolation tree — random binary partitioning."""

    def __init__(self, max_depth: int = 8) -> None:
        self.max_depth = max_depth
        self._split_feature: Optional[int] = None
        self._split_value: Optional[float] = None
        self._left: Optional["_IsolationTree"] = None
        self._right: Optional["_IsolationTree"] = None
        self._size: int = 0

    def fit(self, data: List[List[float]], depth: int = 0) -> None:
        """Recursively build the tree."""
        self._size = len(data)
        if depth >= self.max_depth or len(data) <= 1:
            return

        n_features = len(data[0])
        # Pick a random feature index using hash of data characteristics
        feat_idx = (len(data) * depth + int(sum(data[0]))) % n_features

        col = [row[feat_idx] for row in data]
        col_min, col_max = min(col), max(col)
        if col_min == col_max:
            return

        # Random split between min and max (deterministic: midpoint)
        split_val = (col_min + col_max) / 2.0

        self._split_feature = feat_idx
        self._split_value = split_val

        left_data = [row for row in data if row[feat_idx] < split_val]
        right_data = [row for row in data if row[feat_idx] >= split_val]

        if left_data:
            self._left = _IsolationTree(self.max_depth)
            self._left.fit(left_data, depth + 1)
        if right_data:
            self._right = _IsolationTree(self.max_depth)
            self._right.fit(right_data, depth + 1)

    def path_length(self, point: List[float], depth: int = 0) -> float:
        """Return the path length (isolation depth) for a point."""
        if (
            self._split_feature is None
            or self._left is None
            or self._right is None
        ):
            return depth + _c_factor(self._size)

        if point[self._split_feature] < self._split_value:
            return self._left.path_length(point, depth + 1)
        return self._right.path_length(point, depth + 1)


def _c_factor(n: int) -> float:
    """Average path length normalisation factor."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


class IsolationForest:
    """
    Lightweight Isolation Forest — no sklearn required.

    Trains on a list of feature vectors and scores new points 0-1
    where 1.0 == maximally anomalous.
    """

    def __init__(self, n_trees: int = 10, max_depth: int = 8) -> None:
        self.n_trees = n_trees
        self.max_depth = max_depth
        self._trees: List[_IsolationTree] = []
        self._n_samples: int = 0

    def fit(self, data: List[List[float]]) -> None:
        """Train the forest on feature vectors."""
        self._n_samples = len(data)
        self._trees = []
        for i in range(self.n_trees):
            # Sub-sample deterministically
            step = max(1, len(data) // max(1, self.n_trees))
            offset = (i * step) % len(data)
            subsample = data[offset:] + data[:offset]
            subsample = subsample[: max(2, len(data))]
            tree = _IsolationTree(self.max_depth)
            tree.fit(subsample)
            self._trees.append(tree)

    def score(self, point: List[float]) -> float:
        """
        Anomaly score for a single point.

        Returns float in [0, 1].  Score > 0.6 is typically anomalous.
        """
        if not self._trees:
            return 0.0
        avg_path = sum(t.path_length(point) for t in self._trees) / len(
            self._trees
        )
        c = _c_factor(self._n_samples)
        if c == 0:
            return 0.5
        return 2.0 ** (-avg_path / c)


# ---------------------------------------------------------------------------
# AnomalyMLEngine
# ---------------------------------------------------------------------------


class AnomalyMLEngine:
    """
    Core ML engine for behavioral anomaly detection.

    Thread-safe, SQLite-backed.

    Args:
        db_path: Path to SQLite database.
        org_id:  Default organisation ID.
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
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ts_events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id      TEXT    NOT NULL,
                    entity_id   TEXT    NOT NULL,
                    entity_type TEXT    NOT NULL DEFAULT 'unknown',
                    metric_name TEXT    NOT NULL,
                    value       REAL    NOT NULL,
                    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_ts_entity_metric
                    ON ts_events (org_id, entity_id, metric_name, recorded_at DESC);

                CREATE TABLE IF NOT EXISTS ml_anomalies (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    entity_id        TEXT NOT NULL,
                    entity_type      TEXT NOT NULL,
                    metric_name      TEXT NOT NULL,
                    category         TEXT NOT NULL,
                    pattern          TEXT,
                    observed_value   REAL NOT NULL,
                    expected_value   REAL NOT NULL,
                    z_score          REAL,
                    isolation_score  REAL,
                    risk_level       TEXT NOT NULL,
                    description      TEXT NOT NULL,
                    detected_at      DATETIME NOT NULL,
                    context          TEXT DEFAULT '{}',
                    feedback         TEXT,
                    feedback_at      DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_ml_org_entity
                    ON ml_anomalies (org_id, entity_id, detected_at DESC);

                CREATE TABLE IF NOT EXISTS feedback_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id      TEXT NOT NULL,
                    anomaly_id  TEXT NOT NULL,
                    label       TEXT NOT NULL,
                    analyst_id  TEXT NOT NULL,
                    notes       TEXT,
                    metric_name TEXT,
                    z_score     REAL,
                    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_fb_org_label
                    ON feedback_history (org_id, label, metric_name);

                CREATE TABLE IF NOT EXISTS composite_alert_groups (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    group_name         TEXT NOT NULL,
                    signal_count       INTEGER NOT NULL DEFAULT 0,
                    correlation_score  REAL NOT NULL DEFAULT 0.0,
                    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_cag_org
                    ON composite_alert_groups (org_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS composite_group_members (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id  TEXT NOT NULL,
                    signal_id TEXT NOT NULL,
                    UNIQUE(group_id, signal_id)
                );
                CREATE INDEX IF NOT EXISTS idx_cgm_group
                    ON composite_group_members (group_id);
                CREATE INDEX IF NOT EXISTS idx_cgm_signal
                    ON composite_group_members (signal_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # 1. Record event
    # ------------------------------------------------------------------

    def record_event(
        self,
        entity_id: str,
        metric_name: str,
        value: float,
        entity_type: str = "user",
        org_id: Optional[str] = None,
        recorded_at: Optional[datetime] = None,
    ) -> int:
        """
        Store a time-series observation for an entity.

        Returns the inserted row ID.
        """
        org = org_id or self.org_id
        ts = recorded_at or datetime.now(timezone.utc)
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO ts_events
                        (org_id, entity_id, entity_type, metric_name, value, recorded_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (org, entity_id, entity_type, metric_name, value, ts.isoformat()),
                )
                conn.commit()
                row_id: int = cur.lastrowid  # type: ignore[assignment]
                logger.debug(
                    "ml_engine.record_event",
                    entity_id=entity_id,
                    metric=metric_name,
                    value=value,
                    row_id=row_id,
                )
                if _get_tg_bus:
                    try:
                        bus = _get_tg_bus()
                        if bus and getattr(bus, "enabled", False):
                            bus.emit("FINDING_CREATED", {"entity_type": "anomaly_ml_engine", "org_id": "unknown", "source_engine": "anomaly_ml_engine"})
                    except Exception:
                        pass
                return row_id

    # ------------------------------------------------------------------
    # 2. Behavioral Baseline
    # ------------------------------------------------------------------

    def build_baseline(
        self,
        entity_id: str,
        metric_name: str,
        window_days: int = 30,
        z_threshold: float = 3.0,
        entity_type: str = "user",
        org_id: Optional[str] = None,
    ) -> Optional[BehavioralProfile]:
        """
        Compute statistical baseline (mean, std_dev, min, max) for an entity/metric.

        Returns None if fewer than 2 samples exist in the window.
        """
        org = org_id or self.org_id
        cutoff = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT value FROM ts_events
                    WHERE org_id=? AND entity_id=? AND metric_name=?
                      AND recorded_at >= ?
                    ORDER BY recorded_at DESC
                    """,
                    (org, entity_id, metric_name, cutoff),
                ).fetchall()

        values = [r["value"] for r in rows]
        if len(values) < 2:
            return None

        mean = statistics.mean(values)
        std_dev = statistics.pstdev(values)

        return BehavioralProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            metric_name=metric_name,
            mean=mean,
            std_dev=std_dev,
            min_value=min(values),
            max_value=max(values),
            sample_count=len(values),
            z_threshold=z_threshold,
            org_id=org,
        )

    # ------------------------------------------------------------------
    # 3. Z-Score Detection
    # ------------------------------------------------------------------

    def detect_zscore(
        self,
        entity_id: str,
        metric_name: str,
        value: float,
        window_days: int = 30,
        z_threshold: float = 3.0,
        entity_type: str = "user",
        org_id: Optional[str] = None,
    ) -> Optional[MLAnomaly]:
        """
        Compute z-score for value against the entity's baseline.

        Returns an MLAnomaly if |z_score| > z_threshold, else None.
        """
        profile = self.build_baseline(
            entity_id=entity_id,
            metric_name=metric_name,
            window_days=window_days,
            z_threshold=z_threshold,
            entity_type=entity_type,
            org_id=org_id,
        )
        if profile is None or profile.std_dev == 0:
            return None

        z = (value - profile.mean) / profile.std_dev
        if abs(z) <= z_threshold:
            return None

        risk = _zscore_to_risk(abs(z))
        anomaly = MLAnomaly(
            entity_id=entity_id,
            entity_type=entity_type,
            metric_name=metric_name,
            category=AnomalyCategory.BEHAVIORAL,
            observed_value=value,
            expected_value=profile.mean,
            z_score=z,
            risk_level=risk,
            description=(
                f"Z-score {z:.2f} exceeds threshold ±{z_threshold} "
                f"for {entity_type} '{entity_id}' metric '{metric_name}'"
            ),
            context={
                "mean": profile.mean,
                "std_dev": profile.std_dev,
                "z_threshold": z_threshold,
                "sample_count": profile.sample_count,
            },
            org_id=org_id or self.org_id,
        )
        self._persist_anomaly(anomaly)
        _emit_event("anomaly.zscore.detected", {
            "anomaly_id": anomaly.anomaly_id,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "metric_name": metric_name,
            "risk_level": anomaly.risk_level.value,
            "org_id": org_id or self.org_id,
        })
        return anomaly

    # ------------------------------------------------------------------
    # 4. Isolation Forest Scoring
    # ------------------------------------------------------------------

    def score_isolation(
        self,
        entity_id: str,
        metric_names: List[str],
        current_values: List[float],
        window_days: int = 14,
        org_id: Optional[str] = None,
    ) -> Optional[MLAnomaly]:
        """
        Score a feature vector against historical data using Isolation Forest.

        Returns MLAnomaly if score > 0.6, else None.
        """
        org = org_id or self.org_id
        cutoff = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()

        # Build training data: one vector per day (latest value per metric)
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT metric_name, value, recorded_atFROM ts_events
                    WHERE org_id=? AND entity_id=? AND metric_name IN ({})
                      AND recorded_at >= ?
                    ORDER BY recorded_at DESC
                    """.format(",".join("?" * len(metric_names))),  # nosec B608
                    (org, entity_id, *metric_names, cutoff),
                ).fetchall()

        if len(rows) < 4:
            return None

        # Group by day-bucket → one feature vector per bucket
        buckets: Dict[str, Dict[str, float]] = {}
        for row in rows:
            day = row["recorded_at"][:10]
            if day not in buckets:
                buckets[day] = {}
            buckets[day].setdefault(row["metric_name"], row["value"])

        training: List[List[float]] = []
        for bucket in buckets.values():
            vec = [bucket.get(m, 0.0) for m in metric_names]
            training.append(vec)

        if len(training) < 2:
            return None

        forest = IsolationForest(n_trees=10, max_depth=8)
        forest.fit(training)
        score = forest.score(current_values)

        if score <= 0.6:
            return None

        risk = _isolation_score_to_risk(score)
        anomaly = MLAnomaly(
            entity_id=entity_id,
            entity_type="entity",
            metric_name=",".join(metric_names),
            category=AnomalyCategory.ISOLATION,
            observed_value=score,
            expected_value=0.5,
            isolation_score=score,
            risk_level=risk,
            description=(
                f"Isolation Forest score {score:.3f} (>0.6) for entity '{entity_id}' "
                f"across metrics: {', '.join(metric_names)}"
            ),
            context={
                "metrics": metric_names,
                "current_values": current_values,
                "training_samples": len(training),
            },
            org_id=org,
        )
        self._persist_anomaly(anomaly)
        return anomaly

    # ------------------------------------------------------------------
    # 5. Time-Series Analysis
    # ------------------------------------------------------------------

    def analyze_timeseries(
        self,
        entity_id: str,
        metric_name: str,
        window_hours: int = 24,
        entity_type: str = "service",
        org_id: Optional[str] = None,
    ) -> List[MLAnomaly]:
        """
        Detect spikes, drops, trends, and seasonality violations.

        Returns a list of detected anomalies (may be empty).
        """
        org = org_id or self.org_id
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=window_hours * 7)
        ).isoformat()

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT value, recorded_at FROM ts_events
                    WHERE org_id=? AND entity_id=? AND metric_name=?
                      AND recorded_at >= ?
                    ORDER BY recorded_at ASC
                    """,
                    (org, entity_id, metric_name, cutoff),
                ).fetchall()

        if len(rows) < 4:
            return []

        values = [r["value"] for r in rows]
        anomalies: List[MLAnomaly] = []

        # Split: last window_hours vs earlier baseline
        n_recent = max(1, len(values) // 7)
        baseline_vals = values[: len(values) - n_recent]
        recent_vals = values[len(values) - n_recent :]

        if len(baseline_vals) < 2 or not recent_vals:
            return []

        baseline_mean = statistics.mean(baseline_vals)
        recent_mean = statistics.mean(recent_vals)
        latest = values[-1]

        # Spike: latest > 3x baseline mean
        if baseline_mean > 0 and latest > baseline_mean * 3.0:
            a = self._make_ts_anomaly(
                entity_id, entity_type, metric_name, org,
                TimeSeriesPattern.SPIKE, latest, baseline_mean,
                f"Spike detected: {latest:.2f} is >{3.0}x baseline mean {baseline_mean:.2f}",
            )
            anomalies.append(a)
            self._persist_anomaly(a)

        # Drop: latest < 0.2x baseline mean
        elif baseline_mean > 0 and 0 < latest < baseline_mean * 0.2:
            a = self._make_ts_anomaly(
                entity_id, entity_type, metric_name, org,
                TimeSeriesPattern.DROP, latest, baseline_mean,
                f"Drop detected: {latest:.2f} is <0.2x baseline mean {baseline_mean:.2f}",
            )
            anomalies.append(a)
            self._persist_anomaly(a)

        # Trend: sustained directional change over recent window
        if len(recent_vals) >= 3:
            diffs = [recent_vals[i + 1] - recent_vals[i] for i in range(len(recent_vals) - 1)]
            all_up = all(d > 0 for d in diffs)
            all_down = all(d < 0 for d in diffs)
            change_pct = abs(recent_mean - baseline_mean) / (baseline_mean + 1e-9) * 100

            if all_up and change_pct > 20:
                a = self._make_ts_anomaly(
                    entity_id, entity_type, metric_name, org,
                    TimeSeriesPattern.TREND_UP, recent_mean, baseline_mean,
                    f"Sustained upward trend: {change_pct:.1f}% above baseline",
                )
                anomalies.append(a)
                self._persist_anomaly(a)
            elif all_down and change_pct > 20:
                a = self._make_ts_anomaly(
                    entity_id, entity_type, metric_name, org,
                    TimeSeriesPattern.TREND_DOWN, recent_mean, baseline_mean,
                    f"Sustained downward trend: {change_pct:.1f}% below baseline",
                )
                anomalies.append(a)
                self._persist_anomaly(a)

        # Seasonality: compare same hour-of-day pattern
        seasonality_anomaly = self._check_seasonality(
            entity_id, entity_type, metric_name, org, values
        )
        if seasonality_anomaly:
            anomalies.append(seasonality_anomaly)
            self._persist_anomaly(seasonality_anomaly)

        return anomalies

    def _check_seasonality(
        self,
        entity_id: str,
        entity_type: str,
        metric_name: str,
        org: str,
        values: List[float],
    ) -> Optional[MLAnomaly]:
        """Flag off-pattern activity by comparing to population mean/std."""
        if len(values) < 6:
            return None
        hist = values[:-1]
        latest = values[-1]
        mean = statistics.mean(hist)
        std = statistics.pstdev(hist)
        if std == 0:
            return None
        z = abs(latest - mean) / std
        if z > 4.0:
            return self._make_ts_anomaly(
                entity_id, entity_type, metric_name, org,
                TimeSeriesPattern.SEASONALITY_VIOLATION, latest, mean,
                f"Seasonality violation: z={z:.2f} (threshold 4.0)",
            )
        return None

    def _make_ts_anomaly(
        self,
        entity_id: str,
        entity_type: str,
        metric_name: str,
        org: str,
        pattern: TimeSeriesPattern,
        observed: float,
        expected: float,
        description: str,
    ) -> MLAnomaly:
        risk = _change_ratio_to_risk(
            abs(observed - expected) / (abs(expected) + 1e-9)
        )
        return MLAnomaly(
            entity_id=entity_id,
            entity_type=entity_type,
            metric_name=metric_name,
            category=AnomalyCategory.TIME_SERIES,
            pattern=pattern,
            observed_value=observed,
            expected_value=expected,
            risk_level=risk,
            description=description,
            org_id=org,
        )

    # ------------------------------------------------------------------
    # 6. UEBA — User Entity Behavior Analytics
    # ------------------------------------------------------------------

    def compute_user_risk(
        self,
        user_id: str,
        org_id: Optional[str] = None,
        window_days: int = 7,
    ) -> UserRiskScore:
        """
        Compute composite UEBA risk score (0-100) for a user.

        Sub-scores:
          - login_anomaly_score   (0-25): z-score on login_count metric
          - access_pattern_score  (0-25): z-score on api_calls metric
          - data_volume_score     (0-25): z-score on data_bytes metric
          - travel_anomaly_score  (0-25): distinct geo_region count > 2 → penalised
        """
        org = org_id or self.org_id
        contributing: List[str] = []

        login_score = self._ueba_metric_score(
            user_id, "login_count", window_days, org, contributing
        )
        access_score = self._ueba_metric_score(
            user_id, "api_calls", window_days, org, contributing
        )
        data_score = self._ueba_metric_score(
            user_id, "data_bytes", window_days, org, contributing
        )
        travel_score = self._ueba_geo_score(user_id, window_days, org)

        composite = login_score + access_score + data_score + travel_score
        composite = max(0.0, min(100.0, composite))

        risk_level = _score_to_risk(composite)

        return UserRiskScore(
            user_id=user_id,
            risk_score=round(composite, 2),
            risk_level=risk_level,
            login_anomaly_score=round(login_score, 2),
            access_pattern_score=round(access_score, 2),
            data_volume_score=round(data_score, 2),
            travel_anomaly_score=round(travel_score, 2),
            contributing_anomalies=contributing,
            org_id=org,
        )

    def _ueba_metric_score(
        self,
        user_id: str,
        metric_name: str,
        window_days: int,
        org: str,
        contributing: List[str],
    ) -> float:
        """Return sub-score 0-25 for a given metric's z-score."""
        profile = self.build_baseline(
            entity_id=user_id,
            metric_name=metric_name,
            window_days=window_days,
            org_id=org,
        )
        if profile is None or profile.sample_count < 2:
            return 0.0
        if profile.std_dev == 0:
            return 0.0

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    """
                    SELECT value FROM ts_events
                    WHERE org_id=? AND entity_id=? AND metric_name=?
                      AND recorded_at >= ?
                    ORDER BY recorded_at DESC LIMIT 1
                    """,
                    (org, user_id, metric_name, cutoff),
                ).fetchone()

        if row is None:
            return 0.0

        z = abs((row["value"] - profile.mean) / profile.std_dev)
        # Map z-score to 0-25 sub-score
        if z < 2.0:
            return 0.0
        if z < 3.0:
            sub = 10.0
        elif z < 4.0:
            sub = 18.0
        else:
            sub = 25.0

        # Detect and store anomaly if z > 3
        if z >= 3.0:
            anomaly = MLAnomaly(
                entity_id=user_id,
                entity_type="user",
                metric_name=metric_name,
                category=AnomalyCategory.UEBA,
                observed_value=row["value"],
                expected_value=profile.mean,
                z_score=z,
                risk_level=_zscore_to_risk(z),
                description=f"UEBA: {metric_name} z-score {z:.2f} for user {user_id}",
                org_id=org,
            )
            self._persist_anomaly(anomaly)
            contributing.append(anomaly.id)

        return sub

    def _ueba_geo_score(
        self, user_id: str, window_days: int, org: str
    ) -> float:
        """Score 0-25 based on distinct geo_region count in window."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=window_days)
        ).isoformat()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT DISTINCT value FROM ts_events
                    WHERE org_id=? AND entity_id=? AND metric_name='geo_region'
                      AND recorded_at >= ?
                    """,
                    (org, user_id, cutoff),
                ).fetchall()

        distinct_regions = len(rows)
        if distinct_regions <= 1:
            return 0.0
        if distinct_regions == 2:
            return 5.0
        if distinct_regions == 3:
            return 15.0
        return 25.0  # impossible travel: > 3 distinct regions

    # ------------------------------------------------------------------
    # 7. Alert Grouping
    # ------------------------------------------------------------------

    def group_anomalies(
        self,
        org_id: Optional[str] = None,
        window_hours: int = 4,
    ) -> List[AlertGroup]:
        """
        Cluster recent anomalies into alert groups to reduce fatigue.

        Groups by:
          1. Same entity_id (same user/service across metrics)
          2. Same metric_name across multiple entities (service-wide issue)
          3. Temporal proximity (all within the window)
        """
        org = org_id or self.org_id
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=window_hours)
        ).isoformat()

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT id, entity_id, entity_type, metric_name, risk_level
                    FROM ml_anomalies
                    WHERE org_id=? AND detected_at >= ?
                    ORDER BY detected_at DESC
                    """,
                    (org, cutoff),
                ).fetchall()

        if not rows:
            return []

        # Group by entity_id
        by_entity: Dict[str, List[Any]] = {}
        by_metric: Dict[str, List[Any]] = {}
        for row in rows:
            by_entity.setdefault(row["entity_id"], []).append(row)
            by_metric.setdefault(row["metric_name"], []).append(row)

        groups: List[AlertGroup] = []

        for entity_id, entity_rows in by_entity.items():
            if len(entity_rows) >= 2:
                ids = [r["id"] for r in entity_rows]
                highest = _highest_risk([r["risk_level"] for r in entity_rows])
                groups.append(
                    AlertGroup(
                        label=f"Entity '{entity_id}': {len(ids)} anomalies",
                        anomaly_ids=ids,
                        grouping_reason="same_entity",
                        entity_id=entity_id,
                        anomaly_count=len(ids),
                        highest_risk=highest,
                        org_id=org,
                    )
                )

        for metric_name, metric_rows in by_metric.items():
            distinct_entities = {r["entity_id"] for r in metric_rows}
            if len(distinct_entities) >= 2:
                ids = [r["id"] for r in metric_rows]
                highest = _highest_risk([r["risk_level"] for r in metric_rows])
                groups.append(
                    AlertGroup(
                        label=f"Metric '{metric_name}' across {len(distinct_entities)} entities",
                        anomaly_ids=ids,
                        grouping_reason="same_metric",
                        anomaly_count=len(ids),
                        highest_risk=highest,
                        org_id=org,
                    )
                )

        # Temporal catch-all: remaining ungrouped anomalies
        grouped_ids: set = {aid for g in groups for aid in g.anomaly_ids}
        ungrouped = [r for r in rows if r["id"] not in grouped_ids]
        if len(ungrouped) >= 3:
            ids = [r["id"] for r in ungrouped]
            highest = _highest_risk([r["risk_level"] for r in ungrouped])
            groups.append(
                AlertGroup(
                    label=f"Temporal cluster: {len(ids)} anomalies in {window_hours}h window",
                    anomaly_ids=ids,
                    grouping_reason="temporal",
                    anomaly_count=len(ids),
                    highest_risk=highest,
                    org_id=org,
                )
            )

        return groups

    # ------------------------------------------------------------------
    # 7b. Composite Alert Grouping (GAP-052)
    # ------------------------------------------------------------------

    def group_signals_into_composite(
        self,
        org_id: str,
        signal_ids: List[str],
        group_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Manually group ≥1 anomaly signals (ml_anomalies rows) into a
        composite_alert_groups row with dedup on (group_id, signal_id).

        Only signals existing in ml_anomalies for this org are linked.
        Returns the created group dict including resolved members + score.
        """
        if not isinstance(signal_ids, list):
            raise TypeError("signal_ids must be a list of strings")
        cleaned_ids: List[str] = [str(s).strip() for s in signal_ids if str(s).strip()]
        if not cleaned_ids:
            raise ValueError("signal_ids must contain at least one signal id")

        group_id = str(uuid.uuid4())
        label = group_name or f"Composite group {group_id[:8]}"
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                # Validate signals belong to org — only keep known ones.
                placeholders = ",".join("?" * len(cleaned_ids))
                rows = conn.execute(
                    f"SELECT id, risk_level FROM ml_anomalies "  # nosec B608
                    f"WHERE org_id=? AND id IN ({placeholders})",
                    (org_id, *cleaned_ids),
                ).fetchall()
                valid_ids = [r["id"] for r in rows]
                risk_levels = [r["risk_level"] for r in rows]

                # Correlation score: share of critical/high + density factor.
                high_crit = sum(
                    1 for rl in risk_levels if rl in ("critical", "high")
                )
                base = len(valid_ids) / max(1, len(cleaned_ids))
                severity_boost = high_crit / max(1, len(valid_ids)) if valid_ids else 0.0
                correlation_score = round(
                    min(1.0, 0.5 * base + 0.5 * severity_boost), 4
                )

                conn.execute(
                    """
                    INSERT INTO composite_alert_groups
                        (id, org_id, group_name, signal_count, correlation_score, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (group_id, org_id, label, len(valid_ids), correlation_score, now),
                )

                inserted: List[str] = []
                for sid in valid_ids:
                    try:
                        cur = conn.execute(
                            "INSERT OR IGNORE INTO composite_group_members "
                            "(group_id, signal_id) VALUES (?, ?)",
                            (group_id, sid),
                        )
                        if cur.rowcount:
                            inserted.append(sid)
                    except sqlite3.IntegrityError:
                        continue
                conn.commit()

        return {
            "id": group_id,
            "org_id": org_id,
            "group_name": label,
            "signal_count": len(valid_ids),
            "correlation_score": correlation_score,
            "created_at": now,
            "member_ids": inserted,
            "skipped_unknown": [sid for sid in cleaned_ids if sid not in valid_ids],
        }

    def auto_group_by_time_window(
        self,
        org_id: str,
        window_seconds: int = 300,
    ) -> List[Dict[str, Any]]:
        """Cluster recent ml_anomalies (anomaly signals) by
        (entity_id, time-bucket of window_seconds) and create a composite
        group for any cluster with ≥3 signals. Returns list of new groups.
        """
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=window_seconds * 2)
        ).isoformat()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT id, entity_id, detected_at
                    FROM ml_anomalies
                    WHERE org_id=? AND detected_at >= ?
                    ORDER BY detected_at ASC
                    """,
                    (org_id, cutoff),
                ).fetchall()

        if not rows:
            return []

        clusters: Dict[Tuple[str, int], List[str]] = {}
        for r in rows:
            try:
                ts = datetime.fromisoformat(r["detected_at"])
            except (ValueError, TypeError):
                continue
            bucket = int(ts.timestamp() // window_seconds)
            key = (r["entity_id"], bucket)
            clusters.setdefault(key, []).append(r["id"])

        new_groups: List[Dict[str, Any]] = []
        for (entity_id, bucket), ids in clusters.items():
            if len(ids) < 3:
                continue
            group = self.group_signals_into_composite(
                org_id=org_id,
                signal_ids=ids,
                group_name=f"Auto: {entity_id} @ bucket {bucket}",
            )
            new_groups.append(group)

        return new_groups

    def list_composite_groups(
        self,
        org_id: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return recent composite_alert_groups for an org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT id, org_id, group_name, signal_count,
                           correlation_score, created_at
                    FROM composite_alert_groups
                    WHERE org_id=?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (org_id, int(limit)),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_composite_group(
        self,
        group_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Return a composite group with its member signal ids, or None."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    """
                    SELECT id, org_id, group_name, signal_count,
                           correlation_score, created_at
                    FROM composite_alert_groups
                    WHERE id=?
                    """,
                    (group_id,),
                ).fetchone()
                if row is None:
                    return None
                members = conn.execute(
                    "SELECT signal_id FROM composite_group_members WHERE group_id=?",
                    (group_id,),
                ).fetchall()
        out = dict(row)
        out["member_ids"] = [m["signal_id"] for m in members]
        return out

    def get_composite_signal_ids(self, org_id: str) -> set:
        """Return set of signal_ids that are members of any composite group
        for this org (used by security_event_correlation to dedup)."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT m.signal_id
                    FROM composite_group_members m
                    JOIN composite_alert_groups g ON g.id = m.group_id
                    WHERE g.org_id=?
                    """,
                    (org_id,),
                ).fetchall()
        return {r["signal_id"] for r in rows}

    # ------------------------------------------------------------------
    # 8. Feedback Loop
    # ------------------------------------------------------------------

    def submit_feedback(
        self,
        anomaly_id: str,
        label: FeedbackLabel,
        analyst_id: str = "unknown",
        notes: str = "",
        org_id: Optional[str] = None,
    ) -> bool:
        """
        Record analyst feedback for an anomaly.

        Stores in feedback_history for threshold adjustment analysis.
        Returns True if the anomaly was found and updated.
        """
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id, metric_name, z_score FROM ml_anomalies WHERE id=? AND org_id=?",
                    (anomaly_id, org),
                ).fetchone()
                if row is None:
                    return False

                conn.execute(
                    """
                    UPDATE ml_anomalies
                    SET feedback=?, feedback_at=?
                    WHERE id=? AND org_id=?
                    """,
                    (
                        label.value,
                        datetime.now(timezone.utc).isoformat(),
                        anomaly_id,
                        org,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO feedback_history
                        (org_id, anomaly_id, label, analyst_id, notes, metric_name, z_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        org,
                        anomaly_id,
                        label.value,
                        analyst_id,
                        notes,
                        row["metric_name"],
                        row["z_score"],
                    ),
                )
                conn.commit()
                logger.info(
                    "ml_engine.feedback_submitted",
                    anomaly_id=anomaly_id,
                    label=label.value,
                    analyst_id=analyst_id,
                )
                return True

    def get_feedback_stats(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Return aggregate feedback statistics.

        Includes false-positive rate per metric, overall label distribution,
        and recommended threshold adjustments.
        """
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT label, metric_name, z_score, COUNT(*) as cnt
                    FROM feedback_history
                    WHERE org_id=?
                    GROUP BY label, metric_name
                    """,
                    (org,),
                ).fetchall()

        total_by_label: Dict[str, int] = {}
        fp_by_metric: Dict[str, int] = {}
        tp_by_metric: Dict[str, int] = {}

        for row in rows:
            label = row["label"]
            metric = row["metric_name"] or "unknown"
            cnt = row["cnt"]
            total_by_label[label] = total_by_label.get(label, 0) + cnt
            if label == FeedbackLabel.FALSE_POSITIVE.value:
                fp_by_metric[metric] = fp_by_metric.get(metric, 0) + cnt
            elif label == FeedbackLabel.TRUE_POSITIVE.value:
                tp_by_metric[metric] = tp_by_metric.get(metric, 0) + cnt

        total_feedback = sum(total_by_label.values())
        fp_total = total_by_label.get(FeedbackLabel.FALSE_POSITIVE.value, 0)
        fp_rate = fp_total / total_feedback if total_feedback > 0 else 0.0

        # Recommend raising threshold for metrics with high FP rates
        threshold_recommendations: Dict[str, str] = {}
        for metric, fp_count in fp_by_metric.items():
            tp_count = tp_by_metric.get(metric, 0)
            total = fp_count + tp_count
            if total >= 5 and fp_count / total > 0.5:
                threshold_recommendations[metric] = "consider raising z_threshold to 4.0"

        return {
            "total_feedback": total_feedback,
            "by_label": total_by_label,
            "false_positive_rate": round(fp_rate, 3),
            "fp_by_metric": fp_by_metric,
            "tp_by_metric": tp_by_metric,
            "threshold_recommendations": threshold_recommendations,
        }

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def list_anomalies(
        self,
        org_id: Optional[str] = None,
        entity_id: Optional[str] = None,
        risk_level: Optional[RiskLevel] = None,
        limit: int = 100,
    ) -> List[MLAnomaly]:
        """Return persisted anomalies, optionally filtered."""
        org = org_id or self.org_id
        params: List[Any] = [org]
        query = "SELECT * FROM ml_anomalies WHERE org_id=?"
        if entity_id:
            query += " AND entity_id=?"
            params.append(entity_id)
        if risk_level:
            query += " AND risk_level=?"
            params.append(risk_level.value)
        query += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [self._row_to_anomaly(r) for r in rows]

    def get_anomaly(
        self, anomaly_id: str, org_id: Optional[str] = None
    ) -> Optional[MLAnomaly]:
        """Fetch a single anomaly by ID."""
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ml_anomalies WHERE id=? AND org_id=?",
                    (anomaly_id, org),
                ).fetchone()
        if row is None:
            return None
        return self._row_to_anomaly(row)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _persist_anomaly(self, anomaly: MLAnomaly) -> None:
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO ml_anomalies
                        (id, org_id, entity_id, entity_type, metric_name, category,
                         pattern, observed_value, expected_value, z_score,
                         isolation_score, risk_level, description, detected_at,
                         context, feedback, feedback_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        anomaly.id,
                        anomaly.org_id,
                        anomaly.entity_id,
                        anomaly.entity_type,
                        anomaly.metric_name,
                        anomaly.category.value,
                        anomaly.pattern.value if anomaly.pattern else None,
                        anomaly.observed_value,
                        anomaly.expected_value,
                        anomaly.z_score,
                        anomaly.isolation_score,
                        anomaly.risk_level.value,
                        anomaly.description,
                        anomaly.detected_at.isoformat(),
                        json.dumps(anomaly.context),
                        anomaly.feedback.value if anomaly.feedback else None,
                        anomaly.feedback_at.isoformat() if anomaly.feedback_at else None,
                    ),
                )
                conn.commit()

    def _row_to_anomaly(self, row: sqlite3.Row) -> MLAnomaly:
        ctx = {}
        try:
            ctx = json.loads(row["context"] or "{}")
        except (json.JSONDecodeError, TypeError):
            pass
        return MLAnomaly(
            id=row["id"],
            entity_id=row["entity_id"],
            entity_type=row["entity_type"],
            metric_name=row["metric_name"],
            category=AnomalyCategory(row["category"]),
            pattern=TimeSeriesPattern(row["pattern"]) if row["pattern"] else None,
            observed_value=row["observed_value"],
            expected_value=row["expected_value"],
            z_score=row["z_score"],
            isolation_score=row["isolation_score"],
            risk_level=RiskLevel(row["risk_level"]),
            description=row["description"],
            detected_at=datetime.fromisoformat(row["detected_at"]),
            context=ctx,
            org_id=row["org_id"],
            feedback=FeedbackLabel(row["feedback"]) if row["feedback"] else None,
            feedback_at=(
                datetime.fromisoformat(row["feedback_at"])
                if row["feedback_at"]
                else None
            ),
        )


# ---------------------------------------------------------------------------
# Risk mapping helpers
# ---------------------------------------------------------------------------


def _zscore_to_risk(z: float) -> RiskLevel:
    if z < 3.5:
        return RiskLevel.LOW
    if z < 5.0:
        return RiskLevel.MEDIUM
    if z < 7.0:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _isolation_score_to_risk(score: float) -> RiskLevel:
    if score < 0.65:
        return RiskLevel.LOW
    if score < 0.75:
        return RiskLevel.MEDIUM
    if score < 0.85:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _change_ratio_to_risk(ratio: float) -> RiskLevel:
    if ratio < 1.0:
        return RiskLevel.LOW
    if ratio < 3.0:
        return RiskLevel.MEDIUM
    if ratio < 6.0:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _score_to_risk(score: float) -> RiskLevel:
    if score < 25:
        return RiskLevel.LOW
    if score < 50:
        return RiskLevel.MEDIUM
    if score < 75:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _highest_risk(risk_levels: List[str]) -> RiskLevel:
    order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]
    level_set = {RiskLevel(r) for r in risk_levels}
    for r in order:
        if r in level_set:
            return r
    return RiskLevel.LOW
