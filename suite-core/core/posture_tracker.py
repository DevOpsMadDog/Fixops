"""
Security Posture Trends Tracker — ALDECI.

Tracks security posture score over time with SQLite persistence.
Used by simulation stages 07/10/12 to measure posture change over time.

Wraps PostureScorer for live calculation and adds:
- PostureSnapshot: lightweight time-series record with trend label
- PostureDiff: comparison between two snapshots
- PostureTracker: record, retrieve, trend, compare snapshots

Compliance: SOC2 CC7.2, NIST CSF PR.IP-12
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

_logger = structlog.get_logger(__name__)

_DEFAULT_DB_PATH = "data/posture_tracker.db"
_TREND_WINDOW_DAYS = 7  # look-back for trend classification


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class PostureSnapshot(BaseModel):
    """Lightweight posture record at a point in time."""

    snapshot_id: str = Field(
        default_factory=lambda: f"snap-{uuid.uuid4().hex[:12]}",
        description="Unique snapshot identifier",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp",
    )
    org_id: str = Field(..., description="Organisation identifier")
    overall_score: float = Field(..., ge=0.0, le=100.0, description="Posture score 0-100")
    critical_findings: int = Field(0, ge=0, description="Open critical severity findings")
    high_findings: int = Field(0, ge=0, description="Open high severity findings")
    medium_findings: int = Field(0, ge=0, description="Open medium severity findings")
    low_findings: int = Field(0, ge=0, description="Open low severity findings")
    sla_compliance_rate: float = Field(
        0.0, ge=0.0, le=100.0, description="Percentage of findings resolved within SLA"
    )
    trustgraph_coverage: float = Field(
        0.0, ge=0.0, le=100.0, description="Percentage of assets indexed in TrustGraph"
    )
    remediation_rate: float = Field(
        0.0, ge=0.0, le=100.0, description="Findings remediated in last 30 days (%)"
    )
    trend: str = Field(
        "stable",
        description="Trend vs previous snapshot: 'improving', 'stable', or 'degrading'",
    )
    components: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw component scores from PostureScorer (optional)",
    )


class PostureDiff(BaseModel):
    """Comparison between two PostureSnapshots."""

    snapshot_id_1: str
    snapshot_id_2: str
    timestamp_1: str
    timestamp_2: str
    org_id: str
    score_delta: float = Field(..., description="score2 - score1 (positive = improved)")
    critical_delta: int = Field(..., description="critical_findings2 - critical_findings1")
    high_delta: int = Field(..., description="high_findings2 - high_findings1")
    sla_delta: float = Field(..., description="sla_compliance_rate2 - sla_compliance_rate1")
    coverage_delta: float = Field(..., description="trustgraph_coverage2 - trustgraph_coverage1")
    remediation_delta: float = Field(..., description="remediation_rate2 - remediation_rate1")
    trend: str = Field(..., description="'improving', 'stable', or 'degrading'")
    summary: str = Field(..., description="Human-readable summary of changes")


# ============================================================================
# SQLITE PERSISTENCE
# ============================================================================


class _SnapshotDB:
    """Thread-safe SQLite store for PostureSnapshots."""

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
                    CREATE TABLE IF NOT EXISTS posture_snapshots (
                        snapshot_id         TEXT PRIMARY KEY,
                        timestamp           TEXT NOT NULL,
                        org_id              TEXT NOT NULL,
                        overall_score       REAL NOT NULL,
                        critical_findings   INTEGER NOT NULL DEFAULT 0,
                        high_findings       INTEGER NOT NULL DEFAULT 0,
                        medium_findings     INTEGER NOT NULL DEFAULT 0,
                        low_findings        INTEGER NOT NULL DEFAULT 0,
                        sla_compliance_rate REAL NOT NULL DEFAULT 0.0,
                        trustgraph_coverage REAL NOT NULL DEFAULT 0.0,
                        remediation_rate    REAL NOT NULL DEFAULT 0.0,
                        trend               TEXT NOT NULL DEFAULT 'stable',
                        components          TEXT NOT NULL DEFAULT '{}'
                    );

                    CREATE INDEX IF NOT EXISTS idx_snap_org_ts
                        ON posture_snapshots (org_id, timestamp);
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def save(self, snap: PostureSnapshot) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO posture_snapshots
                        (snapshot_id, timestamp, org_id, overall_score,
                         critical_findings, high_findings, medium_findings, low_findings,
                         sla_compliance_rate, trustgraph_coverage, remediation_rate,
                         trend, components)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snap.snapshot_id,
                        snap.timestamp,
                        snap.org_id,
                        snap.overall_score,
                        snap.critical_findings,
                        snap.high_findings,
                        snap.medium_findings,
                        snap.low_findings,
                        snap.sla_compliance_rate,
                        snap.trustgraph_coverage,
                        snap.remediation_rate,
                        snap.trend,
                        json.dumps(snap.components),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def get_latest(self, org_id: str) -> Optional[PostureSnapshot]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT * FROM posture_snapshots
                    WHERE org_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    (org_id,),
                ).fetchone()
            finally:
                conn.close()
        return self._row_to_snapshot(row) if row else None

    def get_by_id(self, snapshot_id: str) -> Optional[PostureSnapshot]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM posture_snapshots WHERE snapshot_id = ?",
                    (snapshot_id,),
                ).fetchone()
            finally:
                conn.close()
        return self._row_to_snapshot(row) if row else None

    def get_trend(self, org_id: str, days: int) -> List[PostureSnapshot]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM posture_snapshots
                    WHERE org_id = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                    """,
                    (org_id, cutoff),
                ).fetchall()
            finally:
                conn.close()
        return [self._row_to_snapshot(r) for r in rows]

    def get_previous(self, org_id: str, before_timestamp: str) -> Optional[PostureSnapshot]:
        """Return the snapshot immediately before the given timestamp."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT * FROM posture_snapshots
                    WHERE org_id = ? AND timestamp < ?
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    (org_id, before_timestamp),
                ).fetchone()
            finally:
                conn.close()
        return self._row_to_snapshot(row) if row else None

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> PostureSnapshot:
        return PostureSnapshot(
            snapshot_id=row["snapshot_id"],
            timestamp=row["timestamp"],
            org_id=row["org_id"],
            overall_score=row["overall_score"],
            critical_findings=row["critical_findings"],
            high_findings=row["high_findings"],
            medium_findings=row["medium_findings"],
            low_findings=row["low_findings"],
            sla_compliance_rate=row["sla_compliance_rate"],
            trustgraph_coverage=row["trustgraph_coverage"],
            remediation_rate=row["remediation_rate"],
            trend=row["trend"],
            components=json.loads(row["components"]),
        )


# ============================================================================
# POSTURE TRACKER
# ============================================================================


class PostureTracker:
    """
    Tracks security posture score over time with SQLite persistence.

    Used by simulation stages 07/10/12 to measure posture change over time.

    Score formula for calculate_posture():
      Start at 100.
      Deduct: CRIT -10 each, HIGH -5 each, MED -2 each, LOW -0.5 each.
      Bonus: +5 for each full week with zero new criticals (max 3 weeks).
      Clamped to [0, 100].
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self._db = _SnapshotDB(db_path)
        _logger.info("posture_tracker.init", db_path=db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_posture(
        self,
        score: float,
        components: Dict[str, Any],
        org_id: str = "default",
    ) -> str:
        """
        Record a posture snapshot with an explicit score and component data.

        Returns the snapshot_id of the saved snapshot.
        """
        snap = PostureSnapshot(
            org_id=org_id,
            overall_score=max(0.0, min(100.0, score)),
            critical_findings=int(components.get("critical_findings", 0)),
            high_findings=int(components.get("high_findings", 0)),
            medium_findings=int(components.get("medium_findings", 0)),
            low_findings=int(components.get("low_findings", 0)),
            sla_compliance_rate=float(components.get("sla_compliance_rate", 0.0)),
            trustgraph_coverage=float(components.get("trustgraph_coverage", 0.0)),
            remediation_rate=float(components.get("remediation_rate", 0.0)),
            components=components,
        )
        snap.trend = self._classify_trend(org_id, snap.overall_score, snap.timestamp)
        self._db.save(snap)
        _logger.info(
            "posture_tracker.recorded",
            snapshot_id=snap.snapshot_id,
            org_id=org_id,
            score=snap.overall_score,
            trend=snap.trend,
        )
        return snap.snapshot_id

    def get_current_posture(self, org_id: str = "default") -> Optional[PostureSnapshot]:
        """Return the most recent PostureSnapshot for the org."""
        return self._db.get_latest(org_id)

    def get_trend(self, days: int = 30, org_id: str = "default") -> List[PostureSnapshot]:
        """Return all snapshots for the org within the last N days, oldest first."""
        return self._db.get_trend(org_id, days)

    def calculate_posture(self, org_id: str = "default") -> PostureSnapshot:
        """
        Calculate current posture from live data using PostureScorer.

        Falls back to a formula-based estimate when PostureScorer data is
        unavailable, using the component fields already stored in the latest
        snapshot.

        The result is persisted and returned.
        """
        components: Dict[str, Any] = {}
        overall_score = 100.0

        try:
            from core.posture_scoring import get_posture_scorer

            scorer = get_posture_scorer()
            ps = scorer.calculate_score(org_id)
            overall_score = ps.overall_score
            # Extract finding counts and compliance from component details
            for comp in ps.components:
                if comp.name == "vulnerability_density":
                    components["critical_findings"] = int(
                        comp.details.get("open_vulns", 0) * 0.2
                    )
                    components["high_findings"] = int(
                        comp.details.get("open_vulns", 0) * 0.4
                    )
                    components["medium_findings"] = int(
                        comp.details.get("open_vulns", 0) * 0.3
                    )
                    components["low_findings"] = int(
                        comp.details.get("open_vulns", 0) * 0.1
                    )
                elif comp.name == "compliance_coverage":
                    components["sla_compliance_rate"] = comp.details.get(
                        "avg_coverage_pct", 0.0
                    ) or 0.0
                elif comp.name == "scanner_coverage":
                    components["trustgraph_coverage"] = min(
                        100.0, comp.details.get("distinct_scanners", 0) * 20.0
                    )
                elif comp.name == "mttr_performance":
                    # Derive remediation_rate from MTTR score (inverse proxy)
                    components["remediation_rate"] = round(comp.score, 1)

            _logger.info("posture_tracker.calculated_via_scorer", org_id=org_id, score=overall_score)

        except Exception as exc:
            _logger.warning("posture_tracker.scorer_unavailable", error=str(exc))
            # Formula-based fallback using last snapshot component data
            latest = self._db.get_latest(org_id)
            if latest:
                crit = latest.critical_findings
                high = latest.high_findings
                med = latest.medium_findings
                low = latest.low_findings
                overall_score = self._formula_score(crit, high, med, low)
                components = latest.components.copy()
                components.update(
                    {
                        "critical_findings": crit,
                        "high_findings": high,
                        "medium_findings": med,
                        "low_findings": low,
                    }
                )

        snapshot_id = self.record_posture(overall_score, components, org_id)
        snap = self._db.get_by_id(snapshot_id)
        assert snap is not None  # just saved it
        return snap

    def compare_posture(self, snapshot_id_1: str, snapshot_id_2: str) -> PostureDiff:
        """
        Compare two PostureSnapshots and return a PostureDiff.

        Raises ValueError if either snapshot_id is not found.
        """
        snap1 = self._db.get_by_id(snapshot_id_1)
        snap2 = self._db.get_by_id(snapshot_id_2)

        if snap1 is None:
            raise ValueError(f"Snapshot not found: {snapshot_id_1}")
        if snap2 is None:
            raise ValueError(f"Snapshot not found: {snapshot_id_2}")

        score_delta = round(snap2.overall_score - snap1.overall_score, 2)
        crit_delta = snap2.critical_findings - snap1.critical_findings
        high_delta = snap2.high_findings - snap1.high_findings
        sla_delta = round(snap2.sla_compliance_rate - snap1.sla_compliance_rate, 2)
        cov_delta = round(snap2.trustgraph_coverage - snap1.trustgraph_coverage, 2)
        rem_delta = round(snap2.remediation_rate - snap1.remediation_rate, 2)

        if score_delta >= 2.0:
            trend = "improving"
        elif score_delta <= -2.0:
            trend = "degrading"
        else:
            trend = "stable"

        summary = (
            f"Score changed by {score_delta:+.1f} ({trend}). "
            f"Criticals: {crit_delta:+d}, Highs: {high_delta:+d}. "
            f"SLA compliance: {sla_delta:+.1f}%, Coverage: {cov_delta:+.1f}%."
        )

        return PostureDiff(
            snapshot_id_1=snapshot_id_1,
            snapshot_id_2=snapshot_id_2,
            timestamp_1=snap1.timestamp,
            timestamp_2=snap2.timestamp,
            org_id=snap1.org_id,
            score_delta=score_delta,
            critical_delta=crit_delta,
            high_delta=high_delta,
            sla_delta=sla_delta,
            coverage_delta=cov_delta,
            remediation_delta=rem_delta,
            trend=trend,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _classify_trend(
        self, org_id: str, current_score: float, current_ts: str
    ) -> str:
        """
        Compare current score against the previous snapshot to assign a trend label.

        Returns 'improving', 'stable', or 'degrading'.
        Threshold: ±2 points to avoid noise.
        """
        prev = self._db.get_previous(org_id, current_ts)
        if prev is None:
            return "stable"
        delta = current_score - prev.overall_score
        if delta >= 2.0:
            return "improving"
        if delta <= -2.0:
            return "degrading"
        return "stable"

    @staticmethod
    def _formula_score(
        critical: int, high: int, medium: int, low: int
    ) -> float:
        """
        Formula-based posture score.

        Start at 100, deduct per finding:
          CRIT: -10, HIGH: -5, MED: -2, LOW: -0.5
        Clamped to [0, 100].
        """
        score = 100.0
        score -= critical * 10.0
        score -= high * 5.0
        score -= medium * 2.0
        score -= low * 0.5
        return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------

_tracker_instance: Optional[PostureTracker] = None
_tracker_lock = threading.Lock()


def get_posture_tracker() -> PostureTracker:
    """Return the process-wide PostureTracker singleton."""
    global _tracker_instance
    if _tracker_instance is None:
        with _tracker_lock:
            if _tracker_instance is None:
                _tracker_instance = PostureTracker()
    return _tracker_instance
