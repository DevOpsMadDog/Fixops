"""
Exposure Scorer — ALDECI organisation-level security exposure measurement.

Aggregates risk scores across all open findings to produce:
- OrgExposureScore: weighted average of open findings risk, coverage penalty,
  patch cadence, and time-to-remediate trend.
- AssetExposureScore: per-asset weighted risk accumulation.
- ExposureTrend: daily snapshot series for dashboard charts.

Score interpretation (0-100):
  80-100  Critical exposure — immediate board-level action
  60-79   High exposure    — CISO escalation required
  40-59   Medium exposure  — active remediation programme
  20-39   Low exposure     — managed, continue monitoring
  0-19    Minimal exposure — healthy security posture

Compliance: SOC2 CC9.2, NIST CSF ID.RA-5, CIS Control 18
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "exposure_scorer.db")

# Weight: open finding risk contributes 70%, remediation velocity 30%
_WEIGHT_FINDING_RISK = 0.70
_WEIGHT_VELOCITY = 0.30


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class OrgExposureScore(BaseModel):
    """Organisation-wide security exposure score."""

    org_id: str = Field("default", description="Organisation / tenant identifier")
    exposure_score: float = Field(
        ..., ge=0.0, le=100.0, description="Overall exposure 0-100"
    )
    open_findings_count: int = Field(0, description="Total open findings scored")
    weighted_risk_avg: float = Field(
        0.0, description="Weighted average composite risk of open findings"
    )
    critical_count: int = Field(0, description="Findings with score >= 80")
    high_count: int = Field(0, description="Findings with score 60-79")
    medium_count: int = Field(0, description="Findings with score 30-59")
    low_count: int = Field(0, description="Findings with score < 30")
    assets_at_risk: int = Field(0, description="Distinct assets with open findings")
    patch_velocity_score: float = Field(
        50.0,
        ge=0.0,
        le=100.0,
        description="Remediation velocity score (100=fast, 0=stalled)",
    )
    rating: str = Field("", description="Human-readable exposure rating")
    calculated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class AssetExposureScore(BaseModel):
    """Exposure score for a single asset."""

    asset_id: str
    exposure_score: float = Field(..., ge=0.0, le=100.0)
    open_findings_count: int = 0
    max_finding_score: float = 0.0
    avg_finding_score: float = 0.0
    calculated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ExposureTrend(BaseModel):
    """Daily exposure snapshot for trend charts."""

    date: str = Field(..., description="ISO date YYYY-MM-DD")
    exposure_score: float = Field(..., ge=0.0, le=100.0)
    open_findings_count: int = 0
    critical_count: int = 0


# ============================================================================
# HELPERS
# ============================================================================


def _exposure_rating(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


# ============================================================================
# EXPOSURE SCORER
# ============================================================================


class ExposureScorer:
    """Scores security exposure across the entire organisation."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB init
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS finding_scores (
                    finding_id      TEXT PRIMARY KEY,
                    asset_id        TEXT NOT NULL DEFAULT 'unknown',
                    composite_score REAL NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'open',
                    scored_at       TEXT NOT NULL,
                    resolved_at     TEXT
                );
                CREATE TABLE IF NOT EXISTS exposure_snapshots (
                    snapshot_id     TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    snapshot_date   TEXT NOT NULL,
                    exposure_score  REAL NOT NULL,
                    open_count      INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL,
                    UNIQUE (org_id, snapshot_date)
                );
                """
            )

    # ------------------------------------------------------------------
    # Ingest finding scores from RiskPrioritizer output
    # ------------------------------------------------------------------

    def ingest_scores(
        self,
        scores: List[Dict[str, Any]],
        org_id: str = "default",
    ) -> int:
        """
        Store composite risk scores for open findings.

        Each item in `scores` must have: finding_id, composite_score.
        Optionally: asset_id, status.

        Returns count of upserted rows.
        """
        now = datetime.now(timezone.utc).isoformat()
        # Batch all upserts into a single executemany — avoids N round-trips
        rows = []
        for s in scores:
            finding_id = str(s.get("finding_id") or s.get("id") or uuid.uuid4())
            composite = float(s.get("composite_score", 0.0))
            asset_id = str(s.get("asset_id") or "unknown")
            status = str(s.get("status") or "open")
            resolved_at = s.get("resolved_at")
            rows.append((finding_id, asset_id, composite, status, now, resolved_at))

        with sqlite3.connect(self._db_path) as conn:
            conn.executemany(
                """
                INSERT INTO finding_scores
                    (finding_id, asset_id, composite_score, status, scored_at, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    composite_score = excluded.composite_score,
                    asset_id        = excluded.asset_id,
                    status          = excluded.status,
                    scored_at       = excluded.scored_at,
                    resolved_at     = excluded.resolved_at
                """,
                rows,
            )
        return len(rows)

    # ------------------------------------------------------------------
    # Organisation exposure
    # ------------------------------------------------------------------

    def calculate_org_exposure(
        self, org_id: str = "default", snapshot: bool = True
    ) -> OrgExposureScore:
        """Overall org security exposure 0-100."""
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT finding_id, asset_id, composite_score
                FROM finding_scores
                WHERE status = 'open'
                """
            ).fetchall()

        if not rows:
            result = OrgExposureScore(
                org_id=org_id,
                exposure_score=0.0,
                rating="minimal",
            )
            if snapshot:
                self._save_snapshot(org_id, result)
            return result

        scores = [r[2] for r in rows]
        assets = {r[1] for r in rows}

        critical = sum(1 for s in scores if s >= 80)
        high = sum(1 for s in scores if 60 <= s < 80)
        medium = sum(1 for s in scores if 30 <= s < 60)
        low = sum(1 for s in scores if s < 30)

        # Weight critical findings more heavily — single pass over scores
        weighted_sum = 0.0
        weight_total = 0.0
        for s in scores:
            w = 2.0 if s >= 80 else 1.5 if s >= 60 else 1.0
            weighted_sum += s * w
            weight_total += w
        weighted_avg = weighted_sum / weight_total if weight_total else 0.0

        # Velocity penalty: if many criticals relative to total → slow velocity
        pct_critical = critical / len(scores) if scores else 0.0
        velocity_score = max(0.0, 100.0 - pct_critical * 100.0)

        exposure = min(
            100.0,
            _WEIGHT_FINDING_RISK * weighted_avg
            + _WEIGHT_VELOCITY * (100.0 - velocity_score),
        )
        exposure = round(exposure, 2)

        result = OrgExposureScore(
            org_id=org_id,
            exposure_score=exposure,
            open_findings_count=len(scores),
            weighted_risk_avg=round(weighted_avg, 2),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            assets_at_risk=len(assets),
            patch_velocity_score=round(velocity_score, 2),
            rating=_exposure_rating(exposure),
        )

        if snapshot:
            self._save_snapshot(org_id, result)

        return result

    def _save_snapshot(self, org_id: str, score: OrgExposureScore) -> None:
        today = datetime.now(timezone.utc).date().isoformat()
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO exposure_snapshots
                    (snapshot_id, org_id, snapshot_date, exposure_score,
                     open_count, critical_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(org_id, snapshot_date) DO UPDATE SET
                    exposure_score = excluded.exposure_score,
                    open_count     = excluded.open_count,
                    critical_count = excluded.critical_count,
                    created_at     = excluded.created_at
                """,
                (
                    str(uuid.uuid4()),
                    org_id,
                    today,
                    score.exposure_score,
                    score.open_findings_count,
                    score.critical_count,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    # ------------------------------------------------------------------
    # Asset exposure
    # ------------------------------------------------------------------

    def calculate_asset_exposure(self, asset_id: str) -> float:
        """Risk exposure score for a single asset (0-100)."""
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT composite_score FROM finding_scores
                WHERE asset_id = ? AND status = 'open'
                """,
                (asset_id,),
            ).fetchall()

        if not rows:
            return 0.0

        scores = [r[0] for r in rows]
        # Cap-aggregation: max score anchors the asset, average softens it
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        # 60% max, 40% avg — single critical finding dominates
        return round(0.60 * max_score + 0.40 * avg_score, 2)

    def get_asset_exposure(self, asset_id: str) -> AssetExposureScore:
        """Return full AssetExposureScore for a single asset."""
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT composite_score FROM finding_scores
                WHERE asset_id = ? AND status = 'open'
                """,
                (asset_id,),
            ).fetchall()

        scores = [r[0] for r in rows]
        if not scores:
            return AssetExposureScore(
                asset_id=asset_id,
                exposure_score=0.0,
            )

        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        exposure = round(0.60 * max_score + 0.40 * avg_score, 2)

        return AssetExposureScore(
            asset_id=asset_id,
            exposure_score=exposure,
            open_findings_count=len(scores),
            max_finding_score=round(max_score, 2),
            avg_finding_score=round(avg_score, 2),
        )

    # ------------------------------------------------------------------
    # Trend
    # ------------------------------------------------------------------

    def get_exposure_trend(
        self, org_id: str = "default", days: int = 30
    ) -> List[ExposureTrend]:
        """Exposure score over time (for dashboard chart)."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).date().isoformat()

        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT snapshot_date, exposure_score, open_count, critical_count
                FROM exposure_snapshots
                WHERE org_id = ? AND snapshot_date >= ?
                ORDER BY snapshot_date ASC
                """,
                (org_id, cutoff),
            ).fetchall()

        return [
            ExposureTrend(
                date=r[0],
                exposure_score=r[1],
                open_findings_count=r[2],
                critical_count=r[3],
            )
            for r in rows
        ]


# ============================================================================
# SINGLETON
# ============================================================================

_instance: Optional[ExposureScorer] = None
_instance_lock = threading.Lock()


def get_exposure_scorer(db_path: str = _DEFAULT_DB) -> ExposureScorer:
    """Return the process-wide ExposureScorer singleton (double-checked locking)."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = ExposureScorer(db_path=db_path)
    return _instance
