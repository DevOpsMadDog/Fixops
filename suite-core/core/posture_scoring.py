"""
Security Posture Scoring Engine — ALDECI.

Computes a single 0-100 security posture score from six weighted components:
- Vulnerability density      (25%)
- MTTR performance           (15%)
- Compliance coverage        (20%)
- Attack surface exposure    (15%)
- Finding age                (10%)
- Scanner coverage           (15%)

Stores historical scores in SQLite and supports trend queries and multi-org
comparison.

Compliance: SOC2 CC7.2 (System monitoring and reporting)
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

_DEFAULT_DB_PATH = "data/posture_scoring.db"

# ---------------------------------------------------------------------------
# Component weights — must sum to 1.0
# ---------------------------------------------------------------------------
_WEIGHTS: Dict[str, float] = {
    "vulnerability_density": 0.25,
    "mttr_performance": 0.15,
    "compliance_coverage": 0.20,
    "attack_surface_exposure": 0.15,
    "finding_age": 0.10,
    "scanner_coverage": 0.15,
}

# Baseline score returned when no data is available for a component
_BASELINE_SCORE = 50.0


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class PostureComponent(BaseModel):
    """A single component of the overall posture score."""

    name: str = Field(..., description="Component identifier (e.g. 'vulnerability_density')")
    score: float = Field(..., ge=0.0, le=100.0, description="Component score 0-100")
    weight: float = Field(..., gt=0.0, le=1.0, description="Fractional weight in overall score")
    details: Dict[str, Any] = Field(default_factory=dict, description="Supporting metrics")


class PostureScore(BaseModel):
    """Aggregate posture score for an organisation at a point in time."""

    id: str = Field(default_factory=lambda: f"ps-{uuid.uuid4().hex[:12]}")
    org_id: str = Field(..., description="Organisation identifier")
    overall_score: float = Field(..., ge=0.0, le=100.0, description="Weighted aggregate score 0-100")
    grade: str = Field(..., description="Letter grade A-F")
    components: List[PostureComponent] = Field(default_factory=list)
    calculated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp",
    )
    period: str = Field("current", description="Score period label")


# ============================================================================
# SQLITE PERSISTENCE
# ============================================================================


class _PostureDB:
    """Thin SQLite wrapper for posture score history."""

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
                    CREATE TABLE IF NOT EXISTS posture_scores (
                        id              TEXT PRIMARY KEY,
                        org_id          TEXT NOT NULL,
                        overall_score   REAL NOT NULL,
                        grade           TEXT NOT NULL,
                        components      TEXT NOT NULL DEFAULT '[]',
                        calculated_at   TEXT NOT NULL,
                        period          TEXT NOT NULL DEFAULT 'current'
                    );

                    CREATE INDEX IF NOT EXISTS idx_ps_org_ts
                        ON posture_scores (org_id, calculated_at);
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def save(self, score: PostureScore) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO posture_scores
                        (id, org_id, overall_score, grade, components, calculated_at, period)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        score.id,
                        score.org_id,
                        score.overall_score,
                        score.grade,
                        json.dumps([c.model_dump() for c in score.components]),
                        score.calculated_at,
                        score.period,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def get_latest(self, org_id: str) -> Optional[PostureScore]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT id, org_id, overall_score, grade, components, calculated_at, period
                    FROM posture_scores
                    WHERE org_id = ?
                    ORDER BY calculated_at DESC
                    LIMIT 1
                    """,
                    (org_id,),
                ).fetchone()
            finally:
                conn.close()
        return self._row_to_score(row) if row else None

    def get_history(self, org_id: str, days: int) -> List[PostureScore]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT id, org_id, overall_score, grade, components, calculated_at, period
                    FROM posture_scores
                    WHERE org_id = ? AND calculated_at >= ?
                    ORDER BY calculated_at ASC
                    """,
                    (org_id, cutoff),
                ).fetchall()
            finally:
                conn.close()
        return [self._row_to_score(r) for r in rows]

    @staticmethod
    def _row_to_score(row: sqlite3.Row) -> PostureScore:
        components_raw = json.loads(row["components"])
        components = [PostureComponent(**c) for c in components_raw]
        return PostureScore(
            id=row["id"],
            org_id=row["org_id"],
            overall_score=row["overall_score"],
            grade=row["grade"],
            components=components,
            calculated_at=row["calculated_at"],
            period=row["period"],
        )


# ============================================================================
# POSTURE SCORER
# ============================================================================


class PostureScorer:
    """
    Computes and persists security posture scores.

    Each component scorer queries its backing data store independently and
    returns a 0-100 float.  When no data is available, ``_BASELINE_SCORE``
    (50) is used so that new orgs start mid-range rather than at zero.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB_PATH,
        analytics_db: str = "data/vulnerability_analytics.db",
        attack_surface_db: str = ".fixops_data/attack_surface.db",
    ) -> None:
        self._db = _PostureDB(db_path)
        self._analytics_db = analytics_db
        self._attack_surface_db = attack_surface_db
        _logger.info("posture_scorer.init", db_path=db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def calculate_score(self, org_id: str, period: str = "current") -> PostureScore:
        """Compute a fresh weighted posture score and persist it."""
        _logger.info("posture_scorer.calculate", org_id=org_id)

        vuln_score, vuln_details = self._score_vulnerability_density(org_id)
        mttr_score, mttr_details = self._score_mttr(org_id)
        compliance_score, compliance_details = self._score_compliance(org_id)
        surface_score, surface_details = self._score_attack_surface(org_id)
        age_score, age_details = self._score_finding_age(org_id)
        scanner_score, scanner_details = self._score_scanner_coverage(org_id)

        components = [
            PostureComponent(
                name="vulnerability_density",
                score=round(vuln_score, 2),
                weight=_WEIGHTS["vulnerability_density"],
                details=vuln_details,
            ),
            PostureComponent(
                name="mttr_performance",
                score=round(mttr_score, 2),
                weight=_WEIGHTS["mttr_performance"],
                details=mttr_details,
            ),
            PostureComponent(
                name="compliance_coverage",
                score=round(compliance_score, 2),
                weight=_WEIGHTS["compliance_coverage"],
                details=compliance_details,
            ),
            PostureComponent(
                name="attack_surface_exposure",
                score=round(surface_score, 2),
                weight=_WEIGHTS["attack_surface_exposure"],
                details=surface_details,
            ),
            PostureComponent(
                name="finding_age",
                score=round(age_score, 2),
                weight=_WEIGHTS["finding_age"],
                details=age_details,
            ),
            PostureComponent(
                name="scanner_coverage",
                score=round(scanner_score, 2),
                weight=_WEIGHTS["scanner_coverage"],
                details=scanner_details,
            ),
        ]

        overall = sum(c.score * c.weight for c in components)
        overall = max(0.0, min(100.0, round(overall, 2)))

        score = PostureScore(
            org_id=org_id,
            overall_score=overall,
            grade=self._calculate_grade(overall),
            components=components,
            period=period,
        )
        self._db.save(score)
        _logger.info(
            "posture_scorer.calculated",
            org_id=org_id,
            overall=overall,
            grade=score.grade,
        )
        return score

    def get_latest_score(self, org_id: str) -> PostureScore:
        """Return the most recent persisted score, or compute one if none exists."""
        existing = self._db.get_latest(org_id)
        if existing:
            return existing
        return self.calculate_score(org_id)

    def get_score_history(self, org_id: str, days: int = 30) -> List[PostureScore]:
        """Return all scores recorded within the last ``days`` days."""
        return self._db.get_history(org_id, days)

    def get_score_trend(self, org_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Return score + date pairs suitable for chart rendering."""
        history = self.get_score_history(org_id, days)
        return [
            {
                "date": s.calculated_at[:10],  # YYYY-MM-DD
                "score": s.overall_score,
                "grade": s.grade,
            }
            for s in history
        ]

    def compare_orgs(self, org_ids: List[str]) -> List[PostureScore]:
        """Return the latest score for each org, sorted by overall_score descending."""
        scores = [self.get_latest_score(oid) for oid in org_ids]
        return sorted(scores, key=lambda s: s.overall_score, reverse=True)

    # ------------------------------------------------------------------
    # Grade helper
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_grade(score: float) -> str:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    # ------------------------------------------------------------------
    # Component scorers
    # ------------------------------------------------------------------

    def _score_vulnerability_density(self, org_id: str) -> tuple[float, Dict[str, Any]]:
        """
        Score based on open vulnerability density (open vulns per asset).

        Lower density → higher score.
        0 open vulns → 100.  High density → approaches 0.
        """
        details: Dict[str, Any] = {"open_vulns": 0, "total_assets": 0, "density": 0.0}
        try:
            analytics_path = Path(self._analytics_db)
            if not analytics_path.exists():
                return _BASELINE_SCORE, details

            conn = sqlite3.connect(str(analytics_path))
            conn.row_factory = sqlite3.Row
            try:
                # Count currently open findings for the org
                row = conn.execute(
                    """
                    SELECT COUNT(DISTINCT finding_id) AS open_count
                    FROM finding_events
                    WHERE org_id = ?
                      AND event_type = 'opened'
                      AND finding_id NOT IN (
                          SELECT DISTINCT finding_id
                          FROM finding_events
                          WHERE org_id = ? AND event_type = 'resolved'
                      )
                    """,
                    (org_id, org_id),
                ).fetchone()
                open_vulns = row["open_count"] if row else 0

                # Count assets from attack surface db as proxy for asset count
                asset_count = self._get_asset_count(org_id)
                details["open_vulns"] = open_vulns
                details["total_assets"] = asset_count

                if asset_count == 0:
                    # No assets registered — use absolute open count
                    if open_vulns == 0:
                        return 100.0, details
                    density = float(open_vulns)
                else:
                    density = open_vulns / asset_count

                details["density"] = round(density, 3)

                # Score: 0 density → 100, density ≥ 10 vulns/asset → 0
                score = max(0.0, 100.0 - (density * 10.0))
                return min(100.0, score), details
            finally:
                conn.close()
        except Exception as exc:
            _logger.warning("posture.vuln_density.error", error=str(exc))
            return _BASELINE_SCORE, details

    def _score_mttr(self, org_id: str) -> tuple[float, Dict[str, Any]]:
        """
        Score based on mean time to remediate (MTTR) in hours.

        Fast remediation → high score.  Target: ≤24 h critical, ≤168 h overall.
        """
        details: Dict[str, Any] = {"avg_mttr_hours": None, "sample_size": 0}
        try:
            analytics_path = Path(self._analytics_db)
            if not analytics_path.exists():
                return _BASELINE_SCORE, details

            conn = sqlite3.connect(str(analytics_path))
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    """
                    SELECT
                        o.finding_id,
                        o.ts AS opened_ts,
                        r.ts AS resolved_ts
                    FROM finding_events o
                    JOIN finding_events r
                        ON o.finding_id = r.finding_id
                       AND r.event_type = 'resolved'
                       AND r.org_id = o.org_id
                    WHERE o.org_id = ?
                      AND o.event_type = 'opened'
                    LIMIT 500
                    """,
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()

            if not rows:
                return _BASELINE_SCORE, details

            total_hours = 0.0
            count = 0
            for row in rows:
                try:
                    opened = datetime.fromisoformat(row["opened_ts"])
                    resolved = datetime.fromisoformat(row["resolved_ts"])
                    hours = (resolved - opened).total_seconds() / 3600
                    if hours >= 0:
                        total_hours += hours
                        count += 1
                except Exception:
                    continue

            if count == 0:
                return _BASELINE_SCORE, details

            avg_mttr = total_hours / count
            details["avg_mttr_hours"] = round(avg_mttr, 1)
            details["sample_size"] = count

            # Score: ≤24 h → 100, 720 h (30 days) → 0
            score = max(0.0, 100.0 - (avg_mttr / 7.2))
            return min(100.0, score), details

        except Exception as exc:
            _logger.warning("posture.mttr.error", error=str(exc))
            return _BASELINE_SCORE, details

    def _score_compliance(self, org_id: str) -> tuple[float, Dict[str, Any]]:
        """
        Score based on compliance coverage in the analytics engine.

        Looks for compliance-tagged metrics.  Falls back to baseline when
        no compliance data is stored.
        """
        details: Dict[str, Any] = {"frameworks_tracked": 0, "avg_coverage_pct": None}
        try:
            analytics_path = Path(self._analytics_db)
            if not analytics_path.exists():
                return _BASELINE_SCORE, details

            conn = sqlite3.connect(str(analytics_path))
            conn.row_factory = sqlite3.Row
            try:
                # Check for compliance metrics stored in analytics engine
                row = conn.execute(
                    """
                    SELECT AVG(value) AS avg_val, COUNT(*) AS cnt
                    FROM metrics
                    WHERE org_id = ?
                      AND metric_name LIKE '%compliance%'
                    """,
                    (org_id,),
                ).fetchone()
            except Exception:
                # metrics table may not exist in analytics db
                row = None
            finally:
                conn.close()

            if row and row["cnt"] and row["avg_val"] is not None:
                avg_pct = float(row["avg_val"])
                details["frameworks_tracked"] = row["cnt"]
                details["avg_coverage_pct"] = round(avg_pct, 1)
                # Assume values stored as 0-100 percentage
                score = max(0.0, min(100.0, avg_pct))
                return score, details

            return _BASELINE_SCORE, details
        except Exception as exc:
            _logger.warning("posture.compliance.error", error=str(exc))
            return _BASELINE_SCORE, details

    def _score_attack_surface(self, org_id: str) -> tuple[float, Dict[str, Any]]:
        """
        Score based on external asset exposure.

        Fewer external assets with vulnerabilities → higher score.
        No external assets → 100.
        """
        details: Dict[str, Any] = {
            "total_assets": 0,
            "external_assets": 0,
            "exposure_ratio": 0.0,
        }
        try:
            surface_path = Path(self._attack_surface_db)
            if not surface_path.exists():
                return _BASELINE_SCORE, details

            conn = sqlite3.connect(str(surface_path))
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM assets WHERE org_id = ?",
                    (org_id,),
                ).fetchone()
                total = row["cnt"] if row else 0

                ext_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM assets WHERE org_id = ? AND exposure_level = 'external'",
                    (org_id,),
                ).fetchone()
                external = ext_row["cnt"] if ext_row else 0
            finally:
                conn.close()

            details["total_assets"] = total
            details["external_assets"] = external

            if total == 0:
                return _BASELINE_SCORE, details

            exposure_ratio = external / total
            details["exposure_ratio"] = round(exposure_ratio, 3)

            # Score: 0% external → 100, 100% external → 0
            score = 100.0 - (exposure_ratio * 100.0)
            return max(0.0, min(100.0, score)), details

        except Exception as exc:
            _logger.warning("posture.attack_surface.error", error=str(exc))
            return _BASELINE_SCORE, details

    def _score_finding_age(self, org_id: str) -> tuple[float, Dict[str, Any]]:
        """
        Score based on age of unresolved findings.

        Findings open longer than 30 days → penalise.
        All findings fresh → 100.
        """
        details: Dict[str, Any] = {
            "open_findings": 0,
            "old_findings_pct": 0.0,
            "avg_age_days": None,
        }
        try:
            analytics_path = Path(self._analytics_db)
            if not analytics_path.exists():
                return _BASELINE_SCORE, details

            now = datetime.now(timezone.utc)
            threshold = (now - timedelta(days=30)).isoformat()

            conn = sqlite3.connect(str(analytics_path))
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    """
                    SELECT finding_id, ts
                    FROM finding_events
                    WHERE org_id = ?
                      AND event_type = 'opened'
                      AND finding_id NOT IN (
                          SELECT DISTINCT finding_id
                          FROM finding_events
                          WHERE org_id = ? AND event_type = 'resolved'
                      )
                    """,
                    (org_id, org_id),
                ).fetchall()
            finally:
                conn.close()

            total = len(rows)
            if total == 0:
                return 100.0, details

            old_count = 0
            total_age_days = 0.0
            for row in rows:
                try:
                    opened = datetime.fromisoformat(row["ts"])
                    age_days = (now - opened).total_seconds() / 86400
                    total_age_days += age_days
                    if row["ts"] < threshold:
                        old_count += 1
                except Exception:
                    continue

            old_pct = (old_count / total) * 100.0 if total > 0 else 0.0
            avg_age = total_age_days / total if total > 0 else 0.0

            details["open_findings"] = total
            details["old_findings_pct"] = round(old_pct, 1)
            details["avg_age_days"] = round(avg_age, 1)

            # Score: 0% old → 100, 100% old → 0
            score = 100.0 - old_pct
            return max(0.0, min(100.0, score)), details

        except Exception as exc:
            _logger.warning("posture.finding_age.error", error=str(exc))
            return _BASELINE_SCORE, details

    def _score_scanner_coverage(self, org_id: str) -> tuple[float, Dict[str, Any]]:
        """
        Score based on variety of active scanners.

        More distinct scanner types active in last 30 days → higher score.
        Target: ≥5 distinct scanners = 100.
        """
        details: Dict[str, Any] = {"distinct_scanners": 0, "scanner_names": []}
        try:
            analytics_path = Path(self._analytics_db)
            if not analytics_path.exists():
                return _BASELINE_SCORE, details

            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

            conn = sqlite3.connect(str(analytics_path))
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    """
                    SELECT DISTINCT scanner
                    FROM finding_events
                    WHERE org_id = ? AND ts >= ?
                      AND scanner != 'unknown'
                    """,
                    (org_id, cutoff),
                ).fetchall()
            finally:
                conn.close()

            scanners = [r["scanner"] for r in rows]
            count = len(scanners)
            details["distinct_scanners"] = count
            details["scanner_names"] = scanners

            # 5+ scanners → 100; linear scale below that
            score = min(100.0, (count / 5.0) * 100.0)
            return score, details

        except Exception as exc:
            _logger.warning("posture.scanner_coverage.error", error=str(exc))
            return _BASELINE_SCORE, details

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_asset_count(self, org_id: str) -> int:
        """Return total asset count from attack surface db."""
        try:
            surface_path = Path(self._attack_surface_db)
            if not surface_path.exists():
                return 0
            conn = sqlite3.connect(str(surface_path))
            try:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM assets WHERE org_id = ?",
                    (org_id,),
                ).fetchone()
                return row[0] if row else 0
            finally:
                conn.close()
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------

_scorer_instance: Optional[PostureScorer] = None
_scorer_lock = threading.Lock()


def get_posture_scorer() -> PostureScorer:
    """Return the process-wide PostureScorer singleton."""
    global _scorer_instance
    if _scorer_instance is None:
        with _scorer_lock:
            if _scorer_instance is None:
                _scorer_instance = PostureScorer()
    return _scorer_instance
