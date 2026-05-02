"""
Security Scorecard Engine — ALDECI.

Multi-dimensional security scoring for teams, assets, projects, vendors, and
services.  Computes weighted overall scores, assigns A-F grades, records trends,
and supports industry benchmarking.

Multi-tenant via org_id.  Thread-safe via RLock.  SQLite WAL for concurrency.

Dimensions (equal 0.125 weight each, 8 total = 1.0):
  vulnerability_hygiene, patch_compliance, security_training, access_control,
  incident_response, threat_awareness, code_security, configuration_hardening
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_scorecard_engine.db"
)

_VALID_ENTITY_TYPES = {"team", "asset", "project", "vendor", "service"}
_VALID_DIMENSIONS = {
    "vulnerability_hygiene",
    "patch_compliance",
    "security_training",
    "access_control",
    "incident_response",
    "threat_awareness",
    "code_security",
    "configuration_hardening",
}
_DEFAULT_WEIGHT = 0.125
_GRADE_THRESHOLDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def _score_to_grade(score: float) -> str:
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


class SecurityScorecardEngine:
    """SQLite WAL-backed security scorecard engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: scorecards, scorecard_dimensions, scorecard_trends, scorecard_benchmarks.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scorecards (
                    scorecard_id    TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    entity_type     TEXT NOT NULL DEFAULT 'team',
                    entity_id       TEXT NOT NULL,
                    entity_name     TEXT NOT NULL DEFAULT '',
                    period_label    TEXT NOT NULL DEFAULT '',
                    overall_score   REAL NOT NULL DEFAULT 0.0,
                    grade           TEXT NOT NULL DEFAULT 'F',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sc_org
                    ON scorecards (org_id, entity_type, period_label);

                CREATE TABLE IF NOT EXISTS scorecard_dimensions (
                    dim_id          TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    scorecard_id    TEXT NOT NULL
                        REFERENCES scorecards(scorecard_id) ON DELETE CASCADE,
                    dimension       TEXT NOT NULL,
                    score           REAL NOT NULL DEFAULT 0.0,
                    weight          REAL NOT NULL DEFAULT 0.125,
                    evidence        TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dim_scorecard
                    ON scorecard_dimensions (scorecard_id);

                CREATE TABLE IF NOT EXISTS scorecard_trends (
                    trend_id        TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    entity_id       TEXT NOT NULL,
                    entity_type     TEXT NOT NULL,
                    period_label    TEXT NOT NULL DEFAULT '',
                    overall_score   REAL NOT NULL DEFAULT 0.0,
                    recorded_at     DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_trend_entity
                    ON scorecard_trends (org_id, entity_id, entity_type, recorded_at);

                CREATE TABLE IF NOT EXISTS scorecard_benchmarks (
                    bench_id            TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    industry            TEXT NOT NULL,
                    entity_type         TEXT NOT NULL,
                    avg_score           REAL NOT NULL DEFAULT 0.0,
                    top_quartile_score  REAL NOT NULL DEFAULT 0.0,
                    updated_at          DATETIME NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_bench_unique
                    ON scorecard_benchmarks (org_id, industry, entity_type);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Scorecards
    # ------------------------------------------------------------------

    def create_scorecard(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a scorecard with dimensions.

        Calculates weighted overall_score from dimension scores, assigns A-F grade,
        and saves a trend record automatically.

        data must include:
          entity_id, entity_type, entity_name, period_label
          dimensions: list of {dimension, score, weight (opt), evidence (opt)}
        """
        scorecard_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        entity_type = data.get("entity_type", "team")
        if entity_type not in _VALID_ENTITY_TYPES:
            entity_type = "team"

        # Build dimension records and compute weighted score
        raw_dims = data.get("dimensions", [])
        dim_records: List[Dict[str, Any]] = []
        weighted_sum = 0.0
        total_weight = 0.0

        for d in raw_dims:
            dim_name = d.get("dimension", "")
            if dim_name not in _VALID_DIMENSIONS:
                continue
            score = float(d.get("score", 0.0))
            score = max(0.0, min(100.0, score))
            weight = float(d.get("weight", _DEFAULT_WEIGHT))
            evidence = d.get("evidence", "")
            dim_records.append({
                "dim_id": str(uuid.uuid4()),
                "org_id": org_id,
                "scorecard_id": scorecard_id,
                "dimension": dim_name,
                "score": score,
                "weight": weight,
                "evidence": evidence,
                "created_at": now,
            })
            weighted_sum += score * weight
            total_weight += weight

        overall_score = round(weighted_sum / total_weight, 2) if total_weight > 0 else 0.0
        overall_score = max(0.0, min(100.0, overall_score))
        grade = _score_to_grade(overall_score)

        scorecard = {
            "scorecard_id": scorecard_id,
            "org_id": org_id,
            "entity_type": entity_type,
            "entity_id": data["entity_id"],
            "entity_name": data.get("entity_name", ""),
            "period_label": data.get("period_label", ""),
            "overall_score": overall_score,
            "grade": grade,
            "created_at": now,
        }

        trend = {
            "trend_id": str(uuid.uuid4()),
            "org_id": org_id,
            "entity_id": data["entity_id"],
            "entity_type": entity_type,
            "period_label": data.get("period_label", ""),
            "overall_score": overall_score,
            "recorded_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scorecards
                       (scorecard_id, org_id, entity_type, entity_id, entity_name,
                        period_label, overall_score, grade, created_at)
                       VALUES (:scorecard_id, :org_id, :entity_type, :entity_id, :entity_name,
                               :period_label, :overall_score, :grade, :created_at)""",
                    scorecard,
                )
                for dim in dim_records:
                    conn.execute(
                        """INSERT INTO scorecard_dimensions
                           (dim_id, org_id, scorecard_id, dimension, score, weight,
                            evidence, created_at)
                           VALUES (:dim_id, :org_id, :scorecard_id, :dimension, :score,
                                   :weight, :evidence, :created_at)""",
                        dim,
                    )
                conn.execute(
                    """INSERT INTO scorecard_trends
                       (trend_id, org_id, entity_id, entity_type, period_label,
                        overall_score, recorded_at)
                       VALUES (:trend_id, :org_id, :entity_id, :entity_type, :period_label,
                               :overall_score, :recorded_at)""",
                    trend,
                )

        result = dict(scorecard)
        result["dimensions"] = dim_records
        _logger.info(
            "Created scorecard %s for %s/%s overall=%.1f grade=%s",
            scorecard_id, entity_type, data["entity_id"], overall_score, grade,
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "security_scorecard", "org_id": org_id, "source_engine": "security_scorecard"})
            except Exception:
                pass

        return result

    def list_scorecards(
        self,
        org_id: str,
        entity_type: Optional[str] = None,
        period_label: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List scorecards for an org, optionally filtered."""
        query = "SELECT * FROM scorecards WHERE org_id = ?"
        params: List[Any] = [org_id]
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if period_label:
            query += " AND period_label = ?"
            params.append(period_label)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_scorecard(self, org_id: str, scorecard_id: str) -> Optional[Dict[str, Any]]:
        """Get a scorecard by ID with dimensions embedded."""
        with self._lock:
            with self._conn() as conn:
                sc_row = conn.execute(
                    "SELECT * FROM scorecards WHERE org_id = ? AND scorecard_id = ?",
                    (org_id, scorecard_id),
                ).fetchone()
                if sc_row is None:
                    return None
                dim_rows = conn.execute(
                    "SELECT * FROM scorecard_dimensions WHERE scorecard_id = ? ORDER BY dimension",
                    (scorecard_id,),
                ).fetchall()
        result = dict(sc_row)
        result["dimensions"] = [dict(d) for d in dim_rows]
        return result

    # ------------------------------------------------------------------
    # Trends
    # ------------------------------------------------------------------

    def get_entity_trend(
        self, org_id: str, entity_id: str, entity_type: str
    ) -> List[Dict[str, Any]]:
        """Return trend records for an entity ordered by recorded_at ascending."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT * FROM scorecard_trends
                       WHERE org_id = ? AND entity_id = ? AND entity_type = ?
                       ORDER BY recorded_at ASC""",
                    (org_id, entity_id, entity_type),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Benchmarks
    # ------------------------------------------------------------------

    def set_benchmark(
        self,
        org_id: str,
        industry: str,
        entity_type: str,
        avg_score: float,
        top_quartile_score: float,
    ) -> Dict[str, Any]:
        """Upsert a benchmark for an industry/entity_type combination."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                # Check if exists
                existing = conn.execute(
                    "SELECT bench_id FROM scorecard_benchmarks WHERE org_id = ? AND industry = ? AND entity_type = ?",
                    (org_id, industry, entity_type),
                ).fetchone()
                if existing:
                    bench_id = existing["bench_id"]
                    conn.execute(
                        """UPDATE scorecard_benchmarks
                           SET avg_score = ?, top_quartile_score = ?, updated_at = ?
                           WHERE bench_id = ?""",
                        (avg_score, top_quartile_score, now, bench_id),
                    )
                else:
                    bench_id = str(uuid.uuid4())
                    conn.execute(
                        """INSERT INTO scorecard_benchmarks
                           (bench_id, org_id, industry, entity_type, avg_score,
                            top_quartile_score, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (bench_id, org_id, industry, entity_type, avg_score,
                         top_quartile_score, now),
                    )
        return {
            "bench_id": bench_id,
            "org_id": org_id,
            "industry": industry,
            "entity_type": entity_type,
            "avg_score": avg_score,
            "top_quartile_score": top_quartile_score,
            "updated_at": now,
        }

    def get_benchmarks(
        self, org_id: str, entity_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List benchmarks, optionally filtered by entity_type."""
        query = "SELECT * FROM scorecard_benchmarks WHERE org_id = ?"
        params: List[Any] = [org_id]
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        query += " ORDER BY industry, entity_type"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def compare_to_benchmark(
        self, org_id: str, scorecard_id: str
    ) -> Optional[Dict[str, Any]]:
        """Compare a scorecard to its industry benchmark.

        Returns scorecard fields + benchmark_avg + benchmark_top_quartile +
        vs_avg (difference) + percentile_estimate.
        Returns None if scorecard not found.
        """
        sc = self.get_scorecard(org_id, scorecard_id)
        if sc is None:
            return None

        with self._lock:
            with self._conn() as conn:
                bench = conn.execute(
                    """SELECT * FROM scorecard_benchmarks
                       WHERE org_id = ? AND entity_type = ?
                       ORDER BY updated_at DESC LIMIT 1""",
                    (org_id, sc["entity_type"]),
                ).fetchone()

        result = dict(sc)
        if bench:
            avg = bench["avg_score"]
            top_q = bench["top_quartile_score"]
            vs_avg = round(sc["overall_score"] - avg, 2)
            # Simple percentile estimate: linear interpolation
            if top_q > avg:
                percentile = min(
                    99,
                    int(50 + 25 * (sc["overall_score"] - avg) / (top_q - avg)),
                )
            else:
                percentile = 50
            result["benchmark_avg"] = avg
            result["benchmark_top_quartile"] = top_q
            result["vs_avg"] = vs_avg
            result["percentile_estimate"] = percentile
        else:
            result["benchmark_avg"] = None
            result["benchmark_top_quartile"] = None
            result["vs_avg"] = None
            result["percentile_estimate"] = None
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Convenience wrappers for domain-weighted scorecard API
    # ------------------------------------------------------------------

    def generate_scorecard(
        self, org_id: str, domain_scores: Dict[str, float]
    ) -> Dict[str, Any]:
        """Generate a scorecard from a 6-domain weighted score dict.

        Domain weights: identity(20%), endpoint(20%), network(15%),
        cloud(15%), data(15%), application(15%).

        domain_scores keys: identity, endpoint, network, cloud, data, application.
        Each score should be 0–100.

        Returns: scorecard dict with overall_score, grade, per-domain grades,
        and percentile_rank (static 50th for now — override via set_benchmark).
        """
        _DOMAIN_WEIGHTS: Dict[str, float] = {
            "identity": 0.20,
            "endpoint": 0.20,
            "network": 0.15,
            "cloud": 0.15,
            "data": 0.15,
            "application": 0.15,
        }

        now = datetime.now(timezone.utc).isoformat()
        str(uuid.uuid4())
        weighted_sum = 0.0
        total_weight = 0.0
        domain_details: List[Dict[str, Any]] = []

        for domain, weight in _DOMAIN_WEIGHTS.items():
            raw_score = float(domain_scores.get(domain, 0.0))
            score = max(0.0, min(100.0, raw_score))
            weighted_sum += score * weight
            total_weight += weight
            domain_details.append({
                "domain": domain,
                "score": score,
                "weight": weight,
                "grade": _score_to_grade(score),
            })

        overall_score = round(weighted_sum / total_weight, 2) if total_weight > 0 else 0.0
        overall_score = max(0.0, min(100.0, overall_score))
        _score_to_grade(overall_score)

        # Flatten domain scores for storage (map to dimension names)
        _domain_to_dim = {
            "identity": "access_control",
            "endpoint": "configuration_hardening",
            "network": "vulnerability_hygiene",
            "cloud": "threat_awareness",
            "data": "patch_compliance",
            "application": "code_security",
        }
        dimensions = []
        for d in domain_details:
            dim_name = _domain_to_dim.get(d["domain"], d["domain"])
            dimensions.append({
                "dimension": dim_name,
                "score": d["score"],
                "weight": d["weight"],
                "evidence": d["domain"],
            })

        sc_data = {
            "entity_type": "team",
            "entity_id": org_id,
            "entity_name": org_id,
            "period_label": now[:7],  # YYYY-MM
            "dimensions": dimensions,
        }
        sc = self.create_scorecard(org_id, sc_data)

        # Enrich with domain-level detail and percentile
        sc["domain_scores"] = domain_details
        sc["percentile_rank"] = 50  # Default; callers may set via compare_to_benchmark

        return sc

    def get_trend(self, org_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Return historical scorecard trend for the org over the last N days.

        Queries scorecard_trends for the org_id entity (org's own trend),
        filtered to the last `days` days.
        """
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT * FROM scorecard_trends
                       WHERE org_id = ? AND entity_id = ? AND recorded_at >= ?
                       ORDER BY recorded_at ASC""",
                    (org_id, org_id, cutoff),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_scorecard_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate stats: total, by_grade, by_entity_type, avg_overall_score, top_performers."""
        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM scorecards WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                grade_rows = conn.execute(
                    "SELECT grade, COUNT(*) as cnt FROM scorecards WHERE org_id = ? GROUP BY grade",
                    (org_id,),
                ).fetchall()

                type_rows = conn.execute(
                    "SELECT entity_type, COUNT(*) as cnt FROM scorecards WHERE org_id = ? GROUP BY entity_type",
                    (org_id,),
                ).fetchall()

                avg_row = conn.execute(
                    "SELECT AVG(overall_score) FROM scorecards WHERE org_id = ?", (org_id,)
                ).fetchone()

                top_rows = conn.execute(
                    """SELECT entity_name, overall_score, grade FROM scorecards
                       WHERE org_id = ? ORDER BY overall_score DESC LIMIT 3""",
                    (org_id,),
                ).fetchall()

        by_grade = {r["grade"]: r["cnt"] for r in grade_rows}
        by_entity_type = {r["entity_type"]: r["cnt"] for r in type_rows}
        avg_overall = round(float(avg_row[0]), 2) if avg_row[0] is not None else 0.0
        top_performers = [
            {"entity_name": r["entity_name"], "overall_score": r["overall_score"], "grade": r["grade"]}
            for r in top_rows
        ]

        return {
            "org_id": org_id,
            "total_scorecards": total,
            "by_grade": by_grade,
            "by_entity_type": by_entity_type,
            "avg_overall_score": avg_overall,
            "top_performers": top_performers,
        }
