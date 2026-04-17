"""Cyber Resilience Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Measures cyber resilience capability — ability to withstand, recover, and
adapt from cyber incidents across the 6 NIST CSF domains.

Tables:
  resilience_assessments — maturity scores per NIST CSF domain
  resilience_exercises   — tabletop/red-team/simulation exercises
  resilience_metrics     — RTO/RPO/MTTR/detection/containment/recovery KPIs

Compliance: NIST CSF 2.0, ISO 22301, NIST SP 800-160 Vol.2
"""
from __future__ import annotations

import json
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cyber_resilience_engine.db"
)

_VALID_DOMAINS = {"identify", "protect", "detect", "respond", "recover", "adapt"}
_VALID_EXERCISE_TYPES = {"tabletop", "red-team", "purple-team", "simulation", "drill", "chaos"}
_VALID_CATEGORIES = {"rto", "rpo", "mttr", "detection", "containment", "recovery"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CyberResilienceEngine:
    """SQLite WAL-backed Cyber Resilience engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/cyber_resilience_engine.db
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
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS resilience_assessments (
                        id               TEXT PRIMARY KEY,
                        org_id           TEXT NOT NULL,
                        assessment_name  TEXT NOT NULL DEFAULT '',
                        resilience_domain TEXT NOT NULL DEFAULT 'identify',
                        maturity_level   INTEGER NOT NULL DEFAULT 1,
                        max_level        INTEGER NOT NULL DEFAULT 5,
                        score            REAL NOT NULL DEFAULT 0.0,
                        evidence         TEXT NOT NULL DEFAULT '',
                        assessor         TEXT NOT NULL DEFAULT '',
                        assessment_date  TEXT NOT NULL DEFAULT '',
                        next_review      TEXT NOT NULL DEFAULT '',
                        created_at       TEXT NOT NULL DEFAULT ''
                    );

                    CREATE INDEX IF NOT EXISTS idx_cr_assessments_org
                        ON resilience_assessments (org_id, resilience_domain);

                    CREATE TABLE IF NOT EXISTS resilience_exercises (
                        id               TEXT PRIMARY KEY,
                        org_id           TEXT NOT NULL,
                        exercise_name    TEXT NOT NULL DEFAULT '',
                        exercise_type    TEXT NOT NULL DEFAULT 'tabletop',
                        scenario         TEXT NOT NULL DEFAULT '',
                        status           TEXT NOT NULL DEFAULT 'scheduled',
                        participants     INTEGER NOT NULL DEFAULT 0,
                        findings_count   INTEGER NOT NULL DEFAULT 0,
                        gaps_identified  TEXT NOT NULL DEFAULT '[]',
                        lessons_learned  TEXT NOT NULL DEFAULT '[]',
                        scheduled_date   TEXT NOT NULL DEFAULT '',
                        completed_date   TEXT NOT NULL DEFAULT '',
                        created_at       TEXT NOT NULL DEFAULT ''
                    );

                    CREATE INDEX IF NOT EXISTS idx_cr_exercises_org
                        ON resilience_exercises (org_id, exercise_type, status);

                    CREATE TABLE IF NOT EXISTS resilience_metrics (
                        id           TEXT PRIMARY KEY,
                        org_id       TEXT NOT NULL,
                        metric_name  TEXT NOT NULL DEFAULT '',
                        category     TEXT NOT NULL DEFAULT 'rto',
                        value        REAL NOT NULL DEFAULT 0.0,
                        target       REAL NOT NULL DEFAULT 0.0,
                        unit         TEXT NOT NULL DEFAULT '',
                        measured_at  TEXT NOT NULL DEFAULT '',
                        created_at   TEXT NOT NULL DEFAULT ''
                    );

                    CREATE INDEX IF NOT EXISTS idx_cr_metrics_org
                        ON resilience_metrics (org_id, category);
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        org_id: str,
        assessment_name: str,
        resilience_domain: str,
        maturity_level: int,
        max_level: int,
        evidence: str = "",
        assessor: str = "",
        next_review: str = "",
    ) -> Dict[str, Any]:
        """Create a new resilience assessment. score = maturity_level/max_level*100."""
        if resilience_domain not in _VALID_DOMAINS:
            raise ValueError(
                f"Invalid resilience_domain '{resilience_domain}'. "
                f"Must be one of {sorted(_VALID_DOMAINS)}"
            )
        if max_level <= 0:
            raise ValueError("max_level must be > 0")
        if maturity_level < 0:
            raise ValueError("maturity_level must be >= 0")

        score = (maturity_level / max_level) * 100.0
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "assessment_name": assessment_name,
            "resilience_domain": resilience_domain,
            "maturity_level": maturity_level,
            "max_level": max_level,
            "score": score,
            "evidence": evidence,
            "assessor": assessor,
            "assessment_date": now,
            "next_review": next_review,
            "created_at": now,
        }
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """INSERT INTO resilience_assessments
                       (id, org_id, assessment_name, resilience_domain, maturity_level,
                        max_level, score, evidence, assessor, assessment_date,
                        next_review, created_at)
                       VALUES (:id, :org_id, :assessment_name, :resilience_domain,
                               :maturity_level, :max_level, :score, :evidence, :assessor,
                               :assessment_date, :next_review, :created_at)""",
                    record,
                )
                conn.commit()
            finally:
                conn.close()
        return record

    def update_maturity(
        self,
        assessment_id: str,
        org_id: str,
        maturity_level: int,
        evidence: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Update maturity level and recompute score."""
        now = _now_iso()
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT * FROM resilience_assessments WHERE id = ? AND org_id = ?",
                    (assessment_id, org_id),
                ).fetchone()
                if not row:
                    return None
                max_level = row["max_level"]
                score = (maturity_level / max_level) * 100.0
                conn.execute(
                    """UPDATE resilience_assessments
                       SET maturity_level = ?, score = ?, evidence = ?, assessment_date = ?
                       WHERE id = ? AND org_id = ?""",
                    (maturity_level, score, evidence, now, assessment_id, org_id),
                )
                conn.commit()
            finally:
                conn.close()
        return self.get_assessment(assessment_id, org_id)

    def get_assessment(self, assessment_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single assessment by ID within the org."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM resilience_assessments WHERE id = ? AND org_id = ?",
                (assessment_id, org_id),
            ).fetchone()
        finally:
            conn.close()
        return self._row(row) if row else None

    def list_assessments(
        self,
        org_id: str,
        resilience_domain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assessments with optional domain filter."""
        sql = "SELECT * FROM resilience_assessments WHERE org_id = ?"
        params: List[Any] = [org_id]
        if resilience_domain:
            sql += " AND resilience_domain = ?"
            params.append(resilience_domain)
        sql += " ORDER BY created_at DESC"
        conn = self._conn()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
        return [self._row(r) for r in rows]

    def get_resilience_score(self, org_id: str) -> Dict[str, Any]:
        """Return overall score (avg of all assessments) + by_domain + maturity_distribution."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT resilience_domain, score, maturity_level FROM resilience_assessments WHERE org_id = ?",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        if not rows:
            return {
                "overall_score": 0.0,
                "by_domain": {},
                "maturity_distribution": {},
            }

        scores = [r["score"] for r in rows]
        overall_score = sum(scores) / len(scores)

        by_domain: Dict[str, Any] = {}
        for r in rows:
            domain = r["resilience_domain"]
            if domain not in by_domain:
                by_domain[domain] = {"scores": [], "avg_score": 0.0}
            by_domain[domain]["scores"].append(r["score"])
        for domain, data in by_domain.items():
            data["avg_score"] = sum(data["scores"]) / len(data["scores"])
            del data["scores"]

        maturity_distribution: Dict[str, int] = {}
        for r in rows:
            lvl = str(r["maturity_level"])
            maturity_distribution[lvl] = maturity_distribution.get(lvl, 0) + 1

        return {
            "overall_score": overall_score,
            "by_domain": by_domain,
            "maturity_distribution": maturity_distribution,
        }

    # ------------------------------------------------------------------
    # Exercises
    # ------------------------------------------------------------------

    def schedule_exercise(
        self,
        org_id: str,
        exercise_name: str,
        exercise_type: str,
        scenario: str,
        scheduled_date: str,
        participants: int = 0,
    ) -> Dict[str, Any]:
        """Schedule a resilience exercise."""
        if exercise_type not in _VALID_EXERCISE_TYPES:
            raise ValueError(
                f"Invalid exercise_type '{exercise_type}'. "
                f"Must be one of {sorted(_VALID_EXERCISE_TYPES)}"
            )
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "exercise_name": exercise_name,
            "exercise_type": exercise_type,
            "scenario": scenario,
            "status": "scheduled",
            "participants": participants,
            "findings_count": 0,
            "gaps_identified": "[]",
            "lessons_learned": "[]",
            "scheduled_date": scheduled_date,
            "completed_date": "",
            "created_at": now,
        }
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """INSERT INTO resilience_exercises
                       (id, org_id, exercise_name, exercise_type, scenario, status,
                        participants, findings_count, gaps_identified, lessons_learned,
                        scheduled_date, completed_date, created_at)
                       VALUES (:id, :org_id, :exercise_name, :exercise_type, :scenario,
                               :status, :participants, :findings_count, :gaps_identified,
                               :lessons_learned, :scheduled_date, :completed_date, :created_at)""",
                    record,
                )
                conn.commit()
            finally:
                conn.close()
        record["gaps_identified"] = []
        record["lessons_learned"] = []
        return record

    def complete_exercise(
        self,
        exercise_id: str,
        org_id: str,
        findings_count: int,
        gaps_identified: List[str],
        lessons_learned: List[str],
    ) -> Optional[Dict[str, Any]]:
        """Mark exercise as completed and record findings."""
        now = _now_iso()
        gaps_json = json.dumps(gaps_identified)
        lessons_json = json.dumps(lessons_learned)
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """UPDATE resilience_exercises
                       SET status = 'completed', completed_date = ?, findings_count = ?,
                           gaps_identified = ?, lessons_learned = ?
                       WHERE id = ? AND org_id = ?""",
                    (now, findings_count, gaps_json, lessons_json, exercise_id, org_id),
                )
                conn.commit()
                row = conn.execute(
                    "SELECT * FROM resilience_exercises WHERE id = ? AND org_id = ?",
                    (exercise_id, org_id),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        result = self._row(row)
        result["gaps_identified"] = json.loads(result.get("gaps_identified") or "[]")
        result["lessons_learned"] = json.loads(result.get("lessons_learned") or "[]")
        return result

    def get_exercise_history(
        self,
        org_id: str,
        exercise_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List exercises with optional type filter."""
        sql = "SELECT * FROM resilience_exercises WHERE org_id = ?"
        params: List[Any] = [org_id]
        if exercise_type:
            sql += " AND exercise_type = ?"
            params.append(exercise_type)
        sql += " ORDER BY created_at DESC"
        conn = self._conn()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
        results = []
        for r in rows:
            rec = self._row(r)
            rec["gaps_identified"] = json.loads(rec.get("gaps_identified") or "[]")
            rec["lessons_learned"] = json.loads(rec.get("lessons_learned") or "[]")
            results.append(rec)
        return results

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def record_metric(
        self,
        org_id: str,
        metric_name: str,
        category: str,
        value: float,
        target: float,
        unit: str = "",
    ) -> Dict[str, Any]:
        """Record a resilience metric measurement."""
        if category not in _VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{category}'. "
                f"Must be one of {sorted(_VALID_CATEGORIES)}"
            )
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "metric_name": metric_name,
            "category": category,
            "value": value,
            "target": target,
            "unit": unit,
            "measured_at": now,
            "created_at": now,
        }
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """INSERT INTO resilience_metrics
                       (id, org_id, metric_name, category, value, target, unit,
                        measured_at, created_at)
                       VALUES (:id, :org_id, :metric_name, :category, :value, :target,
                               :unit, :measured_at, :created_at)""",
                    record,
                )
                conn.commit()
            finally:
                conn.close()
        return record

    def get_metrics_summary(self, org_id: str) -> Dict[str, Any]:
        """Return per-category avg value, avg target, above/below target count."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT category, value, target FROM resilience_metrics WHERE org_id = ?",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        summary: Dict[str, Any] = {}
        for r in rows:
            cat = r["category"]
            if cat not in summary:
                summary[cat] = {"values": [], "targets": [], "above_target": 0, "below_target": 0}
            summary[cat]["values"].append(r["value"])
            summary[cat]["targets"].append(r["target"])
            if r["value"] >= r["target"]:
                summary[cat]["above_target"] += 1
            else:
                summary[cat]["below_target"] += 1

        result: Dict[str, Any] = {}
        for cat, data in summary.items():
            result[cat] = {
                "avg_value": sum(data["values"]) / len(data["values"]),
                "avg_target": sum(data["targets"]) / len(data["targets"]),
                "above_target": data["above_target"],
                "below_target": data["below_target"],
            }
        return result
