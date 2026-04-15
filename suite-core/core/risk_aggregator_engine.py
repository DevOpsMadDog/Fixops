"""Risk Aggregator Engine — ALDECI.

Aggregates risk scores from all security engines into a unified,
composite organisational risk posture with per-entity tracking,
heatmaps, threshold enforcement, and trend analysis.

Compliance: NIST CSF ID.RA, ISO/IEC 27001 A.8, SOC 2 CC3.2
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

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "risk_aggregator.db"
)

_VALID_ENTITY_TYPES = {"asset", "user", "network", "application", "vendor"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_THRESHOLD_ACTIONS = {"alert", "escalate", "block"}


def _score_to_severity(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _score_to_grade(score: float) -> str:
    if score <= 20:
        return "A"
    if score <= 40:
        return "B"
    if score <= 60:
        return "C"
    if score <= 80:
        return "D"
    return "F"


class RiskAggregatorEngine:
    """SQLite WAL-backed Risk Aggregator engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS risk_scores (
                    score_id      TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    source_engine TEXT NOT NULL DEFAULT '',
                    entity_type   TEXT NOT NULL DEFAULT 'asset',
                    entity_id     TEXT NOT NULL DEFAULT '',
                    entity_name   TEXT NOT NULL DEFAULT '',
                    risk_score    REAL NOT NULL DEFAULT 0,
                    risk_factors  TEXT NOT NULL DEFAULT '[]',
                    severity      TEXT NOT NULL DEFAULT 'low',
                    recorded_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rs_org
                    ON risk_scores (org_id, entity_type, severity);

                CREATE INDEX IF NOT EXISTS idx_rs_entity
                    ON risk_scores (org_id, entity_id);

                CREATE TABLE IF NOT EXISTS risk_thresholds (
                    threshold_id TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    entity_type  TEXT NOT NULL DEFAULT 'asset',
                    threshold    REAL NOT NULL DEFAULT 70,
                    action       TEXT NOT NULL DEFAULT 'alert',
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rt_org
                    ON risk_thresholds (org_id, entity_type);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("risk_factors",):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    # ------------------------------------------------------------------
    # Risk Scores
    # ------------------------------------------------------------------

    def record_risk_score(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a risk score for an entity.

        Required keys: entity_id, risk_score
        Optional keys: source_engine, entity_type, entity_name, risk_factors, severity
        """
        entity_type = data.get("entity_type", "asset")
        if entity_type not in _VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of {_VALID_ENTITY_TYPES}")

        risk_score = float(data.get("risk_score", 0))
        if not (0 <= risk_score <= 100):
            raise ValueError("risk_score must be between 0 and 100")

        severity = data.get("severity") or _score_to_severity(risk_score)
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")

        risk_factors = data.get("risk_factors", [])

        score_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "score_id": score_id,
            "org_id": org_id,
            "source_engine": data.get("source_engine", ""),
            "entity_type": entity_type,
            "entity_id": data.get("entity_id", ""),
            "entity_name": data.get("entity_name", ""),
            "risk_score": risk_score,
            "risk_factors": json.dumps(risk_factors),
            "severity": severity,
            "recorded_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO risk_scores
                    (score_id, org_id, source_engine, entity_type, entity_id,
                     entity_name, risk_score, risk_factors, severity, recorded_at)
                VALUES
                    (:score_id, :org_id, :source_engine, :entity_type, :entity_id,
                     :entity_name, :risk_score, :risk_factors, :severity, :recorded_at)
                """,
                row,
            )
        result = dict(row)
        result["risk_factors"] = risk_factors
        return result

    def list_risk_scores(
        self,
        org_id: str,
        entity_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List latest risk scores, optionally filtered."""
        query = "SELECT * FROM risk_scores WHERE org_id = ?"
        params: list = [org_id]
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_entity_risk(self, org_id: str, entity_id: str) -> Dict[str, Any]:
        """Return the latest risk score and full history for an entity."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM risk_scores
                WHERE org_id = ? AND entity_id = ?
                ORDER BY recorded_at DESC
                """,
                (org_id, entity_id),
            ).fetchall()

        if not rows:
            return {"entity_id": entity_id, "latest": None, "history": []}

        history = [self._row_to_dict(r) for r in rows]
        return {
            "entity_id": entity_id,
            "entity_name": history[0].get("entity_name", ""),
            "entity_type": history[0].get("entity_type", ""),
            "latest": history[0],
            "history": history,
        }

    def get_risk_heatmap(self, org_id: str) -> Dict[str, Any]:
        """Return counts per entity_type per severity bucket."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """
                SELECT entity_type, severity, COUNT(*) AS cnt
                FROM risk_scores
                WHERE org_id = ?
                GROUP BY entity_type, severity
                """,
                (org_id,),
            ).fetchall()

        heatmap: Dict[str, Dict[str, int]] = {}
        for r in rows:
            et = r["entity_type"]
            sev = r["severity"]
            if et not in heatmap:
                heatmap[et] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            heatmap[et][sev] = r["cnt"]

        return {"org_id": org_id, "heatmap": heatmap}

    def get_top_risks(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the highest risk entities (latest score per entity)."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """
                SELECT rs.*
                FROM risk_scores rs
                INNER JOIN (
                    SELECT entity_id, MAX(recorded_at) AS max_ts
                    FROM risk_scores
                    WHERE org_id = ?
                    GROUP BY entity_id
                ) latest ON rs.entity_id = latest.entity_id
                         AND rs.recorded_at = latest.max_ts
                WHERE rs.org_id = ?
                ORDER BY rs.risk_score DESC
                LIMIT ?
                """,
                (org_id, org_id, limit),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def calculate_org_risk_score(self, org_id: str) -> Dict[str, Any]:
        """Calculate composite organisational risk score (0-100) with trend."""
        with self._lock, self._conn() as conn:
            # Latest score per entity
            latest_rows = conn.execute(
                """
                SELECT rs.entity_type, rs.risk_score, rs.recorded_at
                FROM risk_scores rs
                INNER JOIN (
                    SELECT entity_id, MAX(recorded_at) AS max_ts
                    FROM risk_scores
                    WHERE org_id = ?
                    GROUP BY entity_id
                ) latest ON rs.entity_id = latest.entity_id
                         AND rs.recorded_at = latest.max_ts
                WHERE rs.org_id = ?
                """,
                (org_id, org_id),
            ).fetchall()

            # Previous period scores (for trend)
            previous_rows = conn.execute(
                """
                SELECT AVG(risk_score) AS avg_score
                FROM risk_scores
                WHERE org_id = ?
                  AND recorded_at < (
                      SELECT MIN(recorded_at) FROM (
                          SELECT recorded_at FROM risk_scores
                          WHERE org_id = ?
                          ORDER BY recorded_at DESC
                          LIMIT (SELECT COUNT(DISTINCT entity_id) FROM risk_scores WHERE org_id = ?)
                      )
                  )
                """,
                (org_id, org_id, org_id),
            ).fetchone()

        if not latest_rows:
            return {
                "org_id": org_id,
                "org_risk_score": 0,
                "grade": "A",
                "breakdown": {},
                "trend": "stable",
                "entity_count": 0,
            }

        scores = [r["risk_score"] for r in latest_rows]
        org_score = round(sum(scores) / len(scores), 2)
        grade = _score_to_grade(org_score)

        breakdown: Dict[str, float] = {}
        type_totals: Dict[str, list] = {}
        for r in latest_rows:
            et = r["entity_type"]
            type_totals.setdefault(et, []).append(r["risk_score"])
        for et, sc_list in type_totals.items():
            breakdown[et] = round(sum(sc_list) / len(sc_list), 2)

        # Trend
        prev_avg = previous_rows["avg_score"] if previous_rows else None
        if prev_avg is None:
            trend = "stable"
        elif org_score > prev_avg + 2:
            trend = "worsening"
        elif org_score < prev_avg - 2:
            trend = "improving"
        else:
            trend = "stable"

        return {
            "org_id": org_id,
            "org_risk_score": org_score,
            "grade": grade,
            "breakdown": breakdown,
            "trend": trend,
            "entity_count": len(scores),
        }

    # ------------------------------------------------------------------
    # Risk Thresholds
    # ------------------------------------------------------------------

    def create_risk_threshold(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a risk threshold rule.

        Required keys: entity_type, threshold, action
        """
        entity_type = data.get("entity_type", "asset")
        if entity_type not in _VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of {_VALID_ENTITY_TYPES}")

        action = data.get("action", "alert")
        if action not in _VALID_THRESHOLD_ACTIONS:
            raise ValueError(f"action must be one of {_VALID_THRESHOLD_ACTIONS}")

        threshold = float(data.get("threshold", 70))
        if not (0 <= threshold <= 100):
            raise ValueError("threshold must be between 0 and 100")

        threshold_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "threshold_id": threshold_id,
            "org_id": org_id,
            "entity_type": entity_type,
            "threshold": threshold,
            "action": action,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO risk_thresholds
                    (threshold_id, org_id, entity_type, threshold, action,
                     created_at, updated_at)
                VALUES
                    (:threshold_id, :org_id, :entity_type, :threshold, :action,
                     :created_at, :updated_at)
                """,
                row,
            )
        return dict(row)

    def list_risk_thresholds(self, org_id: str) -> List[Dict[str, Any]]:
        """List all risk thresholds for an org."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM risk_thresholds WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_aggregator_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated risk statistics."""
        with self._lock, self._conn() as conn:
            entity_count = conn.execute(
                "SELECT COUNT(DISTINCT entity_id) FROM risk_scores WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            high_risk_count = conn.execute(
                """
                SELECT COUNT(DISTINCT rs.entity_id)
                FROM risk_scores rs
                INNER JOIN (
                    SELECT entity_id, MAX(recorded_at) AS max_ts
                    FROM risk_scores WHERE org_id = ? GROUP BY entity_id
                ) latest ON rs.entity_id = latest.entity_id
                         AND rs.recorded_at = latest.max_ts
                WHERE rs.org_id = ? AND rs.severity IN ('critical', 'high')
                """,
                (org_id, org_id),
            ).fetchone()[0]

            last_updated_row = conn.execute(
                "SELECT MAX(recorded_at) FROM risk_scores WHERE org_id = ?",
                (org_id,),
            ).fetchone()

        org_score_data = self.calculate_org_risk_score(org_id)

        return {
            "org_id": org_id,
            "entities_tracked": entity_count,
            "high_risk_count": high_risk_count,
            "org_risk_score": org_score_data["org_risk_score"],
            "grade": org_score_data["grade"],
            "last_updated": last_updated_row[0] if last_updated_row else None,
        }
