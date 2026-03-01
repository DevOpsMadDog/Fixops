"""
FAIL Engine Database — Persistent storage for FAIL scores.

Stores computed FAIL scores with full sub-score breakdown for audit trail,
trend analysis, and compliance evidence.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class FAILDB:
    """SQLite database for FAIL scores (WAL mode)."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "data", "fail_scores.db"
        )
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        conn = self._conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS fail_scores (
                score_id        TEXT PRIMARY KEY,
                cve_id          TEXT,
                finding_id      TEXT,
                org_id          TEXT DEFAULT 'default',
                fail_score      REAL NOT NULL,
                grade           TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                fact_score      REAL NOT NULL DEFAULT 0,
                assess_score    REAL NOT NULL DEFAULT 0,
                impact_score    REAL NOT NULL DEFAULT 0,
                likelihood_score REAL NOT NULL DEFAULT 0,
                sub_scores_json TEXT,
                weights_json    TEXT,
                input_json      TEXT,
                engine_version  TEXT DEFAULT '1.0.0',
                computation_ms  REAL DEFAULT 0,
                scored_at       TEXT NOT NULL,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_fail_cve ON fail_scores(cve_id);
            CREATE INDEX IF NOT EXISTS idx_fail_finding ON fail_scores(finding_id);
            CREATE INDEX IF NOT EXISTS idx_fail_org ON fail_scores(org_id);
            CREATE INDEX IF NOT EXISTS idx_fail_grade ON fail_scores(grade);
            CREATE INDEX IF NOT EXISTS idx_fail_scored_at ON fail_scores(scored_at);
            CREATE INDEX IF NOT EXISTS idx_fail_score_val ON fail_scores(fail_score DESC);
        """
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save_score(
        self,
        result_dict: Dict[str, Any],
        org_id: str = "default",
        input_dict: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Persist a FAIL score result. Returns score_id."""
        conn = self._conn()
        score_id = result_dict["score_id"]
        sub_scores = result_dict.get("sub_scores", {})

        conn.execute(
            """
            INSERT OR REPLACE INTO fail_scores
                (score_id, cve_id, finding_id, org_id, fail_score, grade,
                 recommended_action, fact_score, assess_score, impact_score,
                 likelihood_score, sub_scores_json, weights_json, input_json,
                 engine_version, computation_ms, scored_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                score_id,
                result_dict.get("cve_id"),
                result_dict.get("finding_id"),
                org_id,
                result_dict["fail_score"],
                result_dict["grade"],
                result_dict["recommended_action"],
                sub_scores.get("fact", {}).get("score", 0),
                sub_scores.get("assess", {}).get("score", 0),
                sub_scores.get("impact", {}).get("score", 0),
                sub_scores.get("likelihood", {}).get("score", 0),
                json.dumps(sub_scores),
                json.dumps(result_dict.get("weights", {})),
                json.dumps(input_dict) if input_dict else None,
                result_dict.get("engine_version", "1.0.0"),
                result_dict.get("computation_ms", 0),
                result_dict.get("scored_at", datetime.now(timezone.utc).isoformat()),
            ),
        )
        conn.commit()
        return score_id

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_score(self, score_id: str) -> Optional[Dict[str, Any]]:
        """Get a single FAIL score by ID."""
        row = self._conn().execute(
            "SELECT * FROM fail_scores WHERE score_id = ?", (score_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_scores_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get all FAIL scores for a CVE (most recent first)."""
        rows = self._conn().execute(
            "SELECT * FROM fail_scores WHERE cve_id = ? ORDER BY scored_at DESC",
            (cve_id,),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_scores_by_org(
        self,
        org_id: str = "default",
        grade: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get FAIL scores for an organisation."""
        query = "SELECT * FROM fail_scores WHERE org_id = ?"
        params: list = [org_id]
        if grade:
            query += " AND grade = ?"
            params.append(grade.upper())
        query += " ORDER BY fail_score DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._conn().execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_top_risks(self, org_id: str = "default", limit: int = 20) -> List[Dict[str, Any]]:
        """Get top risks by FAIL score."""
        rows = self._conn().execute(
            """
            SELECT * FROM fail_scores
            WHERE org_id = ?
            ORDER BY fail_score DESC
            LIMIT ?
            """,
            (org_id, limit),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_grade_distribution(self, org_id: str = "default") -> Dict[str, int]:
        """Get count of each grade."""
        rows = self._conn().execute(
            """
            SELECT grade, COUNT(*) as cnt
            FROM fail_scores
            WHERE org_id = ?
            GROUP BY grade
            ORDER BY cnt DESC
            """,
            (org_id,),
        ).fetchall()
        return {r["grade"]: r["cnt"] for r in rows}

    def get_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Aggregate statistics."""
        row = self._conn().execute(
            """
            SELECT
                COUNT(*) as total,
                AVG(fail_score) as avg_score,
                MAX(fail_score) as max_score,
                MIN(fail_score) as min_score,
                SUM(CASE WHEN grade = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN grade = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                SUM(CASE WHEN grade = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
                SUM(CASE WHEN grade = 'LOW' THEN 1 ELSE 0 END) as low_count,
                SUM(CASE WHEN grade = 'INFO' THEN 1 ELSE 0 END) as info_count
            FROM fail_scores
            WHERE org_id = ?
            """,
            (org_id,),
        ).fetchone()

        return {
            "total": row["total"] or 0,
            "average_score": round(row["avg_score"] or 0, 2),
            "max_score": round(row["max_score"] or 0, 2),
            "min_score": round(row["min_score"] or 0, 2),
            "grade_distribution": {
                "CRITICAL": row["critical_count"] or 0,
                "HIGH": row["high_count"] or 0,
                "MEDIUM": row["medium_count"] or 0,
                "LOW": row["low_count"] or 0,
                "INFO": row["info_count"] or 0,
            },
        }

    def count(self, org_id: str = "default") -> int:
        row = self._conn().execute(
            "SELECT COUNT(*) as cnt FROM fail_scores WHERE org_id = ?", (org_id,)
        ).fetchone()
        return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_score(self, score_id: str) -> bool:
        conn = self._conn()
        cursor = conn.execute("DELETE FROM fail_scores WHERE score_id = ?", (score_id,))
        conn.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for json_field in ("sub_scores_json", "weights_json", "input_json"):
            if d.get(json_field):
                try:
                    d[json_field.replace("_json", "")] = json.loads(d[json_field])
                except (json.JSONDecodeError, TypeError):
                    d[json_field.replace("_json", "")] = {}
                del d[json_field]
            else:
                d[json_field.replace("_json", "")] = {}
                if json_field in d:
                    del d[json_field]
        return d
