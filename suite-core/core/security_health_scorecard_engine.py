"""Security Health Scorecard Engine — ALDECI.

Unified security health scorecard aggregating scores across all security
domains. Provides weighted composite scoring, grade assignment, trend
analysis, and target tracking.

Compliance: NIST CSF ID.GV-1, ISO/IEC 27001 A.5.1, SOC 2 CC1.1
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import threading
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_health_scorecard.db"
)

_VALID_DOMAIN_CATEGORIES = {
    "vulnerability", "compliance", "identity", "network",
    "endpoint", "cloud", "data", "physical",
}
_VALID_STATUSES = {"green", "amber", "red"}
_VALID_GRADES = {"A", "B", "C", "D", "F"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today() -> str:
    return date.today().isoformat()


class SecurityHealthScorecardEngine:
    """SQLite WAL-backed Security Health Scorecard engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scorecard_domains (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    domain_name     TEXT NOT NULL,
                    domain_category TEXT NOT NULL DEFAULT 'vulnerability',
                    weight          REAL NOT NULL DEFAULT 1.0,
                    score           REAL NOT NULL DEFAULT 0.0,
                    max_score       REAL NOT NULL DEFAULT 100.0,
                    status          TEXT NOT NULL DEFAULT 'red',
                    last_updated    TEXT,
                    created_at      TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_shs_domain_org
                    ON scorecard_domains (org_id, domain_name);

                CREATE TABLE IF NOT EXISTS scorecard_snapshots (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    overall_score     REAL NOT NULL DEFAULT 0.0,
                    grade             TEXT NOT NULL DEFAULT 'F',
                    snapshot_date     TEXT NOT NULL,
                    domain_scores     TEXT NOT NULL DEFAULT '{}',
                    improvement_areas TEXT NOT NULL DEFAULT '[]',
                    created_at        TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_shs_snapshot_org_date
                    ON scorecard_snapshots (org_id, snapshot_date);

                CREATE TABLE IF NOT EXISTS scorecard_targets (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    domain_name   TEXT NOT NULL,
                    target_score  REAL NOT NULL DEFAULT 0.0,
                    current_score REAL NOT NULL DEFAULT 0.0,
                    deadline      TEXT,
                    owner         TEXT NOT NULL DEFAULT '',
                    created_at    TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_shs_target_org_domain
                    ON scorecard_targets (org_id, domain_name);
                """
            )

    @contextlib.contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _compute_status(score: float, max_score: float) -> str:
        if max_score <= 0:
            return "red"
        ratio = score / max_score
        if ratio >= 0.8:
            return "green"
        if ratio >= 0.6:
            return "amber"
        return "red"

    @staticmethod
    def _compute_grade(overall_score: float) -> str:
        if overall_score >= 90:
            return "A"
        if overall_score >= 80:
            return "B"
        if overall_score >= 70:
            return "C"
        if overall_score >= 60:
            return "D"
        return "F"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def upsert_domain(
        self,
        org_id: str,
        domain_name: str,
        domain_category: str,
        weight: float,
        score: float,
        max_score: float,
    ) -> Dict[str, Any]:
        """Upsert a scorecard domain. Weight clamped 0-1. Status auto-computed."""
        if domain_category not in _VALID_DOMAIN_CATEGORIES:
            raise ValueError(
                f"Invalid domain_category '{domain_category}'. "
                f"Valid: {sorted(_VALID_DOMAIN_CATEGORIES)}"
            )

        weight = max(0.0, min(1.0, weight))
        status = self._compute_status(score, max_score)
        now = _now()

        with self._lock:
            with self._conn() as conn:
                # Try to get existing id
                existing = conn.execute(
                    "SELECT id FROM scorecard_domains WHERE org_id = ? AND domain_name = ?",
                    (org_id, domain_name),
                ).fetchone()
                domain_id = existing["id"] if existing else str(uuid.uuid4())

                if existing:
                    conn.execute(
                        """
                        UPDATE scorecard_domains
                        SET domain_category = ?, weight = ?, score = ?,
                            max_score = ?, status = ?, last_updated = ?
                        WHERE id = ?
                        """,
                        (domain_category, weight, score, max_score, status, now, domain_id),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO scorecard_domains
                            (id, org_id, domain_name, domain_category, weight,
                             score, max_score, status, last_updated, created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            domain_id, org_id, domain_name, domain_category,
                            weight, score, max_score, status, now, now,
                        ),
                    )

        return self.get_domain(org_id, domain_name)  # type: ignore[return-value]

    def get_domain(self, org_id: str, domain_name: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scorecard_domains WHERE org_id = ? AND domain_name = ?",
                (org_id, domain_name),
            ).fetchone()
        return self._row(row) if row else None

    def get_domains(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List domains for org, optionally filtered by status."""
        query = "SELECT * FROM scorecard_domains WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY domain_name"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def take_snapshot(self, org_id: str) -> Dict[str, Any]:
        """Compute and persist a scorecard snapshot.

        overall_score = weighted average of (score/max_score * weight * 100),
        normalized by sum(weights).
        """
        domains = self.get_domains(org_id)

        overall_score = 0.0
        domain_scores: Dict[str, float] = {}
        improvement_areas: List[str] = []
        total_weight = sum(d["weight"] for d in domains if d["max_score"] > 0)

        if total_weight > 0:
            weighted_sum = 0.0
            for d in domains:
                if d["max_score"] > 0:
                    ratio = d["score"] / d["max_score"]
                    weighted_sum += ratio * d["weight"] * 100
                domain_scores[d["domain_name"]] = round(
                    (d["score"] / d["max_score"] * 100) if d["max_score"] > 0 else 0.0, 2
                )
                if d["status"] == "red":
                    improvement_areas.append(d["domain_name"])
            overall_score = weighted_sum / total_weight

        grade = self._compute_grade(overall_score)
        snapshot_id = str(uuid.uuid4())
        now = _now()
        today = _today()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scorecard_snapshots
                        (id, org_id, overall_score, grade, snapshot_date,
                         domain_scores, improvement_areas, created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        snapshot_id, org_id, round(overall_score, 2), grade,
                        today, json.dumps(domain_scores),
                        json.dumps(improvement_areas), now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "security_health_scorecard", "org_id": org_id, "source_engine": "security_health_scorecard"})
            except Exception:
                pass

        return self.get_snapshot(snapshot_id)  # type: ignore[return-value]

    def get_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scorecard_snapshots WHERE id = ?",
                (snapshot_id,),
            ).fetchone()
        if not row:
            return None
        d = self._row(row)
        d["domain_scores"] = json.loads(d["domain_scores"])
        d["improvement_areas"] = json.loads(d["improvement_areas"])
        return d

    def set_target(
        self,
        org_id: str,
        domain_name: str,
        target_score: float,
        current_score: float,
        deadline: str,
        owner: str,
    ) -> Dict[str, Any]:
        """Upsert a target for a domain."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM scorecard_targets WHERE org_id = ? AND domain_name = ?",
                    (org_id, domain_name),
                ).fetchone()
                if existing:
                    conn.execute(
                        """
                        UPDATE scorecard_targets
                        SET target_score = ?, current_score = ?, deadline = ?, owner = ?
                        WHERE org_id = ? AND domain_name = ?
                        """,
                        (target_score, current_score, deadline, owner, org_id, domain_name),
                    )
                    target_id = existing["id"]
                else:
                    target_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO scorecard_targets
                            (id, org_id, domain_name, target_score, current_score,
                             deadline, owner, created_at)
                        VALUES (?,?,?,?,?,?,?,?)
                        """,
                        (
                            target_id, org_id, domain_name, target_score,
                            current_score, deadline, owner, now,
                        ),
                    )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scorecard_targets WHERE id = ?", (target_id,)
            ).fetchone()
        return self._row(row)  # type: ignore[return-value]

    def get_current_scorecard(self, org_id: str) -> Dict[str, Any]:
        """Return latest snapshot + all domains + targets."""
        with self._conn() as conn:
            snap_row = conn.execute(
                """
                SELECT * FROM scorecard_snapshots
                WHERE org_id = ?
                ORDER BY snapshot_date DESC, created_at DESC
                LIMIT 1
                """,
                (org_id,),
            ).fetchone()

            target_rows = conn.execute(
                "SELECT * FROM scorecard_targets WHERE org_id = ? ORDER BY domain_name",
                (org_id,),
            ).fetchall()

        domains = self.get_domains(org_id)
        targets = [self._row(r) for r in target_rows]

        snapshot = None
        if snap_row:
            snapshot = self._row(snap_row)
            snapshot["domain_scores"] = json.loads(snapshot["domain_scores"])
            snapshot["improvement_areas"] = json.loads(snapshot["improvement_areas"])

        return {
            "snapshot": snapshot,
            "domains": domains,
            "targets": targets,
        }

    def get_snapshot_history(self, org_id: str, days: int = 90) -> List[Dict[str, Any]]:
        """Return snapshots within the past `days` days, newest first."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM scorecard_snapshots
                WHERE org_id = ?
                  AND snapshot_date >= date('now', ? || ' days')
                ORDER BY snapshot_date DESC, created_at DESC
                """,
                (org_id, f"-{days}"),
            ).fetchall()

        results = []
        for r in rows:
            d = self._row(r)
            d["domain_scores"] = json.loads(d["domain_scores"])
            d["improvement_areas"] = json.loads(d["improvement_areas"])
            results.append(d)
        return results

    def get_grade_trend(self, org_id: str) -> List[Dict[str, Any]]:
        """Return grade trend per snapshot, ordered chronologically."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT snapshot_date, grade, overall_score
                FROM scorecard_snapshots
                WHERE org_id = ?
                ORDER BY snapshot_date ASC, created_at ASC
                """,
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]
