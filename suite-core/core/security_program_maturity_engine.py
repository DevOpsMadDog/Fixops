"""Security Program Maturity Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

CMMI-style security program maturity scoring across governance domains:
  - Register maturity domains with target levels
  - Assess domains with current_level (1-5) and score (0-100)
  - Create and complete formal assessments (aggregate AVG across domains)
  - Track improvement plans with priority ordering
  - Roadmap view ordered by priority then effort

Compliance: CMMI, NIST CSF, ISO 27001, CIS Controls v8
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_program_maturity.db"
)

VALID_DOMAIN_TYPES = frozenset({
    "governance", "risk", "compliance", "asset-management", "access-control",
    "incident-response", "threat-intel", "vulnerability-management",
    "security-awareness", "third-party",
})
VALID_PRIORITIES = frozenset({"critical", "high", "medium", "low"})

_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp_level(v: int) -> int:
    return max(1, min(int(v), 5))


def _clamp_score(v: float) -> float:
    return max(0.0, min(float(v), 100.0))


class SecurityProgramMaturityEngine:
    """SQLite WAL-backed Security Program Maturity engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_program_maturity.db
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
                CREATE TABLE IF NOT EXISTS maturity_domains (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    domain_name     TEXT NOT NULL,
                    domain_type     TEXT NOT NULL DEFAULT 'governance',
                    current_level   INTEGER NOT NULL DEFAULT 1,
                    target_level    INTEGER NOT NULL DEFAULT 3,
                    score           REAL NOT NULL DEFAULT 0.0,
                    evidence        TEXT NOT NULL DEFAULT '',
                    last_assessed   TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_md_org
                    ON maturity_domains (org_id);

                CREATE TABLE IF NOT EXISTS maturity_assessments (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    assessment_name   TEXT NOT NULL,
                    assessor          TEXT NOT NULL DEFAULT '',
                    status            TEXT NOT NULL DEFAULT 'in_progress',
                    overall_level     REAL NOT NULL DEFAULT 0.0,
                    overall_score     REAL NOT NULL DEFAULT 0.0,
                    domains_assessed  INTEGER NOT NULL DEFAULT 0,
                    created_at        TEXT NOT NULL,
                    completed_at      TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_ma_org
                    ON maturity_assessments (org_id);

                CREATE TABLE IF NOT EXISTS maturity_improvements (
                    id                TEXT PRIMARY KEY,
                    domain_id         TEXT NOT NULL,
                    org_id            TEXT NOT NULL,
                    improvement_name  TEXT NOT NULL,
                    priority          TEXT NOT NULL DEFAULT 'medium',
                    target_level      INTEGER NOT NULL DEFAULT 3,
                    effort_days       INTEGER NOT NULL DEFAULT 0,
                    status            TEXT NOT NULL DEFAULT 'planned',
                    due_date          TEXT NOT NULL DEFAULT '',
                    completed_at      TEXT NOT NULL DEFAULT '',
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mi_org
                    ON maturity_improvements (org_id);
                CREATE INDEX IF NOT EXISTS idx_mi_domain
                    ON maturity_improvements (domain_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Domains
    # ------------------------------------------------------------------

    def register_domain(
        self,
        org_id: str,
        domain_name: str,
        domain_type: str = "governance",
        target_level: int = 3,
    ) -> Dict[str, Any]:
        """Register a new maturity domain. current_level=1, score=0."""
        if domain_type not in VALID_DOMAIN_TYPES:
            raise ValueError(f"domain_type must be one of {sorted(VALID_DOMAIN_TYPES)}")
        if not domain_name:
            raise ValueError("domain_name is required")
        target_level = _clamp_level(target_level)
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "domain_name": domain_name,
            "domain_type": domain_type,
            "current_level": 1,
            "target_level": target_level,
            "score": 0.0,
            "evidence": "",
            "last_assessed": "",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO maturity_domains
                       (id, org_id, domain_name, domain_type, current_level,
                        target_level, score, evidence, last_assessed, created_at)
                       VALUES (:id, :org_id, :domain_name, :domain_type, :current_level,
                               :target_level, :score, :evidence, :last_assessed, :created_at)""",
                    record,
                )
        _logger.info("domain registered id=%s org=%s name=%s", record["id"], org_id, domain_name)
        return record

    def assess_domain(
        self,
        domain_id: str,
        org_id: str,
        current_level: int,
        score: float,
        evidence: str = "",
    ) -> Dict[str, Any]:
        """Update a domain's current_level (1-5), score (0-100), evidence, and last_assessed."""
        current_level = _clamp_level(current_level)
        score = _clamp_score(score)
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM maturity_domains WHERE id=? AND org_id=?",
                    (domain_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"domain {domain_id!r} not found")
                conn.execute(
                    """UPDATE maturity_domains
                       SET current_level=?, score=?, evidence=?, last_assessed=?
                       WHERE id=? AND org_id=?""",
                    (current_level, score, evidence, now, domain_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM maturity_domains WHERE id=?", (domain_id,)
                ).fetchone()
        return self._row(updated)

    def list_domains(self, org_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM maturity_domains WHERE org_id=? ORDER BY domain_name",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        org_id: str,
        assessment_name: str,
        assessor: str = "",
    ) -> Dict[str, Any]:
        """Create a new formal assessment (status=in_progress)."""
        if not assessment_name:
            raise ValueError("assessment_name is required")
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "assessment_name": assessment_name,
            "assessor": assessor,
            "status": "in_progress",
            "overall_level": 0.0,
            "overall_score": 0.0,
            "domains_assessed": 0,
            "created_at": now,
            "completed_at": "",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO maturity_assessments
                       (id, org_id, assessment_name, assessor, status, overall_level,
                        overall_score, domains_assessed, created_at, completed_at)
                       VALUES (:id, :org_id, :assessment_name, :assessor, :status,
                               :overall_level, :overall_score, :domains_assessed,
                               :created_at, :completed_at)""",
                    record,
                )
        return record

    def complete_assessment(self, assessment_id: str, org_id: str) -> Dict[str, Any]:
        """Complete an assessment: aggregate AVG(current_level), AVG(score), COUNT from org domains."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM maturity_assessments WHERE id=? AND org_id=?",
                    (assessment_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"assessment {assessment_id!r} not found")

                agg = conn.execute(
                    """SELECT AVG(current_level) AS avg_level,
                              AVG(score) AS avg_score,
                              COUNT(*) AS cnt
                       FROM maturity_domains
                       WHERE org_id=?""",
                    (org_id,),
                ).fetchone()

                overall_level = float(agg["avg_level"] or 0.0)
                overall_score = float(agg["avg_score"] or 0.0)
                domains_assessed = int(agg["cnt"] or 0)

                conn.execute(
                    """UPDATE maturity_assessments
                       SET status='completed', overall_level=?, overall_score=?,
                           domains_assessed=?, completed_at=?
                       WHERE id=? AND org_id=?""",
                    (overall_level, overall_score, domains_assessed, now, assessment_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM maturity_assessments WHERE id=?", (assessment_id,)
                ).fetchone()
        return self._row(updated)

    def list_assessments(self, org_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM maturity_assessments WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Improvements
    # ------------------------------------------------------------------

    def add_improvement(
        self,
        domain_id: str,
        org_id: str,
        improvement_name: str,
        priority: str = "medium",
        target_level: int = 3,
        effort_days: int = 0,
        due_date: str = "",
    ) -> Dict[str, Any]:
        """Add an improvement plan to a domain."""
        if priority not in VALID_PRIORITIES:
            raise ValueError(f"priority must be one of {sorted(VALID_PRIORITIES)}")
        target_level = _clamp_level(target_level)
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "domain_id": domain_id,
            "org_id": org_id,
            "improvement_name": improvement_name,
            "priority": priority,
            "target_level": target_level,
            "effort_days": max(0, int(effort_days)),
            "status": "planned",
            "due_date": due_date,
            "completed_at": "",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO maturity_improvements
                       (id, domain_id, org_id, improvement_name, priority, target_level,
                        effort_days, status, due_date, completed_at, created_at)
                       VALUES (:id, :domain_id, :org_id, :improvement_name, :priority,
                               :target_level, :effort_days, :status, :due_date,
                               :completed_at, :created_at)""",
                    record,
                )
        return record

    def complete_improvement(self, improvement_id: str, org_id: str) -> Dict[str, Any]:
        """Mark an improvement as completed."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM maturity_improvements WHERE id=? AND org_id=?",
                    (improvement_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"improvement {improvement_id!r} not found")
                conn.execute(
                    """UPDATE maturity_improvements
                       SET status='completed', completed_at=?
                       WHERE id=? AND org_id=?""",
                    (now, improvement_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM maturity_improvements WHERE id=?", (improvement_id,)
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Views
    # ------------------------------------------------------------------

    def get_maturity_profile(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all domains with gap and improvements list per domain."""
        with self._conn() as conn:
            domains = conn.execute(
                "SELECT * FROM maturity_domains WHERE org_id=? ORDER BY domain_name",
                (org_id,),
            ).fetchall()
            result = []
            for d in domains:
                d_dict = self._row(d)
                d_dict["gap"] = d_dict["target_level"] - d_dict["current_level"]
                imps = conn.execute(
                    "SELECT * FROM maturity_improvements WHERE domain_id=? AND org_id=?",
                    (d_dict["id"], org_id),
                ).fetchall()
                d_dict["improvements"] = [self._row(i) for i in imps]
                result.append(d_dict)
        return result

    def get_roadmap(self, org_id: str) -> List[Dict[str, Any]]:
        """Return pending improvements ordered by priority (critical→low) then effort_days ASC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM maturity_improvements
                   WHERE org_id=? AND status != 'completed'
                   ORDER BY effort_days ASC""",
                (org_id,),
            ).fetchall()
        items = [self._row(r) for r in rows]
        items.sort(key=lambda x: (_PRIORITY_ORDER.get(x["priority"], 99), x["effort_days"]))
        return items

    def get_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate summary for the org."""
        with self._conn() as conn:
            agg = conn.execute(
                """SELECT AVG(current_level) AS avg_level,
                          AVG(score) AS avg_score,
                          COUNT(*) AS total,
                          SUM(CASE WHEN current_level >= target_level THEN 1 ELSE 0 END) AS at_target
                   FROM maturity_domains
                   WHERE org_id=?""",
                (org_id,),
            ).fetchone()

            pending = conn.execute(
                """SELECT COUNT(*) AS cnt FROM maturity_improvements
                   WHERE org_id=? AND status != 'completed'""",
                (org_id,),
            ).fetchone()

            type_rows = conn.execute(
                """SELECT domain_type, COUNT(*) AS cnt
                   FROM maturity_domains WHERE org_id=?
                   GROUP BY domain_type""",
                (org_id,),
            ).fetchall()

        by_domain_type = {r["domain_type"]: r["cnt"] for r in type_rows}

        return {
            "avg_current_level": float(agg["avg_level"] or 0.0),
            "avg_score": float(agg["avg_score"] or 0.0),
            "total_domains": int(agg["total"] or 0),
            "domains_at_target": int(agg["at_target"] or 0),
            "pending_improvements": int(pending["cnt"] or 0),
            "by_domain_type": by_domain_type,
        }
