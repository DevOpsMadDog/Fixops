"""Hunting Automation Engine — ALDECI.

Manages automated threat hunting: hypotheses, queries, and scheduled executions.

Features:
- Hypothesis lifecycle with validation
- Query management with rolling avg_execution_secs
- Execution tracking: findings_count accumulation, fail_execution no stat update
- data_sources stored as JSON list
- High-yield query filtering by findings_count threshold

Compliance: NIST SP 800-53 SI-4, CA-8; MITRE ATT&CK threat hunting framework
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "hunting_automation.db"
)

_VALID_THREAT_CATEGORIES = {
    "lateral_movement", "privilege_escalation", "exfiltration",
    "persistence", "defense_evasion", "discovery", "collection", "impact",
}
_VALID_CONFIDENCE_LEVELS = {"low", "medium", "high"}
_VALID_QUERY_LANGUAGES = {"KQL", "SPL", "SQL", "EQL", "YARA", "sigma", "lucene"}
_VALID_DATA_SOURCES = {"siem", "edr", "network", "cloud", "identity", "application"}
_VALID_STATUSES = {"running", "completed", "failed"}


class HuntingAutomationEngine:
    """Engine for automated threat hunting management."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS hunt_hypotheses (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    hypothesis        TEXT NOT NULL DEFAULT '',
                    threat_category   TEXT NOT NULL DEFAULT 'lateral_movement',
                    mitre_technique   TEXT NOT NULL DEFAULT '',
                    confidence        TEXT NOT NULL DEFAULT 'medium',
                    data_sources      TEXT NOT NULL DEFAULT '[]',
                    created_by        TEXT NOT NULL DEFAULT '',
                    validated         INTEGER NOT NULL DEFAULT 0,
                    validation_result TEXT NOT NULL DEFAULT '',
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_hh_org
                    ON hunt_hypotheses(org_id);
                CREATE INDEX IF NOT EXISTS idx_hh_category
                    ON hunt_hypotheses(org_id, threat_category);

                CREATE TABLE IF NOT EXISTS hunt_queries (
                    id                    TEXT PRIMARY KEY,
                    hypothesis_id         TEXT NOT NULL,
                    org_id                TEXT NOT NULL,
                    query_name            TEXT NOT NULL DEFAULT '',
                    query_language        TEXT NOT NULL DEFAULT 'KQL',
                    query_content         TEXT NOT NULL DEFAULT '',
                    data_source           TEXT NOT NULL DEFAULT 'siem',
                    execution_count       INTEGER NOT NULL DEFAULT 0,
                    last_executed         TEXT,
                    avg_execution_secs    REAL NOT NULL DEFAULT 0.0,
                    findings_count        INTEGER NOT NULL DEFAULT 0,
                    created_at            TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_hq_hypothesis
                    ON hunt_queries(hypothesis_id, org_id);
                CREATE INDEX IF NOT EXISTS idx_hq_org
                    ON hunt_queries(org_id);
                CREATE INDEX IF NOT EXISTS idx_hq_findings
                    ON hunt_queries(org_id, findings_count);

                CREATE TABLE IF NOT EXISTS hunt_executions (
                    id               TEXT PRIMARY KEY,
                    query_id         TEXT NOT NULL,
                    org_id           TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'running',
                    started_at       TEXT NOT NULL,
                    completed_at     TEXT,
                    execution_secs   REAL NOT NULL DEFAULT 0.0,
                    records_scanned  INTEGER NOT NULL DEFAULT 0,
                    findings         INTEGER NOT NULL DEFAULT 0,
                    notes            TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_he_query
                    ON hunt_executions(query_id, org_id);
                CREATE INDEX IF NOT EXISTS idx_he_org
                    ON hunt_executions(org_id);
                CREATE INDEX IF NOT EXISTS idx_he_status
                    ON hunt_executions(org_id, status);
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # HYPOTHESES
    # ------------------------------------------------------------------

    def create_hypothesis(
        self,
        org_id: str,
        hypothesis: str,
        threat_category: str,
        mitre_technique: str,
        confidence: str,
        data_sources: List[str],
        created_by: str,
    ) -> Dict[str, Any]:
        """Create a new hunt hypothesis. data_sources stored as JSON list."""
        if threat_category not in _VALID_THREAT_CATEGORIES:
            raise ValueError(
                f"Invalid threat_category '{threat_category}'. "
                f"Must be one of {sorted(_VALID_THREAT_CATEGORIES)}"
            )
        if confidence not in _VALID_CONFIDENCE_LEVELS:
            raise ValueError(
                f"Invalid confidence '{confidence}'. "
                f"Must be one of {sorted(_VALID_CONFIDENCE_LEVELS)}"
            )

        hyp_id = str(uuid.uuid4())
        now = self._now()
        sources_json = json.dumps(data_sources if isinstance(data_sources, list) else [])

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO hunt_hypotheses
                   (id, org_id, hypothesis, threat_category, mitre_technique,
                    confidence, data_sources, created_by, validated, validation_result, created_at)
                   VALUES (?,?,?,?,?,?,?,?,0,'',?)""",
                (
                    hyp_id, org_id, hypothesis, threat_category, mitre_technique,
                    confidence, sources_json, created_by, now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM hunt_hypotheses WHERE id=?", (hyp_id,)
            ).fetchone()

        _logger.info(
            "hunt.hypothesis_created org=%s id=%s category=%s",
            org_id, hyp_id, threat_category,
        )
        result = self._row(row)
        result["data_sources"] = json.loads(result["data_sources"])
        return result

    def validate_hypothesis(
        self,
        hypothesis_id: str,
        org_id: str,
        validated: bool,
        validation_result: str,
    ) -> Dict[str, Any]:
        """Update validation status of a hypothesis."""
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE hunt_hypotheses
                   SET validated=?, validation_result=?
                   WHERE id=? AND org_id=?""",
                (1 if validated else 0, validation_result, hypothesis_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM hunt_hypotheses WHERE id=? AND org_id=?",
                (hypothesis_id, org_id),
            ).fetchone()
        if row is None:
            raise ValueError(
                f"Hypothesis '{hypothesis_id}' not found for org '{org_id}'"
            )
        result = self._row(row)
        result["data_sources"] = json.loads(result.get("data_sources") or "[]")
        return result

    def get_hypothesis(
        self, hypothesis_id: str, org_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch a single hypothesis scoped to org_id."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_hypotheses WHERE id=? AND org_id=?",
                (hypothesis_id, org_id),
            ).fetchone()
        if row is None:
            return None
        result = self._row(row)
        result["data_sources"] = json.loads(result.get("data_sources") or "[]")
        return result

    def list_hypotheses(self, org_id: str) -> List[Dict[str, Any]]:
        """List all hypotheses for the org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM hunt_hypotheses WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        results = []
        for r in rows:
            d = self._row(r)
            d["data_sources"] = json.loads(d.get("data_sources") or "[]")
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # QUERIES
    # ------------------------------------------------------------------

    def add_query(
        self,
        hypothesis_id: str,
        org_id: str,
        query_name: str,
        query_language: str,
        query_content: str,
        data_source: str,
    ) -> Dict[str, Any]:
        """Add a hunt query to a hypothesis."""
        if query_language not in _VALID_QUERY_LANGUAGES:
            raise ValueError(
                f"Invalid query_language '{query_language}'. "
                f"Must be one of {sorted(_VALID_QUERY_LANGUAGES)}"
            )
        if data_source not in _VALID_DATA_SOURCES:
            raise ValueError(
                f"Invalid data_source '{data_source}'. "
                f"Must be one of {sorted(_VALID_DATA_SOURCES)}"
            )

        query_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO hunt_queries
                   (id, hypothesis_id, org_id, query_name, query_language,
                    query_content, data_source, execution_count, findings_count, created_at)
                   VALUES (?,?,?,?,?,?,?,0,0,?)""",
                (
                    query_id, hypothesis_id, org_id, query_name, query_language,
                    query_content, data_source, now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM hunt_queries WHERE id=?", (query_id,)
            ).fetchone()

        _logger.info(
            "hunt.query_added org=%s query_id=%s language=%s",
            org_id, query_id, query_language,
        )
        return self._row(row)

    def get_query(self, query_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single query scoped to org_id."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_queries WHERE id=? AND org_id=?",
                (query_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # EXECUTIONS
    # ------------------------------------------------------------------

    def execute_query(
        self,
        query_id: str,
        org_id: str,
        records_scanned: int,
        findings: int,
        execution_secs: float,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Record a successful query execution.

        - Inserts execution record with status=completed
        - Updates query: execution_count+=1, last_executed=now,
          findings_count+=findings, avg_execution_secs rolling avg
          avg = ((old_avg * (count-1)) + new_secs) / count
        """
        # Fetch current query stats first
        with self._conn() as conn:
            q_row = conn.execute(
                "SELECT * FROM hunt_queries WHERE id=? AND org_id=?",
                (query_id, org_id),
            ).fetchone()
        if q_row is None:
            raise ValueError(f"Query '{query_id}' not found for org '{org_id}'")

        q = self._row(q_row)
        old_count = q["execution_count"]
        old_avg = q["avg_execution_secs"]
        new_count = old_count + 1
        new_avg = ((old_avg * old_count) + float(execution_secs)) / new_count

        exec_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO hunt_executions
                   (id, query_id, org_id, status, started_at, completed_at,
                    execution_secs, records_scanned, findings, notes, created_at)
                   VALUES (?,?,?,'completed',?,?,?,?,?,?,?)""",
                (
                    exec_id, query_id, org_id, now, now,
                    float(execution_secs), records_scanned, findings, notes, now,
                ),
            )
            conn.execute(
                """UPDATE hunt_queries
                   SET execution_count=?, last_executed=?,
                       findings_count=findings_count+?,
                       avg_execution_secs=?
                   WHERE id=? AND org_id=?""",
                (new_count, now, findings, new_avg, query_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM hunt_executions WHERE id=?", (exec_id,)
            ).fetchone()

        _logger.info(
            "hunt.query_executed org=%s query_id=%s findings=%d secs=%.2f",
            org_id, query_id, findings, execution_secs,
        )
        return self._row(row)

    def fail_execution(
        self,
        query_id: str,
        org_id: str,
        notes: str,
    ) -> Dict[str, Any]:
        """Record a failed execution. Does NOT update query stats."""
        exec_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO hunt_executions
                   (id, query_id, org_id, status, started_at, completed_at,
                    execution_secs, records_scanned, findings, notes, created_at)
                   VALUES (?,?,?,'failed',?,?,0,0,0,?,?)""",
                (exec_id, query_id, org_id, now, now, notes, now),
            )
            row = conn.execute(
                "SELECT * FROM hunt_executions WHERE id=?", (exec_id,)
            ).fetchone()

        _logger.info(
            "hunt.execution_failed org=%s query_id=%s notes=%s",
            org_id, query_id, notes,
        )
        return self._row(row)

    def get_recent_executions(
        self, org_id: str, limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Return recent executions with query_name via JOIN."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT he.*, hq.query_name, hq.query_language, hq.data_source
                   FROM hunt_executions he
                   JOIN hunt_queries hq ON hq.id=he.query_id AND hq.org_id=he.org_id
                   WHERE he.org_id=?
                   ORDER BY he.started_at DESC LIMIT ?""",
                (org_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # ANALYTICS
    # ------------------------------------------------------------------

    def get_hunt_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate summary.

        - total_hypotheses, validated_count, total_queries, total_findings
        - by_threat_category: {category: hypothesis_count}
        - top_queries: top 5 by findings_count DESC
        """
        with self._conn() as conn:
            total_hyp = conn.execute(
                "SELECT COUNT(*) FROM hunt_hypotheses WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            validated = conn.execute(
                "SELECT COUNT(*) FROM hunt_hypotheses WHERE org_id=? AND validated=1",
                (org_id,),
            ).fetchone()[0]

            total_queries = conn.execute(
                "SELECT COUNT(*) FROM hunt_queries WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            total_findings = conn.execute(
                "SELECT COALESCE(SUM(findings_count),0) FROM hunt_queries WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            by_category = conn.execute(
                """SELECT threat_category, COUNT(*) AS cnt
                   FROM hunt_hypotheses WHERE org_id=?
                   GROUP BY threat_category""",
                (org_id,),
            ).fetchall()

            top_queries = conn.execute(
                """SELECT id, query_name, findings_count, execution_count,
                          avg_execution_secs, data_source
                   FROM hunt_queries WHERE org_id=?
                   ORDER BY findings_count DESC LIMIT 5""",
                (org_id,),
            ).fetchall()

        return {
            "total_hypotheses": total_hyp,
            "validated_count": validated,
            "total_queries": total_queries,
            "total_findings": int(total_findings),
            "by_threat_category": {r["threat_category"]: r["cnt"] for r in by_category},
            "top_queries": [self._row(r) for r in top_queries],
        }

    def get_hypothesis_detail(
        self, hypothesis_id: str, org_id: str
    ) -> Optional[Dict[str, Any]]:
        """Return hypothesis + queries + last 5 executions per query."""
        hyp = self.get_hypothesis(hypothesis_id, org_id)
        if hyp is None:
            return None

        with self._conn() as conn:
            queries = conn.execute(
                "SELECT * FROM hunt_queries WHERE hypothesis_id=? AND org_id=? ORDER BY created_at",
                (hypothesis_id, org_id),
            ).fetchall()

        query_list = []
        for q_row in queries:
            q = self._row(q_row)
            with self._conn() as conn:
                execs = conn.execute(
                    """SELECT * FROM hunt_executions
                       WHERE query_id=? AND org_id=?
                       ORDER BY started_at DESC LIMIT 5""",
                    (q["id"], org_id),
                ).fetchall()
            q["recent_executions"] = [self._row(e) for e in execs]
            query_list.append(q)

        hyp["queries"] = query_list
        return hyp

    def get_high_yield_queries(
        self, org_id: str, min_findings: int = 1
    ) -> List[Dict[str, Any]]:
        """Return queries with findings_count >= min_findings, ordered by findings DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM hunt_queries
                   WHERE org_id=? AND findings_count >= ?
                   ORDER BY findings_count DESC""",
                (org_id, min_findings),
            ).fetchall()
        return [self._row(r) for r in rows]
