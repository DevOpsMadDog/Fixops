"""
ForensicsReadinessEngine — ALDECI.

Tracks evidence sources, assesses forensic readiness, and manages collection plans
for incident response. Supports lifecycle: draft → executing → completed.

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: SOC2 CC7.3, NIST SP 800-53 IR-4 (incident handling), AU-9 (audit protection).
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "forensics_readiness.db"
)

VALID_SOURCE_TYPES = frozenset({
    "endpoint_logs", "network_pcap", "cloud_trail", "email_archive",
    "database_audit", "identity_logs", "application_logs",
})
VALID_COLLECTION_METHODS = frozenset({"agent", "api", "syslog", "manual"})
VALID_PRIORITIES = frozenset({"low", "medium", "high", "critical"})

_READINESS_THRESHOLDS = {"ready": 80, "partial": 40}


def _score_to_level(score: int) -> str:
    if score >= _READINESS_THRESHOLDS["ready"]:
        return "ready"
    if score >= _READINESS_THRESHOLDS["partial"]:
        return "partial"
    return "not_ready"


class ForensicsReadinessEngine:
    """
    SQLite-backed forensics readiness tracking engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to .fixops_data/forensics_readiness.db.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS evidence_sources (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL,
                    source_type       TEXT NOT NULL,
                    retention_days    INTEGER NOT NULL DEFAULT 365,
                    collection_method TEXT NOT NULL DEFAULT 'api',
                    coverage_score    INTEGER NOT NULL DEFAULT 0,
                    readiness_level   TEXT NOT NULL DEFAULT 'not_ready',
                    status            TEXT NOT NULL DEFAULT 'active',
                    assessed_at       DATETIME,
                    created_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sources_org
                    ON evidence_sources (org_id);

                CREATE INDEX IF NOT EXISTS idx_sources_org_type
                    ON evidence_sources (org_id, source_type);

                CREATE TABLE IF NOT EXISTS collection_plans (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL,
                    incident_type    TEXT NOT NULL,
                    priority         TEXT NOT NULL,
                    target_sources   TEXT NOT NULL DEFAULT '[]',
                    collection_steps TEXT NOT NULL DEFAULT '[]',
                    status           TEXT NOT NULL DEFAULT 'draft',
                    executed_by      TEXT,
                    items_collected  INTEGER,
                    notes            TEXT DEFAULT '',
                    created_at       DATETIME NOT NULL,
                    started_at       DATETIME,
                    completed_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_plans_org
                    ON collection_plans (org_id);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Evidence Sources
    # ------------------------------------------------------------------

    def register_evidence_source(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Register an evidence source.

        data keys: name (required), source_type (required), retention_days (default=365),
                   collection_method (default=api), status=active.
        Returns the created source record.
        """
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        source_type = data.get("source_type", "")
        if source_type not in VALID_SOURCE_TYPES:
            raise ValueError(f"source_type must be one of {sorted(VALID_SOURCE_TYPES)}")

        retention_days = int(data.get("retention_days", 365))
        collection_method = data.get("collection_method", "api")
        if collection_method not in VALID_COLLECTION_METHODS:
            raise ValueError(f"collection_method must be one of {sorted(VALID_COLLECTION_METHODS)}")

        status = data.get("status", "active")
        now = datetime.now(timezone.utc).isoformat()
        source_id = str(uuid.uuid4())

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO evidence_sources
                        (id, org_id, name, source_type, retention_days, collection_method,
                         coverage_score, readiness_level, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 0, 'not_ready', ?, ?)
                    """,
                    (source_id, org_id, name, source_type, retention_days,
                     collection_method, status, now),
                )

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("EVIDENCE_COLLECTED", {"entity_type": "forensics_readiness_engine", "org_id": org_id, "source_engine": "forensics_readiness_engine"})
            except Exception:
                pass
        return {
            "id": source_id,
            "org_id": org_id,
            "name": name,
            "source_type": source_type,
            "retention_days": retention_days,
            "collection_method": collection_method,
            "coverage_score": 0,
            "readiness_level": "not_ready",
            "status": status,
            "assessed_at": None,
            "created_at": now,
        }

    def list_evidence_sources(
        self, org_id: str, source_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return evidence sources for the org, optionally filtered by source_type."""
        query = "SELECT * FROM evidence_sources WHERE org_id = ?"
        params: List[Any] = [org_id]

        if source_type:
            query += " AND source_type = ?"
            params.append(source_type)

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    def assess_readiness(
        self,
        org_id: str,
        source_id: str,
        assessment_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Assess the forensic readiness of an evidence source.

        assessment_data keys (bool): encryption, integrity_check, chain_of_custody,
                                     offsite_backup, access_logging.
        coverage_score = count(True) * 20  (0-100).
        readiness_level: 80-100=ready, 40-79=partial, 0-39=not_ready.
        """
        checks = [
            bool(assessment_data.get("encryption", False)),
            bool(assessment_data.get("integrity_check", False)),
            bool(assessment_data.get("chain_of_custody", False)),
            bool(assessment_data.get("offsite_backup", False)),
            bool(assessment_data.get("access_logging", False)),
        ]
        coverage_score = sum(checks) * 20
        readiness_level = _score_to_level(coverage_score)
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    """
                    UPDATE evidence_sources
                    SET coverage_score = ?, readiness_level = ?, assessed_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (coverage_score, readiness_level, now, source_id, org_id),
                )
                if cursor.rowcount == 0:
                    raise ValueError(f"Source {source_id} not found for org {org_id}")
                row = conn.execute(
                    "SELECT * FROM evidence_sources WHERE id = ?", (source_id,)
                ).fetchone()

        return dict(row)

    # ------------------------------------------------------------------
    # Collection Plans
    # ------------------------------------------------------------------

    def create_collection_plan(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a forensic collection plan.

        data keys: name (required), incident_type (required), priority (required),
                   target_sources (list of source IDs), collection_steps (list).
        Returns the created plan with status=draft.
        """
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        incident_type = data.get("incident_type", "").strip()
        if not incident_type:
            raise ValueError("incident_type is required")

        priority = data.get("priority", "")
        if priority not in VALID_PRIORITIES:
            raise ValueError(f"priority must be one of {sorted(VALID_PRIORITIES)}")

        target_sources = data.get("target_sources", [])
        collection_steps = data.get("collection_steps", [])
        now = datetime.now(timezone.utc).isoformat()
        plan_id = str(uuid.uuid4())

        target_sources_json = json.dumps(target_sources)
        collection_steps_json = json.dumps(collection_steps)

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO collection_plans
                        (id, org_id, name, incident_type, priority, target_sources,
                         collection_steps, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?)
                    """,
                    (plan_id, org_id, name, incident_type, priority,
                     target_sources_json, collection_steps_json, now),
                )

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("EVIDENCE_COLLECTED", {"entity_type": "forensics_readiness_engine", "org_id": org_id, "source_engine": "forensics_readiness_engine"})
            except Exception:
                pass
        return {
            "id": plan_id,
            "org_id": org_id,
            "name": name,
            "incident_type": incident_type,
            "priority": priority,
            "target_sources": target_sources,
            "collection_steps": collection_steps,
            "status": "draft",
            "executed_by": None,
            "items_collected": None,
            "notes": "",
            "created_at": now,
            "started_at": None,
            "completed_at": None,
        }

    def execute_collection_plan(
        self, org_id: str, plan_id: str, executed_by: str
    ) -> Dict[str, Any]:
        """
        Mark a collection plan as executing.

        Sets status=executing, executed_by, started_at=now.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    """
                    UPDATE collection_plans
                    SET status = 'executing', executed_by = ?, started_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (executed_by, now, plan_id, org_id),
                )
                if cursor.rowcount == 0:
                    raise ValueError(f"Plan {plan_id} not found for org {org_id}")
                row = conn.execute(
                    "SELECT * FROM collection_plans WHERE id = ?", (plan_id,)
                ).fetchone()

        return self._parse_plan(row)

    def complete_collection_plan(
        self,
        org_id: str,
        plan_id: str,
        items_collected: int,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Mark a collection plan as completed.

        Sets status=completed, completed_at, items_collected, notes.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    """
                    UPDATE collection_plans
                    SET status = 'completed', completed_at = ?, items_collected = ?, notes = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (now, items_collected, notes, plan_id, org_id),
                )
                if cursor.rowcount == 0:
                    raise ValueError(f"Plan {plan_id} not found for org {org_id}")
                row = conn.execute(
                    "SELECT * FROM collection_plans WHERE id = ?", (plan_id,)
                ).fetchone()

        return self._parse_plan(row)

    def _parse_plan(self, row: sqlite3.Row) -> Dict[str, Any]:
        result = dict(row)
        result["target_sources"] = json.loads(result.get("target_sources") or "[]")
        result["collection_steps"] = json.loads(result.get("collection_steps") or "[]")
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_readiness_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Return aggregate forensics readiness statistics for the org.

        Keys: total_sources, by_type, avg_coverage_score, ready_sources,
              partial_sources, not_ready_sources, total_plans, active_plans,
              overall_readiness_score.
        """
        with self._lock:
            with self._get_conn() as conn:
                agg = conn.execute(
                    "SELECT COUNT(*) as total, AVG(coverage_score) as avg_score FROM evidence_sources WHERE org_id = ?",
                    (org_id,),
                ).fetchone()

                type_rows = conn.execute(
                    "SELECT source_type, COUNT(*) as cnt FROM evidence_sources WHERE org_id = ? GROUP BY source_type",
                    (org_id,),
                ).fetchall()

                ready_sources = conn.execute(
                    "SELECT COUNT(*) FROM evidence_sources WHERE org_id = ? AND coverage_score >= 80",
                    (org_id,),
                ).fetchone()[0]

                partial_sources = conn.execute(
                    "SELECT COUNT(*) FROM evidence_sources WHERE org_id = ? AND coverage_score >= 40 AND coverage_score < 80",
                    (org_id,),
                ).fetchone()[0]

                not_ready_sources = conn.execute(
                    "SELECT COUNT(*) FROM evidence_sources WHERE org_id = ? AND coverage_score < 40",
                    (org_id,),
                ).fetchone()[0]

                total_plans = conn.execute(
                    "SELECT COUNT(*) FROM collection_plans WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                active_plans = conn.execute(
                    "SELECT COUNT(*) FROM collection_plans WHERE org_id = ? AND status = 'executing'",
                    (org_id,),
                ).fetchone()[0]

        by_type: Dict[str, int] = {}
        for r in type_rows:
            by_type[r["source_type"]] = r["cnt"]

        avg_coverage_score = round(float(agg["avg_score"] or 0.0), 2)
        overall_readiness_score = round(avg_coverage_score)

        return {
            "total_sources": agg["total"] or 0,
            "by_type": by_type,
            "avg_coverage_score": avg_coverage_score,
            "ready_sources": ready_sources,
            "partial_sources": partial_sources,
            "not_ready_sources": not_ready_sources,
            "total_plans": total_plans,
            "active_plans": active_plans,
            "overall_readiness_score": overall_readiness_score,
        }
