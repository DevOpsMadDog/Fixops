"""
Regulatory Change Tracker Engine — ALDECI compliance intelligence.

Tracks regulatory changes (new requirements, amendments, deadlines, enforcement
actions), compliance obligations, and assessments across frameworks such as
GDPR, PCI DSS, NIS2, DORA, HIPAA, SOC 2, ISO 27001, and more.

Multi-tenant via org_id. Thread-safe via RLock. SQLite WAL for concurrency.

Compliance: SOC2 CC6.1 (Change management), ISO27001 A.18.1 (Legal requirements)
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "regulatory_tracker_engine.db"
)

_VALID_CATEGORIES = {"privacy", "cybersecurity", "financial", "healthcare", "government"}
_VALID_REG_STATUSES = {"draft", "proposed", "enacted", "superseded"}
_VALID_CHANGE_TYPES = {
    "new_requirement", "amendment", "clarification", "deadline", "enforcement_action"
}
_VALID_IMPACT_LEVELS = {"critical", "high", "medium", "low"}
_VALID_OBLIGATION_TYPES = {"technical", "administrative", "operational"}
_VALID_OBLIGATION_STATUSES = {"pending", "in_progress", "compliant", "exempt"}


class RegulatoryTrackerEngine:
    """SQLite WAL-backed regulatory change tracking engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: regulations, regulatory_changes, compliance_obligations, reg_assessments.
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
                CREATE TABLE IF NOT EXISTS regulations (
                    reg_id          TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    jurisdiction    TEXT NOT NULL DEFAULT '',
                    category        TEXT NOT NULL DEFAULT 'cybersecurity',
                    version         TEXT NOT NULL DEFAULT '',
                    effective_date  TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'enacted',
                    url             TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_regs_org
                    ON regulations (org_id, category, status);

                CREATE TABLE IF NOT EXISTS regulatory_changes (
                    change_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    reg_id          TEXT NOT NULL
                        REFERENCES regulations(reg_id) ON DELETE CASCADE,
                    change_type     TEXT NOT NULL DEFAULT 'new_requirement',
                    title           TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    impact_level    TEXT NOT NULL DEFAULT 'medium',
                    affected_domains TEXT NOT NULL DEFAULT '[]',
                    published_at    DATETIME NOT NULL,
                    effective_at    DATETIME NOT NULL,
                    action_required INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_changes_org
                    ON regulatory_changes (org_id, impact_level, effective_at);

                CREATE TABLE IF NOT EXISTS compliance_obligations (
                    obligation_id   TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    reg_id          TEXT NOT NULL
                        REFERENCES regulations(reg_id) ON DELETE CASCADE,
                    change_id       TEXT,
                    title           TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    obligation_type TEXT NOT NULL DEFAULT 'technical',
                    deadline        TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    owner           TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_obligations_org
                    ON compliance_obligations (org_id, status, deadline);

                CREATE TABLE IF NOT EXISTS reg_assessments (
                    assessment_id   TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    reg_id          TEXT NOT NULL,
                    assessed_at     DATETIME NOT NULL,
                    compliance_pct  REAL NOT NULL DEFAULT 0.0,
                    gaps_count      INTEGER NOT NULL DEFAULT 0,
                    critical_gaps   INTEGER NOT NULL DEFAULT 0,
                    assessor        TEXT NOT NULL DEFAULT '',
                    notes           TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_assessments_org
                    ON reg_assessments (org_id, reg_id, assessed_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Regulations
    # ------------------------------------------------------------------

    def add_regulation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a regulation. Returns the full regulation record."""
        reg_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        category = data.get("category", "cybersecurity")
        if category not in _VALID_CATEGORIES:
            category = "cybersecurity"
        status = data.get("status", "enacted")
        if status not in _VALID_REG_STATUSES:
            status = "enacted"

        record = {
            "reg_id": reg_id,
            "org_id": org_id,
            "name": data["name"],
            "jurisdiction": data.get("jurisdiction", ""),
            "category": category,
            "version": data.get("version", ""),
            "effective_date": data.get("effective_date", ""),
            "status": status,
            "url": data.get("url", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO regulations
                       (reg_id, org_id, name, jurisdiction, category, version,
                        effective_date, status, url, created_at)
                       VALUES (:reg_id, :org_id, :name, :jurisdiction, :category,
                               :version, :effective_date, :status, :url, :created_at)""",
                    record,
                )
        _logger.info("Added regulation %s (%s) for org %s", reg_id, record["name"], org_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "regulatory_tracker", "org_id": org_id, "source_engine": "regulatory_tracker"})
            except Exception:
                pass

        return record

    def list_regulations(
        self,
        org_id: str,
        category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List regulations for an org, optionally filtered by category and/or status."""
        query = "SELECT * FROM regulations WHERE org_id = ?"
        params: List[Any] = [org_id]
        if category:
            query += " AND category = ?"
            params.append(category)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Regulatory Changes
    # ------------------------------------------------------------------

    def add_change(self, org_id: str, reg_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a regulatory change. affected_domains is stored as JSON."""
        change_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        change_type = data.get("change_type", "new_requirement")
        if change_type not in _VALID_CHANGE_TYPES:
            change_type = "new_requirement"
        impact_level = data.get("impact_level", "medium")
        if impact_level not in _VALID_IMPACT_LEVELS:
            impact_level = "medium"

        affected_domains = data.get("affected_domains", [])
        if isinstance(affected_domains, str):
            try:
                affected_domains = json.loads(affected_domains)
            except (json.JSONDecodeError, ValueError):
                affected_domains = []

        record = {
            "change_id": change_id,
            "org_id": org_id,
            "reg_id": reg_id,
            "change_type": change_type,
            "title": data["title"],
            "description": data.get("description", ""),
            "impact_level": impact_level,
            "affected_domains": json.dumps(affected_domains),
            "published_at": data.get("published_at", now),
            "effective_at": data.get("effective_at", now),
            "action_required": 1 if data.get("action_required", True) else 0,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO regulatory_changes
                       (change_id, org_id, reg_id, change_type, title, description,
                        impact_level, affected_domains, published_at, effective_at, action_required)
                       VALUES (:change_id, :org_id, :reg_id, :change_type, :title, :description,
                               :impact_level, :affected_domains, :published_at, :effective_at,
                               :action_required)""",
                    record,
                )
        out = dict(record)
        out["affected_domains"] = affected_domains
        _logger.info("Added change %s (%s) for org %s", change_id, record["title"], org_id)
        return out

    def list_changes(
        self,
        org_id: str,
        impact_level: Optional[str] = None,
        action_required: bool = True,
    ) -> List[Dict[str, Any]]:
        """List changes ordered by effective_at ascending."""
        query = "SELECT * FROM regulatory_changes WHERE org_id = ?"
        params: List[Any] = [org_id]
        if impact_level:
            query += " AND impact_level = ?"
            params.append(impact_level)
        if action_required:
            query += " AND action_required = 1"
        query += " ORDER BY effective_at ASC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            rec = dict(r)
            try:
                rec["affected_domains"] = json.loads(rec.get("affected_domains") or "[]")
            except (json.JSONDecodeError, ValueError):
                rec["affected_domains"] = []
            result.append(rec)
        return result

    def get_upcoming_changes(self, org_id: str, days_ahead: int = 90) -> List[Dict[str, Any]]:
        """Return changes where effective_at is within the next days_ahead days."""
        now = datetime.now(timezone.utc)
        horizon = (now + timedelta(days=days_ahead)).isoformat()
        now_iso = now.isoformat()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT * FROM regulatory_changes
                       WHERE org_id = ? AND effective_at >= ? AND effective_at <= ?
                       ORDER BY effective_at ASC""",
                    (org_id, now_iso, horizon),
                ).fetchall()
        result = []
        for r in rows:
            rec = dict(r)
            try:
                rec["affected_domains"] = json.loads(rec.get("affected_domains") or "[]")
            except (json.JSONDecodeError, ValueError):
                rec["affected_domains"] = []
            result.append(rec)
        return result

    # ------------------------------------------------------------------
    # Compliance Obligations
    # ------------------------------------------------------------------

    def add_obligation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a compliance obligation linked to a regulation (and optionally a change)."""
        obligation_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        obligation_type = data.get("obligation_type", "technical")
        if obligation_type not in _VALID_OBLIGATION_TYPES:
            obligation_type = "technical"
        status = data.get("status", "pending")
        if status not in _VALID_OBLIGATION_STATUSES:
            status = "pending"

        record = {
            "obligation_id": obligation_id,
            "org_id": org_id,
            "reg_id": data["reg_id"],
            "change_id": data.get("change_id"),
            "title": data["title"],
            "description": data.get("description", ""),
            "obligation_type": obligation_type,
            "deadline": data.get("deadline", ""),
            "status": status,
            "owner": data.get("owner", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO compliance_obligations
                       (obligation_id, org_id, reg_id, change_id, title, description,
                        obligation_type, deadline, status, owner, created_at)
                       VALUES (:obligation_id, :org_id, :reg_id, :change_id, :title, :description,
                               :obligation_type, :deadline, :status, :owner, :created_at)""",
                    record,
                )
        _logger.info("Added obligation %s for org %s", obligation_id, org_id)
        return record

    def list_obligations(
        self,
        org_id: str,
        status: Optional[str] = None,
        deadline_before: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List obligations, optionally filtered by status and/or deadline_before (ISO date)."""
        query = "SELECT * FROM compliance_obligations WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        if deadline_before:
            query += " AND deadline <= ?"
            params.append(deadline_before)
        query += " ORDER BY deadline ASC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_obligation_status(
        self,
        org_id: str,
        obligation_id: str,
        status: str,
        owner: Optional[str] = None,
    ) -> bool:
        """Update obligation status (and optionally owner). Returns True if updated."""
        if status not in _VALID_OBLIGATION_STATUSES:
            return False
        with self._lock:
            with self._conn() as conn:
                if owner is not None:
                    result = conn.execute(
                        """UPDATE compliance_obligations
                           SET status = ?, owner = ?
                           WHERE org_id = ? AND obligation_id = ?""",
                        (status, owner, org_id, obligation_id),
                    )
                else:
                    result = conn.execute(
                        """UPDATE compliance_obligations
                           SET status = ?
                           WHERE org_id = ? AND obligation_id = ?""",
                        (status, org_id, obligation_id),
                    )
                return result.rowcount > 0

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def record_assessment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a compliance assessment for a regulation."""
        assessment_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record = {
            "assessment_id": assessment_id,
            "org_id": org_id,
            "reg_id": data["reg_id"],
            "assessed_at": data.get("assessed_at", now),
            "compliance_pct": float(data.get("compliance_pct", 0.0)),
            "gaps_count": int(data.get("gaps_count", 0)),
            "critical_gaps": int(data.get("critical_gaps", 0)),
            "assessor": data.get("assessor", ""),
            "notes": data.get("notes", ""),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO reg_assessments
                       (assessment_id, org_id, reg_id, assessed_at, compliance_pct,
                        gaps_count, critical_gaps, assessor, notes)
                       VALUES (:assessment_id, :org_id, :reg_id, :assessed_at, :compliance_pct,
                               :gaps_count, :critical_gaps, :assessor, :notes)""",
                    record,
                )
        _logger.info("Recorded assessment %s for org %s", assessment_id, org_id)
        return record

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_regulatory_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Aggregate stats for an org:
        - total_regulations, active_regulations (status=enacted)
        - pending_changes (action_required), critical_changes
        - overdue_obligations (deadline < today AND status NOT compliant/exempt)
        - avg_compliance_pct (from assessments)
        - upcoming_changes_90d
        """
        today = date.today().isoformat()
        now = datetime.now(timezone.utc)
        horizon_90 = (now + timedelta(days=90)).isoformat()
        now_iso = now.isoformat()

        with self._lock:
            with self._conn() as conn:
                total_regulations = conn.execute(
                    "SELECT COUNT(*) FROM regulations WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                active_regulations = conn.execute(
                    "SELECT COUNT(*) FROM regulations WHERE org_id = ? AND status = 'enacted'",
                    (org_id,),
                ).fetchone()[0]

                pending_changes = conn.execute(
                    "SELECT COUNT(*) FROM regulatory_changes WHERE org_id = ? AND action_required = 1",
                    (org_id,),
                ).fetchone()[0]

                critical_changes = conn.execute(
                    "SELECT COUNT(*) FROM regulatory_changes WHERE org_id = ? AND impact_level = 'critical'",
                    (org_id,),
                ).fetchone()[0]

                overdue_obligations = conn.execute(
                    """SELECT COUNT(*) FROM compliance_obligations
                       WHERE org_id = ? AND deadline != '' AND deadline < ?
                         AND status NOT IN ('compliant', 'exempt')""",
                    (org_id, today),
                ).fetchone()[0]

                avg_row = conn.execute(
                    "SELECT AVG(compliance_pct) FROM reg_assessments WHERE org_id = ?",
                    (org_id,),
                ).fetchone()
                avg_compliance_pct = float(avg_row[0]) if avg_row[0] is not None else 0.0

                upcoming_changes_90d = conn.execute(
                    """SELECT COUNT(*) FROM regulatory_changes
                       WHERE org_id = ? AND effective_at >= ? AND effective_at <= ?""",
                    (org_id, now_iso, horizon_90),
                ).fetchone()[0]

        return {
            "org_id": org_id,
            "total_regulations": total_regulations,
            "active_regulations": active_regulations,
            "pending_changes": pending_changes,
            "critical_changes": critical_changes,
            "overdue_obligations": overdue_obligations,
            "avg_compliance_pct": round(avg_compliance_pct, 2),
            "upcoming_changes_90d": upcoming_changes_90d,
        }
