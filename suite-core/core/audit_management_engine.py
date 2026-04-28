"""Audit Management Engine — ALDECI.

Manages audit lifecycle: planning, execution, findings, resolution.

Features:
- Audit registration with type/scope/auditor classification
- Audit lifecycle: planned → in_progress → completed
- Finding recording with severity/category tracking
- Finding resolution workflow
- Stats: by_type, by_status, resolution rate, critical finding count
- Org isolation enforced on all queries

Compliance: ISO 27001 A.18, SOC 2, PCI-DSS Req 12, NIST SP 800-53 CA-2
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

from pydantic import BaseModel

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / ".fixops_data" / "audit_management.db")

_VALID_AUDIT_TYPES = {
    "internal", "external", "compliance", "security", "financial", "operational"
}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_CATEGORIES = {
    "access_control", "data_protection", "config", "process", "compliance", "technical"
}


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class AuditCreate(BaseModel):
    name: str
    audit_type: str  # internal/external/compliance/security/financial/operational
    scope: str
    auditor: str
    planned_date: str


class FindingCreate(BaseModel):
    title: str
    severity: str  # low/medium/high/critical
    category: str  # access_control/data_protection/config/process/compliance/technical
    description: str


class FindingResolve(BaseModel):
    resolution: str
    resolved_by: str


class AuditComplete(BaseModel):
    summary: str


# ============================================================================
# AUDIT MANAGEMENT ENGINE
# ============================================================================


class AuditManagementEngine:
    """Audit lifecycle management engine — audits, findings, resolution."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_exports (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    framework         TEXT NOT NULL DEFAULT '',
                    export_filter     TEXT NOT NULL DEFAULT '{}',
                    verification_id   TEXT NOT NULL DEFAULT '',
                    recorded_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_exports_org
                    ON audit_exports(org_id, framework, recorded_at);

                CREATE TABLE IF NOT EXISTS audits (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    audit_type      TEXT NOT NULL,
                    scope           TEXT NOT NULL,
                    auditor         TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'planned',
                    planned_date    TEXT NOT NULL,
                    started_at      TEXT,
                    completed_at    TEXT,
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    summary         TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    audit_id        TEXT NOT NULL,
                    title           TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    category        TEXT NOT NULL,
                    description     TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'open',
                    resolution      TEXT,
                    resolved_by     TEXT,
                    found_at        TEXT NOT NULL,
                    resolved_at     TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_audits_org    ON audits(org_id);
                CREATE INDEX IF NOT EXISTS idx_findings_org  ON findings(org_id);
                CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # AUDITS
    # ------------------------------------------------------------------

    def create_audit(self, org_id: str, data: AuditCreate) -> Dict[str, Any]:
        """Create a new audit in planned status."""
        if not data.name:
            raise ValueError("name is required")
        if data.audit_type not in _VALID_AUDIT_TYPES:
            raise ValueError(
                f"audit_type must be one of: {sorted(_VALID_AUDIT_TYPES)}"
            )
        if not data.scope:
            raise ValueError("scope is required")
        if not data.auditor:
            raise ValueError("auditor is required")
        if not data.planned_date:
            raise ValueError("planned_date is required")

        audit_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO audits
                   (id, org_id, name, audit_type, scope, auditor,
                    status, planned_date, started_at, completed_at,
                    findings_count, summary, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    audit_id, org_id, data.name, data.audit_type,
                    data.scope, data.auditor,
                    "planned", data.planned_date, None, None,
                    0, None, now,
                ),
            )
        _logger.info("audit.created org=%s id=%s", org_id, audit_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "audit_management", "org_id": org_id, "source_engine": "audit_management"})
            except Exception:
                pass

        return self.get_audit(org_id, audit_id)

    def list_audits(
        self,
        org_id: str,
        audit_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List audits for org, optionally filtered."""
        query = "SELECT * FROM audits WHERE org_id=?"
        params: List[Any] = [org_id]
        if audit_type:
            query += " AND audit_type=?"
            params.append(audit_type)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_audit(self, org_id: str, audit_id: str) -> Dict[str, Any]:
        """Fetch a single audit scoped to org_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM audits WHERE org_id=? AND id=?",
                (org_id, audit_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Audit {audit_id} not found for org {org_id}")
        return dict(row)

    def start_audit(self, org_id: str, audit_id: str) -> Dict[str, Any]:
        """Transition audit to in_progress status."""
        self.get_audit(org_id, audit_id)
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE audits SET status='in_progress', started_at=?
                   WHERE org_id=? AND id=?""",
                (now, org_id, audit_id),
            )
        _logger.info("audit.started org=%s id=%s", org_id, audit_id)
        return self.get_audit(org_id, audit_id)

    def complete_audit(self, org_id: str, audit_id: str, summary: str) -> Dict[str, Any]:
        """Mark audit as completed with a summary."""
        self.get_audit(org_id, audit_id)
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE audits SET status='completed', completed_at=?, summary=?
                   WHERE org_id=? AND id=?""",
                (now, summary, org_id, audit_id),
            )
        _logger.info("audit.completed org=%s id=%s", org_id, audit_id)
        return self.get_audit(org_id, audit_id)

    # ------------------------------------------------------------------
    # FINDINGS
    # ------------------------------------------------------------------

    def record_finding(
        self, org_id: str, audit_id: str, data: FindingCreate
    ) -> Dict[str, Any]:
        """Record a new finding against an audit. Increments audit findings_count."""
        # Verify audit belongs to org
        self.get_audit(org_id, audit_id)

        if not data.title:
            raise ValueError("title is required")
        if data.severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of: {sorted(_VALID_SEVERITIES)}")
        if data.category not in _VALID_CATEGORIES:
            raise ValueError(f"category must be one of: {sorted(_VALID_CATEGORIES)}")

        finding_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO findings
                   (id, org_id, audit_id, title, severity, category,
                    description, status, resolution, resolved_by, found_at, resolved_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    finding_id, org_id, audit_id, data.title,
                    data.severity, data.category, data.description,
                    "open", None, None, now, None,
                ),
            )
            conn.execute(
                """UPDATE audits SET findings_count = findings_count + 1
                   WHERE org_id=? AND id=?""",
                (org_id, audit_id),
            )
        _logger.info("audit.finding_recorded org=%s audit=%s finding=%s", org_id, audit_id, finding_id)
        return self._get_finding(org_id, finding_id)

    def resolve_finding(
        self, org_id: str, finding_id: str, resolution: str, resolved_by: str
    ) -> Dict[str, Any]:
        """Resolve a finding with resolution text and resolver identity."""
        self._get_finding(org_id, finding_id)
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE findings
                   SET status='resolved', resolution=?, resolved_by=?, resolved_at=?
                   WHERE org_id=? AND id=?""",
                (resolution, resolved_by, now, org_id, finding_id),
            )
        _logger.info("audit.finding_resolved org=%s id=%s by=%s", org_id, finding_id, resolved_by)
        return self._get_finding(org_id, finding_id)

    def _get_finding(self, org_id: str, finding_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE org_id=? AND id=?",
                (org_id, finding_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Finding {finding_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_audit_stats(self, org_id: str) -> Dict[str, Any]:
        """Return audit statistics for the org."""
        with self._connect() as conn:
            audits = conn.execute(
                "SELECT * FROM audits WHERE org_id=?", (org_id,)
            ).fetchall()
            findings = conn.execute(
                "SELECT severity, status FROM findings WHERE org_id=?", (org_id,)
            ).fetchall()

        total_audits = len(audits)
        by_type: Dict[str, int] = {}
        by_status: Dict[str, int] = {}

        for a in audits:
            atype = a["audit_type"]
            astatus = a["status"]
            by_type[atype] = by_type.get(atype, 0) + 1
            by_status[astatus] = by_status.get(astatus, 0) + 1

        total_findings = len(findings)
        open_findings = sum(1 for f in findings if f["status"] == "open")
        critical_findings = sum(1 for f in findings if f["severity"] == "critical")
        resolved_findings = sum(1 for f in findings if f["status"] == "resolved")
        resolution_rate = round(
            resolved_findings / total_findings * 100, 2
        ) if total_findings > 0 else 0.0

        return {
            "total_audits": total_audits,
            "by_type": by_type,
            "by_status": by_status,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "resolution_rate": resolution_rate,
        }

    # ------------------------------------------------------------------
    # AUDIT EXPORT LINKAGE (GAP-040)
    # ------------------------------------------------------------------

    def record_audit_export(
        self,
        org_id: str,
        framework: str,
        export_filter: Dict[str, Any],
        verification_id: str,
    ) -> Dict[str, Any]:
        """Link an audit event (export) to a coverage verification record."""
        if not framework:
            raise ValueError("framework is required")
        if not verification_id:
            raise ValueError("verification_id is required")
        export_filter = export_filter or {}

        export_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO audit_exports
                   (id, org_id, framework, export_filter,
                    verification_id, recorded_at)
                   VALUES (?,?,?,?,?,?)""",
                (
                    export_id, org_id, framework,
                    json.dumps(export_filter, sort_keys=True, default=str),
                    verification_id, now,
                ),
            )
        _logger.info(
            "audit.export_recorded org=%s framework=%s verification=%s",
            org_id, framework, verification_id,
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "CONTROL_ASSESSED",
                        {
                            "entity_type": "audit_export",
                            "org_id": org_id,
                            "source_engine": "audit_management",
                            "framework": framework,
                            "verification_id": verification_id,
                        },
                    )
            except Exception:
                pass
        return {
            "id": export_id,
            "org_id": org_id,
            "framework": framework,
            "export_filter": export_filter,
            "verification_id": verification_id,
            "recorded_at": now,
        }

    def audit_export_history(
        self, org_id: str, framework: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return audit-export history for org, optionally filtered by framework."""
        query = "SELECT * FROM audit_exports WHERE org_id=?"
        params: List[Any] = [org_id]
        if framework:
            query += " AND framework=?"
            params.append(framework)
        query += " ORDER BY recorded_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["export_filter"] = json.loads(d.get("export_filter") or "{}")
            except (ValueError, TypeError):
                d["export_filter"] = {}
            out.append(d)
        return out
