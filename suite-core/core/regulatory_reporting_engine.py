"""Regulatory Reporting Engine — ALDECI.

Manages regulatory compliance tracking and report lifecycle.

Features:
- Regulation registry with type/jurisdiction classification
- Compliance score tracking with maturity level derivation
- Report lifecycle: draft → submitted
- Stats: compliance distribution, submission rates, org isolation

Compliance: GDPR, HIPAA, PCI-DSS, SOX, ISO 27001, NIST, CCPA, FedRAMP
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

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / ".fixops_data" / "regulatory_reporting.db")

_VALID_REGULATION_TYPES = {
    "gdpr", "hipaa", "pci_dss", "sox", "iso27001", "nist", "ccpa", "fedramp", "custom"
}
_VALID_REPORT_TYPES = {
    "annual", "quarterly", "monthly", "incident", "audit", "self_assessment"
}


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class RegulationCreate(BaseModel):
    name: str
    regulation_type: str  # gdpr/hipaa/pci_dss/sox/iso27001/nist/ccpa/fedramp/custom
    jurisdiction: str = "global"
    notes: Optional[str] = None


class ComplianceScoreUpdate(BaseModel):
    score: float
    notes: str = ""


class ReportCreate(BaseModel):
    regulation_id: str
    report_type: str  # annual/quarterly/monthly/incident/audit/self_assessment
    period_start: str
    period_end: str
    report_data: Optional[Dict[str, Any]] = None


class ReportSubmit(BaseModel):
    submitted_by: str


# ============================================================================
# REGULATORY REPORTING ENGINE
# ============================================================================


class RegulatoryReportingEngine:
    """Regulatory compliance tracking and report lifecycle engine."""

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
                CREATE TABLE IF NOT EXISTS regulations (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL,
                    regulation_type   TEXT NOT NULL,
                    jurisdiction      TEXT NOT NULL DEFAULT 'global',
                    compliance_score  REAL NOT NULL DEFAULT 0,
                    compliance_level  TEXT NOT NULL DEFAULT 'non_compliant',
                    notes             TEXT NOT NULL DEFAULT '',
                    status            TEXT NOT NULL DEFAULT 'active',
                    assessed_at       TEXT,
                    created_at        TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    regulation_id   TEXT NOT NULL,
                    report_type     TEXT NOT NULL,
                    period_start    TEXT NOT NULL,
                    period_end      TEXT NOT NULL,
                    report_data     TEXT NOT NULL DEFAULT '{}',
                    status          TEXT NOT NULL DEFAULT 'draft',
                    submitted_by    TEXT,
                    submitted_at    TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_regulations_org ON regulations(org_id);
                CREATE INDEX IF NOT EXISTS idx_reports_org     ON reports(org_id);
                CREATE INDEX IF NOT EXISTS idx_reports_reg     ON reports(regulation_id);
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

    @staticmethod
    def _derive_compliance_level(score: float) -> str:
        if score >= 90:
            return "compliant"
        if score >= 70:
            return "mostly_compliant"
        if score >= 50:
            return "partially_compliant"
        return "non_compliant"

    # ------------------------------------------------------------------
    # REGULATIONS
    # ------------------------------------------------------------------

    def register_regulation(self, org_id: str, data: RegulationCreate) -> Dict[str, Any]:
        """Register a new regulation. Returns the regulation record."""
        if not data.name:
            raise ValueError("name is required")
        if data.regulation_type not in _VALID_REGULATION_TYPES:
            raise ValueError(
                f"regulation_type must be one of: {sorted(_VALID_REGULATION_TYPES)}"
            )
        reg_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO regulations
                   (id, org_id, name, regulation_type, jurisdiction,
                    compliance_score, compliance_level, notes, status, assessed_at, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    reg_id, org_id, data.name, data.regulation_type,
                    data.jurisdiction or "global",
                    0, "non_compliant",
                    data.notes or "", "active", None, now,
                ),
            )
        _logger.info("regulatory.regulation_registered org=%s id=%s", org_id, reg_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "regulatory_reporting", "org_id": org_id, "source_engine": "regulatory_reporting"})
            except Exception:
                pass

        return self._get_regulation(org_id, reg_id)

    def list_regulations(
        self,
        org_id: str,
        regulation_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List regulations for org, optionally filtered by regulation_type."""
        query = "SELECT * FROM regulations WHERE org_id=?"
        params: List[Any] = [org_id]
        if regulation_type:
            query += " AND regulation_type=?"
            params.append(regulation_type)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def _get_regulation(self, org_id: str, reg_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM regulations WHERE org_id=? AND id=?",
                (org_id, reg_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Regulation {reg_id} not found for org {org_id}")
        return dict(row)

    def update_compliance_score(
        self, org_id: str, reg_id: str, score: float, notes: str = ""
    ) -> Dict[str, Any]:
        """Update compliance score (clamped 0-100) and derive compliance level."""
        # Verify exists and org scoped
        self._get_regulation(org_id, reg_id)
        score = max(0.0, min(100.0, score))
        level = self._derive_compliance_level(score)
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE regulations
                   SET compliance_score=?, compliance_level=?, notes=?, assessed_at=?
                   WHERE org_id=? AND id=?""",
                (score, level, notes, now, org_id, reg_id),
            )
        _logger.info(
            "regulatory.score_updated org=%s id=%s score=%.1f level=%s",
            org_id, reg_id, score, level,
        )
        return self._get_regulation(org_id, reg_id)

    # ------------------------------------------------------------------
    # REPORTS
    # ------------------------------------------------------------------

    def create_report(self, org_id: str, data: ReportCreate) -> Dict[str, Any]:
        """Create a new compliance report in draft status."""
        if data.report_type not in _VALID_REPORT_TYPES:
            raise ValueError(
                f"report_type must be one of: {sorted(_VALID_REPORT_TYPES)}"
            )
        # Validate regulation belongs to org
        self._get_regulation(org_id, data.regulation_id)
        report_id = str(uuid.uuid4())
        now = self._now()
        report_data_str = json.dumps(data.report_data or {})
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO reports
                   (id, org_id, regulation_id, report_type, period_start, period_end,
                    report_data, status, submitted_by, submitted_at, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    report_id, org_id, data.regulation_id, data.report_type,
                    data.period_start, data.period_end,
                    report_data_str, "draft", None, None, now,
                ),
            )
        _logger.info("regulatory.report_created org=%s id=%s", org_id, report_id)
        return self._get_report(org_id, report_id)

    def submit_report(
        self, org_id: str, report_id: str, submitted_by: str
    ) -> Dict[str, Any]:
        """Submit a draft report."""
        self._get_report(org_id, report_id)
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE reports
                   SET status='submitted', submitted_by=?, submitted_at=?
                   WHERE org_id=? AND id=?""",
                (submitted_by, now, org_id, report_id),
            )
        _logger.info("regulatory.report_submitted org=%s id=%s by=%s", org_id, report_id, submitted_by)
        return self._get_report(org_id, report_id)

    def list_reports(
        self,
        org_id: str,
        regulation_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List reports for org, optionally filtered."""
        query = "SELECT * FROM reports WHERE org_id=?"
        params: List[Any] = [org_id]
        if regulation_id:
            query += " AND regulation_id=?"
            params.append(regulation_id)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            rec = dict(r)
            try:
                rec["report_data"] = json.loads(rec["report_data"])
            except (json.JSONDecodeError, TypeError):
                rec["report_data"] = {}
            results.append(rec)
        return results

    def _get_report(self, org_id: str, report_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM reports WHERE org_id=? AND id=?",
                (org_id, report_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Report {report_id} not found for org {org_id}")
        rec = dict(row)
        try:
            rec["report_data"] = json.loads(rec["report_data"])
        except (json.JSONDecodeError, TypeError):
            rec["report_data"] = {}
        return rec

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_regulatory_stats(self, org_id: str) -> Dict[str, Any]:
        """Return regulatory compliance statistics for the org."""
        with self._connect() as conn:
            regs = conn.execute(
                "SELECT * FROM regulations WHERE org_id=?", (org_id,)
            ).fetchall()
            rpts = conn.execute(
                "SELECT status FROM reports WHERE org_id=?", (org_id,)
            ).fetchall()

        total_regulations = len(regs)
        by_type: Dict[str, int] = {}
        scores: List[float] = []
        compliant_count = 0
        non_compliant_count = 0

        for r in regs:
            rtype = r["regulation_type"]
            by_type[rtype] = by_type.get(rtype, 0) + 1
            score = r["compliance_score"]
            scores.append(score)
            if score >= 90:
                compliant_count += 1
            if score < 50:
                non_compliant_count += 1

        avg_compliance_score = round(sum(scores) / len(scores), 2) if scores else 0.0

        total_reports = len(rpts)
        submitted_reports = sum(1 for r in rpts if r["status"] == "submitted")
        pending_reports = sum(1 for r in rpts if r["status"] == "draft")

        return {
            "total_regulations": total_regulations,
            "by_type": by_type,
            "avg_compliance_score": avg_compliance_score,
            "compliant_count": compliant_count,
            "non_compliant_count": non_compliant_count,
            "total_reports": total_reports,
            "submitted_reports": submitted_reports,
            "pending_reports": pending_reports,
        }
