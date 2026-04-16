"""Governance, Risk & Compliance (GRC) Engine — ALDECI.

Unified GRC platform covering:
  - Framework management (SOC2, ISO27001, NIST-CSF, PCI-DSS, HIPAA, GDPR, CIS)
  - Control tracking with evidence and status lifecycle
  - Risk register with likelihood × impact scoring
  - Assessment management (draft → in_progress → completed → approved)

Compliance: ISO 27001:2022, NIST SP 800-53, SOC 2 Type II
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "grc.db"
)

_VALID_FRAMEWORKS = {
    "SOC2", "ISO27001", "NIST-CSF", "PCI-DSS", "HIPAA", "GDPR", "CIS",
}
_VALID_CONTROL_STATUS = {
    "implemented", "partial", "not_implemented", "not_applicable",
}
_VALID_RISK_CATEGORIES = {
    "strategic", "operational", "compliance", "financial", "reputational",
}
_VALID_RISK_TREATMENTS = {"accept", "mitigate", "transfer", "avoid"}
_VALID_RISK_STATUSES = {"open", "mitigated", "accepted", "closed"}
_VALID_ASSESSMENT_STATUSES = {
    "draft", "in_progress", "completed", "approved",
}


class GRCEngine:
    """SQLite WAL-backed Governance, Risk & Compliance engine.

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
                CREATE TABLE IF NOT EXISTS grc_frameworks (
                    framework_id          TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    name                  TEXT NOT NULL,
                    version               TEXT NOT NULL DEFAULT '',
                    total_controls        INTEGER NOT NULL DEFAULT 0,
                    implemented_controls  INTEGER NOT NULL DEFAULT 0,
                    compliance_score      REAL NOT NULL DEFAULT 0.0,
                    last_assessed         DATETIME,
                    created_at            DATETIME NOT NULL,
                    updated_at            DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_grc_fw_org
                    ON grc_frameworks (org_id);

                CREATE TABLE IF NOT EXISTS grc_controls (
                    control_id    TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    framework_id  TEXT NOT NULL,
                    control_ref   TEXT NOT NULL DEFAULT '',
                    title         TEXT NOT NULL DEFAULT '',
                    description   TEXT NOT NULL DEFAULT '',
                    category      TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'not_implemented',
                    evidence_count INTEGER NOT NULL DEFAULT 0,
                    owner         TEXT NOT NULL DEFAULT '',
                    due_date      DATETIME,
                    evidence_notes TEXT NOT NULL DEFAULT '[]',
                    created_at    DATETIME NOT NULL,
                    updated_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_grc_ctrl_org
                    ON grc_controls (org_id, framework_id);

                CREATE INDEX IF NOT EXISTS idx_grc_ctrl_status
                    ON grc_controls (org_id, status);

                CREATE TABLE IF NOT EXISTS grc_risks (
                    risk_id    TEXT PRIMARY KEY,
                    org_id     TEXT NOT NULL,
                    title      TEXT NOT NULL,
                    category   TEXT NOT NULL DEFAULT 'operational',
                    likelihood INTEGER NOT NULL DEFAULT 3,
                    impact     INTEGER NOT NULL DEFAULT 3,
                    risk_score INTEGER NOT NULL DEFAULT 9,
                    treatment  TEXT NOT NULL DEFAULT 'mitigate',
                    owner      TEXT NOT NULL DEFAULT '',
                    status     TEXT NOT NULL DEFAULT 'open',
                    notes      TEXT NOT NULL DEFAULT '',
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_grc_risk_org
                    ON grc_risks (org_id, status);

                CREATE TABLE IF NOT EXISTS grc_assessments (
                    assessment_id   TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    framework_id    TEXT NOT NULL,
                    assessor        TEXT NOT NULL DEFAULT '',
                    assessment_date DATETIME NOT NULL,
                    scope           TEXT NOT NULL DEFAULT '',
                    overall_score   REAL NOT NULL DEFAULT 0.0,
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    status          TEXT NOT NULL DEFAULT 'draft',
                    created_at      DATETIME NOT NULL,
                    updated_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_grc_assess_org
                    ON grc_assessments (org_id, framework_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _recalc_framework_score(
        self, conn: sqlite3.Connection, org_id: str, framework_id: str
    ) -> None:
        """Recompute implemented_controls and compliance_score for a framework."""
        row = conn.execute(
            "SELECT COUNT(*) AS total FROM grc_controls WHERE org_id=? AND framework_id=?",
            (org_id, framework_id),
        ).fetchone()
        total = row["total"] if row else 0

        impl_row = conn.execute(
            "SELECT COUNT(*) AS impl FROM grc_controls "
            "WHERE org_id=? AND framework_id=? AND status='implemented'",
            (org_id, framework_id),
        ).fetchone()
        implemented = impl_row["impl"] if impl_row else 0

        score = round((implemented / total) * 100, 1) if total > 0 else 0.0
        conn.execute(
            "UPDATE grc_frameworks SET total_controls=?, implemented_controls=?, "
            "compliance_score=?, updated_at=? WHERE framework_id=? AND org_id=?",
            (total, implemented, score, self._now(), framework_id, org_id),
        )

    # ------------------------------------------------------------------
    # Frameworks
    # ------------------------------------------------------------------

    def add_framework(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new GRC framework entry."""
        framework_id = str(uuid.uuid4())
        now = self._now()
        name = data.get("name", "")
        version = data.get("version", "1.0")
        last_assessed = data.get("last_assessed")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO grc_frameworks
                        (framework_id, org_id, name, version, total_controls,
                         implemented_controls, compliance_score, last_assessed,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        framework_id,
                        org_id,
                        name,
                        version,
                        int(data.get("total_controls", 0)),
                        int(data.get("implemented_controls", 0)),
                        float(data.get("compliance_score", 0.0)),
                        last_assessed,
                        now,
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM grc_frameworks WHERE framework_id=?",
                    (framework_id,),
                ).fetchone()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "grc", "org_id": org_id, "source_engine": "grc"})
            except Exception:
                pass

        return self._row(row)

    def list_frameworks(self, org_id: str) -> List[Dict[str, Any]]:
        """List all frameworks for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM grc_frameworks WHERE org_id=? ORDER BY name ASC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def add_control(
        self,
        org_id: str,
        framework_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add a control to a framework."""
        control_id = str(uuid.uuid4())
        now = self._now()
        status = data.get("status", "not_implemented")
        if status not in _VALID_CONTROL_STATUS:
            status = "not_implemented"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO grc_controls
                        (control_id, org_id, framework_id, control_ref, title,
                         description, category, status, evidence_count, owner,
                         due_date, evidence_notes, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        control_id,
                        org_id,
                        framework_id,
                        data.get("control_ref", ""),
                        data.get("title", ""),
                        data.get("description", ""),
                        data.get("category", ""),
                        status,
                        int(data.get("evidence_count", 0)),
                        data.get("owner", ""),
                        data.get("due_date"),
                        json.dumps([]),
                        now,
                        now,
                    ),
                )
                self._recalc_framework_score(conn, org_id, framework_id)
                row = conn.execute(
                    "SELECT * FROM grc_controls WHERE control_id=?",
                    (control_id,),
                ).fetchone()
        d = self._row(row)
        d["evidence_notes"] = json.loads(d.get("evidence_notes") or "[]")
        return d

    def list_controls(
        self,
        org_id: str,
        framework_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List controls, optionally filtered by framework and/or status."""
        query = "SELECT * FROM grc_controls WHERE org_id=?"
        params: list = [org_id]
        if framework_id:
            query += " AND framework_id=?"
            params.append(framework_id)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY control_ref ASC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            d = self._row(r)
            d["evidence_notes"] = json.loads(d.get("evidence_notes") or "[]")
            result.append(d)
        return result

    def update_control_status(
        self,
        org_id: str,
        control_id: str,
        status: str,
        evidence_note: Optional[str] = None,
    ) -> bool:
        """Update a control's status and optionally append an evidence note."""
        if status not in _VALID_CONTROL_STATUS:
            return False

        now = self._now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM grc_controls WHERE control_id=? AND org_id=?",
                    (control_id, org_id),
                ).fetchone()
                if not row:
                    return False

                notes = json.loads(row["evidence_notes"] or "[]")
                if evidence_note:
                    notes.append({"note": evidence_note, "timestamp": now})
                    evidence_count = row["evidence_count"] + 1
                else:
                    evidence_count = row["evidence_count"]

                conn.execute(
                    "UPDATE grc_controls SET status=?, evidence_notes=?, "
                    "evidence_count=?, updated_at=? WHERE control_id=? AND org_id=?",
                    (
                        status,
                        json.dumps(notes),
                        evidence_count,
                        now,
                        control_id,
                        org_id,
                    ),
                )
                self._recalc_framework_score(conn, org_id, row["framework_id"])
        return True

    # ------------------------------------------------------------------
    # Risks
    # ------------------------------------------------------------------

    def add_risk(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a risk to the register."""
        risk_id = str(uuid.uuid4())
        now = self._now()

        category = data.get("category", "operational")
        if category not in _VALID_RISK_CATEGORIES:
            category = "operational"

        treatment = data.get("treatment", "mitigate")
        if treatment not in _VALID_RISK_TREATMENTS:
            treatment = "mitigate"

        status = data.get("status", "open")
        if status not in _VALID_RISK_STATUSES:
            status = "open"

        likelihood = max(1, min(5, int(data.get("likelihood", 3))))
        impact = max(1, min(5, int(data.get("impact", 3))))
        risk_score = likelihood * impact

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO grc_risks
                        (risk_id, org_id, title, category, likelihood, impact,
                         risk_score, treatment, owner, status, notes,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        risk_id,
                        org_id,
                        data.get("title", ""),
                        category,
                        likelihood,
                        impact,
                        risk_score,
                        treatment,
                        data.get("owner", ""),
                        status,
                        data.get("notes", ""),
                        now,
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM grc_risks WHERE risk_id=?",
                    (risk_id,),
                ).fetchone()
        return self._row(row)

    def list_risks(
        self,
        org_id: str,
        status: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List risks, optionally filtered by status and/or category."""
        query = "SELECT * FROM grc_risks WHERE org_id=?"
        params: list = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if category:
            query += " AND category=?"
            params.append(category)
        query += " ORDER BY risk_score DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def update_risk(
        self, org_id: str, risk_id: str, data: Dict[str, Any]
    ) -> bool:
        """Partially update a risk record."""
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM grc_risks WHERE risk_id=? AND org_id=?",
                    (risk_id, org_id),
                ).fetchone()
                if not row:
                    return False

                existing = dict(row)
                likelihood = max(
                    1,
                    min(5, int(data.get("likelihood", existing["likelihood"]))),
                )
                impact = max(
                    1, min(5, int(data.get("impact", existing["impact"])))
                )
                risk_score = likelihood * impact

                category = data.get("category", existing["category"])
                if category not in _VALID_RISK_CATEGORIES:
                    category = existing["category"]

                treatment = data.get("treatment", existing["treatment"])
                if treatment not in _VALID_RISK_TREATMENTS:
                    treatment = existing["treatment"]

                status = data.get("status", existing["status"])
                if status not in _VALID_RISK_STATUSES:
                    status = existing["status"]

                conn.execute(
                    """
                    UPDATE grc_risks SET
                        title=?, category=?, likelihood=?, impact=?,
                        risk_score=?, treatment=?, owner=?, status=?,
                        notes=?, updated_at=?
                    WHERE risk_id=? AND org_id=?
                    """,
                    (
                        data.get("title", existing["title"]),
                        category,
                        likelihood,
                        impact,
                        risk_score,
                        treatment,
                        data.get("owner", existing["owner"]),
                        status,
                        data.get("notes", existing["notes"]),
                        now,
                        risk_id,
                        org_id,
                    ),
                )
        return True

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a new GRC assessment."""
        assessment_id = str(uuid.uuid4())
        now = self._now()

        status = data.get("status", "draft")
        if status not in _VALID_ASSESSMENT_STATUSES:
            status = "draft"

        assessment_date = data.get("assessment_date", now)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO grc_assessments
                        (assessment_id, org_id, framework_id, assessor,
                         assessment_date, scope, overall_score, findings_count,
                         status, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        assessment_id,
                        org_id,
                        data.get("framework_id", ""),
                        data.get("assessor", ""),
                        assessment_date,
                        data.get("scope", ""),
                        float(data.get("overall_score", 0.0)),
                        int(data.get("findings_count", 0)),
                        status,
                        now,
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM grc_assessments WHERE assessment_id=?",
                    (assessment_id,),
                ).fetchone()
        return self._row(row)

    def list_assessments(
        self, org_id: str, framework_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List assessments for an org."""
        query = "SELECT * FROM grc_assessments WHERE org_id=?"
        params: list = [org_id]
        if framework_id:
            query += " AND framework_id=?"
            params.append(framework_id)
        query += " ORDER BY assessment_date DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_grc_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated GRC statistics for an org."""
        with self._conn() as conn:
            fw_row = conn.execute(
                "SELECT COUNT(*) AS cnt, AVG(compliance_score) AS avg_score "
                "FROM grc_frameworks WHERE org_id=?",
                (org_id,),
            ).fetchone()

            open_risks = conn.execute(
                "SELECT COUNT(*) AS cnt FROM grc_risks WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()

            ctrl_row = conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN status='implemented' THEN 1 ELSE 0 END) AS impl "
                "FROM grc_controls WHERE org_id=?",
                (org_id,),
            ).fetchone()

            assess_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM grc_assessments "
                "WHERE org_id=? AND status='completed'",
                (org_id,),
            ).fetchone()

        total_ctrls = ctrl_row["total"] or 0
        impl_ctrls = ctrl_row["impl"] or 0
        impl_pct = round((impl_ctrls / total_ctrls) * 100, 1) if total_ctrls > 0 else 0.0

        return {
            "frameworks_count": fw_row["cnt"] or 0,
            "avg_compliance_score": round(fw_row["avg_score"] or 0.0, 1),
            "open_risks": open_risks["cnt"] or 0,
            "controls_implemented_pct": impl_pct,
            "assessments_completed": assess_row["cnt"] or 0,
        }
