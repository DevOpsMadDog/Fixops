"""Privacy Impact Assessment Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

PIA/DPIA workflow tracking for GDPR/CCPA compliance:
  - Assessment lifecycle (draft → approved)
  - Risk scoring with likelihood × impact formula
  - Consultation tracking with required-completion guard
  - DPO approval workflow
  - High-risk assessment detection

Compliance: GDPR Art. 35, CCPA, ISO 29134
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2]
    / ".fixops_data"
    / "privacy_impact_assessment_engine.db"
)

_VALID_ASSESSMENT_TYPES = {"pia", "dpia", "lightweight"}
_VALID_LEGAL_BASES = {
    "consent", "contract", "legal_obligation",
    "vital_interests", "public_task", "legitimate_interests",
}
_VALID_RISK_CATEGORIES = {
    "unauthorized_access", "data_breach", "loss_of_data", "inaccurate_data",
    "purpose_limitation", "retention_violation", "cross_border_risk", "profiling_risk",
}
_VALID_LIKELIHOOD_IMPACT = {"low", "medium", "high", "critical"}
_VALID_RISK_STATUSES = {"open", "mitigated", "accepted", "transferred"}

_SCORE_MAP: Dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_risk_level(avg_score: float) -> str:
    if avg_score >= 9:
        return "critical"
    if avg_score >= 6:
        return "high"
    if avg_score >= 3:
        return "medium"
    return "low"


class PrivacyImpactAssessmentEngine:
    """SQLite WAL-backed PIA/DPIA engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/privacy_impact_assessment_engine.db
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
                CREATE TABLE IF NOT EXISTS pia_assessments (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    project_name            TEXT NOT NULL DEFAULT '',
                    assessment_type         TEXT NOT NULL DEFAULT 'pia',
                    data_controller         TEXT NOT NULL DEFAULT '',
                    data_processor          TEXT NOT NULL DEFAULT '',
                    legal_basis             TEXT NOT NULL DEFAULT '',
                    data_categories         TEXT NOT NULL DEFAULT '[]',
                    data_subjects           TEXT NOT NULL DEFAULT '[]',
                    retention_period_days   INTEGER NOT NULL DEFAULT 365,
                    cross_border_transfer   INTEGER NOT NULL DEFAULT 0,
                    status                  TEXT NOT NULL DEFAULT 'draft',
                    risk_score              REAL NOT NULL DEFAULT 0.0,
                    risk_level              TEXT NOT NULL DEFAULT 'medium',
                    dpo_approved            INTEGER NOT NULL DEFAULT 0,
                    created_at              TEXT,
                    approved_at             TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_pia_assessments_org
                    ON pia_assessments (org_id, status, risk_level);

                CREATE TABLE IF NOT EXISTS pia_risks (
                    id               TEXT PRIMARY KEY,
                    assessment_id    TEXT NOT NULL,
                    org_id           TEXT NOT NULL,
                    risk_category    TEXT NOT NULL DEFAULT '',
                    risk_description TEXT NOT NULL DEFAULT '',
                    likelihood       TEXT NOT NULL DEFAULT 'medium',
                    impact           TEXT NOT NULL DEFAULT 'medium',
                    risk_score       REAL NOT NULL DEFAULT 0.0,
                    mitigation       TEXT NOT NULL DEFAULT '',
                    residual_risk    TEXT NOT NULL DEFAULT 'medium',
                    status           TEXT NOT NULL DEFAULT 'open',
                    created_at       TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_pia_risks_org
                    ON pia_risks (org_id, assessment_id, status);

                CREATE TABLE IF NOT EXISTS pia_consultations (
                    id                TEXT PRIMARY KEY,
                    assessment_id     TEXT NOT NULL,
                    org_id            TEXT NOT NULL,
                    consulted_party   TEXT NOT NULL DEFAULT '',
                    consultation_type TEXT NOT NULL DEFAULT 'internal',
                    outcome           TEXT NOT NULL DEFAULT '',
                    required          INTEGER NOT NULL DEFAULT 0,
                    completed         INTEGER NOT NULL DEFAULT 0,
                    completed_at      TEXT,
                    created_at        TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_pia_consultations_org
                    ON pia_consultations (org_id, assessment_id, required, completed);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        org_id: str,
        project_name: str,
        assessment_type: str = "pia",
        data_controller: str = "",
        data_processor: str = "",
        legal_basis: str = "",
        data_categories: Optional[List[str]] = None,
        data_subjects: Optional[List[str]] = None,
        retention_period_days: int = 365,
        cross_border_transfer: bool = False,
    ) -> Dict[str, Any]:
        """Create a new PIA/DPIA assessment record."""
        if assessment_type not in _VALID_ASSESSMENT_TYPES:
            raise ValueError(
                f"Invalid assessment_type '{assessment_type}'. "
                f"Must be one of {sorted(_VALID_ASSESSMENT_TYPES)}"
            )
        if legal_basis and legal_basis not in _VALID_LEGAL_BASES:
            raise ValueError(
                f"Invalid legal_basis '{legal_basis}'. "
                f"Must be one of {sorted(_VALID_LEGAL_BASES)}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "project_name": project_name,
            "assessment_type": assessment_type,
            "data_controller": data_controller,
            "data_processor": data_processor,
            "legal_basis": legal_basis,
            "data_categories": json.dumps(data_categories or []),
            "data_subjects": json.dumps(data_subjects or []),
            "retention_period_days": retention_period_days,
            "cross_border_transfer": 1 if cross_border_transfer else 0,
            "status": "draft",
            "risk_score": 0.0,
            "risk_level": "medium",
            "dpo_approved": 0,
            "created_at": now,
            "approved_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO pia_assessments
                       (id, org_id, project_name, assessment_type, data_controller,
                        data_processor, legal_basis, data_categories, data_subjects,
                        retention_period_days, cross_border_transfer, status,
                        risk_score, risk_level, dpo_approved, created_at, approved_at)
                       VALUES (:id, :org_id, :project_name, :assessment_type,
                               :data_controller, :data_processor, :legal_basis,
                               :data_categories, :data_subjects, :retention_period_days,
                               :cross_border_transfer, :status, :risk_score, :risk_level,
                               :dpo_approved, :created_at, :approved_at)""",
                    record,
                )
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("CONTROL_ASSESSED", {
                    "org_id": org_id,
                    "entity": "privacy_impact_assessment",
                    "assessment_id": record["id"],
                    "project_name": project_name,
                    "assessment_type": assessment_type,
                })
            except Exception:
                pass
        return record

    def list_assessments(
        self,
        org_id: str,
        status: Optional[str] = None,
        assessment_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assessments with optional status/type filters."""
        sql = "SELECT * FROM pia_assessments WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if assessment_type:
            sql += " AND assessment_type = ?"
            params.append(assessment_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_assessment(
        self, assessment_id: str, org_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get assessment with its risks and consultations."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM pia_assessments WHERE id = ? AND org_id = ?",
                (assessment_id, org_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            risks = conn.execute(
                "SELECT * FROM pia_risks WHERE assessment_id = ? AND org_id = ? ORDER BY created_at",
                (assessment_id, org_id),
            ).fetchall()
            consultations = conn.execute(
                "SELECT * FROM pia_consultations WHERE assessment_id = ? AND org_id = ? ORDER BY created_at",
                (assessment_id, org_id),
            ).fetchall()
        result["risks"] = [self._row(r) for r in risks]
        result["consultations"] = [self._row(c) for c in consultations]
        return result

    def approve_assessment(
        self, assessment_id: str, org_id: str, dpo: str
    ) -> Dict[str, Any]:
        """DPO approval — validates all required consultations are completed first."""
        with self._lock:
            with self._conn() as conn:
                # Check all required consultations are completed
                incomplete = conn.execute(
                    """SELECT COUNT(*) FROM pia_consultations
                       WHERE assessment_id = ? AND org_id = ?
                         AND required = 1 AND completed = 0""",
                    (assessment_id, org_id),
                ).fetchone()[0]
                if incomplete > 0:
                    raise ValueError(
                        f"{incomplete} required consultation(s) are not yet completed."
                    )
                now = _now_iso()
                conn.execute(
                    """UPDATE pia_assessments
                       SET dpo_approved = 1, approved_at = ?, status = 'approved'
                       WHERE id = ? AND org_id = ?""",
                    (now, assessment_id, org_id),
                )
        result = self.get_assessment(assessment_id, org_id)
        if result is None:
            raise ValueError(f"Assessment {assessment_id} not found.")
        return result

    def get_high_risk_assessments(self, org_id: str) -> List[Dict[str, Any]]:
        """Return assessments with risk_level in (critical, high) ordered by risk_score DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM pia_assessments
                   WHERE org_id = ? AND risk_level IN ('critical', 'high')
                   ORDER BY risk_score DESC""",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated summary for the org."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM pia_assessments WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM pia_assessments WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

            type_rows = conn.execute(
                "SELECT assessment_type, COUNT(*) as cnt FROM pia_assessments WHERE org_id = ? GROUP BY assessment_type",
                (org_id,),
            ).fetchall()
            by_type = {r["assessment_type"]: r["cnt"] for r in type_rows}

            avg_risk = conn.execute(
                "SELECT AVG(risk_score) FROM pia_assessments WHERE org_id = ?", (org_id,)
            ).fetchone()[0] or 0.0

            high_risk_count = conn.execute(
                """SELECT COUNT(*) FROM pia_assessments
                   WHERE org_id = ? AND risk_level IN ('critical', 'high')""",
                (org_id,),
            ).fetchone()[0]

            pending_dpo = conn.execute(
                """SELECT COUNT(*) FROM pia_assessments
                   WHERE org_id = ? AND status = 'draft' AND risk_level IN ('high', 'critical')""",
                (org_id,),
            ).fetchone()[0]

        return {
            "total": total,
            "by_status": by_status,
            "by_type": by_type,
            "avg_risk_score": round(avg_risk, 4),
            "high_risk_count": high_risk_count,
            "pending_dpo_approval": pending_dpo,
        }

    # ------------------------------------------------------------------
    # Risks
    # ------------------------------------------------------------------

    def add_risk(
        self,
        assessment_id: str,
        org_id: str,
        risk_category: str,
        risk_description: str = "",
        likelihood: str = "medium",
        impact: str = "medium",
        mitigation: str = "",
        residual_risk: str = "medium",
    ) -> Dict[str, Any]:
        """Add a risk to an assessment and recompute assessment risk_score/risk_level."""
        if risk_category not in _VALID_RISK_CATEGORIES:
            raise ValueError(
                f"Invalid risk_category '{risk_category}'. "
                f"Must be one of {sorted(_VALID_RISK_CATEGORIES)}"
            )
        if likelihood not in _VALID_LIKELIHOOD_IMPACT:
            raise ValueError(
                f"Invalid likelihood '{likelihood}'. "
                f"Must be one of {sorted(_VALID_LIKELIHOOD_IMPACT)}"
            )
        if impact not in _VALID_LIKELIHOOD_IMPACT:
            raise ValueError(
                f"Invalid impact '{impact}'. "
                f"Must be one of {sorted(_VALID_LIKELIHOOD_IMPACT)}"
            )
        if residual_risk not in _VALID_LIKELIHOOD_IMPACT:
            raise ValueError(
                f"Invalid residual_risk '{residual_risk}'. "
                f"Must be one of {sorted(_VALID_LIKELIHOOD_IMPACT)}"
            )

        risk_score = float(_SCORE_MAP[likelihood] * _SCORE_MAP[impact])
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "assessment_id": assessment_id,
            "org_id": org_id,
            "risk_category": risk_category,
            "risk_description": risk_description,
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": risk_score,
            "mitigation": mitigation,
            "residual_risk": residual_risk,
            "status": "open",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO pia_risks
                       (id, assessment_id, org_id, risk_category, risk_description,
                        likelihood, impact, risk_score, mitigation, residual_risk,
                        status, created_at)
                       VALUES (:id, :assessment_id, :org_id, :risk_category,
                               :risk_description, :likelihood, :impact, :risk_score,
                               :mitigation, :residual_risk, :status, :created_at)""",
                    record,
                )
                # Recompute assessment risk_score and risk_level
                avg_row = conn.execute(
                    "SELECT AVG(risk_score) FROM pia_risks WHERE assessment_id = ? AND org_id = ?",
                    (assessment_id, org_id),
                ).fetchone()
                avg_score = avg_row[0] or 0.0
                new_level = _compute_risk_level(avg_score)
                conn.execute(
                    """UPDATE pia_assessments
                       SET risk_score = ?, risk_level = ?
                       WHERE id = ? AND org_id = ?""",
                    (round(avg_score, 4), new_level, assessment_id, org_id),
                )
        return record

    def update_risk_status(
        self, risk_id: str, org_id: str, status: str
    ) -> Optional[Dict[str, Any]]:
        """Update status for a specific risk."""
        if status not in _VALID_RISK_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. "
                f"Must be one of {sorted(_VALID_RISK_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE pia_risks SET status = ? WHERE id = ? AND org_id = ?",
                    (status, risk_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM pia_risks WHERE id = ? AND org_id = ?",
                    (risk_id, org_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Consultations
    # ------------------------------------------------------------------

    def add_consultation(
        self,
        assessment_id: str,
        org_id: str,
        consulted_party: str,
        consultation_type: str = "internal",
        required: bool = False,
    ) -> Dict[str, Any]:
        """Add a consultation record to an assessment."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "assessment_id": assessment_id,
            "org_id": org_id,
            "consulted_party": consulted_party,
            "consultation_type": consultation_type,
            "outcome": "",
            "required": 1 if required else 0,
            "completed": 0,
            "completed_at": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO pia_consultations
                       (id, assessment_id, org_id, consulted_party, consultation_type,
                        outcome, required, completed, completed_at, created_at)
                       VALUES (:id, :assessment_id, :org_id, :consulted_party,
                               :consultation_type, :outcome, :required, :completed,
                               :completed_at, :created_at)""",
                    record,
                )
        return record

    def complete_consultation(
        self, consultation_id: str, org_id: str, outcome: str
    ) -> Optional[Dict[str, Any]]:
        """Mark a consultation as completed with its outcome."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE pia_consultations
                       SET completed = 1, completed_at = ?, outcome = ?
                       WHERE id = ? AND org_id = ?""",
                    (now, outcome, consultation_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM pia_consultations WHERE id = ? AND org_id = ?",
                    (consultation_id, org_id),
                ).fetchone()
        return self._row(row) if row else None
