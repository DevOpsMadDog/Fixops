"""Security Questionnaire Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Manages vendor/third-party security assessments via structured questionnaires:
  - Create questionnaires with typed questions and scoring weights
  - Send assessments to vendors, track responses
  - Auto-score when all required questions are answered
  - Overdue detection and vendor risk summaries

Compliance: CAIQ, SIG, VSAQ, NIST, ISO 27001
"""
from __future__ import annotations

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_questionnaire_engine.db"
)

_VALID_QUESTIONNAIRE_TYPES = {
    "vendor", "internal", "partner", "cloud-provider", "third-party", "regulatory",
}
_VALID_FRAMEWORKS = {
    "CAIQ", "SIG", "VSAQ", "NIST", "ISO27001", "custom",
}
_VALID_QUESTION_CATEGORIES = {
    "access-control", "data-security", "incident-response", "network",
    "physical", "compliance", "governance", "business-continuity",
}
_VALID_STATUSES = {"sent", "completed", "cancelled", "overdue"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_risk_level(score: float) -> str:
    if score >= 80:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"


class SecurityQuestionnaireEngine:
    """SQLite WAL-backed Security Questionnaire engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_questionnaire_engine.db
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
                CREATE TABLE IF NOT EXISTS questionnaires (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    questionnaire_name  TEXT NOT NULL DEFAULT '',
                    questionnaire_type  TEXT NOT NULL DEFAULT 'vendor',
                    framework           TEXT NOT NULL DEFAULT 'custom',
                    question_count      INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_sq_questionnaires_org
                    ON questionnaires (org_id);

                CREATE TABLE IF NOT EXISTS questions (
                    id                  TEXT PRIMARY KEY,
                    questionnaire_id    TEXT NOT NULL,
                    org_id              TEXT NOT NULL,
                    question_text       TEXT NOT NULL DEFAULT '',
                    question_category   TEXT NOT NULL DEFAULT 'governance',
                    weight              REAL NOT NULL DEFAULT 1.0,
                    required            INTEGER NOT NULL DEFAULT 1,
                    created_at          TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_sq_questions_qid
                    ON questions (questionnaire_id, org_id);

                CREATE TABLE IF NOT EXISTS assessments (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    questionnaire_id    TEXT NOT NULL,
                    vendor_id           TEXT NOT NULL DEFAULT '',
                    vendor_name         TEXT NOT NULL DEFAULT '',
                    status              TEXT NOT NULL DEFAULT 'sent',
                    score               REAL,
                    risk_level          TEXT,
                    sent_at             TEXT,
                    completed_at        TEXT,
                    due_date            TEXT,
                    created_at          TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_sq_assessments_org
                    ON assessments (org_id, vendor_id, status);

                CREATE TABLE IF NOT EXISTS responses (
                    id              TEXT PRIMARY KEY,
                    assessment_id   TEXT NOT NULL,
                    question_id     TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    response_text   TEXT NOT NULL DEFAULT '',
                    response_value  INTEGER NOT NULL DEFAULT 0,
                    responded_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_sq_responses_assessment
                    ON responses (assessment_id, org_id);
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
    # Questionnaires
    # ------------------------------------------------------------------

    def create_questionnaire(
        self,
        org_id: str,
        questionnaire_name: str,
        questionnaire_type: str = "vendor",
        framework: str = "custom",
    ) -> Dict[str, Any]:
        """Create a new questionnaire template."""
        if questionnaire_type not in _VALID_QUESTIONNAIRE_TYPES:
            raise ValueError(
                f"Invalid questionnaire_type '{questionnaire_type}'. "
                f"Must be one of {sorted(_VALID_QUESTIONNAIRE_TYPES)}"
            )
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid framework '{framework}'. "
                f"Must be one of {sorted(_VALID_FRAMEWORKS)}"
            )
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "questionnaire_name": questionnaire_name,
            "questionnaire_type": questionnaire_type,
            "framework": framework,
            "question_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO questionnaires
                       (id, org_id, questionnaire_name, questionnaire_type,
                        framework, question_count, created_at)
                       VALUES (:id, :org_id, :questionnaire_name, :questionnaire_type,
                               :framework, :question_count, :created_at)""",
                    record,
                )
        return record

    def add_question(
        self,
        questionnaire_id: str,
        org_id: str,
        question_text: str,
        question_category: str = "governance",
        weight: float = 1.0,
        required: bool = True,
    ) -> Dict[str, Any]:
        """Add a question to a questionnaire; increments question_count."""
        if question_category not in _VALID_QUESTION_CATEGORIES:
            raise ValueError(
                f"Invalid question_category '{question_category}'. "
                f"Must be one of {sorted(_VALID_QUESTION_CATEGORIES)}"
            )
        weight = max(0.0, float(weight))
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "questionnaire_id": questionnaire_id,
            "org_id": org_id,
            "question_text": question_text,
            "question_category": question_category,
            "weight": weight,
            "required": 1 if required else 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO questions
                       (id, questionnaire_id, org_id, question_text, question_category,
                        weight, required, created_at)
                       VALUES (:id, :questionnaire_id, :org_id, :question_text,
                               :question_category, :weight, :required, :created_at)""",
                    record,
                )
                conn.execute(
                    """UPDATE questionnaires
                       SET question_count = question_count + 1
                       WHERE id = ? AND org_id = ?""",
                    (questionnaire_id, org_id),
                )
        return record

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def send_assessment(
        self,
        org_id: str,
        questionnaire_id: str,
        vendor_id: str,
        vendor_name: str,
        due_date: str,
    ) -> Dict[str, Any]:
        """Send a questionnaire assessment to a vendor."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "questionnaire_id": questionnaire_id,
            "vendor_id": vendor_id,
            "vendor_name": vendor_name,
            "status": "sent",
            "score": None,
            "risk_level": None,
            "sent_at": now,
            "completed_at": None,
            "due_date": due_date,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO assessments
                       (id, org_id, questionnaire_id, vendor_id, vendor_name,
                        status, score, risk_level, sent_at, completed_at,
                        due_date, created_at)
                       VALUES (:id, :org_id, :questionnaire_id, :vendor_id, :vendor_name,
                               :status, :score, :risk_level, :sent_at, :completed_at,
                               :due_date, :created_at)""",
                    record,
                )
        return record

    def submit_response(
        self,
        assessment_id: str,
        question_id: str,
        org_id: str,
        response_text: str,
        response_value: int,
    ) -> Dict[str, Any]:
        """Submit a response for a question in an assessment.

        response_value: 0=no, 1=partial, 2=yes, 3=yes-with-evidence, 4=N/A
        Auto-scores the assessment if all required questions are answered.
        """
        # Clamp response_value to 0-4
        response_value = max(0, min(4, int(response_value)))
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "assessment_id": assessment_id,
            "question_id": question_id,
            "org_id": org_id,
            "response_text": response_text,
            "response_value": response_value,
            "responded_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                # Upsert: replace existing response for same question in assessment
                conn.execute(
                    """INSERT OR REPLACE INTO responses
                       (id, assessment_id, question_id, org_id, response_text,
                        response_value, responded_at)
                       VALUES (:id, :assessment_id, :question_id, :org_id,
                               :response_text, :response_value, :responded_at)""",
                    record,
                )

        # Check if all required questions have responses → auto-score
        self._maybe_auto_score(assessment_id, org_id)
        return record

    def _maybe_auto_score(self, assessment_id: str, org_id: str) -> None:
        """Auto-score if all required questions for this assessment are answered."""
        with self._conn() as conn:
            assessment_row = conn.execute(
                "SELECT questionnaire_id FROM assessments WHERE id = ? AND org_id = ?",
                (assessment_id, org_id),
            ).fetchone()
            if not assessment_row:
                return
            questionnaire_id = assessment_row["questionnaire_id"]

            # Count required questions for this questionnaire
            required_count = conn.execute(
                "SELECT COUNT(*) FROM questions WHERE questionnaire_id = ? AND org_id = ? AND required = 1",
                (questionnaire_id, org_id),
            ).fetchone()[0]

            if required_count == 0:
                return

            # Count responses to required questions for this assessment
            answered_count = conn.execute(
                """SELECT COUNT(*) FROM responses r
                   JOIN questions q ON r.question_id = q.id
                   WHERE r.assessment_id = ? AND r.org_id = ? AND q.required = 1""",
                (assessment_id, org_id),
            ).fetchone()[0]

        if answered_count >= required_count:
            self.score_assessment(assessment_id, org_id)

    def score_assessment(self, assessment_id: str, org_id: str) -> Dict[str, Any]:
        """Score an assessment.

        score = sum(response_value * weight) / sum(weight) * 25  (scale to 100)
        risk_level: >=80=low, >=60=medium, >=40=high, <40=critical
        """
        with self._lock:
            with self._conn() as conn:
                assessment_row = conn.execute(
                    "SELECT questionnaire_id FROM assessments WHERE id = ? AND org_id = ?",
                    (assessment_id, org_id),
                ).fetchone()
                if not assessment_row:
                    raise ValueError(f"Assessment {assessment_id} not found")
                questionnaire_id = assessment_row["questionnaire_id"]

                # Fetch all questions and their responses
                rows = conn.execute(
                    """SELECT q.id, q.weight, COALESCE(r.response_value, 0) as rv
                       FROM questions q
                       LEFT JOIN responses r
                         ON r.question_id = q.id AND r.assessment_id = ?
                       WHERE q.questionnaire_id = ? AND q.org_id = ?""",
                    (assessment_id, questionnaire_id, org_id),
                ).fetchall()

                if not rows:
                    score = 0.0
                else:
                    total_weight = sum(float(r["weight"]) for r in rows)
                    weighted_sum = sum(float(r["rv"]) * float(r["weight"]) for r in rows)
                    if total_weight > 0:
                        score = (weighted_sum / total_weight) * 25.0
                    else:
                        score = 0.0

                score = round(min(100.0, max(0.0, score)), 2)
                risk_level = _compute_risk_level(score)
                now = _now_iso()

                conn.execute(
                    """UPDATE assessments
                       SET score = ?, risk_level = ?, status = 'completed', completed_at = ?
                       WHERE id = ? AND org_id = ?""",
                    (score, risk_level, now, assessment_id, org_id),
                )

        return self.get_assessment(assessment_id, org_id)

    def get_assessment(self, assessment_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Get assessment with its responses."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM assessments WHERE id = ? AND org_id = ?",
                (assessment_id, org_id),
            ).fetchone()
            if not row:
                return None
            assessment = self._row(row)

            resp_rows = conn.execute(
                "SELECT * FROM responses WHERE assessment_id = ? AND org_id = ?",
                (assessment_id, org_id),
            ).fetchall()
            assessment["responses"] = [self._row(r) for r in resp_rows]
        return assessment

    def list_assessments(
        self,
        org_id: str,
        vendor_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assessments for an org with optional filters."""
        sql = "SELECT * FROM assessments WHERE org_id = ?"
        params: List[Any] = [org_id]
        if vendor_id:
            sql += " AND vendor_id = ?"
            params.append(vendor_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_overdue_assessments(self, org_id: str) -> List[Dict[str, Any]]:
        """Return sent assessments whose due_date is in the past."""
        now = _now_iso()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM assessments
                   WHERE org_id = ? AND status = 'sent' AND due_date < ?
                   ORDER BY due_date ASC""",
                (org_id, now),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_vendor_risk_summary(self, org_id: str) -> List[Dict[str, Any]]:
        """Return per-vendor: latest score, risk_level, assessment count."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT vendor_id, vendor_name,
                          COUNT(*) as assessment_count,
                          MAX(completed_at) as last_completed_at,
                          AVG(score) as avg_score
                   FROM assessments
                   WHERE org_id = ? AND status = 'completed'
                   GROUP BY vendor_id, vendor_name""",
                (org_id,),
            ).fetchall()
            summary = []
            for r in rows:
                # Get latest score for risk_level
                latest = conn.execute(
                    """SELECT score, risk_level FROM assessments
                       WHERE org_id = ? AND vendor_id = ? AND status = 'completed'
                       ORDER BY completed_at DESC LIMIT 1""",
                    (org_id, r["vendor_id"]),
                ).fetchone()
                entry = {
                    "vendor_id": r["vendor_id"],
                    "vendor_name": r["vendor_name"],
                    "assessment_count": r["assessment_count"],
                    "latest_score": latest["score"] if latest else None,
                    "risk_level": latest["risk_level"] if latest else None,
                    "avg_score": round(r["avg_score"], 2) if r["avg_score"] is not None else None,
                }
                summary.append(entry)
        return summary
