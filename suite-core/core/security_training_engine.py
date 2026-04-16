"""Security Awareness Training Engine — ALDECI.

Manages training courses, user assignments, completion records, certificates,
and awareness campaigns across the organization.

Multi-tenant via org_id. SQLite WAL for durability.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_training.db"
)

_COURSE_TYPES = {
    "phishing_awareness", "secure_coding", "gdpr", "pci_dss",
    "incident_response", "social_engineering", "password_security",
    "ai_security", "zero_trust",
    # legacy categories kept for backward compat
    "phishing", "password", "compliance", "privacy",
    "secure_coding", "physical_security", "ai_safety",
}
_CATEGORIES = _COURSE_TYPES  # alias
_DIFFICULTIES = {"beginner", "intermediate", "advanced"}
_FORMATS = {"video", "interactive", "quiz", "live"}
_CAMPAIGN_STATUSES = {"active", "completed", "draft", "cancelled"}
_ASSIGNMENT_STATUSES = {"assigned", "in_progress", "completed", "overdue", "failed",
                        # legacy aliases
                        "enrolled"}
_FREQUENCIES = {"once", "annual", "biannual", "quarterly"}

# Days until due based on frequency
_FREQUENCY_DAYS = {
    "once": 90,
    "annual": 365,
    "biannual": 180,
    "quarterly": 90,
}


class SecurityTrainingEngine:
    """SQLite WAL-backed security awareness training engine.

    Thread-safe via RLock. Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS training_courses (
                    course_id           TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    title               TEXT NOT NULL,
                    course_name         TEXT NOT NULL DEFAULT '',
                    description         TEXT NOT NULL DEFAULT '',
                    category            TEXT NOT NULL DEFAULT 'compliance',
                    course_type         TEXT NOT NULL DEFAULT 'compliance',
                    duration_minutes    INTEGER NOT NULL DEFAULT 30,
                    difficulty          TEXT NOT NULL DEFAULT 'beginner',
                    format              TEXT NOT NULL DEFAULT 'video',
                    passing_score       INTEGER NOT NULL DEFAULT 70,
                    mandatory           INTEGER NOT NULL DEFAULT 0,
                    frequency           TEXT NOT NULL DEFAULT 'annual',
                    cpe_credits         REAL NOT NULL DEFAULT 0.0,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tc_org
                    ON training_courses (org_id, category);

                CREATE TABLE IF NOT EXISTS user_enrollments (
                    enrollment_id   TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    course_id       TEXT NOT NULL,
                    user_id         TEXT NOT NULL,
                    user_email      TEXT NOT NULL DEFAULT '',
                    department      TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'assigned',
                    assigned_date   TEXT,
                    due_date        TEXT,
                    completed_date  TEXT,
                    score           INTEGER,
                    passed          INTEGER,
                    attempts        INTEGER NOT NULL DEFAULT 0,
                    enrolled_at     TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ue_org
                    ON user_enrollments (org_id, user_id, course_id);

                CREATE INDEX IF NOT EXISTS idx_ue_org_dept
                    ON user_enrollments (org_id, department);

                CREATE TABLE IF NOT EXISTS completion_records (
                    record_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    enrollment_id   TEXT NOT NULL,
                    user_id         TEXT NOT NULL,
                    course_id       TEXT NOT NULL,
                    score           INTEGER NOT NULL DEFAULT 0,
                    passed          INTEGER NOT NULL DEFAULT 0,
                    completed_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cr_org
                    ON completion_records (org_id, user_id, course_id);

                CREATE TABLE IF NOT EXISTS training_campaigns (
                    campaign_id             TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    name                    TEXT NOT NULL,
                    campaign_name           TEXT NOT NULL DEFAULT '',
                    target_group            TEXT NOT NULL DEFAULT '',
                    target_departments      TEXT NOT NULL DEFAULT '[]',
                    target_role_level       TEXT NOT NULL DEFAULT '[]',
                    course_id               TEXT NOT NULL DEFAULT '',
                    course_ids              TEXT NOT NULL DEFAULT '[]',
                    start_date              TEXT,
                    end_date                TEXT,
                    due_date                TEXT,
                    status                  TEXT NOT NULL DEFAULT 'draft',
                    completion_target_pct   INTEGER NOT NULL DEFAULT 100,
                    actual_completion_pct   REAL NOT NULL DEFAULT 0.0,
                    completion_rate         REAL NOT NULL DEFAULT 0.0,
                    created_at              TEXT NOT NULL,
                    updated_at              TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tc_org_status
                    ON training_campaigns (org_id, status);

                CREATE TABLE IF NOT EXISTS training_certificates (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    user_id             TEXT NOT NULL,
                    user_email          TEXT NOT NULL DEFAULT '',
                    course_id           TEXT NOT NULL,
                    course_name         TEXT NOT NULL DEFAULT '',
                    issued_date         TEXT NOT NULL,
                    expiry_date         TEXT,
                    certificate_number  TEXT NOT NULL,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cert_org_user
                    ON training_certificates (org_id, user_id);

                CREATE INDEX IF NOT EXISTS idx_cert_org_expiry
                    ON training_certificates (org_id, expiry_date);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Courses
    # ------------------------------------------------------------------

    def create_course(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a training course. Returns the created course record."""
        course_id = str(uuid.uuid4())
        now = self._now()
        # Support both course_type and category field names
        course_type = data.get("course_type") or data.get("category", "compliance")
        if course_type not in _COURSE_TYPES:
            course_type = "compliance"
        category = course_type
        difficulty = data.get("difficulty", "beginner")
        if difficulty not in _DIFFICULTIES:
            difficulty = "beginner"
        fmt = data.get("format", "video")
        if fmt not in _FORMATS:
            fmt = "video"
        frequency = data.get("frequency", "annual")
        if frequency not in _FREQUENCIES:
            frequency = "annual"
        # Support both title and course_name
        title = data.get("title") or data.get("course_name", "")
        course_name = data.get("course_name") or title

        record = {
            "course_id": course_id,
            "org_id": org_id,
            "title": title,
            "course_name": course_name,
            "description": data.get("description", ""),
            "category": category,
            "course_type": course_type,
            "duration_minutes": int(data.get("duration_minutes", 30)),
            "difficulty": difficulty,
            "format": fmt,
            "passing_score": int(data.get("passing_score", 70)),
            "mandatory": 1 if data.get("mandatory", False) else 0,
            "frequency": frequency,
            "cpe_credits": float(data.get("cpe_credits", 0.0)),
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO training_courses
                        (course_id, org_id, title, course_name, description, category, course_type,
                         duration_minutes, difficulty, format, passing_score,
                         mandatory, frequency, cpe_credits, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["course_id"], record["org_id"], record["title"],
                        record["course_name"], record["description"],
                        record["category"], record["course_type"],
                        record["duration_minutes"], record["difficulty"],
                        record["format"], record["passing_score"],
                        record["mandatory"], record["frequency"], record["cpe_credits"],
                        record["created_at"], record["updated_at"],
                    ),
                )
        record["mandatory"] = bool(record["mandatory"])
        _logger.info("Created course %s (org=%s, category=%s)", course_id, org_id, category)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_training", "org_id": org_id, "source_engine": "security_training"})
            except Exception:
                pass

        return record

    def list_courses(
        self,
        org_id: str,
        category: Optional[str] = None,
        course_type: Optional[str] = None,
        mandatory: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List training courses for an org, optionally filtered by category/course_type/mandatory."""
        sql = "SELECT * FROM training_courses WHERE org_id=?"
        params: list = [org_id]
        filter_cat = category or course_type
        if filter_cat:
            sql += " AND (category=? OR course_type=?)"
            params.extend([filter_cat, filter_cat])
        if mandatory is not None:
            sql += " AND mandatory=?"
            params.append(1 if mandatory else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = self._row(r)
            d["mandatory"] = bool(d.get("mandatory", 0))
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Enrollments
    # ------------------------------------------------------------------

    def enroll_user(
        self,
        org_id: str,
        course_id: str,
        user_id: str,
        due_date: Optional[str] = None,
        user_email: str = "",
        department: str = "",
    ) -> Dict[str, Any]:
        """Enroll a user in a course. Returns the enrollment record."""
        enrollment_id = str(uuid.uuid4())
        now = self._now()

        record = {
            "enrollment_id": enrollment_id,
            "org_id": org_id,
            "course_id": course_id,
            "user_id": user_id,
            "user_email": user_email,
            "department": department,
            "status": "assigned",
            "assigned_date": now,
            "due_date": due_date,
            "completed_date": None,
            "score": None,
            "passed": None,
            "attempts": 0,
            "enrolled_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO user_enrollments
                        (enrollment_id, org_id, course_id, user_id, user_email, department,
                         status, assigned_date, due_date, completed_date, score, passed,
                         attempts, enrolled_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["enrollment_id"], record["org_id"], record["course_id"],
                        record["user_id"], record["user_email"], record["department"],
                        record["status"], record["assigned_date"], record["due_date"],
                        record["completed_date"], record["score"], record["passed"],
                        record["attempts"], record["enrolled_at"], record["updated_at"],
                    ),
                )
        _logger.info("Enrolled user %s in course %s (org=%s)", user_id, course_id, org_id)
        return record

    def assign_training(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a training assignment with auto-computed due_date from course frequency.

        data must contain: course_id, user_id. Optional: user_email, department, due_date.
        If due_date is not provided, it is computed from the course's frequency setting.
        """
        course_id = data.get("course_id", "")
        user_id = data.get("user_id", "")
        if not course_id or not user_id:
            raise ValueError("course_id and user_id are required.")

        # Look up course for frequency-based due_date
        due_date = data.get("due_date")
        if not due_date:
            with self._conn() as conn:
                course_row = conn.execute(
                    "SELECT frequency FROM training_courses WHERE course_id=? AND org_id=?",
                    (course_id, org_id),
                ).fetchone()
            if course_row:
                freq = course_row["frequency"] or "annual"
                days = _FREQUENCY_DAYS.get(freq, 365)
            else:
                days = 365
            due_date = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

        return self.enroll_user(
            org_id,
            course_id,
            user_id,
            due_date=due_date,
            user_email=data.get("user_email", ""),
            department=data.get("department", ""),
        )

    def list_enrollments(
        self,
        org_id: str,
        user_id: Optional[str] = None,
        course_id: Optional[str] = None,
        status: Optional[str] = None,
        department: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List enrollments for an org with optional filters. Auto-detects overdue."""
        clauses = ["org_id=?"]
        params: list = [org_id]
        if user_id:
            clauses.append("user_id=?")
            params.append(user_id)
        if course_id:
            clauses.append("course_id=?")
            params.append(course_id)
        if department:
            clauses.append("department=?")
            params.append(department)
        if status:
            clauses.append("status=?")
            params.append(status)
        where = " AND ".join(clauses)
        query = f"SELECT * FROM user_enrollments WHERE {where} ORDER BY enrolled_at DESC"  # nosec B608

        now = self._now()
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            d = self._row(r)
            # Mark overdue in returned data (don't persist unless caller requests)
            if (d.get("status") not in ("completed",) and
                    d.get("due_date") and d["due_date"] < now):
                d["is_overdue"] = True
            else:
                d["is_overdue"] = False
            result.append(d)
        return result

    def list_assignments(
        self,
        org_id: str,
        user_id: Optional[str] = None,
        status: Optional[str] = None,
        department: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Spec-aligned alias for list_enrollments."""
        return self.list_enrollments(
            org_id, user_id=user_id, status=status, department=department
        )

    # ------------------------------------------------------------------
    # Completions
    # ------------------------------------------------------------------

    def complete_course(
        self, org_id: str, enrollment_id: str, score: int
    ) -> Dict[str, Any]:
        """Record a course completion. Returns the completion record.

        Looks up the enrollment to find course_id and passing_score,
        then sets passed=True if score >= passing_score.
        Updates the enrollment status to 'completed'.
        Issues a training certificate if the user passed.
        """
        now = self._now()

        with self._conn() as conn:
            enrollment = conn.execute(
                "SELECT * FROM user_enrollments WHERE enrollment_id=? AND org_id=?",
                (enrollment_id, org_id),
            ).fetchone()

        if not enrollment:
            raise ValueError(f"Enrollment {enrollment_id} not found for org {org_id}")

        enrollment = dict(enrollment)
        course_id = enrollment["course_id"]
        user_id = enrollment["user_id"]
        user_email = enrollment.get("user_email", "")

        # Look up course details
        with self._conn() as conn:
            course = conn.execute(
                "SELECT passing_score, title, course_name, frequency FROM training_courses WHERE course_id=? AND org_id=?",
                (course_id, org_id),
            ).fetchone()

        course_data = dict(course) if course else {}
        passing_score = course_data.get("passing_score", 70)
        course_name = course_data.get("course_name") or course_data.get("title", "")
        passed = score >= passing_score

        # Compute due_date for overdue check
        due_date = enrollment.get("due_date")
        is_past_due = bool(due_date and due_date < now)
        new_status = "completed" if (passed or not is_past_due) else "failed"
        if passed:
            new_status = "completed"
        elif score < passing_score:
            new_status = "failed"

        record_id = str(uuid.uuid4())
        record = {
            "record_id": record_id,
            "org_id": org_id,
            "enrollment_id": enrollment_id,
            "user_id": user_id,
            "course_id": course_id,
            "score": score,
            "passed": passed,
            "completed_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO completion_records
                        (record_id, org_id, enrollment_id, user_id, course_id,
                         score, passed, completed_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["record_id"], record["org_id"], record["enrollment_id"],
                        record["user_id"], record["course_id"], record["score"],
                        1 if record["passed"] else 0, record["completed_at"],
                    ),
                )
                # Update enrollment status, score, and completed_date
                conn.execute(
                    """UPDATE user_enrollments
                       SET status=?, score=?, passed=?, completed_date=?, updated_at=?,
                           attempts=attempts+1
                       WHERE enrollment_id=? AND org_id=?""",
                    (new_status, score, 1 if passed else 0, now, now, enrollment_id, org_id),
                )

        # Issue certificate if passed
        if passed:
            try:
                freq = course_data.get("frequency", "annual")
                expiry_days = _FREQUENCY_DAYS.get(freq, 365)
                expiry_date = (datetime.now(timezone.utc) + timedelta(days=expiry_days)).isoformat()
                cert_number = f"CERT-{org_id[:4].upper()}-{record_id[:8].upper()}"
                self._issue_certificate(org_id, user_id, user_email, course_id, course_name,
                                        now, expiry_date, cert_number)
                record["certificate_issued"] = True
                record["certificate_number"] = cert_number
            except Exception as exc:
                _logger.warning("Failed to issue certificate: %s", exc)

        _logger.info(
            "Completed course %s for user %s (score=%d, passed=%s)",
            course_id, user_id, score, passed,
        )
        return record

    def _issue_certificate(
        self, org_id: str, user_id: str, user_email: str,
        course_id: str, course_name: str,
        issued_date: str, expiry_date: str, certificate_number: str
    ) -> Dict[str, Any]:
        """Internal: insert a training certificate record."""
        now = self._now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "user_id": user_id,
            "user_email": user_email,
            "course_id": course_id,
            "course_name": course_name,
            "issued_date": issued_date,
            "expiry_date": expiry_date,
            "certificate_number": certificate_number,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO training_certificates
                       (id, org_id, user_id, user_email, course_id, course_name,
                        issued_date, expiry_date, certificate_number, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (record["id"], record["org_id"], record["user_id"], record["user_email"],
                     record["course_id"], record["course_name"], record["issued_date"],
                     record["expiry_date"], record["certificate_number"], record["created_at"]),
                )
        return record

    def complete_training(self, org_id: str, assignment_id: str, score: int) -> Dict[str, Any]:
        """Spec-aligned alias for complete_course."""
        return self.complete_course(org_id, assignment_id, score)

    # ------------------------------------------------------------------
    # Progress
    # ------------------------------------------------------------------

    def get_user_progress(self, org_id: str, user_id: str) -> Dict[str, Any]:
        """Return training progress summary for a user."""
        with self._conn() as conn:
            enrolled = conn.execute(
                "SELECT COUNT(*) FROM user_enrollments WHERE org_id=? AND user_id=?",
                (org_id, user_id),
            ).fetchone()[0]

            completed = conn.execute(
                "SELECT COUNT(*) FROM user_enrollments WHERE org_id=? AND user_id=? "
                "AND status='completed'",
                (org_id, user_id),
            ).fetchone()[0]

            # passed / failed from completion_records
            passed_row = conn.execute(
                "SELECT COUNT(*) FROM completion_records WHERE org_id=? AND user_id=? AND passed=1",
                (org_id, user_id),
            ).fetchone()
            passed = passed_row[0] if passed_row else 0

            failed_row = conn.execute(
                "SELECT COUNT(*) FROM completion_records WHERE org_id=? AND user_id=? AND passed=0",
                (org_id, user_id),
            ).fetchone()
            failed = failed_row[0] if failed_row else 0

            avg_score_row = conn.execute(
                "SELECT AVG(score) FROM completion_records WHERE org_id=? AND user_id=?",
                (org_id, user_id),
            ).fetchone()
            avg_score = round(avg_score_row[0], 1) if avg_score_row and avg_score_row[0] else 0.0

            # Compliance completion: courses in compliance/privacy/phishing categories
            compliance_enrolled_row = conn.execute(
                """
                SELECT COUNT(*) FROM user_enrollments ue
                JOIN training_courses tc ON ue.course_id = tc.course_id
                WHERE ue.org_id=? AND ue.user_id=?
                  AND tc.category IN ('compliance','privacy','phishing')
                """,
                (org_id, user_id),
            ).fetchone()
            compliance_enrolled = compliance_enrolled_row[0] if compliance_enrolled_row else 0

            compliance_done_row = conn.execute(
                """
                SELECT COUNT(*) FROM user_enrollments ue
                JOIN training_courses tc ON ue.course_id = tc.course_id
                WHERE ue.org_id=? AND ue.user_id=? AND ue.status='completed'
                  AND tc.category IN ('compliance','privacy','phishing')
                """,
                (org_id, user_id),
            ).fetchone()
            compliance_done = compliance_done_row[0] if compliance_done_row else 0

        compliance_rate = (
            round(compliance_done / compliance_enrolled * 100, 1)
            if compliance_enrolled > 0
            else 0.0
        )

        return {
            "enrolled": enrolled,
            "completed": completed,
            "passed": passed,
            "failed": failed,
            "avg_score": avg_score,
            "compliance_completion_rate": compliance_rate,
        }

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def create_campaign(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a training campaign. Returns the created campaign record."""
        campaign_id = str(uuid.uuid4())
        now = self._now()
        status = data.get("status", "draft")
        if status not in _CAMPAIGN_STATUSES:
            status = "draft"

        course_ids = data.get("course_ids", [])
        if isinstance(course_ids, list):
            course_ids_json = json.dumps(course_ids)
        else:
            course_ids_json = "[]"

        target_departments = data.get("target_departments", [])
        target_role_level = data.get("target_role_level", [])
        campaign_name = data.get("campaign_name") or data.get("name", "")

        record = {
            "campaign_id": campaign_id,
            "org_id": org_id,
            "name": campaign_name,
            "campaign_name": campaign_name,
            "target_group": data.get("target_group", ""),
            "target_departments": json.dumps(target_departments if isinstance(target_departments, list) else []),
            "target_role_level": json.dumps(target_role_level if isinstance(target_role_level, list) else []),
            "course_id": data.get("course_id", course_ids[0] if course_ids else ""),
            "course_ids": course_ids_json,
            "start_date": data.get("start_date"),
            "end_date": data.get("end_date"),
            "due_date": data.get("due_date"),
            "status": status,
            "completion_target_pct": int(data.get("completion_target_pct", 100)),
            "actual_completion_pct": float(data.get("actual_completion_pct", 0.0)),
            "completion_rate": float(data.get("completion_rate", 0.0)),
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO training_campaigns
                        (campaign_id, org_id, name, campaign_name, target_group,
                         target_departments, target_role_level, course_id, course_ids,
                         start_date, end_date, due_date, status,
                         completion_target_pct, actual_completion_pct, completion_rate,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["campaign_id"], record["org_id"], record["name"],
                        record["campaign_name"], record["target_group"],
                        record["target_departments"], record["target_role_level"],
                        record["course_id"], record["course_ids"],
                        record["start_date"], record["end_date"], record["due_date"],
                        record["status"], record["completion_target_pct"],
                        record["actual_completion_pct"], record["completion_rate"],
                        record["created_at"], record["updated_at"],
                    ),
                )
        out = dict(record)
        out["course_ids"] = json.loads(course_ids_json)
        out["target_departments"] = target_departments if isinstance(target_departments, list) else []
        out["target_role_level"] = target_role_level if isinstance(target_role_level, list) else []
        return out

    def update_campaign_progress(self, org_id: str, campaign_id: str) -> Dict[str, Any]:
        """Recompute actual_completion_pct from assignments linked to this campaign's course(s)."""
        with self._conn() as conn:
            camp_row = conn.execute(
                "SELECT * FROM training_campaigns WHERE campaign_id=? AND org_id=?",
                (campaign_id, org_id),
            ).fetchone()
        if not camp_row:
            raise ValueError(f"Campaign {campaign_id} not found for org {org_id}")

        camp = dict(camp_row)
        course_ids = json.loads(camp.get("course_ids") or "[]")
        main_course_id = camp.get("course_id") or (course_ids[0] if course_ids else None)

        if main_course_id:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM user_enrollments WHERE org_id=? AND course_id=?",
                    (org_id, main_course_id),
                ).fetchone()[0]
                completed = conn.execute(
                    "SELECT COUNT(*) FROM user_enrollments WHERE org_id=? AND course_id=? AND status='completed'",
                    (org_id, main_course_id),
                ).fetchone()[0]
            pct = round(completed / total * 100.0, 2) if total > 0 else 0.0
        else:
            pct = 0.0

        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE training_campaigns
                       SET actual_completion_pct=?, completion_rate=?, updated_at=?
                       WHERE campaign_id=? AND org_id=?""",
                    (pct, pct, now, campaign_id, org_id),
                )
        camp["actual_completion_pct"] = pct
        camp["completion_rate"] = pct
        return camp

    def list_campaigns(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List campaigns for an org, optionally filtered by status."""
        sql = "SELECT * FROM training_campaigns WHERE org_id=?"
        params: list = [org_id]
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = self._row(r)
            for field in ("course_ids", "target_departments", "target_role_level"):
                if field in d and isinstance(d[field], str):
                    try:
                        d[field] = json.loads(d[field])
                    except (json.JSONDecodeError, TypeError):
                        d[field] = []
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------

    def list_certificates(
        self, org_id: str, user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List training certificates with expiry status."""
        sql = "SELECT * FROM training_certificates WHERE org_id=?"
        params: list = [org_id]
        if user_id:
            sql += " AND user_id=?"
            params.append(user_id)
        sql += " ORDER BY issued_date DESC"

        now = self._now()
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()

        result = []
        for r in rows:
            d = self._row(r)
            exp = d.get("expiry_date")
            if exp:
                d["expired"] = exp < now
            else:
                d["expired"] = False
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_training_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated training statistics for an org."""
        now = self._now()
        in_30_days = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

        with self._conn() as conn:
            total_courses = conn.execute(
                "SELECT COUNT(*) FROM training_courses WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            total_assignments = conn.execute(
                "SELECT COUNT(*) FROM user_enrollments WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            enrollments_active = conn.execute(
                "SELECT COUNT(*) FROM user_enrollments WHERE org_id=? AND status IN ('assigned','enrolled','in_progress')",
                (org_id,),
            ).fetchone()[0]

            completed_enrollments = conn.execute(
                "SELECT COUNT(*) FROM user_enrollments WHERE org_id=? AND status='completed'",
                (org_id,),
            ).fetchone()[0]

            avg_score_row = conn.execute(
                "SELECT AVG(score) FROM completion_records WHERE org_id=?", (org_id,)
            ).fetchone()
            avg_score = round(avg_score_row[0], 1) if avg_score_row and avg_score_row[0] else 0.0

            # overdue: past due_date and not completed
            overdue_count = conn.execute(
                "SELECT COUNT(*) FROM user_enrollments WHERE org_id=? "
                "AND status NOT IN ('completed') AND due_date IS NOT NULL AND due_date < ?",
                (org_id, now),
            ).fetchone()[0]

            # by_category / by_course_type
            cat_rows = conn.execute(
                """
                SELECT tc.category, COUNT(ue.enrollment_id) as cnt
                FROM user_enrollments ue
                JOIN training_courses tc ON ue.course_id = tc.course_id
                WHERE ue.org_id=?
                GROUP BY tc.category
                """,
                (org_id,),
            ).fetchall()
            by_department_rows = conn.execute(
                "SELECT department, COUNT(*) as cnt FROM user_enrollments WHERE org_id=? GROUP BY department",
                (org_id,),
            ).fetchall()

            certificates_issued = conn.execute(
                "SELECT COUNT(*) FROM training_certificates WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            expiring_soon_count = conn.execute(
                "SELECT COUNT(*) FROM training_certificates WHERE org_id=? AND expiry_date IS NOT NULL AND expiry_date <= ? AND expiry_date > ?",
                (org_id, in_30_days, now),
            ).fetchone()[0]

        completion_rate = (
            round(completed_enrollments / total_assignments * 100, 1)
            if total_assignments > 0
            else 0.0
        )
        by_category = {r["category"]: r["cnt"] for r in cat_rows}
        by_department = {(r["department"] or "unknown"): r["cnt"] for r in by_department_rows}

        return {
            "total_courses": total_courses,
            "total_assignments": total_assignments,
            "enrollments_active": enrollments_active,
            "completion_rate": completion_rate,
            "avg_score": avg_score,
            "overdue_count": overdue_count,
            "by_category": by_category,
            "by_course_type": by_category,
            "by_department": by_department,
            "certificates_issued": certificates_issued,
            "expiring_soon_count": expiring_soon_count,
        }

    def get_department_compliance(self, org_id: str) -> Dict[str, Any]:
        """Return per-department completion rates for mandatory courses."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT ue.department,
                       COUNT(ue.enrollment_id) as total,
                       SUM(CASE WHEN ue.status='completed' THEN 1 ELSE 0 END) as completed
                FROM user_enrollments ue
                JOIN training_courses tc ON ue.course_id = tc.course_id
                WHERE ue.org_id=? AND tc.mandatory=1
                GROUP BY ue.department
                """,
                (org_id,),
            ).fetchall()

        result: Dict[str, Any] = {}
        for r in rows:
            dept = r["department"] or "unknown"
            total = r["total"] or 0
            completed = r["completed"] or 0
            rate = round(completed / total * 100.0, 1) if total > 0 else 0.0
            result[dept] = {
                "total_assigned": total,
                "completed": completed,
                "completion_rate": rate,
            }
        return result
