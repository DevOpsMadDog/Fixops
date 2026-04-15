"""Tests for SecurityAwarenessProgramEngine — ALDECI Beast Mode."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from core.security_awareness_program_engine import SecurityAwarenessProgramEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityAwarenessProgramEngine(db_path=str(tmp_path / "sap.db"))


@pytest.fixture
def org():
    return f"org-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def other_org():
    return f"org-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_program(engine, org, program_type="phishing", passing_score=70):
    return engine.create_program(
        org_id=org,
        program_name=f"Prog-{uuid.uuid4().hex[:6]}",
        program_type=program_type,
        target_audience="all_staff",
        duration_mins=30,
        frequency="annual",
        passing_score=passing_score,
    )


def enroll(engine, org, program_id, user_id=None, department="Engineering"):
    if user_id is None:
        user_id = f"user-{uuid.uuid4().hex[:6]}"
    return engine.enroll_user(
        program_id=program_id,
        org_id=org,
        user_id=user_id,
        user_name=f"User {user_id}",
        department=department,
    )


# ---------------------------------------------------------------------------
# Program creation
# ---------------------------------------------------------------------------

class TestCreateProgram:
    def test_creates_with_defaults(self, engine, org):
        prog = make_program(engine, org)
        assert prog["status"] == "active"
        assert prog["enrolled_count"] == 0
        assert prog["completed_count"] == 0
        assert prog["pass_rate"] == 0.0
        assert prog["org_id"] == org

    def test_all_program_types_valid(self, engine, org):
        types = ["phishing", "social_engineering", "data_handling", "password_security",
                 "incident_reporting", "compliance", "general", "role_based"]
        for t in types:
            prog = make_program(engine, org, program_type=t)
            assert prog["program_type"] == t

    def test_invalid_program_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="program_type"):
            engine.create_program(org, "P", "bad_type", "all_staff", 30, "annual", 70)

    def test_invalid_frequency_raises(self, engine, org):
        with pytest.raises(ValueError, match="frequency"):
            engine.create_program(org, "P", "phishing", "all_staff", 30, "weekly", 70)

    def test_invalid_target_audience_raises(self, engine, org):
        with pytest.raises(ValueError, match="target_audience"):
            engine.create_program(org, "P", "phishing", "interns", 30, "annual", 70)

    def test_all_frequencies_valid(self, engine, org):
        for freq in ["one_time", "monthly", "quarterly", "annual"]:
            prog = engine.create_program(org, f"P-{freq}", "phishing", "all_staff", 30, freq, 70)
            assert prog["frequency"] == freq

    def test_all_target_audiences_valid(self, engine, org):
        for ta in ["all_staff", "developers", "managers", "executives", "it_staff", "finance"]:
            prog = engine.create_program(org, f"P-{ta}", "phishing", ta, 30, "annual", 70)
            assert prog["target_audience"] == ta

    def test_passing_score_stored(self, engine, org):
        prog = make_program(engine, org, passing_score=80)
        assert prog["passing_score"] == 80


# ---------------------------------------------------------------------------
# Enroll user
# ---------------------------------------------------------------------------

class TestEnrollUser:
    def test_enroll_creates_record(self, engine, org):
        prog = make_program(engine, org)
        result = enroll(engine, org, prog["id"])
        assert result["program_id"] == prog["id"]
        assert result["newly_enrolled"] is True

    def test_enroll_increments_enrolled_count(self, engine, org):
        prog = make_program(engine, org)
        enroll(engine, org, prog["id"], "user-1")
        enroll(engine, org, prog["id"], "user-2")
        stats = engine.get_program_stats(prog["id"], org)
        assert stats["enrolled_count"] == 2

    def test_dedup_does_not_increment_twice(self, engine, org):
        prog = make_program(engine, org)
        r1 = enroll(engine, org, prog["id"], "user-1")
        r2 = enroll(engine, org, prog["id"], "user-1")
        assert r1["newly_enrolled"] is True
        assert r2["newly_enrolled"] is False
        stats = engine.get_program_stats(prog["id"], org)
        assert stats["enrolled_count"] == 1

    def test_same_user_different_programs_allowed(self, engine, org):
        prog1 = make_program(engine, org)
        prog2 = make_program(engine, org)
        r1 = enroll(engine, org, prog1["id"], "user-1")
        r2 = enroll(engine, org, prog2["id"], "user-1")
        assert r1["newly_enrolled"] is True
        assert r2["newly_enrolled"] is True

    def test_org_isolation_enrollment(self, engine, org, other_org):
        prog = make_program(engine, org)
        enroll(engine, org, prog["id"], "user-1")
        # other_org has no enrollments
        summary = engine.get_program_summary(other_org)
        assert summary["total_enrolled"] == 0


# ---------------------------------------------------------------------------
# Record completion
# ---------------------------------------------------------------------------

class TestRecordCompletion:
    def test_completion_sets_completed_at(self, engine, org):
        prog = make_program(engine, org, passing_score=70)
        enrollment = enroll(engine, org, prog["id"])
        result = engine.record_completion(enrollment["id"], org, score=80)
        assert result["completed_at"] is not None
        assert result["score"] == 80

    def test_score_above_threshold_passes(self, engine, org):
        prog = make_program(engine, org, passing_score=70)
        enrollment = enroll(engine, org, prog["id"])
        result = engine.record_completion(enrollment["id"], org, score=75)
        assert result["passed"] == 1

    def test_score_at_threshold_passes(self, engine, org):
        prog = make_program(engine, org, passing_score=70)
        enrollment = enroll(engine, org, prog["id"])
        result = engine.record_completion(enrollment["id"], org, score=70)
        assert result["passed"] == 1

    def test_score_below_threshold_fails(self, engine, org):
        prog = make_program(engine, org, passing_score=70)
        enrollment = enroll(engine, org, prog["id"])
        result = engine.record_completion(enrollment["id"], org, score=65)
        assert result["passed"] == 0

    def test_attempts_incremented(self, engine, org):
        prog = make_program(engine, org, passing_score=70)
        enrollment = enroll(engine, org, prog["id"])
        result = engine.record_completion(enrollment["id"], org, score=80)
        assert result["attempts"] == 1

    def test_pass_rate_recomputed(self, engine, org):
        prog = make_program(engine, org, passing_score=70)
        e1 = enroll(engine, org, prog["id"], "u1")
        e2 = enroll(engine, org, prog["id"], "u2")
        engine.record_completion(e1["id"], org, score=80)  # pass
        engine.record_completion(e2["id"], org, score=60)  # fail
        stats = engine.get_program_stats(prog["id"], org)
        assert stats["pass_rate"] == pytest.approx(50.0)

    def test_completed_count_recomputed(self, engine, org):
        prog = make_program(engine, org, passing_score=70)
        e1 = enroll(engine, org, prog["id"], "u1")
        e2 = enroll(engine, org, prog["id"], "u2")
        engine.record_completion(e1["id"], org, score=80)
        engine.record_completion(e2["id"], org, score=90)
        stats = engine.get_program_stats(prog["id"], org)
        assert stats["completed_count"] == 2

    def test_pass_rate_100_when_all_pass(self, engine, org):
        prog = make_program(engine, org, passing_score=60)
        e1 = enroll(engine, org, prog["id"], "u1")
        e2 = enroll(engine, org, prog["id"], "u2")
        engine.record_completion(e1["id"], org, score=90)
        engine.record_completion(e2["id"], org, score=80)
        stats = engine.get_program_stats(prog["id"], org)
        assert stats["pass_rate"] == pytest.approx(100.0)

    def test_not_found_raises(self, engine, org):
        with pytest.raises(KeyError):
            engine.record_completion("nonexistent", org, score=80)

    def test_org_isolation_completion(self, engine, org, other_org):
        prog = make_program(engine, org)
        enrollment = enroll(engine, org, prog["id"])
        with pytest.raises(KeyError):
            engine.record_completion(enrollment["id"], other_org, score=80)


# ---------------------------------------------------------------------------
# Record event
# ---------------------------------------------------------------------------

class TestRecordEvent:
    def test_records_event(self, engine, org):
        event = engine.record_event(
            org_id=org,
            event_type="phishing_simulation",
            description="Simulated phishing campaign",
            affected_users=50,
            department="Finance",
            event_date="2026-04-16",
            response_action="Training required",
        )
        assert event["event_type"] == "phishing_simulation"
        assert event["affected_users"] == 50

    def test_all_event_types_valid(self, engine, org):
        for et in ["phishing_simulation", "security_incident", "policy_violation",
                   "near_miss", "positive_behavior"]:
            event = engine.record_event(org, et, "", 0, "IT", "2026-04-16", "")
            assert event["event_type"] == et

    def test_invalid_event_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="event_type"):
            engine.record_event(org, "bad_event", "", 0, "IT", "2026-04-16", "")


# ---------------------------------------------------------------------------
# Program stats
# ---------------------------------------------------------------------------

class TestGetProgramStats:
    def test_completion_rate_formula(self, engine, org):
        prog = make_program(engine, org)
        e1 = enroll(engine, org, prog["id"], "u1")
        enroll(engine, org, prog["id"], "u2")  # not completed
        engine.record_completion(e1["id"], org, score=80)
        stats = engine.get_program_stats(prog["id"], org)
        assert stats["completion_rate"] == pytest.approx(50.0)

    def test_dept_breakdown(self, engine, org):
        prog = make_program(engine, org)
        e1 = enroll(engine, org, prog["id"], "u1", "Engineering")
        e2 = enroll(engine, org, prog["id"], "u2", "Finance")
        engine.record_completion(e1["id"], org, score=80)
        stats = engine.get_program_stats(prog["id"], org)
        assert "Engineering" in stats["dept_breakdown"]
        assert "Finance" in stats["dept_breakdown"]
        assert stats["dept_breakdown"]["Engineering"]["completed"] == 1
        assert stats["dept_breakdown"]["Finance"]["completed"] == 0

    def test_low_score_users(self, engine, org):
        prog = make_program(engine, org, passing_score=70)
        e1 = enroll(engine, org, prog["id"], "u1")
        e2 = enroll(engine, org, prog["id"], "u2")
        engine.record_completion(e1["id"], org, score=40)  # low
        engine.record_completion(e2["id"], org, score=90)  # high — not in low list
        stats = engine.get_program_stats(prog["id"], org)
        low_users = stats["low_score_users"]
        assert len(low_users) == 1
        assert low_users[0]["score"] == 40

    def test_not_found_raises(self, engine, org):
        with pytest.raises(KeyError):
            engine.get_program_stats("nonexistent", org)

    def test_org_isolation_stats(self, engine, org, other_org):
        prog = make_program(engine, org)
        with pytest.raises(KeyError):
            engine.get_program_stats(prog["id"], other_org)


# ---------------------------------------------------------------------------
# Department compliance
# ---------------------------------------------------------------------------

class TestGetDepartmentCompliance:
    def test_compliance_rate_formula(self, engine, org):
        prog = make_program(engine, org, passing_score=70)
        e1 = enroll(engine, org, prog["id"], "u1", "IT")
        e2 = enroll(engine, org, prog["id"], "u2", "IT")
        engine.record_completion(e1["id"], org, score=80)  # pass
        engine.record_completion(e2["id"], org, score=60)  # fail
        compliance = engine.get_department_compliance(org)
        it_dept = next(d for d in compliance if d["department"] == "IT")
        # 1 pass out of 2 enrolled = 50%
        assert it_dept["compliance_rate"] == pytest.approx(50.0)

    def test_multiple_departments(self, engine, org):
        prog = make_program(engine, org)
        enroll(engine, org, prog["id"], "u1", "IT")
        enroll(engine, org, prog["id"], "u2", "Finance")
        compliance = engine.get_department_compliance(org)
        depts = [d["department"] for d in compliance]
        assert "IT" in depts
        assert "Finance" in depts

    def test_org_isolation_compliance(self, engine, org, other_org):
        prog = make_program(engine, org)
        enroll(engine, org, prog["id"], "u1", "IT")
        compliance = engine.get_department_compliance(other_org)
        assert compliance == []


# ---------------------------------------------------------------------------
# Overdue enrollments
# ---------------------------------------------------------------------------

class TestGetOverdueEnrollments:
    def test_no_overdue_for_recent_enrollments(self, engine, org):
        prog = make_program(engine, org)
        enroll(engine, org, prog["id"], "u1")
        overdue = engine.get_overdue_enrollments(org)
        assert overdue == []

    def test_completed_not_overdue(self, engine, org):
        prog = make_program(engine, org)
        enrollment = enroll(engine, org, prog["id"], "u1")
        engine.record_completion(enrollment["id"], org, score=80)
        overdue = engine.get_overdue_enrollments(org)
        assert len(overdue) == 0

    def test_old_enrollment_detected(self, engine, org, tmp_path):
        """Manually insert an old enrollment to test 30-day detection."""
        # We need to manually set enrolled_at to 31 days ago
        import sqlite3
        db_path = str(tmp_path / "sap.db")
        engine2 = SecurityAwarenessProgramEngine(db_path=db_path)
        prog = make_program(engine2, org)
        old_date = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        enrollment_id = str(uuid.uuid4())
        import sqlite3 as _sqlite3
        conn = _sqlite3.connect(db_path)
        conn.row_factory = _sqlite3.Row
        conn.execute(
            """INSERT INTO program_enrollments
               (id, program_id, org_id, user_id, user_name, department,
                enrolled_at, completed_at, score, passed, attempts, created_at)
               VALUES (?,?,?,?,?,?,?,NULL,0,0,0,?)""",
            (enrollment_id, prog["id"], org, "old-user", "Old User", "IT", old_date, old_date),
        )
        conn.commit()
        conn.close()
        overdue = engine2.get_overdue_enrollments(org)
        assert len(overdue) == 1
        assert overdue[0]["user_id"] == "old-user"

    def test_org_isolation_overdue(self, engine, org, other_org):
        prog = make_program(engine, org)
        enroll(engine, org, prog["id"], "u1")
        overdue = engine.get_overdue_enrollments(other_org)
        assert overdue == []


# ---------------------------------------------------------------------------
# Program summary
# ---------------------------------------------------------------------------

class TestGetProgramSummary:
    def test_summary_empty(self, engine, org):
        summary = engine.get_program_summary(org)
        assert summary["total_programs"] == 0
        assert summary["total_enrolled"] == 0
        assert summary["total_completed"] == 0
        assert summary["overall_pass_rate"] == 0.0
        assert summary["by_type"] == {}

    def test_summary_counts(self, engine, org):
        prog = make_program(engine, org, program_type="phishing")
        e1 = enroll(engine, org, prog["id"], "u1")
        e2 = enroll(engine, org, prog["id"], "u2")
        engine.record_completion(e1["id"], org, score=80)

        summary = engine.get_program_summary(org)
        assert summary["total_programs"] == 1
        assert summary["total_enrolled"] == 2
        assert summary["total_completed"] == 1
        assert "phishing" in summary["by_type"]
        assert summary["by_type"]["phishing"] == 1

    def test_overall_pass_rate(self, engine, org):
        prog = make_program(engine, org, passing_score=70)
        e1 = enroll(engine, org, prog["id"], "u1")
        e2 = enroll(engine, org, prog["id"], "u2")
        engine.record_completion(e1["id"], org, score=80)  # pass
        engine.record_completion(e2["id"], org, score=50)  # fail
        summary = engine.get_program_summary(org)
        assert summary["overall_pass_rate"] == pytest.approx(50.0)

    def test_by_type_aggregation(self, engine, org):
        make_program(engine, org, program_type="phishing")
        make_program(engine, org, program_type="phishing")
        make_program(engine, org, program_type="compliance")
        summary = engine.get_program_summary(org)
        assert summary["by_type"]["phishing"] == 2
        assert summary["by_type"]["compliance"] == 1

    def test_org_isolation_summary(self, engine, org, other_org):
        make_program(engine, org)
        summary = engine.get_program_summary(other_org)
        assert summary["total_programs"] == 0
