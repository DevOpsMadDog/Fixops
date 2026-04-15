"""Tests for SecurityTrainingEffectivenessEngine.

Covers: program lifecycle, enrollment_count++, completion_count++ + avg_score
recompute + completion_rate recompute, score_improvement=post-pre,
passed=1 if>=passing_score, retention tracking, department_compliance
grouping, summary aggregation, org isolation.
"""

from __future__ import annotations

import tempfile
import os
import pytest

from core.security_training_effectiveness_engine import (
    SecurityTrainingEffectivenessEngine,
)


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "ste_test.db")
    return SecurityTrainingEffectivenessEngine(db_path=db)


@pytest.fixture
def org():
    return "org-ste-001"


@pytest.fixture
def org2():
    return "org-ste-002"


# ---------------------------------------------------------------------------
# Program creation
# ---------------------------------------------------------------------------

class TestCreateProgram:
    def test_create_basic(self, engine, org):
        p = engine.create_program(org, "Security Awareness 101")
        assert p["id"]
        assert p["org_id"] == org
        assert p["program_name"] == "Security Awareness 101"
        assert p["training_type"] == "awareness"
        assert p["delivery_method"] == "online"
        assert p["passing_score"] == 70.0
        assert p["enrollment_count"] == 0
        assert p["completion_count"] == 0
        assert p["avg_score"] == 0.0
        assert p["completion_rate"] == 0.0

    def test_create_all_fields(self, engine, org):
        p = engine.create_program(
            org, "Phishing Sim", training_type="phishing",
            target_audience="developers", delivery_method="simulation",
            duration_mins=30, passing_score=80.0,
        )
        assert p["training_type"] == "phishing"
        assert p["delivery_method"] == "simulation"
        assert p["passing_score"] == 80.0
        assert p["duration_mins"] == 30

    def test_passing_score_clamped_high(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=150.0)
        assert p["passing_score"] == 100.0

    def test_passing_score_clamped_low(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=-10.0)
        assert p["passing_score"] == 0.0

    def test_invalid_training_type(self, engine, org):
        with pytest.raises(ValueError, match="training_type"):
            engine.create_program(org, "Prog", training_type="unknown")

    def test_invalid_delivery_method(self, engine, org):
        with pytest.raises(ValueError, match="delivery_method"):
            engine.create_program(org, "Prog", delivery_method="carrier-pigeon")

    def test_all_valid_training_types(self, engine, org):
        for tt in ["awareness", "phishing", "compliance", "technical",
                   "leadership", "onboarding", "refresher"]:
            p = engine.create_program(org, f"Prog-{tt}", training_type=tt)
            assert p["training_type"] == tt

    def test_all_valid_delivery_methods(self, engine, org):
        for dm in ["online", "instructor-led", "hybrid", "self-paced", "simulation"]:
            p = engine.create_program(org, f"Prog-{dm}", delivery_method=dm)
            assert p["delivery_method"] == dm


# ---------------------------------------------------------------------------
# List programs
# ---------------------------------------------------------------------------

class TestListPrograms:
    def test_list_empty(self, engine, org):
        assert engine.list_programs(org) == []

    def test_list_multiple(self, engine, org):
        engine.create_program(org, "P1", training_type="awareness")
        engine.create_program(org, "P2", training_type="phishing")
        programs = engine.list_programs(org)
        assert len(programs) == 2

    def test_list_filtered_by_type(self, engine, org):
        engine.create_program(org, "P1", training_type="awareness")
        engine.create_program(org, "P2", training_type="phishing")
        engine.create_program(org, "P3", training_type="awareness")
        result = engine.list_programs(org, training_type="awareness")
        assert len(result) == 2
        for p in result:
            assert p["training_type"] == "awareness"

    def test_list_org_isolation(self, engine, org, org2):
        engine.create_program(org, "P1")
        engine.create_program(org2, "P2")
        assert len(engine.list_programs(org)) == 1
        assert len(engine.list_programs(org2)) == 1


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------

class TestEnroll:
    def test_enroll_increments_count(self, engine, org):
        p = engine.create_program(org, "Prog")
        engine.enroll(p["id"], org, "emp-001")
        updated = engine.list_programs(org)[0]
        assert updated["enrollment_count"] == 1

    def test_enroll_multiple_employees(self, engine, org):
        p = engine.create_program(org, "Prog")
        engine.enroll(p["id"], org, "emp-001")
        engine.enroll(p["id"], org, "emp-002")
        engine.enroll(p["id"], org, "emp-003")
        updated = engine.list_programs(org)[0]
        assert updated["enrollment_count"] == 3

    def test_enroll_returns_record(self, engine, org):
        p = engine.create_program(org, "Prog")
        result = engine.enroll(p["id"], org, "emp-001", department="Engineering")
        assert result["employee_id"] == "emp-001"
        assert result["program_id"] == p["id"]

    def test_enroll_not_found(self, engine, org):
        with pytest.raises(KeyError):
            engine.enroll("nonexistent-id", org, "emp-001")

    def test_enroll_org_isolation(self, engine, org, org2):
        p = engine.create_program(org, "Prog")
        with pytest.raises(KeyError):
            engine.enroll(p["id"], org2, "emp-001")


# ---------------------------------------------------------------------------
# Completion recording
# ---------------------------------------------------------------------------

class TestRecordCompletion:
    def test_completion_increments_count(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        engine.enroll(p["id"], org, "emp-001")
        engine.record_completion(p["id"], org, "emp-001", pre_score=50.0, post_score=80.0)
        updated = engine.list_programs(org)[0]
        assert updated["completion_count"] == 1

    def test_completion_avg_score_recomputed(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        engine.enroll(p["id"], org, "emp-001")
        engine.enroll(p["id"], org, "emp-002")
        engine.record_completion(p["id"], org, "emp-001", 40.0, 80.0)
        engine.record_completion(p["id"], org, "emp-002", 50.0, 60.0)
        updated = engine.list_programs(org)[0]
        assert abs(updated["avg_score"] - 70.0) < 0.01  # (80+60)/2

    def test_completion_rate_recomputed(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        engine.enroll(p["id"], org, "emp-001")
        engine.enroll(p["id"], org, "emp-002")
        engine.record_completion(p["id"], org, "emp-001", 40.0, 80.0)
        updated = engine.list_programs(org)[0]
        assert abs(updated["completion_rate"] - 50.0) < 0.01  # 1/2 * 100

    def test_score_improvement_computed(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        engine.enroll(p["id"], org, "emp-001")
        engine.record_completion(p["id"], org, "emp-001", pre_score=40.0, post_score=85.0)
        eff = engine.get_effectiveness(p["id"], org)
        assert abs(eff["avg_improvement"] - 45.0) < 0.01

    def test_passed_when_above_passing_score(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        engine.enroll(p["id"], org, "emp-001")
        engine.record_completion(p["id"], org, "emp-001", 50.0, 75.0)
        eff = engine.get_effectiveness(p["id"], org)
        assert eff["pass_rate"] == 100.0

    def test_not_passed_when_below_passing_score(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        engine.enroll(p["id"], org, "emp-001")
        engine.record_completion(p["id"], org, "emp-001", 30.0, 60.0)
        eff = engine.get_effectiveness(p["id"], org)
        assert eff["pass_rate"] == 0.0

    def test_passed_at_exact_passing_score(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        engine.enroll(p["id"], org, "emp-001")
        engine.record_completion(p["id"], org, "emp-001", 50.0, 70.0)
        eff = engine.get_effectiveness(p["id"], org)
        assert eff["pass_rate"] == 100.0

    def test_pre_post_scores_clamped(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        engine.enroll(p["id"], org, "emp-001")
        engine.record_completion(p["id"], org, "emp-001", pre_score=-10.0, post_score=150.0)
        eff = engine.get_effectiveness(p["id"], org)
        assert eff["avg_pre_score"] == 0.0
        assert eff["avg_post_score"] == 100.0

    def test_completion_not_found_program(self, engine, org):
        with pytest.raises(KeyError):
            engine.record_completion("bad-id", org, "emp-001", 50.0, 80.0)


# ---------------------------------------------------------------------------
# Knowledge retention
# ---------------------------------------------------------------------------

class TestRecordRetention:
    def test_record_retention_basic(self, engine, org):
        p = engine.create_program(org, "Prog")
        result = engine.record_retention(p["id"], org, "emp-001", 85.0, 30)
        assert result["retention_score"] == 85.0
        assert result["days_since_training"] == 30

    def test_retention_score_clamped(self, engine, org):
        p = engine.create_program(org, "Prog")
        result = engine.record_retention(p["id"], org, "emp-001", 150.0, 7)
        assert result["retention_score"] == 100.0

    def test_retention_score_clamped_low(self, engine, org):
        p = engine.create_program(org, "Prog")
        result = engine.record_retention(p["id"], org, "emp-001", -5.0, 7)
        assert result["retention_score"] == 0.0

    def test_retention_trend_in_effectiveness(self, engine, org):
        p = engine.create_program(org, "Prog")
        engine.record_retention(p["id"], org, "emp-001", 90.0, 5)   # bucket 7
        engine.record_retention(p["id"], org, "emp-002", 80.0, 25)  # bucket 30
        engine.record_retention(p["id"], org, "emp-003", 70.0, 55)  # bucket 60
        eff = engine.get_effectiveness(p["id"], org)
        assert "7" in eff["retention_trend"] or "30" in eff["retention_trend"]


# ---------------------------------------------------------------------------
# Effectiveness report
# ---------------------------------------------------------------------------

class TestGetEffectiveness:
    def test_effectiveness_no_completions(self, engine, org):
        p = engine.create_program(org, "Prog")
        eff = engine.get_effectiveness(p["id"], org)
        assert eff["avg_pre_score"] == 0.0
        assert eff["avg_post_score"] == 0.0
        assert eff["avg_improvement"] == 0.0
        assert eff["pass_rate"] == 0.0
        assert eff["by_department"] == {}
        assert eff["retention_trend"] == {}

    def test_effectiveness_not_found(self, engine, org):
        with pytest.raises(KeyError):
            engine.get_effectiveness("bad-id", org)

    def test_effectiveness_by_department(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        engine.enroll(p["id"], org, "emp-001", department="Engineering")
        engine.enroll(p["id"], org, "emp-002", department="Sales")
        engine.record_completion(p["id"], org, "emp-001", 50.0, 90.0)
        engine.record_completion(p["id"], org, "emp-002", 40.0, 60.0)
        eff = engine.get_effectiveness(p["id"], org)
        assert "Engineering" in eff["by_department"]
        assert "Sales" in eff["by_department"]
        assert abs(eff["by_department"]["Engineering"]["avg_score"] - 90.0) < 0.01

    def test_effectiveness_pass_rate_mixed(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        for i, score in enumerate([80.0, 90.0, 55.0, 65.0]):
            engine.enroll(p["id"], org, f"emp-{i}")
            engine.record_completion(p["id"], org, f"emp-{i}", 40.0, score)
        eff = engine.get_effectiveness(p["id"], org)
        assert abs(eff["pass_rate"] - 50.0) < 0.01  # 2 out of 4 passed


# ---------------------------------------------------------------------------
# Department compliance
# ---------------------------------------------------------------------------

class TestDepartmentCompliance:
    def test_empty_compliance(self, engine, org):
        result = engine.get_department_compliance(org)
        assert result == []

    def test_compliance_grouping(self, engine, org):
        p = engine.create_program(org, "Prog", passing_score=70.0)
        engine.enroll(p["id"], org, "emp-001", department="Eng")
        engine.enroll(p["id"], org, "emp-002", department="Eng")
        engine.enroll(p["id"], org, "emp-003", department="HR")
        engine.record_completion(p["id"], org, "emp-001", 50.0, 85.0)
        engine.record_completion(p["id"], org, "emp-002", 40.0, 75.0)
        result = engine.get_department_compliance(org)
        depts = {r["department"]: r for r in result}
        assert "Eng" in depts
        assert "HR" in depts
        eng = depts["Eng"]
        assert eng["passed_count"] == 2
        assert abs(eng["completion_rate"] - 100.0) < 0.01

    def test_compliance_org_isolation(self, engine, org, org2):
        p1 = engine.create_program(org, "Prog1", passing_score=70.0)
        p2 = engine.create_program(org2, "Prog2", passing_score=70.0)
        engine.enroll(p1["id"], org, "emp-a", department="Dept-A")
        engine.enroll(p2["id"], org2, "emp-b", department="Dept-B")
        result1 = engine.get_department_compliance(org)
        result2 = engine.get_department_compliance(org2)
        depts1 = {r["department"] for r in result1}
        depts2 = {r["department"] for r in result2}
        assert "Dept-A" in depts1
        assert "Dept-B" not in depts1
        assert "Dept-B" in depts2


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

class TestGetSummary:
    def test_summary_empty(self, engine, org):
        s = engine.get_summary(org)
        assert s["total_programs"] == 0
        assert s["total_enrollments"] == 0
        assert s["total_completions"] == 0
        assert s["overall_completion_rate"] == 0.0
        assert s["overall_avg_score"] == 0.0
        assert s["low_performing_programs"] == 0

    def test_summary_aggregates(self, engine, org):
        p1 = engine.create_program(org, "P1", passing_score=70.0)
        p2 = engine.create_program(org, "P2", passing_score=70.0)
        engine.enroll(p1["id"], org, "emp-001")
        engine.enroll(p1["id"], org, "emp-002")
        engine.enroll(p2["id"], org, "emp-003")
        engine.record_completion(p1["id"], org, "emp-001", 40.0, 80.0)
        s = engine.get_summary(org)
        assert s["total_programs"] == 2
        assert s["total_enrollments"] == 3
        assert s["total_completions"] == 1

    def test_summary_low_performing_programs(self, engine, org):
        # Program with avg_score < passing_score (no completions → avg=0 < 70)
        engine.create_program(org, "Low", passing_score=70.0)
        s = engine.get_summary(org)
        assert s["low_performing_programs"] >= 1

    def test_summary_org_isolation(self, engine, org, org2):
        engine.create_program(org, "P1")
        engine.create_program(org, "P2")
        engine.create_program(org2, "P3")
        assert engine.get_summary(org)["total_programs"] == 2
        assert engine.get_summary(org2)["total_programs"] == 1
