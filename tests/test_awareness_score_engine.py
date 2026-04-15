"""
Tests for AwarenessScoreEngine (Security Awareness Score Tracker).
25+ tests covering all methods with org isolation.
"""
from __future__ import annotations

import pytest

from core.awareness_score_engine import AwarenessScoreEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_awareness.db")
    return AwarenessScoreEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_employee(employee_id="emp-001", **kwargs):
    return {
        "employee_id": employee_id,
        "name": "Alice Smith",
        "department": "Engineering",
        "role": "Software Engineer",
        "risk_level": "standard",
        **kwargs,
    }


def _make_training(name="Security Basics 101", **kwargs):
    return {
        "training_name": name,
        "training_type": "security_basics",
        "score": 85.0,
        "passed": 1,
        **kwargs,
    }


def _make_phishing(campaign="Q1 Phishing Sim", **kwargs):
    return {
        "campaign_name": campaign,
        "clicked": 0,
        "reported": 1,
        **kwargs,
    }


# ---------------------------------------------------------------------------
# register_employee
# ---------------------------------------------------------------------------

class TestRegisterEmployee:
    def test_register_returns_record(self, engine):
        emp = engine.register_employee(ORG_A, _make_employee())
        assert emp["profile_id"]
        assert emp["org_id"] == ORG_A
        assert emp["employee_id"] == "emp-001"
        assert emp["risk_level"] == "standard"

    def test_register_all_risk_levels(self, engine):
        for risk, eid in [("high_risk", "e1"), ("elevated", "e2"), ("standard", "e3")]:
            emp = engine.register_employee(ORG_A, _make_employee(employee_id=eid, risk_level=risk))
            assert emp["risk_level"] == risk

    def test_register_invalid_risk_level_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid risk_level"):
            engine.register_employee(ORG_A, _make_employee(risk_level="super_high"))

    def test_upsert_updates_name(self, engine):
        engine.register_employee(ORG_A, _make_employee(name="Alice"))
        engine.register_employee(ORG_A, _make_employee(name="Alice Updated"))
        emps = engine.list_employees(ORG_A)
        assert len(emps) == 1
        assert emps[0]["name"] == "Alice Updated"

    def test_org_isolation(self, engine):
        engine.register_employee(ORG_A, _make_employee("emp-a"))
        engine.register_employee(ORG_B, _make_employee("emp-b"))
        assert len(engine.list_employees(ORG_A)) == 1
        assert len(engine.list_employees(ORG_B)) == 1


# ---------------------------------------------------------------------------
# list_employees
# ---------------------------------------------------------------------------

class TestListEmployees:
    def test_list_by_department(self, engine):
        engine.register_employee(ORG_A, _make_employee("e1", department="Engineering"))
        engine.register_employee(ORG_A, _make_employee("e2", department="Finance"))
        eng = engine.list_employees(ORG_A, department="Engineering")
        assert len(eng) == 1
        assert eng[0]["department"] == "Engineering"

    def test_list_by_risk_level(self, engine):
        engine.register_employee(ORG_A, _make_employee("e1", risk_level="high_risk"))
        engine.register_employee(ORG_A, _make_employee("e2", risk_level="standard"))
        high = engine.list_employees(ORG_A, risk_level="high_risk")
        assert len(high) == 1

    def test_list_all(self, engine):
        for i in range(3):
            engine.register_employee(ORG_A, _make_employee(f"e{i}"))
        assert len(engine.list_employees(ORG_A)) == 3


# ---------------------------------------------------------------------------
# record_training
# ---------------------------------------------------------------------------

class TestRecordTraining:
    def test_record_returns_record(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        tc = engine.record_training(ORG_A, "emp-001", _make_training())
        assert tc["completion_id"]
        assert tc["employee_id"] == "emp-001"
        assert tc["passed"] == 1
        assert tc["score"] == 85.0

    def test_record_all_training_types(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        types = ["phishing_sim", "security_basics", "data_handling",
                 "incident_response", "compliance", "role_specific"]
        for i, tt in enumerate(types):
            tc = engine.record_training(ORG_A, "emp-001",
                                        _make_training(f"T{i}", training_type=tt))
            assert tc["training_type"] == tt

    def test_record_invalid_type_raises(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        with pytest.raises(ValueError, match="Invalid training_type"):
            engine.record_training(ORG_A, "emp-001", _make_training(training_type="yoga"))

    def test_record_sets_expires_at(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        tc = engine.record_training(ORG_A, "emp-001", _make_training())
        assert tc["expires_at"] is not None

    def test_record_updates_last_training_at(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        engine.record_training(ORG_A, "emp-001", _make_training())
        emps = engine.list_employees(ORG_A)
        assert emps[0]["last_training_at"] is not None


# ---------------------------------------------------------------------------
# record_phishing_test
# ---------------------------------------------------------------------------

class TestRecordPhishingTest:
    def test_record_not_clicked(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        pt = engine.record_phishing_test(ORG_A, "emp-001", _make_phishing(clicked=0))
        assert pt["test_id"]
        assert pt["clicked"] == 0

    def test_record_clicked(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        pt = engine.record_phishing_test(ORG_A, "emp-001", _make_phishing(clicked=1))
        assert pt["clicked"] == 1

    def test_click_rate_updated_on_profile(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        engine.record_phishing_test(ORG_A, "emp-001", _make_phishing(clicked=1))
        engine.record_phishing_test(ORG_A, "emp-001", _make_phishing(clicked=0))
        emps = engine.list_employees(ORG_A)
        # 1 click out of 2 tests = 0.5
        assert emps[0]["phishing_click_rate"] == pytest.approx(0.5, abs=0.01)


# ---------------------------------------------------------------------------
# calculate_score
# ---------------------------------------------------------------------------

class TestCalculateScore:
    def _setup_employee_with_data(self, engine, clicked=0):
        engine.register_employee(ORG_A, _make_employee())
        engine.record_training(ORG_A, "emp-001", _make_training(score=80.0, passed=1))
        engine.record_phishing_test(ORG_A, "emp-001", _make_phishing(clicked=clicked))

    def test_calculate_score_returns_record(self, engine):
        self._setup_employee_with_data(engine)
        score = engine.calculate_score(ORG_A, "emp-001")
        assert score["score_id"]
        assert score["employee_id"] == "emp-001"
        assert 0.0 <= score["overall_score"] <= 100.0
        assert score["risk_tier"] in {"champion", "proficient", "developing", "at_risk"}

    def test_calculate_champion_score(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        # High training score, no phishing clicks
        for i in range(5):
            engine.record_training(ORG_A, "emp-001", _make_training(f"T{i}", score=100.0, passed=1))
        engine.record_phishing_test(ORG_A, "emp-001", _make_phishing(clicked=0))
        score = engine.calculate_score(ORG_A, "emp-001")
        assert score["risk_tier"] == "champion"
        assert score["overall_score"] >= 85.0

    def test_calculate_at_risk_score(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        # Low training, high click rate
        engine.record_training(ORG_A, "emp-001", _make_training(score=10.0, passed=0))
        for _ in range(5):
            engine.record_phishing_test(ORG_A, "emp-001", _make_phishing(clicked=1))
        score = engine.calculate_score(ORG_A, "emp-001")
        assert score["risk_tier"] == "at_risk"
        assert score["overall_score"] < 50.0

    def test_calculate_score_unknown_employee_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.calculate_score(ORG_A, "ghost-emp")

    def test_calculate_score_org_isolation(self, engine):
        engine.register_employee(ORG_A, _make_employee("emp-a"))
        engine.register_employee(ORG_B, _make_employee("emp-b"))
        engine.record_training(ORG_A, "emp-a", _make_training())
        engine.record_training(ORG_B, "emp-b", _make_training())
        score_a = engine.calculate_score(ORG_A, "emp-a")
        score_b = engine.calculate_score(ORG_B, "emp-b")
        assert score_a["org_id"] == ORG_A
        assert score_b["org_id"] == ORG_B

    def test_calculate_saves_score_record(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        engine.record_training(ORG_A, "emp-001", _make_training())
        engine.calculate_score(ORG_A, "emp-001")
        scores = engine.list_scores(ORG_A)
        assert len(scores) == 1


# ---------------------------------------------------------------------------
# list_scores
# ---------------------------------------------------------------------------

class TestListScores:
    def test_list_scores_by_risk_tier(self, engine):
        engine.register_employee(ORG_A, _make_employee("e1"))
        engine.register_employee(ORG_A, _make_employee("e2"))
        # Make e1 champion
        for i in range(5):
            engine.record_training(ORG_A, "e1", _make_training(f"T{i}", score=100.0, passed=1))
        engine.record_phishing_test(ORG_A, "e1", _make_phishing(clicked=0))
        engine.calculate_score(ORG_A, "e1")
        # e2 has no data → at_risk
        engine.calculate_score(ORG_A, "e2")
        champions = engine.list_scores(ORG_A, risk_tier="champion")
        assert all(s["risk_tier"] == "champion" for s in champions)

    def test_list_latest_score_per_employee(self, engine):
        engine.register_employee(ORG_A, _make_employee())
        engine.record_training(ORG_A, "emp-001", _make_training())
        # Calculate twice
        engine.calculate_score(ORG_A, "emp-001")
        engine.calculate_score(ORG_A, "emp-001")
        scores = engine.list_scores(ORG_A)
        # Should only return 1 record (latest) per employee
        assert len(scores) == 1


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

class TestSummaries:
    def test_department_summary_empty(self, engine):
        summary = engine.get_department_summary(ORG_A)
        assert summary["by_department"] == {}

    def test_department_summary_with_data(self, engine):
        engine.register_employee(ORG_A, _make_employee("e1", department="Engineering"))
        engine.register_employee(ORG_A, _make_employee("e2", department="Finance"))
        engine.record_training(ORG_A, "e1", _make_training())
        engine.calculate_score(ORG_A, "e1")
        engine.calculate_score(ORG_A, "e2")
        summary = engine.get_department_summary(ORG_A)
        assert "Engineering" in summary["by_department"]
        assert "Finance" in summary["by_department"]

    def test_awareness_stats_empty(self, engine):
        stats = engine.get_awareness_stats(ORG_A)
        assert stats["total_employees"] == 0
        assert stats["avg_overall_score"] == 0.0

    def test_awareness_stats_with_data(self, engine):
        engine.register_employee(ORG_A, _make_employee("e1"))
        engine.register_employee(ORG_A, _make_employee("e2"))
        engine.record_training(ORG_A, "e1", _make_training())
        engine.record_phishing_test(ORG_A, "e1", _make_phishing(clicked=0))
        engine.record_phishing_test(ORG_A, "e2", _make_phishing(clicked=1))
        engine.calculate_score(ORG_A, "e1")
        engine.calculate_score(ORG_A, "e2")
        stats = engine.get_awareness_stats(ORG_A)
        assert stats["total_employees"] == 2
        assert stats["phishing_click_rate_avg"] >= 0.0

    def test_awareness_stats_org_isolation(self, engine):
        engine.register_employee(ORG_A, _make_employee("e1"))
        engine.register_employee(ORG_B, _make_employee("e2"))
        engine.register_employee(ORG_B, _make_employee("e3"))
        stats_a = engine.get_awareness_stats(ORG_A)
        stats_b = engine.get_awareness_stats(ORG_B)
        assert stats_a["total_employees"] == 1
        assert stats_b["total_employees"] == 2
