"""Tests for ControlTestingEngine — 35+ tests covering all methods and edge cases."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

import pytest
from core.control_testing_engine import ControlTestingEngine, _score_to_status

ORG = "org-ct-test"
ORG2 = "org-ct-other"


@pytest.fixture
def engine(tmp_path):
    return ControlTestingEngine(db_path=str(tmp_path / "test_ct.db"))


def _make_control(engine, org=ORG, **kwargs):
    defaults = dict(
        control_name="MFA Enforcement",
        control_type="preventive",
        framework="NIST",
        description="Enforce MFA for all users",
        owner="security-team",
        test_frequency_days=30,
    )
    defaults.update(kwargs)
    return engine.create_control(org_id=org, **defaults)


def _run_test(engine, control_id, org=ORG, score=85.0, **kwargs):
    defaults = dict(
        test_name="MFA check",
        test_method="automated",
        tester="bot",
        result="pass",
        score=score,
        findings="",
        evidence="",
    )
    defaults.update(kwargs)
    return engine.run_test(control_id=control_id, org_id=org, **defaults)


# ---------------------------------------------------------------------------
# _score_to_status unit tests
# ---------------------------------------------------------------------------

def test_score_to_status_effective_boundary():
    assert _score_to_status(80.0) == "effective"


def test_score_to_status_effective_above():
    assert _score_to_status(95.0) == "effective"


def test_score_to_status_partially_effective_boundary():
    assert _score_to_status(60.0) == "partially-effective"


def test_score_to_status_partially_effective_range():
    assert _score_to_status(79.9) == "partially-effective"


def test_score_to_status_ineffective_boundary():
    assert _score_to_status(40.0) == "ineffective"


def test_score_to_status_ineffective_range():
    assert _score_to_status(59.9) == "ineffective"


def test_score_to_status_failing_below_40():
    assert _score_to_status(39.9) == "failing"


def test_score_to_status_failing_zero():
    assert _score_to_status(0.0) == "failing"


# ---------------------------------------------------------------------------
# create_control
# ---------------------------------------------------------------------------

def test_create_control_basic(engine):
    c = _make_control(engine)
    assert c["id"]
    assert c["control_name"] == "MFA Enforcement"
    assert c["status"] == "untested"
    assert c["effectiveness_score"] == 0.0
    assert c["last_tested"] is None


def test_create_control_org_isolation(engine):
    c1 = _make_control(engine, org=ORG)
    c2 = _make_control(engine, org=ORG2)
    assert c1["id"] != c2["id"]


def test_create_control_custom_frequency(engine):
    c = _make_control(engine, test_frequency_days=14)
    assert c["test_frequency_days"] == 14


# ---------------------------------------------------------------------------
# run_test
# ---------------------------------------------------------------------------

def test_run_test_creates_record(engine):
    c = _make_control(engine)
    t = _run_test(engine, c["id"])
    assert t["id"]
    assert t["control_id"] == c["id"]
    assert t["result"] == "pass"


def test_run_test_updates_control_last_tested(engine):
    c = _make_control(engine)
    _run_test(engine, c["id"])
    updated = engine.get_control(c["id"], ORG)
    assert updated["last_tested"] is not None


def test_run_test_score_clamped_above_100(engine):
    c = _make_control(engine)
    t = _run_test(engine, c["id"], score=150.0)
    assert t["score"] == 100.0


def test_run_test_score_clamped_below_0(engine):
    c = _make_control(engine)
    t = _run_test(engine, c["id"], score=-10.0)
    assert t["score"] == 0.0


def test_run_test_status_effective_at_80(engine):
    c = _make_control(engine)
    _run_test(engine, c["id"], score=80.0)
    updated = engine.get_control(c["id"], ORG)
    assert updated["status"] == "effective"


def test_run_test_status_partially_effective_at_60(engine):
    c = _make_control(engine)
    _run_test(engine, c["id"], score=60.0)
    updated = engine.get_control(c["id"], ORG)
    assert updated["status"] == "partially-effective"


def test_run_test_status_ineffective_at_40(engine):
    c = _make_control(engine)
    _run_test(engine, c["id"], score=40.0)
    updated = engine.get_control(c["id"], ORG)
    assert updated["status"] == "ineffective"


def test_run_test_status_failing_below_40(engine):
    c = _make_control(engine)
    _run_test(engine, c["id"], score=30.0)
    updated = engine.get_control(c["id"], ORG)
    assert updated["status"] == "failing"


def test_run_test_rolling_avg_last_5(engine):
    c = _make_control(engine)
    # Run 6 tests: first 1 is old and should NOT affect avg
    # First test score=0 (this is the 6th oldest and ignored in rolling avg)
    _run_test(engine, c["id"], score=0.0)
    # Next 5 tests all score=100
    for _ in range(5):
        _run_test(engine, c["id"], score=100.0)
    updated = engine.get_control(c["id"], ORG)
    # Rolling avg of last 5 = 100.0
    assert updated["effectiveness_score"] == 100.0
    assert updated["status"] == "effective"


def test_run_test_rolling_avg_mixed_scores(engine):
    c = _make_control(engine)
    # 3 tests with scores 80, 60, 100 → avg=80
    _run_test(engine, c["id"], score=80.0)
    _run_test(engine, c["id"], score=60.0)
    _run_test(engine, c["id"], score=100.0)
    updated = engine.get_control(c["id"], ORG)
    assert abs(updated["effectiveness_score"] - 80.0) < 0.01


def test_run_test_wrong_control_returns_none(engine):
    result = _run_test(engine, "no-such-id")
    assert result is None


def test_run_test_wrong_org_returns_none(engine):
    c = _make_control(engine)
    result = engine.run_test(
        control_id=c["id"], org_id=ORG2,
        test_name="X", test_method="manual", tester="x",
        result="pass", score=90.0, findings="", evidence="",
    )
    assert result is None


# ---------------------------------------------------------------------------
# create_schedule / update_schedule_run
# ---------------------------------------------------------------------------

def test_create_schedule(engine):
    c = _make_control(engine)
    s = engine.create_schedule(ORG, c["id"], "Monthly check", 30)
    assert s["id"]
    assert s["schedule_name"] == "Monthly check"
    assert s["enabled"] == 1
    assert s["last_run"] is None


def test_update_schedule_run_advances_next_run(engine):
    c = _make_control(engine)
    s = engine.create_schedule(ORG, c["id"], "Weekly", 7)
    old_next = s["next_run"]
    updated = engine.update_schedule_run(s["id"], ORG)
    assert updated["last_run"] is not None
    assert updated["next_run"] != old_next


def test_update_schedule_run_wrong_org_returns_none(engine):
    c = _make_control(engine)
    s = engine.create_schedule(ORG, c["id"], "S", 7)
    result = engine.update_schedule_run(s["id"], ORG2)
    assert result is None


# ---------------------------------------------------------------------------
# get_control
# ---------------------------------------------------------------------------

def test_get_control_includes_recent_tests(engine):
    c = _make_control(engine)
    _run_test(engine, c["id"], score=75.0)
    result = engine.get_control(c["id"], ORG)
    assert len(result["recent_tests"]) == 1


def test_get_control_limits_to_10_recent(engine):
    c = _make_control(engine)
    for i in range(12):
        _run_test(engine, c["id"], score=float(i * 5))
    result = engine.get_control(c["id"], ORG)
    assert len(result["recent_tests"]) == 10


def test_get_control_wrong_org_returns_none(engine):
    c = _make_control(engine)
    result = engine.get_control(c["id"], ORG2)
    assert result is None


# ---------------------------------------------------------------------------
# list_controls
# ---------------------------------------------------------------------------

def test_list_controls_by_org(engine):
    _make_control(engine, org=ORG, control_name="C1")
    _make_control(engine, org=ORG, control_name="C2")
    _make_control(engine, org=ORG2, control_name="C3")
    results = engine.list_controls(ORG)
    assert len(results) == 2


def test_list_controls_filter_framework(engine):
    _make_control(engine, control_name="NIST-C", framework="NIST")
    _make_control(engine, control_name="SOC2-C", framework="SOC2")
    results = engine.list_controls(ORG, framework="SOC2")
    assert all(r["framework"] == "SOC2" for r in results)


def test_list_controls_filter_status(engine):
    c = _make_control(engine, control_name="Tested")
    _run_test(engine, c["id"], score=90.0)
    _make_control(engine, control_name="Untested")
    results = engine.list_controls(ORG, status="untested")
    assert all(r["status"] == "untested" for r in results)


# ---------------------------------------------------------------------------
# get_due_tests
# ---------------------------------------------------------------------------

def test_get_due_tests_never_tested(engine):
    _make_control(engine)
    due = engine.get_due_tests(ORG)
    assert len(due) == 1


def test_get_due_tests_recently_tested_not_due(engine):
    c = _make_control(engine, test_frequency_days=90)
    _run_test(engine, c["id"], score=80.0)
    due = engine.get_due_tests(ORG)
    # Recently tested, frequency=90 days → not due
    assert len(due) == 0


# ---------------------------------------------------------------------------
# get_control_effectiveness_summary
# ---------------------------------------------------------------------------

def test_get_control_effectiveness_summary_empty(engine):
    summary = engine.get_control_effectiveness_summary(ORG)
    assert summary["avg_effectiveness_score"] == 0.0
    assert summary["controls_never_tested"] == 0


def test_get_control_effectiveness_summary_counts(engine):
    c1 = _make_control(engine, control_name="C1")
    c2 = _make_control(engine, control_name="C2")
    _run_test(engine, c1["id"], score=90.0)
    # c2 never tested
    summary = engine.get_control_effectiveness_summary(ORG)
    assert summary["controls_never_tested"] == 1
    assert "effective" in summary["by_status"]


def test_get_control_effectiveness_summary_framework_breakdown(engine):
    _make_control(engine, control_name="N1", framework="NIST")
    _make_control(engine, control_name="N2", framework="NIST")
    _make_control(engine, control_name="S1", framework="SOC2")
    summary = engine.get_control_effectiveness_summary(ORG)
    fw = {f["framework"]: f["control_count"] for f in summary["framework_breakdown"]}
    assert fw["NIST"] == 2
    assert fw["SOC2"] == 1


# ---------------------------------------------------------------------------
# get_failing_controls
# ---------------------------------------------------------------------------

def test_get_failing_controls(engine):
    c1 = _make_control(engine, control_name="Good")
    c2 = _make_control(engine, control_name="Bad")
    c3 = _make_control(engine, control_name="Ugly")
    _run_test(engine, c1["id"], score=90.0)
    _run_test(engine, c2["id"], score=30.0)   # failing
    _run_test(engine, c3["id"], score=45.0)   # ineffective
    failing = engine.get_failing_controls(ORG)
    names = {f["control_name"] for f in failing}
    assert "Bad" in names
    assert "Ugly" in names
    assert "Good" not in names


def test_get_failing_controls_empty_when_all_effective(engine):
    c = _make_control(engine)
    _run_test(engine, c["id"], score=95.0)
    failing = engine.get_failing_controls(ORG)
    assert failing == []
