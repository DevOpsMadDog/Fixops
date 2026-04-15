"""Tests for SecurityOKREngine — 35+ tests."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.security_okr_engine import SecurityOKREngine

ORG = "test-org"
OTHER_ORG = "other-org"


@pytest.fixture
def engine(tmp_path):
    return SecurityOKREngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# create_objective
# ---------------------------------------------------------------------------

def test_create_objective_basic(engine):
    obj = engine.create_objective(ORG, "Reduce attack surface", period="Q1-2026")
    assert obj["id"]
    assert obj["org_id"] == ORG
    assert obj["title"] == "Reduce attack surface"
    assert obj["status"] == "draft"
    assert obj["progress"] == 0.0
    assert obj["period"] == "Q1-2026"


def test_create_objective_all_periods(engine):
    periods = ["Q1-2026", "Q2-2026", "Q3-2026", "Q4-2026", "H1-2026", "H2-2026", "FY-2026"]
    for p in periods:
        obj = engine.create_objective(ORG, f"Obj-{p}", period=p)
        assert obj["period"] == p


def test_create_objective_invalid_period(engine):
    with pytest.raises(ValueError, match="period"):
        engine.create_objective(ORG, "Bad", period="Q5-2026")


def test_create_objective_empty_title(engine):
    with pytest.raises(ValueError, match="title"):
        engine.create_objective(ORG, "", period="Q1-2026")


def test_create_objective_with_owner(engine):
    obj = engine.create_objective(ORG, "Zero trust rollout", owner="alice", period="Q2-2026")
    assert obj["owner"] == "alice"


def test_create_objective_with_due_date(engine):
    obj = engine.create_objective(ORG, "Harden endpoints", due_date="2026-03-31", period="Q1-2026")
    assert obj["due_date"] == "2026-03-31"


# ---------------------------------------------------------------------------
# add_key_result
# ---------------------------------------------------------------------------

def test_add_key_result_basic(engine):
    obj = engine.create_objective(ORG, "Reduce vulns", period="Q1-2026")
    kr = engine.add_key_result(obj["id"], ORG, "Close 100 critical vulns", 100.0, unit="count")
    assert kr["id"]
    assert kr["objective_id"] == obj["id"]
    assert kr["target_value"] == 100.0
    assert kr["current_value"] == 0.0
    assert kr["progress"] == 0.0
    assert kr["unit"] == "count"


def test_add_key_result_all_units(engine):
    obj = engine.create_objective(ORG, "Test", period="Q1-2026")
    units = ["percentage", "count", "days", "hours", "score", "incidents", "vulnerabilities"]
    for u in units:
        kr = engine.add_key_result(obj["id"], ORG, f"KR-{u}", 10.0, unit=u)
        assert kr["unit"] == u


def test_add_key_result_invalid_unit(engine):
    obj = engine.create_objective(ORG, "Test", period="Q1-2026")
    with pytest.raises(ValueError, match="unit"):
        engine.add_key_result(obj["id"], ORG, "Bad KR", 10.0, unit="invalid")


def test_add_key_result_invalid_target(engine):
    obj = engine.create_objective(ORG, "Test", period="Q1-2026")
    with pytest.raises(ValueError, match="target_value"):
        engine.add_key_result(obj["id"], ORG, "Bad KR", 0.0)


def test_add_key_result_empty_title(engine):
    obj = engine.create_objective(ORG, "Test", period="Q1-2026")
    with pytest.raises(ValueError, match="title"):
        engine.add_key_result(obj["id"], ORG, "", 10.0)


# ---------------------------------------------------------------------------
# update_key_result
# ---------------------------------------------------------------------------

def test_update_key_result_computes_progress(engine):
    obj = engine.create_objective(ORG, "Patch systems", period="Q1-2026")
    kr = engine.add_key_result(obj["id"], ORG, "Patch 200 servers", 200.0, unit="count")
    updated_kr = engine.update_key_result(kr["id"], obj["id"], ORG, 100.0, "halfway there", "alice")
    assert updated_kr["current_value"] == 100.0
    assert updated_kr["progress"] == pytest.approx(50.0)


def test_update_key_result_progress_clamped_at_100(engine):
    obj = engine.create_objective(ORG, "Train staff", period="Q1-2026")
    kr = engine.add_key_result(obj["id"], ORG, "Train 50 people", 50.0, unit="count")
    updated_kr = engine.update_key_result(kr["id"], obj["id"], ORG, 60.0)
    assert updated_kr["progress"] == 100.0


def test_update_key_result_creates_okr_update_record(engine):
    obj = engine.create_objective(ORG, "Improve score", period="Q1-2026")
    kr = engine.add_key_result(obj["id"], ORG, "Score 90", 90.0, unit="score")
    engine.update_key_result(kr["id"], obj["id"], ORG, 45.0, notes="Q1 check-in", updated_by="bob")
    velocity = engine.get_okr_velocity(ORG)
    obj_entry = next(v for v in velocity if v["objective_id"] == obj["id"])
    assert len(obj_entry["updates"]) == 1
    assert obj_entry["updates"][0]["new_value"] == 45.0
    assert obj_entry["updates"][0]["notes"] == "Q1 check-in"
    assert obj_entry["updates"][0]["updated_by"] == "bob"


def test_update_key_result_updates_objective_progress(engine):
    obj = engine.create_objective(ORG, "Multi-KR objective", period="Q1-2026")
    kr1 = engine.add_key_result(obj["id"], ORG, "KR1", 100.0, unit="count")
    kr2 = engine.add_key_result(obj["id"], ORG, "KR2", 100.0, unit="count")
    engine.update_key_result(kr1["id"], obj["id"], ORG, 100.0)  # 100% progress
    engine.update_key_result(kr2["id"], obj["id"], ORG, 0.0)    # 0% progress
    obj_detail = engine.get_objective(obj["id"], ORG)
    assert obj_detail["progress"] == pytest.approx(50.0)


def test_update_key_result_not_found(engine):
    obj = engine.create_objective(ORG, "Test", period="Q1-2026")
    with pytest.raises(KeyError):
        engine.update_key_result("nonexistent", obj["id"], ORG, 10.0)


def test_update_key_result_records_previous_value(engine):
    obj = engine.create_objective(ORG, "Reduce incidents", period="Q1-2026")
    kr = engine.add_key_result(obj["id"], ORG, "Target: 0 incidents", 100.0, unit="incidents")
    engine.update_key_result(kr["id"], obj["id"], ORG, 50.0)
    engine.update_key_result(kr["id"], obj["id"], ORG, 80.0, notes="second update")
    velocity = engine.get_okr_velocity(ORG)
    obj_entry = next(v for v in velocity if v["objective_id"] == obj["id"])
    assert obj_entry["updates"][1]["previous_value"] == 50.0
    assert obj_entry["updates"][1]["new_value"] == 80.0


# ---------------------------------------------------------------------------
# get_objective
# ---------------------------------------------------------------------------

def test_get_objective_with_key_results(engine):
    obj = engine.create_objective(ORG, "Test obj", period="Q1-2026")
    engine.add_key_result(obj["id"], ORG, "KR1", 10.0)
    engine.add_key_result(obj["id"], ORG, "KR2", 20.0)
    result = engine.get_objective(obj["id"], ORG)
    assert result["title"] == "Test obj"
    assert len(result["key_results"]) == 2


def test_get_objective_not_found(engine):
    assert engine.get_objective("nonexistent", ORG) is None


def test_get_objective_org_isolation(engine):
    obj = engine.create_objective(ORG, "Secret obj", period="Q1-2026")
    assert engine.get_objective(obj["id"], OTHER_ORG) is None


# ---------------------------------------------------------------------------
# list_objectives
# ---------------------------------------------------------------------------

def test_list_objectives_all(engine):
    engine.create_objective(ORG, "Obj1", period="Q1-2026")
    engine.create_objective(ORG, "Obj2", period="Q2-2026")
    objectives = engine.list_objectives(ORG)
    assert len(objectives) == 2


def test_list_objectives_period_filter(engine):
    engine.create_objective(ORG, "Obj1", period="Q1-2026")
    engine.create_objective(ORG, "Obj2", period="Q2-2026")
    q1_objs = engine.list_objectives(ORG, period="Q1-2026")
    assert len(q1_objs) == 1
    assert q1_objs[0]["period"] == "Q1-2026"


def test_list_objectives_status_filter(engine):
    engine.create_objective(ORG, "Obj1", period="Q1-2026")
    objectives = engine.list_objectives(ORG, status="draft")
    assert len(objectives) == 1
    assert objectives[0]["status"] == "draft"


def test_list_objectives_org_isolation(engine):
    engine.create_objective(ORG, "Obj1", period="Q1-2026")
    engine.create_objective(OTHER_ORG, "Obj2", period="Q1-2026")
    objectives = engine.list_objectives(ORG)
    assert len(objectives) == 1


# ---------------------------------------------------------------------------
# get_period_summary
# ---------------------------------------------------------------------------

def test_period_summary_on_track_at_risk_off_track(engine):
    # on-track: progress >= 70
    obj1 = engine.create_objective(ORG, "On-track obj", period="Q1-2026")
    kr1 = engine.add_key_result(obj1["id"], ORG, "KR1", 100.0, unit="count")
    engine.update_key_result(kr1["id"], obj1["id"], ORG, 80.0)  # 80% → on-track

    # at-risk: 30 <= progress < 70
    obj2 = engine.create_objective(ORG, "At-risk obj", period="Q1-2026")
    kr2 = engine.add_key_result(obj2["id"], ORG, "KR2", 100.0, unit="count")
    engine.update_key_result(kr2["id"], obj2["id"], ORG, 50.0)  # 50% → at-risk

    # off-track: progress < 30
    obj3 = engine.create_objective(ORG, "Off-track obj", period="Q1-2026")
    kr3 = engine.add_key_result(obj3["id"], ORG, "KR3", 100.0, unit="count")
    engine.update_key_result(kr3["id"], obj3["id"], ORG, 10.0)  # 10% → off-track

    summary = engine.get_period_summary(ORG, "Q1-2026")
    assert summary["total_objectives"] == 3
    assert summary["on_track_count"] == 1
    assert summary["at_risk_count"] == 1
    assert summary["off_track_count"] == 1


def test_period_summary_empty_period(engine):
    summary = engine.get_period_summary(ORG, "Q3-2026")
    assert summary["total_objectives"] == 0
    assert summary["avg_progress"] == 0.0


def test_period_summary_avg_progress(engine):
    for p in [0.0, 50.0, 100.0]:
        obj = engine.create_objective(ORG, f"Obj at {p}%", period="Q2-2026")
        kr = engine.add_key_result(obj["id"], ORG, "KR", 100.0, unit="count")
        engine.update_key_result(kr["id"], obj["id"], ORG, p)
    summary = engine.get_period_summary(ORG, "Q2-2026")
    assert summary["avg_progress"] == pytest.approx(50.0)


# ---------------------------------------------------------------------------
# get_team_okrs
# ---------------------------------------------------------------------------

def test_get_team_okrs_filters_by_owner(engine):
    engine.create_objective(ORG, "Alice obj", owner="alice", period="Q1-2026")
    engine.create_objective(ORG, "Bob obj", owner="bob", period="Q1-2026")
    alice_objs = engine.get_team_okrs(ORG, "alice")
    assert len(alice_objs) == 1
    assert alice_objs[0]["owner"] == "alice"


def test_get_team_okrs_empty(engine):
    result = engine.get_team_okrs(ORG, "nobody")
    assert result == []


# ---------------------------------------------------------------------------
# close_objective
# ---------------------------------------------------------------------------

def test_close_objective_completed(engine):
    obj = engine.create_objective(ORG, "Complete me", period="Q1-2026")
    closed = engine.close_objective(obj["id"], ORG, "completed")
    assert closed["status"] == "completed"


def test_close_objective_cancelled(engine):
    obj = engine.create_objective(ORG, "Cancel me", period="Q1-2026")
    closed = engine.close_objective(obj["id"], ORG, "cancelled")
    assert closed["status"] == "cancelled"


def test_close_objective_progress_unchanged(engine):
    obj = engine.create_objective(ORG, "Test", period="Q1-2026")
    kr = engine.add_key_result(obj["id"], ORG, "KR", 100.0)
    engine.update_key_result(kr["id"], obj["id"], ORG, 75.0)
    closed = engine.close_objective(obj["id"], ORG, "completed")
    assert closed["progress"] == pytest.approx(75.0)


def test_close_objective_invalid_status(engine):
    obj = engine.create_objective(ORG, "Test", period="Q1-2026")
    with pytest.raises(ValueError, match="final_status"):
        engine.close_objective(obj["id"], ORG, "invalid_status")


def test_close_objective_not_found(engine):
    with pytest.raises(KeyError):
        engine.close_objective("nonexistent", ORG, "completed")


# ---------------------------------------------------------------------------
# get_okr_velocity
# ---------------------------------------------------------------------------

def test_get_okr_velocity_structure(engine):
    obj = engine.create_objective(ORG, "Velocity test", period="Q1-2026")
    kr = engine.add_key_result(obj["id"], ORG, "KR", 100.0)
    engine.update_key_result(kr["id"], obj["id"], ORG, 25.0, notes="week 1")
    engine.update_key_result(kr["id"], obj["id"], ORG, 50.0, notes="week 2")
    velocity = engine.get_okr_velocity(ORG)
    assert len(velocity) >= 1
    obj_vel = next(v for v in velocity if v["objective_id"] == obj["id"])
    assert obj_vel["objective_title"] == "Velocity test"
    assert len(obj_vel["updates"]) == 2


def test_get_okr_velocity_empty(engine):
    result = engine.get_okr_velocity(ORG)
    assert result == []


def test_get_okr_velocity_org_isolation(engine):
    obj = engine.create_objective(ORG, "My obj", period="Q1-2026")
    kr = engine.add_key_result(obj["id"], ORG, "KR", 100.0)
    engine.update_key_result(kr["id"], obj["id"], ORG, 50.0)
    other_velocity = engine.get_okr_velocity(OTHER_ORG)
    assert other_velocity == []
