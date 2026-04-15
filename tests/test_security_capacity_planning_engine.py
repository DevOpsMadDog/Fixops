"""Tests for SecurityCapacityPlanningEngine — 38+ tests covering all methods."""
from __future__ import annotations

import json
import pytest

from core.security_capacity_planning_engine import SecurityCapacityPlanningEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_capacity_planning.db")


@pytest.fixture
def engine(db_path):
    return SecurityCapacityPlanningEngine(db_path=db_path)


ORG = "org-cap-test"
ORG2 = "org-cap-other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_resource(engine, org=ORG, **kwargs):
    defaults = dict(
        resource_name="Alice",
        role="analyst",
        team="soc",
        fte=1.0,
        skills=["siem", "threat-hunting"],
        certifications=["CISSP"],
        cost_per_year=90000.0,
    )
    defaults.update(kwargs)
    return engine.register_resource(org_id=org, **defaults)


def _make_demand(engine, org=ORG, **kwargs):
    defaults = dict(
        demand_name="SOC Analyst Demand",
        domain="detection",
        priority="high",
        required_fte=1.0,
        required_skills=["siem"],
        timeline="q1",
    )
    defaults.update(kwargs)
    return engine.add_demand(org_id=org, **defaults)


# ---------------------------------------------------------------------------
# register_resource
# ---------------------------------------------------------------------------

def test_register_resource_returns_dict(engine):
    r = _make_resource(engine)
    assert r["id"]
    assert r["resource_name"] == "Alice"
    assert r["org_id"] == ORG


def test_register_resource_skills_stored_as_list(engine):
    r = _make_resource(engine, skills=["python", "splunk"])
    assert isinstance(r["skills"], list)
    assert "python" in r["skills"]


def test_register_resource_certifications_stored_as_list(engine):
    r = _make_resource(engine, certifications=["CEH", "OSCP"])
    assert isinstance(r["certifications"], list)
    assert "CEH" in r["certifications"]


def test_register_resource_utilization_starts_at_zero(engine):
    r = _make_resource(engine)
    assert r["utilization_pct"] == 0.0


def test_register_resource_status_active(engine):
    r = _make_resource(engine)
    assert r["status"] == "active"


def test_register_resource_invalid_role_raises(engine):
    with pytest.raises(ValueError, match="Invalid role"):
        _make_resource(engine, role="hacker")


def test_register_resource_empty_skills(engine):
    r = _make_resource(engine, skills=[])
    assert r["skills"] == []


# ---------------------------------------------------------------------------
# update_utilization
# ---------------------------------------------------------------------------

def test_update_utilization_sets_value(engine):
    r = _make_resource(engine)
    updated = engine.update_utilization(r["id"], ORG, 75.0)
    assert updated["utilization_pct"] == 75.0


def test_update_utilization_clamps_above_100(engine):
    r = _make_resource(engine)
    updated = engine.update_utilization(r["id"], ORG, 150.0)
    assert updated["utilization_pct"] == 100.0


def test_update_utilization_clamps_below_zero(engine):
    r = _make_resource(engine)
    updated = engine.update_utilization(r["id"], ORG, -10.0)
    assert updated["utilization_pct"] == 0.0


def test_update_utilization_wrong_org_raises(engine):
    r = _make_resource(engine)
    with pytest.raises(ValueError):
        engine.update_utilization(r["id"], ORG2, 50.0)


def test_update_utilization_nonexistent_raises(engine):
    with pytest.raises(ValueError):
        engine.update_utilization("no-such-id", ORG, 50.0)


# ---------------------------------------------------------------------------
# add_demand
# ---------------------------------------------------------------------------

def test_add_demand_returns_dict(engine):
    d = _make_demand(engine)
    assert d["id"]
    assert d["demand_name"] == "SOC Analyst Demand"
    assert d["org_id"] == ORG


def test_add_demand_required_skills_stored_as_list(engine):
    d = _make_demand(engine, required_skills=["siem", "edr"])
    assert isinstance(d["required_skills"], list)
    assert "siem" in d["required_skills"]


def test_add_demand_status_open(engine):
    d = _make_demand(engine)
    assert d["status"] == "open"


def test_add_demand_gap_fte_equals_required_when_no_resources(engine):
    d = _make_demand(engine, required_fte=2.0, required_skills=["splunk"])
    assert d["gap_fte"] == pytest.approx(2.0)


def test_add_demand_gap_fte_reduced_by_matching_resource(engine):
    # Resource with matching skill, 1.0 FTE
    _make_resource(engine, skills=["siem"], fte=1.0)
    # Demand requires 2.0 FTE with skill "siem"
    d = _make_demand(engine, required_fte=2.0, required_skills=["siem"])
    # gap = 2.0 - 1.0 = 1.0
    assert d["gap_fte"] == pytest.approx(1.0)


def test_add_demand_gap_fte_zero_when_enough_resources(engine):
    _make_resource(engine, skills=["threat-hunting"], fte=3.0)
    d = _make_demand(engine, required_fte=2.0, required_skills=["threat-hunting"])
    assert d["gap_fte"] == pytest.approx(0.0)


def test_add_demand_invalid_domain_raises(engine):
    with pytest.raises(ValueError, match="Invalid domain"):
        _make_demand(engine, domain="hacking")


def test_add_demand_invalid_priority_raises(engine):
    with pytest.raises(ValueError, match="Invalid priority"):
        _make_demand(engine, priority="urgent")


def test_add_demand_invalid_timeline_raises(engine):
    with pytest.raises(ValueError, match="Invalid timeline"):
        _make_demand(engine, timeline="asap")


# ---------------------------------------------------------------------------
# assign_resource
# ---------------------------------------------------------------------------

def test_assign_resource_fulfilled_when_fte_covers(engine):
    r = _make_resource(engine, fte=2.0)
    d = _make_demand(engine, required_fte=2.0)
    result = engine.assign_resource(d["id"], ORG, r["id"])
    assert result["status"] == "fulfilled"
    assert result["gap_fte"] == pytest.approx(0.0)


def test_assign_resource_partially_fulfilled_when_fte_insufficient(engine):
    r = _make_resource(engine, fte=1.0)
    d = _make_demand(engine, required_fte=3.0)
    result = engine.assign_resource(d["id"], ORG, r["id"])
    assert result["status"] == "partially_fulfilled"
    assert result["gap_fte"] == pytest.approx(2.0)


def test_assign_resource_stores_resource_id(engine):
    r = _make_resource(engine, fte=1.0)
    d = _make_demand(engine, required_fte=1.0)
    result = engine.assign_resource(d["id"], ORG, r["id"])
    assert result["assigned_resource_id"] == r["id"]


def test_assign_resource_wrong_org_demand_raises(engine):
    r = _make_resource(engine)
    d = _make_demand(engine)
    with pytest.raises(ValueError):
        engine.assign_resource(d["id"], ORG2, r["id"])


def test_assign_resource_nonexistent_resource_raises(engine):
    d = _make_demand(engine)
    with pytest.raises(ValueError):
        engine.assign_resource(d["id"], ORG, "no-such-resource")


# ---------------------------------------------------------------------------
# take_snapshot
# ---------------------------------------------------------------------------

def test_take_snapshot_returns_snapshot(engine):
    _make_resource(engine, fte=2.0)
    snap = engine.take_snapshot(ORG)
    assert snap["org_id"] == ORG
    assert snap["total_fte"] == pytest.approx(2.0)


def test_take_snapshot_utilization_rate_formula(engine):
    r = _make_resource(engine, fte=2.0)
    engine.update_utilization(r["id"], ORG, 50.0)
    snap = engine.take_snapshot(ORG)
    # utilized_fte = 2.0 * 50/100 = 1.0; rate = 1.0/2.0*100 = 50.0
    assert snap["utilization_rate"] == pytest.approx(50.0)


def test_take_snapshot_zero_rate_when_no_resources(engine):
    snap = engine.take_snapshot(ORG)
    assert snap["utilization_rate"] == pytest.approx(0.0)


def test_take_snapshot_demand_fte_includes_open_demands(engine):
    _make_demand(engine, required_fte=1.5)
    snap = engine.take_snapshot(ORG)
    assert snap["demand_fte"] == pytest.approx(1.5)


def test_take_snapshot_skill_gaps_is_list(engine):
    _make_demand(engine, required_skills=["forensics"], required_fte=1.0)
    snap = engine.take_snapshot(ORG)
    assert isinstance(snap["skill_gaps"], list)
    assert "forensics" in snap["skill_gaps"]


# ---------------------------------------------------------------------------
# get_capacity_summary
# ---------------------------------------------------------------------------

def test_get_capacity_summary_counts_resources(engine):
    _make_resource(engine)
    _make_resource(engine, resource_name="Bob")
    s = engine.get_capacity_summary(ORG)
    assert s["total_resources"] == 2


def test_get_capacity_summary_over_utilized_count(engine):
    r = _make_resource(engine)
    engine.update_utilization(r["id"], ORG, 95.0)
    s = engine.get_capacity_summary(ORG)
    assert s["over_utilized"] == 1


def test_get_capacity_summary_open_demands(engine):
    _make_demand(engine)
    _make_demand(engine, demand_name="Demand 2")
    s = engine.get_capacity_summary(ORG)
    assert s["open_demands"] == 2


def test_get_capacity_summary_total_gap_fte(engine):
    _make_demand(engine, required_fte=2.0, required_skills=["rare-skill"])
    s = engine.get_capacity_summary(ORG)
    assert s["total_gap_fte"] == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# get_skill_gap_analysis
# ---------------------------------------------------------------------------

def test_get_skill_gap_analysis_returns_unassigned_demands(engine):
    _make_demand(engine, required_skills=["cloud-security"])
    gaps = engine.get_skill_gap_analysis(ORG)
    assert len(gaps) == 1
    assert "cloud-security" in gaps[0]["required_skills"]


def test_get_skill_gap_analysis_excludes_assigned(engine):
    r = _make_resource(engine, fte=1.0)
    d = _make_demand(engine, required_fte=1.0)
    engine.assign_resource(d["id"], ORG, r["id"])
    # Demand is now fulfilled — still has assigned_resource_id so excluded
    gaps = engine.get_skill_gap_analysis(ORG)
    assert all(g["assigned_resource_id"] == "" for g in gaps)


# ---------------------------------------------------------------------------
# get_team_breakdown
# ---------------------------------------------------------------------------

def test_get_team_breakdown_groups_by_team(engine):
    _make_resource(engine, team="soc", resource_name="A", fte=1.0)
    _make_resource(engine, team="soc", resource_name="B", fte=1.0)
    _make_resource(engine, team="cloud", resource_name="C", fte=2.0)
    breakdown = engine.get_team_breakdown(ORG)
    teams = {t["team"]: t for t in breakdown}
    assert teams["soc"]["resource_count"] == 2
    assert teams["soc"]["total_fte"] == pytest.approx(2.0)
    assert teams["cloud"]["resource_count"] == 1
    assert teams["cloud"]["total_fte"] == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_resources(engine):
    _make_resource(engine, org=ORG)
    _make_resource(engine, org=ORG2, resource_name="Other")
    s1 = engine.get_capacity_summary(ORG)
    s2 = engine.get_capacity_summary(ORG2)
    assert s1["total_resources"] == 1
    assert s2["total_resources"] == 1


def test_org_isolation_demands(engine):
    _make_demand(engine, org=ORG)
    _make_demand(engine, org=ORG2, demand_name="Other demand")
    s1 = engine.get_capacity_summary(ORG)
    s2 = engine.get_capacity_summary(ORG2)
    assert s1["open_demands"] == 1
    assert s2["open_demands"] == 1


def test_org_isolation_snapshots(engine):
    _make_resource(engine, org=ORG, fte=3.0)
    _make_resource(engine, org=ORG2, fte=5.0)
    snap1 = engine.take_snapshot(ORG)
    snap2 = engine.take_snapshot(ORG2)
    assert snap1["total_fte"] == pytest.approx(3.0)
    assert snap2["total_fte"] == pytest.approx(5.0)
