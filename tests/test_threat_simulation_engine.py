"""Tests for ThreatSimulationEngine — 30+ tests covering all methods and stats."""

from __future__ import annotations

import pytest

from core.threat_simulation_engine import ThreatSimulationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_threat_simulation.db")


@pytest.fixture
def engine(db_path):
    return ThreatSimulationEngine(db_path=db_path)


ORG = "org-ts-test"
ORG2 = "org-ts-other"


# ---------------------------------------------------------------------------
# create_scenario
# ---------------------------------------------------------------------------

def test_create_scenario_minimal(engine):
    s = engine.create_scenario(ORG, {"name": "Ransomware Test", "scenario_type": "ransomware"})
    assert s["name"] == "Ransomware Test"
    assert s["scenario_type"] == "ransomware"
    assert s["difficulty"] == "medium"
    assert s["status"] == "draft"
    assert "id" in s
    assert "created_at" in s
    assert s["mitre_techniques"] == []


def test_create_scenario_all_fields(engine):
    s = engine.create_scenario(ORG, {
        "name": "APT Campaign",
        "scenario_type": "apt",
        "difficulty": "expert",
        "description": "Nation-state APT simulation",
        "mitre_techniques": ["T1059", "T1078"],
    })
    assert s["scenario_type"] == "apt"
    assert s["difficulty"] == "expert"
    assert s["description"] == "Nation-state APT simulation"
    assert s["mitre_techniques"] == ["T1059", "T1078"]


def test_create_scenario_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_scenario(ORG, {"scenario_type": "ransomware"})


def test_create_scenario_missing_type(engine):
    with pytest.raises(ValueError, match="Invalid scenario_type"):
        engine.create_scenario(ORG, {"name": "X", "scenario_type": ""})


def test_create_scenario_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid scenario_type"):
        engine.create_scenario(ORG, {"name": "X", "scenario_type": "zombie_attack"})


def test_create_scenario_invalid_difficulty(engine):
    with pytest.raises(ValueError, match="Invalid difficulty"):
        engine.create_scenario(ORG, {"name": "X", "scenario_type": "ddos", "difficulty": "impossible"})


def test_create_scenario_all_valid_types(engine):
    valid_types = ["ransomware", "apt", "insider_threat", "supply_chain",
                   "ddos", "data_exfiltration", "lateral_movement"]
    for t in valid_types:
        s = engine.create_scenario(ORG, {"name": f"Type {t}", "scenario_type": t})
        assert s["scenario_type"] == t


def test_create_scenario_all_difficulties(engine):
    for d in ("easy", "medium", "hard", "expert"):
        s = engine.create_scenario(ORG, {"name": f"Diff {d}", "scenario_type": "ddos", "difficulty": d})
        assert s["difficulty"] == d


def test_create_scenario_unique_ids(engine):
    s1 = engine.create_scenario(ORG, {"name": "S1", "scenario_type": "ddos"})
    s2 = engine.create_scenario(ORG, {"name": "S2", "scenario_type": "apt"})
    assert s1["id"] != s2["id"]


# ---------------------------------------------------------------------------
# list_scenarios / get_scenario
# ---------------------------------------------------------------------------

def test_list_scenarios_empty(engine):
    assert engine.list_scenarios(ORG) == []


def test_list_scenarios_returns_all(engine):
    engine.create_scenario(ORG, {"name": "A", "scenario_type": "ddos"})
    engine.create_scenario(ORG, {"name": "B", "scenario_type": "apt"})
    assert len(engine.list_scenarios(ORG)) == 2


def test_list_scenarios_filter_type(engine):
    engine.create_scenario(ORG, {"name": "Ransomware", "scenario_type": "ransomware"})
    engine.create_scenario(ORG, {"name": "APT", "scenario_type": "apt"})
    results = engine.list_scenarios(ORG, scenario_type="ransomware")
    assert len(results) == 1
    assert results[0]["scenario_type"] == "ransomware"


def test_list_scenarios_filter_difficulty(engine):
    engine.create_scenario(ORG, {"name": "Easy", "scenario_type": "ddos", "difficulty": "easy"})
    engine.create_scenario(ORG, {"name": "Hard", "scenario_type": "apt", "difficulty": "hard"})
    results = engine.list_scenarios(ORG, difficulty="easy")
    assert len(results) == 1
    assert results[0]["difficulty"] == "easy"


def test_list_scenarios_org_isolation(engine):
    engine.create_scenario(ORG, {"name": "Org1", "scenario_type": "ddos"})
    engine.create_scenario(ORG2, {"name": "Org2", "scenario_type": "apt"})
    assert len(engine.list_scenarios(ORG)) == 1
    assert len(engine.list_scenarios(ORG2)) == 1


def test_get_scenario_found(engine):
    s = engine.create_scenario(ORG, {"name": "Findable", "scenario_type": "ddos"})
    fetched = engine.get_scenario(ORG, s["id"])
    assert fetched is not None
    assert fetched["name"] == "Findable"


def test_get_scenario_not_found(engine):
    assert engine.get_scenario(ORG, "ghost-id") is None


def test_get_scenario_wrong_org(engine):
    s = engine.create_scenario(ORG, {"name": "Private", "scenario_type": "ddos"})
    assert engine.get_scenario(ORG2, s["id"]) is None


# ---------------------------------------------------------------------------
# start_simulation
# ---------------------------------------------------------------------------

def test_start_simulation_basic(engine):
    s = engine.create_scenario(ORG, {"name": "Sim Scenario", "scenario_type": "apt"})
    sim = engine.start_simulation(ORG, {
        "scenario_id": s["id"],
        "initiated_by": "analyst@corp.com",
        "target_systems": ["server-01", "server-02"],
    })
    assert sim["scenario_id"] == s["id"]
    assert sim["initiated_by"] == "analyst@corp.com"
    assert sim["status"] == "running"
    assert sim["target_systems"] == ["server-01", "server-02"]
    assert sim["detections"] == []
    assert "id" in sim
    assert "started_at" in sim


def test_start_simulation_missing_scenario_id(engine):
    with pytest.raises(ValueError, match="scenario_id is required"):
        engine.start_simulation(ORG, {"initiated_by": "analyst"})


def test_start_simulation_missing_initiated_by(engine):
    with pytest.raises(ValueError, match="initiated_by is required"):
        engine.start_simulation(ORG, {"scenario_id": "some-id"})


# ---------------------------------------------------------------------------
# record_detection
# ---------------------------------------------------------------------------

def test_record_detection_basic(engine):
    s = engine.create_scenario(ORG, {"name": "Detect Test", "scenario_type": "apt"})
    sim = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "red-team"})
    updated = engine.record_detection(ORG, sim["id"], {
        "technique": "T1059",
        "detected_by": "SIEM",
        "detection_time_seconds": 120,
        "true_positive": True,
    })
    assert updated is not None
    assert len(updated["detections"]) == 1
    assert updated["detections"][0]["technique"] == "T1059"
    assert updated["detections"][0]["detected_by"] == "SIEM"
    assert updated["detections"][0]["true_positive"] is True


def test_record_detection_accumulates(engine):
    s = engine.create_scenario(ORG, {"name": "Multi Detect", "scenario_type": "apt"})
    sim = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "red-team"})
    engine.record_detection(ORG, sim["id"], {"technique": "T1059", "detected_by": "EDR"})
    updated = engine.record_detection(ORG, sim["id"], {"technique": "T1078", "detected_by": "SIEM"})
    assert len(updated["detections"]) == 2


def test_record_detection_missing_technique(engine):
    s = engine.create_scenario(ORG, {"name": "X", "scenario_type": "ddos"})
    sim = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "analyst"})
    with pytest.raises(ValueError, match="technique is required"):
        engine.record_detection(ORG, sim["id"], {"detected_by": "EDR"})


def test_record_detection_missing_detected_by(engine):
    s = engine.create_scenario(ORG, {"name": "X", "scenario_type": "ddos"})
    sim = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "analyst"})
    with pytest.raises(ValueError, match="detected_by is required"):
        engine.record_detection(ORG, sim["id"], {"technique": "T1059"})


def test_record_detection_sim_not_found(engine):
    result = engine.record_detection(ORG, "ghost-sim", {"technique": "T1059", "detected_by": "EDR"})
    assert result is None


# ---------------------------------------------------------------------------
# complete_simulation
# ---------------------------------------------------------------------------

def test_complete_simulation_basic(engine):
    s = engine.create_scenario(ORG, {"name": "Complete Test", "scenario_type": "apt"})
    sim = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "red-team"})
    completed = engine.complete_simulation(ORG, sim["id"], {
        "total_techniques_executed": 10,
        "techniques_detected": 7,
        "dwell_time_seconds": 3600,
    })
    assert completed["status"] == "completed"
    assert completed["total_techniques_executed"] == 10
    assert completed["techniques_detected"] == 7
    assert completed["detection_rate"] == 70.0
    assert completed["dwell_time_seconds"] == 3600
    assert completed["completed_at"] is not None


def test_complete_simulation_detection_rate_math(engine):
    s = engine.create_scenario(ORG, {"name": "Rate Math", "scenario_type": "ddos"})
    sim = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "analyst"})
    completed = engine.complete_simulation(ORG, sim["id"], {
        "total_techniques_executed": 4,
        "techniques_detected": 1,
    })
    assert completed["detection_rate"] == 25.0


def test_complete_simulation_zero_techniques(engine):
    s = engine.create_scenario(ORG, {"name": "Zero", "scenario_type": "ddos"})
    sim = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "analyst"})
    completed = engine.complete_simulation(ORG, sim["id"], {
        "total_techniques_executed": 0,
        "techniques_detected": 0,
    })
    assert completed["detection_rate"] == 0.0


def test_complete_simulation_not_found(engine):
    result = engine.complete_simulation(ORG, "ghost-sim", {"total_techniques_executed": 5})
    assert result is None


# ---------------------------------------------------------------------------
# list_simulations
# ---------------------------------------------------------------------------

def test_list_simulations_empty(engine):
    assert engine.list_simulations(ORG) == []


def test_list_simulations_filter_status(engine):
    s = engine.create_scenario(ORG, {"name": "S", "scenario_type": "apt"})
    sim = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "analyst"})
    engine.complete_simulation(ORG, sim["id"], {"total_techniques_executed": 5, "techniques_detected": 3})
    running = engine.list_simulations(ORG, status="running")
    completed = engine.list_simulations(ORG, status="completed")
    assert len(running) == 0
    assert len(completed) == 1


def test_list_simulations_filter_scenario_id(engine):
    s1 = engine.create_scenario(ORG, {"name": "S1", "scenario_type": "apt"})
    s2 = engine.create_scenario(ORG, {"name": "S2", "scenario_type": "ddos"})
    engine.start_simulation(ORG, {"scenario_id": s1["id"], "initiated_by": "analyst"})
    engine.start_simulation(ORG, {"scenario_id": s2["id"], "initiated_by": "analyst"})
    results = engine.list_simulations(ORG, scenario_id=s1["id"])
    assert len(results) == 1
    assert results[0]["scenario_id"] == s1["id"]


def test_list_simulations_org_isolation(engine):
    s = engine.create_scenario(ORG, {"name": "S", "scenario_type": "apt"})
    engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "analyst"})
    assert len(engine.list_simulations(ORG)) == 1
    assert len(engine.list_simulations(ORG2)) == 0


# ---------------------------------------------------------------------------
# get_simulation_stats
# ---------------------------------------------------------------------------

def test_stats_empty_org(engine):
    stats = engine.get_simulation_stats(ORG)
    assert stats["total_scenarios"] == 0
    assert stats["by_type"] == {}
    assert stats["total_simulations"] == 0
    assert stats["completed_simulations"] == 0
    assert stats["avg_detection_rate"] == 0.0
    assert stats["avg_dwell_time_seconds"] == 0.0


def test_stats_scenario_counts(engine):
    engine.create_scenario(ORG, {"name": "A", "scenario_type": "apt"})
    engine.create_scenario(ORG, {"name": "B", "scenario_type": "apt"})
    engine.create_scenario(ORG, {"name": "C", "scenario_type": "ddos"})
    stats = engine.get_simulation_stats(ORG)
    assert stats["total_scenarios"] == 3
    assert stats["by_type"]["apt"] == 2
    assert stats["by_type"]["ddos"] == 1


def test_stats_avg_detection_rate_completed_only(engine):
    s = engine.create_scenario(ORG, {"name": "S", "scenario_type": "apt"})
    # Running sim — should NOT count in avg
    engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "analyst"})
    # Completed sim with 80% detection
    sim2 = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "analyst"})
    engine.complete_simulation(ORG, sim2["id"], {
        "total_techniques_executed": 10,
        "techniques_detected": 8,
        "dwell_time_seconds": 1800,
    })
    stats = engine.get_simulation_stats(ORG)
    assert stats["completed_simulations"] == 1
    assert stats["avg_detection_rate"] == 80.0
    assert stats["avg_dwell_time_seconds"] == 1800.0


def test_stats_avg_detection_rate_multiple(engine):
    s = engine.create_scenario(ORG, {"name": "S", "scenario_type": "apt"})
    sim1 = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "analyst"})
    sim2 = engine.start_simulation(ORG, {"scenario_id": s["id"], "initiated_by": "analyst"})
    engine.complete_simulation(ORG, sim1["id"], {"total_techniques_executed": 10, "techniques_detected": 6})
    engine.complete_simulation(ORG, sim2["id"], {"total_techniques_executed": 10, "techniques_detected": 4})
    stats = engine.get_simulation_stats(ORG)
    assert stats["avg_detection_rate"] == 50.0
