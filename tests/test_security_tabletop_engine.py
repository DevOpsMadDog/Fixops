"""Tests for SecurityTabletopEngine — wave 20."""

import pytest
from core.security_tabletop_engine import SecurityTabletopEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityTabletopEngine(db_path=str(tmp_path / "tabletop.db"))


# ---------------------------------------------------------------------------
# create_exercise — basic
# ---------------------------------------------------------------------------

def test_create_exercise_returns_record(engine):
    ex = engine.create_exercise("org1", {
        "title": "Ransomware Response Drill",
        "scenario_type": "ransomware",
    })
    assert ex["title"] == "Ransomware Response Drill"
    assert ex["scenario_type"] == "ransomware"
    assert ex["status"] == "planned"
    assert ex["overall_score"] == 0.0
    assert ex["findings_count"] == 0
    assert "id" in ex
    assert "created_at" in ex


def test_create_exercise_invalid_scenario_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid scenario_type"):
        engine.create_exercise("org1", {
            "title": "Bad Exercise",
            "scenario_type": "alien_invasion",
        })


def test_create_exercise_invalid_status_raises(engine):
    with pytest.raises(ValueError, match="Invalid status"):
        engine.create_exercise("org1", {
            "title": "Bad Status",
            "scenario_type": "ransomware",
            "status": "archived",
        })


def test_create_exercise_all_scenario_types(engine):
    scenario_types = [
        "ransomware", "data_breach", "supply_chain", "insider_threat",
        "nation_state", "ddos", "phishing", "physical",
    ]
    for st in scenario_types:
        ex = engine.create_exercise("org1", {"title": f"Exercise-{st}", "scenario_type": st})
        assert ex["scenario_type"] == st


def test_create_exercise_missing_title_raises(engine):
    with pytest.raises(ValueError, match="title"):
        engine.create_exercise("org1", {"scenario_type": "ransomware"})


def test_create_exercise_with_facilitator(engine):
    ex = engine.create_exercise("org1", {
        "title": "Phishing Sim",
        "scenario_type": "phishing",
        "facilitator": "Alice",
        "participant_count": 10,
    })
    assert ex["facilitator"] == "Alice"
    assert ex["participant_count"] == 10


# ---------------------------------------------------------------------------
# list_exercises
# ---------------------------------------------------------------------------

def test_list_exercises_empty(engine):
    assert engine.list_exercises("org1") == []


def test_list_exercises_org_isolation(engine):
    engine.create_exercise("org1", {"title": "Org1 Exercise", "scenario_type": "ddos"})
    assert engine.list_exercises("org2") == []
    assert len(engine.list_exercises("org1")) == 1


def test_list_exercises_filter_by_status(engine):
    engine.create_exercise("org1", {"title": "Planned", "scenario_type": "ransomware", "status": "planned"})
    engine.create_exercise("org1", {"title": "In Progress", "scenario_type": "ddos", "status": "in_progress"})
    planned = engine.list_exercises("org1", status="planned")
    assert len(planned) == 1
    assert planned[0]["title"] == "Planned"


def test_list_exercises_filter_by_scenario_type(engine):
    engine.create_exercise("org1", {"title": "Ransomware Ex", "scenario_type": "ransomware"})
    engine.create_exercise("org1", {"title": "DDoS Ex", "scenario_type": "ddos"})
    ransomware = engine.list_exercises("org1", scenario_type="ransomware")
    assert len(ransomware) == 1
    assert ransomware[0]["scenario_type"] == "ransomware"


# ---------------------------------------------------------------------------
# get_exercise
# ---------------------------------------------------------------------------

def test_get_exercise_returns_record(engine):
    ex = engine.create_exercise("org1", {"title": "GetMe", "scenario_type": "phishing"})
    found = engine.get_exercise("org1", ex["id"])
    assert found is not None
    assert found["id"] == ex["id"]
    assert found["title"] == "GetMe"


def test_get_exercise_not_found_returns_none(engine):
    assert engine.get_exercise("org1", "nonexistent-id") is None


def test_get_exercise_org_isolation(engine):
    ex = engine.create_exercise("org1", {"title": "OrgTest", "scenario_type": "ransomware"})
    assert engine.get_exercise("org2", ex["id"]) is None


# ---------------------------------------------------------------------------
# complete_exercise
# ---------------------------------------------------------------------------

def test_complete_exercise_sets_completed_status(engine):
    ex = engine.create_exercise("org1", {"title": "Complete Me", "scenario_type": "data_breach"})
    assert ex["status"] == "planned"
    completed = engine.complete_exercise("org1", ex["id"], 85.0)
    assert completed["status"] == "completed"
    assert completed["overall_score"] == 85.0
    assert completed["completed_at"] is not None


def test_complete_exercise_clamps_score_high(engine):
    ex = engine.create_exercise("org1", {"title": "Over Score", "scenario_type": "ransomware"})
    completed = engine.complete_exercise("org1", ex["id"], 150.0)
    assert completed["overall_score"] == 100.0


def test_complete_exercise_clamps_score_low(engine):
    ex = engine.create_exercise("org1", {"title": "Under Score", "scenario_type": "ddos"})
    completed = engine.complete_exercise("org1", ex["id"], -5.0)
    assert completed["overall_score"] == 0.0


def test_complete_exercise_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.complete_exercise("org1", "nonexistent-id", 75.0)


# ---------------------------------------------------------------------------
# add_participant + list_participants
# ---------------------------------------------------------------------------

def test_add_participant_returns_record(engine):
    ex = engine.create_exercise("org1", {"title": "Participant Test", "scenario_type": "phishing"})
    p = engine.add_participant("org1", {
        "exercise_id": ex["id"],
        "name": "Bob Smith",
        "role": "CISO",
        "department": "Security",
        "attended": True,
        "performance_score": 88.0,
    })
    assert p["name"] == "Bob Smith"
    assert p["role"] == "CISO"
    assert p["department"] == "Security"
    assert p["performance_score"] == 88.0
    assert "id" in p


def test_add_participant_performance_score_clamp(engine):
    ex = engine.create_exercise("org1", {"title": "Clamp Test", "scenario_type": "ransomware"})
    p_high = engine.add_participant("org1", {
        "exercise_id": ex["id"],
        "name": "OverPerformer",
        "performance_score": 200.0,
    })
    assert p_high["performance_score"] == 100.0

    p_low = engine.add_participant("org1", {
        "exercise_id": ex["id"],
        "name": "UnderPerformer",
        "performance_score": -20.0,
    })
    assert p_low["performance_score"] == 0.0


def test_list_participants_basic_flow(engine):
    ex = engine.create_exercise("org1", {"title": "List Part", "scenario_type": "ddos"})
    engine.add_participant("org1", {"exercise_id": ex["id"], "name": "Alice"})
    engine.add_participant("org1", {"exercise_id": ex["id"], "name": "Bob"})
    participants = engine.list_participants("org1", ex["id"])
    assert len(participants) == 2
    names = {p["name"] for p in participants}
    assert "Alice" in names
    assert "Bob" in names


def test_list_participants_exercise_isolation(engine):
    ex1 = engine.create_exercise("org1", {"title": "Ex1", "scenario_type": "ransomware"})
    ex2 = engine.create_exercise("org1", {"title": "Ex2", "scenario_type": "phishing"})
    engine.add_participant("org1", {"exercise_id": ex1["id"], "name": "Ex1Participant"})
    assert engine.list_participants("org1", ex2["id"]) == []


def test_add_participant_missing_exercise_id_raises(engine):
    with pytest.raises(ValueError, match="exercise_id"):
        engine.add_participant("org1", {"name": "NoExercise"})


def test_add_participant_missing_name_raises(engine):
    ex = engine.create_exercise("org1", {"title": "NameTest", "scenario_type": "ddos"})
    with pytest.raises(ValueError, match="name"):
        engine.add_participant("org1", {"exercise_id": ex["id"]})


# ---------------------------------------------------------------------------
# record_finding
# ---------------------------------------------------------------------------

def test_record_finding_returns_record(engine):
    ex = engine.create_exercise("org1", {"title": "Finding Test", "scenario_type": "data_breach"})
    f = engine.record_finding("org1", {
        "exercise_id": ex["id"],
        "finding_type": "gap",
        "title": "No incident response plan",
        "description": "Team had no documented IR plan",
        "severity": "critical",
        "assigned_to": "security_team",
    })
    assert f["finding_type"] == "gap"
    assert f["title"] == "No incident response plan"
    assert f["severity"] == "critical"
    assert f["status"] == "open"
    assert "id" in f


def test_record_finding_invalid_finding_type_raises(engine):
    ex = engine.create_exercise("org1", {"title": "BadType", "scenario_type": "ransomware"})
    with pytest.raises(ValueError, match="Invalid finding_type"):
        engine.record_finding("org1", {
            "exercise_id": ex["id"],
            "finding_type": "observation",
            "title": "Bad type finding",
        })


def test_record_finding_invalid_severity_raises(engine):
    ex = engine.create_exercise("org1", {"title": "BadSev", "scenario_type": "ransomware"})
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.record_finding("org1", {
            "exercise_id": ex["id"],
            "finding_type": "gap",
            "title": "Bad severity",
            "severity": "extreme",
        })


def test_record_finding_all_finding_types(engine):
    ex = engine.create_exercise("org1", {"title": "AllTypes", "scenario_type": "phishing"})
    for ftype in ["gap", "strength", "improvement", "critical_failure"]:
        f = engine.record_finding("org1", {
            "exercise_id": ex["id"],
            "finding_type": ftype,
            "title": f"Finding-{ftype}",
        })
        assert f["finding_type"] == ftype


def test_record_finding_all_severities(engine):
    ex = engine.create_exercise("org1", {"title": "AllSev", "scenario_type": "ddos"})
    for sev in ["critical", "high", "medium", "low"]:
        f = engine.record_finding("org1", {
            "exercise_id": ex["id"],
            "finding_type": "gap",
            "title": f"Finding-{sev}",
            "severity": sev,
        })
        assert f["severity"] == sev


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

def test_list_findings_filter_by_severity(engine):
    ex = engine.create_exercise("org1", {"title": "FilterSev", "scenario_type": "ransomware"})
    engine.record_finding("org1", {"exercise_id": ex["id"], "finding_type": "gap", "title": "Crit", "severity": "critical"})
    engine.record_finding("org1", {"exercise_id": ex["id"], "finding_type": "gap", "title": "Low", "severity": "low"})
    critical = engine.list_findings("org1", severity="critical")
    assert len(critical) == 1
    assert critical[0]["severity"] == "critical"


def test_list_findings_filter_by_status(engine):
    ex = engine.create_exercise("org1", {"title": "FilterStatus", "scenario_type": "phishing"})
    engine.record_finding("org1", {"exercise_id": ex["id"], "finding_type": "gap", "title": "Open", "status": "open"})
    engine.record_finding("org1", {"exercise_id": ex["id"], "finding_type": "strength", "title": "Remediated", "status": "remediated"})
    open_findings = engine.list_findings("org1", status="open")
    assert len(open_findings) == 1
    assert open_findings[0]["title"] == "Open"


def test_list_findings_filter_by_exercise_id(engine):
    ex1 = engine.create_exercise("org1", {"title": "Ex1F", "scenario_type": "ddos"})
    ex2 = engine.create_exercise("org1", {"title": "Ex2F", "scenario_type": "ransomware"})
    engine.record_finding("org1", {"exercise_id": ex1["id"], "finding_type": "gap", "title": "Finding Ex1"})
    engine.record_finding("org1", {"exercise_id": ex2["id"], "finding_type": "gap", "title": "Finding Ex2"})
    findings_ex1 = engine.list_findings("org1", exercise_id=ex1["id"])
    assert len(findings_ex1) == 1
    assert findings_ex1[0]["title"] == "Finding Ex1"


def test_list_findings_org_isolation(engine):
    ex = engine.create_exercise("org1", {"title": "OrgIso", "scenario_type": "ransomware"})
    engine.record_finding("org1", {"exercise_id": ex["id"], "finding_type": "gap", "title": "Org1 Finding"})
    assert engine.list_findings("org2") == []


# ---------------------------------------------------------------------------
# get_tabletop_stats
# ---------------------------------------------------------------------------

def test_get_tabletop_stats_empty(engine):
    stats = engine.get_tabletop_stats("empty_org")
    assert stats["total_exercises"] == 0
    assert stats["completed_exercises"] == 0
    assert stats["total_findings"] == 0
    assert stats["open_findings"] == 0
    assert stats["critical_findings"] == 0
    assert stats["avg_score"] == 0.0
    assert stats["by_scenario"] == {}
    assert stats["by_status"] == {}


def test_get_tabletop_stats_populated(engine):
    ex1 = engine.create_exercise("org1", {"title": "Stat Ex1", "scenario_type": "ransomware"})
    ex2 = engine.create_exercise("org1", {"title": "Stat Ex2", "scenario_type": "phishing"})
    ex3 = engine.create_exercise("org1", {"title": "Stat Ex3", "scenario_type": "ransomware"})

    engine.complete_exercise("org1", ex1["id"], 80.0)
    engine.complete_exercise("org1", ex2["id"], 60.0)

    engine.record_finding("org1", {"exercise_id": ex1["id"], "finding_type": "gap", "title": "F1", "severity": "critical", "status": "open"})
    engine.record_finding("org1", {"exercise_id": ex1["id"], "finding_type": "gap", "title": "F2", "severity": "high", "status": "remediated"})
    engine.record_finding("org1", {"exercise_id": ex2["id"], "finding_type": "strength", "title": "F3", "severity": "low", "status": "open"})

    stats = engine.get_tabletop_stats("org1")
    assert stats["total_exercises"] == 3
    assert stats["completed_exercises"] == 2
    assert stats["avg_score"] == pytest.approx(70.0, rel=1e-2)
    assert stats["total_findings"] == 3
    assert stats["open_findings"] == 2
    assert stats["critical_findings"] == 1
    assert stats["by_scenario"]["ransomware"] == 2
    assert stats["by_scenario"]["phishing"] == 1
    assert stats["by_status"]["completed"] == 2
    assert stats["by_status"]["planned"] == 1


def test_get_tabletop_stats_org_isolation(engine):
    ex = engine.create_exercise("org1", {"title": "OrgStat", "scenario_type": "ddos"})
    engine.complete_exercise("org1", ex["id"], 90.0)
    stats = engine.get_tabletop_stats("org2")
    assert stats["total_exercises"] == 0
    assert stats["completed_exercises"] == 0
