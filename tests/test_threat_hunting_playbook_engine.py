"""Tests for ThreatHuntingPlaybookEngine — 35+ tests."""

from __future__ import annotations

import json

import pytest

from core.threat_hunting_playbook_engine import ThreatHuntingPlaybookEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "hunt_playbook_test.db")
    return ThreatHuntingPlaybookEngine(db_path=db)


@pytest.fixture
def org():
    return "org_hunt_test"


@pytest.fixture
def playbook(engine, org):
    return engine.create_playbook(
        org_id=org,
        playbook_name="Lateral Movement Hunt",
        hunt_type="hypothesis",
        threat_category="lateral-movement",
        mitre_technique="T1021",
        hypothesis="Attacker used SMB for lateral movement",
        data_sources=["EDR", "SIEM"],
        tools=["Velociraptor", "Sigma"],
    )


# ---------------------------------------------------------------------------
# create_playbook
# ---------------------------------------------------------------------------


def test_create_playbook_defaults(engine, org):
    pb = engine.create_playbook(org, "Hunt1", "ioc", "ransomware")
    assert pb["playbook_name"] == "Hunt1"
    assert pb["hunt_type"] == "ioc"
    assert pb["threat_category"] == "ransomware"
    assert pb["status"] == "draft"
    assert pb["execution_count"] == 0
    assert pb["success_rate"] == 0.0
    assert pb["avg_duration_mins"] == 0.0
    assert pb["executions"] == []
    assert pb["hypotheses"] == []


def test_create_playbook_data_sources_as_json(engine, org):
    pb = engine.create_playbook(org, "H", "ioc", "cat", data_sources=["A", "B"])
    assert json.loads(pb["data_sources"]) == ["A", "B"]


def test_create_playbook_tools_as_json(engine, org):
    pb = engine.create_playbook(org, "H", "ioc", "cat", tools=["T1", "T2"])
    assert json.loads(pb["tools"]) == ["T1", "T2"]


def test_create_playbook_all_hunt_types(engine, org):
    for ht in ("hypothesis", "ioc", "anomaly", "behavioral", "threat-actor", "ttp", "situational"):
        pb = engine.create_playbook(org, f"pb-{ht}", ht, "cat")
        assert pb["hunt_type"] == ht


def test_create_playbook_invalid_hunt_type(engine, org):
    with pytest.raises(ValueError, match="Invalid hunt_type"):
        engine.create_playbook(org, "bad", "random_type", "cat")


# ---------------------------------------------------------------------------
# list_playbooks
# ---------------------------------------------------------------------------


def test_list_playbooks_empty(engine, org):
    assert engine.list_playbooks(org) == []


def test_list_playbooks_all(engine, org, playbook):
    engine.create_playbook(org, "P2", "ioc", "phishing")
    pbs = engine.list_playbooks(org)
    assert len(pbs) == 2


def test_list_playbooks_filter_by_hunt_type(engine, org):
    engine.create_playbook(org, "P1", "hypothesis", "cat1")
    engine.create_playbook(org, "P2", "ioc", "cat2")
    result = engine.list_playbooks(org, hunt_type="hypothesis")
    assert len(result) == 1
    assert result[0]["hunt_type"] == "hypothesis"


def test_list_playbooks_filter_by_threat_category(engine, org):
    engine.create_playbook(org, "P1", "ioc", "ransomware")
    engine.create_playbook(org, "P2", "ioc", "phishing")
    result = engine.list_playbooks(org, threat_category="ransomware")
    assert len(result) == 1
    assert result[0]["threat_category"] == "ransomware"


# ---------------------------------------------------------------------------
# add_hypothesis
# ---------------------------------------------------------------------------


def test_add_hypothesis_basic(engine, org, playbook):
    h = engine.add_hypothesis(playbook["id"], org, "Attacker used PowerShell", "high")
    assert h["hypothesis_text"] == "Attacker used PowerShell"
    assert h["confidence"] == "high"
    assert h["validated"] == 0
    assert h["evidence"] == ""


def test_add_hypothesis_all_confidences(engine, org, playbook):
    for c in ("high", "medium", "low"):
        h = engine.add_hypothesis(playbook["id"], org, f"hyp-{c}", c)
        assert h["confidence"] == c


def test_add_hypothesis_invalid_confidence(engine, org, playbook):
    with pytest.raises(ValueError, match="Invalid confidence"):
        engine.add_hypothesis(playbook["id"], org, "hyp", "very_high")


def test_add_hypothesis_nonexistent_playbook(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.add_hypothesis("nonexistent", org, "hyp")


def test_add_hypothesis_appears_in_get_playbook(engine, org, playbook):
    engine.add_hypothesis(playbook["id"], org, "My hypothesis", "medium")
    pb = engine.get_playbook(playbook["id"], org)
    assert len(pb["hypotheses"]) == 1
    assert pb["hypotheses"][0]["hypothesis_text"] == "My hypothesis"


# ---------------------------------------------------------------------------
# validate_hypothesis
# ---------------------------------------------------------------------------


def test_validate_hypothesis(engine, org, playbook):
    h = engine.add_hypothesis(playbook["id"], org, "hyp", "medium")
    vh = engine.validate_hypothesis(h["id"], org, "Found SMB traffic on 3 hosts")
    assert vh["validated"] == 1
    assert vh["evidence"] == "Found SMB traffic on 3 hosts"


def test_validate_hypothesis_nonexistent(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.validate_hypothesis("nonexistent", org, "evidence")


def test_validate_hypothesis_org_isolation(engine, org):
    pb = engine.create_playbook(org, "P", "ioc", "cat")
    h = engine.add_hypothesis(pb["id"], org, "hyp", "medium")
    with pytest.raises(ValueError, match="not found"):
        engine.validate_hypothesis(h["id"], "other_org", "evidence")


# ---------------------------------------------------------------------------
# start_execution
# ---------------------------------------------------------------------------


def test_start_execution_creates_record(engine, org, playbook):
    ex = engine.start_execution(playbook["id"], org, analyst="alice")
    assert ex["analyst"] == "alice"
    assert ex["outcome"] == "in_progress"
    assert ex["start_time"] is not None
    assert ex["end_time"] is None
    assert ex["duration_mins"] == 0.0


def test_start_execution_increments_execution_count(engine, org, playbook):
    engine.start_execution(playbook["id"], org)
    engine.start_execution(playbook["id"], org)
    pb = engine.get_playbook(playbook["id"], org)
    assert pb["execution_count"] == 2


def test_start_execution_nonexistent_playbook(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.start_execution("nonexistent", org)


def test_start_execution_appears_in_get_playbook(engine, org, playbook):
    engine.start_execution(playbook["id"], org, analyst="bob")
    pb = engine.get_playbook(playbook["id"], org)
    assert len(pb["executions"]) == 1
    assert pb["executions"][0]["analyst"] == "bob"


# ---------------------------------------------------------------------------
# complete_execution
# ---------------------------------------------------------------------------


def test_complete_execution_sets_outcome(engine, org, playbook):
    ex = engine.start_execution(playbook["id"], org)
    completed = engine.complete_execution(ex["id"], org, outcome="finding", findings_count=3)
    assert completed["outcome"] == "finding"
    assert completed["findings_count"] == 3
    assert completed["end_time"] is not None


def test_complete_execution_invalid_outcome(engine, org, playbook):
    ex = engine.start_execution(playbook["id"], org)
    with pytest.raises(ValueError, match="Invalid outcome"):
        engine.complete_execution(ex["id"], org, outcome="bad_outcome")


def test_complete_execution_iocs_as_json(engine, org, playbook):
    ex = engine.start_execution(playbook["id"], org)
    completed = engine.complete_execution(
        ex["id"], org, outcome="finding", iocs_discovered=["1.2.3.4", "evil.com"]
    )
    assert json.loads(completed["iocs_discovered"]) == ["1.2.3.4", "evil.com"]


def test_complete_execution_nonexistent(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.complete_execution("nonexistent", org, outcome="no_finding")


def test_complete_execution_success_rate_finding(engine, org, playbook):
    """finding → success_rate = 100%"""
    ex = engine.start_execution(playbook["id"], org)
    engine.complete_execution(ex["id"], org, outcome="finding")
    pb = engine.get_playbook(playbook["id"], org)
    assert pb["success_rate"] == pytest.approx(100.0, abs=0.01)


def test_complete_execution_success_rate_no_finding(engine, org, playbook):
    """no_finding → success_rate = 0%"""
    ex = engine.start_execution(playbook["id"], org)
    engine.complete_execution(ex["id"], org, outcome="no_finding")
    pb = engine.get_playbook(playbook["id"], org)
    assert pb["success_rate"] == pytest.approx(0.0, abs=0.01)


def test_complete_execution_success_rate_partial(engine, org, playbook):
    """partial_finding counts as success"""
    ex = engine.start_execution(playbook["id"], org)
    engine.complete_execution(ex["id"], org, outcome="partial_finding")
    pb = engine.get_playbook(playbook["id"], org)
    assert pb["success_rate"] == pytest.approx(100.0, abs=0.01)


def test_complete_execution_success_rate_mixed(engine, org, playbook):
    """2 finding + 1 no_finding out of 3 = 66.67%"""
    ex1 = engine.start_execution(playbook["id"], org)
    ex2 = engine.start_execution(playbook["id"], org)
    ex3 = engine.start_execution(playbook["id"], org)
    engine.complete_execution(ex1["id"], org, outcome="finding")
    engine.complete_execution(ex2["id"], org, outcome="finding")
    engine.complete_execution(ex3["id"], org, outcome="no_finding")
    pb = engine.get_playbook(playbook["id"], org)
    assert pb["success_rate"] == pytest.approx(200.0 / 3, abs=0.1)


def test_complete_execution_avg_duration_computed(engine, org, playbook):
    """avg_duration_mins should be >= 0 after execution completes"""
    ex = engine.start_execution(playbook["id"], org)
    engine.complete_execution(ex["id"], org, outcome="finding")
    pb = engine.get_playbook(playbook["id"], org)
    assert pb["avg_duration_mins"] >= 0.0


def test_complete_execution_all_outcomes(engine, org):
    for outcome in ("finding", "no_finding", "partial_finding", "inconclusive"):
        pb = engine.create_playbook(org, f"pb-{outcome}", "ioc", "cat")
        ex = engine.start_execution(pb["id"], org)
        completed = engine.complete_execution(ex["id"], org, outcome=outcome)
        assert completed["outcome"] == outcome


# ---------------------------------------------------------------------------
# org_id isolation
# ---------------------------------------------------------------------------


def test_org_isolation_playbooks(engine):
    engine.create_playbook("org_a", "P1", "ioc", "cat")
    engine.create_playbook("org_b", "P2", "ioc", "cat")
    assert len(engine.list_playbooks("org_a")) == 1
    assert len(engine.list_playbooks("org_b")) == 1


def test_org_isolation_get_playbook(engine):
    pb = engine.create_playbook("org_a", "P1", "ioc", "cat")
    assert engine.get_playbook(pb["id"], "org_b") is None


def test_org_isolation_executions(engine):
    pb = engine.create_playbook("org_a", "P1", "ioc", "cat")
    with pytest.raises(ValueError, match="not found"):
        engine.start_execution(pb["id"], "org_b")


# ---------------------------------------------------------------------------
# get_hunt_stats
# ---------------------------------------------------------------------------


def test_hunt_stats_empty(engine, org):
    s = engine.get_hunt_stats(org)
    assert s["total_playbooks"] == 0
    assert s["total_executions"] == 0
    assert s["overall_success_rate"] == 0.0
    assert s["active_hunts"] == 0


def test_hunt_stats_total_playbooks(engine, org):
    engine.create_playbook(org, "P1", "ioc", "cat1")
    engine.create_playbook(org, "P2", "hypothesis", "cat2")
    s = engine.get_hunt_stats(org)
    assert s["total_playbooks"] == 2


def test_hunt_stats_total_executions(engine, org, playbook):
    ex1 = engine.start_execution(playbook["id"], org)
    engine.start_execution(playbook["id"], org)
    engine.complete_execution(ex1["id"], org, outcome="finding")
    s = engine.get_hunt_stats(org)
    assert s["total_executions"] == 2


def test_hunt_stats_active_hunts(engine, org, playbook):
    engine.start_execution(playbook["id"], org)
    s = engine.get_hunt_stats(org)
    assert s["active_hunts"] == 1


def test_hunt_stats_active_hunts_decreases_after_complete(engine, org, playbook):
    ex = engine.start_execution(playbook["id"], org)
    engine.complete_execution(ex["id"], org, outcome="no_finding")
    s = engine.get_hunt_stats(org)
    assert s["active_hunts"] == 0


def test_hunt_stats_by_hunt_type(engine, org):
    engine.create_playbook(org, "P1", "ioc", "cat")
    engine.create_playbook(org, "P2", "ioc", "cat")
    engine.create_playbook(org, "P3", "behavioral", "cat")
    s = engine.get_hunt_stats(org)
    assert s["by_hunt_type"]["ioc"] == 2
    assert s["by_hunt_type"]["behavioral"] == 1


def test_hunt_stats_by_threat_category(engine, org):
    engine.create_playbook(org, "P1", "ioc", "ransomware")
    engine.create_playbook(org, "P2", "ioc", "phishing")
    engine.create_playbook(org, "P3", "ioc", "ransomware")
    s = engine.get_hunt_stats(org)
    assert s["by_threat_category"]["ransomware"] == 2
    assert s["by_threat_category"]["phishing"] == 1


def test_hunt_stats_overall_success_rate(engine, org):
    pb1 = engine.create_playbook(org, "P1", "ioc", "cat")
    pb2 = engine.create_playbook(org, "P2", "ioc", "cat")
    ex1 = engine.start_execution(pb1["id"], org)
    ex2 = engine.start_execution(pb2["id"], org)
    engine.complete_execution(ex1["id"], org, outcome="finding")
    engine.complete_execution(ex2["id"], org, outcome="no_finding")
    s = engine.get_hunt_stats(org)
    # pb1 success_rate=100, pb2 success_rate=0 → AVG=50
    assert s["overall_success_rate"] == pytest.approx(50.0, abs=0.01)
