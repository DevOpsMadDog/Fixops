"""Tests for AttackSimulationDbEngine — SQLite-backed multi-tenant BAS engine.

Covers: simulation CRUD, attack paths, findings, MITRE coverage, stats.
"""
import pytest

from core.attack_simulation_engine import AttackSimulationDbEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "attack_sim_test.db")
    return AttackSimulationDbEngine(db_path=db)


# ---------------------------------------------------------------------------
# Simulation creation
# ---------------------------------------------------------------------------

def test_create_simulation_basic(engine):
    sim = engine.create_simulation("org1", {"name": "Quarterly BAS"})
    assert sim["sim_id"]
    assert sim["name"] == "Quarterly BAS"
    assert sim["org_id"] == "org1"
    assert sim["simulation_type"] == "BAS"
    assert sim["status"] == "planned"


def test_create_simulation_all_types(engine):
    for sim_type in ("BAS", "purple_team", "tabletop", "red_team"):
        sim = engine.create_simulation("org1", {"name": f"Sim {sim_type}", "simulation_type": sim_type})
        assert sim["simulation_type"] == sim_type


def test_create_simulation_invalid_type_defaults_to_bas(engine):
    sim = engine.create_simulation("org1", {"name": "Bad Type", "simulation_type": "unknown"})
    assert sim["simulation_type"] == "BAS"


def test_create_simulation_with_target_profile(engine):
    sim = engine.create_simulation("org1", {
        "name": "Targeted",
        "target_profile": {"environment": "cloud", "os": "linux"},
    })
    assert isinstance(sim["target_profile"], dict)
    assert sim["target_profile"]["environment"] == "cloud"


def test_create_simulation_with_scope(engine):
    sim = engine.create_simulation("org1", {
        "name": "Scoped Sim",
        "scope": "10.0.0.0/8",
    })
    assert sim["scope"] == "10.0.0.0/8"


def test_create_simulation_has_uuid(engine):
    sim = engine.create_simulation("org1", {"name": "UUID Test"})
    parts = sim["sim_id"].split("-")
    assert len(parts) == 5


def test_create_simulation_status_variants(engine):
    for status in ("planned", "running", "completed"):
        sim = engine.create_simulation("org1", {"name": f"Status {status}", "status": status})
        assert sim["status"] == status


def test_create_simulation_invalid_status_defaults(engine):
    sim = engine.create_simulation("org1", {"name": "Bad Status", "status": "paused"})
    assert sim["status"] == "planned"


# ---------------------------------------------------------------------------
# Simulation listing
# ---------------------------------------------------------------------------

def test_list_simulations_empty(engine):
    assert engine.list_simulations("org_new") == []


def test_list_simulations_returns_org_sims(engine):
    engine.create_simulation("org1", {"name": "S1"})
    engine.create_simulation("org1", {"name": "S2"})
    engine.create_simulation("org2", {"name": "S3"})
    results = engine.list_simulations("org1")
    assert len(results) == 2
    assert all(s["org_id"] == "org1" for s in results)


def test_list_simulations_status_filter(engine):
    engine.create_simulation("org1", {"name": "Planned", "status": "planned"})
    engine.create_simulation("org1", {"name": "Running", "status": "running"})
    engine.create_simulation("org1", {"name": "Done", "status": "completed"})
    planned = engine.list_simulations("org1", status="planned")
    assert len(planned) == 1
    assert planned[0]["status"] == "planned"


def test_list_simulations_tenant_isolation(engine):
    engine.create_simulation("orgA", {"name": "A"})
    engine.create_simulation("orgB", {"name": "B"})
    assert all(s["org_id"] == "orgA" for s in engine.list_simulations("orgA"))


# ---------------------------------------------------------------------------
# Attack paths
# ---------------------------------------------------------------------------

def test_add_attack_path_basic(engine):
    sim = engine.create_simulation("org1", {"name": "Path Test"})
    path = engine.add_attack_path("org1", sim["sim_id"], {
        "tactic": "initial_access",
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "success": True,
        "detection_time_seconds": 300.0,
    })
    assert path["path_id"]
    assert path["tactic"] == "initial_access"
    assert path["technique_id"] == "T1566"
    assert path["technique_name"] == "Phishing"
    assert path["success"] is True
    assert path["detection_time_seconds"] == pytest.approx(300.0)


def test_add_attack_path_failed(engine):
    sim = engine.create_simulation("org1", {"name": "Failed Path"})
    path = engine.add_attack_path("org1", sim["sim_id"], {
        "tactic": "lateral_movement",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "success": False,
    })
    assert path["success"] is False


def test_list_attack_paths(engine):
    sim = engine.create_simulation("org1", {"name": "Multi Path"})
    engine.add_attack_path("org1", sim["sim_id"], {"technique_id": "T1595", "tactic": "reconnaissance"})
    engine.add_attack_path("org1", sim["sim_id"], {"technique_id": "T1566", "tactic": "initial_access"})
    paths = engine.list_attack_paths("org1", sim["sim_id"])
    assert len(paths) == 2


def test_list_attack_paths_empty(engine):
    sim = engine.create_simulation("org1", {"name": "Empty Paths"})
    assert engine.list_attack_paths("org1", sim["sim_id"]) == []


def test_list_attack_paths_tenant_isolation(engine):
    sim1 = engine.create_simulation("org1", {"name": "Org1 Sim"})
    sim2 = engine.create_simulation("org2", {"name": "Org2 Sim"})
    engine.add_attack_path("org1", sim1["sim_id"], {"technique_id": "T1566"})
    engine.add_attack_path("org2", sim2["sim_id"], {"technique_id": "T1190"})
    paths_org1 = engine.list_attack_paths("org1", sim1["sim_id"])
    assert len(paths_org1) == 1
    assert paths_org1[0]["technique_id"] == "T1566"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def test_create_finding_basic(engine):
    sim = engine.create_simulation("org1", {"name": "Finding Sim"})
    finding = engine.create_finding("org1", sim["sim_id"], {
        "technique_id": "T1566",
        "title": "Phishing susceptibility detected",
        "severity": "high",
    })
    assert finding["finding_id"]
    assert finding["technique_id"] == "T1566"
    assert finding["title"] == "Phishing susceptibility detected"
    assert finding["severity"] == "high"
    assert finding["remediation_priority"] == 2  # high = priority 2


def test_create_finding_invalid_severity_defaults(engine):
    sim = engine.create_simulation("org1", {"name": "Bad Severity"})
    finding = engine.create_finding("org1", sim["sim_id"], {
        "title": "Test",
        "severity": "apocalyptic",
    })
    assert finding["severity"] == "medium"


def test_create_finding_critical_priority_1(engine):
    sim = engine.create_simulation("org1", {"name": "Critical Finding"})
    finding = engine.create_finding("org1", sim["sim_id"], {
        "title": "RCE",
        "severity": "critical",
    })
    assert finding["remediation_priority"] == 1


def test_list_findings_by_sim(engine):
    sim1 = engine.create_simulation("org1", {"name": "Sim1"})
    sim2 = engine.create_simulation("org1", {"name": "Sim2"})
    engine.create_finding("org1", sim1["sim_id"], {"title": "F1"})
    engine.create_finding("org1", sim2["sim_id"], {"title": "F2"})
    findings = engine.list_findings("org1", sim_id=sim1["sim_id"])
    assert len(findings) == 1
    assert findings[0]["title"] == "F1"


def test_list_findings_all_org(engine):
    sim = engine.create_simulation("org1", {"name": "All Findings"})
    engine.create_finding("org1", sim["sim_id"], {"title": "A"})
    engine.create_finding("org1", sim["sim_id"], {"title": "B"})
    findings = engine.list_findings("org1")
    assert len(findings) >= 2


def test_list_findings_ordered_by_priority(engine):
    sim = engine.create_simulation("org1", {"name": "Priority Order"})
    engine.create_finding("org1", sim["sim_id"], {"title": "Low", "severity": "low"})
    engine.create_finding("org1", sim["sim_id"], {"title": "Critical", "severity": "critical"})
    engine.create_finding("org1", sim["sim_id"], {"title": "High", "severity": "high"})
    findings = engine.list_findings("org1", sim_id=sim["sim_id"])
    priorities = [f["remediation_priority"] for f in findings]
    assert priorities == sorted(priorities)


# ---------------------------------------------------------------------------
# MITRE coverage
# ---------------------------------------------------------------------------

def test_get_mitre_coverage_empty(engine):
    coverage = engine.get_mitre_coverage("org_new")
    # Should have all standard tactics with 0 coverage
    assert "reconnaissance" in coverage
    assert coverage["reconnaissance"]["coverage_pct"] == 0.0


def test_get_mitre_coverage_all_tactics_present(engine):
    coverage = engine.get_mitre_coverage("org1")
    expected_tactics = [
        "reconnaissance", "initial_access", "execution", "persistence",
        "privilege_escalation", "lateral_movement", "command_and_control", "exfiltration",
    ]
    for tactic in expected_tactics:
        assert tactic in coverage


def test_get_mitre_coverage_tracks_success(engine):
    sim = engine.create_simulation("org1", {"name": "Coverage Test"})
    engine.add_attack_path("org1", sim["sim_id"], {
        "tactic": "initial_access",
        "technique_id": "T1566",
        "success": True,
    })
    engine.add_attack_path("org1", sim["sim_id"], {
        "tactic": "initial_access",
        "technique_id": "T1190",
        "success": False,
    })
    coverage = engine.get_mitre_coverage("org1")
    ia = coverage["initial_access"]
    assert ia["total_techniques"] == 2
    assert ia["succeeded"] == 1
    assert ia["coverage_pct"] == pytest.approx(50.0)


def test_get_mitre_coverage_tenant_isolation(engine):
    sim1 = engine.create_simulation("org1", {"name": "O1"})
    sim2 = engine.create_simulation("org2", {"name": "O2"})
    engine.add_attack_path("org1", sim1["sim_id"], {
        "tactic": "execution", "technique_id": "T1059", "success": True,
    })
    engine.add_attack_path("org2", sim2["sim_id"], {
        "tactic": "persistence", "technique_id": "T1098", "success": True,
    })
    cov1 = engine.get_mitre_coverage("org1")
    cov2 = engine.get_mitre_coverage("org2")
    # org1 should have execution coverage, not persistence
    assert cov1["execution"]["total_techniques"] >= 1
    assert cov1["persistence"]["total_techniques"] == 0
    # org2 should have persistence, not execution
    assert cov2["persistence"]["total_techniques"] >= 1
    assert cov2["execution"]["total_techniques"] == 0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_simulation_stats_empty(engine):
    stats = engine.get_simulation_stats("org_empty")
    assert stats["total_simulations"] == 0
    assert stats["total_attack_paths"] == 0
    assert stats["total_findings"] == 0
    assert stats["success_rate_pct"] == 0.0


def test_get_simulation_stats_with_data(engine):
    sim = engine.create_simulation("org1", {"name": "Stats Sim", "status": "completed"})
    engine.add_attack_path("org1", sim["sim_id"], {
        "technique_id": "T1566", "tactic": "initial_access", "success": True,
        "detection_time_seconds": 120.0,
    })
    engine.add_attack_path("org1", sim["sim_id"], {
        "technique_id": "T1190", "tactic": "initial_access", "success": False,
        "detection_time_seconds": 60.0,
    })
    engine.create_finding("org1", sim["sim_id"], {"title": "RCE", "severity": "critical"})

    stats = engine.get_simulation_stats("org1")
    assert stats["total_simulations"] >= 1
    assert stats["completed"] >= 1
    assert stats["total_attack_paths"] >= 2
    assert stats["successful_attack_paths"] >= 1
    assert stats["success_rate_pct"] == pytest.approx(50.0)
    assert stats["total_findings"] >= 1
    assert stats["critical_findings"] >= 1


def test_get_simulation_stats_avg_detection_time(engine):
    sim = engine.create_simulation("org1", {"name": "Detection Time"})
    engine.add_attack_path("org1", sim["sim_id"], {
        "technique_id": "T1566", "success": True, "detection_time_seconds": 100.0,
    })
    engine.add_attack_path("org1", sim["sim_id"], {
        "technique_id": "T1190", "success": True, "detection_time_seconds": 200.0,
    })
    stats = engine.get_simulation_stats("org1")
    assert stats["avg_detection_time_seconds"] == pytest.approx(150.0)


def test_get_simulation_stats_tenant_isolation(engine):
    engine.create_simulation("org1", {"name": "Org1"})
    engine.create_simulation("org1", {"name": "Org1 2"})
    engine.create_simulation("org2", {"name": "Org2"})
    s1 = engine.get_simulation_stats("org1")
    s2 = engine.get_simulation_stats("org2")
    assert s1["total_simulations"] == 2
    assert s2["total_simulations"] == 1
