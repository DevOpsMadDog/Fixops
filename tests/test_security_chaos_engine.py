"""Tests for SecurityChaosEngine — Beast Mode wave 19."""

from __future__ import annotations

import pytest
from core.security_chaos_engine import SecurityChaosEngine


@pytest.fixture()
def engine(tmp_path):
    return SecurityChaosEngine(db_path=str(tmp_path / "chaos.db"))


def _exp(engine, org_id="org1", **kwargs):
    data = {
        "experiment_name": "Test Firewall Bypass",
        "experiment_type": "firewall_bypass",
        "target_system": "perimeter-fw-01",
    }
    data.update(kwargs)
    return engine.create_experiment(org_id, data)


# ---------------------------------------------------------------------------
# create_experiment
# ---------------------------------------------------------------------------

def test_create_experiment_basic(engine):
    exp = _exp(engine)
    assert exp["id"]
    assert exp["status"] == "planned"
    assert exp["resilience_score"] == 0
    assert exp["experiment_type"] == "firewall_bypass"


def test_create_experiment_all_types(engine):
    types = [
        "firewall_bypass", "auth_disruption", "mfa_failure", "cert_expiry",
        "key_rotation", "siem_outage", "dlp_bypass", "iam_misconfiguration",
    ]
    for t in types:
        exp = engine.create_experiment("org1", {
            "experiment_name": f"Test {t}",
            "experiment_type": t,
            "target_system": "sys",
        })
        assert exp["experiment_type"] == t


def test_create_experiment_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid experiment_type"):
        engine.create_experiment("org1", {
            "experiment_name": "Bad",
            "experiment_type": "invalid_type",
            "target_system": "sys",
        })


def test_create_experiment_missing_name(engine):
    with pytest.raises(ValueError, match="experiment_name is required"):
        engine.create_experiment("org1", {
            "experiment_name": "",
            "experiment_type": "firewall_bypass",
            "target_system": "sys",
        })


def test_create_experiment_missing_target(engine):
    with pytest.raises(ValueError, match="target_system is required"):
        engine.create_experiment("org1", {
            "experiment_name": "Test",
            "experiment_type": "firewall_bypass",
            "target_system": "",
        })


def test_create_experiment_with_hypothesis(engine):
    exp = _exp(engine, hypothesis="Control should hold", expected_outcome="No bypass")
    assert exp["hypothesis"] == "Control should hold"
    assert exp["expected_outcome"] == "No bypass"


# ---------------------------------------------------------------------------
# list_experiments / get_experiment
# ---------------------------------------------------------------------------

def test_list_experiments_empty(engine):
    assert engine.list_experiments("org1") == []


def test_list_experiments_filtered_by_type(engine):
    _exp(engine, experiment_type="firewall_bypass")
    _exp(engine, experiment_type="mfa_failure", experiment_name="MFA Test")
    results = engine.list_experiments("org1", experiment_type="firewall_bypass")
    assert len(results) == 1
    assert results[0]["experiment_type"] == "firewall_bypass"


def test_list_experiments_filtered_by_status(engine):
    exp = _exp(engine)
    engine.start_experiment("org1", exp["id"])
    planned = engine.list_experiments("org1", status="planned")
    running = engine.list_experiments("org1", status="running")
    assert len(planned) == 0
    assert len(running) == 1


def test_get_experiment_found(engine):
    exp = _exp(engine)
    fetched = engine.get_experiment("org1", exp["id"])
    assert fetched["id"] == exp["id"]


def test_get_experiment_not_found(engine):
    assert engine.get_experiment("org1", "nonexistent") is None


def test_get_experiment_wrong_org(engine):
    exp = _exp(engine, org_id="org1")
    assert engine.get_experiment("org2", exp["id"]) is None


# ---------------------------------------------------------------------------
# start_experiment
# ---------------------------------------------------------------------------

def test_start_experiment(engine):
    exp = _exp(engine)
    started = engine.start_experiment("org1", exp["id"])
    assert started["status"] == "running"
    assert started["started_at"] is not None


def test_start_experiment_not_found(engine):
    with pytest.raises(KeyError):
        engine.start_experiment("org1", "no-such-id")


def test_start_experiment_already_running(engine):
    exp = _exp(engine)
    engine.start_experiment("org1", exp["id"])
    with pytest.raises(ValueError, match="Cannot start"):
        engine.start_experiment("org1", exp["id"])


def test_start_experiment_from_cancelled(engine):
    exp = _exp(engine)
    # Force to cancelled via complete then update won't work — just test planned->running
    # start from planned is covered above; also test cancelled is allowed
    # We'll directly update status to cancelled for this test
    import sqlite3
    conn = sqlite3.connect(engine._db_path)
    conn.execute("UPDATE chaos_experiments SET status='cancelled' WHERE id=?", (exp["id"],))
    conn.commit()
    conn.close()
    started = engine.start_experiment("org1", exp["id"])
    assert started["status"] == "running"


# ---------------------------------------------------------------------------
# complete_experiment
# ---------------------------------------------------------------------------

def test_complete_experiment(engine):
    exp = _exp(engine)
    engine.start_experiment("org1", exp["id"])
    completed = engine.complete_experiment("org1", exp["id"], {
        "actual_outcome": "Control held",
        "resilience_score": 85,
    })
    assert completed["status"] == "completed"
    assert completed["resilience_score"] == 85
    assert completed["actual_outcome"] == "Control held"
    assert completed["completed_at"] is not None


def test_complete_experiment_not_found(engine):
    with pytest.raises(KeyError):
        engine.complete_experiment("org1", "no-such-id", {})


def test_complete_experiment_default_score(engine):
    exp = _exp(engine)
    completed = engine.complete_experiment("org1", exp["id"], {})
    assert completed["resilience_score"] == 0


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------

def test_add_observation(engine):
    exp = _exp(engine)
    obs = engine.add_observation("org1", exp["id"], {
        "observation_type": "control_held",
        "severity": "low",
        "description": "Firewall blocked the attempt",
    })
    assert obs["id"]
    assert obs["observation_type"] == "control_held"
    assert obs["severity"] == "low"


def test_add_observation_invalid_type(engine):
    exp = _exp(engine)
    with pytest.raises(ValueError, match="Invalid observation_type"):
        engine.add_observation("org1", exp["id"], {
            "observation_type": "bad_type",
            "severity": "low",
        })


def test_add_observation_invalid_severity(engine):
    exp = _exp(engine)
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.add_observation("org1", exp["id"], {
            "observation_type": "control_held",
            "severity": "extreme",
        })


def test_add_observation_experiment_not_found(engine):
    with pytest.raises(KeyError):
        engine.add_observation("org1", "no-such-id", {
            "observation_type": "control_held",
            "severity": "low",
        })


def test_list_observations_ordered(engine):
    exp = _exp(engine)
    engine.add_observation("org1", exp["id"], {
        "observation_type": "alert_triggered",
        "severity": "high",
        "observed_at": "2026-04-16T10:00:00+00:00",
    })
    engine.add_observation("org1", exp["id"], {
        "observation_type": "control_held",
        "severity": "low",
        "observed_at": "2026-04-16T09:00:00+00:00",
    })
    obs = engine.list_observations("org1", exp["id"])
    assert len(obs) == 2
    # Should be ordered ASC by observed_at
    assert obs[0]["observed_at"] < obs[1]["observed_at"]


# ---------------------------------------------------------------------------
# Remediations
# ---------------------------------------------------------------------------

def test_add_remediation(engine):
    exp = _exp(engine)
    rem = engine.add_remediation("org1", exp["id"], {
        "finding": "Firewall rule gap detected",
        "remediation_action": "Add deny rule for VLAN 200",
        "priority": "critical",
    })
    assert rem["id"]
    assert rem["status"] == "open"
    assert rem["priority"] == "critical"


def test_add_remediation_missing_finding(engine):
    exp = _exp(engine)
    with pytest.raises(ValueError, match="finding is required"):
        engine.add_remediation("org1", exp["id"], {
            "finding": "",
            "remediation_action": "Do something",
        })


def test_add_remediation_missing_action(engine):
    exp = _exp(engine)
    with pytest.raises(ValueError, match="remediation_action is required"):
        engine.add_remediation("org1", exp["id"], {
            "finding": "Gap found",
            "remediation_action": "",
        })


def test_add_remediation_invalid_priority(engine):
    exp = _exp(engine)
    with pytest.raises(ValueError, match="Invalid priority"):
        engine.add_remediation("org1", exp["id"], {
            "finding": "Gap",
            "remediation_action": "Fix it",
            "priority": "ultra",
        })


def test_update_remediation_status_lifecycle(engine):
    exp = _exp(engine)
    rem = engine.add_remediation("org1", exp["id"], {
        "finding": "Gap",
        "remediation_action": "Fix it",
    })
    updated = engine.update_remediation_status("org1", rem["id"], "in_progress")
    assert updated["status"] == "in_progress"
    completed = engine.update_remediation_status("org1", rem["id"], "completed")
    assert completed["status"] == "completed"


def test_update_remediation_status_invalid(engine):
    exp = _exp(engine)
    rem = engine.add_remediation("org1", exp["id"], {
        "finding": "Gap",
        "remediation_action": "Fix it",
    })
    with pytest.raises(ValueError, match="Invalid status"):
        engine.update_remediation_status("org1", rem["id"], "done")


def test_update_remediation_status_not_found(engine):
    with pytest.raises(KeyError):
        engine.update_remediation_status("org1", "no-id", "completed")


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_chaos_stats_empty(engine):
    stats = engine.get_chaos_stats("org1")
    assert stats["total_experiments"] == 0
    assert stats["avg_resilience_score"] == 0.0
    assert stats["critical_findings"] == 0
    assert stats["total_observations"] == 0


def test_get_chaos_stats_avg_resilience(engine):
    exp1 = _exp(engine, experiment_name="E1")
    exp2 = _exp(engine, experiment_name="E2", experiment_type="mfa_failure")
    engine.complete_experiment("org1", exp1["id"], {"resilience_score": 80})
    engine.complete_experiment("org1", exp2["id"], {"resilience_score": 60})
    stats = engine.get_chaos_stats("org1")
    assert stats["avg_resilience_score"] == pytest.approx(70.0)
    assert stats["by_status"]["completed"] == 2


def test_get_chaos_stats_critical_findings(engine):
    exp = _exp(engine)
    engine.add_remediation("org1", exp["id"], {
        "finding": "Critical gap",
        "remediation_action": "Patch immediately",
        "priority": "critical",
    })
    engine.add_remediation("org1", exp["id"], {
        "finding": "Minor gap",
        "remediation_action": "Review",
        "priority": "low",
    })
    stats = engine.get_chaos_stats("org1")
    assert stats["critical_findings"] == 1


def test_get_chaos_stats_critical_findings_completed_excluded(engine):
    exp = _exp(engine)
    rem = engine.add_remediation("org1", exp["id"], {
        "finding": "Critical gap",
        "remediation_action": "Fix",
        "priority": "critical",
    })
    engine.update_remediation_status("org1", rem["id"], "completed")
    stats = engine.get_chaos_stats("org1")
    assert stats["critical_findings"] == 0


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation(engine):
    _exp(engine, org_id="org1")
    _exp(engine, org_id="org2", experiment_name="Org2 Exp")
    assert len(engine.list_experiments("org1")) == 1
    assert len(engine.list_experiments("org2")) == 1
    assert engine.get_chaos_stats("org1")["total_experiments"] == 1
    assert engine.get_chaos_stats("org2")["total_experiments"] == 1
