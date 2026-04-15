"""Tests for BehavioralAnalyticsEngine — 33 tests."""

from __future__ import annotations

import pytest

from core.behavioral_analytics_engine import BehavioralAnalyticsEngine


@pytest.fixture()
def engine(tmp_path):
    return BehavioralAnalyticsEngine(db_path=str(tmp_path / "ba.db"))


# ---------------------------------------------------------------------------
# establish_baseline
# ---------------------------------------------------------------------------


def test_establish_baseline_basic(engine):
    bl = engine.establish_baseline("org1", {
        "user_id": "alice",
        "baseline_type": "login_hours",
        "normal_value": 9.0,
        "std_deviation": 1.5,
        "samples_count": 30,
    })
    assert bl["id"]
    assert bl["user_id"] == "alice"
    assert bl["baseline_type"] == "login_hours"
    assert bl["normal_value"] == 9.0
    assert bl["samples_count"] == 30


def test_establish_baseline_missing_user_id_raises(engine):
    with pytest.raises(ValueError, match="user_id"):
        engine.establish_baseline("org1", {"baseline_type": "login_hours"})


def test_establish_baseline_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="baseline_type"):
        engine.establish_baseline("org1", {"user_id": "alice", "baseline_type": "mood"})


def test_establish_baseline_all_types(engine):
    types = ["login_hours", "access_volume", "data_transfer", "command_frequency", "location"]
    for bt in types:
        bl = engine.establish_baseline("org1", {"user_id": f"u_{bt}", "baseline_type": bt})
        assert bl["baseline_type"] == bt


def test_establish_baseline_upsert(engine):
    engine.establish_baseline("org1", {"user_id": "alice", "baseline_type": "login_hours", "normal_value": 9.0})
    updated = engine.establish_baseline("org1", {"user_id": "alice", "baseline_type": "login_hours", "normal_value": 10.0})
    assert updated["normal_value"] == 10.0
    # Same ID — only one record
    baselines = engine.list_baselines("org1", user_id="alice")
    assert len(baselines) == 1


def test_establish_baseline_org_isolation(engine):
    engine.establish_baseline("org1", {"user_id": "alice", "baseline_type": "login_hours"})
    engine.establish_baseline("org2", {"user_id": "alice", "baseline_type": "login_hours"})
    assert len(engine.list_baselines("org1")) == 1
    assert len(engine.list_baselines("org2")) == 1


# ---------------------------------------------------------------------------
# list_baselines
# ---------------------------------------------------------------------------


def test_list_baselines_empty(engine):
    assert engine.list_baselines("org1") == []


def test_list_baselines_all(engine):
    engine.establish_baseline("org1", {"user_id": "a", "baseline_type": "login_hours"})
    engine.establish_baseline("org1", {"user_id": "a", "baseline_type": "access_volume"})
    assert len(engine.list_baselines("org1")) == 2


def test_list_baselines_filter_user(engine):
    engine.establish_baseline("org1", {"user_id": "alice", "baseline_type": "login_hours"})
    engine.establish_baseline("org1", {"user_id": "bob", "baseline_type": "login_hours"})
    result = engine.list_baselines("org1", user_id="alice")
    assert len(result) == 1
    assert result[0]["user_id"] == "alice"


def test_list_baselines_filter_type(engine):
    engine.establish_baseline("org1", {"user_id": "a", "baseline_type": "login_hours"})
    engine.establish_baseline("org1", {"user_id": "a", "baseline_type": "access_volume"})
    result = engine.list_baselines("org1", baseline_type="access_volume")
    assert len(result) == 1


# ---------------------------------------------------------------------------
# detect_anomaly
# ---------------------------------------------------------------------------


def test_detect_anomaly_basic(engine):
    anomaly = engine.detect_anomaly("org1", {
        "user_id": "alice",
        "behavior_type": "login_anomaly",
        "severity": "high",
        "observed_value": 23.0,
        "baseline_value": 9.0,
        "deviation_score": 9.3,
        "description": "Login at 11pm",
    })
    assert anomaly["id"]
    assert anomaly["status"] == "new"
    assert anomaly["user_id"] == "alice"
    assert anomaly["severity"] == "high"
    assert anomaly["resolved_at"] is None


def test_detect_anomaly_missing_user_id_raises(engine):
    with pytest.raises(ValueError, match="user_id"):
        engine.detect_anomaly("org1", {"behavior_type": "login_anomaly", "severity": "low"})


def test_detect_anomaly_invalid_behavior_type_raises(engine):
    with pytest.raises(ValueError, match="behavior_type"):
        engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "teleport"})


def test_detect_anomaly_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "extreme"})


def test_detect_anomaly_all_behavior_types(engine):
    types = [
        "login_anomaly", "data_access_spike", "privilege_escalation",
        "lateral_movement", "exfiltration_attempt", "policy_violation",
        "off_hours_activity", "geo_anomaly",
    ]
    for bt in types:
        a = engine.detect_anomaly("org1", {"user_id": "u1", "behavior_type": bt, "severity": "low"})
        assert a["behavior_type"] == bt


def test_detect_anomaly_all_severities(engine):
    for sev in ["critical", "high", "medium", "low"]:
        a = engine.detect_anomaly("org1", {"user_id": "u1", "behavior_type": "login_anomaly", "severity": sev})
        assert a["severity"] == sev


# ---------------------------------------------------------------------------
# list_anomalies
# ---------------------------------------------------------------------------


def test_list_anomalies_empty(engine):
    assert engine.list_anomalies("org1") == []


def test_list_anomalies_all(engine):
    engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "low"})
    engine.detect_anomaly("org1", {"user_id": "b", "behavior_type": "geo_anomaly", "severity": "high"})
    assert len(engine.list_anomalies("org1")) == 2


def test_list_anomalies_filter_user(engine):
    engine.detect_anomaly("org1", {"user_id": "alice", "behavior_type": "login_anomaly", "severity": "low"})
    engine.detect_anomaly("org1", {"user_id": "bob", "behavior_type": "login_anomaly", "severity": "low"})
    result = engine.list_anomalies("org1", user_id="alice")
    assert len(result) == 1


def test_list_anomalies_filter_severity(engine):
    engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "critical"})
    engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "low"})
    result = engine.list_anomalies("org1", severity="critical")
    assert len(result) == 1


def test_list_anomalies_filter_status(engine):
    a = engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "low"})
    engine.update_anomaly_status("org1", a["id"], "resolved")
    new_result = engine.list_anomalies("org1", status="new")
    assert len(new_result) == 0
    resolved_result = engine.list_anomalies("org1", status="resolved")
    assert len(resolved_result) == 1


def test_list_anomalies_org_isolation(engine):
    engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "low"})
    engine.detect_anomaly("org2", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "low"})
    assert len(engine.list_anomalies("org1")) == 1
    assert len(engine.list_anomalies("org2")) == 1


# ---------------------------------------------------------------------------
# update_anomaly_status
# ---------------------------------------------------------------------------


def test_update_anomaly_status_valid(engine):
    a = engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "medium"})
    updated = engine.update_anomaly_status("org1", a["id"], "investigating", notes="Looking into it")
    assert updated["status"] == "investigating"
    assert updated["notes"] == "Looking into it"
    assert updated["resolved_at"] is None


def test_update_anomaly_status_resolved_sets_timestamp(engine):
    a = engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "medium"})
    updated = engine.update_anomaly_status("org1", a["id"], "resolved")
    assert updated["status"] == "resolved"
    assert updated["resolved_at"] is not None


def test_update_anomaly_status_invalid_raises(engine):
    a = engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "medium"})
    with pytest.raises(ValueError, match="status"):
        engine.update_anomaly_status("org1", a["id"], "deleted")


def test_update_anomaly_status_not_found_returns_none(engine):
    result = engine.update_anomaly_status("org1", "nonexistent", "resolved")
    assert result is None


def test_update_anomaly_status_all_valid(engine):
    for status in ["new", "investigating", "confirmed", "false_positive", "resolved"]:
        a = engine.detect_anomaly("org1", {"user_id": "a", "behavior_type": "login_anomaly", "severity": "low"})
        updated = engine.update_anomaly_status("org1", a["id"], status)
        assert updated["status"] == status


# ---------------------------------------------------------------------------
# get_user_risk_profile
# ---------------------------------------------------------------------------


def test_user_risk_profile_no_anomalies(engine):
    profile = engine.get_user_risk_profile("org1", "alice")
    assert profile["user_id"] == "alice"
    assert profile["total_anomalies"] == 0
    assert profile["risk_score"] == 0
    assert profile["last_anomaly_at"] is None


def test_user_risk_profile_with_anomalies(engine):
    engine.detect_anomaly("org1", {"user_id": "alice", "behavior_type": "login_anomaly", "severity": "critical"})
    engine.detect_anomaly("org1", {"user_id": "alice", "behavior_type": "geo_anomaly", "severity": "high"})
    profile = engine.get_user_risk_profile("org1", "alice")
    assert profile["total_anomalies"] == 2
    assert profile["critical_count"] == 1
    assert profile["high_count"] == 1
    assert profile["risk_score"] == 20
    assert profile["last_anomaly_at"] is not None


def test_user_risk_profile_risk_score_capped(engine):
    for _ in range(15):
        engine.detect_anomaly("org1", {"user_id": "bob", "behavior_type": "login_anomaly", "severity": "high"})
    profile = engine.get_user_risk_profile("org1", "bob")
    assert profile["risk_score"] == 100


def test_user_risk_profile_open_anomalies(engine):
    a = engine.detect_anomaly("org1", {"user_id": "u", "behavior_type": "login_anomaly", "severity": "medium"})
    engine.detect_anomaly("org1", {"user_id": "u", "behavior_type": "geo_anomaly", "severity": "low"})
    engine.update_anomaly_status("org1", a["id"], "resolved")
    profile = engine.get_user_risk_profile("org1", "u")
    assert profile["open_anomalies"] == 1


# ---------------------------------------------------------------------------
# get_behavioral_stats
# ---------------------------------------------------------------------------


def test_behavioral_stats_empty(engine):
    stats = engine.get_behavioral_stats("org1")
    assert stats["total_users_monitored"] == 0
    assert stats["total_anomalies"] == 0
    assert stats["false_positive_rate"] == 0.0


def test_behavioral_stats_populated(engine):
    engine.establish_baseline("org1", {"user_id": "alice", "baseline_type": "login_hours"})
    engine.establish_baseline("org1", {"user_id": "bob", "baseline_type": "login_hours"})
    a1 = engine.detect_anomaly("org1", {"user_id": "alice", "behavior_type": "login_anomaly", "severity": "critical"})
    a2 = engine.detect_anomaly("org1", {"user_id": "bob", "behavior_type": "geo_anomaly", "severity": "medium"})
    engine.detect_anomaly("org1", {"user_id": "alice", "behavior_type": "login_anomaly", "severity": "low"})
    engine.update_anomaly_status("org1", a1["id"], "confirmed")
    engine.update_anomaly_status("org1", a2["id"], "false_positive")

    stats = engine.get_behavioral_stats("org1")
    assert stats["total_users_monitored"] == 2
    assert stats["total_anomalies"] == 3
    assert stats["confirmed_threats"] == 1
    assert stats["critical_anomalies"] == 1
    # 1 false positive out of 3 total
    assert abs(stats["false_positive_rate"] - 33.333) < 0.1
    assert stats["by_behavior_type"]["login_anomaly"] == 2
    assert stats["by_behavior_type"]["geo_anomaly"] == 1
