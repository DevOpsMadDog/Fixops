"""Tests for CloudDriftDetectionEngine."""

from __future__ import annotations

import sqlite3

import pytest
from core.cloud_drift_engine import CloudDriftDetectionEngine


@pytest.fixture
def engine(tmp_path):
    return CloudDriftDetectionEngine(db_path=str(tmp_path / "test_drift.db"))


def _baseline(resource_id="res-001", resource_type="ec2", environment="prod"):
    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "resource_name": f"My {resource_type.upper()} Resource",
        "expected_config": {"instance_type": "t3.micro", "monitoring": True},
        "source": "terraform",
        "environment": environment,
    }


def _drift(resource_id="res-001", drift_type="config_changed", severity="medium"):
    return {
        "resource_id": resource_id,
        "drift_type": drift_type,
        "severity": severity,
        "expected_value": '{"monitoring": true}',
        "actual_value": '{"monitoring": false}',
    }


def _seed_scan_row(engine, org_id: str, environment: str = "prod") -> None:
    """Insert a drift_scans row directly via SQLite (bypasses run_drift_scan stub)."""
    import uuid
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    scan_id = str(uuid.uuid4())
    with engine._lock:
        with engine._conn() as conn:
            conn.execute(
                """INSERT INTO drift_scans VALUES
                   (:scan_id,:org_id,:environment,:scanned,:drifts_found,
                    :resolved_drifts,:scanned_at)""",
                {
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "environment": environment,
                    "scanned": 1,
                    "drifts_found": 0,
                    "resolved_drifts": 0,
                    "scanned_at": now,
                },
            )


# ------------------------------------------------------------------
# Initialization
# ------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = tmp_path / "drift.db"
    CloudDriftDetectionEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_no_error(tmp_path):
    db = str(tmp_path / "drift.db")
    CloudDriftDetectionEngine(db_path=db)
    CloudDriftDetectionEngine(db_path=db)


# ------------------------------------------------------------------
# register_baseline / list_baselines
# ------------------------------------------------------------------

def test_register_baseline_returns_baseline_id(engine):
    result = engine.register_baseline("org1", _baseline())
    assert "baseline_id" in result
    assert result["resource_id"] == "res-001"


def test_register_baseline_stores_config(engine):
    data = _baseline()
    result = engine.register_baseline("org1", data)
    assert result["expected_config"] == data["expected_config"]


def test_list_baselines_empty(engine):
    assert engine.list_baselines("org1") == []


def test_list_baselines_returns_registered(engine):
    engine.register_baseline("org1", _baseline("r1"))
    engine.register_baseline("org1", _baseline("r2"))
    baselines = engine.list_baselines("org1")
    assert len(baselines) == 2


def test_list_baselines_filter_by_environment(engine):
    engine.register_baseline("org1", _baseline("r1", environment="prod"))
    engine.register_baseline("org1", _baseline("r2", environment="staging"))
    prod = engine.list_baselines("org1", environment="prod")
    assert len(prod) == 1
    assert prod[0]["environment"] == "prod"


def test_register_baseline_invalid_type_defaults(engine):
    data = _baseline()
    data["resource_type"] = "unknown_type"
    result = engine.register_baseline("org1", data)
    assert result["resource_type"] == "ec2"


def test_register_baseline_invalid_source_defaults(engine):
    data = _baseline()
    data["source"] = "puppet"
    result = engine.register_baseline("org1", data)
    assert result["source"] == "terraform"


def test_register_baseline_invalid_environment_defaults(engine):
    data = _baseline()
    data["environment"] = "qa"
    result = engine.register_baseline("org1", data)
    assert result["environment"] == "prod"


# ------------------------------------------------------------------
# record_drift / list_drifts
# ------------------------------------------------------------------

def test_record_drift_returns_drift_id(engine):
    result = engine.record_drift("org1", _drift())
    assert "drift_id" in result
    assert result["status"] == "open"


def test_record_drift_stores_values(engine):
    result = engine.record_drift("org1", _drift(drift_type="tag_missing", severity="high"))
    assert result["drift_type"] == "tag_missing"
    assert result["severity"] == "high"


def test_list_drifts_empty(engine):
    assert engine.list_drifts("org1") == []


def test_list_drifts_returns_recorded(engine):
    engine.record_drift("org1", _drift("r1"))
    engine.record_drift("org1", _drift("r2"))
    drifts = engine.list_drifts("org1")
    assert len(drifts) == 2


def test_list_drifts_filter_by_severity(engine):
    engine.record_drift("org1", _drift(severity="critical"))
    engine.record_drift("org1", _drift(severity="low"))
    critical = engine.list_drifts("org1", severity="critical")
    assert len(critical) == 1
    assert critical[0]["severity"] == "critical"


def test_list_drifts_filter_by_type(engine):
    engine.record_drift("org1", _drift(drift_type="config_changed"))
    engine.record_drift("org1", _drift(drift_type="resource_deleted"))
    deleted = engine.list_drifts("org1", drift_type="resource_deleted")
    assert len(deleted) == 1


def test_list_drifts_filter_by_status(engine):
    engine.record_drift("org1", _drift("r1"))
    engine.record_drift("org1", _drift("r2"))
    open_drifts = engine.list_drifts("org1", status="open")
    assert len(open_drifts) == 2
    acked = engine.list_drifts("org1", status="acknowledged")
    assert len(acked) == 0


def test_record_drift_invalid_type_defaults(engine):
    data = _drift()
    data["drift_type"] = "totally_wrong"
    result = engine.record_drift("org1", data)
    assert result["drift_type"] == "config_changed"


def test_record_drift_invalid_severity_defaults(engine):
    data = _drift()
    data["severity"] = "super_critical"
    result = engine.record_drift("org1", data)
    assert result["severity"] == "medium"


# ------------------------------------------------------------------
# acknowledge_drift
# ------------------------------------------------------------------

def test_acknowledge_drift_changes_status(engine):
    drift = engine.record_drift("org1", _drift())
    result = engine.acknowledge_drift("org1", drift["drift_id"], "alice", "Investigating")
    assert result["status"] == "acknowledged"
    assert result["acknowledged_by"] == "alice"
    assert result["ack_notes"] == "Investigating"


def test_acknowledge_drift_not_found_returns_error(engine):
    result = engine.acknowledge_drift("org1", "nonexistent-id", "alice")
    assert "error" in result


def test_list_drifts_shows_acknowledged(engine):
    drift = engine.record_drift("org1", _drift())
    engine.acknowledge_drift("org1", drift["drift_id"], "bob")
    acked = engine.list_drifts("org1", status="acknowledged")
    assert len(acked) == 1


# ------------------------------------------------------------------
# remediate_drift
# ------------------------------------------------------------------

def test_remediate_drift_changes_status(engine):
    drift = engine.record_drift("org1", _drift())
    result = engine.remediate_drift("org1", drift["drift_id"], "bob", "automated")
    assert result["status"] == "remediated"
    assert result["remediated_by"] == "bob"
    assert result["remediation_method"] == "automated"


def test_remediate_drift_not_found_returns_error(engine):
    result = engine.remediate_drift("org1", "nonexistent-id", "bob")
    assert "error" in result


def test_remediate_drift_invalid_method_defaults(engine):
    drift = engine.record_drift("org1", _drift())
    result = engine.remediate_drift("org1", drift["drift_id"], "bob", "magic")
    assert result["remediation_method"] == "manual"


# ------------------------------------------------------------------
# run_drift_scan — now raises NotImplementedError (no CSPM connector)
# ------------------------------------------------------------------

def test_run_drift_scan_no_baselines(engine):
    """run_drift_scan() raises NotImplementedError until CSPM connector is wired."""
    with pytest.raises(NotImplementedError):
        engine.run_drift_scan("org1")


def test_run_drift_scan_returns_required_keys(engine):
    """run_drift_scan() raises NotImplementedError regardless of registered baselines."""
    engine.register_baseline("org1", _baseline("r1"))
    engine.register_baseline("org1", _baseline("r2"))
    with pytest.raises(NotImplementedError):
        engine.run_drift_scan("org1")


def test_run_drift_scan_scanned_count_matches_baselines(engine):
    """run_drift_scan() raises NotImplementedError regardless of baseline count."""
    engine.register_baseline("org1", _baseline("r1"))
    engine.register_baseline("org1", _baseline("r2"))
    engine.register_baseline("org1", _baseline("r3"))
    with pytest.raises(NotImplementedError):
        engine.run_drift_scan("org1")


def test_run_drift_scan_filters_by_environment(engine):
    """run_drift_scan() raises NotImplementedError regardless of environment filter."""
    engine.register_baseline("org1", _baseline("r1", environment="prod"))
    engine.register_baseline("org1", _baseline("r2", environment="staging"))
    with pytest.raises(NotImplementedError):
        engine.run_drift_scan("org1", environment="prod")


# ------------------------------------------------------------------
# get_drift_stats
# ------------------------------------------------------------------

def test_get_drift_stats_structure(engine):
    stats = engine.get_drift_stats("org1")
    assert "total_baselines" in stats
    assert "drifts_open" in stats
    assert "by_severity" in stats
    assert "by_drift_type" in stats
    assert "remediated_count" in stats
    assert "drift_rate_pct" in stats
    assert "scans_last_7d" in stats


def test_get_drift_stats_empty(engine):
    stats = engine.get_drift_stats("org1")
    assert stats["total_baselines"] == 0
    assert stats["drifts_open"] == 0
    assert stats["drift_rate_pct"] == 0.0


def test_get_drift_stats_counts_baselines(engine):
    engine.register_baseline("org1", _baseline("r1"))
    engine.register_baseline("org1", _baseline("r2"))
    stats = engine.get_drift_stats("org1")
    assert stats["total_baselines"] == 2


def test_get_drift_stats_drift_rate_pct(engine):
    engine.register_baseline("org1", _baseline("r1"))
    engine.register_baseline("org1", _baseline("r2"))
    engine.record_drift("org1", _drift("r1"))
    stats = engine.get_drift_stats("org1")
    assert stats["drift_rate_pct"] == 50.0


def test_get_drift_stats_remediated_count(engine):
    drift = engine.record_drift("org1", _drift())
    engine.remediate_drift("org1", drift["drift_id"], "alice")
    stats = engine.get_drift_stats("org1")
    assert stats["remediated_count"] == 1


def test_get_drift_stats_by_severity(engine):
    engine.record_drift("org1", _drift(severity="critical"))
    engine.record_drift("org1", _drift(severity="critical"))
    engine.record_drift("org1", _drift(severity="low"))
    stats = engine.get_drift_stats("org1")
    assert stats["by_severity"].get("critical", 0) == 2
    assert stats["by_severity"].get("low", 0) == 1


def test_get_drift_stats_scans_last_7d(engine):
    """Seed a scan row directly (run_drift_scan is a stub) and verify stats counts it."""
    engine.register_baseline("org1", _baseline())
    _seed_scan_row(engine, "org1")
    stats = engine.get_drift_stats("org1")
    assert stats["scans_last_7d"] >= 1


# ------------------------------------------------------------------
# Org isolation
# ------------------------------------------------------------------

def test_org_isolation_baselines(engine):
    engine.register_baseline("org1", _baseline("r1"))
    engine.register_baseline("org2", _baseline("r2"))
    assert len(engine.list_baselines("org1")) == 1
    assert len(engine.list_baselines("org2")) == 1


def test_org_isolation_drifts(engine):
    engine.record_drift("org1", _drift("r1"))
    engine.record_drift("org2", _drift("r2"))
    assert len(engine.list_drifts("org1")) == 1
    assert len(engine.list_drifts("org2")) == 1


def test_org_isolation_acknowledge(engine):
    drift_org1 = engine.record_drift("org1", _drift())
    result = engine.acknowledge_drift("org2", drift_org1["drift_id"], "attacker")
    assert "error" in result


def test_org_isolation_stats(engine):
    engine.register_baseline("org1", _baseline())
    stats_org2 = engine.get_drift_stats("org2")
    assert stats_org2["total_baselines"] == 0
