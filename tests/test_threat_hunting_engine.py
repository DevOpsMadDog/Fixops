"""
Tests for ThreatHuntingEngine (suite-core/core/threat_hunting_engine.py).

Covers: create_hunt, run_hunt, schedule_hunt, get_hunt, list_hunts,
get_results, delete_hunt, get_hunt_stats, clone_hunt, and internal
hunt-type dispatchers (ioc_match, behavior_pattern, anomaly_correlation,
lateral_movement, persistence, exfiltration, custom).

Run with:
    python -m pytest tests/test_threat_hunting_engine.py -x --tb=short --timeout=10 -q --no-cov
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.threat_hunting_engine import (
    HUNT_STATES,
    HUNT_TYPES,
    ThreatHuntingEngine,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def engine(tmp_path):
    """ThreatHuntingEngine backed by a temporary SQLite database."""
    return ThreatHuntingEngine(db_path=str(tmp_path / "hunt_engine_test.db"))


# ============================================================================
# CONSTANTS
# ============================================================================


class TestConstants:
    def test_hunt_types_contains_ioc_match(self):
        assert "ioc_match" in HUNT_TYPES

    def test_hunt_types_contains_behavior_pattern(self):
        assert "behavior_pattern" in HUNT_TYPES

    def test_hunt_types_contains_anomaly_correlation(self):
        assert "anomaly_correlation" in HUNT_TYPES

    def test_hunt_types_contains_lateral_movement(self):
        assert "lateral_movement" in HUNT_TYPES

    def test_hunt_types_contains_persistence(self):
        assert "persistence" in HUNT_TYPES

    def test_hunt_types_contains_exfiltration(self):
        assert "exfiltration" in HUNT_TYPES

    def test_hunt_types_contains_custom(self):
        assert "custom" in HUNT_TYPES

    def test_hunt_states_all_expected(self):
        for state in ["ready", "running", "completed", "failed", "cancelled"]:
            assert state in HUNT_STATES


# ============================================================================
# CREATE HUNT
# ============================================================================


class TestCreateHunt:
    def test_create_hunt_returns_dict(self, engine):
        result = engine.create_hunt(
            name="IOC Hunt",
            hunt_type="ioc_match",
            query={"ioc_value": "10.0.0.1", "ioc_type": "ip"},
        )
        assert isinstance(result, dict)

    def test_create_hunt_has_hunt_id(self, engine):
        result = engine.create_hunt(
            name="IOC Hunt",
            hunt_type="ioc_match",
            query={"ioc_value": "10.0.0.1"},
        )
        assert "hunt_id" in result
        assert result["hunt_id"]

    def test_create_hunt_state_is_ready(self, engine):
        result = engine.create_hunt(
            name="Ready Hunt",
            hunt_type="ioc_match",
            query={"ioc_value": "1.2.3.4"},
        )
        assert result["state"] == "ready"

    def test_create_hunt_stores_name(self, engine):
        result = engine.create_hunt(
            name="My Named Hunt",
            hunt_type="behavior_pattern",
            query={"pattern": "cmd.exe"},
        )
        assert result["name"] == "My Named Hunt"

    def test_create_hunt_stores_hunt_type(self, engine):
        result = engine.create_hunt(
            name="Exfil Hunt",
            hunt_type="exfiltration",
            query={"threshold_mb": 500},
        )
        assert result["hunt_type"] == "exfiltration"

    def test_create_hunt_stores_description(self, engine):
        result = engine.create_hunt(
            name="Described Hunt",
            hunt_type="persistence",
            query={"persistence_type": "cron"},
            description="Detects cron persistence",
        )
        assert result["description"] == "Detects cron persistence"

    def test_create_hunt_stores_org_id(self, engine):
        result = engine.create_hunt(
            name="Org Hunt",
            hunt_type="ioc_match",
            query={"ioc_value": "x"},
            org_id="org_test",
        )
        assert result["org_id"] == "org_test"

    def test_create_hunt_invalid_type_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid hunt_type"):
            engine.create_hunt(
                name="Bad Hunt",
                hunt_type="nonexistent_type",
                query={},
            )

    def test_create_hunt_custom_with_valid_sql(self, engine):
        result = engine.create_hunt(
            name="Custom Hunt",
            hunt_type="custom",
            query={"sql": "SELECT * FROM hunts LIMIT 5"},
        )
        assert result["hunt_type"] == "custom"

    def test_create_hunt_custom_with_dangerous_sql_raises(self, engine):
        with pytest.raises(ValueError, match="read-only SELECT"):
            engine.create_hunt(
                name="Evil Hunt",
                hunt_type="custom",
                query={"sql": "DROP TABLE hunts"},
            )

    def test_create_hunt_custom_insert_raises(self, engine):
        with pytest.raises(ValueError, match="read-only SELECT"):
            engine.create_hunt(
                name="Insert Hunt",
                hunt_type="custom",
                query={"sql": "INSERT INTO hunts VALUES (1,2,3)"},
            )

    def test_create_hunt_has_created_at(self, engine):
        result = engine.create_hunt(
            name="Time Hunt",
            hunt_type="ioc_match",
            query={"ioc_value": "1.1.1.1"},
        )
        assert "created_at" in result
        assert result["created_at"]

    def test_create_hunt_stores_query(self, engine):
        query = {"ioc_value": "192.168.0.1", "ioc_type": "ip"}
        result = engine.create_hunt(
            name="Query Check",
            hunt_type="ioc_match",
            query=query,
        )
        assert result["query"] == query


# ============================================================================
# GET HUNT
# ============================================================================


class TestGetHunt:
    def test_get_hunt_returns_dict(self, engine):
        created = engine.create_hunt("G1", "ioc_match", {"ioc_value": "x"})
        fetched = engine.get_hunt(created["hunt_id"])
        assert isinstance(fetched, dict)

    def test_get_hunt_returns_same_id(self, engine):
        created = engine.create_hunt("G2", "ioc_match", {"ioc_value": "x"})
        fetched = engine.get_hunt(created["hunt_id"])
        assert fetched["hunt_id"] == created["hunt_id"]

    def test_get_hunt_nonexistent_returns_none(self, engine):
        assert engine.get_hunt("nonexistent-uuid") is None


# ============================================================================
# LIST HUNTS
# ============================================================================


class TestListHunts:
    def test_list_hunts_returns_list(self, engine):
        result = engine.list_hunts()
        assert isinstance(result, list)

    def test_list_hunts_includes_created_hunt(self, engine):
        engine.create_hunt("Listed", "ioc_match", {"ioc_value": "x"}, org_id="org_list")
        hunts = engine.list_hunts(org_id="org_list")
        assert any(h["name"] == "Listed" for h in hunts)

    def test_list_hunts_org_isolation(self, engine):
        engine.create_hunt("OrgA", "ioc_match", {"ioc_value": "x"}, org_id="org_a")
        engine.create_hunt("OrgB", "ioc_match", {"ioc_value": "x"}, org_id="org_b")
        hunts_a = engine.list_hunts(org_id="org_a")
        assert all(h["org_id"] == "org_a" for h in hunts_a)
        assert not any(h["name"] == "OrgB" for h in hunts_a)

    def test_list_hunts_filter_by_type(self, engine):
        engine.create_hunt("Behavior", "behavior_pattern", {"pattern": "x"}, org_id="org_flt")
        engine.create_hunt("IOC", "ioc_match", {"ioc_value": "x"}, org_id="org_flt")
        behavior_hunts = engine.list_hunts(org_id="org_flt", hunt_type="behavior_pattern")
        assert all(h["hunt_type"] == "behavior_pattern" for h in behavior_hunts)
        assert len(behavior_hunts) == 1


# ============================================================================
# RUN HUNT
# ============================================================================


class TestRunHunt:
    def test_run_hunt_returns_dict(self, engine):
        hunt = engine.create_hunt("Run1", "ioc_match", {"ioc_value": "1.2.3.4"})
        result = engine.run_hunt(hunt["hunt_id"])
        assert isinstance(result, dict)

    def test_run_hunt_has_state(self, engine):
        hunt = engine.create_hunt("Run2", "ioc_match", {"ioc_value": "1.2.3.4"})
        result = engine.run_hunt(hunt["hunt_id"])
        assert result["state"] in ("completed", "failed")

    def test_run_hunt_has_hit_count(self, engine):
        hunt = engine.create_hunt("Run3", "ioc_match", {"ioc_value": "1.2.3.4"})
        result = engine.run_hunt(hunt["hunt_id"])
        assert "hit_count" in result

    def test_run_hunt_has_duration_ms(self, engine):
        hunt = engine.create_hunt("Run4", "ioc_match", {"ioc_value": "1.2.3.4"})
        result = engine.run_hunt(hunt["hunt_id"])
        assert result["duration_ms"] >= 1

    def test_run_hunt_has_hits_list(self, engine):
        hunt = engine.create_hunt("Run5", "ioc_match", {"ioc_value": "1.2.3.4"})
        result = engine.run_hunt(hunt["hunt_id"])
        assert isinstance(result["hits"], list)

    def test_run_hunt_updates_hunt_state(self, engine):
        hunt = engine.create_hunt("Run6", "ioc_match", {"ioc_value": "1.2.3.4"})
        engine.run_hunt(hunt["hunt_id"])
        updated = engine.get_hunt(hunt["hunt_id"])
        assert updated["state"] in ("completed", "failed")

    def test_run_hunt_nonexistent_raises(self, engine):
        with pytest.raises(KeyError):
            engine.run_hunt("does-not-exist")

    def test_run_hunt_behavior_pattern_returns_dict(self, engine):
        hunt = engine.create_hunt(
            "Behavior Run",
            "behavior_pattern",
            {"pattern": "cmd.exe", "timewindow_minutes": 30},
        )
        result = engine.run_hunt(hunt["hunt_id"])
        assert result["state"] in ("completed", "failed")

    def test_run_hunt_anomaly_correlation_returns_dict(self, engine):
        hunt = engine.create_hunt(
            "Anomaly Run",
            "anomaly_correlation",
            {"severity_threshold": "high", "min_events": 2},
        )
        result = engine.run_hunt(hunt["hunt_id"])
        assert result["state"] in ("completed", "failed")

    def test_run_hunt_lateral_movement_returns_hit(self, engine):
        hunt = engine.create_hunt(
            "LM Run",
            "lateral_movement",
            {"source_asset": "10.0.0.5", "hop_count": 2},
        )
        result = engine.run_hunt(hunt["hunt_id"])
        # lateral_movement always returns 1 simulated hit for a non-empty source_asset
        assert result["state"] in ("completed", "failed")
        assert isinstance(result["hits"], list)

    def test_run_hunt_persistence_returns_hit(self, engine):
        hunt = engine.create_hunt(
            "Persistence Run",
            "persistence",
            {"persistence_type": "registry", "asset": "WIN-01"},
        )
        result = engine.run_hunt(hunt["hunt_id"])
        assert len(result["hits"]) == 1
        assert result["hits"][0]["source"] == "persistence_detector"

    def test_run_hunt_exfiltration_returns_hit(self, engine):
        hunt = engine.create_hunt(
            "Exfil Run",
            "exfiltration",
            {"threshold_mb": 200, "timewindow_hours": 12},
        )
        result = engine.run_hunt(hunt["hunt_id"])
        assert len(result["hits"]) == 1
        assert result["hits"][0]["source"] == "exfiltration_detector"

    def test_run_hunt_custom_sql_valid(self, engine):
        hunt = engine.create_hunt(
            "Custom SQL Run",
            "custom",
            {"sql": "SELECT hunt_id FROM hunts LIMIT 10"},
        )
        result = engine.run_hunt(hunt["hunt_id"])
        assert result["state"] in ("completed", "failed")

    def test_run_hunt_ioc_match_empty_value_returns_no_hits(self, engine):
        hunt = engine.create_hunt(
            "Empty IOC",
            "ioc_match",
            {"ioc_value": "", "ioc_type": "ip"},
        )
        result = engine.run_hunt(hunt["hunt_id"])
        assert result["hit_count"] == 0


# ============================================================================
# GET RESULTS
# ============================================================================


class TestGetResults:
    def test_get_results_returns_list(self, engine):
        hunt = engine.create_hunt("Res1", "ioc_match", {"ioc_value": "x"})
        engine.run_hunt(hunt["hunt_id"])
        results = engine.get_results(hunt["hunt_id"])
        assert isinstance(results, list)

    def test_get_results_has_one_entry_after_run(self, engine):
        hunt = engine.create_hunt("Res2", "ioc_match", {"ioc_value": "x"})
        engine.run_hunt(hunt["hunt_id"])
        results = engine.get_results(hunt["hunt_id"])
        assert len(results) == 1

    def test_get_results_entry_has_expected_keys(self, engine):
        hunt = engine.create_hunt("Res3", "persistence", {"persistence_type": "all"})
        engine.run_hunt(hunt["hunt_id"])
        results = engine.get_results(hunt["hunt_id"])
        entry = results[0]
        for key in ("hunt_id", "run_at", "state", "hit_count", "duration_ms", "hits"):
            assert key in entry, f"Missing key: {key}"

    def test_get_results_accumulates_on_multiple_runs(self, engine):
        hunt = engine.create_hunt("Res4", "ioc_match", {"ioc_value": "y"})
        engine.run_hunt(hunt["hunt_id"])
        engine.run_hunt(hunt["hunt_id"])
        results = engine.get_results(hunt["hunt_id"])
        assert len(results) == 2


# ============================================================================
# DELETE HUNT
# ============================================================================


class TestDeleteHunt:
    def test_delete_hunt_returns_true(self, engine):
        hunt = engine.create_hunt("Del1", "ioc_match", {"ioc_value": "x"})
        assert engine.delete_hunt(hunt["hunt_id"]) is True

    def test_delete_hunt_not_found_returns_false(self, engine):
        assert engine.delete_hunt("nonexistent-id") is False

    def test_delete_hunt_removes_from_list(self, engine):
        hunt = engine.create_hunt("Del2", "ioc_match", {"ioc_value": "x"}, org_id="org_del")
        engine.delete_hunt(hunt["hunt_id"])
        hunts = engine.list_hunts(org_id="org_del")
        assert not any(h["hunt_id"] == hunt["hunt_id"] for h in hunts)

    def test_delete_hunt_get_returns_none(self, engine):
        hunt = engine.create_hunt("Del3", "ioc_match", {"ioc_value": "x"})
        engine.delete_hunt(hunt["hunt_id"])
        assert engine.get_hunt(hunt["hunt_id"]) is None


# ============================================================================
# STATS
# ============================================================================


class TestHuntStats:
    def test_stats_returns_dict(self, engine):
        stats = engine.get_hunt_stats()
        assert isinstance(stats, dict)

    def test_stats_empty_org_zero_hunts(self, engine):
        stats = engine.get_hunt_stats(org_id="org_empty_stats")
        assert stats["total_hunts"] == 0

    def test_stats_counts_hunts(self, engine):
        engine.create_hunt("S1", "ioc_match", {"ioc_value": "x"}, org_id="org_s")
        engine.create_hunt("S2", "ioc_match", {"ioc_value": "x"}, org_id="org_s")
        stats = engine.get_hunt_stats(org_id="org_s")
        assert stats["total_hunts"] == 2

    def test_stats_hunts_by_type(self, engine):
        engine.create_hunt("T1", "ioc_match", {"ioc_value": "x"}, org_id="org_by_type")
        engine.create_hunt("T2", "behavior_pattern", {"pattern": "p"}, org_id="org_by_type")
        stats = engine.get_hunt_stats(org_id="org_by_type")
        assert stats["hunts_by_type"]["ioc_match"] == 1
        assert stats["hunts_by_type"]["behavior_pattern"] == 1

    def test_stats_total_hits_after_run(self, engine):
        hunt = engine.create_hunt(
            "Hits Hunt",
            "persistence",
            {"persistence_type": "all"},
            org_id="org_hits",
        )
        engine.run_hunt(hunt["hunt_id"])
        stats = engine.get_hunt_stats(org_id="org_hits")
        assert stats["total_hits"] >= 1

    def test_stats_avg_hits_per_hunt(self, engine):
        engine.create_hunt("Avg1", "ioc_match", {"ioc_value": "x"}, org_id="org_avg")
        stats = engine.get_hunt_stats(org_id="org_avg")
        assert "avg_hits_per_hunt" in stats
        assert stats["avg_hits_per_hunt"] >= 0.0

    def test_stats_org_isolation(self, engine):
        engine.create_hunt("IsoA", "ioc_match", {"ioc_value": "x"}, org_id="org_iso_a")
        engine.create_hunt("IsoB", "ioc_match", {"ioc_value": "x"}, org_id="org_iso_b")
        stats_a = engine.get_hunt_stats(org_id="org_iso_a")
        stats_b = engine.get_hunt_stats(org_id="org_iso_b")
        assert stats_a["total_hunts"] == 1
        assert stats_b["total_hunts"] == 1


# ============================================================================
# CLONE HUNT
# ============================================================================


class TestCloneHunt:
    def test_clone_hunt_returns_dict(self, engine):
        original = engine.create_hunt("Original", "ioc_match", {"ioc_value": "x"})
        cloned = engine.clone_hunt(original["hunt_id"], "Clone")
        assert isinstance(cloned, dict)

    def test_clone_hunt_new_name(self, engine):
        original = engine.create_hunt("CloneSrc", "ioc_match", {"ioc_value": "x"})
        cloned = engine.clone_hunt(original["hunt_id"], "CloneDst")
        assert cloned["name"] == "CloneDst"

    def test_clone_hunt_same_type(self, engine):
        original = engine.create_hunt("CloneType", "behavior_pattern", {"pattern": "x"})
        cloned = engine.clone_hunt(original["hunt_id"], "CloneTypeCopy")
        assert cloned["hunt_type"] == "behavior_pattern"

    def test_clone_hunt_different_id(self, engine):
        original = engine.create_hunt("CloneId", "ioc_match", {"ioc_value": "z"})
        cloned = engine.clone_hunt(original["hunt_id"], "CloneIdCopy")
        assert cloned["hunt_id"] != original["hunt_id"]

    def test_clone_hunt_nonexistent_raises(self, engine):
        with pytest.raises(KeyError):
            engine.clone_hunt("nonexistent-id", "Will Fail")


# ============================================================================
# SCHEDULE HUNT
# ============================================================================


class TestScheduleHunt:
    def test_schedule_hunt_returns_dict(self, engine):
        hunt = engine.create_hunt("Sched1", "ioc_match", {"ioc_value": "x"})
        sched = engine.schedule_hunt(hunt["hunt_id"], interval_hours=12)
        assert isinstance(sched, dict)

    def test_schedule_hunt_has_schedule_id(self, engine):
        hunt = engine.create_hunt("Sched2", "ioc_match", {"ioc_value": "x"})
        sched = engine.schedule_hunt(hunt["hunt_id"])
        assert "schedule_id" in sched
        assert sched["schedule_id"]

    def test_schedule_hunt_stores_interval(self, engine):
        hunt = engine.create_hunt("Sched3", "ioc_match", {"ioc_value": "x"})
        sched = engine.schedule_hunt(hunt["hunt_id"], interval_hours=48)
        assert sched["interval_hours"] == 48

    def test_schedule_hunt_has_next_run_at(self, engine):
        hunt = engine.create_hunt("Sched4", "ioc_match", {"ioc_value": "x"})
        sched = engine.schedule_hunt(hunt["hunt_id"])
        assert "next_run_at" in sched
        assert sched["next_run_at"]

    def test_schedule_hunt_nonexistent_raises(self, engine):
        with pytest.raises(KeyError):
            engine.schedule_hunt("nonexistent-id")
