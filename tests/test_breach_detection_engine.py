"""
Comprehensive tests for BreachDetectionEngine.

Covers:
- create_detection_rule: valid/invalid rule_type and data_source, defaults
- list_detection_rules: filtering by rule_type and data_source, org isolation
- record_detection_event: creation, trigger_count increment, invalid fields
- list_detection_events: filtering by severity/status/rule_id, ordering
- investigate_event: status transition, investigator, notes
- close_event: verdict validation, status=closed, resolution
- get_detection_stats: totals, false_positive_rate, avg_response_time_hours, org isolation
- Multi-tenant isolation throughout
"""

from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.breach_detection_engine import BreachDetectionEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "breach_detection.db")
    return BreachDetectionEngine(db_path=db)


ORG = "org-breach-test"
ORG2 = "org-breach-other"


def _rule(overrides=None):
    base = {
        "name": "Test Rule",
        "rule_type": "behavioral",
        "data_source": "endpoint",
        "threshold": 5,
    }
    if overrides:
        base.update(overrides)
    return base


def _event(rule_id, overrides=None):
    base = {
        "rule_id": rule_id,
        "severity": "high",
        "entity": "host-001",
        "indicators": ["ioc-1", "ioc-2"],
        "matched_count": 3,
    }
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# create_detection_rule
# ---------------------------------------------------------------------------

class TestCreateDetectionRule:
    def test_returns_dict_with_id(self, engine):
        result = engine.create_detection_rule(ORG, _rule())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_stores_name_and_rule_type(self, engine):
        result = engine.create_detection_rule(ORG, _rule({"name": "Sig Rule", "rule_type": "signature"}))
        assert result["name"] == "Sig Rule"
        assert result["rule_type"] == "signature"

    def test_default_data_source_is_endpoint(self, engine):
        data = {"name": "R", "rule_type": "anomaly"}
        result = engine.create_detection_rule(ORG, data)
        assert result["data_source"] == "endpoint"

    def test_default_threshold_is_5(self, engine):
        data = {"name": "R", "rule_type": "heuristic"}
        result = engine.create_detection_rule(ORG, data)
        assert result["threshold"] == 5

    def test_default_status_is_active(self, engine):
        result = engine.create_detection_rule(ORG, _rule())
        assert result["status"] == "active"

    def test_trigger_count_starts_at_zero(self, engine):
        result = engine.create_detection_rule(ORG, _rule())
        assert result["trigger_count"] == 0

    def test_all_valid_rule_types(self, engine):
        for rt in ("behavioral", "signature", "anomaly", "heuristic", "ml_based"):
            result = engine.create_detection_rule(ORG, _rule({"rule_type": rt, "name": rt}))
            assert result["rule_type"] == rt

    def test_all_valid_data_sources(self, engine):
        for ds in ("endpoint", "network", "cloud", "email", "identity", "application"):
            result = engine.create_detection_rule(ORG, _rule({"data_source": ds, "name": ds}))
            assert result["data_source"] == ds

    def test_invalid_rule_type_raises(self, engine):
        with pytest.raises(ValueError, match="rule_type"):
            engine.create_detection_rule(ORG, _rule({"rule_type": "invalid"}))

    def test_invalid_data_source_raises(self, engine):
        with pytest.raises(ValueError, match="data_source"):
            engine.create_detection_rule(ORG, _rule({"data_source": "unknown"}))

    def test_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name"):
            engine.create_detection_rule(ORG, {"rule_type": "behavioral"})


# ---------------------------------------------------------------------------
# list_detection_rules
# ---------------------------------------------------------------------------

class TestListDetectionRules:
    def test_returns_created_rules(self, engine):
        engine.create_detection_rule(ORG, _rule())
        rules = engine.list_detection_rules(ORG)
        assert len(rules) >= 1

    def test_filter_by_rule_type(self, engine):
        engine.create_detection_rule(ORG, _rule({"rule_type": "signature", "name": "S"}))
        engine.create_detection_rule(ORG, _rule({"rule_type": "anomaly", "name": "A"}))
        rules = engine.list_detection_rules(ORG, rule_type="signature")
        assert all(r["rule_type"] == "signature" for r in rules)

    def test_filter_by_data_source(self, engine):
        engine.create_detection_rule(ORG, _rule({"data_source": "network", "name": "N"}))
        engine.create_detection_rule(ORG, _rule({"data_source": "cloud", "name": "C"}))
        rules = engine.list_detection_rules(ORG, data_source="network")
        assert all(r["data_source"] == "network" for r in rules)

    def test_org_isolation(self, engine):
        engine.create_detection_rule(ORG, _rule({"name": "Org1 Rule"}))
        rules2 = engine.list_detection_rules(ORG2)
        assert all(r["org_id"] == ORG2 for r in rules2)


# ---------------------------------------------------------------------------
# record_detection_event
# ---------------------------------------------------------------------------

class TestRecordDetectionEvent:
    def test_returns_dict_with_id(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        result = engine.record_detection_event(ORG, _event(rule["id"]))
        assert "id" in result
        assert len(result["id"]) == 36

    def test_status_defaults_to_open(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        result = engine.record_detection_event(ORG, _event(rule["id"]))
        assert result["status"] == "open"

    def test_indicators_stored_as_list(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        result = engine.record_detection_event(ORG, _event(rule["id"]))
        assert isinstance(result["indicators"], list)
        assert "ioc-1" in result["indicators"]

    def test_increments_rule_trigger_count(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        engine.record_detection_event(ORG, _event(rule["id"]))
        engine.record_detection_event(ORG, _event(rule["id"]))
        rules = engine.list_detection_rules(ORG)
        matched = [r for r in rules if r["id"] == rule["id"]]
        assert matched[0]["trigger_count"] == 2

    def test_invalid_severity_raises(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        with pytest.raises(ValueError, match="severity"):
            engine.record_detection_event(ORG, _event(rule["id"], {"severity": "extreme"}))

    def test_missing_rule_id_raises(self, engine):
        with pytest.raises(ValueError, match="rule_id"):
            engine.record_detection_event(ORG, {"severity": "high", "entity": "host"})

    def test_missing_entity_raises(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        with pytest.raises(ValueError, match="entity"):
            engine.record_detection_event(ORG, {"rule_id": rule["id"], "severity": "high"})


# ---------------------------------------------------------------------------
# list_detection_events
# ---------------------------------------------------------------------------

class TestListDetectionEvents:
    def test_returns_events_for_org(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        engine.record_detection_event(ORG, _event(rule["id"]))
        events = engine.list_detection_events(ORG)
        assert len(events) >= 1

    def test_filter_by_severity(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        engine.record_detection_event(ORG, _event(rule["id"], {"severity": "critical"}))
        engine.record_detection_event(ORG, _event(rule["id"], {"severity": "low"}))
        events = engine.list_detection_events(ORG, severity="critical")
        assert all(e["severity"] == "critical" for e in events)

    def test_filter_by_status(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        engine.record_detection_event(ORG, _event(rule["id"]))
        events = engine.list_detection_events(ORG, status="open")
        assert all(e["status"] == "open" for e in events)

    def test_filter_by_rule_id(self, engine):
        rule1 = engine.create_detection_rule(ORG, _rule({"name": "R1"}))
        rule2 = engine.create_detection_rule(ORG, _rule({"name": "R2"}))
        engine.record_detection_event(ORG, _event(rule1["id"]))
        engine.record_detection_event(ORG, _event(rule2["id"]))
        events = engine.list_detection_events(ORG, rule_id=rule1["id"])
        assert all(e["rule_id"] == rule1["id"] for e in events)

    def test_org_isolation(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        engine.record_detection_event(ORG, _event(rule["id"]))
        events2 = engine.list_detection_events(ORG2)
        assert events2 == []


# ---------------------------------------------------------------------------
# investigate_event
# ---------------------------------------------------------------------------

class TestInvestigateEvent:
    def test_sets_status_investigating(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev = engine.record_detection_event(ORG, _event(rule["id"]))
        result = engine.investigate_event(ORG, ev["id"], "analyst-1", "Looking into it")
        assert result["status"] == "investigating"

    def test_sets_investigator(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev = engine.record_detection_event(ORG, _event(rule["id"]))
        result = engine.investigate_event(ORG, ev["id"], "alice", "notes")
        assert result["investigator"] == "alice"

    def test_sets_investigation_notes(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev = engine.record_detection_event(ORG, _event(rule["id"]))
        result = engine.investigate_event(ORG, ev["id"], "bob", "Suspicious traffic")
        assert result["investigation_notes"] == "Suspicious traffic"

    def test_sets_investigation_started_at(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev = engine.record_detection_event(ORG, _event(rule["id"]))
        result = engine.investigate_event(ORG, ev["id"], "carol", "")
        assert result["investigation_started_at"] is not None

    def test_invalid_event_id_raises(self, engine):
        with pytest.raises(ValueError):
            engine.investigate_event(ORG, "nonexistent-id", "analyst", "notes")


# ---------------------------------------------------------------------------
# close_event
# ---------------------------------------------------------------------------

class TestCloseEvent:
    def test_sets_status_closed(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev = engine.record_detection_event(ORG, _event(rule["id"]))
        result = engine.close_event(ORG, ev["id"], "true_positive", "Confirmed breach")
        assert result["status"] == "closed"

    def test_sets_verdict(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev = engine.record_detection_event(ORG, _event(rule["id"]))
        result = engine.close_event(ORG, ev["id"], "false_positive", "Noise")
        assert result["verdict"] == "false_positive"

    def test_sets_resolution(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev = engine.record_detection_event(ORG, _event(rule["id"]))
        result = engine.close_event(ORG, ev["id"], "benign", "Expected behavior")
        assert result["resolution"] == "Expected behavior"

    def test_sets_closed_at(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev = engine.record_detection_event(ORG, _event(rule["id"]))
        result = engine.close_event(ORG, ev["id"], "true_positive", "")
        assert result["closed_at"] is not None

    def test_all_valid_verdicts(self, engine):
        for verdict in ("true_positive", "false_positive", "benign"):
            rule = engine.create_detection_rule(ORG, _rule({"name": verdict}))
            ev = engine.record_detection_event(ORG, _event(rule["id"]))
            result = engine.close_event(ORG, ev["id"], verdict, "")
            assert result["verdict"] == verdict

    def test_invalid_verdict_raises(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev = engine.record_detection_event(ORG, _event(rule["id"]))
        with pytest.raises(ValueError, match="verdict"):
            engine.close_event(ORG, ev["id"], "unknown_verdict", "")

    def test_invalid_event_id_raises(self, engine):
        with pytest.raises(ValueError):
            engine.close_event(ORG, "nonexistent-id", "benign", "")


# ---------------------------------------------------------------------------
# get_detection_stats
# ---------------------------------------------------------------------------

class TestGetDetectionStats:
    def test_total_rules(self, engine):
        engine.create_detection_rule(ORG, _rule({"name": "R1"}))
        engine.create_detection_rule(ORG, _rule({"name": "R2"}))
        stats = engine.get_detection_stats(ORG)
        assert stats["total_rules"] == 2

    def test_active_rules_count(self, engine):
        engine.create_detection_rule(ORG, _rule({"name": "Active", "status": "active"}))
        engine.create_detection_rule(ORG, _rule({"name": "Inactive", "status": "disabled"}))
        stats = engine.get_detection_stats(ORG)
        assert stats["active_rules"] == 1

    def test_by_rule_type_dict(self, engine):
        engine.create_detection_rule(ORG, _rule({"rule_type": "behavioral", "name": "B1"}))
        engine.create_detection_rule(ORG, _rule({"rule_type": "behavioral", "name": "B2"}))
        engine.create_detection_rule(ORG, _rule({"rule_type": "signature", "name": "S1"}))
        stats = engine.get_detection_stats(ORG)
        assert stats["by_rule_type"]["behavioral"] == 2
        assert stats["by_rule_type"]["signature"] == 1

    def test_open_events_count(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        engine.record_detection_event(ORG, _event(rule["id"]))
        engine.record_detection_event(ORG, _event(rule["id"]))
        stats = engine.get_detection_stats(ORG)
        assert stats["open_events"] >= 2

    def test_critical_events_count(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        engine.record_detection_event(ORG, _event(rule["id"], {"severity": "critical"}))
        stats = engine.get_detection_stats(ORG)
        assert stats["critical_events"] >= 1

    def test_false_positive_rate(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev1 = engine.record_detection_event(ORG, _event(rule["id"]))
        ev2 = engine.record_detection_event(ORG, _event(rule["id"]))
        engine.close_event(ORG, ev1["id"], "false_positive", "noise")
        engine.close_event(ORG, ev2["id"], "true_positive", "real")
        stats = engine.get_detection_stats(ORG)
        # 1 FP out of 2 closed = 50%
        assert abs(stats["false_positive_rate"] - 50.0) < 0.1

    def test_false_positive_rate_zero_when_no_closed(self, engine):
        stats = engine.get_detection_stats(ORG)
        assert stats["false_positive_rate"] == 0.0

    def test_avg_response_time_hours_positive(self, engine):
        rule = engine.create_detection_rule(ORG, _rule())
        ev = engine.record_detection_event(ORG, _event(rule["id"]))
        engine.close_event(ORG, ev["id"], "true_positive", "done")
        stats = engine.get_detection_stats(ORG)
        assert stats["avg_response_time_hours"] >= 0.0

    def test_avg_response_time_zero_when_no_closed(self, engine):
        stats = engine.get_detection_stats("empty-org-rt")
        assert stats["avg_response_time_hours"] == 0.0

    def test_empty_org_stats(self, engine):
        stats = engine.get_detection_stats("empty-org")
        assert stats["total_rules"] == 0
        assert stats["active_rules"] == 0
        assert stats["open_events"] == 0
        assert stats["critical_events"] == 0

    def test_org_isolation(self, engine):
        engine.create_detection_rule(ORG, _rule({"name": "R1"}))
        engine.create_detection_rule(ORG, _rule({"name": "R2"}))
        engine.create_detection_rule(ORG2, _rule({"name": "X1"}))
        stats1 = engine.get_detection_stats(ORG)
        stats2 = engine.get_detection_stats(ORG2)
        assert stats1["total_rules"] == 2
        assert stats2["total_rules"] == 1
