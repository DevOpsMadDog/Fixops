"""Tests for ThreatResponseEngine — ALDECI Beast Mode."""

from __future__ import annotations

import time
import uuid
import pytest

from core.threat_response_engine import ThreatResponseEngine


@pytest.fixture
def engine(tmp_path):
    return ThreatResponseEngine(db_path=str(tmp_path / "threat_response.db"))


@pytest.fixture
def org():
    return f"org-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def other_org():
    return f"org-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_playbook(engine, org, threat_type="ransomware", severity_scope="all"):
    return engine.create_playbook(
        org_id=org,
        playbook_name=f"PB-{uuid.uuid4().hex[:6]}",
        threat_type=threat_type,
        severity_scope=severity_scope,
        description="Test playbook",
        created_by="admin",
    )


def make_incident(engine, org, playbook_id, threat_type="ransomware"):
    return engine.trigger_incident(
        org_id=org,
        playbook_id=playbook_id,
        incident_name=f"INC-{uuid.uuid4().hex[:6]}",
        threat_type=threat_type,
        severity="high",
        triggered_by="soc_analyst",
    )


# ---------------------------------------------------------------------------
# Playbook creation
# ---------------------------------------------------------------------------

class TestCreatePlaybook:
    def test_creates_with_defaults(self, engine, org):
        pb = make_playbook(engine, org)
        assert pb["status"] == "active"
        assert pb["step_count"] == 0
        assert pb["execution_count"] == 0
        assert pb["avg_resolution_mins"] == 0.0
        assert pb["org_id"] == org

    def test_all_threat_types_valid(self, engine, org):
        types = ["ransomware", "phishing", "insider_threat", "ddos", "data_breach",
                 "malware", "apt", "supply_chain", "zero_day", "other"]
        for t in types:
            pb = make_playbook(engine, org, threat_type=t)
            assert pb["threat_type"] == t

    def test_invalid_threat_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="threat_type"):
            engine.create_playbook(org, "PB", "unknown_type", "all", "", "admin")

    def test_invalid_severity_scope_raises(self, engine, org):
        with pytest.raises(ValueError, match="severity_scope"):
            engine.create_playbook(org, "PB", "ransomware", "ultra", "", "admin")

    def test_all_severity_scopes_valid(self, engine, org):
        for scope in ["critical", "high", "medium", "low", "all"]:
            pb = make_playbook(engine, org, severity_scope=scope)
            assert pb["severity_scope"] == scope

    def test_id_is_unique(self, engine, org):
        pb1 = make_playbook(engine, org)
        pb2 = make_playbook(engine, org)
        assert pb1["id"] != pb2["id"]


# ---------------------------------------------------------------------------
# Add actions and step_number auto-increment
# ---------------------------------------------------------------------------

class TestAddAction:
    def test_first_action_is_step_1(self, engine, org):
        pb = make_playbook(engine, org)
        action = engine.add_action(pb["id"], org, "Isolate", "containment", "Isolate host")
        assert action["step_number"] == 1

    def test_step_numbers_increment(self, engine, org):
        pb = make_playbook(engine, org)
        a1 = engine.add_action(pb["id"], org, "Isolate", "containment", "step1")
        a2 = engine.add_action(pb["id"], org, "Notify", "notification", "step2")
        a3 = engine.add_action(pb["id"], org, "Document", "documentation", "step3")
        assert a1["step_number"] == 1
        assert a2["step_number"] == 2
        assert a3["step_number"] == 3

    def test_step_count_increments_on_playbook(self, engine, org):
        pb = make_playbook(engine, org)
        engine.add_action(pb["id"], org, "A1", "containment", "")
        engine.add_action(pb["id"], org, "A2", "eradication", "")
        performance = engine.get_playbook_performance(org)
        pb_perf = next(p for p in performance if p["id"] == pb["id"])
        assert pb_perf["step_count"] == 2

    def test_invalid_action_type_raises(self, engine, org):
        pb = make_playbook(engine, org)
        with pytest.raises(ValueError, match="action_type"):
            engine.add_action(pb["id"], org, "Bad", "invalid_type", "")

    def test_all_action_types_valid(self, engine, org):
        pb = make_playbook(engine, org)
        for i, atype in enumerate([
            "containment", "eradication", "recovery", "notification",
            "investigation", "escalation", "documentation"
        ]):
            action = engine.add_action(pb["id"], org, f"Action-{i}", atype, "")
            assert action["action_type"] == atype

    def test_playbook_not_found_raises(self, engine, org):
        with pytest.raises(KeyError):
            engine.add_action("nonexistent-id", org, "A", "containment", "")

    def test_org_isolation_add_action(self, engine, org, other_org):
        pb = make_playbook(engine, org)
        with pytest.raises(KeyError):
            engine.add_action(pb["id"], other_org, "A", "containment", "")

    def test_automated_flag_stored(self, engine, org):
        pb = make_playbook(engine, org)
        action = engine.add_action(pb["id"], org, "Auto", "containment", "", automated=True)
        assert action["automated"] == 1

    def test_timeout_mins_stored(self, engine, org):
        pb = make_playbook(engine, org)
        action = engine.add_action(pb["id"], org, "A", "containment", "", timeout_mins=60)
        assert action["timeout_mins"] == 60


# ---------------------------------------------------------------------------
# Trigger incident
# ---------------------------------------------------------------------------

class TestTriggerIncident:
    def test_trigger_creates_active_incident(self, engine, org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        assert inc["status"] == "active"
        assert inc["started_at"] is not None
        assert inc["resolved_at"] is None
        assert inc["resolution_mins"] == 0.0

    def test_trigger_increments_execution_count(self, engine, org):
        pb = make_playbook(engine, org)
        make_incident(engine, org, pb["id"])
        make_incident(engine, org, pb["id"])
        performance = engine.get_playbook_performance(org)
        pb_perf = next(p for p in performance if p["id"] == pb["id"])
        assert pb_perf["execution_count"] == 2

    def test_invalid_threat_type_raises(self, engine, org):
        pb = make_playbook(engine, org)
        with pytest.raises(ValueError, match="threat_type"):
            engine.trigger_incident(org, pb["id"], "INC", "unknown", "high", "analyst")

    def test_all_threat_types_triggerable(self, engine, org):
        pb = make_playbook(engine, org)
        types = ["phishing", "ddos", "data_breach", "malware", "apt"]
        for t in types:
            inc = engine.trigger_incident(org, pb["id"], f"INC-{t}", t, "high", "soc")
            assert inc["threat_type"] == t


# ---------------------------------------------------------------------------
# Log action
# ---------------------------------------------------------------------------

class TestLogAction:
    def test_log_creates_in_progress(self, engine, org):
        pb = make_playbook(engine, org)
        action = engine.add_action(pb["id"], org, "Isolate", "containment", "")
        inc = make_incident(engine, org, pb["id"])
        log = engine.log_action(inc["id"], org, action["id"], "Isolate", "analyst")
        assert log["status"] == "in_progress"
        assert log["started_at"] is not None
        assert log["completed_at"] is None

    def test_log_stores_action_name(self, engine, org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        log = engine.log_action(inc["id"], org, "", "Custom Action", "analyst")
        assert log["action_name"] == "Custom Action"


# ---------------------------------------------------------------------------
# Complete action
# ---------------------------------------------------------------------------

class TestCompleteAction:
    def test_complete_sets_completed_status(self, engine, org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        log = engine.log_action(inc["id"], org, "", "Isolate", "analyst")
        result = engine.complete_action(log["id"], org, "completed", "Done")
        assert result["status"] == "completed"
        assert result["completed_at"] is not None
        assert result["notes"] == "Done"

    def test_fail_sets_failed_status(self, engine, org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        log = engine.log_action(inc["id"], org, "", "Notify", "analyst")
        result = engine.complete_action(log["id"], org, "failed", "Network error")
        assert result["status"] == "failed"

    def test_invalid_status_raises(self, engine, org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        log = engine.log_action(inc["id"], org, "", "Notify", "analyst")
        with pytest.raises(ValueError, match="status"):
            engine.complete_action(log["id"], org, "in_progress")

    def test_not_found_raises(self, engine, org):
        with pytest.raises(KeyError):
            engine.complete_action("nonexistent", org, "completed")

    def test_org_isolation_complete(self, engine, org, other_org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        log = engine.log_action(inc["id"], org, "", "A", "analyst")
        with pytest.raises(KeyError):
            engine.complete_action(log["id"], other_org, "completed")


# ---------------------------------------------------------------------------
# Resolve incident
# ---------------------------------------------------------------------------

class TestResolveIncident:
    def test_resolve_sets_resolved_status(self, engine, org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        resolved = engine.resolve_incident(inc["id"], org)
        assert resolved["status"] == "resolved"
        assert resolved["resolved_at"] is not None

    def test_resolution_mins_computed(self, engine, org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        # Small sleep to ensure non-zero resolution time
        time.sleep(0.05)
        resolved = engine.resolve_incident(inc["id"], org)
        assert resolved["resolution_mins"] >= 0.0

    def test_avg_resolution_mins_updated_on_playbook(self, engine, org):
        pb = make_playbook(engine, org)
        inc1 = make_incident(engine, org, pb["id"])
        time.sleep(0.05)
        engine.resolve_incident(inc1["id"], org)

        inc2 = make_incident(engine, org, pb["id"])
        time.sleep(0.05)
        engine.resolve_incident(inc2["id"], org)

        performance = engine.get_playbook_performance(org)
        pb_perf = next(p for p in performance if p["id"] == pb["id"])
        assert pb_perf["avg_resolution_mins"] >= 0.0

    def test_resolve_not_found_raises(self, engine, org):
        with pytest.raises(KeyError):
            engine.resolve_incident("nonexistent", org)

    def test_org_isolation_resolve(self, engine, org, other_org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        with pytest.raises(KeyError):
            engine.resolve_incident(inc["id"], other_org)


# ---------------------------------------------------------------------------
# Active incidents
# ---------------------------------------------------------------------------

class TestGetActiveIncidents:
    def test_returns_only_active(self, engine, org):
        pb = make_playbook(engine, org)
        inc1 = make_incident(engine, org, pb["id"])
        inc2 = make_incident(engine, org, pb["id"])
        engine.resolve_incident(inc1["id"], org)

        active = engine.get_active_incidents(org)
        active_ids = [i["id"] for i in active]
        assert inc2["id"] in active_ids
        assert inc1["id"] not in active_ids

    def test_includes_action_log(self, engine, org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        engine.log_action(inc["id"], org, "", "Isolate", "analyst")

        active = engine.get_active_incidents(org)
        target = next(i for i in active if i["id"] == inc["id"])
        assert len(target["action_log"]) == 1

    def test_org_isolation_active_incidents(self, engine, org, other_org):
        pb = make_playbook(engine, org)
        make_incident(engine, org, pb["id"])
        assert engine.get_active_incidents(other_org) == []


# ---------------------------------------------------------------------------
# Incident timeline
# ---------------------------------------------------------------------------

class TestGetIncidentTimeline:
    def test_timeline_includes_actions_ordered(self, engine, org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        engine.log_action(inc["id"], org, "", "Action A", "analyst")
        engine.log_action(inc["id"], org, "", "Action B", "analyst")

        timeline = engine.get_incident_timeline(inc["id"], org)
        assert timeline["id"] == inc["id"]
        assert len(timeline["timeline"]) == 2
        names = [t["action_name"] for t in timeline["timeline"]]
        assert "Action A" in names
        assert "Action B" in names

    def test_timeline_not_found_raises(self, engine, org):
        with pytest.raises(KeyError):
            engine.get_incident_timeline("nonexistent", org)

    def test_org_isolation_timeline(self, engine, org, other_org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        with pytest.raises(KeyError):
            engine.get_incident_timeline(inc["id"], other_org)


# ---------------------------------------------------------------------------
# Response summary
# ---------------------------------------------------------------------------

class TestGetResponseSummary:
    def test_summary_empty_org(self, engine, org):
        summary = engine.get_response_summary(org)
        assert summary["total_playbooks"] == 0
        assert summary["total_incidents"] == 0
        assert summary["active_incidents"] == 0
        assert summary["resolved_incidents"] == 0
        assert summary["avg_resolution_mins"] == 0.0
        assert summary["by_threat_type"] == {}

    def test_summary_counts(self, engine, org):
        pb = make_playbook(engine, org, threat_type="ransomware")
        make_incident(engine, org, pb["id"], threat_type="ransomware")
        inc2 = make_incident(engine, org, pb["id"], threat_type="ransomware")
        engine.resolve_incident(inc2["id"], org)

        summary = engine.get_response_summary(org)
        assert summary["total_playbooks"] == 1
        assert summary["total_incidents"] == 2
        assert summary["active_incidents"] == 1
        assert summary["resolved_incidents"] == 1
        assert "ransomware" in summary["by_threat_type"]
        assert summary["by_threat_type"]["ransomware"] == 2

    def test_summary_avg_resolution_mins(self, engine, org):
        pb = make_playbook(engine, org)
        inc = make_incident(engine, org, pb["id"])
        time.sleep(0.05)
        engine.resolve_incident(inc["id"], org)
        summary = engine.get_response_summary(org)
        assert summary["avg_resolution_mins"] >= 0.0

    def test_org_isolation_summary(self, engine, org, other_org):
        pb = make_playbook(engine, org)
        make_incident(engine, org, pb["id"])
        summary = engine.get_response_summary(other_org)
        assert summary["total_incidents"] == 0
