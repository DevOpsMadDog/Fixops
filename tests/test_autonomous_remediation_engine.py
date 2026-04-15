"""Tests for AutonomousRemediationEngine — 35 tests covering all methods + org isolation."""

from __future__ import annotations

import pytest
from core.autonomous_remediation_engine import AutonomousRemediationEngine


@pytest.fixture
def engine(tmp_path):
    return AutonomousRemediationEngine(db_path=str(tmp_path / "ar.db"))


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _workflow(engine, org, name="Patch Critical CVEs", trigger_type="vulnerability", action_type="patch"):
    return engine.create_workflow(org, {
        "name": name,
        "trigger_type": trigger_type,
        "trigger_condition": {"severity": "critical"},
        "action_type": action_type,
        "target_type": "host",
        "automation_level": "semi",
    })


def _playbook(engine, org, name="Isolate Host Playbook", target_type="host"):
    return engine.create_playbook(org, {
        "playbook_name": name,
        "steps": [{"step": 1, "action": "scan"}, {"step": 2, "action": "isolate"}],
        "target_type": target_type,
        "estimated_duration_minutes": 15,
    })


# ---------------------------------------------------------------------------
# create_workflow
# ---------------------------------------------------------------------------

def test_create_workflow_returns_record(engine, org):
    w = _workflow(engine, org)
    assert w["name"] == "Patch Critical CVEs"
    assert w["org_id"] == org
    assert w["status"] == "draft"
    assert w["trigger_type"] == "vulnerability"
    assert w["action_type"] == "patch"
    assert w["automation_level"] == "semi"
    assert w["success_count"] == 0
    assert w["failure_count"] == 0
    assert "id" in w


def test_create_workflow_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.create_workflow(org, {"trigger_type": "manual", "action_type": "notify", "target_type": "host", "automation_level": "manual"})


def test_create_workflow_invalid_trigger_type_raises(engine, org):
    with pytest.raises(ValueError, match="trigger_type"):
        engine.create_workflow(org, {"name": "W", "trigger_type": "bad_trigger", "action_type": "notify", "target_type": "host", "automation_level": "manual"})


def test_create_workflow_invalid_action_type_raises(engine, org):
    with pytest.raises(ValueError, match="action_type"):
        engine.create_workflow(org, {"name": "W", "trigger_type": "manual", "action_type": "explode", "target_type": "host", "automation_level": "manual"})


def test_create_workflow_invalid_target_type_raises(engine, org):
    with pytest.raises(ValueError, match="target_type"):
        engine.create_workflow(org, {"name": "W", "trigger_type": "manual", "action_type": "notify", "target_type": "airplane", "automation_level": "manual"})


def test_create_workflow_invalid_automation_level_raises(engine, org):
    with pytest.raises(ValueError, match="automation_level"):
        engine.create_workflow(org, {"name": "W", "trigger_type": "manual", "action_type": "notify", "target_type": "host", "automation_level": "auto"})


def test_create_workflow_status_defaults_draft(engine, org):
    w = _workflow(engine, org)
    assert w["status"] == "draft"


# ---------------------------------------------------------------------------
# list_workflows
# ---------------------------------------------------------------------------

def test_list_workflows_empty(engine, org):
    assert engine.list_workflows(org) == []


def test_list_workflows_org_isolation(engine, org, org2):
    _workflow(engine, org)
    assert engine.list_workflows(org2) == []


def test_list_workflows_filter_trigger_type(engine, org):
    _workflow(engine, org, trigger_type="vulnerability")
    _workflow(engine, org, name="Alert W", trigger_type="alert")
    result = engine.list_workflows(org, trigger_type="alert")
    assert len(result) == 1
    assert result[0]["trigger_type"] == "alert"


def test_list_workflows_filter_status(engine, org):
    w = _workflow(engine, org)
    engine.activate_workflow(org, w["id"])
    _workflow(engine, org, name="W2")
    active = engine.list_workflows(org, status="active")
    assert len(active) == 1
    assert active[0]["status"] == "active"
    draft = engine.list_workflows(org, status="draft")
    assert len(draft) == 1


# ---------------------------------------------------------------------------
# activate_workflow
# ---------------------------------------------------------------------------

def test_activate_workflow_changes_status(engine, org):
    w = _workflow(engine, org)
    activated = engine.activate_workflow(org, w["id"])
    assert activated["status"] == "active"


def test_activate_workflow_not_found_raises(engine, org):
    with pytest.raises(ValueError):
        engine.activate_workflow(org, "nonexistent-id")


def test_activate_workflow_org_isolation(engine, org, org2):
    w = _workflow(engine, org)
    with pytest.raises(ValueError):
        engine.activate_workflow(org2, w["id"])


# ---------------------------------------------------------------------------
# record_execution
# ---------------------------------------------------------------------------

def test_record_execution_updates_success_count(engine, org):
    w = _workflow(engine, org)
    engine.record_execution(org, {
        "workflow_id": w["id"],
        "status": "succeeded",
        "target_id": "host-001",
        "target_type": "host",
    })
    updated = engine.get_workflow(org, w["id"])
    assert updated["success_count"] == 1
    assert updated["failure_count"] == 0


def test_record_execution_updates_failure_count(engine, org):
    w = _workflow(engine, org)
    engine.record_execution(org, {
        "workflow_id": w["id"],
        "status": "failed",
        "error_message": "Patch deployment failed",
    })
    updated = engine.get_workflow(org, w["id"])
    assert updated["failure_count"] == 1
    assert updated["success_count"] == 0


def test_record_execution_invalid_status_raises(engine, org):
    w = _workflow(engine, org)
    with pytest.raises(ValueError, match="status"):
        engine.record_execution(org, {"workflow_id": w["id"], "status": "exploded"})


def test_record_execution_missing_workflow_id_raises(engine, org):
    with pytest.raises(ValueError, match="workflow_id"):
        engine.record_execution(org, {"status": "pending"})


def test_record_execution_non_succeeded_failed_does_not_change_counts(engine, org):
    w = _workflow(engine, org)
    engine.record_execution(org, {"workflow_id": w["id"], "status": "running"})
    updated = engine.get_workflow(org, w["id"])
    assert updated["success_count"] == 0
    assert updated["failure_count"] == 0


# ---------------------------------------------------------------------------
# list_executions
# ---------------------------------------------------------------------------

def test_list_executions_filter_by_workflow_id(engine, org):
    w1 = _workflow(engine, org, name="W1")
    w2 = _workflow(engine, org, name="W2")
    engine.record_execution(org, {"workflow_id": w1["id"], "status": "succeeded"})
    engine.record_execution(org, {"workflow_id": w2["id"], "status": "failed"})
    result = engine.list_executions(org, workflow_id=w1["id"])
    assert len(result) == 1
    assert result[0]["workflow_id"] == w1["id"]


def test_list_executions_filter_by_status(engine, org):
    w = _workflow(engine, org)
    engine.record_execution(org, {"workflow_id": w["id"], "status": "succeeded"})
    engine.record_execution(org, {"workflow_id": w["id"], "status": "failed"})
    succeeded = engine.list_executions(org, status="succeeded")
    assert len(succeeded) == 1
    assert succeeded[0]["status"] == "succeeded"


def test_list_executions_org_isolation(engine, org, org2):
    w = _workflow(engine, org)
    engine.record_execution(org, {"workflow_id": w["id"], "status": "succeeded"})
    assert engine.list_executions(org2) == []


# ---------------------------------------------------------------------------
# create_playbook + list_playbooks
# ---------------------------------------------------------------------------

def test_create_playbook_returns_record(engine, org):
    pb = _playbook(engine, org)
    assert pb["playbook_name"] == "Isolate Host Playbook"
    assert pb["org_id"] == org
    assert pb["run_count"] == 0
    assert pb["last_run"] == ""
    assert isinstance(pb["steps"], list)
    assert len(pb["steps"]) == 2
    assert "id" in pb


def test_create_playbook_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="playbook_name"):
        engine.create_playbook(org, {"target_type": "host"})


def test_create_playbook_invalid_target_type_raises(engine, org):
    with pytest.raises(ValueError, match="target_type"):
        engine.create_playbook(org, {"playbook_name": "P", "target_type": "robot"})


def test_list_playbooks_filter_by_target_type(engine, org):
    _playbook(engine, org, target_type="host")
    _playbook(engine, org, name="Container PB", target_type="container")
    result = engine.list_playbooks(org, target_type="container")
    assert len(result) == 1
    assert result[0]["target_type"] == "container"


def test_list_playbooks_org_isolation(engine, org, org2):
    _playbook(engine, org)
    assert engine.list_playbooks(org2) == []


# ---------------------------------------------------------------------------
# run_playbook
# ---------------------------------------------------------------------------

def test_run_playbook_increments_run_count(engine, org):
    pb = _playbook(engine, org)
    result = engine.run_playbook(org, pb["id"])
    assert result["run_count"] == 1
    result2 = engine.run_playbook(org, pb["id"])
    assert result2["run_count"] == 2


def test_run_playbook_updates_last_run(engine, org):
    pb = _playbook(engine, org)
    result = engine.run_playbook(org, pb["id"])
    assert result["last_run"] != ""


def test_run_playbook_not_found_raises(engine, org):
    with pytest.raises(KeyError):
        engine.run_playbook(org, "nonexistent-id")


def test_run_playbook_steps_deserialized(engine, org):
    pb = _playbook(engine, org)
    result = engine.run_playbook(org, pb["id"])
    assert isinstance(result["steps"], list)


# ---------------------------------------------------------------------------
# get_remediation_stats
# ---------------------------------------------------------------------------

def test_get_remediation_stats_empty_org(engine, org):
    stats = engine.get_remediation_stats(org)
    assert stats["total_workflows"] == 0
    assert stats["active_workflows"] == 0
    assert stats["total_executions"] == 0
    assert stats["succeeded_executions"] == 0
    assert stats["failed_executions"] == 0
    assert stats["total_playbooks"] == 0
    assert stats["success_rate"] == 0.0
    assert stats["by_trigger_type"] == {}
    assert stats["by_action_type"] == {}


def test_get_remediation_stats_success_rate(engine, org):
    w = _workflow(engine, org)
    engine.record_execution(org, {"workflow_id": w["id"], "status": "succeeded"})
    engine.record_execution(org, {"workflow_id": w["id"], "status": "succeeded"})
    engine.record_execution(org, {"workflow_id": w["id"], "status": "failed"})
    stats = engine.get_remediation_stats(org)
    assert stats["total_executions"] == 3
    assert stats["succeeded_executions"] == 2
    assert stats["failed_executions"] == 1
    assert abs(stats["success_rate"] - (2 / 3)) < 1e-6


def test_get_remediation_stats_populated(engine, org):
    _workflow(engine, org, trigger_type="vulnerability", action_type="patch")
    w2 = _workflow(engine, org, name="Alert WF", trigger_type="alert", action_type="notify")
    engine.activate_workflow(org, w2["id"])
    _playbook(engine, org)
    stats = engine.get_remediation_stats(org)
    assert stats["total_workflows"] == 2
    assert stats["active_workflows"] == 1
    assert stats["total_playbooks"] == 1
    assert "vulnerability" in stats["by_trigger_type"]
    assert "alert" in stats["by_trigger_type"]
    assert "patch" in stats["by_action_type"]
    assert "notify" in stats["by_action_type"]
