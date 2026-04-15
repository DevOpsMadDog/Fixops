"""Tests for SOCWorkflowEngine — 30+ tests covering all methods and stats."""

from __future__ import annotations

import pytest

from core.soc_workflow_engine import SOCWorkflowEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_soc_workflow.db")


@pytest.fixture
def engine(db_path):
    return SOCWorkflowEngine(db_path=db_path)


ORG = "org-soc-test"
ORG2 = "org-soc-other"


# ---------------------------------------------------------------------------
# create_workflow
# ---------------------------------------------------------------------------

def test_create_workflow_minimal(engine):
    wf = engine.create_workflow(ORG, {"name": "Alert Triage", "workflow_type": "alert_triage"})
    assert wf["name"] == "Alert Triage"
    assert wf["workflow_type"] == "alert_triage"
    assert wf["status"] == "active"
    assert wf["trigger"] == "manual"
    assert isinstance(wf["steps"], list)
    assert "id" in wf
    assert "created_at" in wf


def test_create_workflow_all_fields(engine):
    wf = engine.create_workflow(ORG, {
        "name": "IR Flow",
        "workflow_type": "incident_response",
        "trigger": "automated",
        "steps": [{"name": "contain"}, {"name": "eradicate"}],
        "description": "Full IR workflow",
    })
    assert wf["trigger"] == "automated"
    assert len(wf["steps"]) == 2
    assert wf["description"] == "Full IR workflow"


def test_create_workflow_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_workflow(ORG, {"workflow_type": "alert_triage"})


def test_create_workflow_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid workflow_type"):
        engine.create_workflow(ORG, {"name": "X", "workflow_type": "unknown_type"})


def test_create_workflow_invalid_trigger(engine):
    with pytest.raises(ValueError, match="Invalid trigger"):
        engine.create_workflow(ORG, {"name": "X", "workflow_type": "alert_triage", "trigger": "magic"})


def test_create_workflow_all_types(engine):
    for wt in ("alert_triage", "incident_response", "threat_hunt", "change_mgmt", "vulnerability_mgmt"):
        wf = engine.create_workflow(ORG, {"name": f"WF {wt}", "workflow_type": wt})
        assert wf["workflow_type"] == wt


def test_create_workflow_all_triggers(engine):
    for trigger in ("manual", "scheduled", "automated"):
        wf = engine.create_workflow(ORG, {
            "name": f"Trigger {trigger}",
            "workflow_type": "alert_triage",
            "trigger": trigger,
        })
        assert wf["trigger"] == trigger


def test_create_workflow_unique_ids(engine):
    w1 = engine.create_workflow(ORG, {"name": "W1", "workflow_type": "alert_triage"})
    w2 = engine.create_workflow(ORG, {"name": "W2", "workflow_type": "alert_triage"})
    assert w1["id"] != w2["id"]


# ---------------------------------------------------------------------------
# list_workflows
# ---------------------------------------------------------------------------

def test_list_workflows_empty(engine):
    assert engine.list_workflows(ORG) == []


def test_list_workflows_returns_all(engine):
    engine.create_workflow(ORG, {"name": "A", "workflow_type": "alert_triage"})
    engine.create_workflow(ORG, {"name": "B", "workflow_type": "threat_hunt"})
    assert len(engine.list_workflows(ORG)) == 2


def test_list_workflows_filter_type(engine):
    engine.create_workflow(ORG, {"name": "AT", "workflow_type": "alert_triage"})
    engine.create_workflow(ORG, {"name": "TH", "workflow_type": "threat_hunt"})
    at_list = engine.list_workflows(ORG, workflow_type="alert_triage")
    assert len(at_list) == 1
    assert at_list[0]["workflow_type"] == "alert_triage"


def test_list_workflows_filter_trigger(engine):
    engine.create_workflow(ORG, {"name": "Manual", "workflow_type": "alert_triage", "trigger": "manual"})
    engine.create_workflow(ORG, {"name": "Auto", "workflow_type": "alert_triage", "trigger": "automated"})
    manual_list = engine.list_workflows(ORG, trigger="manual")
    assert len(manual_list) == 1
    assert manual_list[0]["trigger"] == "manual"


def test_list_workflows_org_isolation(engine):
    engine.create_workflow(ORG, {"name": "Org1 WF", "workflow_type": "alert_triage"})
    engine.create_workflow(ORG2, {"name": "Org2 WF", "workflow_type": "alert_triage"})
    assert len(engine.list_workflows(ORG)) == 1
    assert len(engine.list_workflows(ORG2)) == 1


def test_list_workflows_steps_deserialized(engine):
    steps = [{"name": "step1"}, {"name": "step2"}]
    engine.create_workflow(ORG, {"name": "Steps WF", "workflow_type": "alert_triage", "steps": steps})
    result = engine.list_workflows(ORG)
    assert isinstance(result[0]["steps"], list)
    assert len(result[0]["steps"]) == 2


# ---------------------------------------------------------------------------
# get_workflow
# ---------------------------------------------------------------------------

def test_get_workflow_found(engine):
    wf = engine.create_workflow(ORG, {"name": "Findable", "workflow_type": "alert_triage"})
    fetched = engine.get_workflow(ORG, wf["id"])
    assert fetched is not None
    assert fetched["name"] == "Findable"


def test_get_workflow_not_found(engine):
    assert engine.get_workflow(ORG, "ghost-id") is None


def test_get_workflow_wrong_org(engine):
    wf = engine.create_workflow(ORG, {"name": "Private", "workflow_type": "alert_triage"})
    assert engine.get_workflow(ORG2, wf["id"]) is None


# ---------------------------------------------------------------------------
# start_execution
# ---------------------------------------------------------------------------

def test_start_execution_basic(engine):
    wf = engine.create_workflow(ORG, {"name": "Exec WF", "workflow_type": "alert_triage"})
    ex = engine.start_execution(ORG, {"workflow_id": wf["id"], "initiated_by": "analyst"})
    assert ex["workflow_id"] == wf["id"]
    assert ex["status"] == "running"
    assert ex["current_step"] == 0
    assert isinstance(ex["execution_log"], list)
    assert "started_at" in ex


def test_start_execution_missing_workflow_id(engine):
    with pytest.raises(ValueError, match="workflow_id is required"):
        engine.start_execution(ORG, {})


def test_start_execution_with_context(engine):
    wf = engine.create_workflow(ORG, {"name": "Context WF", "workflow_type": "alert_triage"})
    ex = engine.start_execution(ORG, {
        "workflow_id": wf["id"],
        "context": {"alert_id": "a-123", "severity": "high"},
    })
    assert ex["context"]["alert_id"] == "a-123"


# ---------------------------------------------------------------------------
# update_execution (step)
# ---------------------------------------------------------------------------

def test_update_execution_step_success(engine):
    wf = engine.create_workflow(ORG, {"name": "Step WF", "workflow_type": "alert_triage"})
    ex = engine.start_execution(ORG, {"workflow_id": wf["id"]})
    updated = engine.update_execution(ORG, ex["id"], "triage_alert", "success", "Alert confirmed")
    assert updated["current_step"] == 1
    assert len(updated["execution_log"]) == 1
    assert updated["execution_log"][0]["step_name"] == "triage_alert"
    assert updated["execution_log"][0]["step_status"] == "success"
    assert updated["status"] == "running"


def test_update_execution_step_failed(engine):
    wf = engine.create_workflow(ORG, {"name": "Fail WF", "workflow_type": "alert_triage"})
    ex = engine.start_execution(ORG, {"workflow_id": wf["id"]})
    updated = engine.update_execution(ORG, ex["id"], "triage_alert", "failed", "Timeout")
    assert updated["status"] == "failed"
    assert updated["completed_at"] is not None


def test_update_execution_multiple_steps(engine):
    wf = engine.create_workflow(ORG, {"name": "Multi WF", "workflow_type": "incident_response"})
    ex = engine.start_execution(ORG, {"workflow_id": wf["id"]})
    engine.update_execution(ORG, ex["id"], "step1", "success")
    updated = engine.update_execution(ORG, ex["id"], "step2", "success")
    assert updated["current_step"] == 2
    assert len(updated["execution_log"]) == 2


def test_update_execution_not_found(engine):
    result = engine.update_execution(ORG, "ghost-id", "step", "success")
    assert result is None


# ---------------------------------------------------------------------------
# complete_execution
# ---------------------------------------------------------------------------

def test_complete_execution(engine):
    wf = engine.create_workflow(ORG, {"name": "Complete WF", "workflow_type": "alert_triage"})
    ex = engine.start_execution(ORG, {"workflow_id": wf["id"]})
    completed = engine.complete_execution(ORG, ex["id"], "All steps passed")
    assert completed["status"] == "completed"
    assert completed["outcome"] == "All steps passed"
    assert completed["completed_at"] is not None


def test_complete_execution_not_found(engine):
    result = engine.complete_execution(ORG, "ghost-id", "done")
    assert result is None


# ---------------------------------------------------------------------------
# list_executions
# ---------------------------------------------------------------------------

def test_list_executions_empty(engine):
    assert engine.list_executions(ORG) == []


def test_list_executions_filter_workflow(engine):
    wf1 = engine.create_workflow(ORG, {"name": "WF1", "workflow_type": "alert_triage"})
    wf2 = engine.create_workflow(ORG, {"name": "WF2", "workflow_type": "threat_hunt"})
    engine.start_execution(ORG, {"workflow_id": wf1["id"]})
    engine.start_execution(ORG, {"workflow_id": wf2["id"]})
    filtered = engine.list_executions(ORG, workflow_id=wf1["id"])
    assert len(filtered) == 1
    assert filtered[0]["workflow_id"] == wf1["id"]


def test_list_executions_filter_status(engine):
    wf = engine.create_workflow(ORG, {"name": "Status WF", "workflow_type": "alert_triage"})
    ex1 = engine.start_execution(ORG, {"workflow_id": wf["id"]})
    ex2 = engine.start_execution(ORG, {"workflow_id": wf["id"]})
    engine.complete_execution(ORG, ex2["id"], "done")
    running = engine.list_executions(ORG, status="running")
    completed = engine.list_executions(ORG, status="completed")
    assert len(running) == 1
    assert len(completed) == 1


def test_list_executions_org_isolation(engine):
    wf = engine.create_workflow(ORG, {"name": "Iso WF", "workflow_type": "alert_triage"})
    engine.start_execution(ORG, {"workflow_id": wf["id"]})
    assert len(engine.list_executions(ORG2)) == 0


# ---------------------------------------------------------------------------
# get_soc_stats
# ---------------------------------------------------------------------------

def test_stats_empty_org(engine):
    stats = engine.get_soc_stats(ORG)
    assert stats["total_workflows"] == 0
    assert stats["by_type"] == {}
    assert stats["total_executions"] == 0
    assert stats["running_executions"] == 0
    assert stats["completed_executions"] == 0
    assert stats["failed_executions"] == 0
    assert stats["avg_duration_seconds"] == 0.0


def test_stats_workflow_counts(engine):
    engine.create_workflow(ORG, {"name": "AT1", "workflow_type": "alert_triage"})
    engine.create_workflow(ORG, {"name": "AT2", "workflow_type": "alert_triage"})
    engine.create_workflow(ORG, {"name": "TH1", "workflow_type": "threat_hunt"})
    stats = engine.get_soc_stats(ORG)
    assert stats["total_workflows"] == 3
    assert stats["by_type"]["alert_triage"] == 2
    assert stats["by_type"]["threat_hunt"] == 1


def test_stats_execution_counts(engine):
    wf = engine.create_workflow(ORG, {"name": "Exec WF", "workflow_type": "alert_triage"})
    ex1 = engine.start_execution(ORG, {"workflow_id": wf["id"]})
    ex2 = engine.start_execution(ORG, {"workflow_id": wf["id"]})
    ex3 = engine.start_execution(ORG, {"workflow_id": wf["id"]})
    engine.complete_execution(ORG, ex2["id"], "done")
    engine.update_execution(ORG, ex3["id"], "step1", "failed")
    stats = engine.get_soc_stats(ORG)
    assert stats["total_executions"] == 3
    assert stats["running_executions"] == 1
    assert stats["completed_executions"] == 1
    assert stats["failed_executions"] == 1


def test_stats_avg_duration(engine):
    wf = engine.create_workflow(ORG, {"name": "Dur WF", "workflow_type": "alert_triage"})
    ex = engine.start_execution(ORG, {"workflow_id": wf["id"]})
    engine.complete_execution(ORG, ex["id"], "done")
    stats = engine.get_soc_stats(ORG)
    assert stats["avg_duration_seconds"] >= 0.0


def test_stats_no_avg_duration_without_completed(engine):
    wf = engine.create_workflow(ORG, {"name": "No Dur WF", "workflow_type": "alert_triage"})
    engine.start_execution(ORG, {"workflow_id": wf["id"]})
    stats = engine.get_soc_stats(ORG)
    assert stats["avg_duration_seconds"] == 0.0
