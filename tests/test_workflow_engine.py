"""Tests for WorkflowEngine — trigger→condition→action automation chains.

Covers:
- CRUD operations (create, get, list, update, delete)
- Condition evaluation for all operators
- Action execution
- Event matching and workflow evaluation
- Built-in templates
- Execution history
- Stats
- Multi-org isolation
- Edge cases (no conditions, disabled workflows, unknown fields)
"""

from __future__ import annotations

import os
import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timezone

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

from core.workflow_engine import (
    ActionType,
    ConditionOperator,
    TriggerType,
    Workflow,
    WorkflowAction,
    WorkflowCondition,
    WorkflowEngine,
    WorkflowExecution,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    """Temporary SQLite database path."""
    return str(tmp_path / "test_workflow.db")


@pytest.fixture
def engine(tmp_db):
    """WorkflowEngine backed by a temp database."""
    return WorkflowEngine(db_path=tmp_db)


@pytest.fixture
def sample_workflow():
    """A basic workflow for reuse in tests."""
    return Workflow(
        name="Test Workflow",
        description="A test workflow",
        trigger=TriggerType.FINDING_CREATED,
        conditions=[
            WorkflowCondition(field="severity", operator=ConditionOperator.EQUALS, value="critical")
        ],
        actions=[
            WorkflowAction(type=ActionType.LOG, config={"level": "info", "message": "Test"})
        ],
        org_id="org_test",
        created_by="tester",
    )


@pytest.fixture
def critical_finding_event():
    """A sample critical finding event."""
    return {
        "event_type": TriggerType.FINDING_CREATED.value,
        "severity": "critical",
        "finding_id": "F-001",
        "title": "SQL Injection",
        "source": "scanner",
    }


# ---------------------------------------------------------------------------
# CRUD Tests
# ---------------------------------------------------------------------------


class TestWorkflowCRUD:
    def test_create_workflow(self, engine, sample_workflow):
        created = engine.create_workflow(sample_workflow)
        assert created.id == sample_workflow.id
        assert created.name == "Test Workflow"
        assert created.trigger == TriggerType.FINDING_CREATED.value

    def test_create_workflow_persists(self, engine, sample_workflow):
        engine.create_workflow(sample_workflow)
        fetched = engine.get_workflow(sample_workflow.id)
        assert fetched is not None
        assert fetched.name == "Test Workflow"

    def test_get_nonexistent_workflow_returns_none(self, engine):
        result = engine.get_workflow("nonexistent-id")
        assert result is None

    def test_list_workflows_empty(self, engine):
        result = engine.list_workflows()
        assert result == []

    def test_list_workflows_returns_all(self, engine):
        wf1 = Workflow(name="WF1", trigger=TriggerType.FINDING_CREATED, org_id="org1")
        wf2 = Workflow(name="WF2", trigger=TriggerType.SLA_BREACH, org_id="org1")
        engine.create_workflow(wf1)
        engine.create_workflow(wf2)
        result = engine.list_workflows()
        assert len(result) == 2

    def test_list_workflows_filter_by_org(self, engine):
        wf1 = Workflow(name="WF1", trigger=TriggerType.FINDING_CREATED, org_id="org1")
        wf2 = Workflow(name="WF2", trigger=TriggerType.SLA_BREACH, org_id="org2")
        engine.create_workflow(wf1)
        engine.create_workflow(wf2)
        result = engine.list_workflows(org_id="org1")
        assert len(result) == 1
        assert result[0].name == "WF1"

    def test_list_workflows_filter_by_trigger(self, engine):
        wf1 = Workflow(name="WF1", trigger=TriggerType.FINDING_CREATED, org_id="org1")
        wf2 = Workflow(name="WF2", trigger=TriggerType.SLA_BREACH, org_id="org1")
        engine.create_workflow(wf1)
        engine.create_workflow(wf2)
        result = engine.list_workflows(trigger_filter=TriggerType.FINDING_CREATED.value)
        assert len(result) == 1
        assert result[0].name == "WF1"

    def test_update_workflow_name(self, engine, sample_workflow):
        engine.create_workflow(sample_workflow)
        updated = engine.update_workflow(sample_workflow.id, {"name": "Updated Name"})
        assert updated.name == "Updated Name"

    def test_update_workflow_enabled(self, engine, sample_workflow):
        engine.create_workflow(sample_workflow)
        updated = engine.update_workflow(sample_workflow.id, {"enabled": False})
        assert updated.enabled is False

    def test_update_workflow_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.update_workflow("nonexistent-id", {"name": "X"})

    def test_delete_workflow_returns_true(self, engine, sample_workflow):
        engine.create_workflow(sample_workflow)
        result = engine.delete_workflow(sample_workflow.id)
        assert result is True

    def test_delete_workflow_removes_it(self, engine, sample_workflow):
        engine.create_workflow(sample_workflow)
        engine.delete_workflow(sample_workflow.id)
        fetched = engine.get_workflow(sample_workflow.id)
        assert fetched is None

    def test_delete_nonexistent_returns_false(self, engine):
        result = engine.delete_workflow("nonexistent-id")
        assert result is False

    def test_workflow_with_no_conditions(self, engine):
        wf = Workflow(
            name="No Conditions",
            trigger=TriggerType.SCAN_COMPLETED,
            conditions=[],
            actions=[WorkflowAction(type=ActionType.LOG, config={"message": "scan done"})],
        )
        created = engine.create_workflow(wf)
        fetched = engine.get_workflow(created.id)
        assert fetched is not None
        assert fetched.conditions == []

    def test_workflow_multiple_actions(self, engine):
        wf = Workflow(
            name="Multi-Action",
            trigger=TriggerType.FINDING_CREATED,
            actions=[
                WorkflowAction(type=ActionType.LOG, config={"message": "logged"}),
                WorkflowAction(type=ActionType.SEND_SLACK_MESSAGE, config={"channel": "#sec"}),
            ],
        )
        engine.create_workflow(wf)
        fetched = engine.get_workflow(wf.id)
        assert len(fetched.actions) == 2


# ---------------------------------------------------------------------------
# Condition Evaluation Tests
# ---------------------------------------------------------------------------


class TestConditionEvaluation:
    def test_equals_match(self, engine):
        condition = WorkflowCondition(field="severity", operator=ConditionOperator.EQUALS, value="critical")
        assert engine._check_conditions({"severity": "critical"}, [condition]) is True

    def test_equals_no_match(self, engine):
        condition = WorkflowCondition(field="severity", operator=ConditionOperator.EQUALS, value="critical")
        assert engine._check_conditions({"severity": "high"}, [condition]) is False

    def test_not_equals_match(self, engine):
        condition = WorkflowCondition(field="severity", operator=ConditionOperator.NOT_EQUALS, value="low")
        assert engine._check_conditions({"severity": "critical"}, [condition]) is True

    def test_not_equals_no_match(self, engine):
        condition = WorkflowCondition(field="severity", operator=ConditionOperator.NOT_EQUALS, value="critical")
        assert engine._check_conditions({"severity": "critical"}, [condition]) is False

    def test_greater_than_match(self, engine):
        condition = WorkflowCondition(field="score", operator=ConditionOperator.GREATER_THAN, value=7.0)
        assert engine._check_conditions({"score": 9.5}, [condition]) is True

    def test_greater_than_no_match(self, engine):
        condition = WorkflowCondition(field="score", operator=ConditionOperator.GREATER_THAN, value=7.0)
        assert engine._check_conditions({"score": 5.0}, [condition]) is False

    def test_less_than_match(self, engine):
        condition = WorkflowCondition(field="score", operator=ConditionOperator.LESS_THAN, value=5.0)
        assert engine._check_conditions({"score": 3.0}, [condition]) is True

    def test_less_than_no_match(self, engine):
        condition = WorkflowCondition(field="score", operator=ConditionOperator.LESS_THAN, value=5.0)
        assert engine._check_conditions({"score": 8.0}, [condition]) is False

    def test_contains_match(self, engine):
        condition = WorkflowCondition(field="title", operator=ConditionOperator.CONTAINS, value="Injection")
        assert engine._check_conditions({"title": "SQL Injection Attack"}, [condition]) is True

    def test_contains_no_match(self, engine):
        condition = WorkflowCondition(field="title", operator=ConditionOperator.CONTAINS, value="XSS")
        assert engine._check_conditions({"title": "SQL Injection Attack"}, [condition]) is False

    def test_in_operator_match(self, engine):
        condition = WorkflowCondition(field="severity", operator=ConditionOperator.IN, value=["critical", "high"])
        assert engine._check_conditions({"severity": "critical"}, [condition]) is True

    def test_in_operator_no_match(self, engine):
        condition = WorkflowCondition(field="severity", operator=ConditionOperator.IN, value=["critical", "high"])
        assert engine._check_conditions({"severity": "low"}, [condition]) is False

    def test_not_in_operator_match(self, engine):
        condition = WorkflowCondition(field="severity", operator=ConditionOperator.NOT_IN, value=["low", "info"])
        assert engine._check_conditions({"severity": "critical"}, [condition]) is True

    def test_not_in_operator_no_match(self, engine):
        condition = WorkflowCondition(field="severity", operator=ConditionOperator.NOT_IN, value=["low", "info"])
        assert engine._check_conditions({"severity": "low"}, [condition]) is False

    def test_empty_conditions_returns_true(self, engine):
        assert engine._check_conditions({"severity": "critical"}, []) is True

    def test_multiple_conditions_all_must_pass(self, engine):
        conditions = [
            WorkflowCondition(field="severity", operator=ConditionOperator.EQUALS, value="critical"),
            WorkflowCondition(field="score", operator=ConditionOperator.GREATER_THAN, value=8.0),
        ]
        assert engine._check_conditions({"severity": "critical", "score": 9.5}, conditions) is True

    def test_multiple_conditions_one_fails(self, engine):
        conditions = [
            WorkflowCondition(field="severity", operator=ConditionOperator.EQUALS, value="critical"),
            WorkflowCondition(field="score", operator=ConditionOperator.GREATER_THAN, value=8.0),
        ]
        assert engine._check_conditions({"severity": "critical", "score": 5.0}, conditions) is False

    def test_missing_field_returns_false(self, engine):
        condition = WorkflowCondition(field="nonexistent", operator=ConditionOperator.EQUALS, value="critical")
        assert engine._check_conditions({"severity": "critical"}, [condition]) is False

    def test_nested_field_resolution(self, engine):
        condition = WorkflowCondition(field="payload.severity", operator=ConditionOperator.EQUALS, value="critical")
        event = {"payload": {"severity": "critical"}}
        assert engine._check_conditions(event, [condition]) is True


# ---------------------------------------------------------------------------
# Action Execution Tests
# ---------------------------------------------------------------------------


class TestActionExecution:
    def test_log_action_executes(self, engine):
        actions = [WorkflowAction(type=ActionType.LOG, config={"level": "info", "message": "test"})]
        results = engine._execute_actions(actions, {"event_type": "finding.created"})
        assert len(results) == 1
        assert results[0]["status"] == "success"
        assert results[0]["action_type"] == ActionType.LOG.value

    def test_slack_action_logs_when_no_token(self, engine):
        actions = [WorkflowAction(type=ActionType.SEND_SLACK_MESSAGE, config={"channel": "#sec"})]
        results = engine._execute_actions(actions, {"event_type": "finding.created"})
        assert results[0]["status"] == "success"

    def test_email_action_logs_when_no_smtp(self, engine):
        actions = [WorkflowAction(type=ActionType.SEND_EMAIL, config={"to": "sec@example.com"})]
        results = engine._execute_actions(actions, {"event_type": "finding.created"})
        assert results[0]["status"] == "success"

    def test_jira_action_executes(self, engine):
        actions = [WorkflowAction(type=ActionType.CREATE_JIRA_TICKET, config={"project": "SEC"})]
        results = engine._execute_actions(actions, {"event_type": "finding.created"})
        assert results[0]["status"] == "success"

    def test_escalate_action_executes(self, engine):
        actions = [WorkflowAction(type=ActionType.ESCALATE, config={"assignee": "lead"})]
        results = engine._execute_actions(actions, {"event_type": "sla.breach"})
        assert results[0]["status"] == "success"

    def test_block_deploy_action_executes(self, engine):
        actions = [WorkflowAction(type=ActionType.BLOCK_DEPLOY, config={"reason": "critical finding"})]
        results = engine._execute_actions(actions, {"event_type": "finding.created"})
        assert results[0]["status"] == "success"

    def test_run_playbook_action_executes(self, engine):
        actions = [WorkflowAction(type=ActionType.RUN_PLAYBOOK, config={"playbook_id": "pb-001"})]
        results = engine._execute_actions(actions, {"event_type": "incident.created"})
        assert results[0]["status"] == "success"

    def test_update_finding_action_executes(self, engine):
        actions = [WorkflowAction(type=ActionType.UPDATE_FINDING, config={"finding_id": "F-001", "updates": {"status": "mitigated"}})]
        results = engine._execute_actions(actions, {"event_type": "finding.updated"})
        assert results[0]["status"] == "success"

    def test_multiple_actions_all_execute(self, engine):
        actions = [
            WorkflowAction(type=ActionType.LOG, config={"message": "step 1"}),
            WorkflowAction(type=ActionType.LOG, config={"message": "step 2"}),
        ]
        results = engine._execute_actions(actions, {"event_type": "scan.completed"})
        assert len(results) == 2
        assert all(r["status"] == "success" for r in results)


# ---------------------------------------------------------------------------
# Event Evaluation Tests
# ---------------------------------------------------------------------------


class TestEventEvaluation:
    def test_evaluate_event_matches_workflow(self, engine, sample_workflow, critical_finding_event):
        engine.create_workflow(sample_workflow)
        executions = engine.evaluate_event(critical_finding_event, org_id="org_test")
        assert len(executions) == 1
        assert executions[0].conditions_met is True
        assert executions[0].status == "success"

    def test_evaluate_event_no_matching_trigger(self, engine, sample_workflow):
        engine.create_workflow(sample_workflow)
        event = {"event_type": TriggerType.SLA_BREACH.value, "severity": "critical"}
        executions = engine.evaluate_event(event, org_id="org_test")
        assert len(executions) == 0

    def test_evaluate_event_conditions_not_met(self, engine, sample_workflow):
        engine.create_workflow(sample_workflow)
        event = {"event_type": TriggerType.FINDING_CREATED.value, "severity": "low"}
        executions = engine.evaluate_event(event, org_id="org_test")
        assert len(executions) == 1
        assert executions[0].conditions_met is False

    def test_evaluate_event_disabled_workflow_skipped(self, engine, sample_workflow):
        sample_workflow.enabled = False
        engine.create_workflow(sample_workflow)
        executions = engine.evaluate_event(
            {"event_type": TriggerType.FINDING_CREATED.value, "severity": "critical"},
            org_id="org_test",
        )
        assert len(executions) == 0

    def test_evaluate_event_persists_execution(self, engine, sample_workflow, critical_finding_event):
        engine.create_workflow(sample_workflow)
        engine.evaluate_event(critical_finding_event, org_id="org_test")
        history = engine.get_execution_history(org_id="org_test")
        assert len(history) == 1

    def test_evaluate_event_multiple_workflows(self, engine, critical_finding_event):
        wf1 = Workflow(
            name="WF1", trigger=TriggerType.FINDING_CREATED,
            conditions=[], actions=[WorkflowAction(type=ActionType.LOG, config={})],
            org_id="org_test",
        )
        wf2 = Workflow(
            name="WF2", trigger=TriggerType.FINDING_CREATED,
            conditions=[], actions=[WorkflowAction(type=ActionType.LOG, config={})],
            org_id="org_test",
        )
        engine.create_workflow(wf1)
        engine.create_workflow(wf2)
        executions = engine.evaluate_event(critical_finding_event, org_id="org_test")
        assert len(executions) == 2

    def test_evaluate_event_no_conditions_always_executes(self, engine):
        wf = Workflow(
            name="No Conditions",
            trigger=TriggerType.SCAN_COMPLETED,
            conditions=[],
            actions=[WorkflowAction(type=ActionType.LOG, config={"message": "done"})],
            org_id="org1",
        )
        engine.create_workflow(wf)
        event = {"event_type": TriggerType.SCAN_COMPLETED.value}
        executions = engine.evaluate_event(event, org_id="org1")
        assert len(executions) == 1
        assert executions[0].conditions_met is True
        assert len(executions[0].actions_executed) == 1


# ---------------------------------------------------------------------------
# Templates Tests
# ---------------------------------------------------------------------------


class TestTemplates:
    def test_get_templates_returns_five(self, engine):
        templates = engine.get_templates()
        assert len(templates) == 5

    def test_templates_have_required_fields(self, engine):
        templates = engine.get_templates()
        for tpl in templates:
            assert tpl.id
            assert tpl.name
            assert tpl.trigger

    def test_template_critical_finding_alert(self, engine):
        templates = engine.get_templates()
        names = [t.name for t in templates]
        assert "Critical Finding Alert" in names

    def test_template_sla_breach_escalation(self, engine):
        templates = engine.get_templates()
        names = [t.name for t in templates]
        assert "SLA Breach Escalation" in names

    def test_template_compliance_gap_ticket(self, engine):
        templates = engine.get_templates()
        names = [t.name for t in templates]
        assert "Compliance Gap Ticket" in names

    def test_template_new_asset_review(self, engine):
        templates = engine.get_templates()
        names = [t.name for t in templates]
        assert "New Asset Review" in names

    def test_template_scan_complete_report(self, engine):
        templates = engine.get_templates()
        names = [t.name for t in templates]
        assert "Scan Complete Report" in names

    def test_templates_have_actions(self, engine):
        templates = engine.get_templates()
        for tpl in templates:
            assert len(tpl.actions) >= 1


# ---------------------------------------------------------------------------
# Execution History Tests
# ---------------------------------------------------------------------------


class TestExecutionHistory:
    def test_execution_history_empty(self, engine):
        history = engine.get_execution_history()
        assert history == []

    def test_execution_history_after_evaluate(self, engine, sample_workflow, critical_finding_event):
        engine.create_workflow(sample_workflow)
        engine.evaluate_event(critical_finding_event, org_id="org_test")
        history = engine.get_execution_history()
        assert len(history) == 1

    def test_execution_history_filter_by_workflow(self, engine):
        wf1 = Workflow(name="WF1", trigger=TriggerType.FINDING_CREATED, org_id="org1",
                       conditions=[], actions=[WorkflowAction(type=ActionType.LOG, config={})])
        wf2 = Workflow(name="WF2", trigger=TriggerType.SLA_BREACH, org_id="org1",
                       conditions=[], actions=[WorkflowAction(type=ActionType.LOG, config={})])
        engine.create_workflow(wf1)
        engine.create_workflow(wf2)
        engine.evaluate_event({"event_type": TriggerType.FINDING_CREATED.value}, org_id="org1")
        engine.evaluate_event({"event_type": TriggerType.SLA_BREACH.value}, org_id="org1")
        history = engine.get_execution_history(workflow_id=wf1.id)
        assert len(history) == 1
        assert history[0].workflow_id == wf1.id

    def test_execution_history_filter_by_org(self, engine):
        wf = Workflow(name="WF", trigger=TriggerType.SCAN_COMPLETED, org_id="org_a",
                      conditions=[], actions=[WorkflowAction(type=ActionType.LOG, config={})])
        engine.create_workflow(wf)
        engine.evaluate_event({"event_type": TriggerType.SCAN_COMPLETED.value}, org_id="org_a")
        history_a = engine.get_execution_history(org_id="org_a")
        history_b = engine.get_execution_history(org_id="org_b")
        assert len(history_a) == 1
        assert len(history_b) == 0

    def test_execution_record_has_timestamps(self, engine, sample_workflow, critical_finding_event):
        engine.create_workflow(sample_workflow)
        executions = engine.evaluate_event(critical_finding_event, org_id="org_test")
        assert executions[0].started_at is not None
        assert executions[0].completed_at is not None

    def test_execution_limit(self, engine):
        wf = Workflow(name="WF", trigger=TriggerType.SCAN_COMPLETED, org_id="org1",
                      conditions=[], actions=[WorkflowAction(type=ActionType.LOG, config={})])
        engine.create_workflow(wf)
        for _ in range(5):
            engine.evaluate_event({"event_type": TriggerType.SCAN_COMPLETED.value}, org_id="org1")
        history = engine.get_execution_history(limit=3)
        assert len(history) == 3


# ---------------------------------------------------------------------------
# Stats Tests
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_empty(self, engine):
        stats = engine.get_workflow_stats()
        assert stats["total_workflows"] == 0
        assert stats["total_executions"] == 0
        assert stats["templates_available"] == 5

    def test_stats_counts_workflows(self, engine):
        wf1 = Workflow(name="WF1", trigger=TriggerType.FINDING_CREATED, org_id="org1")
        wf2 = Workflow(name="WF2", trigger=TriggerType.SLA_BREACH, org_id="org1", enabled=False)
        engine.create_workflow(wf1)
        engine.create_workflow(wf2)
        stats = engine.get_workflow_stats(org_id="org1")
        assert stats["total_workflows"] == 2
        assert stats["enabled_workflows"] == 1
        assert stats["disabled_workflows"] == 1

    def test_stats_counts_executions(self, engine):
        wf = Workflow(name="WF", trigger=TriggerType.SCAN_COMPLETED, org_id="org1",
                      conditions=[], actions=[WorkflowAction(type=ActionType.LOG, config={})])
        engine.create_workflow(wf)
        engine.evaluate_event({"event_type": TriggerType.SCAN_COMPLETED.value}, org_id="org1")
        engine.evaluate_event({"event_type": TriggerType.SCAN_COMPLETED.value}, org_id="org1")
        stats = engine.get_workflow_stats(org_id="org1")
        assert stats["total_executions"] == 2

    def test_stats_trigger_breakdown(self, engine):
        wf1 = Workflow(name="WF1", trigger=TriggerType.FINDING_CREATED, org_id="org1")
        wf2 = Workflow(name="WF2", trigger=TriggerType.SLA_BREACH, org_id="org1")
        engine.create_workflow(wf1)
        engine.create_workflow(wf2)
        stats = engine.get_workflow_stats(org_id="org1")
        assert TriggerType.FINDING_CREATED.value in stats["workflows_by_trigger"]
        assert TriggerType.SLA_BREACH.value in stats["workflows_by_trigger"]
