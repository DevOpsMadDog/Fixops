"""Tests for ComplianceWorkflowEngine — 35+ tests covering full lifecycle."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.compliance_workflow_engine import ComplianceWorkflowEngine

ORG = "test-org"


@pytest.fixture
def engine(tmp_path):
    return ComplianceWorkflowEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_workflow(engine, framework="SOC2", workflow_type="assessment", owner="alice", due_date="2026-12-31"):
    return engine.create_workflow(
        org_id=ORG,
        workflow_name="Test Workflow",
        framework=framework,
        workflow_type=workflow_type,
        owner=owner,
        due_date=due_date,
    )


def _make_task(engine, workflow_id, task_name="Collect evidence", priority="high",
               evidence_required=3, due_date="2026-11-30"):
    return engine.add_task(
        workflow_id=workflow_id,
        org_id=ORG,
        task_name=task_name,
        task_type="evidence-collection",
        assignee="bob",
        priority=priority,
        evidence_required=evidence_required,
        due_date=due_date,
    )


# ---------------------------------------------------------------------------
# create_workflow
# ---------------------------------------------------------------------------

class TestCreateWorkflow:
    def test_basic_creation(self, engine):
        wf = _make_workflow(engine)
        assert wf["id"]
        assert wf["org_id"] == ORG
        assert wf["workflow_name"] == "Test Workflow"
        assert wf["framework"] == "SOC2"
        assert wf["workflow_type"] == "assessment"
        assert wf["status"] == "draft"
        assert wf["completion_rate"] == 0.0
        assert wf["completed_at"] is None

    def test_all_frameworks(self, engine):
        frameworks = ["SOC2", "ISO27001", "NIST", "PCI-DSS", "HIPAA", "GDPR", "CIS", "FedRAMP"]
        for fw in frameworks:
            wf = _make_workflow(engine, framework=fw)
            assert wf["framework"] == fw

    def test_all_workflow_types(self, engine):
        types = ["assessment", "remediation", "audit-prep", "certification", "review", "gap-analysis"]
        for wt in types:
            wf = _make_workflow(engine, workflow_type=wt)
            assert wf["workflow_type"] == wt

    def test_invalid_framework_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid framework"):
            engine.create_workflow(ORG, "WF", "INVALID", "assessment", "alice", "2026-12-31")

    def test_invalid_workflow_type_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid workflow_type"):
            engine.create_workflow(ORG, "WF", "SOC2", "invalid-type", "alice", "2026-12-31")

    def test_unique_ids(self, engine):
        wf1 = _make_workflow(engine)
        wf2 = _make_workflow(engine)
        assert wf1["id"] != wf2["id"]


# ---------------------------------------------------------------------------
# add_task
# ---------------------------------------------------------------------------

class TestAddTask:
    def test_basic_task(self, engine):
        wf = _make_workflow(engine)
        task = _make_task(engine, wf["id"])
        assert task["id"]
        assert task["workflow_id"] == wf["id"]
        assert task["org_id"] == ORG
        assert task["status"] == "pending"
        assert task["evidence_provided"] == 0

    def test_all_task_types(self, engine):
        wf = _make_workflow(engine)
        types = ["documentation", "evidence-collection", "control-testing", "remediation", "review", "approval"]
        for tt in types:
            task = engine.add_task(wf["id"], ORG, f"Task {tt}", tt, "bob", "medium", 1, "2026-12-01")
            assert task["task_type"] == tt

    def test_all_priorities(self, engine):
        wf = _make_workflow(engine)
        for p in ["critical", "high", "medium", "low"]:
            task = engine.add_task(wf["id"], ORG, f"Task {p}", "documentation", "bob", p, 0, "2026-12-01")
            assert task["priority"] == p

    def test_invalid_task_type_raises(self, engine):
        wf = _make_workflow(engine)
        with pytest.raises(ValueError, match="Invalid task_type"):
            engine.add_task(wf["id"], ORG, "Task", "invalid", "bob", "high", 0, "2026-12-01")

    def test_invalid_priority_raises(self, engine):
        wf = _make_workflow(engine)
        with pytest.raises(ValueError, match="Invalid priority"):
            engine.add_task(wf["id"], ORG, "Task", "documentation", "bob", "urgent", 0, "2026-12-01")


# ---------------------------------------------------------------------------
# complete_task
# ---------------------------------------------------------------------------

class TestCompleteTask:
    def test_single_task_completion(self, engine):
        wf = _make_workflow(engine)
        task = _make_task(engine, wf["id"])
        result = engine.complete_task(wf["id"], task["id"], ORG, evidence_provided=3)
        assert result["status"] == "completed"
        assert result["evidence_provided"] == 3
        assert result["completed_at"] is not None

    def test_completion_rate_partial(self, engine):
        wf = _make_workflow(engine)
        t1 = _make_task(engine, wf["id"], task_name="Task 1")
        _make_task(engine, wf["id"], task_name="Task 2")
        engine.complete_task(wf["id"], t1["id"], ORG, evidence_provided=1)
        updated_wf = engine.get_workflow(wf["id"], ORG)
        assert updated_wf["completion_rate"] == 50.0

    def test_completion_rate_full_transitions_to_pending_approval(self, engine):
        wf = _make_workflow(engine)
        t1 = _make_task(engine, wf["id"], task_name="Task 1")
        t2 = _make_task(engine, wf["id"], task_name="Task 2")
        engine.complete_task(wf["id"], t1["id"], ORG, evidence_provided=1)
        engine.complete_task(wf["id"], t2["id"], ORG, evidence_provided=2)
        updated_wf = engine.get_workflow(wf["id"], ORG)
        assert updated_wf["completion_rate"] == 100.0
        assert updated_wf["status"] == "pending-approval"

    def test_completion_rate_100_single_task(self, engine):
        wf = _make_workflow(engine)
        t = _make_task(engine, wf["id"])
        engine.complete_task(wf["id"], t["id"], ORG, evidence_provided=2)
        updated_wf = engine.get_workflow(wf["id"], ORG)
        assert updated_wf["completion_rate"] == 100.0
        assert updated_wf["status"] == "pending-approval"

    def test_complete_nonexistent_task_returns_none(self, engine):
        wf = _make_workflow(engine)
        result = engine.complete_task(wf["id"], "bad-task-id", ORG, evidence_provided=0)
        assert result is None


# ---------------------------------------------------------------------------
# submit_approval
# ---------------------------------------------------------------------------

class TestSubmitApproval:
    def test_approved_transitions_workflow_to_completed(self, engine):
        wf = _make_workflow(engine)
        t = _make_task(engine, wf["id"])
        engine.complete_task(wf["id"], t["id"], ORG, evidence_provided=1)
        approval = engine.submit_approval(wf["id"], ORG, "manager", "approved", "LGTM")
        assert approval["decision"] == "approved"
        updated_wf = engine.get_workflow(wf["id"], ORG)
        assert updated_wf["status"] == "completed"
        assert updated_wf["completed_at"] is not None

    def test_rejected_transitions_workflow_to_needs_rework(self, engine):
        wf = _make_workflow(engine)
        engine.submit_approval(wf["id"], ORG, "manager", "rejected", "Missing evidence")
        updated_wf = engine.get_workflow(wf["id"], ORG)
        assert updated_wf["status"] == "needs-rework"

    def test_approval_fields(self, engine):
        wf = _make_workflow(engine)
        approval = engine.submit_approval(wf["id"], ORG, "ciso@acme.com", "approved", "All good")
        assert approval["approver"] == "ciso@acme.com"
        assert approval["comments"] == "All good"
        assert approval["decided_at"] is not None
        assert approval["created_at"] is not None

    def test_approval_included_in_get_workflow(self, engine):
        wf = _make_workflow(engine)
        engine.submit_approval(wf["id"], ORG, "auditor", "approved", "OK")
        fetched = engine.get_workflow(wf["id"], ORG)
        assert len(fetched["approvals"]) == 1
        assert fetched["approvals"][0]["approver"] == "auditor"


# ---------------------------------------------------------------------------
# get_workflow
# ---------------------------------------------------------------------------

class TestGetWorkflow:
    def test_returns_none_for_missing(self, engine):
        assert engine.get_workflow("no-such-id", ORG) is None

    def test_org_isolation(self, engine):
        wf = _make_workflow(engine)
        assert engine.get_workflow(wf["id"], "other-org") is None

    def test_includes_tasks_and_approvals(self, engine):
        wf = _make_workflow(engine)
        _make_task(engine, wf["id"], task_name="T1")
        _make_task(engine, wf["id"], task_name="T2")
        engine.submit_approval(wf["id"], ORG, "alice", "approved", "")
        fetched = engine.get_workflow(wf["id"], ORG)
        assert len(fetched["tasks"]) == 2
        assert len(fetched["approvals"]) == 1


# ---------------------------------------------------------------------------
# list_workflows
# ---------------------------------------------------------------------------

class TestListWorkflows:
    def test_list_all(self, engine):
        _make_workflow(engine, framework="SOC2")
        _make_workflow(engine, framework="NIST")
        wfs = engine.list_workflows(ORG)
        assert len(wfs) == 2

    def test_filter_by_framework(self, engine):
        _make_workflow(engine, framework="SOC2")
        _make_workflow(engine, framework="NIST")
        soc2_wfs = engine.list_workflows(ORG, framework="SOC2")
        assert all(w["framework"] == "SOC2" for w in soc2_wfs)
        assert len(soc2_wfs) == 1

    def test_filter_by_status(self, engine):
        _make_workflow(engine)
        _make_workflow(engine)
        wfs = engine.list_workflows(ORG, status="draft")
        assert len(wfs) == 2

    def test_org_isolation(self, engine):
        _make_workflow(engine)
        assert engine.list_workflows("other-org") == []


# ---------------------------------------------------------------------------
# get_overdue_tasks
# ---------------------------------------------------------------------------

class TestGetOverdueTasks:
    def test_overdue_task_detected(self, engine):
        wf = _make_workflow(engine)
        engine.add_task(wf["id"], ORG, "Old task", "documentation", "bob", "high", 0, "2020-01-01")
        overdue = engine.get_overdue_tasks(ORG)
        assert len(overdue) == 1
        assert overdue[0]["task_name"] == "Old task"

    def test_future_task_not_overdue(self, engine):
        wf = _make_workflow(engine)
        engine.add_task(wf["id"], ORG, "Future task", "documentation", "bob", "low", 0, "2099-12-31")
        assert engine.get_overdue_tasks(ORG) == []

    def test_completed_task_not_in_overdue(self, engine):
        wf = _make_workflow(engine)
        t = engine.add_task(wf["id"], ORG, "Done task", "documentation", "bob", "medium", 0, "2020-01-01")
        engine.complete_task(wf["id"], t["id"], ORG, evidence_provided=0)
        assert engine.get_overdue_tasks(ORG) == []


# ---------------------------------------------------------------------------
# get_framework_readiness
# ---------------------------------------------------------------------------

class TestGetFrameworkReadiness:
    def test_empty_framework(self, engine):
        result = engine.get_framework_readiness(ORG, "HIPAA")
        assert result["framework"] == "HIPAA"
        assert result["total_workflows"] == 0
        assert result["completed_workflows"] == 0
        assert result["avg_completion_rate"] == 0.0

    def test_with_workflows(self, engine):
        wf = _make_workflow(engine, framework="GDPR")
        t = _make_task(engine, wf["id"])
        engine.complete_task(wf["id"], t["id"], ORG, evidence_provided=1)
        engine.submit_approval(wf["id"], ORG, "ciso", "approved", "OK")
        result = engine.get_framework_readiness(ORG, "GDPR")
        assert result["total_workflows"] == 1
        assert result["completed_workflows"] == 1
        assert result["avg_completion_rate"] == 100.0

    def test_mixed_completion(self, engine):
        _make_workflow(engine, framework="PCI-DSS")
        _make_workflow(engine, framework="PCI-DSS")
        result = engine.get_framework_readiness(ORG, "PCI-DSS")
        assert result["total_workflows"] == 2
        assert result["completed_workflows"] == 0


# ---------------------------------------------------------------------------
# get_workflow_summary
# ---------------------------------------------------------------------------

class TestGetWorkflowSummary:
    def test_empty_summary(self, engine):
        summary = engine.get_workflow_summary(ORG)
        assert summary["total_workflows"] == 0
        assert summary["by_status"] == {}
        assert summary["by_framework"] == {}

    def test_summary_counts(self, engine):
        _make_workflow(engine, framework="SOC2")
        _make_workflow(engine, framework="SOC2")
        _make_workflow(engine, framework="NIST")
        summary = engine.get_workflow_summary(ORG)
        assert summary["total_workflows"] == 3
        assert summary["by_status"]["draft"] == 3
        assert summary["by_framework"]["SOC2"] == 2
        assert summary["by_framework"]["NIST"] == 1

    def test_org_isolation(self, engine):
        _make_workflow(engine)
        summary = engine.get_workflow_summary("other-org")
        assert summary["total_workflows"] == 0
