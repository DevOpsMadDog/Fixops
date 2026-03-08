"""Tests for WorkflowDB — workflow orchestration database."""

import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.workflow_models import (
    Workflow,
    WorkflowExecution,
    WorkflowStatus,
    WorkflowStepStatus,
)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------
class TestWorkflowModels:
    def test_workflow_status_enum(self):
        assert WorkflowStatus.PENDING == "pending"
        assert WorkflowStatus.RUNNING == "running"
        assert WorkflowStatus.COMPLETED == "completed"
        assert WorkflowStatus.FAILED == "failed"
        assert WorkflowStatus.CANCELLED == "cancelled"

    def test_workflow_step_status_enum(self):
        assert WorkflowStepStatus.PENDING == "pending"
        assert WorkflowStepStatus.RUNNING == "running"
        assert WorkflowStepStatus.COMPLETED == "completed"
        assert WorkflowStepStatus.FAILED == "failed"
        assert WorkflowStepStatus.SKIPPED == "skipped"

    def test_workflow_to_dict(self):
        wf = Workflow(
            id="wf-1",
            name="Vuln Triage",
            description="Auto-triage vulnerabilities",
            steps=[
                {"name": "scan", "type": "scanner"},
                {"name": "score", "type": "fail_engine"},
            ],
            triggers={"event": "finding_created"},
            enabled=True,
            created_by="admin",
        )
        d = wf.to_dict()
        assert d["id"] == "wf-1"
        assert d["name"] == "Vuln Triage"
        assert len(d["steps"]) == 2
        assert d["triggers"]["event"] == "finding_created"
        assert d["enabled"] is True

    def test_workflow_execution_to_dict(self):
        exe = WorkflowExecution(
            id="exe-1",
            workflow_id="wf-1",
            status=WorkflowStatus.COMPLETED,
            triggered_by="event_bus",
            input_data={"finding_id": "f1"},
            output_data={"score": 85},
        )
        d = exe.to_dict()
        assert d["id"] == "exe-1"
        assert d["status"] == "completed"
        assert d["input_data"]["finding_id"] == "f1"


# ---------------------------------------------------------------------------
# WorkflowDB tests
# ---------------------------------------------------------------------------
class TestWorkflowDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.workflow_db import WorkflowDB
        return WorkflowDB(db_path=str(tmp_path / "test_workflows.db"))

    @pytest.fixture
    def sample_workflow(self, db):
        wf = Workflow(
            id="",
            name="Test Workflow",
            description="A test workflow",
            steps=[{"name": "step1", "type": "scan"}],
            enabled=True,
            created_by="test",
        )
        return db.create_workflow(wf)

    def test_create_workflow(self, db):
        wf = Workflow(
            id="",
            name="New Workflow",
            description="New workflow desc",
            steps=[],
        )
        created = db.create_workflow(wf)
        assert created.id != ""
        assert created.name == "New Workflow"

    def test_get_workflow(self, db, sample_workflow):
        wf = db.get_workflow(sample_workflow.id)
        assert wf is not None
        assert wf.name == "Test Workflow"
        assert len(wf.steps) == 1

    def test_get_workflow_not_found(self, db):
        assert db.get_workflow("nonexistent") is None

    def test_list_workflows(self, db, sample_workflow):
        workflows = db.list_workflows()
        assert len(workflows) >= 1

    def test_update_workflow(self, db, sample_workflow):
        sample_workflow.name = "Updated Workflow"
        sample_workflow.description = "Updated desc"
        updated = db.update_workflow(sample_workflow)
        assert updated.name == "Updated Workflow"
        # Verify from DB
        from_db = db.get_workflow(sample_workflow.id)
        assert from_db.name == "Updated Workflow"

    def test_delete_workflow(self, db, sample_workflow):
        result = db.delete_workflow(sample_workflow.id)
        assert result is True
        assert db.get_workflow(sample_workflow.id) is None

    def test_list_workflows_pagination(self, db):
        for i in range(5):
            db.create_workflow(Workflow(
                id="",
                name=f"Workflow {i}",
                description=f"Desc {i}",
                steps=[],
            ))
        page1 = db.list_workflows(limit=3)
        page2 = db.list_workflows(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 2


# ---------------------------------------------------------------------------
# Workflow Execution tests
# ---------------------------------------------------------------------------
class TestWorkflowExecutionDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.workflow_db import WorkflowDB
        return WorkflowDB(db_path=str(tmp_path / "test_exec.db"))

    @pytest.fixture
    def workflow(self, db):
        return db.create_workflow(Workflow(
            id="",
            name="Exec Test WF",
            description="For execution testing",
            steps=[{"name": "scan", "type": "sast"}],
        ))

    def test_create_execution(self, db, workflow):
        exe = WorkflowExecution(
            id="",
            workflow_id=workflow.id,
            status=WorkflowStatus.PENDING,
            triggered_by="manual",
            input_data={"target": "app"},
        )
        created = db.create_execution(exe)
        assert created.id != ""

    def test_get_execution(self, db, workflow):
        exe = db.create_execution(WorkflowExecution(
            id="",
            workflow_id=workflow.id,
            status=WorkflowStatus.RUNNING,
        ))
        retrieved = db.get_execution(exe.id)
        assert retrieved is not None
        assert retrieved.status == WorkflowStatus.RUNNING

    def test_list_executions(self, db, workflow):
        db.create_execution(WorkflowExecution(
            id="",
            workflow_id=workflow.id,
            status=WorkflowStatus.COMPLETED,
        ))
        execs = db.list_executions(workflow_id=workflow.id)
        assert len(execs) >= 1

    def test_update_execution(self, db, workflow):
        exe = db.create_execution(WorkflowExecution(
            id="",
            workflow_id=workflow.id,
            status=WorkflowStatus.RUNNING,
        ))
        exe.status = WorkflowStatus.COMPLETED
        exe.output_data = {"result": "success"}
        exe.completed_at = datetime.utcnow()
        updated = db.update_execution(exe)
        assert updated.status == WorkflowStatus.COMPLETED
