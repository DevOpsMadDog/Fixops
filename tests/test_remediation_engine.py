"""
Tests for FixEngine — Automated Remediation Workflow Engine.

Coverage:
- Playbook CRUD (create, get, list, templates)
- Execution lifecycle: pending → running → completed
- Approval gate: awaiting_approval → approved → running → completed
- Reject gate: awaiting_approval → cancelled
- Rollback: completed → rolled_back
- Cancel: pending/awaiting_approval/running → cancelled
- Step execution tracking (progress, output)
- Error handling and edge cases

Run with:
    python -m pytest tests/test_remediation_engine.py -x --tb=short --timeout=10 -q
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.remediation_engine import (
    ApprovalGate,
    CodeFix,
    EffortLevel,
    ExecutionStatus,
    PlanState,
    PlaybookStep,
    PlaybookType,
    RemediationEngine,
    RemediationExecution,
    RemediationPlan,
    RemediationPlanEngine,
    RemediationPlaybook,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """RemediationEngine backed by a temporary SQLite database."""
    db = str(tmp_path / "test_remediation.db")
    return RemediationEngine(db_path=db)


@pytest.fixture
def simple_steps():
    """Minimal step list — uses noop action so no side-effects."""
    return [
        {"name": "Step A", "action": "noop", "params": {}},
        {"name": "Step B", "action": "noop", "params": {}},
    ]


@pytest.fixture
def patch_steps():
    """Steps that exercise the patch_vulnerability built-in actions."""
    return [
        {"name": "Scan packages", "action": "scan_packages", "params": {}},
        {"name": "Download patch", "action": "download_patch", "params": {}},
        {"name": "Run tests", "action": "run_tests", "params": {"environment": "staging"}},
        {"name": "Apply patch", "action": "apply_patch", "params": {"environment": "production"}},
        {"name": "Verify patch", "action": "verify_patch", "params": {}},
    ]


@pytest.fixture
def basic_playbook(engine, simple_steps):
    """A no-approval playbook with two noop steps."""
    return engine.create_playbook(
        name="Basic Playbook",
        type=PlaybookType.CUSTOM,
        steps=simple_steps,
        requires_approval=False,
        auto_rollback=False,
        org_id="org_test",
    )


@pytest.fixture
def approval_playbook(engine, simple_steps):
    """A playbook that requires approval before running."""
    return engine.create_playbook(
        name="Approval Playbook",
        type=PlaybookType.PATCH_VULNERABILITY,
        steps=simple_steps,
        requires_approval=True,
        auto_rollback=True,
        org_id="org_test",
    )


# ---------------------------------------------------------------------------
# Playbook CRUD
# ---------------------------------------------------------------------------


class TestPlaybookCRUD:
    def test_create_playbook_returns_model(self, engine, simple_steps):
        pb = engine.create_playbook(
            name="My Playbook",
            type=PlaybookType.BLOCK_IP,
            steps=simple_steps,
            org_id="org1",
        )
        assert isinstance(pb, RemediationPlaybook)
        assert pb.name == "My Playbook"
        assert pb.type == PlaybookType.BLOCK_IP
        assert len(pb.steps) == 2
        assert pb.org_id == "org1"

    def test_create_playbook_assigns_id(self, engine, simple_steps):
        pb = engine.create_playbook(
            name="ID Test", type=PlaybookType.CUSTOM, steps=simple_steps
        )
        assert pb.id is not None
        assert len(pb.id) > 0

    def test_get_playbook_by_id(self, engine, basic_playbook):
        fetched = engine.get_playbook(basic_playbook.id)
        assert fetched is not None
        assert fetched.id == basic_playbook.id
        assert fetched.name == basic_playbook.name

    def test_get_playbook_not_found(self, engine):
        result = engine.get_playbook("nonexistent-id")
        assert result is None

    def test_list_playbooks_no_filter(self, engine, simple_steps):
        engine.create_playbook(name="PB1", type=PlaybookType.CUSTOM, steps=simple_steps, org_id="orgA")
        engine.create_playbook(name="PB2", type=PlaybookType.BLOCK_IP, steps=simple_steps, org_id="orgB")
        all_pbs = engine.list_playbooks()
        assert len(all_pbs) >= 2

    def test_list_playbooks_filter_by_org(self, engine, simple_steps):
        engine.create_playbook(name="PB-A1", type=PlaybookType.CUSTOM, steps=simple_steps, org_id="orgA")
        engine.create_playbook(name="PB-A2", type=PlaybookType.CUSTOM, steps=simple_steps, org_id="orgA")
        engine.create_playbook(name="PB-B1", type=PlaybookType.CUSTOM, steps=simple_steps, org_id="orgB")
        orgA = engine.list_playbooks(org_id="orgA")
        assert all(p.org_id == "orgA" for p in orgA)
        assert len(orgA) == 2

    def test_list_playbooks_filter_by_type(self, engine, simple_steps):
        engine.create_playbook(name="IP1", type=PlaybookType.BLOCK_IP, steps=simple_steps)
        engine.create_playbook(name="IP2", type=PlaybookType.BLOCK_IP, steps=simple_steps)
        engine.create_playbook(name="Custom1", type=PlaybookType.CUSTOM, steps=simple_steps)
        ip_pbs = engine.list_playbooks(type_filter=PlaybookType.BLOCK_IP)
        assert all(p.type == PlaybookType.BLOCK_IP for p in ip_pbs)
        assert len(ip_pbs) >= 2

    def test_create_playbook_with_all_types(self, engine, simple_steps):
        for pb_type in PlaybookType:
            pb = engine.create_playbook(
                name=f"Test {pb_type.value}",
                type=pb_type,
                steps=simple_steps,
            )
            assert pb.type == pb_type

    def test_playbook_step_order_assigned(self, engine, simple_steps):
        pb = engine.create_playbook(name="Order Test", type=PlaybookType.CUSTOM, steps=simple_steps)
        orders = [s.order for s in pb.steps]
        assert orders == sorted(orders)

    def test_playbook_requires_approval_flag(self, engine, simple_steps):
        pb = engine.create_playbook(
            name="Needs Approval",
            type=PlaybookType.PATCH_VULNERABILITY,
            steps=simple_steps,
            requires_approval=True,
        )
        assert pb.requires_approval is True

    def test_playbook_target_finding_id(self, engine, simple_steps):
        pb = engine.create_playbook(
            name="Finding Linked",
            type=PlaybookType.CUSTOM,
            steps=simple_steps,
            target_finding_id="FINDING-123",
        )
        assert pb.target_finding_id == "FINDING-123"


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


class TestTemplates:
    def test_get_templates_returns_list(self, engine):
        templates = engine.get_playbook_templates()
        assert isinstance(templates, list)
        assert len(templates) == len(PlaybookType)

    def test_templates_cover_all_types(self, engine):
        templates = engine.get_playbook_templates()
        types_covered = {t["type"] for t in templates}
        all_types = {pt.value for pt in PlaybookType}
        assert types_covered == all_types

    def test_templates_have_required_keys(self, engine):
        for template in engine.get_playbook_templates():
            assert "type" in template
            assert "name" in template
            assert "description" in template
            assert "steps" in template
            assert isinstance(template["steps"], list)

    def test_patch_template_has_steps(self, engine):
        templates = engine.get_playbook_templates()
        patch = next(t for t in templates if t["type"] == PlaybookType.PATCH_VULNERABILITY.value)
        assert len(patch["steps"]) >= 3

    def test_block_ip_template_no_approval(self, engine):
        templates = engine.get_playbook_templates()
        block_ip = next(t for t in templates if t["type"] == PlaybookType.BLOCK_IP.value)
        assert block_ip["requires_approval"] is False


# ---------------------------------------------------------------------------
# Execution lifecycle — no approval
# ---------------------------------------------------------------------------


class TestExecutionNoApproval:
    def test_execute_runs_to_completion(self, engine, basic_playbook):
        execution = engine.execute_playbook(basic_playbook.id)
        assert execution.status == ExecutionStatus.COMPLETED

    def test_execution_steps_completed_count(self, engine, basic_playbook):
        execution = engine.execute_playbook(basic_playbook.id)
        assert execution.steps_completed == 2

    def test_execution_has_started_at(self, engine, basic_playbook):
        execution = engine.execute_playbook(basic_playbook.id)
        assert execution.started_at is not None

    def test_execution_has_completed_at(self, engine, basic_playbook):
        execution = engine.execute_playbook(basic_playbook.id)
        assert execution.completed_at is not None

    def test_execution_not_found_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.execute_playbook("no-such-id")

    def test_get_execution_by_id(self, engine, basic_playbook):
        ex = engine.execute_playbook(basic_playbook.id)
        fetched = engine.get_execution(ex.id)
        assert fetched is not None
        assert fetched.id == ex.id

    def test_get_execution_not_found(self, engine):
        result = engine.get_execution("nonexistent")
        assert result is None

    def test_execution_rollback_data_populated(self, engine, basic_playbook):
        execution = engine.execute_playbook(basic_playbook.id)
        assert isinstance(execution.rollback_data, dict)
        assert len(execution.rollback_data) > 0

    def test_list_executions(self, engine, basic_playbook):
        engine.execute_playbook(basic_playbook.id)
        engine.execute_playbook(basic_playbook.id)
        executions = engine.list_executions()
        assert len(executions) >= 2

    def test_list_executions_filter_by_org(self, engine, simple_steps):
        pb = engine.create_playbook(
            name="Org Filter", type=PlaybookType.CUSTOM, steps=simple_steps, org_id="org_xyz"
        )
        engine.execute_playbook(pb.id)
        results = engine.list_executions(org_id="org_xyz")
        assert all(e.org_id == "org_xyz" for e in results)

    def test_list_executions_filter_by_status(self, engine, basic_playbook):
        engine.execute_playbook(basic_playbook.id)
        completed = engine.list_executions(status_filter=ExecutionStatus.COMPLETED)
        assert all(e.status == ExecutionStatus.COMPLETED for e in completed)


# ---------------------------------------------------------------------------
# Approval gate
# ---------------------------------------------------------------------------


class TestApprovalGate:
    def test_execute_requires_approval_starts_awaiting(self, engine, approval_playbook):
        execution = engine.execute_playbook(approval_playbook.id)
        assert execution.status == ExecutionStatus.AWAITING_APPROVAL

    def test_execute_requires_approval_has_gate(self, engine, approval_playbook):
        execution = engine.execute_playbook(approval_playbook.id)
        assert execution.approval is not None

    def test_approve_execution_completes(self, engine, approval_playbook):
        execution = engine.execute_playbook(approval_playbook.id)
        engine.approve_execution(execution.id, approver_email="admin@example.com", comment="LGTM")
        updated = engine.get_execution(execution.id)
        assert updated.status == ExecutionStatus.COMPLETED

    def test_approve_execution_records_approver(self, engine, approval_playbook):
        execution = engine.execute_playbook(approval_playbook.id)
        engine.approve_execution(execution.id, approver_email="admin@example.com", comment="Approved")
        updated = engine.get_execution(execution.id)
        assert updated.approval.approver_email == "admin@example.com"
        assert updated.approval.comment == "Approved"
        assert updated.approval.approved_at is not None

    def test_approve_non_awaiting_raises(self, engine, basic_playbook):
        execution = engine.execute_playbook(basic_playbook.id)
        # Already completed — cannot approve
        with pytest.raises(ValueError):
            engine.approve_execution(execution.id, approver_email="x@example.com")

    def test_reject_execution_cancels(self, engine, approval_playbook):
        execution = engine.execute_playbook(approval_playbook.id)
        engine.reject_execution(execution.id, approver_email="mgr@example.com", reason="Not ready")
        updated = engine.get_execution(execution.id)
        assert updated.status == ExecutionStatus.CANCELLED

    def test_reject_execution_records_reason(self, engine, approval_playbook):
        execution = engine.execute_playbook(approval_playbook.id)
        engine.reject_execution(execution.id, approver_email="mgr@example.com", reason="Policy violation")
        updated = engine.get_execution(execution.id)
        assert updated.approval.rejected is True
        assert "Policy violation" in (updated.approval.rejected_reason or "")

    def test_reject_non_awaiting_raises(self, engine, basic_playbook):
        execution = engine.execute_playbook(basic_playbook.id)
        with pytest.raises(ValueError):
            engine.reject_execution(execution.id, approver_email="x@example.com")


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


class TestRollback:
    def test_rollback_completed_execution(self, engine, simple_steps):
        pb = engine.create_playbook(
            name="Rollback Test",
            type=PlaybookType.CUSTOM,
            steps=simple_steps,
            auto_rollback=False,  # manual rollback
        )
        execution = engine.execute_playbook(pb.id)
        assert execution.status == ExecutionStatus.COMPLETED

        engine.rollback_execution(execution.id)
        rolled = engine.get_execution(execution.id)
        assert rolled.status == ExecutionStatus.ROLLED_BACK

    def test_rollback_records_rollback_log(self, engine, simple_steps):
        pb = engine.create_playbook(
            name="Rollback Log Test", type=PlaybookType.CUSTOM, steps=simple_steps, auto_rollback=False
        )
        execution = engine.execute_playbook(pb.id)
        engine.rollback_execution(execution.id)
        rolled = engine.get_execution(execution.id)
        assert "rollback_log" in rolled.rollback_data

    def test_rollback_pending_raises(self, engine, approval_playbook):
        execution = engine.execute_playbook(approval_playbook.id)
        assert execution.status == ExecutionStatus.AWAITING_APPROVAL
        with pytest.raises(ValueError):
            engine.rollback_execution(execution.id)

    def test_rollback_cancelled_raises(self, engine, approval_playbook):
        execution = engine.execute_playbook(approval_playbook.id)
        engine.cancel_execution(execution.id)
        with pytest.raises(ValueError):
            engine.rollback_execution(execution.id)


# ---------------------------------------------------------------------------
# Cancel
# ---------------------------------------------------------------------------


class TestCancel:
    def test_cancel_awaiting_approval(self, engine, approval_playbook):
        execution = engine.execute_playbook(approval_playbook.id)
        engine.cancel_execution(execution.id)
        updated = engine.get_execution(execution.id)
        assert updated.status == ExecutionStatus.CANCELLED

    def test_cancel_sets_completed_at(self, engine, approval_playbook):
        execution = engine.execute_playbook(approval_playbook.id)
        engine.cancel_execution(execution.id)
        updated = engine.get_execution(execution.id)
        assert updated.completed_at is not None

    def test_cancel_completed_raises(self, engine, basic_playbook):
        execution = engine.execute_playbook(basic_playbook.id)
        assert execution.status == ExecutionStatus.COMPLETED
        with pytest.raises(ValueError):
            engine.cancel_execution(execution.id)

    def test_cancel_rolled_back_raises(self, engine, simple_steps):
        pb = engine.create_playbook(
            name="Cancel Rolled", type=PlaybookType.CUSTOM, steps=simple_steps, auto_rollback=False
        )
        execution = engine.execute_playbook(pb.id)
        engine.rollback_execution(execution.id)
        with pytest.raises(ValueError):
            engine.cancel_execution(execution.id)


# ---------------------------------------------------------------------------
# Step execution tracking
# ---------------------------------------------------------------------------


class TestStepTracking:
    def test_patch_steps_completed(self, engine, patch_steps):
        pb = engine.create_playbook(
            name="Patch Workflow",
            type=PlaybookType.PATCH_VULNERABILITY,
            steps=patch_steps,
            requires_approval=False,
            auto_rollback=False,
        )
        execution = engine.execute_playbook(pb.id)
        assert execution.status == ExecutionStatus.COMPLETED
        assert execution.steps_completed == len(patch_steps)

    def test_block_ip_steps(self, engine):
        steps = [
            {"name": "Lookup threat", "action": "threat_intel_lookup", "params": {}},
            {"name": "Block firewall", "action": "firewall_block", "params": {}},
            {"name": "Block WAF", "action": "waf_block", "params": {}},
        ]
        pb = engine.create_playbook(
            name="Block IP", type=PlaybookType.BLOCK_IP, steps=steps, requires_approval=False
        )
        execution = engine.execute_playbook(pb.id)
        assert execution.steps_completed == 3

    def test_unknown_action_simulates(self, engine):
        steps = [{"name": "Weird step", "action": "some_custom_unknown_action", "params": {"x": 1}}]
        pb = engine.create_playbook(name="Unknown", type=PlaybookType.CUSTOM, steps=steps)
        execution = engine.execute_playbook(pb.id)
        # Should still complete (unknown actions are simulated)
        assert execution.status == ExecutionStatus.COMPLETED

    def test_execution_total_steps(self, engine, patch_steps):
        pb = engine.create_playbook(
            name="Total Steps", type=PlaybookType.PATCH_VULNERABILITY, steps=patch_steps
        )
        execution = engine.execute_playbook(pb.id)
        assert execution.total_steps == len(patch_steps)
