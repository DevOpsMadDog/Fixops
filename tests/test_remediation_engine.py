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


# ===========================================================================
# RemediationPlanEngine — CWE-based plan generation, SLA, and fix verification
# ===========================================================================


@pytest.fixture
def plan_engine(tmp_path):
    """RemediationPlanEngine backed by a temporary SQLite database."""
    return RemediationPlanEngine(db_path=str(tmp_path / "plans.db"))


@pytest.fixture
def sql_finding():
    return {"id": "find-sql-01", "cwe_id": "CWE-89", "severity": "HIGH", "title": "SQL Injection"}


@pytest.fixture
def xss_finding():
    return {"id": "find-xss-01", "cwe_id": "CWE-79", "severity": "MEDIUM"}


@pytest.fixture
def hardcoded_finding():
    return {"id": "find-cred-01", "cwe_id": "CWE-798", "severity": "CRITICAL"}


class TestCreateRemediationPlan:
    def test_returns_remediation_plan(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        assert isinstance(plan, RemediationPlan)

    def test_plan_has_plan_id(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        assert plan.plan_id and len(plan.plan_id) > 0

    def test_plan_finding_id_matches(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        assert plan.finding_id == sql_finding["id"]

    def test_plan_cwe_id_set(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        assert plan.cwe_id == "CWE-89"

    def test_plan_has_steps(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        assert len(plan.steps) >= 3

    def test_plan_initial_state_identified(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        assert plan.state == PlanState.IDENTIFIED

    def test_plan_effort_set(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        assert isinstance(plan.effort, EffortLevel)

    def test_plan_auto_fixable_sql_injection(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        assert plan.auto_fixable is True

    def test_plan_references_nonempty(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        assert len(plan.references) >= 1

    def test_plan_sla_deadline_set(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        assert plan.sla_deadline is not None

    def test_plan_sla_high_72h(self, plan_engine, sql_finding):
        from datetime import timezone as tz
        from datetime import datetime as dt
        plan = plan_engine.create_remediation_plan(sql_finding)
        delta = plan.sla_deadline - dt.now(tz.utc)
        # Should be ~72h for HIGH severity (allow ±5 min)
        assert 71 <= delta.total_seconds() / 3600 <= 73

    def test_plan_critical_sla_24h(self, plan_engine, hardcoded_finding):
        from datetime import timezone as tz
        from datetime import datetime as dt
        plan = plan_engine.create_remediation_plan(hardcoded_finding)
        delta = plan.sla_deadline - dt.now(tz.utc)
        assert 23 <= delta.total_seconds() / 3600 <= 25

    def test_plan_unknown_cwe_fallback(self, plan_engine):
        plan = plan_engine.create_remediation_plan({"id": "f-unk", "cwe_id": "CWE-9999", "severity": "LOW"})
        assert plan.cwe_id == "CWE-9999"
        assert len(plan.steps) >= 1

    def test_plan_persisted_and_fetchable(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        fetched = plan_engine.get_plan(plan.plan_id)
        assert fetched is not None
        assert fetched.plan_id == plan.plan_id

    def test_list_plans_returns_created(self, plan_engine, sql_finding, xss_finding):
        plan_engine.create_remediation_plan(sql_finding)
        plan_engine.create_remediation_plan(xss_finding)
        plans = plan_engine.list_plans()
        assert len(plans) >= 2

    def test_list_plans_filter_by_finding(self, plan_engine, sql_finding, xss_finding):
        plan_engine.create_remediation_plan(sql_finding)
        plan_engine.create_remediation_plan(xss_finding)
        plans = plan_engine.list_plans(finding_id=sql_finding["id"])
        assert all(p.finding_id == sql_finding["id"] for p in plans)


class TestSuggestCodeFix:
    def test_returns_code_fix(self, plan_engine, sql_finding):
        fix = plan_engine.suggest_code_fix(sql_finding)
        assert isinstance(fix, CodeFix)

    def test_fix_has_description(self, plan_engine, sql_finding):
        fix = plan_engine.suggest_code_fix(sql_finding)
        assert len(fix.description) > 0

    def test_fix_has_after_snippet(self, plan_engine, sql_finding):
        fix = plan_engine.suggest_code_fix(sql_finding)
        assert len(fix.after_snippet) > 0

    def test_fix_uses_provided_code_snippet_as_before(self, plan_engine, sql_finding):
        snippet = "query = 'SELECT * FROM users WHERE id=' + uid"
        fix = plan_engine.suggest_code_fix(sql_finding, code_snippet=snippet)
        assert fix.before_snippet == snippet

    def test_fix_confidence_high_for_known_cwe(self, plan_engine, sql_finding):
        fix = plan_engine.suggest_code_fix(sql_finding)
        assert fix.confidence >= 0.8

    def test_fix_confidence_lower_for_unknown_cwe(self, plan_engine):
        fix = plan_engine.suggest_code_fix({"id": "f-unk", "cwe_id": "CWE-9999"})
        assert fix.confidence < 0.8

    def test_fix_finding_id_set(self, plan_engine, sql_finding):
        fix = plan_engine.suggest_code_fix(sql_finding)
        assert fix.finding_id == sql_finding["id"]

    def test_fix_cwe_id_set(self, plan_engine, xss_finding):
        fix = plan_engine.suggest_code_fix(xss_finding)
        assert fix.cwe_id == "CWE-79"

    def test_fix_xss_mentions_encoding(self, plan_engine, xss_finding):
        fix = plan_engine.suggest_code_fix(xss_finding)
        combined = fix.description + fix.after_snippet
        assert any(kw in combined.lower() for kw in ("escap", "encod", "markup"))


class TestRemediationStateTracking:
    def test_update_state_identified_to_planned(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        updated = plan_engine.update_state(plan.plan_id, PlanState.PLANNED)
        assert updated.state == PlanState.PLANNED

    def test_full_state_progression(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        for state in (PlanState.PLANNED, PlanState.IN_PROGRESS, PlanState.FIXED, PlanState.VERIFIED):
            plan = plan_engine.update_state(plan.plan_id, state)
        assert plan.state == PlanState.VERIFIED

    def test_invalid_transition_raises(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        with pytest.raises(ValueError, match="Invalid transition"):
            plan_engine.update_state(plan.plan_id, PlanState.VERIFIED)

    def test_skip_state_raises(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        with pytest.raises(ValueError):
            plan_engine.update_state(plan.plan_id, PlanState.IN_PROGRESS)

    def test_update_state_not_found_raises(self, plan_engine):
        with pytest.raises(ValueError, match="not found"):
            plan_engine.update_state("nonexistent-plan-id", PlanState.PLANNED)

    def test_track_remediation_returns_plan(self, plan_engine, sql_finding):
        plan = plan_engine.create_remediation_plan(sql_finding)
        tracked = plan_engine.track_remediation(sql_finding["id"], plan.plan_id)
        assert tracked.plan_id == plan.plan_id

    def test_track_remediation_not_found_raises(self, plan_engine, sql_finding):
        with pytest.raises(ValueError, match="not found"):
            plan_engine.track_remediation(sql_finding["id"], "bad-plan-id")

    def test_list_plans_filter_by_state(self, plan_engine, sql_finding, xss_finding):
        p1 = plan_engine.create_remediation_plan(sql_finding)
        plan_engine.create_remediation_plan(xss_finding)
        plan_engine.update_state(p1.plan_id, PlanState.PLANNED)
        planned = plan_engine.list_plans(state_filter=PlanState.PLANNED)
        assert all(p.state == PlanState.PLANNED for p in planned)


class TestVerifyFix:
    def test_verify_fix_not_in_results(self, plan_engine):
        assert plan_engine.verify_fix("find-001", [{"id": "find-002"}, {"id": "find-003"}]) is True

    def test_verify_fix_still_in_results(self, plan_engine):
        assert plan_engine.verify_fix("find-001", [{"id": "find-001"}]) is False

    def test_verify_fix_empty_results(self, plan_engine):
        assert plan_engine.verify_fix("find-001", []) is True

    def test_verify_fix_multiple_results_contains(self, plan_engine):
        results = [{"id": "find-x"}, {"id": "find-001"}, {"id": "find-y"}]
        assert plan_engine.verify_fix("find-001", results) is False


class TestSLACalculation:
    def test_sla_critical_24h(self, plan_engine):
        sla = plan_engine.calculate_remediation_sla("CRITICAL")
        assert sla.total_seconds() == 24 * 3600

    def test_sla_high_72h(self, plan_engine):
        sla = plan_engine.calculate_remediation_sla("HIGH")
        assert sla.total_seconds() == 72 * 3600

    def test_sla_medium_7d(self, plan_engine):
        sla = plan_engine.calculate_remediation_sla("MEDIUM")
        assert sla.total_seconds() == 7 * 24 * 3600

    def test_sla_low_30d(self, plan_engine):
        sla = plan_engine.calculate_remediation_sla("LOW")
        assert sla.total_seconds() == 30 * 24 * 3600

    def test_sla_case_insensitive(self, plan_engine):
        assert plan_engine.calculate_remediation_sla("critical") == plan_engine.calculate_remediation_sla("CRITICAL")

    def test_sla_unknown_falls_back_to_medium(self, plan_engine):
        sla = plan_engine.calculate_remediation_sla("UNKNOWN")
        assert sla.total_seconds() == 7 * 24 * 3600


class TestCWETemplates:
    def test_list_templates_returns_all_seven(self, plan_engine):
        templates = plan_engine.list_cwe_templates()
        assert len(templates) == 7

    def test_templates_have_required_keys(self, plan_engine):
        for t in plan_engine.list_cwe_templates():
            assert "cwe_id" in t
            assert "name" in t
            assert "effort" in t
            assert "auto_fixable" in t
            assert "step_count" in t
            assert "references" in t

    def test_sql_injection_template_present(self, plan_engine):
        templates = plan_engine.list_cwe_templates()
        ids = [t["cwe_id"] for t in templates]
        assert "CWE-89" in ids

    def test_missing_auth_not_auto_fixable(self, plan_engine):
        templates = plan_engine.list_cwe_templates()
        auth = next(t for t in templates if t["cwe_id"] == "CWE-306")
        assert auth["auto_fixable"] is False

    def test_hardcoded_creds_auto_fixable(self, plan_engine):
        templates = plan_engine.list_cwe_templates()
        creds = next(t for t in templates if t["cwe_id"] == "CWE-798")
        assert creds["auto_fixable"] is True
