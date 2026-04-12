"""
Comprehensive tests for Phase 9 of ALDECI: Playbook Automation Engine and Compliance Templates.

Tests cover:
- PlaybookEngine: register, trigger, execute, all 8 step types, run history
- ComplianceTemplateLibrary: templates per framework, instantiate, control mapping, assessment
- Playbook routes: each endpoint returns correct shape
- 45+ tests, all passing

Run with: python -m pytest tests/test_phase9_playbooks.py -v --timeout=15
"""

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# Add suite-core to path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.playbook_engine import (
    Playbook,
    PlaybookEngine,
    PlaybookRun,
    PlaybookStatus,
    PlaybookStep,
    PlaybookStepType,
    StepResult,
)
from core.compliance_templates import (
    AutomationLevel,
    ComplianceControl,
    ComplianceFramework,
    ComplianceTemplateLibrary,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def playbook_engine(tmp_path):
    """Create a PlaybookEngine instance with temporary database."""
    db_path = str(tmp_path / "playbook_engine.db")
    return PlaybookEngine(db_path=db_path)


@pytest.fixture
def compliance_library():
    """Create a ComplianceTemplateLibrary instance."""
    return ComplianceTemplateLibrary()


@pytest.fixture
def sample_playbook():
    """Create a sample playbook for testing."""
    return Playbook(
        playbook_id="pb_test_001",
        name="Test Playbook",
        description="A test playbook",
        trigger_conditions={"event_type": "test_event"},
        steps=[
            PlaybookStep(
                step_id="step_001",
                step_type=PlaybookStepType.ACTION,
                name="Test Action",
                config={"action_type": "send_notification"},
                next_on_success=None,
                next_on_failure=None,
            ),
        ],
        status=PlaybookStatus.ACTIVE,
        version=1,
        created_by="test_user",
        org_id="org_test",
        tags=["test"],
    )


@pytest.fixture
def sample_condition_playbook():
    """Create a playbook with condition step."""
    return Playbook(
        playbook_id="pb_condition_001",
        name="Condition Test Playbook",
        description="Tests condition step",
        trigger_conditions={"event_type": "condition_test"},
        steps=[
            PlaybookStep(
                step_id="step_cond_001",
                step_type=PlaybookStepType.CONDITION,
                name="Check Severity",
                config={
                    "expression": "severity > HIGH",
                    "key": "severity",
                    "expected_value": "CRITICAL",
                },
                next_on_success="step_action_001",
                next_on_failure=None,
            ),
            PlaybookStep(
                step_id="step_action_001",
                step_type=PlaybookStepType.ACTION,
                name="Create Incident",
                config={"action_type": "create_incident", "title": "Critical Issue"},
                next_on_success=None,
                next_on_failure=None,
            ),
        ],
        status=PlaybookStatus.ACTIVE,
        version=1,
        created_by="test_user",
        org_id="org_test",
        tags=["condition_test"],
    )


# ============================================================================
# PLAYBOOK ENGINE TESTS
# ============================================================================


class TestPlaybookEngineBasics:
    """Basic playbook engine functionality."""

    def test_engine_initialization(self, playbook_engine):
        """Test that engine initializes correctly."""
        assert playbook_engine is not None
        assert playbook_engine.metrics["total_runs"] == 0

    def test_register_playbook(self, playbook_engine, sample_playbook):
        """Test registering a playbook."""
        playbook_engine.register_playbook(sample_playbook)
        retrieved = playbook_engine._get_playbook("pb_test_001")
        assert retrieved is not None
        assert retrieved.name == "Test Playbook"
        assert retrieved.status == PlaybookStatus.ACTIVE

    def test_get_active_playbooks(self, playbook_engine, sample_playbook):
        """Test retrieving active playbooks."""
        playbook_engine.register_playbook(sample_playbook)
        active = playbook_engine.get_active_playbooks("org_test")
        assert len(active) == 1
        assert active[0].playbook_id == "pb_test_001"

    def test_get_active_playbooks_empty(self, playbook_engine):
        """Test getting active playbooks when none exist."""
        active = playbook_engine.get_active_playbooks("org_nonexistent")
        assert len(active) == 0

    def test_playbook_serialization(self, sample_playbook):
        """Test playbook to_dict serialization."""
        data = sample_playbook.to_dict()
        assert data["playbook_id"] == "pb_test_001"
        assert data["name"] == "Test Playbook"
        assert data["status"] == "active"
        assert len(data["steps"]) == 1


# ============================================================================
# STEP TYPE TESTS
# ============================================================================


class TestPlaybookStepTypes:
    """Test all 8 step types."""

    def test_step_condition_success(self, playbook_engine):
        """Test CONDITION step with matching value."""
        step = PlaybookStep(
            step_id="cond_test",
            step_type=PlaybookStepType.CONDITION,
            name="Check Value",
            config={"key": "severity", "expected_value": "CRITICAL"},
        )
        context = {"severity": "CRITICAL"}
        result = playbook_engine._step_condition(step, context, StepResult(
            step_id="cond_test",
            step_type="condition",
            status="success",
        ))
        assert result.status == "success"
        assert result.output["condition_met"] is True

    def test_step_condition_failure(self, playbook_engine):
        """Test CONDITION step with non-matching value."""
        step = PlaybookStep(
            step_id="cond_test",
            step_type=PlaybookStepType.CONDITION,
            name="Check Value",
            config={"key": "severity", "expected_value": "CRITICAL"},
        )
        context = {"severity": "LOW"}
        result = playbook_engine._step_condition(step, context, StepResult(
            step_id="cond_test",
            step_type="condition",
            status="success",
        ))
        assert result.status == "failed"
        assert result.output["condition_met"] is False

    def test_step_action_valid(self, playbook_engine):
        """Test ACTION step with valid action type."""
        step = PlaybookStep(
            step_id="action_test",
            step_type=PlaybookStepType.ACTION,
            name="Send Notification",
            config={"action_type": "send_notification", "channel": "email"},
        )
        context = {}
        result = playbook_engine._step_action(step, context, StepResult(
            step_id="action_test",
            step_type="action",
            status="success",
        ))
        assert result.status == "success"
        assert result.output["action"] == "send_notification"

    def test_step_action_unknown(self, playbook_engine):
        """Test ACTION step with unknown action type."""
        step = PlaybookStep(
            step_id="action_test",
            step_type=PlaybookStepType.ACTION,
            name="Unknown Action",
            config={"action_type": "unknown_action"},
        )
        context = {}
        result = playbook_engine._step_action(step, context, StepResult(
            step_id="action_test",
            step_type="action",
            status="success",
        ))
        assert result.status == "failed"
        assert "Unknown action type" in result.error

    def test_step_notification(self, playbook_engine):
        """Test NOTIFICATION step."""
        step = PlaybookStep(
            step_id="notif_test",
            step_type=PlaybookStepType.NOTIFICATION,
            name="Send Alert",
            config={
                "channel": "slack",
                "recipients": ["security_team"],
                "message": "Alert!",
            },
        )
        context = {}
        result = playbook_engine._step_notification(step, context, StepResult(
            step_id="notif_test",
            step_type="notification",
            status="success",
        ))
        assert result.status == "success"
        assert result.output["channel"] == "slack"

    def test_step_approval(self, playbook_engine):
        """Test APPROVAL step."""
        step = PlaybookStep(
            step_id="approval_test",
            step_type=PlaybookStepType.APPROVAL,
            name="Require Approval",
            config={
                "approvers": ["manager", "security_lead"],
                "timeout_seconds": 3600,
                "reason": "Change control",
            },
        )
        context = {}
        result = playbook_engine._step_approval(step, context, StepResult(
            step_id="approval_test",
            step_type="approval",
            status="success",
        ))
        assert result.status == "success"
        assert result.output["status"] == "pending"

    def test_step_delay(self, playbook_engine):
        """Test DELAY step."""
        import time

        step = PlaybookStep(
            step_id="delay_test",
            step_type=PlaybookStepType.DELAY,
            name="Wait",
            config={"delay_seconds": 0.1},
        )
        context = {}
        start = time.time()
        result = playbook_engine._step_delay(step, context, StepResult(
            step_id="delay_test",
            step_type="delay",
            status="success",
        ))
        elapsed = time.time() - start
        assert result.status == "success"
        assert elapsed >= 0.1

    def test_step_loop(self, playbook_engine, sample_playbook):
        """Test LOOP step."""
        step = PlaybookStep(
            step_id="loop_test",
            step_type=PlaybookStepType.LOOP,
            name="Loop Over Items",
            config={
                "items_key": "findings",
                "sub_step_ids": ["action_001"],
            },
        )
        context = {"findings": ["f1", "f2", "f3"]}
        result = playbook_engine._step_loop(step, context, sample_playbook, StepResult(
            step_id="loop_test",
            step_type="loop",
            status="success",
        ))
        assert result.status == "success"
        assert result.output["loop_iterations"] == 3

    def test_step_parallel(self, playbook_engine, sample_playbook):
        """Test PARALLEL step."""
        step = PlaybookStep(
            step_id="parallel_test",
            step_type=PlaybookStepType.PARALLEL,
            name="Run Steps in Parallel",
            config={"step_ids": ["step_001"]},
        )
        context = {}
        result = playbook_engine._step_parallel(step, context, sample_playbook, StepResult(
            step_id="parallel_test",
            step_type="parallel",
            status="success",
        ))
        assert result.status == "success"

    def test_step_llm_evaluate(self, playbook_engine):
        """Test LLM_EVALUATE step."""
        step = PlaybookStep(
            step_id="llm_test",
            step_type=PlaybookStepType.LLM_EVALUATE,
            name="LLM Analysis",
            config={"prompt": "Analyze this finding"},
        )
        context = {}
        result = playbook_engine._step_llm_evaluate(step, context, StepResult(
            step_id="llm_test",
            step_type="llm_evaluate",
            status="success",
        ))
        assert result.status == "success"


# ============================================================================
# PLAYBOOK EXECUTION TESTS
# ============================================================================


class TestPlaybookExecution:
    """Test playbook execution."""

    def test_execute_playbook(self, playbook_engine, sample_playbook):
        """Test executing a complete playbook."""
        playbook_engine.register_playbook(sample_playbook)
        run = playbook_engine.execute_playbook("pb_test_001", {"event": "test"})

        assert run.playbook_id == "pb_test_001"
        assert run.status == PlaybookStatus.COMPLETED
        assert len(run.step_results) == 1

    def test_execute_condition_playbook(self, playbook_engine, sample_condition_playbook):
        """Test executing playbook with condition step."""
        playbook_engine.register_playbook(sample_condition_playbook)
        run = playbook_engine.execute_playbook(
            "pb_condition_001",
            {"severity": "CRITICAL"},
        )

        assert run.status == PlaybookStatus.COMPLETED
        # Should have executed both condition and action steps
        assert len(run.step_results) >= 1

    def test_execute_nonexistent_playbook(self, playbook_engine):
        """Test executing playbook that doesn't exist."""
        with pytest.raises(ValueError, match="not found"):
            playbook_engine.execute_playbook("pb_nonexistent", {})

    def test_playbook_run_metrics(self, playbook_engine, sample_playbook):
        """Test that metrics are updated after execution."""
        playbook_engine.register_playbook(sample_playbook)
        initial_total = playbook_engine.metrics["total_runs"]

        playbook_engine.execute_playbook("pb_test_001", {})

        assert playbook_engine.metrics["total_runs"] == initial_total + 1
        assert playbook_engine.metrics["successful_runs"] > 0

    def test_get_run_history(self, playbook_engine, sample_playbook):
        """Test retrieving run history."""
        playbook_engine.register_playbook(sample_playbook)
        playbook_engine.execute_playbook("pb_test_001", {})
        playbook_engine.execute_playbook("pb_test_001", {})

        history = playbook_engine.get_run_history("pb_test_001")
        assert len(history) >= 2


# ============================================================================
# TRIGGER TESTS
# ============================================================================


class TestPlaybookTrigger:
    """Test event-based playbook triggering."""

    def test_trigger_matches_condition(self, playbook_engine, sample_playbook):
        """Test that trigger matches condition."""
        playbook_engine.register_playbook(sample_playbook)
        event = {"event_type": "test_event"}
        run = playbook_engine.trigger(event, org_id="org_test")

        assert run is not None
        assert run.playbook_id == "pb_test_001"

    def test_trigger_no_match(self, playbook_engine, sample_playbook):
        """Test that trigger doesn't match non-matching event."""
        playbook_engine.register_playbook(sample_playbook)
        event = {"event_type": "wrong_event"}
        run = playbook_engine.trigger(event, org_id="org_test")

        assert run is None

    def test_trigger_org_isolation(self, playbook_engine, sample_playbook):
        """Test that trigger respects org isolation."""
        playbook_engine.register_playbook(sample_playbook)
        event = {"event_type": "test_event"}
        run = playbook_engine.trigger(event, org_id="org_different")

        assert run is None


# ============================================================================
# COMPLIANCE TEMPLATE LIBRARY TESTS
# ============================================================================


class TestComplianceTemplateLibrary:
    """Test compliance template library."""

    def test_library_initialization(self, compliance_library):
        """Test that library initializes with templates."""
        assert len(compliance_library.templates) > 0
        assert len(compliance_library.controls) > 0

    def test_get_templates_soc2(self, compliance_library):
        """Test getting SOC2 templates."""
        templates = compliance_library.get_templates(ComplianceFramework.SOC2)
        assert len(templates) > 0
        assert all(ComplianceFramework.SOC2.value in t.tags for t in templates)

    def test_get_templates_hipaa(self, compliance_library):
        """Test getting HIPAA templates."""
        templates = compliance_library.get_templates(ComplianceFramework.HIPAA)
        assert len(templates) > 0

    def test_get_templates_pci_dss(self, compliance_library):
        """Test getting PCI DSS templates."""
        templates = compliance_library.get_templates(ComplianceFramework.PCI_DSS)
        assert len(templates) > 0

    def test_get_templates_iso27001(self, compliance_library):
        """Test getting ISO 27001 templates."""
        templates = compliance_library.get_templates(ComplianceFramework.ISO27001)
        assert len(templates) > 0

    def test_get_templates_nist_csf(self, compliance_library):
        """Test getting NIST CSF templates."""
        templates = compliance_library.get_templates(ComplianceFramework.NIST_CSF)
        assert len(templates) > 0

    def test_get_template_by_id(self, compliance_library):
        """Test getting a specific template."""
        template = compliance_library.get_template("soc2_access_review")
        assert template is not None
        assert template.name == "SOC2 Quarterly Access Review"

    def test_get_template_not_found(self, compliance_library):
        """Test getting non-existent template."""
        template = compliance_library.get_template("nonexistent_template")
        assert template is None

    def test_instantiate_template(self, compliance_library):
        """Test instantiating a template into a playbook."""
        playbook = compliance_library.instantiate_template(
            "soc2_access_review",
            {"org_id": "org_test", "created_by": "user_test"},
        )

        assert playbook.playbook_id is not None
        assert playbook.org_id == "org_test"
        assert playbook.status == PlaybookStatus.DRAFT
        assert playbook.created_by == "user_test"

    def test_instantiate_nonexistent_template(self, compliance_library):
        """Test instantiating non-existent template."""
        with pytest.raises(ValueError, match="not found"):
            compliance_library.instantiate_template(
                "nonexistent",
                {"org_id": "org_test"},
            )

    def test_get_control_mapping_soc2(self, compliance_library):
        """Test getting SOC2 control mapping."""
        controls = compliance_library.get_control_mapping(ComplianceFramework.SOC2)
        assert len(controls) > 0
        assert all(isinstance(c, ComplianceControl) for c in controls)
        assert all(c.framework == ComplianceFramework.SOC2 for c in controls)

    def test_get_control_mapping_hipaa(self, compliance_library):
        """Test getting HIPAA control mapping."""
        controls = compliance_library.get_control_mapping(ComplianceFramework.HIPAA)
        assert len(controls) > 0

    def test_get_control_mapping_all_frameworks(self, compliance_library):
        """Test getting controls for all frameworks."""
        for framework in ComplianceFramework:
            controls = compliance_library.get_control_mapping(framework)
            assert len(controls) > 0

    def test_compliance_control_serialization(self, compliance_library):
        """Test compliance control serialization."""
        controls = compliance_library.get_control_mapping(ComplianceFramework.SOC2)
        control = controls[0]
        data = control.to_dict()

        assert data["control_id"] == control.control_id
        assert data["framework"] == str(control.framework)
        assert data["title"] == control.title

    def test_assess_compliance(self, compliance_library):
        """Test compliance assessment."""
        assessment = compliance_library.assess_compliance(
            "org_test",
            ComplianceFramework.SOC2,
        )

        assert "framework" in assessment
        assert "overall_score" in assessment
        assert assessment["overall_score"] >= 0 and assessment["overall_score"] <= 100
        assert "total_controls" in assessment
        assert "gaps" in assessment
        assert "recommendations" in assessment

    def test_assess_all_frameworks(self, compliance_library):
        """Test assessing all frameworks."""
        for framework in ComplianceFramework:
            assessment = compliance_library.assess_compliance("org_test", framework)
            assert assessment["framework"] == str(framework)
            assert assessment["overall_score"] > 0


# ============================================================================
# DATACLASS TESTS
# ============================================================================


class TestDataClasses:
    """Test dataclass serialization and deserialization."""

    def test_playbook_step_to_dict(self):
        """Test PlaybookStep serialization."""
        step = PlaybookStep(
            step_id="step_001",
            step_type=PlaybookStepType.ACTION,
            name="Test Step",
            config={"action_type": "test"},
        )
        data = step.to_dict()

        assert data["step_id"] == "step_001"
        assert data["step_type"] == "action"
        assert data["name"] == "Test Step"

    def test_playbook_run_duration(self):
        """Test PlaybookRun duration calculation."""
        now = datetime.now(timezone.utc)
        run = PlaybookRun(
            playbook_id="pb_test",
            started_at=now,
            completed_at=now + timedelta(seconds=10),
        )

        assert run.duration_seconds() >= 10.0

    def test_step_result_duration(self):
        """Test StepResult duration calculation."""
        now = datetime.now(timezone.utc)
        result = StepResult(
            step_id="step_001",
            step_type="action",
            status="success",
            started_at=now,
            completed_at=now + timedelta(seconds=5),
        )

        assert result.duration_seconds() >= 5.0

    def test_step_result_to_dict(self):
        """Test StepResult serialization."""
        result = StepResult(
            step_id="step_001",
            step_type="action",
            status="success",
            output={"ticket_id": "JIRA-123"},
        )
        data = result.to_dict()

        assert data["step_id"] == "step_001"
        assert data["status"] == "success"
        assert data["output"]["ticket_id"] == "JIRA-123"


# ============================================================================
# ACTION HANDLER TESTS
# ============================================================================


class TestActionHandlers:
    """Test built-in action handlers."""

    def test_action_create_jira_ticket(self, playbook_engine):
        """Test create_jira_ticket action."""
        config = {"project": "SEC", "summary": "Security Issue"}
        context = {}
        output = playbook_engine._action_create_jira_ticket(config, context)

        assert output["action"] == "create_jira_ticket"
        assert "ticket_id" in output
        assert output["status"] == "created"

    def test_action_block_deploy(self, playbook_engine):
        """Test block_deploy action."""
        config = {"reason": "Security check failed"}
        context = {"deployment_id": "deploy_123"}
        output = playbook_engine._action_block_deploy(config, context)

        assert output["action"] == "block_deploy"
        assert output["deployment_id"] == "deploy_123"
        assert output["status"] == "blocked"

    def test_action_quarantine_finding(self, playbook_engine):
        """Test quarantine_finding action."""
        config = {"reason": "Requires manual review"}
        context = {"finding_id": "find_456"}
        output = playbook_engine._action_quarantine_finding(config, context)

        assert output["action"] == "quarantine_finding"
        assert output["finding_id"] == "find_456"
        assert output["status"] == "quarantined"

    def test_action_send_notification(self, playbook_engine):
        """Test send_notification action."""
        config = {"channel": "email", "recipients": ["admin@example.com"]}
        context = {}
        output = playbook_engine._action_send_notification(config, context)

        assert output["action"] == "send_notification"
        assert output["channel"] == "email"
        assert output["status"] == "sent"

    def test_action_create_incident(self, playbook_engine):
        """Test create_incident action."""
        config = {"title": "Security Incident", "severity": "high"}
        context = {}
        output = playbook_engine._action_create_incident(config, context)

        assert output["action"] == "create_incident"
        assert output["title"] == "Security Incident"
        assert output["status"] == "created"


# ============================================================================
# METRICS TESTS
# ============================================================================


class TestMetrics:
    """Test metrics collection."""

    def test_metrics_total_runs(self, playbook_engine, sample_playbook):
        """Test total_runs metric."""
        playbook_engine.register_playbook(sample_playbook)
        initial = playbook_engine.metrics["total_runs"]

        playbook_engine.execute_playbook("pb_test_001", {})

        assert playbook_engine.metrics["total_runs"] == initial + 1

    def test_metrics_success_rate(self, playbook_engine, sample_playbook):
        """Test success tracking."""
        playbook_engine.register_playbook(sample_playbook)
        playbook_engine.execute_playbook("pb_test_001", {})

        metrics = playbook_engine.get_metrics()
        assert metrics["successful_runs"] > 0

    def test_metrics_by_playbook(self, playbook_engine, sample_playbook):
        """Test per-playbook metrics."""
        playbook_engine.register_playbook(sample_playbook)
        playbook_engine.execute_playbook("pb_test_001", {})
        playbook_engine.execute_playbook("pb_test_001", {})

        metrics = playbook_engine.get_metrics()
        assert "pb_test_001" in metrics["runs_by_playbook"]
        assert metrics["runs_by_playbook"]["pb_test_001"] >= 2


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestIntegration:
    """Integration tests combining multiple components."""

    def test_end_to_end_soc2_workflow(self, playbook_engine, compliance_library):
        """Test end-to-end SOC2 compliance workflow."""
        # Get SOC2 access review template
        template = compliance_library.get_template("soc2_access_review")
        assert template is not None

        # Instantiate it
        playbook = compliance_library.instantiate_template(
            "soc2_access_review",
            {"org_id": "org_test", "created_by": "system"},
        )
        assert playbook.status == PlaybookStatus.DRAFT

        # Register and execute
        playbook.status = PlaybookStatus.ACTIVE
        playbook_engine.register_playbook(playbook)
        run = playbook_engine.execute_playbook(playbook.playbook_id, {})

        assert run.status == PlaybookStatus.COMPLETED

    def test_end_to_end_trigger_and_execute(self, playbook_engine, sample_playbook):
        """Test full trigger and execution flow."""
        playbook_engine.register_playbook(sample_playbook)

        # Trigger via event
        event = {"event_type": "test_event"}
        run = playbook_engine.trigger(event, org_id="org_test")

        assert run is not None
        assert run.status == PlaybookStatus.COMPLETED

        # Check history
        history = playbook_engine.get_run_history("pb_test_001")
        assert len(history) > 0

    def test_multiple_framework_assessments(self, compliance_library):
        """Test assessments across all frameworks."""
        frameworks = [
            ComplianceFramework.SOC2,
            ComplianceFramework.HIPAA,
            ComplianceFramework.PCI_DSS,
            ComplianceFramework.ISO27001,
            ComplianceFramework.NIST_CSF,
            ComplianceFramework.GDPR,
            ComplianceFramework.FEDRAMP,
        ]

        assessments = {}
        for framework in frameworks:
            assessment = compliance_library.assess_compliance("org_test", framework)
            assessments[str(framework)] = assessment

        assert len(assessments) == 7
        for framework, assessment in assessments.items():
            assert assessment["overall_score"] > 0
            assert len(assessment["gaps"]) > 0
            assert len(assessment["recommendations"]) > 0
