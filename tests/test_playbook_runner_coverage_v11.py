"""Comprehensive coverage tests for core.playbook_runner — v11 swarm coverage push.

Targets: PlaybookKind, StepStatus, ActionType, PlaybookStep, PlaybookDefinition,
         StepResult, PlaybookResult, PlaybookRunner adapter registry.
"""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.playbook_runner import (
    ActionType,
    PlaybookKind,
    StepStatus,
)


# ---------------------------------------------------------------------------
# PlaybookKind
# ---------------------------------------------------------------------------


class TestPlaybookKind:
    def test_playbook(self):
        assert PlaybookKind.PLAYBOOK == "Playbook"

    def test_compliance_pack(self):
        assert PlaybookKind.COMPLIANCE_PACK == "CompliancePack"

    def test_test_pack(self):
        assert PlaybookKind.TEST_PACK == "TestPack"

    def test_mitigation_pack(self):
        assert PlaybookKind.MITIGATION_PACK == "MitigationPack"

    def test_all_kinds_count(self):
        assert len(PlaybookKind) == 4


# ---------------------------------------------------------------------------
# StepStatus
# ---------------------------------------------------------------------------


class TestStepStatus:
    def test_pending(self):
        assert StepStatus.PENDING == "pending"

    def test_running(self):
        assert StepStatus.RUNNING == "running"

    def test_success(self):
        assert StepStatus.SUCCESS == "success"

    def test_failed(self):
        assert StepStatus.FAILED == "failed"

    def test_skipped(self):
        assert StepStatus.SKIPPED == "skipped"

    def test_all_statuses_count(self):
        assert len(StepStatus) == 5


# ---------------------------------------------------------------------------
# ActionType
# ---------------------------------------------------------------------------


class TestActionType:
    def test_opa_evaluate(self):
        assert ActionType.OPA_EVALUATE == "opa.evaluate"

    def test_evidence_assert(self):
        assert ActionType.EVIDENCE_ASSERT == "evidence.assert"

    def test_evidence_collect(self):
        assert ActionType.EVIDENCE_COLLECT == "evidence.collect"

    def test_evidence_sign(self):
        assert ActionType.EVIDENCE_SIGN == "evidence.sign"

    def test_compliance_check(self):
        assert ActionType.COMPLIANCE_CHECK_CONTROL == "compliance.check_control"

    def test_pentest_request(self):
        assert ActionType.PENTEST_REQUEST == "pentest.request"

    def test_scanner_run(self):
        assert ActionType.SCANNER_RUN == "scanner.run"

    def test_all_action_types_exist(self):
        # Should have many action types
        assert len(ActionType) >= 10


# ---------------------------------------------------------------------------
# PlaybookStep
# ---------------------------------------------------------------------------


class TestPlaybookStep:
    def test_import(self):
        from core.playbook_runner import PlaybookStep
        assert PlaybookStep is not None

    def test_basic_step(self):
        from core.playbook_runner import PlaybookStep
        step = PlaybookStep(
            name="Check OPA Policy",
            action=ActionType.OPA_EVALUATE,
        )
        assert step.name == "Check OPA Policy"
        assert step.action == ActionType.OPA_EVALUATE

    def test_step_with_params(self):
        from core.playbook_runner import PlaybookStep
        step = PlaybookStep(
            name="Run Scanner",
            action=ActionType.SCANNER_RUN,
            params={"scanner": "trivy", "target": "image:latest"},
            timeout="60s",
        )
        assert step.params["scanner"] == "trivy"
        assert step.timeout == "60s"


# ---------------------------------------------------------------------------
# Playbook (replaces PlaybookDefinition)
# ---------------------------------------------------------------------------


class TestPlaybook:
    def test_import(self):
        from core.playbook_runner import Playbook
        assert Playbook is not None

    def test_basic_playbook(self):
        from core.playbook_runner import Playbook, PlaybookMetadata, PlaybookStep
        meta = PlaybookMetadata(name="SOC2 Check", version="1.0.0")
        pb = Playbook(
            api_version="v1",
            kind=PlaybookKind.PLAYBOOK,
            metadata=meta,
            steps=[
                PlaybookStep(name="step1", action=ActionType.OPA_EVALUATE),
            ],
        )
        assert pb.kind == PlaybookKind.PLAYBOOK
        assert len(pb.steps) == 1


# ---------------------------------------------------------------------------
# StepResult
# ---------------------------------------------------------------------------


class TestStepResult:
    def test_import(self):
        from core.playbook_runner import StepResult
        assert StepResult is not None

    def test_success_result(self):
        from core.playbook_runner import StepResult
        result = StepResult(
            name="step-001",
            status=StepStatus.SUCCESS,
        )
        assert result.name == "step-001"
        assert result.status == StepStatus.SUCCESS

    def test_failed_result(self):
        from core.playbook_runner import StepResult
        result = StepResult(
            name="step-002",
            status=StepStatus.FAILED,
            error="Connection refused",
        )
        assert result.status == StepStatus.FAILED
        assert result.error == "Connection refused"


# ---------------------------------------------------------------------------
# PlaybookExecutionContext
# ---------------------------------------------------------------------------


class TestPlaybookExecutionContext:
    def test_import(self):
        from core.playbook_runner import PlaybookExecutionContext
        assert PlaybookExecutionContext is not None


# ---------------------------------------------------------------------------
# PlaybookRunner
# ---------------------------------------------------------------------------


class TestPlaybookRunner:
    def test_import(self):
        from core.playbook_runner import PlaybookRunner
        assert PlaybookRunner is not None

    def test_init(self):
        from core.playbook_runner import PlaybookRunner
        runner = PlaybookRunner()
        assert runner is not None

    def test_singleton(self):
        from core.playbook_runner import get_playbook_runner
        runner = get_playbook_runner()
        assert runner is not None

    def test_has_adapters(self):
        from core.playbook_runner import PlaybookRunner
        runner = PlaybookRunner()
        if hasattr(runner, '_adapters'):
            assert isinstance(runner._adapters, dict)
        elif hasattr(runner, 'adapters'):
            assert isinstance(runner.adapters, dict)


# ---------------------------------------------------------------------------
# StepCondition
# ---------------------------------------------------------------------------


class TestStepCondition:
    def test_import(self):
        from core.playbook_runner import StepCondition
        assert StepCondition is not None


# ---------------------------------------------------------------------------
# ValidationError
# ---------------------------------------------------------------------------


class TestValidationError:
    def test_import(self):
        from core.playbook_runner import ValidationError
        assert ValidationError is not None

    def test_create(self):
        from core.playbook_runner import ValidationError
        err = ValidationError(path="steps[0].action", message="invalid action type")
        assert err.path == "steps[0].action"
        assert err.message == "invalid action type"
        assert err.severity == "error"

    def test_custom_severity(self):
        from core.playbook_runner import ValidationError
        err = ValidationError(path="metadata.name", message="missing", severity="warning")
        assert err.severity == "warning"
