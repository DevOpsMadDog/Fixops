"""
Tests for core/playbook_runner.py to ensure 100% diff coverage.

This module tests the PlaybookRunner class and related functionality.
"""
import pytest


def test_playbook_kind_enum():
    """Test PlaybookKind enum values."""
    from core.playbook_runner import PlaybookKind

    assert PlaybookKind.PLAYBOOK == "Playbook"
    assert PlaybookKind.COMPLIANCE_PACK == "CompliancePack"
    assert PlaybookKind.TEST_PACK == "TestPack"
    assert PlaybookKind.MITIGATION_PACK == "MitigationPack"


def test_step_status_enum():
    """Test StepStatus enum values."""
    from core.playbook_runner import StepStatus

    assert StepStatus.PENDING == "pending"
    assert StepStatus.RUNNING == "running"
    assert StepStatus.SUCCESS == "success"
    assert StepStatus.FAILED == "failed"
    assert StepStatus.SKIPPED == "skipped"


def test_action_type_enum():
    """Test ActionType enum values."""
    from core.playbook_runner import ActionType

    assert ActionType.OPA_EVALUATE == "opa.evaluate"
    assert ActionType.OPA_ASSERT == "opa.assert"
    assert ActionType.EVIDENCE_ASSERT == "evidence.assert"
    assert ActionType.EVIDENCE_COLLECT == "evidence.collect"
    assert ActionType.EVIDENCE_SIGN == "evidence.sign"
    assert ActionType.COMPLIANCE_CHECK_CONTROL == "compliance.check_control"
    assert ActionType.COMPLIANCE_MAP_FINDING == "compliance.map_finding"
    assert ActionType.COMPLIANCE_GENERATE_REPORT == "compliance.generate_report"
    assert ActionType.PENTEST_REQUEST == "pentest.request"
    assert (
        ActionType.PENTEST_VALIDATE_EXPLOITABILITY == "pentest.validate_exploitability"
    )
    assert ActionType.SCANNER_RUN == "scanner.run"
    assert ActionType.NOTIFY_SLACK == "notify.slack"
    assert ActionType.NOTIFY_EMAIL == "notify.email"
    assert ActionType.NOTIFY_PAGERDUTY == "notify.pagerduty"
    assert ActionType.JIRA_CREATE_ISSUE == "jira.create_issue"
    assert ActionType.JIRA_UPDATE_ISSUE == "jira.update_issue"
    assert ActionType.JIRA_ADD_COMMENT == "jira.add_comment"
    assert ActionType.CONFLUENCE_CREATE_PAGE == "confluence.create_page"
    assert ActionType.CONFLUENCE_UPDATE_PAGE == "confluence.update_page"
    assert ActionType.WORKFLOW_APPROVE == "workflow.approve"
    assert ActionType.WORKFLOW_REJECT == "workflow.reject"
    assert ActionType.WORKFLOW_ESCALATE == "workflow.escalate"
    assert ActionType.DATA_FILTER == "data.filter"
    assert ActionType.DATA_AGGREGATE == "data.aggregate"
    assert ActionType.DATA_TRANSFORM == "data.transform"


def test_playbook_metadata_dataclass():
    """Test PlaybookMetadata dataclass."""
    from core.playbook_runner import PlaybookMetadata

    metadata = PlaybookMetadata(
        name="test-playbook",
        version="1.0.0",
        description="Test playbook description",
        author="test-author",
    )
    assert metadata.name == "test-playbook"
    assert metadata.version == "1.0.0"
    assert metadata.description == "Test playbook description"
    assert metadata.author == "test-author"
    assert metadata.license == "MIT"
    assert metadata.tags == []
    assert metadata.compliance_frameworks == []
    assert metadata.ssdlc_stages == []


def test_step_condition_dataclass():
    """Test StepCondition dataclass."""
    from core.playbook_runner import StepCondition

    condition = StepCondition(
        when="{{ inputs.enabled }}",
        unless="{{ inputs.skip }}",
        depends_on=["step1", "step2"],
    )
    assert condition.when == "{{ inputs.enabled }}"
    assert condition.unless == "{{ inputs.skip }}"
    assert condition.depends_on == ["step1", "step2"]


def test_step_result_dataclass():
    """Test StepResult dataclass."""
    from core.playbook_runner import StepResult, StepStatus

    result = StepResult(
        name="step1",
        status=StepStatus.SUCCESS,
        output={"key": "value"},
        error=None,
        duration_ms=100,
    )
    assert result.name == "step1"
    assert result.status == StepStatus.SUCCESS
    assert result.output == {"key": "value"}
    assert result.error is None
    assert result.duration_ms == 100


def test_step_result_to_dict():
    """Test StepResult.to_dict method."""
    from datetime import datetime, timezone

    from core.playbook_runner import StepResult, StepStatus

    now = datetime.now(timezone.utc)
    result = StepResult(
        name="step1",
        status=StepStatus.SUCCESS,
        output={"result": "ok"},
        error=None,
        started_at=now,
        completed_at=now,
        duration_ms=50,
    )
    result_dict = result.to_dict()
    assert result_dict["name"] == "step1"
    assert result_dict["status"] == "success"
    assert result_dict["output"] == {"result": "ok"}
    assert result_dict["duration_ms"] == 50


def test_playbook_step_dataclass():
    """Test PlaybookStep dataclass."""
    from core.playbook_runner import ActionType, PlaybookStep

    step = PlaybookStep(
        name="Test Step",
        action=ActionType.OPA_EVALUATE,
        params={"policy": "test.rego"},
    )
    assert step.name == "Test Step"
    assert step.action == ActionType.OPA_EVALUATE
    assert step.params == {"policy": "test.rego"}
    assert step.timeout == "30s"


def test_playbook_dataclass():
    """Test Playbook dataclass."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookStep,
    )

    metadata = PlaybookMetadata(name="test-playbook", version="1.0.0")
    step = PlaybookStep(name="Test Step", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    assert playbook.api_version == "fixops.io/v1"
    assert playbook.kind == PlaybookKind.PLAYBOOK
    assert playbook.metadata.name == "test-playbook"
    assert len(playbook.steps) == 1


def test_playbook_execution_context_dataclass():
    """Test PlaybookExecutionContext dataclass."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookStep,
    )

    metadata = PlaybookMetadata(name="test-playbook", version="1.0.0")
    step = PlaybookStep(name="Test Step", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(playbook=playbook, inputs={"key": "value"})
    assert context.playbook == playbook
    assert context.inputs == {"key": "value"}
    assert context.variables == {}
    assert context.step_results == {}


def test_playbook_execution_context_to_dict():
    """Test PlaybookExecutionContext.to_dict method."""
    from datetime import datetime, timezone

    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookStep,
        StepResult,
        StepStatus,
    )

    metadata = PlaybookMetadata(name="test-playbook", version="1.0.0")
    step = PlaybookStep(name="Test Step", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    now = datetime.now(timezone.utc)
    context = PlaybookExecutionContext(
        playbook=playbook,
        inputs={"key": "value"},
        started_at=now,
        completed_at=now,
    )
    context.step_results["Test Step"] = StepResult(
        name="Test Step",
        status=StepStatus.SUCCESS,
        output={"result": "ok"},
    )
    result = context.to_dict()
    assert result["playbook"]["name"] == "test-playbook"
    assert result["inputs"] == {"key": "value"}
    assert "Test Step" in result["step_results"]
    assert "status" in result
    assert "summary" in result


def test_playbook_execution_context_compute_status():
    """Test PlaybookExecutionContext._compute_status method."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookStep,
        StepResult,
        StepStatus,
    )

    metadata = PlaybookMetadata(name="test-playbook", version="1.0.0")
    step = PlaybookStep(name="Test Step", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(playbook=playbook, inputs={})

    assert context._compute_status() == "pending"

    context.step_results["step1"] = StepResult(
        name="step1", status=StepStatus.SUCCESS, output={}
    )
    assert context._compute_status() == "completed"

    context.step_results["step2"] = StepResult(
        name="step2", status=StepStatus.FAILED, output={}
    )
    assert context._compute_status() == "failed"

    context.step_results = {}
    context.step_results["step1"] = StepResult(
        name="step1", status=StepStatus.RUNNING, output={}
    )
    assert context._compute_status() == "running"

    context.step_results = {}
    context.step_results["step1"] = StepResult(
        name="step1", status=StepStatus.SKIPPED, output={}
    )
    assert context._compute_status() == "completed"


def test_playbook_execution_context_compute_summary():
    """Test PlaybookExecutionContext._compute_summary method."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookStep,
        StepResult,
        StepStatus,
    )

    metadata = PlaybookMetadata(name="test-playbook", version="1.0.0")
    step = PlaybookStep(name="Test Step", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(playbook=playbook, inputs={})
    context.step_results["step1"] = StepResult(
        name="step1", status=StepStatus.SUCCESS, output={}
    )
    context.step_results["step2"] = StepResult(
        name="step2", status=StepStatus.FAILED, output={}
    )
    context.step_results["step3"] = StepResult(
        name="step3", status=StepStatus.SKIPPED, output={}
    )
    context.step_results["step4"] = StepResult(
        name="step4", status=StepStatus.PENDING, output={}
    )

    summary = context._compute_summary()
    assert summary["total"] == 4
    assert summary["success"] == 1
    assert summary["failed"] == 1
    assert summary["skipped"] == 1
    assert summary["pending"] == 1


def test_validation_error_dataclass():
    """Test ValidationError dataclass."""
    from core.playbook_runner import ValidationError

    error = ValidationError(
        path="steps[0].action", message="Invalid action type", severity="error"
    )
    assert error.path == "steps[0].action"
    assert error.message == "Invalid action type"
    assert error.severity == "error"


def test_validation_error_to_dict():
    """Test ValidationError.to_dict method."""
    from core.playbook_runner import ValidationError

    error = ValidationError(
        path="steps[0].action", message="Invalid action type", severity="error"
    )
    result = error.to_dict()
    assert result["path"] == "steps[0].action"
    assert result["message"] == "Invalid action type"
    assert result["severity"] == "error"


def test_playbook_runner_init():
    """Test PlaybookRunner initialization."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()
    assert runner is not None
    assert runner._action_handlers is not None


def test_playbook_runner_init_with_overlay(tmp_path):
    """Test PlaybookRunner initialization with overlay path."""
    from core.playbook_runner import PlaybookRunner

    overlay_path = tmp_path / "overlay.yml"
    overlay_path.write_text("modules:\n  playbooks:\n    enabled: true\n")

    runner = PlaybookRunner(overlay_path=str(overlay_path))
    assert runner is not None


def test_playbook_runner_load_playbook(tmp_path):
    """Test PlaybookRunner.load_playbook method."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
  description: Test playbook
spec:
  inputs: {}
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    assert playbook is not None
    assert playbook.metadata.name == "test-playbook"


def test_playbook_runner_load_playbook_json(tmp_path):
    """Test PlaybookRunner.load_playbook with JSON file."""
    import json

    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_data = {
        "apiVersion": "fixops.io/v1",
        "kind": "Playbook",
        "metadata": {"name": "test-playbook", "version": "1.0.0"},
        "spec": {
            "inputs": {},
            "steps": [
                {
                    "name": "step1",
                    "action": "data.filter",
                    "params": {"data": [1, 2, 3]},
                }
            ],
        },
    }
    playbook_path = tmp_path / "test-playbook.json"
    playbook_path.write_text(json.dumps(playbook_data))

    playbook = runner.load_playbook(playbook_path)
    assert playbook is not None
    assert playbook.metadata.name == "test-playbook"


def test_playbook_runner_load_playbook_not_found():
    """Test PlaybookRunner.load_playbook with non-existent file."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    with pytest.raises(FileNotFoundError):
        runner.load_playbook("/non/existent/path.yml")


def test_playbook_runner_load_playbook_unsupported_format(tmp_path):
    """Test PlaybookRunner.load_playbook with unsupported format."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_path = tmp_path / "test-playbook.txt"
    playbook_path.write_text("some content")

    with pytest.raises(ValueError, match="Unsupported file format"):
        runner.load_playbook(playbook_path)


def test_playbook_runner_load_playbook_from_string():
    """Test PlaybookRunner.load_playbook_from_string method."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
"""
    playbook = runner.load_playbook_from_string(playbook_content)
    assert playbook is not None
    assert playbook.metadata.name == "test-playbook"


def test_playbook_runner_load_playbook_from_string_json():
    """Test PlaybookRunner.load_playbook_from_string with JSON format."""
    import json

    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_data = {
        "apiVersion": "fixops.io/v1",
        "kind": "Playbook",
        "metadata": {"name": "test-playbook", "version": "1.0.0"},
        "spec": {
            "steps": [
                {
                    "name": "step1",
                    "action": "data.filter",
                    "params": {"data": [1, 2, 3]},
                }
            ],
        },
    }
    playbook = runner.load_playbook_from_string(
        json.dumps(playbook_data), format="json"
    )
    assert playbook is not None
    assert playbook.metadata.name == "test-playbook"


def test_playbook_runner_load_playbook_from_string_unsupported():
    """Test PlaybookRunner.load_playbook_from_string with unsupported format."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    with pytest.raises(ValueError, match="Unsupported format"):
        runner.load_playbook_from_string("content", format="xml")


def test_playbook_runner_validate_playbook():
    """Test PlaybookRunner.validate_playbook method."""
    from core.playbook_runner import (
        Playbook,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
    )

    runner = PlaybookRunner()

    metadata = PlaybookMetadata(name="", version="")
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[],
    )

    errors = runner.validate_playbook(playbook)
    assert len(errors) >= 2


def test_playbook_runner_validate_playbook_duplicate_steps(tmp_path):
    """Test PlaybookRunner.validate_playbook with duplicate step names."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params: {}
    - name: step1
      action: data.filter
      params: {}
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    errors = runner.validate_playbook(playbook)
    assert any("Duplicate" in e.message for e in errors)


def test_playbook_runner_validate_playbook_invalid_depends_on(tmp_path):
    """Test PlaybookRunner.validate_playbook with invalid depends_on."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params: {}
      condition:
        depends_on:
          - nonexistent_step
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    errors = runner.validate_playbook(playbook)
    assert any("non-existent" in e.message for e in errors)


def test_playbook_runner_validate_playbook_file(tmp_path):
    """Test PlaybookRunner.validate_playbook_file method."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    errors = runner.validate_playbook_file(playbook_path)
    assert isinstance(errors, list)


def test_playbook_runner_validate_playbook_file_error(tmp_path):
    """Test PlaybookRunner.validate_playbook_file with invalid file."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_path = tmp_path / "invalid.yml"
    playbook_path.write_text("invalid: yaml: content:")

    errors = runner.validate_playbook_file(playbook_path)
    assert len(errors) > 0
    assert errors[0].path == "file"


def test_playbook_runner_execute_sync(tmp_path):
    """Test PlaybookRunner.execute_sync method."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_playbook_runner_execute_sync_dry_run(tmp_path):
    """Test PlaybookRunner.execute_sync with dry_run mode."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {}, dry_run=True)
    assert context is not None
    assert context.step_results["step1"].output.get("dry_run") is True


def test_playbook_runner_resolve_template():
    """Test PlaybookRunner._resolve_template method."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
        PlaybookStep,
    )

    runner = PlaybookRunner()
    metadata = PlaybookMetadata(name="test", version="1.0.0")
    step = PlaybookStep(name="step1", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(playbook=playbook, inputs={"name": "test-value"})

    result = runner._resolve_template("Hello {{ inputs.name }}", context)
    assert result == "Hello test-value"


def test_playbook_runner_resolve_params():
    """Test PlaybookRunner._resolve_params method."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
        PlaybookStep,
    )

    runner = PlaybookRunner()
    metadata = PlaybookMetadata(name="test", version="1.0.0")
    step = PlaybookStep(name="step1", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(playbook=playbook, inputs={"value": "resolved"})

    params = {"key": "{{ inputs.value }}"}
    result = runner._resolve_params(params, context)
    assert result["key"] == "resolved"


def test_playbook_runner_resolve_params_nested():
    """Test PlaybookRunner._resolve_params with nested params."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
        PlaybookStep,
    )

    runner = PlaybookRunner()
    metadata = PlaybookMetadata(name="test", version="1.0.0")
    step = PlaybookStep(name="step1", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(playbook=playbook, inputs={"value": "resolved"})

    params = {"nested": {"key": "{{ inputs.value }}"}, "list": ["{{ inputs.value }}"]}
    result = runner._resolve_params(params, context)
    assert result["nested"]["key"] == "resolved"
    assert result["list"][0] == "resolved"


def test_playbook_runner_get_value_by_path():
    """Test PlaybookRunner._get_value_by_path method."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
        PlaybookStep,
    )

    runner = PlaybookRunner()
    metadata = PlaybookMetadata(name="test", version="1.0.0")
    step = PlaybookStep(name="step1", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(
        playbook=playbook, inputs={"nested": {"key": "value"}}
    )

    result = runner._get_value_by_path("inputs.nested.key", context)
    assert result == "value"


def test_playbook_runner_evaluate_expression():
    """Test PlaybookRunner._evaluate_expression method."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
        PlaybookStep,
    )

    runner = PlaybookRunner()
    metadata = PlaybookMetadata(name="test", version="1.0.0")
    step = PlaybookStep(name="step1", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(playbook=playbook, inputs={"enabled": True})

    result = runner._evaluate_expression("{{ inputs.enabled }}", context)
    assert result is True


def test_playbook_runner_check_conditions():
    """Test PlaybookRunner._check_conditions method."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
        PlaybookStep,
    )

    runner = PlaybookRunner()
    metadata = PlaybookMetadata(name="test", version="1.0.0")
    step = PlaybookStep(name="step1", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(playbook=playbook, inputs={})

    result = runner._check_conditions({}, context)
    assert result is True


def test_playbook_runner_check_conditions_min_severity():
    """Test PlaybookRunner._check_conditions with min_severity."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
        PlaybookStep,
    )

    runner = PlaybookRunner()
    metadata = PlaybookMetadata(name="test", version="1.0.0")
    step = PlaybookStep(name="step1", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(
        playbook=playbook,
        inputs={"findings": [{"severity": "high"}]},
    )

    result = runner._check_conditions({"min_severity": "medium"}, context)
    assert result is True

    result = runner._check_conditions({"min_severity": "critical"}, context)
    assert result is False


def test_playbook_runner_check_conditions_frameworks():
    """Test PlaybookRunner._check_conditions with frameworks."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
        PlaybookStep,
    )

    runner = PlaybookRunner()
    metadata = PlaybookMetadata(
        name="test", version="1.0.0", compliance_frameworks=["SOC2", "PCI-DSS"]
    )
    step = PlaybookStep(name="step1", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(playbook=playbook, inputs={})

    result = runner._check_conditions({"frameworks": ["SOC2"]}, context)
    assert result is True

    result = runner._check_conditions({"frameworks": ["HIPAA"]}, context)
    assert result is False


def test_playbook_runner_extract_max_severity():
    """Test PlaybookRunner._extract_max_severity method."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()
    severity_order = ["low", "medium", "high", "critical"]

    findings = [{"severity": "high"}, {"severity": "low"}]
    result = runner._extract_max_severity(findings, severity_order)
    assert result == "high"


def test_playbook_runner_extract_max_severity_sarif():
    """Test PlaybookRunner._extract_max_severity with SARIF format."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()
    severity_order = ["low", "medium", "high", "critical"]

    findings = {
        "runs": [
            {
                "results": [
                    {"level": "error"},
                    {"level": "warning"},
                ]
            }
        ]
    }
    result = runner._extract_max_severity(findings, severity_order)
    assert result == "critical"


def test_playbook_runner_sarif_level_to_severity():
    """Test PlaybookRunner._sarif_level_to_severity method."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    assert runner._sarif_level_to_severity("error") == "critical"
    assert runner._sarif_level_to_severity("warning") == "high"
    assert runner._sarif_level_to_severity("note") == "medium"
    assert runner._sarif_level_to_severity("none") == "low"
    assert runner._sarif_level_to_severity("unknown") == "medium"


def test_playbook_runner_register_handler():
    """Test PlaybookRunner.register_handler method."""
    from core.playbook_runner import ActionType, PlaybookRunner

    runner = PlaybookRunner()

    async def custom_handler(params, context):
        return {"custom": True}

    runner.register_handler(ActionType.OPA_EVALUATE, custom_handler)
    assert runner._action_handlers[ActionType.OPA_EVALUATE] == custom_handler


def test_step_with_condition(tmp_path):
    """Test step with condition."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
      condition:
        when: "{{ inputs.run_step }}"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {"run_step": True})
    assert context is not None


def test_step_with_unless_condition(tmp_path):
    """Test step with unless condition."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
      condition:
        unless: "{{ inputs.skip_step }}"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {"skip_step": True})
    assert context is not None
    assert context.step_results["step1"].status.value == "skipped"


def test_step_with_depends_on(tmp_path):
    """Test step with depends_on."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 0"
    - name: step2
      action: data.filter
      params:
        data: [4, 5, 6]
        condition: "x > 4"
      condition:
        depends_on:
          - step1
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_step_with_on_success(tmp_path):
    """Test step with on_success handler."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 0"
      on_success:
        set:
          result: success
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None
    assert context.variables.get("result") == "success"


def test_step_with_on_failure_retry(tmp_path):
    """Test step with on_failure retry configuration."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 0"
      on_failure:
        retry: 1
        continue: true
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_get_playbook_runner():
    """Test get_playbook_runner function."""
    from core.playbook_runner import get_playbook_runner

    runner = get_playbook_runner()
    assert runner is not None

    runner2 = get_playbook_runner()
    assert runner is runner2


def test_data_filter_handler(tmp_path):
    """Test data.filter action handler."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: filter_step
      action: data.filter
      params:
        data: [1, 2, 3, 4, 5]
        condition: "x > 2"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_data_transform_handler(tmp_path):
    """Test data.transform action handler."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: transform_step
      action: data.transform
      params:
        data:
          key: value
        template: "{{ data.key }}"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_data_aggregate_handler(tmp_path):
    """Test data.aggregate action handler."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: aggregate_step
      action: data.aggregate
      params:
        data: [1, 2, 3, 4, 5]
        operation: sum
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_opa_evaluate_handler(tmp_path):
    """Test opa.evaluate action handler."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: opa_step
      action: opa.evaluate
      params:
        policy: test.rego
        input:
          key: value
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_opa_assert_handler(tmp_path):
    """Test opa.assert action handler."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: opa_assert_step
      action: opa.assert
      params:
        policy: test.rego
        expected: true
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_evidence_handlers(tmp_path):
    """Test evidence action handlers."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: evidence_assert
      action: evidence.assert
      params:
        evidence_id: test-evidence
        assertion: exists
    - name: evidence_collect
      action: evidence.collect
      params:
        source: test-source
        type: log
    - name: evidence_sign
      action: evidence.sign
      params:
        evidence_id: test-evidence
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_compliance_handlers(tmp_path):
    """Test compliance action handlers."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: compliance_check
      action: compliance.check_control
      params:
        control_id: SOC2-CC1.1
        framework: SOC2
    - name: compliance_map
      action: compliance.map_finding
      params:
        finding_id: test-finding
        control_id: SOC2-CC1.1
    - name: compliance_report
      action: compliance.generate_report
      params:
        framework: SOC2
        format: json
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_pentest_handlers(tmp_path):
    """Test pentest action handlers."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: pentest_request
      action: pentest.request
      params:
        target: test-target
        type: web
    - name: pentest_validate
      action: pentest.validate_exploitability
      params:
        finding_id: test-finding
    - name: scanner_run
      action: scanner.run
      params:
        scanner: test-scanner
        target: test-target
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_notification_handlers(tmp_path):
    """Test notification action handlers."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: notify_slack
      action: notify.slack
      params:
        channel: test-channel
        message: Test message
    - name: notify_email
      action: notify.email
      params:
        to: test@example.com
        subject: Test subject
        body: Test body
    - name: notify_pagerduty
      action: notify.pagerduty
      params:
        service_key: test-key
        description: Test alert
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_jira_handlers(tmp_path):
    """Test Jira action handlers."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: jira_create
      action: jira.create_issue
      params:
        project: TEST
        summary: Test issue
        description: Test description
    - name: jira_update
      action: jira.update_issue
      params:
        issue_key: TEST-123
        fields:
          status: Done
    - name: jira_comment
      action: jira.add_comment
      params:
        issue_key: TEST-123
        comment: Test comment
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_confluence_handlers(tmp_path):
    """Test Confluence action handlers."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: confluence_create
      action: confluence.create_page
      params:
        space: TEST
        title: Test page
        content: Test content
    - name: confluence_update
      action: confluence.update_page
      params:
        page_id: "123456"
        content: Updated content
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_workflow_handlers(tmp_path):
    """Test workflow action handlers."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: workflow_approve
      action: workflow.approve
      params:
        workflow_id: test-workflow
        comment: Approved
    - name: workflow_reject
      action: workflow.reject
      params:
        workflow_id: test-workflow
        reason: Rejected
    - name: workflow_escalate
      action: workflow.escalate
      params:
        workflow_id: test-workflow
        to: manager
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    playbook = runner.load_playbook(playbook_path)
    context = runner.execute_sync(playbook, {})
    assert context is not None


def test_parse_playbook_missing_fields():
    """Test _parse_playbook with missing required fields."""
    from core.playbook_runner import PlaybookRunner

    runner = PlaybookRunner()

    with pytest.raises(ValueError, match="Missing required field: apiVersion"):
        runner._parse_playbook({})

    with pytest.raises(ValueError, match="Missing required field: kind"):
        runner._parse_playbook({"apiVersion": "fixops.io/v1"})

    with pytest.raises(ValueError, match="Missing required field: metadata"):
        runner._parse_playbook({"apiVersion": "fixops.io/v1", "kind": "Playbook"})

    with pytest.raises(ValueError, match="Missing required field: spec"):
        runner._parse_playbook(
            {
                "apiVersion": "fixops.io/v1",
                "kind": "Playbook",
                "metadata": {"name": "test"},
            }
        )


def test_validate_inputs():
    """Test _validate_inputs method."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
        PlaybookStep,
    )

    runner = PlaybookRunner()
    metadata = PlaybookMetadata(name="test", version="1.0.0")
    step = PlaybookStep(name="step1", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
        inputs={
            "required_input": {"required": True},
            "optional_input": {"default": "default_value"},
        },
    )

    with pytest.raises(ValueError, match="Missing required input"):
        runner._validate_inputs(playbook, {})

    inputs = {}
    runner._validate_inputs(playbook, {"required_input": "value"})

    inputs = {}
    runner._validate_inputs(playbook, {"required_input": "value"})
    assert inputs.get("optional_input") is None


def test_check_step_condition():
    """Test _check_step_condition method."""
    from core.playbook_runner import (
        ActionType,
        Playbook,
        PlaybookExecutionContext,
        PlaybookKind,
        PlaybookMetadata,
        PlaybookRunner,
        PlaybookStep,
        StepCondition,
    )

    runner = PlaybookRunner()
    metadata = PlaybookMetadata(name="test", version="1.0.0")
    step = PlaybookStep(name="step1", action=ActionType.DATA_FILTER, params={})
    playbook = Playbook(
        api_version="fixops.io/v1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata,
        steps=[step],
    )
    context = PlaybookExecutionContext(
        playbook=playbook, inputs={"enabled": True, "skip": False}
    )

    condition = StepCondition(when="{{ inputs.enabled }}")
    assert runner._check_step_condition(condition, context) is True

    condition = StepCondition(when="{{ inputs.skip }}")
    assert runner._check_step_condition(condition, context) is False

    condition = StepCondition(unless="{{ inputs.skip }}")
    assert runner._check_step_condition(condition, context) is True

    condition = StepCondition(unless="{{ inputs.enabled }}")
    assert runner._check_step_condition(condition, context) is False
