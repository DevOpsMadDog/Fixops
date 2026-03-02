"""
Comprehensive unit tests for suite-core/core/playbook_runner.py.

Covers:
  - PlaybookKind, StepStatus, ActionType enums
  - PlaybookMetadata, StepCondition, StepResult dataclasses
  - PlaybookStep, Playbook, PlaybookExecutionContext dataclasses
  - ValidationError dataclass
  - PlaybookRunner: init, register_handler, load_playbook_from_string,
    _parse_playbook, validate_playbook, _register_handlers,
    execute (via asyncio), _resolve_template
  - PlaybookExecutionContext: _compute_status, _compute_summary, to_dict
  - Condition handling: when, unless, depends_on
  - Error cases: missing fields, invalid formats, duplicate step names
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from core.playbook_runner import (
    PlaybookKind,
    StepStatus,
    ActionType,
    PlaybookMetadata,
    StepCondition,
    StepResult,
    PlaybookStep,
    Playbook,
    PlaybookExecutionContext,
    ValidationError,
    PlaybookRunner,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


MINIMAL_PLAYBOOK_YAML = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
  description: A test playbook
spec:
  steps:
    - name: check-compliance
      action: compliance.check_control
      params:
        framework: SOC2
        control_id: CC-1.1
"""

MULTI_STEP_PLAYBOOK_YAML = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: multi-step
  version: "2.0.0"
spec:
  steps:
    - name: step-1
      action: evidence.collect
      params:
        source: scanner
    - name: step-2
      action: evidence.assert
      params:
        condition: "findings_count > 0"
      condition:
        depends_on:
          - step-1
    - name: step-3
      action: notify.slack
      params:
        text: "Scan complete"
      condition:
        depends_on:
          - step-2
"""


@pytest.fixture
def runner():
    return PlaybookRunner()


@pytest.fixture
def minimal_playbook(runner):
    return runner.load_playbook_from_string(MINIMAL_PLAYBOOK_YAML)


@pytest.fixture
def multi_step_playbook(runner):
    return runner.load_playbook_from_string(MULTI_STEP_PLAYBOOK_YAML)


# ===========================================================================
# Enums
# ===========================================================================


class TestEnums:
    def test_playbook_kind_values(self):
        assert PlaybookKind.PLAYBOOK.value == "Playbook"
        assert PlaybookKind.COMPLIANCE_PACK.value == "CompliancePack"
        assert PlaybookKind.TEST_PACK.value == "TestPack"
        assert PlaybookKind.MITIGATION_PACK.value == "MitigationPack"

    def test_step_status_values(self):
        assert StepStatus.PENDING.value == "pending"
        assert StepStatus.RUNNING.value == "running"
        assert StepStatus.SUCCESS.value == "success"
        assert StepStatus.FAILED.value == "failed"
        assert StepStatus.SKIPPED.value == "skipped"

    def test_action_type_values(self):
        # Verify a sampling of action types
        assert ActionType.OPA_EVALUATE.value == "opa.evaluate"
        assert ActionType.EVIDENCE_ASSERT.value == "evidence.assert"
        assert ActionType.JIRA_CREATE_ISSUE.value == "jira.create_issue"
        assert ActionType.NOTIFY_SLACK.value == "notify.slack"
        assert ActionType.DATA_FILTER.value == "data.filter"
        assert ActionType.SCANNER_RUN.value == "scanner.run"
        assert ActionType.WORKFLOW_APPROVE.value == "workflow.approve"
        assert ActionType.CONFLUENCE_CREATE_PAGE.value == "confluence.create_page"


# ===========================================================================
# Data Classes
# ===========================================================================


class TestPlaybookMetadata:
    def test_defaults(self):
        meta = PlaybookMetadata(name="test", version="1.0.0")
        assert meta.description == ""
        assert meta.author == ""
        assert meta.license == "MIT"
        assert meta.tags == []
        assert meta.compliance_frameworks == []
        assert meta.ssdlc_stages == []

    def test_full_construction(self):
        meta = PlaybookMetadata(
            name="compliance-check",
            version="2.1.0",
            description="Check SOC2 compliance",
            author="security-team",
            tags=["compliance", "soc2"],
            compliance_frameworks=["SOC2"],
        )
        assert meta.name == "compliance-check"
        assert "soc2" in meta.tags


class TestStepCondition:
    def test_defaults(self):
        cond = StepCondition()
        assert cond.when is None
        assert cond.unless is None
        assert cond.depends_on == []

    def test_with_values(self):
        cond = StepCondition(when="step1.status == 'success'", depends_on=["step1"])
        assert cond.when == "step1.status == 'success'"
        assert "step1" in cond.depends_on


class TestStepResult:
    def test_construction(self):
        result = StepResult(name="step-1", status=StepStatus.SUCCESS, output={"count": 5})
        assert result.name == "step-1"
        assert result.status == StepStatus.SUCCESS
        assert result.output == {"count": 5}

    def test_to_dict(self):
        now = datetime.now(timezone.utc)
        result = StepResult(
            name="step-1",
            status=StepStatus.FAILED,
            error="timeout",
            started_at=now,
            completed_at=now,
            duration_ms=1500,
        )
        d = result.to_dict()
        assert d["name"] == "step-1"
        assert d["status"] == "failed"
        assert d["error"] == "timeout"
        assert d["duration_ms"] == 1500
        assert d["started_at"] is not None
        assert d["completed_at"] is not None

    def test_to_dict_no_timestamps(self):
        result = StepResult(name="step-1", status=StepStatus.PENDING)
        d = result.to_dict()
        assert d["started_at"] is None
        assert d["completed_at"] is None


class TestValidationError:
    def test_to_dict(self):
        err = ValidationError(path="metadata.name", message="Name required", severity="error")
        d = err.to_dict()
        assert d["path"] == "metadata.name"
        assert d["message"] == "Name required"
        assert d["severity"] == "error"

    def test_default_severity(self):
        err = ValidationError(path="x", message="y")
        assert err.severity == "error"


# ===========================================================================
# PlaybookExecutionContext
# ===========================================================================


class TestPlaybookExecutionContext:
    def _make_context(self, step_results=None):
        playbook = Playbook(
            api_version="fixops.io/v1",
            kind=PlaybookKind.PLAYBOOK,
            metadata=PlaybookMetadata(name="test", version="1.0"),
            steps=[],
        )
        ctx = PlaybookExecutionContext(
            playbook=playbook,
            inputs={"app_id": "app-001"},
        )
        if step_results:
            ctx.step_results = step_results
        return ctx

    def test_compute_status_pending(self):
        ctx = self._make_context()
        assert ctx._compute_status() == "pending"

    def test_compute_status_completed(self):
        ctx = self._make_context({
            "s1": StepResult(name="s1", status=StepStatus.SUCCESS),
            "s2": StepResult(name="s2", status=StepStatus.SUCCESS),
        })
        assert ctx._compute_status() == "completed"

    def test_compute_status_with_skipped(self):
        ctx = self._make_context({
            "s1": StepResult(name="s1", status=StepStatus.SUCCESS),
            "s2": StepResult(name="s2", status=StepStatus.SKIPPED),
        })
        assert ctx._compute_status() == "completed"

    def test_compute_status_failed(self):
        ctx = self._make_context({
            "s1": StepResult(name="s1", status=StepStatus.SUCCESS),
            "s2": StepResult(name="s2", status=StepStatus.FAILED),
        })
        assert ctx._compute_status() == "failed"

    def test_compute_status_running(self):
        ctx = self._make_context({
            "s1": StepResult(name="s1", status=StepStatus.SUCCESS),
            "s2": StepResult(name="s2", status=StepStatus.RUNNING),
        })
        assert ctx._compute_status() == "running"

    def test_compute_status_partial(self):
        ctx = self._make_context({
            "s1": StepResult(name="s1", status=StepStatus.SUCCESS),
            "s2": StepResult(name="s2", status=StepStatus.PENDING),
        })
        assert ctx._compute_status() == "partial"

    def test_compute_summary(self):
        ctx = self._make_context({
            "s1": StepResult(name="s1", status=StepStatus.SUCCESS),
            "s2": StepResult(name="s2", status=StepStatus.FAILED),
            "s3": StepResult(name="s3", status=StepStatus.SKIPPED),
        })
        summary = ctx._compute_summary()
        assert summary["total"] == 3
        assert summary["success"] == 1
        assert summary["failed"] == 1
        assert summary["skipped"] == 1

    def test_to_dict(self):
        now = datetime.now(timezone.utc)
        ctx = self._make_context({
            "s1": StepResult(name="s1", status=StepStatus.SUCCESS),
        })
        ctx.started_at = now
        ctx.completed_at = now
        d = ctx.to_dict()
        assert d["playbook"]["name"] == "test"
        assert d["inputs"] == {"app_id": "app-001"}
        assert "s1" in d["step_results"]
        assert d["status"] == "completed"
        assert d["summary"]["total"] == 1
        assert d["started_at"] is not None

    def test_to_dict_no_timestamps(self):
        ctx = self._make_context()
        d = ctx.to_dict()
        assert d["started_at"] is None
        assert d["completed_at"] is None


# ===========================================================================
# PlaybookRunner: parsing
# ===========================================================================


class TestPlaybookParsing:
    def test_load_minimal_playbook(self, runner, minimal_playbook):
        assert minimal_playbook.api_version == "fixops.io/v1"
        assert minimal_playbook.kind == PlaybookKind.PLAYBOOK
        assert minimal_playbook.metadata.name == "test-playbook"
        assert minimal_playbook.metadata.version == "1.0.0"
        assert len(minimal_playbook.steps) == 1
        assert minimal_playbook.steps[0].name == "check-compliance"
        assert minimal_playbook.steps[0].action == ActionType.COMPLIANCE_CHECK_CONTROL

    def test_load_multi_step_playbook(self, runner, multi_step_playbook):
        assert len(multi_step_playbook.steps) == 3
        assert multi_step_playbook.steps[1].condition is not None
        assert "step-1" in multi_step_playbook.steps[1].condition.depends_on

    def test_load_json_format(self, runner):
        data = {
            "apiVersion": "fixops.io/v1",
            "kind": "Playbook",
            "metadata": {"name": "json-test", "version": "1.0"},
            "spec": {
                "steps": [
                    {"name": "s1", "action": "data.filter", "params": {"field": "severity"}}
                ]
            },
        }
        playbook = runner.load_playbook_from_string(json.dumps(data), format="json")
        assert playbook.metadata.name == "json-test"

    def test_missing_api_version_raises(self, runner):
        with pytest.raises(ValueError, match="apiVersion"):
            runner.load_playbook_from_string("""
kind: Playbook
metadata:
  name: test
  version: "1.0"
spec:
  steps:
    - name: s1
      action: data.filter
""")

    def test_missing_kind_raises(self, runner):
        with pytest.raises(ValueError, match="kind"):
            runner.load_playbook_from_string("""
apiVersion: fixops.io/v1
metadata:
  name: test
  version: "1.0"
spec:
  steps:
    - name: s1
      action: data.filter
""")

    def test_missing_metadata_raises(self, runner):
        with pytest.raises(ValueError, match="metadata"):
            runner.load_playbook_from_string("""
apiVersion: fixops.io/v1
kind: Playbook
spec:
  steps:
    - name: s1
      action: data.filter
""")

    def test_missing_spec_raises(self, runner):
        with pytest.raises(ValueError, match="spec"):
            runner.load_playbook_from_string("""
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test
  version: "1.0"
""")

    def test_unsupported_format_raises(self, runner):
        with pytest.raises(ValueError, match="Unsupported format"):
            runner.load_playbook_from_string("{}", format="xml")

    def test_compliance_pack_kind(self, runner):
        playbook = runner.load_playbook_from_string("""
apiVersion: fixops.io/v1
kind: CompliancePack
metadata:
  name: soc2-pack
  version: "1.0"
spec:
  steps:
    - name: check
      action: compliance.check_control
      params:
        framework: SOC2
""")
        assert playbook.kind == PlaybookKind.COMPLIANCE_PACK


# ===========================================================================
# PlaybookRunner: validation
# ===========================================================================


class TestPlaybookValidation:
    def test_valid_playbook_no_errors(self, runner, minimal_playbook):
        errors = runner.validate_playbook(minimal_playbook)
        assert len(errors) == 0

    def test_missing_name(self, runner):
        playbook = Playbook(
            api_version="fixops.io/v1",
            kind=PlaybookKind.PLAYBOOK,
            metadata=PlaybookMetadata(name="", version="1.0"),
            steps=[PlaybookStep(name="s1", action=ActionType.DATA_FILTER)],
        )
        errors = runner.validate_playbook(playbook)
        assert any("name is required" in e.message for e in errors)

    def test_missing_version(self, runner):
        playbook = Playbook(
            api_version="fixops.io/v1",
            kind=PlaybookKind.PLAYBOOK,
            metadata=PlaybookMetadata(name="test", version=""),
            steps=[PlaybookStep(name="s1", action=ActionType.DATA_FILTER)],
        )
        errors = runner.validate_playbook(playbook)
        assert any("version is required" in e.message for e in errors)

    def test_no_steps(self, runner):
        playbook = Playbook(
            api_version="fixops.io/v1",
            kind=PlaybookKind.PLAYBOOK,
            metadata=PlaybookMetadata(name="test", version="1.0"),
            steps=[],
        )
        errors = runner.validate_playbook(playbook)
        assert any("At least one step" in e.message for e in errors)

    def test_duplicate_step_names(self, runner):
        playbook = Playbook(
            api_version="fixops.io/v1",
            kind=PlaybookKind.PLAYBOOK,
            metadata=PlaybookMetadata(name="test", version="1.0"),
            steps=[
                PlaybookStep(name="dup", action=ActionType.DATA_FILTER),
                PlaybookStep(name="dup", action=ActionType.DATA_AGGREGATE),
            ],
        )
        errors = runner.validate_playbook(playbook)
        assert any("Duplicate" in e.message for e in errors)

    def test_invalid_dependency_reference(self, runner):
        playbook = Playbook(
            api_version="fixops.io/v1",
            kind=PlaybookKind.PLAYBOOK,
            metadata=PlaybookMetadata(name="test", version="1.0"),
            steps=[
                PlaybookStep(
                    name="s1",
                    action=ActionType.DATA_FILTER,
                    condition=StepCondition(depends_on=["nonexistent"]),
                ),
            ],
        )
        errors = runner.validate_playbook(playbook)
        assert any("non-existent" in e.message for e in errors)


# ===========================================================================
# PlaybookRunner: registration
# ===========================================================================


class TestPlaybookHandlerRegistration:
    def test_default_handlers_registered(self, runner):
        # All ActionType values should have handlers
        for action_type in ActionType:
            assert action_type in runner._action_handlers, f"Missing handler for {action_type}"

    def test_register_custom_handler(self, runner):
        custom_handler = MagicMock(return_value={"result": "ok"})
        runner.register_handler(ActionType.DATA_FILTER, custom_handler)
        assert runner._action_handlers[ActionType.DATA_FILTER] is custom_handler


# ===========================================================================
# PlaybookRunner: file loading
# ===========================================================================


class TestPlaybookFileLoading:
    def test_load_from_yaml_file(self, runner, tmp_path):
        f = tmp_path / "playbook.yaml"
        f.write_text(MINIMAL_PLAYBOOK_YAML)
        playbook = runner.load_playbook(f)
        assert playbook.metadata.name == "test-playbook"

    def test_load_from_json_file(self, runner, tmp_path):
        data = {
            "apiVersion": "fixops.io/v1",
            "kind": "Playbook",
            "metadata": {"name": "json-file", "version": "1.0"},
            "spec": {"steps": [{"name": "s1", "action": "data.filter"}]},
        }
        f = tmp_path / "playbook.json"
        f.write_text(json.dumps(data))
        playbook = runner.load_playbook(f)
        assert playbook.metadata.name == "json-file"

    def test_load_nonexistent_file_raises(self, runner):
        with pytest.raises(FileNotFoundError):
            runner.load_playbook("/nonexistent/playbook.yaml")

    def test_load_unsupported_extension_raises(self, runner, tmp_path):
        f = tmp_path / "playbook.xml"
        f.write_text("<playbook/>")
        with pytest.raises(ValueError, match="Unsupported file format"):
            runner.load_playbook(f)

    def test_validate_playbook_file(self, runner, tmp_path):
        f = tmp_path / "playbook.yaml"
        f.write_text(MINIMAL_PLAYBOOK_YAML)
        errors = runner.validate_playbook_file(f)
        assert len(errors) == 0

    def test_validate_playbook_file_invalid(self, runner, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("invalid: yaml: ::")
        errors = runner.validate_playbook_file(f)
        assert len(errors) > 0


# ===========================================================================
# PlaybookRunner: execute
# ===========================================================================


class TestPlaybookExecution:
    def test_execute_minimal(self, runner, minimal_playbook):
        result = asyncio.run(
            runner.execute(minimal_playbook, inputs={"app_id": "test"})
        )
        assert result.started_at is not None
        assert len(result.step_results) == 1

    def test_execute_dry_run(self, runner, minimal_playbook):
        result = asyncio.run(
            runner.execute(minimal_playbook, dry_run=True)
        )
        assert result.started_at is not None

    def test_execute_multi_step(self, runner, multi_step_playbook):
        result = asyncio.run(
            runner.execute(multi_step_playbook)
        )
        assert len(result.step_results) == 3

    def test_execute_with_custom_handler(self, runner):
        custom_output = {"matched": 5}

        async def custom_handler(params, context):
            return custom_output

        runner.register_handler(ActionType.DATA_FILTER, custom_handler)

        playbook = runner.load_playbook_from_string("""
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: custom-test
  version: "1.0"
spec:
  steps:
    - name: filter-step
      action: data.filter
      params:
        field: severity
""")
        result = asyncio.run(
            runner.execute(playbook)
        )
        assert "filter-step" in result.step_results

    def test_execute_result_to_dict(self, runner, minimal_playbook):
        result = asyncio.run(
            runner.execute(minimal_playbook)
        )
        d = result.to_dict()
        assert "playbook" in d
        assert "step_results" in d
        assert "status" in d
        assert "summary" in d


# ===========================================================================
# Playbook dataclass
# ===========================================================================


class TestPlaybookDataclass:
    def test_construction(self):
        playbook = Playbook(
            api_version="fixops.io/v1",
            kind=PlaybookKind.PLAYBOOK,
            metadata=PlaybookMetadata(name="test", version="1.0"),
            steps=[PlaybookStep(name="s1", action=ActionType.DATA_FILTER)],
            inputs={"threshold": 5},
            triggers=[{"event": "scan_complete"}],
        )
        assert playbook.api_version == "fixops.io/v1"
        assert playbook.inputs == {"threshold": 5}
        assert len(playbook.triggers) == 1

    def test_default_fields(self):
        playbook = Playbook(
            api_version="v1",
            kind=PlaybookKind.PLAYBOOK,
            metadata=PlaybookMetadata(name="t", version="1"),
            steps=[],
        )
        assert playbook.inputs == {}
        assert playbook.conditions == {}
        assert playbook.outputs == {}
        assert playbook.triggers == []


class TestPlaybookStep:
    def test_construction(self):
        step = PlaybookStep(
            name="scan",
            action=ActionType.SCANNER_RUN,
            params={"scanner": "sast"},
            timeout="60s",
        )
        assert step.name == "scan"
        assert step.timeout == "60s"

    def test_defaults(self):
        step = PlaybookStep(name="s", action=ActionType.DATA_FILTER)
        assert step.params == {}
        assert step.condition is None
        assert step.on_success is None
        assert step.on_failure is None
        assert step.timeout == "30s"
