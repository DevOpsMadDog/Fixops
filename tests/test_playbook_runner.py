"""
Comprehensive unit tests for suite-core/core/playbook_runner.py

Tests cover:
- Enums: PlaybookKind, StepStatus, ActionType
- Dataclasses: PlaybookMetadata, StepCondition, StepResult, PlaybookStep,
               Playbook, PlaybookExecutionContext, ValidationError
- PlaybookRunner: initialization, handler registration, YAML/JSON loading,
                  validation, template resolution, expression evaluation,
                  condition checking, step execution, full playbook execution
- Module-level helpers: get_playbook_runner singleton
- Edge cases: empty inputs, boundary values, dependency failures
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

# Path setup
sys.path.insert(0, "/Users/devops.ai/developement/fixops/Fixops/suite-core")
sys.path.insert(0, "/Users/devops.ai/developement/fixops/Fixops/suite-attack")
sys.path.insert(0, "/Users/devops.ai/developement/fixops/Fixops/suite-integrations")

# Required env vars before import
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.playbook_runner import (  # noqa: E402
    ActionType,
    Playbook,
    PlaybookExecutionContext,
    PlaybookKind,
    PlaybookMetadata,
    PlaybookRunner,
    PlaybookStep,
    StepCondition,
    StepResult,
    StepStatus,
    ValidationError,
    get_playbook_runner,
)

# ============================================================
# Helpers / Fixtures
# ============================================================

MINIMAL_YAML = """
apiVersion: fixops/v1alpha1
kind: Playbook
metadata:
  name: test-playbook
  version: 1.0.0
spec:
  steps:
    - name: step1
      action: opa.evaluate
      params:
        policy: test-policy
"""

FULL_YAML = """
apiVersion: fixops/v1alpha1
kind: Playbook
metadata:
  name: full-playbook
  version: 2.0.0
  description: A full test playbook
  author: Test Author
  license: Apache-2.0
  tags:
    - security
    - compliance
  compliance_frameworks:
    - SOC2
    - ISO27001
  ssdlc_stages:
    - build
    - deploy
spec:
  inputs:
    app_id:
      required: true
    severity_threshold:
      required: false
      default: high
  steps:
    - name: check-policy
      action: opa.evaluate
      params:
        policy: security-policy
    - name: create-ticket
      action: jira.create_issue
      params:
        summary: "Security finding"
      condition:
        when: "inputs.severity_threshold == high"
        depends_on:
          - check-policy
      on_success:
        set:
          ticket_created: "true"
      on_failure:
        continue: true
"""

COMPLIANCE_YAML = """
apiVersion: fixops/v1alpha1
kind: CompliancePack
metadata:
  name: soc2-compliance
  version: 1.0.0
  compliance_frameworks:
    - SOC2
spec:
  steps:
    - name: check-control
      action: compliance.check_control
      params:
        framework: SOC2
        control: CC6.1
"""


def make_runner() -> PlaybookRunner:
    """Create a fresh PlaybookRunner with no overlay."""
    return PlaybookRunner()


def make_metadata(**kwargs) -> PlaybookMetadata:
    defaults = {"name": "test", "version": "1.0.0"}
    defaults.update(kwargs)
    return PlaybookMetadata(**defaults)


def make_step(name: str = "s1", action: ActionType = ActionType.OPA_EVALUATE, **kw) -> PlaybookStep:
    return PlaybookStep(name=name, action=action, **kw)


def make_playbook(steps=None, inputs=None, metadata=None, conditions=None) -> Playbook:
    if steps is None:
        steps = [make_step()]
    return Playbook(
        api_version="fixops/v1alpha1",
        kind=PlaybookKind.PLAYBOOK,
        metadata=metadata or make_metadata(),
        steps=steps,
        inputs=inputs or {},
        conditions=conditions or {},
    )


def make_context(playbook=None, inputs=None) -> PlaybookExecutionContext:
    pb = playbook or make_playbook()
    return PlaybookExecutionContext(
        playbook=pb,
        inputs=inputs or {},
        started_at=datetime.now(timezone.utc),
    )


def make_step_result(name: str, status: StepStatus, output=None, error=None) -> StepResult:
    return StepResult(name=name, status=status, output=output, error=error)


# ============================================================
# 1. PlaybookKind Enum
# ============================================================

class TestPlaybookKind:
    def test_playbook_value(self):
        assert PlaybookKind.PLAYBOOK.value == "Playbook"

    def test_compliance_pack_value(self):
        assert PlaybookKind.COMPLIANCE_PACK.value == "CompliancePack"

    def test_test_pack_value(self):
        assert PlaybookKind.TEST_PACK.value == "TestPack"

    def test_mitigation_pack_value(self):
        assert PlaybookKind.MITIGATION_PACK.value == "MitigationPack"

    def test_str_enum_isinstance(self):
        assert isinstance(PlaybookKind.PLAYBOOK, str)

    def test_all_members_count(self):
        assert len(PlaybookKind) == 4

    def test_from_string(self):
        assert PlaybookKind("Playbook") == PlaybookKind.PLAYBOOK

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            PlaybookKind("Invalid")

    def test_compliance_from_string(self):
        assert PlaybookKind("CompliancePack") == PlaybookKind.COMPLIANCE_PACK


# ============================================================
# 2. StepStatus Enum
# ============================================================

class TestStepStatus:
    def test_pending_value(self):
        assert StepStatus.PENDING.value == "pending"

    def test_running_value(self):
        assert StepStatus.RUNNING.value == "running"

    def test_success_value(self):
        assert StepStatus.SUCCESS.value == "success"

    def test_failed_value(self):
        assert StepStatus.FAILED.value == "failed"

    def test_skipped_value(self):
        assert StepStatus.SKIPPED.value == "skipped"

    def test_str_enum(self):
        assert isinstance(StepStatus.SUCCESS, str)

    def test_all_members_count(self):
        assert len(StepStatus) == 5

    def test_from_string(self):
        assert StepStatus("success") == StepStatus.SUCCESS

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            StepStatus("unknown")


# ============================================================
# 3. ActionType Enum
# ============================================================

class TestActionType:
    def test_opa_evaluate(self):
        assert ActionType.OPA_EVALUATE.value == "opa.evaluate"

    def test_opa_assert(self):
        assert ActionType.OPA_ASSERT.value == "opa.assert"

    def test_evidence_assert(self):
        assert ActionType.EVIDENCE_ASSERT.value == "evidence.assert"

    def test_evidence_collect(self):
        assert ActionType.EVIDENCE_COLLECT.value == "evidence.collect"

    def test_evidence_sign(self):
        assert ActionType.EVIDENCE_SIGN.value == "evidence.sign"

    def test_compliance_check_control(self):
        assert ActionType.COMPLIANCE_CHECK_CONTROL.value == "compliance.check_control"

    def test_compliance_map_finding(self):
        assert ActionType.COMPLIANCE_MAP_FINDING.value == "compliance.map_finding"

    def test_compliance_generate_report(self):
        assert ActionType.COMPLIANCE_GENERATE_REPORT.value == "compliance.generate_report"

    def test_pentest_request(self):
        assert ActionType.PENTEST_REQUEST.value == "pentest.request"

    def test_pentest_validate(self):
        assert ActionType.PENTEST_VALIDATE_EXPLOITABILITY.value == "pentest.validate_exploitability"

    def test_scanner_run(self):
        assert ActionType.SCANNER_RUN.value == "scanner.run"

    def test_notify_slack(self):
        assert ActionType.NOTIFY_SLACK.value == "notify.slack"

    def test_notify_email(self):
        assert ActionType.NOTIFY_EMAIL.value == "notify.email"

    def test_notify_pagerduty(self):
        assert ActionType.NOTIFY_PAGERDUTY.value == "notify.pagerduty"

    def test_jira_create_issue(self):
        assert ActionType.JIRA_CREATE_ISSUE.value == "jira.create_issue"

    def test_jira_update_issue(self):
        assert ActionType.JIRA_UPDATE_ISSUE.value == "jira.update_issue"

    def test_jira_add_comment(self):
        assert ActionType.JIRA_ADD_COMMENT.value == "jira.add_comment"

    def test_confluence_create_page(self):
        assert ActionType.CONFLUENCE_CREATE_PAGE.value == "confluence.create_page"

    def test_confluence_update_page(self):
        assert ActionType.CONFLUENCE_UPDATE_PAGE.value == "confluence.update_page"

    def test_workflow_approve(self):
        assert ActionType.WORKFLOW_APPROVE.value == "workflow.approve"

    def test_workflow_reject(self):
        assert ActionType.WORKFLOW_REJECT.value == "workflow.reject"

    def test_workflow_escalate(self):
        assert ActionType.WORKFLOW_ESCALATE.value == "workflow.escalate"

    def test_data_filter(self):
        assert ActionType.DATA_FILTER.value == "data.filter"

    def test_data_aggregate(self):
        assert ActionType.DATA_AGGREGATE.value == "data.aggregate"

    def test_data_transform(self):
        assert ActionType.DATA_TRANSFORM.value == "data.transform"

    def test_total_count(self):
        assert len(ActionType) == 25

    def test_str_enum(self):
        assert isinstance(ActionType.OPA_EVALUATE, str)

    def test_from_string(self):
        assert ActionType("opa.evaluate") == ActionType.OPA_EVALUATE

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            ActionType("invalid.action")


# ============================================================
# 4. PlaybookMetadata Dataclass
# ============================================================

class TestPlaybookMetadata:
    def test_minimal_creation(self):
        m = PlaybookMetadata(name="test", version="1.0.0")
        assert m.name == "test"
        assert m.version == "1.0.0"

    def test_defaults(self):
        m = PlaybookMetadata(name="n", version="v")
        assert m.description == ""
        assert m.author == ""
        assert m.license == "MIT"
        assert m.tags == []
        assert m.compliance_frameworks == []
        assert m.ssdlc_stages == []

    def test_full_creation(self):
        m = PlaybookMetadata(
            name="full",
            version="2.0",
            description="desc",
            author="auth",
            license="Apache-2.0",
            tags=["sec"],
            compliance_frameworks=["SOC2"],
            ssdlc_stages=["build"],
        )
        assert m.description == "desc"
        assert m.author == "auth"
        assert m.license == "Apache-2.0"
        assert m.tags == ["sec"]
        assert m.compliance_frameworks == ["SOC2"]
        assert m.ssdlc_stages == ["build"]

    def test_tags_are_independent_per_instance(self):
        m1 = PlaybookMetadata(name="a", version="1")
        m2 = PlaybookMetadata(name="b", version="1")
        m1.tags.append("x")
        assert "x" not in m2.tags


# ============================================================
# 5. StepCondition Dataclass
# ============================================================

class TestStepCondition:
    def test_defaults(self):
        c = StepCondition()
        assert c.when is None
        assert c.unless is None
        assert c.depends_on == []

    def test_with_when(self):
        c = StepCondition(when="severity == critical")
        assert c.when == "severity == critical"

    def test_with_unless(self):
        c = StepCondition(unless="dry_run == true")
        assert c.unless == "dry_run == true"

    def test_with_depends_on(self):
        c = StepCondition(depends_on=["step1", "step2"])
        assert c.depends_on == ["step1", "step2"]

    def test_depends_on_independent(self):
        c1 = StepCondition()
        c2 = StepCondition()
        c1.depends_on.append("x")
        assert "x" not in c2.depends_on


# ============================================================
# 6. StepResult Dataclass
# ============================================================

class TestStepResult:
    def test_minimal(self):
        r = StepResult(name="s1", status=StepStatus.PENDING)
        assert r.name == "s1"
        assert r.status == StepStatus.PENDING
        assert r.output is None
        assert r.error is None
        assert r.duration_ms == 0

    def test_to_dict_pending(self):
        r = StepResult(name="s1", status=StepStatus.PENDING)
        d = r.to_dict()
        assert d["name"] == "s1"
        assert d["status"] == "pending"
        assert d["output"] is None
        assert d["error"] is None
        assert d["started_at"] is None
        assert d["completed_at"] is None
        assert d["duration_ms"] == 0

    def test_to_dict_with_dates(self):
        now = datetime.now(timezone.utc)
        r = StepResult(name="s1", status=StepStatus.SUCCESS, started_at=now, completed_at=now)
        d = r.to_dict()
        assert d["started_at"] is not None
        assert d["completed_at"] is not None

    def test_to_dict_with_output(self):
        r = StepResult(name="s1", status=StepStatus.SUCCESS, output={"key": "val"})
        d = r.to_dict()
        assert d["output"] == {"key": "val"}

    def test_to_dict_with_error(self):
        r = StepResult(name="s1", status=StepStatus.FAILED, error="oops")
        d = r.to_dict()
        assert d["error"] == "oops"

    def test_duration_ms(self):
        r = StepResult(name="s1", status=StepStatus.SUCCESS, duration_ms=250)
        assert r.duration_ms == 250


# ============================================================
# 7. PlaybookStep Dataclass
# ============================================================

class TestPlaybookStep:
    def test_minimal(self):
        s = PlaybookStep(name="s1", action=ActionType.OPA_EVALUATE)
        assert s.name == "s1"
        assert s.action == ActionType.OPA_EVALUATE
        assert s.params == {}
        assert s.condition is None
        assert s.on_success is None
        assert s.on_failure is None
        assert s.timeout == "30s"

    def test_with_params(self):
        s = PlaybookStep(name="s1", action=ActionType.OPA_EVALUATE, params={"policy": "p1"})
        assert s.params["policy"] == "p1"

    def test_with_condition(self):
        cond = StepCondition(when="x == y")
        s = PlaybookStep(name="s1", action=ActionType.OPA_EVALUATE, condition=cond)
        assert s.condition.when == "x == y"

    def test_on_success_and_failure(self):
        s = PlaybookStep(
            name="s1",
            action=ActionType.OPA_EVALUATE,
            on_success={"set": {"done": "true"}},
            on_failure={"continue": True},
        )
        assert s.on_success["set"]["done"] == "true"
        assert s.on_failure["continue"] is True

    def test_custom_timeout(self):
        s = PlaybookStep(name="s1", action=ActionType.OPA_EVALUATE, timeout="60s")
        assert s.timeout == "60s"


# ============================================================
# 8. Playbook Dataclass
# ============================================================

class TestPlaybook:
    def test_minimal(self):
        pb = make_playbook()
        assert pb.api_version == "fixops/v1alpha1"
        assert pb.kind == PlaybookKind.PLAYBOOK

    def test_defaults(self):
        pb = make_playbook()
        assert pb.inputs == {}
        assert pb.conditions == {}
        assert pb.outputs == {}
        assert pb.triggers == []

    def test_with_inputs(self):
        pb = make_playbook(inputs={"app_id": {"required": True}})
        assert "app_id" in pb.inputs

    def test_steps_list(self):
        steps = [make_step("a"), make_step("b")]
        pb = make_playbook(steps=steps)
        assert len(pb.steps) == 2
        assert pb.steps[0].name == "a"
        assert pb.steps[1].name == "b"


# ============================================================
# 9. PlaybookExecutionContext
# ============================================================

class TestPlaybookExecutionContext:
    def test_minimal(self):
        ctx = make_context()
        assert ctx.inputs == {}
        assert ctx.variables == {}
        assert ctx.step_results == {}

    def test_compute_status_no_results(self):
        ctx = make_context()
        assert ctx._compute_status() == "pending"

    def test_compute_status_all_success(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.SUCCESS)
        ctx.step_results["s2"] = make_step_result("s2", StepStatus.SUCCESS)
        assert ctx._compute_status() == "completed"

    def test_compute_status_all_skipped(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.SKIPPED)
        assert ctx._compute_status() == "completed"

    def test_compute_status_mixed_success_skipped(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.SUCCESS)
        ctx.step_results["s2"] = make_step_result("s2", StepStatus.SKIPPED)
        assert ctx._compute_status() == "completed"

    def test_compute_status_has_failed(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.FAILED)
        assert ctx._compute_status() == "failed"

    def test_compute_status_has_running(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.RUNNING)
        assert ctx._compute_status() == "running"

    def test_compute_status_partial(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.SUCCESS)
        ctx.step_results["s2"] = make_step_result("s2", StepStatus.PENDING)
        assert ctx._compute_status() == "partial"

    def test_compute_summary_empty(self):
        ctx = make_context()
        s = ctx._compute_summary()
        assert s["total"] == 0
        assert s["success"] == 0
        assert s["failed"] == 0
        assert s["skipped"] == 0
        assert s["pending"] == 0

    def test_compute_summary_mixed(self):
        ctx = make_context()
        ctx.step_results["a"] = make_step_result("a", StepStatus.SUCCESS)
        ctx.step_results["b"] = make_step_result("b", StepStatus.FAILED)
        ctx.step_results["c"] = make_step_result("c", StepStatus.SKIPPED)
        ctx.step_results["d"] = make_step_result("d", StepStatus.PENDING)
        s = ctx._compute_summary()
        assert s["total"] == 4
        assert s["success"] == 1
        assert s["failed"] == 1
        assert s["skipped"] == 1
        assert s["pending"] == 1

    def test_to_dict_basic(self):
        ctx = make_context()
        ctx.completed_at = datetime.now(timezone.utc)
        d = ctx.to_dict()
        assert "playbook" in d
        assert d["playbook"]["name"] == "test"
        assert "inputs" in d
        assert "status" in d
        assert "summary" in d

    def test_to_dict_step_results(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.SUCCESS)
        d = ctx.to_dict()
        assert "s1" in d["step_results"]

    def test_to_dict_started_and_completed(self):
        ctx = make_context()
        ctx.started_at = datetime.now(timezone.utc)
        ctx.completed_at = datetime.now(timezone.utc)
        d = ctx.to_dict()
        assert d["started_at"] is not None
        assert d["completed_at"] is not None

    def test_to_dict_no_dates(self):
        pb = make_playbook()
        ctx = PlaybookExecutionContext(playbook=pb, inputs={})
        d = ctx.to_dict()
        assert d["started_at"] is None
        assert d["completed_at"] is None


# ============================================================
# 10. ValidationError Dataclass
# ============================================================

class TestValidationError:
    def test_minimal(self):
        e = ValidationError(path="metadata.name", message="required")
        assert e.path == "metadata.name"
        assert e.message == "required"
        assert e.severity == "error"

    def test_warning_severity(self):
        e = ValidationError(path="metadata.tags", message="optional", severity="warning")
        assert e.severity == "warning"

    def test_to_dict(self):
        e = ValidationError(path="spec.steps", message="empty", severity="error")
        d = e.to_dict()
        assert d["path"] == "spec.steps"
        assert d["message"] == "empty"
        assert d["severity"] == "error"


# ============================================================
# 11. PlaybookRunner Init & Handler Registration
# ============================================================

class TestPlaybookRunnerInit:
    def test_default_init_no_overlay(self):
        runner = PlaybookRunner()
        assert runner._overlay is None
        assert runner._connectors is None

    def test_all_handlers_registered(self):
        runner = PlaybookRunner()
        for action in ActionType:
            assert action in runner._action_handlers, f"Missing handler for {action}"

    def test_register_custom_handler(self):
        runner = PlaybookRunner()
        mock_handler = MagicMock()
        runner.register_handler(ActionType.OPA_EVALUATE, mock_handler)
        assert runner._action_handlers[ActionType.OPA_EVALUATE] is mock_handler

    def test_handler_count_matches_action_types(self):
        runner = PlaybookRunner()
        assert len(runner._action_handlers) == len(ActionType)

    def test_get_connectors_no_overlay(self):
        runner = PlaybookRunner()
        assert runner._get_connectors() is None

    def test_overlay_path_nonexistent_does_not_raise(self):
        # prepare_overlay with a nonexistent path uses defaults and does NOT raise
        # (the overlay runtime returns a default config when path not found)
        PlaybookRunner(overlay_path="/nonexistent/path.yaml")
        # Either None (load failed) or a default OverlayConfig — both are valid
        # What matters: no exception was raised during construction
        assert True  # If we reach here, no exception was raised


# ============================================================
# 12. load_playbook_from_string
# ============================================================

class TestLoadPlaybookFromString:
    def test_load_minimal_yaml(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        assert pb.metadata.name == "test-playbook"
        assert pb.metadata.version == "1.0.0"
        assert len(pb.steps) == 1

    def test_load_full_yaml(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(FULL_YAML)
        assert pb.metadata.name == "full-playbook"
        assert pb.metadata.version == "2.0.0"
        assert pb.metadata.author == "Test Author"
        assert pb.metadata.license == "Apache-2.0"
        assert pb.metadata.tags == ["security", "compliance"]

    def test_load_yaml_steps(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(FULL_YAML)
        assert len(pb.steps) == 2
        assert pb.steps[0].name == "check-policy"
        assert pb.steps[1].name == "create-ticket"

    def test_load_yaml_step_action(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        assert pb.steps[0].action == ActionType.OPA_EVALUATE

    def test_load_yaml_compliance_pack(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(COMPLIANCE_YAML)
        assert pb.kind == PlaybookKind.COMPLIANCE_PACK

    def test_load_json(self):
        runner = PlaybookRunner()
        data = {
            "apiVersion": "fixops/v1alpha1",
            "kind": "Playbook",
            "metadata": {"name": "json-pb", "version": "1.0.0"},
            "spec": {
                "steps": [
                    {"name": "s1", "action": "opa.evaluate", "params": {}}
                ]
            },
        }
        pb = runner.load_playbook_from_string(json.dumps(data), format="json")
        assert pb.metadata.name == "json-pb"

    def test_invalid_format_raises(self):
        runner = PlaybookRunner()
        with pytest.raises(ValueError, match="Unsupported format"):
            runner.load_playbook_from_string("data", format="xml")

    def test_step_condition_parsed(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(FULL_YAML)
        step2 = pb.steps[1]
        assert step2.condition is not None
        assert step2.condition.when == "inputs.severity_threshold == high"
        assert step2.condition.depends_on == ["check-policy"]

    def test_step_on_success_parsed(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(FULL_YAML)
        step2 = pb.steps[1]
        assert step2.on_success is not None
        assert step2.on_success["set"]["ticket_created"] == "true"

    def test_step_on_failure_parsed(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(FULL_YAML)
        step2 = pb.steps[1]
        assert step2.on_failure is not None
        assert step2.on_failure["continue"] is True

    def test_inputs_parsed(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(FULL_YAML)
        assert "app_id" in pb.inputs
        assert pb.inputs["app_id"]["required"] is True
        assert "severity_threshold" in pb.inputs
        assert pb.inputs["severity_threshold"]["default"] == "high"

    def test_compliance_frameworks_parsed(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(FULL_YAML)
        assert "SOC2" in pb.metadata.compliance_frameworks
        assert "ISO27001" in pb.metadata.compliance_frameworks

    def test_api_version_stored(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        assert pb.api_version == "fixops/v1alpha1"


# ============================================================
# 13. load_playbook (from file)
# ============================================================

class TestLoadPlaybookFromFile:
    def test_load_yaml_file(self, tmp_path):
        f = tmp_path / "pb.yaml"
        f.write_text(MINIMAL_YAML)
        runner = PlaybookRunner()
        pb = runner.load_playbook(str(f))
        assert pb.metadata.name == "test-playbook"

    def test_load_yml_extension(self, tmp_path):
        f = tmp_path / "pb.yml"
        f.write_text(MINIMAL_YAML)
        runner = PlaybookRunner()
        pb = runner.load_playbook(str(f))
        assert pb.metadata.version == "1.0.0"

    def test_load_json_file(self, tmp_path):
        f = tmp_path / "pb.json"
        data = {
            "apiVersion": "fixops/v1alpha1",
            "kind": "Playbook",
            "metadata": {"name": "file-json", "version": "1.0.0"},
            "spec": {"steps": [{"name": "s1", "action": "opa.evaluate", "params": {}}]},
        }
        f.write_text(json.dumps(data))
        runner = PlaybookRunner()
        pb = runner.load_playbook(str(f))
        assert pb.metadata.name == "file-json"

    def test_load_nonexistent_raises(self):
        runner = PlaybookRunner()
        with pytest.raises(FileNotFoundError):
            runner.load_playbook("/nonexistent/path.yaml")

    def test_unsupported_extension_raises(self, tmp_path):
        f = tmp_path / "pb.toml"
        f.write_text("key = value")
        runner = PlaybookRunner()
        with pytest.raises(ValueError, match="Unsupported file format"):
            runner.load_playbook(str(f))


# ============================================================
# 14. _parse_playbook — Error Cases
# ============================================================

class TestParsePlaybook:
    def test_missing_api_version_raises(self):
        runner = PlaybookRunner()
        with pytest.raises(ValueError, match="apiVersion"):
            runner._parse_playbook({
                "kind": "Playbook",
                "metadata": {"name": "x", "version": "1"},
                "spec": {"steps": []},
            })

    def test_missing_kind_raises(self):
        runner = PlaybookRunner()
        with pytest.raises(ValueError, match="kind"):
            runner._parse_playbook({
                "apiVersion": "v1",
                "metadata": {"name": "x", "version": "1"},
                "spec": {"steps": []},
            })

    def test_missing_metadata_raises(self):
        runner = PlaybookRunner()
        with pytest.raises(ValueError, match="metadata"):
            runner._parse_playbook({
                "apiVersion": "v1",
                "kind": "Playbook",
                "spec": {"steps": []},
            })

    def test_missing_spec_raises(self):
        runner = PlaybookRunner()
        with pytest.raises(ValueError, match="spec"):
            runner._parse_playbook({
                "apiVersion": "v1",
                "kind": "Playbook",
                "metadata": {"name": "x", "version": "1"},
            })

    def test_metadata_defaults(self):
        runner = PlaybookRunner()
        pb = runner._parse_playbook({
            "apiVersion": "v1",
            "kind": "Playbook",
            "metadata": {"name": "minimal"},
            "spec": {"steps": [{"name": "s1", "action": "opa.evaluate"}]},
        })
        assert pb.metadata.version == "1.0.0"
        assert pb.metadata.license == "MIT"


# ============================================================
# 15. validate_playbook
# ============================================================

class TestValidatePlaybook:
    def test_valid_playbook_no_errors(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        errors = runner.validate_playbook(pb)
        assert errors == []

    def test_missing_name_error(self):
        runner = PlaybookRunner()
        pb = make_playbook(metadata=PlaybookMetadata(name="", version="1.0.0"))
        errors = runner.validate_playbook(pb)
        paths = [e.path for e in errors]
        assert "metadata.name" in paths

    def test_missing_version_error(self):
        runner = PlaybookRunner()
        pb = make_playbook(metadata=PlaybookMetadata(name="x", version=""))
        errors = runner.validate_playbook(pb)
        paths = [e.path for e in errors]
        assert "metadata.version" in paths

    def test_no_steps_error(self):
        runner = PlaybookRunner()
        pb = make_playbook(steps=[])
        errors = runner.validate_playbook(pb)
        paths = [e.path for e in errors]
        assert "spec.steps" in paths

    def test_duplicate_step_names_error(self):
        runner = PlaybookRunner()
        pb = make_playbook(steps=[make_step("dup"), make_step("dup")])
        errors = runner.validate_playbook(pb)
        messages = [e.message for e in errors]
        assert any("Duplicate step name" in m for m in messages)

    def test_dependency_on_future_step_error(self):
        runner = PlaybookRunner()
        steps = [
            PlaybookStep(
                name="step1",
                action=ActionType.OPA_EVALUATE,
                condition=StepCondition(depends_on=["step2"]),  # step2 comes after
            ),
            PlaybookStep(name="step2", action=ActionType.OPA_EVALUATE),
        ]
        pb = make_playbook(steps=steps)
        errors = runner.validate_playbook(pb)
        assert len(errors) > 0

    def test_valid_dependency_no_error(self):
        runner = PlaybookRunner()
        steps = [
            PlaybookStep(name="step1", action=ActionType.OPA_EVALUATE),
            PlaybookStep(
                name="step2",
                action=ActionType.OPA_EVALUATE,
                condition=StepCondition(depends_on=["step1"]),
            ),
        ]
        pb = make_playbook(steps=steps)
        errors = runner.validate_playbook(pb)
        assert errors == []

    def test_validate_playbook_file_not_found(self):
        runner = PlaybookRunner()
        errors = runner.validate_playbook_file("/nonexistent/path.yaml")
        assert len(errors) == 1
        assert errors[0].path == "file"

    def test_validate_playbook_file_valid(self, tmp_path):
        runner = PlaybookRunner()
        f = tmp_path / "pb.yaml"
        f.write_text(MINIMAL_YAML)
        errors = runner.validate_playbook_file(str(f))
        assert errors == []


# ============================================================
# 16. _sarif_level_to_severity
# ============================================================

class TestSarifLevelToSeverity:
    def setup_method(self):
        self.runner = PlaybookRunner()

    def test_error_to_critical(self):
        assert self.runner._sarif_level_to_severity("error") == "critical"

    def test_warning_to_high(self):
        assert self.runner._sarif_level_to_severity("warning") == "high"

    def test_note_to_medium(self):
        assert self.runner._sarif_level_to_severity("note") == "medium"

    def test_none_to_low(self):
        assert self.runner._sarif_level_to_severity("none") == "low"

    def test_unknown_to_medium(self):
        assert self.runner._sarif_level_to_severity("unknown") == "medium"

    def test_case_insensitive(self):
        assert self.runner._sarif_level_to_severity("ERROR") == "critical"
        assert self.runner._sarif_level_to_severity("Warning") == "high"


# ============================================================
# 17. _extract_max_severity
# ============================================================

class TestExtractMaxSeverity:
    def setup_method(self):
        self.runner = PlaybookRunner()
        self.sev_order = ["low", "medium", "high", "critical"]

    def test_empty_dict(self):
        result = self.runner._extract_max_severity({}, self.sev_order)
        assert result is None

    def test_empty_list(self):
        result = self.runner._extract_max_severity([], self.sev_order)
        assert result is None

    def test_list_with_single_item(self):
        findings = [{"severity": "high"}]
        result = self.runner._extract_max_severity(findings, self.sev_order)
        assert result == "high"

    def test_list_returns_max(self):
        findings = [
            {"severity": "low"},
            {"severity": "critical"},
            {"severity": "medium"},
        ]
        result = self.runner._extract_max_severity(findings, self.sev_order)
        assert result == "critical"

    def test_sarif_dict_format(self):
        findings = {
            "runs": [
                {
                    "results": [
                        {"level": "warning"},
                        {"level": "error"},
                    ]
                }
            ]
        }
        result = self.runner._extract_max_severity(findings, self.sev_order)
        assert result == "critical"  # error -> critical

    def test_sarif_note_level(self):
        findings = {
            "runs": [{"results": [{"level": "note"}]}]
        }
        result = self.runner._extract_max_severity(findings, self.sev_order)
        assert result == "medium"

    def test_unknown_severity_in_list_ignored(self):
        findings = [{"severity": "unknown_value"}]
        result = self.runner._extract_max_severity(findings, self.sev_order)
        assert result is None

    def test_none_input(self):
        result = self.runner._extract_max_severity(None, self.sev_order)
        assert result is None


# ============================================================
# 18. _check_conditions
# ============================================================

class TestCheckConditions:
    def setup_method(self):
        self.runner = PlaybookRunner()

    def test_empty_conditions_pass(self):
        ctx = make_context()
        assert self.runner._check_conditions({}, ctx) is True

    def test_min_severity_met(self):
        findings = [{"severity": "critical"}]
        ctx = make_context(inputs={"findings": findings})
        assert self.runner._check_conditions({"min_severity": "high"}, ctx) is True

    def test_min_severity_not_met(self):
        findings = [{"severity": "low"}]
        ctx = make_context(inputs={"findings": findings})
        assert self.runner._check_conditions({"min_severity": "high"}, ctx) is False

    def test_min_severity_no_findings_fails(self):
        ctx = make_context(inputs={})
        assert self.runner._check_conditions({"min_severity": "high"}, ctx) is False

    def test_frameworks_match(self):
        pb = make_playbook(metadata=PlaybookMetadata(
            name="x", version="1", compliance_frameworks=["SOC2"]
        ))
        ctx = make_context(playbook=pb)
        assert self.runner._check_conditions({"frameworks": ["SOC2"]}, ctx) is True

    def test_frameworks_no_match(self):
        pb = make_playbook(metadata=PlaybookMetadata(
            name="x", version="1", compliance_frameworks=["SOC2"]
        ))
        ctx = make_context(playbook=pb)
        assert self.runner._check_conditions({"frameworks": ["ISO27001"]}, ctx) is False

    def test_frameworks_partial_match(self):
        pb = make_playbook(metadata=PlaybookMetadata(
            name="x", version="1", compliance_frameworks=["SOC2", "ISO27001"]
        ))
        ctx = make_context(playbook=pb)
        assert self.runner._check_conditions({"frameworks": ["ISO27001", "NIST"]}, ctx) is True


# ============================================================
# 19. _evaluate_expression
# ============================================================

class TestEvaluateExpression:
    def setup_method(self):
        self.runner = PlaybookRunner()

    def _ctx(self, inputs=None, variables=None) -> PlaybookExecutionContext:
        ctx = make_context(inputs=inputs or {})
        if variables:
            ctx.variables.update(variables)
        return ctx

    def test_true_literal(self):
        assert self.runner._evaluate_expression("true", self._ctx()) is True

    def test_false_literal(self):
        assert self.runner._evaluate_expression("false", self._ctx()) is False

    def test_yes_literal(self):
        assert self.runner._evaluate_expression("yes", self._ctx()) is True

    def test_no_literal(self):
        assert self.runner._evaluate_expression("no", self._ctx()) is False

    def test_one_literal(self):
        assert self.runner._evaluate_expression("1", self._ctx()) is True

    def test_zero_literal(self):
        assert self.runner._evaluate_expression("0", self._ctx()) is False

    def test_empty_string_false(self):
        assert self.runner._evaluate_expression("", self._ctx()) is False

    def test_equality_true(self):
        assert self.runner._evaluate_expression("foo == foo", self._ctx()) is True

    def test_equality_false(self):
        assert self.runner._evaluate_expression("foo == bar", self._ctx()) is False

    def test_equality_with_quotes(self):
        assert self.runner._evaluate_expression("'hello' == 'hello'", self._ctx()) is True

    def test_inequality_true(self):
        assert self.runner._evaluate_expression("foo != bar", self._ctx()) is True

    def test_inequality_false(self):
        assert self.runner._evaluate_expression("foo != foo", self._ctx()) is False

    def test_greater_than_true(self):
        assert self.runner._evaluate_expression("10 > 5", self._ctx()) is True

    def test_greater_than_false(self):
        assert self.runner._evaluate_expression("3 > 10", self._ctx()) is False

    def test_greater_than_invalid_returns_false(self):
        assert self.runner._evaluate_expression("abc > xyz", self._ctx()) is False

    def test_greater_than_or_equal_true(self):
        assert self.runner._evaluate_expression("5 >= 5", self._ctx()) is True

    def test_greater_than_or_equal_false(self):
        assert self.runner._evaluate_expression("4 >= 5", self._ctx()) is False

    def test_less_than_true(self):
        assert self.runner._evaluate_expression("3 < 10", self._ctx()) is True

    def test_less_than_false(self):
        assert self.runner._evaluate_expression("10 < 3", self._ctx()) is False

    def test_less_than_or_equal_true(self):
        assert self.runner._evaluate_expression("5 <= 5", self._ctx()) is True

    def test_less_than_or_equal_false(self):
        assert self.runner._evaluate_expression("6 <= 5", self._ctx()) is False

    def test_and_both_true(self):
        assert self.runner._evaluate_expression("true and true", self._ctx()) is True

    def test_and_one_false(self):
        assert self.runner._evaluate_expression("true and false", self._ctx()) is False

    def test_or_both_false(self):
        assert self.runner._evaluate_expression("false or false", self._ctx()) is False

    def test_or_one_true(self):
        assert self.runner._evaluate_expression("false or true", self._ctx()) is True

    def test_not_true(self):
        assert self.runner._evaluate_expression("not true", self._ctx()) is False

    def test_not_false(self):
        assert self.runner._evaluate_expression("not false", self._ctx()) is True

    def test_input_variable_resolution(self):
        ctx = self._ctx(inputs={"severity": "critical"})
        assert self.runner._evaluate_expression("{{ inputs.severity }} == critical", ctx) is True

    def test_input_variable_inequality(self):
        ctx = self._ctx(inputs={"severity": "low"})
        assert self.runner._evaluate_expression("{{ inputs.severity }} != critical", ctx) is True


# ============================================================
# 20. _resolve_template
# ============================================================

class TestResolveTemplate:
    def setup_method(self):
        self.runner = PlaybookRunner()

    def test_no_template_vars(self):
        ctx = make_context()
        result = self.runner._resolve_template("hello world", ctx)
        assert result == "hello world"

    def test_resolve_input_var(self):
        ctx = make_context(inputs={"app_id": "my-app"})
        result = self.runner._resolve_template("App: {{ inputs.app_id }}", ctx)
        assert result == "App: my-app"

    def test_resolve_variable_var(self):
        ctx = make_context()
        ctx.variables["ticket_id"] = "SEC-123"
        result = self.runner._resolve_template("Ticket: {{ variables.ticket_id }}", ctx)
        assert result == "Ticket: SEC-123"

    def test_unresolved_var_kept_as_is(self):
        ctx = make_context()
        result = self.runner._resolve_template("{{ inputs.missing }}", ctx)
        assert result == "{{ inputs.missing }}"

    def test_multiple_vars(self):
        ctx = make_context(inputs={"a": "1", "b": "2"})
        result = self.runner._resolve_template("{{ inputs.a }}-{{ inputs.b }}", ctx)
        assert result == "1-2"

    def test_step_status_resolution(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.SUCCESS)
        result = self.runner._resolve_template("{{ steps.s1.status }}", ctx)
        assert result == "success"

    def test_step_error_resolution(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.FAILED, error="boom")
        result = self.runner._resolve_template("{{ steps.s1.error }}", ctx)
        assert result == "boom"


# ============================================================
# 21. _get_value_by_path
# ============================================================

class TestGetValueByPath:
    def setup_method(self):
        self.runner = PlaybookRunner()

    def test_inputs_top_level(self):
        ctx = make_context(inputs={"x": 42})
        assert self.runner._get_value_by_path("inputs.x", ctx) == 42

    def test_inputs_nested(self):
        ctx = make_context(inputs={"obj": {"key": "val"}})
        assert self.runner._get_value_by_path("inputs.obj.key", ctx) == "val"

    def test_variables_path(self):
        ctx = make_context()
        ctx.variables["foo"] = "bar"
        assert self.runner._get_value_by_path("variables.foo", ctx) == "bar"

    def test_steps_status(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.SUCCESS)
        assert self.runner._get_value_by_path("steps.s1.status", ctx) == "success"

    def test_steps_error(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.FAILED, error="err")
        assert self.runner._get_value_by_path("steps.s1.error", ctx) == "err"

    def test_steps_output_nested(self):
        ctx = make_context()
        ctx.step_results["s1"] = make_step_result("s1", StepStatus.SUCCESS, output={"key": "val"})
        assert self.runner._get_value_by_path("steps.s1.output.key", ctx) == "val"

    def test_steps_missing_step_returns_none(self):
        ctx = make_context()
        assert self.runner._get_value_by_path("steps.missing.status", ctx) is None

    def test_unknown_root_returns_none(self):
        ctx = make_context()
        assert self.runner._get_value_by_path("unknown.something", ctx) is None

    def test_steps_short_path_returns_none(self):
        ctx = make_context()
        assert self.runner._get_value_by_path("steps", ctx) is None

    def test_inputs_missing_key(self):
        ctx = make_context(inputs={})
        assert self.runner._get_value_by_path("inputs.missing", ctx) is None


# ============================================================
# 22. _resolve_params
# ============================================================

class TestResolveParams:
    def setup_method(self):
        self.runner = PlaybookRunner()

    def test_simple_string_param(self):
        ctx = make_context(inputs={"x": "hello"})
        params = {"msg": "{{ inputs.x }}"}
        resolved = self.runner._resolve_params(params, ctx)
        assert resolved["msg"] == "hello"

    def test_non_string_param_unchanged(self):
        ctx = make_context()
        params = {"count": 42, "flag": True}
        resolved = self.runner._resolve_params(params, ctx)
        assert resolved["count"] == 42
        assert resolved["flag"] is True

    def test_nested_dict_params(self):
        ctx = make_context(inputs={"app": "myapp"})
        params = {"nested": {"key": "{{ inputs.app }}"}}
        resolved = self.runner._resolve_params(params, ctx)
        assert resolved["nested"]["key"] == "myapp"

    def test_list_params(self):
        ctx = make_context(inputs={"val": "x"})
        params = {"items": ["{{ inputs.val }}", "static"]}
        resolved = self.runner._resolve_params(params, ctx)
        assert resolved["items"] == ["x", "static"]

    def test_list_with_non_string(self):
        ctx = make_context()
        params = {"items": [1, 2, 3]}
        resolved = self.runner._resolve_params(params, ctx)
        assert resolved["items"] == [1, 2, 3]


# ============================================================
# 23. _validate_inputs
# ============================================================

class TestValidateInputs:
    def setup_method(self):
        self.runner = PlaybookRunner()

    def test_required_present_no_error(self):
        pb = make_playbook(inputs={"app_id": {"required": True}})
        inputs = {"app_id": "my-app"}
        self.runner._validate_inputs(pb, inputs)  # Should not raise

    def test_required_missing_raises(self):
        pb = make_playbook(inputs={"app_id": {"required": True}})
        with pytest.raises(ValueError, match="Missing required input: app_id"):
            self.runner._validate_inputs(pb, {})

    def test_optional_with_default_applied(self):
        pb = make_playbook(inputs={"threshold": {"required": False, "default": "medium"}})
        inputs = {}
        self.runner._validate_inputs(pb, inputs)
        assert inputs["threshold"] == "medium"

    def test_optional_present_not_overridden(self):
        pb = make_playbook(inputs={"threshold": {"required": False, "default": "medium"}})
        inputs = {"threshold": "high"}
        self.runner._validate_inputs(pb, inputs)
        assert inputs["threshold"] == "high"

    def test_no_inputs_spec_no_error(self):
        pb = make_playbook(inputs={})
        self.runner._validate_inputs(pb, {})  # Should not raise


# ============================================================
# 24. _check_step_condition
# ============================================================

class TestCheckStepCondition:
    def setup_method(self):
        self.runner = PlaybookRunner()

    def test_no_when_no_unless_passes(self):
        cond = StepCondition()
        ctx = make_context()
        assert self.runner._check_step_condition(cond, ctx) is True

    def test_when_true_passes(self):
        cond = StepCondition(when="true")
        ctx = make_context()
        assert self.runner._check_step_condition(cond, ctx) is True

    def test_when_false_fails(self):
        cond = StepCondition(when="false")
        ctx = make_context()
        assert self.runner._check_step_condition(cond, ctx) is False

    def test_unless_true_fails(self):
        cond = StepCondition(unless="true")
        ctx = make_context()
        assert self.runner._check_step_condition(cond, ctx) is False

    def test_unless_false_passes(self):
        cond = StepCondition(unless="false")
        ctx = make_context()
        assert self.runner._check_step_condition(cond, ctx) is True

    def test_when_with_input(self):
        cond = StepCondition(when="{{ inputs.flag }} == yes")
        ctx = make_context(inputs={"flag": "yes"})
        assert self.runner._check_step_condition(cond, ctx) is True


# ============================================================
# 25. Async Execute — dry_run mode
# ============================================================

class TestExecuteDryRun:
    def test_dry_run_returns_context(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        ctx = asyncio.run(runner.execute(pb, inputs={}, dry_run=True))
        assert ctx is not None
        assert "step1" in ctx.step_results

    def test_dry_run_step_output(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        ctx = asyncio.run(runner.execute(pb, inputs={}, dry_run=True))
        result = ctx.step_results["step1"]
        assert result.status == StepStatus.SUCCESS
        assert result.output["dry_run"] is True
        assert result.output["action"] == "opa.evaluate"

    def test_dry_run_params_resolved(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        ctx = asyncio.run(runner.execute(pb, inputs={}, dry_run=True))
        result = ctx.step_results["step1"]
        assert "params" in result.output

    def test_execute_sets_completed_at(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        ctx = asyncio.run(runner.execute(pb, inputs={}, dry_run=True))
        assert ctx.completed_at is not None

    def test_execute_sets_started_at(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        ctx = asyncio.run(runner.execute(pb, inputs={}, dry_run=True))
        assert ctx.started_at is not None


# ============================================================
# 26. execute_sync
# ============================================================

class TestExecuteSync:
    def test_execute_sync_returns_context(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        ctx = runner.execute_sync(pb, inputs={}, dry_run=True)
        assert ctx is not None
        assert ctx.step_results

    def test_execute_sync_status_completed(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        ctx = runner.execute_sync(pb, inputs={}, dry_run=True)
        assert ctx._compute_status() == "completed"


# ============================================================
# 27. Async Execute — Live Handlers (no connectors)
# ============================================================

class TestExecuteLiveHandlers:
    def test_opa_evaluate_handler(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        ctx = asyncio.run(runner.execute(pb, inputs={}, dry_run=False))
        result = ctx.step_results["step1"]
        assert result.status == StepStatus.SUCCESS
        assert "result" in result.output

    def test_jira_create_handler_no_connector(self):
        runner = PlaybookRunner()
        yaml_str = """
apiVersion: fixops/v1alpha1
kind: Playbook
metadata:
  name: jira-test
  version: 1.0.0
spec:
  steps:
    - name: create
      action: jira.create_issue
      params:
        summary: Test issue
"""
        pb = runner.load_playbook_from_string(yaml_str)
        ctx = asyncio.run(runner.execute(pb))
        assert ctx.step_results["create"].status == StepStatus.SUCCESS
        assert "issue_key" in ctx.step_results["create"].output

    def test_notify_slack_handler_no_connector(self):
        runner = PlaybookRunner()
        yaml_str = """
apiVersion: fixops/v1alpha1
kind: Playbook
metadata:
  name: slack-test
  version: 1.0.0
spec:
  steps:
    - name: notify
      action: notify.slack
      params:
        channel: "#security"
        message: "Test"
"""
        pb = runner.load_playbook_from_string(yaml_str)
        ctx = asyncio.run(runner.execute(pb))
        result = ctx.step_results["notify"]
        assert result.status == StepStatus.SUCCESS
        assert result.output["sent"] is True

    def test_data_filter_handler(self):
        runner = PlaybookRunner()
        yaml_str = """
apiVersion: fixops/v1alpha1
kind: Playbook
metadata:
  name: filter-test
  version: 1.0.0
spec:
  steps:
    - name: filter
      action: data.filter
      params:
        data:
          - {severity: critical}
          - {severity: low}
        field: severity
        value: critical
"""
        pb = runner.load_playbook_from_string(yaml_str)
        ctx = asyncio.run(runner.execute(pb))
        result = ctx.step_results["filter"]
        assert result.status == StepStatus.SUCCESS
        assert result.output["count"] == 1


# ============================================================
# 28. Step Skipping Due to Conditions
# ============================================================

class TestStepSkipping:
    def test_step_skipped_when_false(self):
        runner = PlaybookRunner()
        yaml_str = """
apiVersion: fixops/v1alpha1
kind: Playbook
metadata:
  name: cond-test
  version: 1.0.0
spec:
  steps:
    - name: skipped-step
      action: opa.evaluate
      params: {}
      condition:
        when: "false"
"""
        pb = runner.load_playbook_from_string(yaml_str)
        ctx = asyncio.run(runner.execute(pb, dry_run=True))
        assert ctx.step_results["skipped-step"].status == StepStatus.SKIPPED

    def test_step_runs_when_true(self):
        runner = PlaybookRunner()
        yaml_str = """
apiVersion: fixops/v1alpha1
kind: Playbook
metadata:
  name: cond-test2
  version: 1.0.0
spec:
  steps:
    - name: run-step
      action: opa.evaluate
      params: {}
      condition:
        when: "true"
"""
        pb = runner.load_playbook_from_string(yaml_str)
        ctx = asyncio.run(runner.execute(pb, dry_run=True))
        assert ctx.step_results["run-step"].status == StepStatus.SUCCESS


# ============================================================
# 29. Dependency Handling
# ============================================================

class TestDependencyHandling:
    def test_step_runs_after_successful_dependency(self):
        runner = PlaybookRunner()
        steps = [
            PlaybookStep(name="step1", action=ActionType.OPA_EVALUATE),
            PlaybookStep(
                name="step2",
                action=ActionType.OPA_EVALUATE,
                condition=StepCondition(depends_on=["step1"]),
            ),
        ]
        pb = make_playbook(steps=steps)
        ctx = asyncio.run(runner.execute(pb, dry_run=True))
        assert ctx.step_results["step1"].status == StepStatus.SUCCESS
        assert ctx.step_results["step2"].status == StepStatus.SUCCESS

    def test_step_skipped_if_dependency_failed(self):
        runner = PlaybookRunner()

        async def failing_handler(params, ctx):
            raise RuntimeError("intentional failure")

        runner.register_handler(ActionType.OPA_EVALUATE, failing_handler)

        steps = [
            PlaybookStep(
                name="step1",
                action=ActionType.OPA_EVALUATE,
                on_failure={"continue": True},
            ),
            PlaybookStep(
                name="step2",
                action=ActionType.NOTIFY_SLACK,
                condition=StepCondition(depends_on=["step1"]),
            ),
        ]
        pb = make_playbook(steps=steps)
        ctx = asyncio.run(runner.execute(pb, dry_run=False))
        assert ctx.step_results["step1"].status == StepStatus.FAILED
        assert ctx.step_results["step2"].status == StepStatus.SKIPPED

    def test_step_skipped_if_dependency_not_in_results(self):
        runner = PlaybookRunner()
        step = PlaybookStep(
            name="dependent",
            action=ActionType.OPA_EVALUATE,
            condition=StepCondition(depends_on=["nonexistent"]),
        )
        pb = make_playbook(steps=[step])
        ctx = asyncio.run(runner.execute(pb, dry_run=True))
        assert ctx.step_results["dependent"].status == StepStatus.SKIPPED
        assert "nonexistent" in ctx.step_results["dependent"].error


# ============================================================
# 30. on_failure continue
# ============================================================

class TestOnFailureContinue:
    def test_execution_stops_on_failure_default(self):
        runner = PlaybookRunner()

        async def failing_handler(params, ctx):
            raise RuntimeError("fail")

        runner.register_handler(ActionType.OPA_EVALUATE, failing_handler)

        steps = [
            PlaybookStep(name="step1", action=ActionType.OPA_EVALUATE),
            PlaybookStep(name="step2", action=ActionType.OPA_EVALUATE),
        ]
        pb = make_playbook(steps=steps)
        ctx = asyncio.run(runner.execute(pb, dry_run=False))
        assert ctx.step_results["step1"].status == StepStatus.FAILED
        assert "step2" not in ctx.step_results

    def test_execution_continues_on_failure_with_continue(self):
        runner = PlaybookRunner()
        call_count = {"n": 0}

        async def failing_handler(params, ctx):
            raise RuntimeError("fail")

        async def success_handler(params, ctx):
            call_count["n"] += 1
            return {"ok": True}

        runner.register_handler(ActionType.OPA_EVALUATE, failing_handler)
        runner.register_handler(ActionType.NOTIFY_SLACK, success_handler)

        steps = [
            PlaybookStep(
                name="step1",
                action=ActionType.OPA_EVALUATE,
                on_failure={"continue": True},
            ),
            PlaybookStep(name="step2", action=ActionType.NOTIFY_SLACK),
        ]
        pb = make_playbook(steps=steps)
        ctx = asyncio.run(runner.execute(pb, dry_run=False))
        assert ctx.step_results["step1"].status == StepStatus.FAILED
        assert ctx.step_results["step2"].status == StepStatus.SUCCESS
        assert call_count["n"] == 1


# ============================================================
# 31. on_success set variable
# ============================================================

class TestOnSuccessSet:
    def test_on_success_sets_variable(self):
        runner = PlaybookRunner()
        steps = [
            PlaybookStep(
                name="step1",
                action=ActionType.OPA_EVALUATE,
                on_success={"set": {"my_var": "my_value"}},
            ),
        ]
        pb = make_playbook(steps=steps)
        ctx = asyncio.run(runner.execute(pb, dry_run=True))
        assert ctx.variables["my_var"] == "my_value"


# ============================================================
# 32. Global Conditions Skipping Execution
# ============================================================

class TestGlobalConditionsSkip:
    def test_playbook_skipped_conditions_not_met(self):
        runner = PlaybookRunner()
        pb = make_playbook(conditions={"min_severity": "critical"})
        # No findings provided → condition not met → context returned immediately
        ctx = asyncio.run(runner.execute(pb, inputs={}))
        assert ctx.step_results == {}

    def test_playbook_runs_conditions_met(self):
        runner = PlaybookRunner()
        findings = [{"severity": "critical"}]
        pb = make_playbook(conditions={"min_severity": "high"})
        ctx = asyncio.run(runner.execute(pb, inputs={"findings": findings}, dry_run=True))
        assert ctx.step_results != {}


# ============================================================
# 33. Missing Required Input
# ============================================================

class TestMissingRequiredInput:
    def test_execute_raises_on_missing_required_input(self):
        runner = PlaybookRunner()
        pb = make_playbook(inputs={"app_id": {"required": True}})
        with pytest.raises(ValueError, match="Missing required input"):
            asyncio.run(runner.execute(pb, inputs={}))


# ============================================================
# 34. get_playbook_runner Singleton
# ============================================================

class TestGetPlaybookRunner:
    def test_returns_instance(self):
        import core.playbook_runner as _mod
        _mod._playbook_runner = None  # Reset singleton
        runner = get_playbook_runner()
        assert isinstance(runner, PlaybookRunner)

    def test_singleton_same_instance(self):
        import core.playbook_runner as _mod
        _mod._playbook_runner = None
        r1 = get_playbook_runner()
        r2 = get_playbook_runner()
        assert r1 is r2

    def test_reset_singleton_creates_new(self):
        import core.playbook_runner as _mod
        _mod._playbook_runner = None
        r1 = get_playbook_runner()
        _mod._playbook_runner = None
        r2 = get_playbook_runner()
        assert r1 is not r2


# ============================================================
# 35. All Action Handlers Execute Without Error
# ============================================================

class TestAllHandlers:
    """Verify every registered handler runs without raising (no connectors)."""

    def _run_single_action(self, action_value: str, params: dict) -> StepResult:
        runner = PlaybookRunner()
        yaml_str = f"""
apiVersion: fixops/v1alpha1
kind: Playbook
metadata:
  name: handler-test
  version: 1.0.0
spec:
  steps:
    - name: test-step
      action: {action_value}
      params: {{}}
"""
        pb = runner.load_playbook_from_string(yaml_str)
        ctx = asyncio.run(runner.execute(pb, inputs=params or {}, dry_run=False))
        return ctx.step_results["test-step"]

    def test_opa_evaluate_runs(self):
        r = self._run_single_action("opa.evaluate", {})
        assert r.status == StepStatus.SUCCESS

    def test_opa_assert_runs(self):
        r = self._run_single_action("opa.assert", {})
        assert r.status == StepStatus.SUCCESS

    def test_evidence_assert_runs(self):
        r = self._run_single_action("evidence.assert", {})
        assert r.status == StepStatus.SUCCESS

    def test_evidence_collect_runs(self):
        r = self._run_single_action("evidence.collect", {})
        assert r.status == StepStatus.SUCCESS

    def test_evidence_sign_runs(self):
        r = self._run_single_action("evidence.sign", {})
        assert r.status == StepStatus.SUCCESS

    def test_compliance_check_control_runs(self):
        r = self._run_single_action("compliance.check_control", {})
        assert r.status == StepStatus.SUCCESS

    def test_compliance_map_finding_runs(self):
        r = self._run_single_action("compliance.map_finding", {})
        assert r.status == StepStatus.SUCCESS

    def test_compliance_generate_report_runs(self):
        r = self._run_single_action("compliance.generate_report", {})
        assert r.status == StepStatus.SUCCESS

    def test_pentest_request_runs(self):
        r = self._run_single_action("pentest.request", {})
        assert r.status == StepStatus.SUCCESS

    def test_pentest_validate_exploitability_runs(self):
        r = self._run_single_action("pentest.validate_exploitability", {})
        assert r.status == StepStatus.SUCCESS

    def test_scanner_run_runs(self):
        r = self._run_single_action("scanner.run", {})
        assert r.status == StepStatus.SUCCESS

    def test_notify_slack_runs(self):
        r = self._run_single_action("notify.slack", {})
        assert r.status == StepStatus.SUCCESS

    def test_notify_email_runs(self):
        r = self._run_single_action("notify.email", {})
        assert r.status == StepStatus.SUCCESS

    def test_notify_pagerduty_runs(self):
        r = self._run_single_action("notify.pagerduty", {})
        assert r.status == StepStatus.SUCCESS

    def test_jira_create_issue_runs(self):
        r = self._run_single_action("jira.create_issue", {})
        assert r.status == StepStatus.SUCCESS

    def test_jira_update_issue_runs(self):
        r = self._run_single_action("jira.update_issue", {})
        assert r.status == StepStatus.SUCCESS

    def test_jira_add_comment_runs(self):
        r = self._run_single_action("jira.add_comment", {})
        assert r.status == StepStatus.SUCCESS

    def test_confluence_create_page_runs(self):
        r = self._run_single_action("confluence.create_page", {})
        assert r.status == StepStatus.SUCCESS

    def test_confluence_update_page_runs(self):
        r = self._run_single_action("confluence.update_page", {})
        assert r.status == StepStatus.SUCCESS

    def test_workflow_approve_runs(self):
        r = self._run_single_action("workflow.approve", {})
        assert r.status == StepStatus.SUCCESS

    def test_workflow_reject_runs(self):
        r = self._run_single_action("workflow.reject", {})
        assert r.status == StepStatus.SUCCESS

    def test_workflow_escalate_runs(self):
        r = self._run_single_action("workflow.escalate", {})
        assert r.status == StepStatus.SUCCESS

    def test_data_filter_runs(self):
        r = self._run_single_action("data.filter", {})
        assert r.status == StepStatus.SUCCESS

    def test_data_aggregate_runs(self):
        r = self._run_single_action("data.aggregate", {})
        assert r.status == StepStatus.SUCCESS

    def test_data_transform_runs(self):
        r = self._run_single_action("data.transform", {})
        assert r.status == StepStatus.SUCCESS


# ============================================================
# 36. Handler Output Verification
# ============================================================

class TestHandlerOutputs:
    def setup_method(self):
        self.runner = PlaybookRunner()
        self.ctx = make_context()

    def _run(self, handler, params):
        return asyncio.run(handler(params, self.ctx))

    def test_evidence_assert_output(self):
        out = self._run(self.runner._handle_evidence_assert, {"evidence_type": "SAST"})
        assert out["asserted"] is True
        assert out["evidence_type"] == "SAST"

    def test_evidence_sign_output(self):
        out = self._run(
            self.runner._handle_evidence_sign,
            {"evidence_id": "ev-001", "algorithm": "RSA-SHA256"},
        )
        assert out["signed"] is True
        assert out["evidence_id"] == "ev-001"
        assert out["algorithm"] == "RSA-SHA256"

    def test_evidence_sign_default_algorithm(self):
        out = self._run(self.runner._handle_evidence_sign, {"evidence_id": "ev-002"})
        assert out["algorithm"] == "RSA-SHA256"

    def test_pentest_validate_output(self):
        out = self._run(self.runner._handle_pentest_validate, {})
        assert out["exploitable"] is False
        assert out["confidence"] == 0.85

    def test_notify_email_output(self):
        out = self._run(self.runner._handle_notify_email, {"to": "sec@company.com"})
        assert out["sent"] is True
        assert out["to"] == "sec@company.com"

    def test_notify_pagerduty_output(self):
        out = self._run(self.runner._handle_notify_pagerduty, {})
        assert "incident_id" in out

    def test_workflow_approve_output(self):
        out = self._run(
            self.runner._handle_workflow_approve, {"workflow_id": "wf-123"}
        )
        assert out["approved"] is True
        assert out["workflow_id"] == "wf-123"

    def test_workflow_reject_output(self):
        out = self._run(
            self.runner._handle_workflow_reject, {"workflow_id": "wf-123"}
        )
        assert out["rejected"] is True

    def test_workflow_escalate_output(self):
        out = self._run(
            self.runner._handle_workflow_escalate, {"workflow_id": "wf-456"}
        )
        assert out["escalated"] is True

    def test_data_aggregate_output(self):
        out = self._run(self.runner._handle_data_aggregate, {})
        assert out["aggregated"] is True

    def test_data_transform_output(self):
        out = self._run(self.runner._handle_data_transform, {})
        assert out["transformed"] is True

    def test_compliance_map_output(self):
        out = self._run(
            self.runner._handle_compliance_map, {"framework": "SOC2"}
        )
        assert out["mapped"] is True
        assert out["framework"] == "SOC2"

    def test_compliance_report_output(self):
        out = self._run(
            self.runner._handle_compliance_report,
            {"framework": "ISO27001", "format": "html"},
        )
        assert "report_id" in out
        assert out["framework"] == "ISO27001"
        assert out["format"] == "html"

    def test_compliance_report_default_format(self):
        out = self._run(
            self.runner._handle_compliance_report, {"framework": "SOC2"}
        )
        assert out["format"] == "pdf"

    def test_data_filter_matching(self):
        params = {
            "data": [
                {"severity": "critical"},
                {"severity": "low"},
                {"severity": "critical"},
            ],
            "field": "severity",
            "value": "critical",
        }
        out = self._run(self.runner._handle_data_filter, params)
        assert out["count"] == 2
        assert len(out["data"]) == 2

    def test_data_filter_no_field(self):
        params = {"data": [{"x": 1}]}
        out = self._run(self.runner._handle_data_filter, params)
        assert out["count"] == 0

    def test_data_filter_non_list(self):
        params = {"data": {}, "field": "x", "value": "y"}
        out = self._run(self.runner._handle_data_filter, params)
        assert out["count"] == 0

    def test_jira_update_output(self):
        out = self._run(
            self.runner._handle_jira_update, {"issue_key": "SEC-123"}
        )
        assert out["updated"] is True
        assert out["issue_key"] == "SEC-123"

    def test_jira_comment_output(self):
        out = self._run(
            self.runner._handle_jira_comment, {"issue_key": "SEC-456"}
        )
        assert "comment_id" in out
        assert out["issue_key"] == "SEC-456"

    def test_confluence_update_output(self):
        out = self._run(
            self.runner._handle_confluence_update, {"page_id": "pg-007"}
        )
        assert out["updated"] is True
        assert out["page_id"] == "pg-007"

    def test_confluence_create_output(self):
        out = self._run(
            self.runner._handle_confluence_create, {"title": "My Page"}
        )
        assert "page_id" in out
        assert out["title"] == "My Page"

    def test_scanner_run_output(self):
        out = self._run(self.runner._handle_scanner_run, {})
        assert "scan_id" in out
        assert out["status"] == "completed"


# ============================================================
# 37. OPA Assert Behavior
# ============================================================

class TestOpaAssert:
    def test_opa_assert_passes_when_result_is_pass(self):
        runner = PlaybookRunner()
        ctx = make_context()
        # Default OPA evaluate returns "pass"
        result = asyncio.run(runner._handle_opa_assert({}, ctx))
        assert result["result"] == "pass"

    def test_opa_assert_raises_when_result_not_pass(self):
        runner = PlaybookRunner()
        ctx = make_context()

        # Patch _handle_opa_evaluate to return "fail"
        async def fake_evaluate(params, ctx):
            return {"result": "fail", "details": {}}

        runner._handle_opa_evaluate = fake_evaluate
        with pytest.raises(AssertionError, match="OPA assertion failed"):
            asyncio.run(runner._handle_opa_assert({}, ctx))


# ============================================================
# 38. Step Duration Calculation
# ============================================================

class TestStepDuration:
    def test_duration_calculated(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        ctx = asyncio.run(runner.execute(pb, dry_run=True))
        result = ctx.step_results["step1"]
        assert result.duration_ms >= 0

    def test_duration_is_non_negative(self):
        runner = PlaybookRunner()
        pb = runner.load_playbook_from_string(MINIMAL_YAML)
        ctx = asyncio.run(runner.execute(pb, dry_run=True))
        for r in ctx.step_results.values():
            assert r.duration_ms >= 0


# ============================================================
# 39. __all__ exports
# ============================================================

class TestAllExports:
    def test_all_exports_importable(self):
        import core.playbook_runner as mod
        for name in mod.__all__:
            assert hasattr(mod, name), f"{name} missing from module"

    def test_all_has_playbook_runner(self):
        import core.playbook_runner as mod
        assert "PlaybookRunner" in mod.__all__

    def test_all_has_get_playbook_runner(self):
        import core.playbook_runner as mod
        assert "get_playbook_runner" in mod.__all__

    def test_all_has_action_type(self):
        import core.playbook_runner as mod
        assert "ActionType" in mod.__all__

    def test_all_has_validation_error(self):
        import core.playbook_runner as mod
        assert "ValidationError" in mod.__all__
