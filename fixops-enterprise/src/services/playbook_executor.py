"""
FixOps Playbook Executor

This module provides the execution engine for FixOps Playbooks - declarative
specifications for vulnerability management automation. Playbooks allow users
to automate compliance tests, security validations, and remediation workflows
without arbitrary code execution.

Security: Playbooks are sandboxed and can only call pre-approved adapters.
No arbitrary code execution is permitted.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import yaml

logger = logging.getLogger(__name__)


class PlaybookKind(str, Enum):
    """Types of playbooks/packs."""

    PLAYBOOK = "Playbook"
    COMPLIANCE_PACK = "CompliancePack"
    TEST_PACK = "TestPack"
    MITIGATION_PACK = "MitigationPack"


class StepStatus(str, Enum):
    """Status of a playbook step."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class ActionType(str, Enum):
    """Pre-approved action types for playbooks."""

    # Policy Evaluation
    OPA_EVALUATE = "opa.evaluate"
    OPA_ASSERT = "opa.assert"

    # Evidence Management
    EVIDENCE_ASSERT = "evidence.assert"
    EVIDENCE_COLLECT = "evidence.collect"
    EVIDENCE_SIGN = "evidence.sign"

    # Compliance Checks
    COMPLIANCE_CHECK_CONTROL = "compliance.check_control"
    COMPLIANCE_MAP_FINDING = "compliance.map_finding"
    COMPLIANCE_GENERATE_REPORT = "compliance.generate_report"

    # Security Testing
    PENTEST_REQUEST = "pentest.request"
    PENTEST_VALIDATE_EXPLOITABILITY = "pentest.validate_exploitability"
    SCANNER_RUN = "scanner.run"

    # Notifications
    NOTIFY_SLACK = "notify.slack"
    NOTIFY_EMAIL = "notify.email"
    NOTIFY_PAGERDUTY = "notify.pagerduty"

    # Issue Tracking
    JIRA_CREATE_ISSUE = "jira.create_issue"
    JIRA_UPDATE_ISSUE = "jira.update_issue"
    JIRA_ADD_COMMENT = "jira.add_comment"

    # Documentation
    CONFLUENCE_CREATE_PAGE = "confluence.create_page"
    CONFLUENCE_UPDATE_PAGE = "confluence.update_page"

    # Workflow Control
    WORKFLOW_APPROVE = "workflow.approve"
    WORKFLOW_REJECT = "workflow.reject"
    WORKFLOW_ESCALATE = "workflow.escalate"

    # Data Operations
    DATA_FILTER = "data.filter"
    DATA_AGGREGATE = "data.aggregate"
    DATA_TRANSFORM = "data.transform"


@dataclass
class PlaybookMetadata:
    """Metadata for a playbook."""

    name: str
    version: str
    description: str = ""
    author: str = ""
    license: str = "MIT"
    tags: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    ssdlc_stages: List[str] = field(default_factory=list)


@dataclass
class StepCondition:
    """Condition for step execution."""

    when: Optional[str] = None
    unless: Optional[str] = None
    depends_on: List[str] = field(default_factory=list)


@dataclass
class StepResult:
    """Result of a playbook step execution."""

    name: str
    status: StepStatus
    output: Any = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: int = 0


@dataclass
class PlaybookStep:
    """A single step in a playbook."""

    name: str
    action: ActionType
    params: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[StepCondition] = None
    on_success: Optional[Dict[str, Any]] = None
    on_failure: Optional[Dict[str, Any]] = None
    timeout: str = "30s"


@dataclass
class Playbook:
    """A FixOps Playbook."""

    api_version: str
    kind: PlaybookKind
    metadata: PlaybookMetadata
    steps: List[PlaybookStep]
    inputs: Dict[str, Any] = field(default_factory=dict)
    conditions: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    triggers: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PlaybookExecutionContext:
    """Context for playbook execution."""

    playbook: Playbook
    inputs: Dict[str, Any]
    variables: Dict[str, Any] = field(default_factory=dict)
    step_results: Dict[str, StepResult] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class PlaybookExecutor:
    """
    Executor for FixOps Playbooks.

    This class provides a sandboxed execution environment for playbooks,
    ensuring that only pre-approved adapters can be called.
    """

    def __init__(self) -> None:
        """Initialize the playbook executor."""
        self._action_handlers: Dict[ActionType, Callable[..., Any]] = {}
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register default action handlers."""
        # Policy Evaluation
        self._action_handlers[ActionType.OPA_EVALUATE] = self._handle_opa_evaluate
        self._action_handlers[ActionType.OPA_ASSERT] = self._handle_opa_assert

        # Evidence Management
        self._action_handlers[ActionType.EVIDENCE_ASSERT] = self._handle_evidence_assert
        self._action_handlers[
            ActionType.EVIDENCE_COLLECT
        ] = self._handle_evidence_collect
        self._action_handlers[ActionType.EVIDENCE_SIGN] = self._handle_evidence_sign

        # Compliance Checks
        self._action_handlers[
            ActionType.COMPLIANCE_CHECK_CONTROL
        ] = self._handle_compliance_check_control
        self._action_handlers[
            ActionType.COMPLIANCE_MAP_FINDING
        ] = self._handle_compliance_map_finding
        self._action_handlers[
            ActionType.COMPLIANCE_GENERATE_REPORT
        ] = self._handle_compliance_generate_report

        # Security Testing
        self._action_handlers[ActionType.PENTEST_REQUEST] = self._handle_pentest_request
        self._action_handlers[
            ActionType.PENTEST_VALIDATE_EXPLOITABILITY
        ] = self._handle_pentest_validate_exploitability
        self._action_handlers[ActionType.SCANNER_RUN] = self._handle_scanner_run

        # Notifications
        self._action_handlers[ActionType.NOTIFY_SLACK] = self._handle_notify_slack
        self._action_handlers[ActionType.NOTIFY_EMAIL] = self._handle_notify_email
        self._action_handlers[
            ActionType.NOTIFY_PAGERDUTY
        ] = self._handle_notify_pagerduty

        # Issue Tracking
        self._action_handlers[
            ActionType.JIRA_CREATE_ISSUE
        ] = self._handle_jira_create_issue
        self._action_handlers[
            ActionType.JIRA_UPDATE_ISSUE
        ] = self._handle_jira_update_issue
        self._action_handlers[
            ActionType.JIRA_ADD_COMMENT
        ] = self._handle_jira_add_comment

        # Documentation
        self._action_handlers[
            ActionType.CONFLUENCE_CREATE_PAGE
        ] = self._handle_confluence_create_page
        self._action_handlers[
            ActionType.CONFLUENCE_UPDATE_PAGE
        ] = self._handle_confluence_update_page

        # Workflow Control
        self._action_handlers[
            ActionType.WORKFLOW_APPROVE
        ] = self._handle_workflow_approve
        self._action_handlers[ActionType.WORKFLOW_REJECT] = self._handle_workflow_reject
        self._action_handlers[
            ActionType.WORKFLOW_ESCALATE
        ] = self._handle_workflow_escalate

        # Data Operations
        self._action_handlers[ActionType.DATA_FILTER] = self._handle_data_filter
        self._action_handlers[ActionType.DATA_AGGREGATE] = self._handle_data_aggregate
        self._action_handlers[ActionType.DATA_TRANSFORM] = self._handle_data_transform

    def register_handler(self, action: ActionType, handler: Callable[..., Any]) -> None:
        """Register a custom handler for an action type."""
        self._action_handlers[action] = handler

    def load_playbook(self, path: Union[str, Path]) -> Playbook:
        """Load a playbook from a YAML or JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Playbook not found: {path}")

        content = path.read_text()
        if path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(content)
        elif path.suffix == ".json":
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported file format: {path.suffix}")

        return self._parse_playbook(data)

    def load_playbook_from_string(self, content: str, format: str = "yaml") -> Playbook:
        """Load a playbook from a string."""
        if format == "yaml":
            data = yaml.safe_load(content)
        elif format == "json":
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported format: {format}")

        return self._parse_playbook(data)

    def _parse_playbook(self, data: Dict[str, Any]) -> Playbook:
        """Parse playbook data into a Playbook object."""
        # Validate required fields
        if "apiVersion" not in data:
            raise ValueError("Missing required field: apiVersion")
        if "kind" not in data:
            raise ValueError("Missing required field: kind")
        if "metadata" not in data:
            raise ValueError("Missing required field: metadata")
        if "spec" not in data:
            raise ValueError("Missing required field: spec")

        # Parse metadata
        meta_data = data["metadata"]
        metadata = PlaybookMetadata(
            name=meta_data.get("name", ""),
            version=meta_data.get("version", "1.0.0"),
            description=meta_data.get("description", ""),
            author=meta_data.get("author", ""),
            license=meta_data.get("license", "MIT"),
            tags=meta_data.get("tags", []),
            compliance_frameworks=meta_data.get("compliance_frameworks", []),
            ssdlc_stages=meta_data.get("ssdlc_stages", []),
        )

        # Parse spec
        spec = data["spec"]
        steps = []
        for step_data in spec.get("steps", []):
            condition = None
            if "condition" in step_data:
                cond_data = step_data["condition"]
                condition = StepCondition(
                    when=cond_data.get("when"),
                    unless=cond_data.get("unless"),
                    depends_on=cond_data.get("depends_on", []),
                )

            step = PlaybookStep(
                name=step_data.get("name", ""),
                action=ActionType(step_data.get("action", "")),
                params=step_data.get("params", {}),
                condition=condition,
                on_success=step_data.get("on_success"),
                on_failure=step_data.get("on_failure"),
                timeout=step_data.get("timeout", "30s"),
            )
            steps.append(step)

        return Playbook(
            api_version=data["apiVersion"],
            kind=PlaybookKind(data["kind"]),
            metadata=metadata,
            steps=steps,
            inputs=spec.get("inputs", {}),
            conditions=spec.get("conditions", {}),
            outputs=spec.get("outputs", {}),
            triggers=spec.get("triggers", []),
        )

    async def execute(
        self,
        playbook: Playbook,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> PlaybookExecutionContext:
        """Execute a playbook with the given inputs."""
        context = PlaybookExecutionContext(
            playbook=playbook,
            inputs=inputs or {},
            started_at=datetime.utcnow(),
        )

        # Validate inputs
        self._validate_inputs(playbook, context.inputs)

        # Check global conditions
        if not self._check_conditions(playbook.conditions, context):
            logger.info(
                f"Playbook {playbook.metadata.name} conditions not met, skipping"
            )
            context.completed_at = datetime.utcnow()
            return context

        # Execute steps
        for step in playbook.steps:
            result = await self._execute_step(step, context)
            context.step_results[step.name] = result

            # Check if we should continue
            if result.status == StepStatus.FAILED:
                on_failure = step.on_failure or {}
                if not on_failure.get("continue", False):
                    logger.error(
                        f"Step {step.name} failed, stopping playbook execution"
                    )
                    break

        context.completed_at = datetime.utcnow()
        return context

    def _validate_inputs(self, playbook: Playbook, inputs: Dict[str, Any]) -> None:
        """Validate playbook inputs."""
        for name, spec in playbook.inputs.items():
            if spec.get("required", False) and name not in inputs:
                raise ValueError(f"Missing required input: {name}")

            if name not in inputs and "default" in spec:
                inputs[name] = spec["default"]

    def _check_conditions(
        self, conditions: Dict[str, Any], context: PlaybookExecutionContext
    ) -> bool:
        """Check if global conditions are met.

        Conditions are evaluated against the execution context inputs.
        If any condition is not met, the playbook execution is skipped.
        """
        if not conditions:
            return True

        severity_order = ["low", "medium", "high", "critical"]

        # Check severity conditions
        if "min_severity" in conditions:
            min_severity = conditions["min_severity"]
            findings = context.inputs.get("findings", {})

            # Extract severity from findings (SARIF format or list of findings)
            max_finding_severity = None
            if isinstance(findings, dict):
                runs = findings.get("runs", [])
                for run in runs:
                    for result in run.get("results", []):
                        level = result.get("level", "warning")
                        severity = self._sarif_level_to_severity(level)
                        if max_finding_severity is None or severity_order.index(
                            severity
                        ) > severity_order.index(max_finding_severity):
                            max_finding_severity = severity
            elif isinstance(findings, list):
                for finding in findings:
                    severity = finding.get("severity", "low").lower()
                    if severity in severity_order:
                        if max_finding_severity is None or severity_order.index(
                            severity
                        ) > severity_order.index(max_finding_severity):
                            max_finding_severity = severity

            # If no findings or max severity below threshold, skip playbook
            if max_finding_severity is None:
                logger.info(
                    f"No findings found, min_severity condition ({min_severity}) not met"
                )
                return False

            min_idx = severity_order.index(min_severity.lower())
            max_idx = severity_order.index(max_finding_severity)
            if max_idx < min_idx:
                logger.info(
                    f"Max finding severity ({max_finding_severity}) below "
                    f"min_severity threshold ({min_severity})"
                )
                return False

        # Check framework conditions
        if "frameworks" in conditions:
            required_frameworks = conditions["frameworks"]
            playbook_frameworks = context.playbook.metadata.compliance_frameworks

            # Check if playbook declares at least one of the required frameworks
            if not any(fw in playbook_frameworks for fw in required_frameworks):
                logger.info(
                    f"Playbook frameworks {playbook_frameworks} do not match "
                    f"required frameworks {required_frameworks}"
                )
                return False

        # Check KEV condition
        if "has_kev" in conditions:
            requires_kev = conditions["has_kev"]
            findings = context.inputs.get("findings", {})

            has_kev_finding = False
            if isinstance(findings, dict):
                runs = findings.get("runs", [])
                for run in runs:
                    for result in run.get("results", []):
                        props = result.get("properties", {})
                        if props.get("kev", False) or props.get("is_kev", False):
                            has_kev_finding = True
                            break
            elif isinstance(findings, list):
                for finding in findings:
                    if finding.get("kev", False) or finding.get("is_kev", False):
                        has_kev_finding = True
                        break

            if requires_kev and not has_kev_finding:
                logger.info("has_kev condition requires KEV findings but none found")
                return False
            if not requires_kev and has_kev_finding:
                logger.info("has_kev=false condition not met, KEV findings present")
                return False

        # Check EPSS threshold
        if "epss_threshold" in conditions:
            threshold = float(conditions["epss_threshold"])
            findings = context.inputs.get("findings", {})

            max_epss = 0.0
            if isinstance(findings, dict):
                runs = findings.get("runs", [])
                for run in runs:
                    for result in run.get("results", []):
                        props = result.get("properties", {})
                        epss = props.get("epss", 0.0)
                        if isinstance(epss, (int, float)) and epss > max_epss:
                            max_epss = epss
            elif isinstance(findings, list):
                for finding in findings:
                    epss = finding.get("epss", 0.0)
                    if isinstance(epss, (int, float)) and epss > max_epss:
                        max_epss = epss

            if max_epss < threshold:
                logger.info(
                    f"Max EPSS score ({max_epss}) below threshold ({threshold})"
                )
                return False

        return True

    def _sarif_level_to_severity(self, level: str) -> str:
        """Convert SARIF level to severity string."""
        level_map = {
            "error": "critical",
            "warning": "high",
            "note": "medium",
            "none": "low",
        }
        return level_map.get(level.lower(), "medium")

    async def _execute_step(
        self, step: PlaybookStep, context: PlaybookExecutionContext
    ) -> StepResult:
        """Execute a single playbook step."""
        result = StepResult(
            name=step.name,
            status=StepStatus.PENDING,
            started_at=datetime.utcnow(),
        )

        # Check step conditions
        if step.condition:
            if not self._check_step_condition(step.condition, context):
                result.status = StepStatus.SKIPPED
                result.completed_at = datetime.utcnow()
                return result

        # Check dependencies
        if step.condition and step.condition.depends_on:
            for dep in step.condition.depends_on:
                if dep not in context.step_results:
                    result.status = StepStatus.SKIPPED
                    result.error = f"Dependency not found: {dep}"
                    result.completed_at = datetime.utcnow()
                    return result
                if context.step_results[dep].status != StepStatus.SUCCESS:
                    result.status = StepStatus.SKIPPED
                    result.error = f"Dependency failed: {dep}"
                    result.completed_at = datetime.utcnow()
                    return result

        # Execute the action
        result.status = StepStatus.RUNNING
        try:
            handler = self._action_handlers.get(step.action)
            if not handler:
                raise ValueError(f"No handler for action: {step.action}")

            # Resolve template variables in params
            resolved_params = self._resolve_params(step.params, context)

            output = await handler(resolved_params, context)
            result.output = output
            result.status = StepStatus.SUCCESS

            # Handle on_success
            if step.on_success:
                if "set" in step.on_success:
                    context.variables.update(step.on_success["set"])

        except Exception as e:
            logger.exception(f"Step {step.name} failed: {e}")
            result.status = StepStatus.FAILED
            result.error = str(e)

            # Handle on_failure
            if step.on_failure:
                retry_count = step.on_failure.get("retry", 0)
                if retry_count > 0:
                    # Retry logic would go here
                    pass

        result.completed_at = datetime.utcnow()
        if result.started_at:
            result.duration_ms = int(
                (result.completed_at - result.started_at).total_seconds() * 1000
            )

        return result

    def _check_step_condition(
        self, condition: StepCondition, context: PlaybookExecutionContext
    ) -> bool:
        """Check if a step condition is met."""
        if condition.when:
            if not self._evaluate_expression(condition.when, context):
                return False

        if condition.unless:
            if self._evaluate_expression(condition.unless, context):
                return False

        return True

    def _evaluate_expression(
        self, expression: str, context: PlaybookExecutionContext
    ) -> bool:
        """
        Evaluate a simple expression.

        Supported expressions:
        - severity == critical
        - steps.step_name.status == 'failed'
        - inputs.value > 10
        """
        # Simple expression parser (production would use a proper parser)
        # This is a safe subset that doesn't allow arbitrary code execution

        # Replace template variables
        resolved = self._resolve_template(expression, context)

        # Simple equality check
        if "==" in resolved:
            parts = resolved.split("==")
            if len(parts) == 2:
                left = parts[0].strip().strip("'\"")
                right = parts[1].strip().strip("'\"")
                return left == right

        # Simple comparison
        if ">" in resolved:
            parts = resolved.split(">")
            if len(parts) == 2:
                try:
                    left = float(parts[0].strip())
                    right = float(parts[1].strip())
                    return left > right
                except ValueError:
                    return False

        if "<" in resolved:
            parts = resolved.split("<")
            if len(parts) == 2:
                try:
                    left = float(parts[0].strip())
                    right = float(parts[1].strip())
                    return left < right
                except ValueError:
                    return False

        return False

    def _resolve_params(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Resolve template variables in parameters."""
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str):
                resolved[key] = self._resolve_template(value, context)
            elif isinstance(value, dict):
                resolved[key] = self._resolve_params(value, context)
            elif isinstance(value, list):
                resolved[key] = [
                    self._resolve_template(v, context) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                resolved[key] = value
        return resolved

    def _resolve_template(
        self, template: str, context: PlaybookExecutionContext
    ) -> str:
        """Resolve template variables in a string."""
        # Match {{ variable }} patterns
        pattern = r"\{\{\s*([^}]+)\s*\}\}"

        def replace(match: re.Match[str]) -> str:
            path = match.group(1).strip()
            value = self._get_value_by_path(path, context)
            return str(value) if value is not None else match.group(0)

        return re.sub(pattern, replace, template)

    def _get_value_by_path(self, path: str, context: PlaybookExecutionContext) -> Any:
        """Get a value from context by dot-notation path."""
        parts = path.split(".")

        if parts[0] == "inputs":
            obj: Any = context.inputs
            parts = parts[1:]
        elif parts[0] == "steps":
            if len(parts) < 2:
                return None
            step_name = parts[1]
            if step_name not in context.step_results:
                return None
            result = context.step_results[step_name]
            if len(parts) == 2:
                return result
            if parts[2] == "status":
                return result.status.value
            if parts[2] == "output":
                obj = result.output
                parts = parts[3:]
            else:
                return None
        elif parts[0] == "variables":
            obj = context.variables
            parts = parts[1:]
        else:
            return None

        for part in parts:
            if isinstance(obj, dict):
                obj = obj.get(part)
            elif hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                return None

        return obj

    # Action Handlers (stub implementations - would integrate with actual services)

    async def _handle_opa_evaluate(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle OPA policy evaluation."""
        logger.info(f"OPA evaluate: {params}")
        return {"result": "pass", "details": {}}

    async def _handle_opa_assert(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle OPA policy assertion."""
        logger.info(f"OPA assert: {params}")
        return {"result": "pass", "details": {}}

    async def _handle_evidence_assert(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle evidence assertion."""
        logger.info(f"Evidence assert: {params}")
        return {"asserted": True}

    async def _handle_evidence_collect(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle evidence collection."""
        logger.info(f"Evidence collect: {params}")
        return {"collected": True, "evidence_id": "ev-001"}

    async def _handle_evidence_sign(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle evidence signing."""
        logger.info(f"Evidence sign: {params}")
        return {"signed": True, "signature": "sig-001"}

    async def _handle_compliance_check_control(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle compliance control check."""
        logger.info(f"Compliance check control: {params}")
        return {"status": "pass", "control": params.get("control", "")}

    async def _handle_compliance_map_finding(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle compliance finding mapping."""
        logger.info(f"Compliance map finding: {params}")
        return {"mapped": True}

    async def _handle_compliance_generate_report(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle compliance report generation."""
        logger.info(f"Compliance generate report: {params}")
        return {"report_id": "rpt-001"}

    async def _handle_pentest_request(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle pentest request."""
        logger.info(f"Pentest request: {params}")
        return {"request_id": "pt-001", "status": "queued"}

    async def _handle_pentest_validate_exploitability(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle exploitability validation."""
        logger.info(f"Pentest validate exploitability: {params}")
        return {"exploitable": False, "confidence": 0.85}

    async def _handle_scanner_run(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle scanner run."""
        logger.info(f"Scanner run: {params}")
        return {"scan_id": "scan-001", "status": "completed"}

    async def _handle_notify_slack(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle Slack notification."""
        logger.info(f"Notify Slack: {params}")
        return {"sent": True, "channel": params.get("channel", "")}

    async def _handle_notify_email(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle email notification."""
        logger.info(f"Notify email: {params}")
        return {"sent": True}

    async def _handle_notify_pagerduty(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle PagerDuty notification."""
        logger.info(f"Notify PagerDuty: {params}")
        return {"incident_id": "pd-001"}

    async def _handle_jira_create_issue(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle Jira issue creation."""
        logger.info(f"Jira create issue: {params}")
        return {"issue_key": "SEC-001", "issue_id": "10001"}

    async def _handle_jira_update_issue(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle Jira issue update."""
        logger.info(f"Jira update issue: {params}")
        return {"updated": True}

    async def _handle_jira_add_comment(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle Jira comment addition."""
        logger.info(f"Jira add comment: {params}")
        return {"comment_id": "c-001"}

    async def _handle_confluence_create_page(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle Confluence page creation."""
        logger.info(f"Confluence create page: {params}")
        return {"page_id": "pg-001"}

    async def _handle_confluence_update_page(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle Confluence page update."""
        logger.info(f"Confluence update page: {params}")
        return {"updated": True}

    async def _handle_workflow_approve(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle workflow approval."""
        logger.info(f"Workflow approve: {params}")
        return {"approved": True}

    async def _handle_workflow_reject(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle workflow rejection."""
        logger.info(f"Workflow reject: {params}")
        return {"rejected": True}

    async def _handle_workflow_escalate(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle workflow escalation."""
        logger.info(f"Workflow escalate: {params}")
        return {"escalated": True}

    async def _handle_data_filter(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle data filtering."""
        logger.info(f"Data filter: {params}")
        return {"filtered": True, "count": 0}

    async def _handle_data_aggregate(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle data aggregation."""
        logger.info(f"Data aggregate: {params}")
        return {"aggregated": True}

    async def _handle_data_transform(
        self, params: Dict[str, Any], context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Handle data transformation."""
        logger.info(f"Data transform: {params}")
        return {"transformed": True}


# Singleton instance
_playbook_executor: Optional[PlaybookExecutor] = None


def get_playbook_executor() -> PlaybookExecutor:
    """Get the singleton playbook executor instance."""
    global _playbook_executor
    if _playbook_executor is None:
        _playbook_executor = PlaybookExecutor()
    return _playbook_executor
