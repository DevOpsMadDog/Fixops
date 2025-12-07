"""API router for Pentagi pen testing integration."""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.pentagi_db import PentagiDB
from core.pentagi_models import (
    ApprovalState,
    ExploitabilityLevel,
    MicroTestCategory,
    MicroTestLifecycle,
    MicroTestPlaybook,
    MicroTestRun,
    MicroTestRunStatus,
    PenTestConfig,
    PenTestPriority,
    PenTestRequest,
    PenTestResult,
    PenTestStatus,
)

router = APIRouter(prefix="/api/v1/pentagi", tags=["pentagi"])
db = PentagiDB()


class CreatePenTestRequestModel(BaseModel):
    """Model for creating pen test request."""

    finding_id: str
    target_url: str
    vulnerability_type: str
    test_case: str
    priority: str = "medium"


class UpdatePenTestRequestModel(BaseModel):
    """Model for updating pen test request."""

    status: Optional[str] = None
    pentagi_job_id: Optional[str] = None


class CreatePenTestResultModel(BaseModel):
    """Model for creating pen test result."""

    request_id: str
    finding_id: str
    exploitability: str
    exploit_successful: bool
    evidence: str
    steps_taken: List[str] = Field(default_factory=list)
    artifacts: List[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    execution_time_seconds: float = 0.0


class CreatePenTestConfigModel(BaseModel):
    """Model for creating Pentagi configuration."""

    name: str
    pentagi_url: str
    api_key: Optional[str] = None
    enabled: bool = True
    max_concurrent_tests: int = 5
    timeout_seconds: int = 300
    auto_trigger: bool = False
    target_environments: List[str] = Field(default_factory=list)


class UpdatePenTestConfigModel(BaseModel):
    """Model for updating Pentagi configuration."""

    pentagi_url: Optional[str] = None
    api_key: Optional[str] = None
    enabled: Optional[bool] = None
    max_concurrent_tests: Optional[int] = None
    timeout_seconds: Optional[int] = None
    auto_trigger: Optional[bool] = None
    target_environments: Optional[List[str]] = None


class CreateMicroTestPlaybookModel(BaseModel):
    """Model for creating micro pen test playbooks."""

    name: str
    description: str
    category: str
    lifecycle: str = MicroTestLifecycle.DRAFT.value
    severity_focus: List[str] = Field(default_factory=list)
    target_types: List[str] = Field(default_factory=list)
    prerequisites: List[str] = Field(default_factory=list)
    tooling_profile: List[str] = Field(default_factory=list)
    controls_required: List[str] = Field(default_factory=list)
    estimated_runtime_seconds: int = 600
    max_execution_seconds: int = 900
    version: str = "1.0.0"
    owner: Optional[str] = None
    enabled: bool = True
    compliance_tags: List[str] = Field(default_factory=list)
    guardrails: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)


class UpdateMicroTestPlaybookModel(BaseModel):
    """Model for updating micro pen test playbooks."""

    description: Optional[str] = None
    category: Optional[str] = None
    lifecycle: Optional[str] = None
    severity_focus: Optional[List[str]] = None
    target_types: Optional[List[str]] = None
    prerequisites: Optional[List[str]] = None
    tooling_profile: Optional[List[str]] = None
    controls_required: Optional[List[str]] = None
    estimated_runtime_seconds: Optional[int] = None
    max_execution_seconds: Optional[int] = None
    version: Optional[str] = None
    owner: Optional[str] = None
    enabled: Optional[bool] = None
    compliance_tags: Optional[List[str]] = None
    guardrails: Optional[dict] = None
    metadata: Optional[dict] = None


class CreateMicroTestRunModel(BaseModel):
    """Model for scheduling/executing micro test runs."""

    playbook_id: str
    request_id: Optional[str] = None
    tenant_id: Optional[str] = None
    priority: str = PenTestPriority.MEDIUM.value
    approval_state: str = ApprovalState.NOT_REQUIRED.value
    runner_label: Optional[str] = None
    runner_location: Optional[str] = None
    scheduled_at: Optional[datetime] = None
    commands: List[str] = Field(default_factory=list)
    policy_blockers: List[str] = Field(default_factory=list)
    telemetry: dict = Field(default_factory=dict)
    risk_score: float = 0.0


class UpdateMicroTestRunModel(BaseModel):
    """Model for updating micro test runs."""

    status: Optional[str] = None
    approval_state: Optional[str] = None
    runner_label: Optional[str] = None
    runner_location: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    evidence_path: Optional[str] = None
    artifacts: Optional[List[str]] = None
    commands: Optional[List[str]] = None
    results: Optional[dict] = None
    policy_blockers: Optional[List[str]] = None
    telemetry: Optional[dict] = None
    risk_score: Optional[float] = None


@router.get("/requests")
def list_pen_test_requests(
    finding_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List pen test requests."""
    status_enum = PenTestStatus(status) if status else None
    requests = db.list_requests(
        finding_id=finding_id, status=status_enum, limit=limit, offset=offset
    )
    return {"items": [r.to_dict() for r in requests], "total": len(requests)}


@router.post("/requests", status_code=201)
def create_pen_test_request(data: CreatePenTestRequestModel):
    """Create a new pen test request."""
    request = PenTestRequest(
        id="",
        finding_id=data.finding_id,
        target_url=data.target_url,
        vulnerability_type=data.vulnerability_type,
        test_case=data.test_case,
        priority=PenTestPriority(data.priority),
    )
    created = db.create_request(request)
    return created.to_dict()


@router.get("/requests/{request_id}")
def get_pen_test_request(request_id: str):
    """Get a pen test request by ID."""
    request = db.get_request(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Pen test request not found")
    return request.to_dict()


@router.put("/requests/{request_id}")
def update_pen_test_request(request_id: str, data: UpdatePenTestRequestModel):
    """Update a pen test request."""
    request = db.get_request(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Pen test request not found")

    if data.status:
        request.status = PenTestStatus(data.status)
    if data.pentagi_job_id:
        request.pentagi_job_id = data.pentagi_job_id

    updated = db.update_request(request)
    return updated.to_dict()


@router.post("/requests/{request_id}/start")
def start_pen_test(request_id: str):
    """Start a pen test."""
    request = db.get_request(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Pen test request not found")

    request.status = PenTestStatus.RUNNING
    from datetime import datetime

    request.started_at = datetime.utcnow()
    updated = db.update_request(request)

    return {"status": "started", "request": updated.to_dict()}


@router.post("/requests/{request_id}/cancel")
def cancel_pen_test(request_id: str):
    """Cancel a pen test."""
    request = db.get_request(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Pen test request not found")

    request.status = PenTestStatus.CANCELLED
    from datetime import datetime

    request.completed_at = datetime.utcnow()
    updated = db.update_request(request)

    return {"status": "cancelled", "request": updated.to_dict()}


@router.get("/results")
def list_pen_test_results(
    finding_id: Optional[str] = Query(None),
    exploitability: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List pen test results."""
    exploitability_enum = (
        ExploitabilityLevel(exploitability) if exploitability else None
    )
    results = db.list_results(
        finding_id=finding_id,
        exploitability=exploitability_enum,
        limit=limit,
        offset=offset,
    )
    return {"items": [r.to_dict() for r in results], "total": len(results)}


@router.post("/results", status_code=201)
def create_pen_test_result(data: CreatePenTestResultModel):
    """Create a new pen test result."""
    result = PenTestResult(
        id="",
        request_id=data.request_id,
        finding_id=data.finding_id,
        exploitability=ExploitabilityLevel(data.exploitability),
        exploit_successful=data.exploit_successful,
        evidence=data.evidence,
        steps_taken=data.steps_taken,
        artifacts=data.artifacts,
        confidence_score=data.confidence_score,
        execution_time_seconds=data.execution_time_seconds,
    )
    created = db.create_result(result)

    request = db.get_request(data.request_id)
    if request:
        request.status = PenTestStatus.COMPLETED
        from datetime import datetime

        request.completed_at = datetime.utcnow()
        db.update_request(request)

    return created.to_dict()


@router.get("/results/by-request/{request_id}")
def get_pen_test_result_by_request(request_id: str):
    """Get pen test result by request ID."""
    result = db.get_result_by_request(request_id)
    if not result:
        raise HTTPException(status_code=404, detail="Pen test result not found")
    return result.to_dict()


@router.get("/configs")
def list_pen_test_configs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List Pentagi configurations."""
    configs = db.list_configs(limit=limit, offset=offset)
    return {"items": [c.to_dict() for c in configs], "total": len(configs)}


@router.post("/configs", status_code=201)
def create_pen_test_config(data: CreatePenTestConfigModel):
    """Create a new Pentagi configuration."""
    config = PenTestConfig(
        id="",
        name=data.name,
        pentagi_url=data.pentagi_url,
        api_key=data.api_key,
        enabled=data.enabled,
        max_concurrent_tests=data.max_concurrent_tests,
        timeout_seconds=data.timeout_seconds,
        auto_trigger=data.auto_trigger,
        target_environments=data.target_environments,
    )
    created = db.create_config(config)
    return created.to_dict()


@router.get("/configs/{config_id}")
def get_pen_test_config(config_id: str):
    """Get Pentagi configuration by ID."""
    config = db.get_config(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Pentagi configuration not found")
    return config.to_dict()


@router.put("/configs/{config_id}")
def update_pen_test_config(config_id: str, data: UpdatePenTestConfigModel):
    """Update Pentagi configuration."""
    config = db.get_config(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Pentagi configuration not found")

    if data.pentagi_url is not None:
        config.pentagi_url = data.pentagi_url
    if data.api_key is not None:
        config.api_key = data.api_key
    if data.enabled is not None:
        config.enabled = data.enabled
    if data.max_concurrent_tests is not None:
        config.max_concurrent_tests = data.max_concurrent_tests
    if data.timeout_seconds is not None:
        config.timeout_seconds = data.timeout_seconds
    if data.auto_trigger is not None:
        config.auto_trigger = data.auto_trigger
    if data.target_environments is not None:
        config.target_environments = data.target_environments

    updated = db.update_config(config)
    return updated.to_dict()


@router.delete("/configs/{config_id}")
def delete_pen_test_config(config_id: str):
    """Delete Pentagi configuration."""
    deleted = db.delete_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Pentagi configuration not found")
    return {"status": "deleted"}


@router.get("/micro-tests")
def list_micro_tests(
    category: Optional[str] = Query(None),
    lifecycle: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List micro pen test playbooks."""
    try:
        category_enum = MicroTestCategory(category) if category else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid category value") from None

    try:
        lifecycle_enum = MicroTestLifecycle(lifecycle) if lifecycle else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid lifecycle value") from None

    playbooks = db.list_micro_test_playbooks(
        category=category_enum,
        lifecycle=lifecycle_enum,
        enabled=enabled,
        limit=limit,
        offset=offset,
    )
    return {"items": [p.to_dict() for p in playbooks], "total": len(playbooks)}


@router.post("/micro-tests", status_code=201)
def create_micro_test_playbook(data: CreateMicroTestPlaybookModel):
    """Create micro pen test playbook."""
    try:
        category = MicroTestCategory(data.category)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid category value") from None

    try:
        lifecycle = MicroTestLifecycle(data.lifecycle)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid lifecycle value") from None

    playbook = MicroTestPlaybook(
        id="",
        name=data.name,
        description=data.description,
        category=category,
        lifecycle=lifecycle,
        severity_focus=data.severity_focus,
        target_types=data.target_types,
        prerequisites=data.prerequisites,
        tooling_profile=data.tooling_profile,
        controls_required=data.controls_required,
        estimated_runtime_seconds=data.estimated_runtime_seconds,
        max_execution_seconds=data.max_execution_seconds,
        version=data.version,
        owner=data.owner,
        enabled=data.enabled,
        compliance_tags=data.compliance_tags,
        guardrails=data.guardrails,
        metadata=data.metadata,
    )
    created = db.create_micro_test_playbook(playbook)
    return created.to_dict()


@router.get("/micro-tests/{playbook_id}")
def get_micro_test_playbook(playbook_id: str):
    """Get micro test playbook."""
    playbook = db.get_micro_test_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Micro test playbook not found")
    return playbook.to_dict()


@router.put("/micro-tests/{playbook_id}")
def update_micro_test_playbook(
    playbook_id: str, data: UpdateMicroTestPlaybookModel
):
    """Update micro test playbook."""
    playbook = db.get_micro_test_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Micro test playbook not found")

    if data.description is not None:
        playbook.description = data.description
    if data.category is not None:
        try:
            playbook.category = MicroTestCategory(data.category)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid category value") from None
    if data.lifecycle is not None:
        try:
            playbook.lifecycle = MicroTestLifecycle(data.lifecycle)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid lifecycle value") from None
    if data.severity_focus is not None:
        playbook.severity_focus = data.severity_focus
    if data.target_types is not None:
        playbook.target_types = data.target_types
    if data.prerequisites is not None:
        playbook.prerequisites = data.prerequisites
    if data.tooling_profile is not None:
        playbook.tooling_profile = data.tooling_profile
    if data.controls_required is not None:
        playbook.controls_required = data.controls_required
    if data.estimated_runtime_seconds is not None:
        playbook.estimated_runtime_seconds = data.estimated_runtime_seconds
    if data.max_execution_seconds is not None:
        playbook.max_execution_seconds = data.max_execution_seconds
    if data.version is not None:
        playbook.version = data.version
    if data.owner is not None:
        playbook.owner = data.owner
    if data.enabled is not None:
        playbook.enabled = data.enabled
    if data.compliance_tags is not None:
        playbook.compliance_tags = data.compliance_tags
    if data.guardrails is not None:
        playbook.guardrails = data.guardrails
    if data.metadata is not None:
        playbook.metadata = data.metadata

    updated = db.update_micro_test_playbook(playbook)
    return updated.to_dict()


@router.delete("/micro-tests/{playbook_id}")
def delete_micro_test_playbook(playbook_id: str):
    """Delete micro test playbook."""
    deleted = db.delete_micro_test_playbook(playbook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Micro test playbook not found")
    return {"status": "deleted"}


@router.get("/micro-test-runs")
def list_micro_test_runs(
    playbook_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    request_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List micro test runs."""
    try:
        status_enum = MicroTestRunStatus(status) if status else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid status value") from None

    runs = db.list_micro_test_runs(
        playbook_id=playbook_id,
        status=status_enum,
        request_id=request_id,
        limit=limit,
        offset=offset,
    )
    return {"items": [r.to_dict() for r in runs], "total": len(runs)}


@router.post("/micro-test-runs", status_code=201)
def create_micro_test_run(data: CreateMicroTestRunModel):
    """Create micro test run."""
    playbook = db.get_micro_test_playbook(data.playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Micro test playbook not found")

    try:
        priority = PenTestPriority(data.priority)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid priority value") from None

    try:
        approval_state = ApprovalState(data.approval_state)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid approval state value"
        ) from None

    run = MicroTestRun(
        id="",
        playbook_id=data.playbook_id,
        status=MicroTestRunStatus.QUEUED,
        priority=priority,
        approval_state=approval_state,
        request_id=data.request_id,
        tenant_id=data.tenant_id,
        runner_label=data.runner_label,
        runner_location=data.runner_location,
        scheduled_at=data.scheduled_at,
        commands=data.commands,
        policy_blockers=data.policy_blockers,
        telemetry=data.telemetry,
        risk_score=data.risk_score,
    )

    created = db.create_micro_test_run(run)
    return created.to_dict()


@router.get("/micro-test-runs/{run_id}")
def get_micro_test_run(run_id: str):
    """Get micro test run."""
    run = db.get_micro_test_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Micro test run not found")
    return run.to_dict()


@router.put("/micro-test-runs/{run_id}")
def update_micro_test_run(run_id: str, data: UpdateMicroTestRunModel):
    """Update micro test run."""
    run = db.get_micro_test_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Micro test run not found")

    if data.status is not None:
        try:
            run.status = MicroTestRunStatus(data.status)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status value") from None
    if data.approval_state is not None:
        try:
            run.approval_state = ApprovalState(data.approval_state)
        except ValueError:
            raise HTTPException(
                status_code=400, detail="Invalid approval state value"
            ) from None
    if data.runner_label is not None:
        run.runner_label = data.runner_label
    if data.runner_location is not None:
        run.runner_location = data.runner_location
    if data.started_at is not None:
        run.started_at = data.started_at
    if data.completed_at is not None:
        run.completed_at = data.completed_at
    if data.evidence_path is not None:
        run.evidence_path = data.evidence_path
    if data.artifacts is not None:
        run.artifacts = data.artifacts
    if data.commands is not None:
        run.commands = data.commands
    if data.results is not None:
        run.results = data.results
    if data.policy_blockers is not None:
        run.policy_blockers = data.policy_blockers
    if data.telemetry is not None:
        run.telemetry = data.telemetry
    if data.risk_score is not None:
        run.risk_score = data.risk_score

    updated = db.update_micro_test_run(run)
    return updated.to_dict()
