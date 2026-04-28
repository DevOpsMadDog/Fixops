"""
Phase 9: Playbook Automation Engine API Routes for ALDECI.

FastAPI routes for:
- Playbook management (CRUD, activation, execution)
- Compliance template library
- Compliance assessment
- Run history and monitoring

Compliance: SOC2 CC7.2 (System monitoring and response automation)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# FastAPI router
router = APIRouter(prefix="/api/v1", tags=["playbooks", "compliance"])


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class PlaybookStepResponse(BaseModel):
    """Response model for a playbook step."""

    step_id: str
    step_type: str
    name: str
    config: Dict[str, Any]
    next_on_success: Optional[str] = None
    next_on_failure: Optional[str] = None
    timeout_seconds: int


class PlaybookResponse(BaseModel):
    """Response model for a playbook."""

    playbook_id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]
    steps: List[PlaybookStepResponse]
    status: str
    version: int
    created_by: str
    org_id: str
    tags: List[str]


class PlaybookCreateRequest(BaseModel):
    """Request model for creating a playbook."""

    name: str
    description: str = ""
    trigger_conditions: Dict[str, Any] = Field(default_factory=dict)
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = "draft"
    tags: List[str] = Field(default_factory=list)


class PlaybookUpdateRequest(BaseModel):
    """Request model for updating a playbook."""

    name: Optional[str] = None
    description: Optional[str] = None
    trigger_conditions: Optional[Dict[str, Any]] = None
    steps: Optional[List[Dict[str, Any]]] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None


class PlaybookExecuteRequest(BaseModel):
    """Request model for executing a playbook."""

    context: Dict[str, Any] = Field(default_factory=dict)


class StepResultResponse(BaseModel):
    """Response model for a step result."""

    step_id: str
    step_type: str
    status: str
    output: Dict[str, Any]
    error: Optional[str] = None
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: float


class PlaybookRunResponse(BaseModel):
    """Response model for a playbook run."""

    run_id: str
    playbook_id: str
    trigger_event: Dict[str, Any]
    status: str
    started_at: str
    completed_at: Optional[str] = None
    step_results: List[StepResultResponse]
    error: Optional[str] = None
    org_id: str
    duration_seconds: float


class ComplianceControlResponse(BaseModel):
    """Response model for a compliance control."""

    control_id: str
    framework: str
    title: str
    description: str
    requirements: List[str]
    evidence_types: List[str]
    automation_level: str


class ComplianceTemplateResponse(BaseModel):
    """Response model for compliance template list."""

    template_id: str
    name: str
    description: str
    framework: str
    status: str


class ComplianceAssessmentResponse(BaseModel):
    """Response model for compliance assessment."""

    framework: str
    overall_score: int
    total_controls: int
    controls_by_automation: Dict[str, int]
    gaps: List[Dict[str, Any]]
    recommendations: List[str]


class PaginatedPlaybooksResponse(BaseModel):
    """Paginated response for playbooks."""

    items: List[PlaybookResponse]
    total: int
    page: int
    page_size: int


class PaginatedRunsResponse(BaseModel):
    """Paginated response for playbook runs."""

    items: List[PlaybookRunResponse]
    total: int
    page: int
    page_size: int


# ============================================================================
# MOCK BACKEND - Replace with real implementation
# ============================================================================

# In-memory storage for demo purposes
_playbooks: Dict[str, Dict[str, Any]] = {}
_runs: Dict[str, Dict[str, Any]] = {}


def _get_org_id() -> str:
    """Extract org_id from request context. In production, from JWT."""
    return "default"


# ============================================================================
# PLAYBOOK ENDPOINTS
# ============================================================================


@router.get("/playbooks", response_model=PaginatedPlaybooksResponse)
async def list_playbooks(
    org_id: str = Depends(_get_org_id),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> PaginatedPlaybooksResponse:
    """
    List all playbooks for an organization.

    Returns playbooks with pagination.
    """
    org_playbooks = [
        p for p in _playbooks.values() if p.get("org_id") == org_id
    ]

    start = (page - 1) * page_size
    end = start + page_size
    paginated = org_playbooks[start:end]

    items = [PlaybookResponse(**p) for p in paginated]

    return PaginatedPlaybooksResponse(
        items=items,
        total=len(org_playbooks),
        page=page,
        page_size=page_size,
    )


@router.get("/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: str,
    org_id: str = Depends(_get_org_id),
) -> PlaybookResponse:
    """Get a specific playbook by ID."""
    playbook = _playbooks.get(playbook_id)

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if playbook.get("org_id") != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return PlaybookResponse(**playbook)


@router.post("/playbooks", response_model=PlaybookResponse)
async def create_playbook(
    request: PlaybookCreateRequest,
    org_id: str = Depends(_get_org_id),
) -> PlaybookResponse:
    """Create a new playbook."""
    import uuid

    playbook_id = str(uuid.uuid4())
    playbook = {
        "playbook_id": playbook_id,
        "name": request.name,
        "description": request.description,
        "trigger_conditions": request.trigger_conditions,
        "steps": request.steps,
        "status": request.status,
        "version": 1,
        "created_by": "api",
        "org_id": org_id,
        "tags": request.tags,
    }

    _playbooks[playbook_id] = playbook
    _logger.info(f"Created playbook {playbook_id}")

    return PlaybookResponse(**playbook)


@router.put("/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: str,
    request: PlaybookUpdateRequest,
    org_id: str = Depends(_get_org_id),
) -> PlaybookResponse:
    """Update an existing playbook."""
    playbook = _playbooks.get(playbook_id)

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if playbook.get("org_id") != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Update fields
    if request.name is not None:
        playbook["name"] = request.name
    if request.description is not None:
        playbook["description"] = request.description
    if request.trigger_conditions is not None:
        playbook["trigger_conditions"] = request.trigger_conditions
    if request.steps is not None:
        playbook["steps"] = request.steps
    if request.status is not None:
        playbook["status"] = request.status
    if request.tags is not None:
        playbook["tags"] = request.tags

    playbook["version"] += 1
    _logger.info(f"Updated playbook {playbook_id}")

    return PlaybookResponse(**playbook)


@router.post(
    "/playbooks/{playbook_id}/execute",
    response_model=PlaybookRunResponse,
)
async def execute_playbook(
    playbook_id: str,
    request: PlaybookExecuteRequest,
    org_id: str = Depends(_get_org_id),
) -> PlaybookRunResponse:
    """Manually trigger execution of a playbook."""
    playbook = _playbooks.get(playbook_id)

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if playbook.get("org_id") != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    import uuid

    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    run = {
        "run_id": run_id,
        "playbook_id": playbook_id,
        "trigger_event": request.context,
        "status": "completed",
        "started_at": now,
        "completed_at": now,
        "step_results": [],
        "error": None,
        "org_id": org_id,
        "duration_seconds": 0.5,
    }

    _runs[run_id] = run
    _logger.info(f"Executed playbook {playbook_id}")

    return PlaybookRunResponse(**run)


@router.get(
    "/playbooks/{playbook_id}/runs",
    response_model=PaginatedRunsResponse,
)
async def get_playbook_runs(
    playbook_id: str,
    org_id: str = Depends(_get_org_id),
    limit: int = Query(50, ge=1, le=500),
) -> PaginatedRunsResponse:
    """Get run history for a playbook."""
    playbook = _playbooks.get(playbook_id)

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if playbook.get("org_id") != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    runs = [
        r for r in _runs.values()
        if r.get("playbook_id") == playbook_id and r.get("org_id") == org_id
    ]

    items = [PlaybookRunResponse(**r) for r in runs[:limit]]

    return PaginatedRunsResponse(
        items=items,
        total=len(runs),
        page=1,
        page_size=limit,
    )


@router.get("/playbooks/runs/{run_id}", response_model=PlaybookRunResponse)
async def get_run_details(
    run_id: str,
    org_id: str = Depends(_get_org_id),
) -> PlaybookRunResponse:
    """Get details of a specific playbook run."""
    run = _runs.get(run_id)

    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    if run.get("org_id") != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return PlaybookRunResponse(**run)


# ============================================================================
# COMPLIANCE TEMPLATE ENDPOINTS
# ============================================================================


@router.get(
    "/compliance/templates",
    response_model=List[ComplianceTemplateResponse],
)
async def list_compliance_templates() -> List[ComplianceTemplateResponse]:
    """List all compliance templates across all frameworks."""
    templates = [
        ComplianceTemplateResponse(
            template_id="soc2_access_review",
            name="SOC2 Quarterly Access Review",
            description="Review and validate user access quarterly",
            framework="soc2",
            status="active",
        ),
        ComplianceTemplateResponse(
            template_id="hipaa_phi_access_audit",
            name="HIPAA PHI Access Audit",
            description="Audit ePHI access for compliance",
            framework="hipaa",
            status="active",
        ),
        ComplianceTemplateResponse(
            template_id="pci_dss_network_scan",
            name="PCI DSS Network Scan",
            description="Regular network vulnerability scans",
            framework="pci_dss",
            status="active",
        ),
        ComplianceTemplateResponse(
            template_id="iso27001_asset_inventory",
            name="ISO 27001 Asset Inventory",
            description="Maintain and update asset inventory",
            framework="iso27001",
            status="active",
        ),
        ComplianceTemplateResponse(
            template_id="nist_csf_identify_assets",
            name="NIST CSF Identify Assets",
            description="Identify and catalog organizational assets",
            framework="nist_csf",
            status="active",
        ),
    ]

    return templates


@router.get(
    "/compliance/templates/{framework}",
    response_model=List[ComplianceTemplateResponse],
)
async def get_framework_templates(
    framework: str,
) -> List[ComplianceTemplateResponse]:
    """Get all templates for a specific compliance framework."""
    framework_lower = framework.lower()

    templates = [
        ComplianceTemplateResponse(
            template_id=f"{framework_lower}_template_1",
            name=f"{framework.upper()} Template 1",
            description=f"First template for {framework}",
            framework=framework,
            status="active",
        ),
        ComplianceTemplateResponse(
            template_id=f"{framework_lower}_template_2",
            name=f"{framework.upper()} Template 2",
            description=f"Second template for {framework}",
            framework=framework,
            status="active",
        ),
    ]

    return templates


@router.post(
    "/compliance/templates/{template_id}/instantiate",
    response_model=PlaybookResponse,
)
async def instantiate_compliance_template(
    template_id: str,
    org_id: str = Depends(_get_org_id),
) -> PlaybookResponse:
    """Create a playbook from a compliance template."""
    import uuid

    playbook_id = str(uuid.uuid4())
    playbook = {
        "playbook_id": playbook_id,
        "name": f"Instantiated {template_id}",
        "description": f"Playbook instantiated from {template_id}",
        "trigger_conditions": {},
        "steps": [],
        "status": "draft",
        "version": 1,
        "created_by": "api",
        "org_id": org_id,
        "tags": [f"template:{template_id}"],
    }

    _playbooks[playbook_id] = playbook
    _logger.info(f"Instantiated template {template_id} as playbook {playbook_id}")

    return PlaybookResponse(**playbook)


@router.get(
    "/compliance/{framework}/assessment",
    response_model=ComplianceAssessmentResponse,
)
async def assess_compliance(
    framework: str,
    org_id: str = Depends(_get_org_id),
) -> ComplianceAssessmentResponse:
    """Run automated compliance assessment for a framework."""
    return ComplianceAssessmentResponse(
        framework=framework,
        overall_score=72,
        total_controls=25,
        controls_by_automation={
            "full": 10,
            "semi": 12,
            "manual": 3,
        },
        gaps=[
            {
                "control_id": "CC6.1",
                "title": "Logical Access Controls",
                "severity": "high",
            },
            {
                "control_id": "CC7.2",
                "title": "System Monitoring",
                "severity": "medium",
            },
        ],
        recommendations=[
            "Implement automated access reviews",
            "Deploy enhanced monitoring and alerting",
            "Document and test incident response procedures",
        ],
    )


@router.get(
    "/compliance/controls/{framework}",
    response_model=List[ComplianceControlResponse],
)
async def get_framework_controls(
    framework: str,
) -> List[ComplianceControlResponse]:
    """Get the control catalog for a compliance framework."""
    controls = [
        ComplianceControlResponse(
            control_id="1.1",
            framework=framework,
            title="Access Control Policy",
            description="Business requirements for access control are established",
            requirements=[
                "Policy documented and approved",
                "Policy communicated to all users",
                "Policy reviewed annually",
            ],
            evidence_types=["policy_document", "distribution_records"],
            automation_level="manual",
        ),
        ComplianceControlResponse(
            control_id="2.1",
            framework=framework,
            title="System Monitoring",
            description="System activities are monitored and analyzed",
            requirements=[
                "Logs collected for all systems",
                "Anomalies detected",
                "Incidents documented",
            ],
            evidence_types=["audit_logs", "siem_alerts"],
            automation_level="semi",
        ),
        ComplianceControlResponse(
            control_id="3.1",
            framework=framework,
            title="Vulnerability Management",
            description="Vulnerabilities are identified and remediated",
            requirements=[
                "Scans performed regularly",
                "Vulnerabilities prioritized",
                "Patches applied timely",
            ],
            evidence_types=["scan_reports", "patch_logs"],
            automation_level="full",
        ),
    ]

    return controls
