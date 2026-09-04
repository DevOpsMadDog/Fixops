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
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import os

from fastapi import APIRouter, Depends, HTTPException, Query

from apps.api.dependencies import get_org_id

if TYPE_CHECKING:  # pragma: no cover
    from core.security_playbook_engine import SecurityPlaybookEngine
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
    """Response model for a step result.

    started_at and duration_seconds are nullable because the execution engine
    records timing for the RUN, not for each step. Returning 0.0 would claim a
    measurement nobody took; null says plainly that it was not recorded.
    """

    step_id: str
    step_type: str
    status: str
    output: Dict[str, Any]
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None


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
    """Response model for compliance template list.

    step_count is reported because 17 of the 21 templates the library ships
    contain no steps at all — only the four SOC2 ones are authored. Listing
    them all identically invites a customer to instantiate "PCI DSS Network
    Scan" and receive a playbook that does nothing, with no way to tell in
    advance. The count is the honest signal, and 0 is a real answer.
    """

    template_id: str
    name: str
    description: str
    framework: str
    status: str
    step_count: int = 0


class ComplianceAssessmentResponse(BaseModel):
    """Response model for compliance assessment.

    overall_score is nullable and `assessed` says whether anything was
    actually evaluated. Nothing in the product measures a tenant's compliance
    posture yet, and a number here is the single most dangerous fabrication
    this API could emit — it is the figure a customer screenshots for an
    auditor.
    """

    framework: str
    overall_score: Optional[int] = None
    total_controls: int
    controls_by_automation: Dict[str, int]
    gaps: List[Dict[str, Any]]
    recommendations: List[str]
    assessed: bool = False
    note: Optional[str] = None


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
# STORAGE — core.security_playbook_engine (SQLite, WAL, org-scoped)
# ============================================================================
#
# These twelve routes are mounted in app.py and grc_app.py, and until now they
# were backed by two module-level dicts and this:
#
#     def _get_org_id() -> str:
#         return "default"
#
# Every tenant therefore resolved to the SAME org. The authorisation code was
# written correctly — get_playbook compared playbook["org_id"] against the
# caller's org and raised 403 — and it never fired, because both sides of the
# comparison were the constant "default". Two components each correct while
# the product was wide open.
#
# Measured against the running app with two real signed-up tenants, before:
#
#   A creates "ALPHA-SECRET-RESPONSE"  -> 200, stored with org_id="default"
#   B lists playbooks                  -> 200, total=1, sees it
#   B GETs it by id                    -> 200, full contents
#   B PUTs it                          -> 200, A's playbook becomes "HIJACKED-BY-B"
#   B executes it                      -> 200
#
# Read, write and execute across tenants on the incident-response automation.
#
# The dicts were also process-local: every playbook a customer created was
# lost on restart and never shared between workers.
#
# core.security_playbook_engine already existed and is org-scoped throughout —
# `org_id NOT NULL`, indexed on (org_id, enabled), and every read, update and
# execute carries org_id in its WHERE clause, so another tenant's row is not
# merely hidden but unreachable.

_engine_singleton: Optional["SecurityPlaybookEngine"] = None


def _engine() -> "SecurityPlaybookEngine":
    global _engine_singleton
    if _engine_singleton is None:
        from core.security_playbook_engine import SecurityPlaybookEngine

        data_dir = os.environ.get("FIXOPS_DATA_DIR")
        db = f"{data_dir}/playbooks.db" if data_dir else "data/playbooks.db"
        _engine_singleton = SecurityPlaybookEngine(db_path=db)
    return _engine_singleton


_template_library_singleton = None


def _template_library():
    global _template_library_singleton
    if _template_library_singleton is None:
        from core.compliance_templates import ComplianceTemplateLibrary

        _template_library_singleton = ComplianceTemplateLibrary()
    return _template_library_singleton


def _controls_for(framework: str) -> List[Any]:
    """Control catalog for a framework name, or [] when there is none.

    The library keys controls by the ComplianceFramework enum, not by string,
    so a plain dict lookup with the URL segment silently returns nothing.
    """
    lib = _template_library()
    wanted = framework.lower().replace("-", "_")
    for key, controls in lib.controls.items():
        if str(getattr(key, "value", key)).lower() == wanted:
            return list(controls or [])
    return []


def _as_dict(obj: Any) -> Dict[str, Any]:
    """A template step is a dataclass; its step_type is an Enum."""
    d = dict(vars(obj)) if hasattr(obj, "__dict__") else dict(obj)
    value = d.get("step_type")
    if value is not None and hasattr(value, "value"):
        d["step_type"] = value.value
    return d


def _template_framework(key: str) -> str:
    """The framework a template belongs to, taken from its library key.

    The key is e.g. "soc2_access_review"; the Playbook dataclass carries no
    framework field, so the key is the only real source.

    Matched against the ComplianceFramework values rather than split on the
    first underscore, because two identifier spaces meet here: the key
    "pci_dss_network_scan" split that way yields "pci", while the control
    catalog for the same framework is keyed "pci_dss". Templates and controls
    would then disagree about the name of the same framework, and a client
    filtering templates with the string the controls endpoint uses would get
    nothing back. Longest match first so "pci_dss" wins over any "pci".
    """
    if not key:
        return ""
    known = sorted(
        (str(getattr(f, "value", f)) for f in _template_library().controls),
        key=len,
        reverse=True,
    )
    for framework in known:
        if key.startswith(framework + "_") or key == framework:
            return framework
    return key.split("_")[0]


def _template_response(key: str, template: Any) -> "ComplianceTemplateResponse":
    """template_id is the library KEY, not Playbook.playbook_id.

    playbook_id is a fresh uuid4 generated when the library is constructed, so
    using it made the listed ids random per process AND un-instantiable —
    get_template() looks up by key, so every id this endpoint advertised
    returned 404 from the instantiate endpoint, and the framework derived from
    a uuid prefix was nonsense like "ae3ea723".
    """
    return ComplianceTemplateResponse(
        template_id=key,
        name=getattr(template, "name", ""),
        description=getattr(template, "description", ""),
        framework=_template_framework(key),
        status=str(getattr(getattr(template, "status", "active"), "value",
                           getattr(template, "status", "active"))),
        step_count=len(getattr(template, "steps", []) or []),
    )


def _playbook_response(row: Dict[str, Any]) -> "PlaybookResponse":
    """Engine row -> API shape. The engine calls the key `id`."""
    return PlaybookResponse(
        playbook_id=row["id"],
        name=row.get("name") or "",
        description=row.get("description") or "",
        trigger_conditions=row.get("trigger_conditions") or {},
        steps=[PlaybookStepResponse(**_step_response(x)) for x in row.get("steps") or []],
        status=row.get("status") or "draft",
        version=int(row.get("version") or 1),
        created_by=row.get("created_by") or "api",
        org_id=row["org_id"],
        tags=row.get("tags") or [],
    )


def _step_response(step: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "step_id": step.get("step_id") or "",
        "step_type": step.get("step_type") or step.get("action_type") or "unspecified",
        "name": step.get("name") or "",
        "config": step.get("config") or step.get("params") or {},
        "next_on_success": step.get("next_on_success") or step.get("on_success"),
        "next_on_failure": step.get("next_on_failure") or step.get("on_failure"),
        "timeout_seconds": int(step.get("timeout_seconds") or 300),
    }


def _run_response(execution: Dict[str, Any]) -> "PlaybookRunResponse":
    """Engine execution row -> API shape.

    trigger_event reports the context KEYS the engine recorded, not values:
    it deliberately stores `context_keys` rather than the context itself, and
    inventing the values back would be worse than reporting what was kept.
    """
    output = execution.get("output") or {}
    return PlaybookRunResponse(
        run_id=execution["id"],
        playbook_id=execution["playbook_id"],
        trigger_event={"context_keys": output.get("context_keys", [])},
        status=execution.get("status") or "unknown",
        started_at=str(execution.get("started_at") or ""),
        completed_at=str(execution["finished_at"]) if execution.get("finished_at") else None,
        step_results=[
            StepResultResponse(
                step_id=x.get("step_id") or "",
                step_type=x.get("action_type") or x.get("step_type") or "unspecified",
                status=x.get("status") or "unknown",
                output=x,
                error=x.get("error"),
                started_at=None,
                completed_at=None,
                duration_seconds=None,
            )
            for x in (output.get("steps") or [])
        ],
        error=None,
        org_id=execution["org_id"],
        duration_seconds=(execution.get("duration_ms") or 0) / 1000.0,
    )


# ============================================================================
# PLAYBOOK ENDPOINTS
# ============================================================================


@router.get("/playbooks", response_model=PaginatedPlaybooksResponse)
async def list_playbooks(
    org_id: str = Depends(get_org_id),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> PaginatedPlaybooksResponse:
    """List this organisation's playbooks, newest first."""
    rows = _engine().list_playbooks(org_id)
    start = (page - 1) * page_size
    return PaginatedPlaybooksResponse(
        items=[_playbook_response(r) for r in rows[start:start + page_size]],
        total=len(rows),
        page=page,
        page_size=page_size,
    )


@router.get("/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: str,
    org_id: str = Depends(get_org_id),
) -> PlaybookResponse:
    """Get one of this organisation's playbooks.

    404, not 403, when the playbook belongs to someone else: the engine's
    lookup carries org_id in its WHERE clause, so a caller in another tenant
    cannot distinguish "not yours" from "does not exist" and cannot use this
    endpoint to confirm that an id is real.
    """
    row = _engine().get_playbook(playbook_id, org_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return _playbook_response(row)


@router.post("/playbooks", response_model=PlaybookResponse)
async def create_playbook(
    request: PlaybookCreateRequest,
    org_id: str = Depends(get_org_id),
) -> PlaybookResponse:
    """Create a playbook owned by the calling organisation."""
    engine = _engine()
    try:
        playbook_id = engine.create_playbook(org_id, {
            "name": request.name,
            "description": request.description,
            "trigger_type": request.trigger_conditions.get("type", "manual"),
            "trigger_conditions": request.trigger_conditions,
            "steps": [_step_response(x) for x in request.steps],
            "status": request.status,
            "tags": request.tags,
        })
    except ValueError as exc:
        # e.g. an unsupported trigger_type. A rejected input is a 422, not the
        # 500 this endpoint used to return when the stored shape failed the
        # response model on the way back out.
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    row = engine.get_playbook(playbook_id, org_id)
    if row is None:  # pragma: no cover - would mean the write did not land
        raise HTTPException(status_code=500, detail="playbook was not persisted")
    _logger.info("Created playbook %s for org %s", playbook_id, org_id)
    return _playbook_response(row)


@router.put("/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: str,
    request: PlaybookUpdateRequest,
    org_id: str = Depends(get_org_id),
) -> PlaybookResponse:
    """Update one of this organisation's playbooks."""
    changes: Dict[str, Any] = {
        "name": request.name,
        "description": request.description,
        "trigger_conditions": request.trigger_conditions,
        "status": request.status,
        "tags": request.tags,
    }
    if request.steps is not None:
        changes["steps"] = [_step_response(x) for x in request.steps]

    row = _engine().update_playbook(playbook_id, org_id, changes)
    if row is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    _logger.info("Updated playbook %s for org %s", playbook_id, org_id)
    return _playbook_response(row)


@router.post(
    "/playbooks/{playbook_id}/execute",
    response_model=PlaybookRunResponse,
)
async def execute_playbook(
    playbook_id: str,
    request: PlaybookExecuteRequest,
    org_id: str = Depends(get_org_id),
) -> PlaybookRunResponse:
    """Run one of this organisation's playbooks.

    This previously ran NOTHING. It minted a run id, wrote
    status="completed", duration_seconds=0.5 and step_results=[] into a dict,
    and returned it — an incident-response product reporting a successful
    remediation that never happened, with a plausible half-second duration
    attached. There was no execution path at all.

    It now goes through the engine, which really walks the steps and labels
    every result execution_mode="simulated" until connectors are wired, so a
    caller can tell a simulation from a real containment action.
    """
    engine = _engine()
    try:
        result = engine.execute_playbook(playbook_id, org_id, request.context)
    except ValueError as exc:
        # The engine refuses a playbook that is not this org's, and says so by
        # raising rather than returning an empty run.
        raise HTTPException(status_code=404, detail="Playbook not found") from exc

    execution = engine.get_execution(result["execution_id"], org_id)
    if execution is None:  # pragma: no cover
        raise HTTPException(status_code=500, detail="execution was not persisted")
    _logger.info("Executed playbook %s for org %s", playbook_id, org_id)
    return _run_response(execution)


@router.get(
    "/playbooks/{playbook_id}/runs",
    response_model=PaginatedRunsResponse,
)
async def get_playbook_runs(
    playbook_id: str,
    org_id: str = Depends(get_org_id),
    limit: int = Query(50, ge=1, le=500),
) -> PaginatedRunsResponse:
    """Get run history for one of this organisation's playbooks."""
    engine = _engine()
    if engine.get_playbook(playbook_id, org_id) is None:
        raise HTTPException(status_code=404, detail="Playbook not found")

    runs = [
        e for e in engine.list_executions(org_id, limit=limit)
        if e.get("playbook_id") == playbook_id
    ]
    return PaginatedRunsResponse(
        items=[_run_response(e) for e in runs],
        total=len(runs),
        page=1,
        page_size=limit,
    )


@router.get("/playbooks/runs/{run_id}", response_model=PlaybookRunResponse)
async def get_run_details(
    run_id: str,
    org_id: str = Depends(get_org_id),
) -> PlaybookRunResponse:
    """Get details of one of this organisation's playbook runs."""
    execution = _engine().get_execution(run_id, org_id)
    if execution is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return _run_response(execution)


# ============================================================================
# COMPLIANCE TEMPLATE ENDPOINTS
# ============================================================================


@router.get(
    "/compliance/templates",
    response_model=List[ComplianceTemplateResponse],
)
async def list_compliance_templates() -> List[ComplianceTemplateResponse]:
    """List every compliance template the library actually ships.

    This returned five hand-written entries. core.compliance_templates has a
    real library whose Playbook dataclass matches these response models field
    for field — playbook_id/name/description/trigger_conditions/steps/status/
    version/created_by/org_id/tags, and steps with step_id/step_type/name/
    config/next_on_*/timeout_seconds. The models were designed against it and
    a literal list was wired in instead, so the API advertised templates that
    did not exist and omitted the ones that did.
    """
    return [_template_response(k, t) for k, t in _template_library().templates.items()]


@router.get(
    "/compliance/templates/{framework}",
    response_model=List[ComplianceTemplateResponse],
)
async def get_framework_templates(
    framework: str,
) -> List[ComplianceTemplateResponse]:
    """Templates for one framework.

    Previously synthesised "{FRAMEWORK} Template 1" and "Template 2" with the
    description "First template for {framework}" — for ANY string the caller
    passed, including one that is not a framework at all. An unknown framework
    now returns an empty list, which is true, rather than two inventions.
    """
    wanted = framework.lower().replace("-", "_")
    return [
        _template_response(k, t)
        for k, t in _template_library().templates.items()
        if _template_framework(k).lower() == wanted
    ]


@router.post(
    "/compliance/templates/{template_id}/instantiate",
    response_model=PlaybookResponse,
)
async def instantiate_compliance_template(
    template_id: str,
    org_id: str = Depends(get_org_id),
) -> PlaybookResponse:
    """Create a playbook for this org from a compliance template.

    Was a no-op dressed as a feature: it built a playbook named
    "Instantiated {template_id}" with `"steps": []` for ANY template id,
    including ids that do not exist, and stored it in the in-process dict. A
    customer instantiating "SOC2 Quarterly Access Review" got an empty
    playbook that ran nothing and vanished on restart.

    It now copies the template's real steps and persists them under the
    calling organisation.
    """
    template = _template_library().get_template(template_id)
    if template is None:
        raise HTTPException(
            status_code=404, detail=f"No such compliance template: {template_id}"
        )

    engine = _engine()
    playbook_id = engine.create_playbook(org_id, {
        "name": getattr(template, "name", template_id),
        "description": getattr(template, "description", ""),
        "trigger_type": "manual",
        "trigger_conditions": getattr(template, "trigger_conditions", {}) or {},
        "steps": [_step_response(_as_dict(x)) for x in getattr(template, "steps", []) or []],
        "status": "draft",
        "tags": list(getattr(template, "tags", []) or []) + [f"template:{template_id}"],
    })
    row = engine.get_playbook(playbook_id, org_id)
    if row is None:  # pragma: no cover
        raise HTTPException(status_code=500, detail="playbook was not persisted")
    _logger.info("Instantiated template %s as playbook %s for org %s",
                 template_id, playbook_id, org_id)
    return _playbook_response(row)


@router.get(
    "/compliance/{framework}/assessment",
    response_model=ComplianceAssessmentResponse,
)
async def assess_compliance(
    framework: str,
    org_id: str = Depends(get_org_id),
) -> ComplianceAssessmentResponse:
    """Report what is known about a framework's controls for this org.

    This endpoint used to return overall_score=72, total_controls=25 and two
    named gaps (CC6.1 "Logical Access Controls", CC7.2 "System Monitoring")
    — the same values for every framework, every organisation, every call.
    A customer could screenshot "72% compliant" and it measured nothing.

    core.compliance_templates.assess_compliance is no better and says so in
    its own source: `overall_score = 65 + (full_auto * 2)  # Mock calculation`,
    derived from how automatable the CATALOG is, with org_id accepted and
    never read. Wiring this to it would have relocated the fiction, not
    removed it.

    What IS real is the control catalog: which controls a framework defines
    and how automatable each is. That is returned. The score is null and
    `assessed` is false until something actually evaluates a tenant's
    evidence — 0 would read as "measured, and you scored nothing", which is a
    different and equally false claim.
    """
    controls = _controls_for(framework)
    if not controls:
        raise HTTPException(
            status_code=404,
            detail=f"No control catalog for framework {framework!r}",
        )

    by_automation: Dict[str, int] = {}
    for control in controls:
        level = getattr(control, "automation_level", None)
        key = str(getattr(level, "value", level) or "unspecified")
        by_automation[key] = by_automation.get(key, 0) + 1

    return ComplianceAssessmentResponse(
        framework=framework,
        overall_score=None,
        total_controls=len(controls),
        controls_by_automation=by_automation,
        gaps=[],
        recommendations=[],
        assessed=False,
        note=(
            "Control catalog only. No compliance evaluation has been performed "
            "for this organisation, so no score, gaps or recommendations are "
            "reported. Ingest control evidence to obtain an assessment."
        ),
    )


@router.get(
    "/compliance/controls/{framework}",
    response_model=List[ComplianceControlResponse],
)
async def get_framework_controls(
    framework: str,
) -> List[ComplianceControlResponse]:
    """The real control catalog for a framework.

    Previously returned three generic controls numbered 1.1/2.1/3.1 —
    "Access Control Policy", "System Monitoring", "Vulnerability Management"
    — for ANY string passed as `framework`, including one that names no
    framework at all. The library ships real catalogs for soc2, hipaa,
    pci_dss, iso27001, nist_csf, gdpr and fedramp.
    """
    controls = _controls_for(framework)
    if not controls:
        raise HTTPException(
            status_code=404,
            detail=f"No control catalog for framework {framework!r}",
        )
    return [
        ComplianceControlResponse(
            control_id=str(getattr(c, "control_id", "")),
            framework=framework,
            title=getattr(c, "title", ""),
            description=getattr(c, "description", ""),
            requirements=list(getattr(c, "requirements", []) or []),
            evidence_types=list(getattr(c, "evidence_types", []) or []),
            automation_level=str(
                getattr(getattr(c, "automation_level", ""), "value",
                        getattr(c, "automation_level", "")) or "unspecified"
            ),
        )
        for c in controls
    ]
