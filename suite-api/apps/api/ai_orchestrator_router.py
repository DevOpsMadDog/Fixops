"""AI Orchestrator REST API.

8 endpoints for coordinating LLM agents in security decisions:
- POST /tasks                      — create a task
- POST /tasks/{task_id}/execute    — execute a task
- GET  /tasks/{task_id}            — get task status/result
- GET  /tasks                      — list task history
- POST /consensus                  — multi-agent consensus
- POST /pipeline/chain             — sequential agent pipeline
- POST /pipeline/parallel          — parallel agent pipeline
- GET  /stats                      — consensus agreement stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ai-orchestrator", tags=["ai-orchestrator"])

# ---------------------------------------------------------------------------
# Lazy import of AIOrchestrator (graceful degradation)
# ---------------------------------------------------------------------------

try:
    from core.ai_orchestrator import (
        AgentRole,
        AgentTask,
        AIOrchestrator,
        ConsensusResult,
        TaskStatus,
        get_orchestrator,
    )

    _ORCHESTRATOR_AVAILABLE = True
except ImportError as _import_err:
    logger.warning("AIOrchestrator not available: %s", _import_err)
    _ORCHESTRATOR_AVAILABLE = False

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateTaskRequest(BaseModel):
    role: str = Field(..., description="Agent role: analyst|reviewer|remediator|investigator|compliance_checker|threat_hunter")
    prompt: str = Field(..., min_length=1, max_length=10_000)
    context: Dict[str, Any] = Field(default_factory=dict)


class ExecuteTaskResponse(BaseModel):
    task_id: str
    role: str
    status: str
    result: Optional[str]
    prompt: str
    created_at: str


class ConsensusRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10_000)
    roles: Optional[List[str]] = Field(
        default=None,
        description="Agent roles to consult. Defaults to analyst+reviewer+investigator.",
    )
    context: Dict[str, Any] = Field(default_factory=dict)


class PipelineRequest(BaseModel):
    tasks: List[Dict[str, Any]] = Field(
        ...,
        description="List of {role, prompt, context} dicts",
        min_length=1,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_orchestrator() -> "AIOrchestrator":
    if not _ORCHESTRATOR_AVAILABLE:
        raise HTTPException(status_code=503, detail="AIOrchestrator not available")
    return get_orchestrator()


def _task_to_response(task: "AgentTask") -> ExecuteTaskResponse:
    return ExecuteTaskResponse(
        task_id=task.id,
        role=task.role.value,
        status=task.status.value,
        result=task.result,
        prompt=task.prompt,
        created_at=task.created_at.isoformat(),
    )


def _parse_role(role_str: str) -> "AgentRole":
    try:
        return AgentRole(role_str.lower())
    except (ValueError, AttributeError):
        valid = [r.value for r in AgentRole]
        raise HTTPException(
            status_code=422,
            detail=f"Invalid role {role_str!r}. Valid: {valid}",
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/tasks", summary="Create an agent task")
def create_task(
    body: CreateTaskRequest,
    org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a new agent task (does not execute it yet)."""
    orch = _require_orchestrator()
    role = _parse_role(body.role)
    task_id = orch.create_task(role, body.prompt, body.context, org_id=org_id)
    return {"task_id": task_id, "status": "pending", "role": role.value}


@router.post("/tasks/{task_id}/execute", summary="Execute a pending task")
def execute_task(
    task_id: str,
    org_id: Optional[str] = Depends(get_org_id),
) -> ExecuteTaskResponse:
    """Run the task through the LLM agent and return the result."""
    orch = _require_orchestrator()
    try:
        task = orch.execute_task(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return _task_to_response(task)


@router.get("/tasks/{task_id}", summary="Get task status and result")
def get_task(
    task_id: str,
    org_id: Optional[str] = Depends(get_org_id),
) -> ExecuteTaskResponse:
    """Retrieve a task by ID."""
    orch = _require_orchestrator()
    task = orch.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Task {task_id!r} not found")
    return _task_to_response(task)


@router.get("/tasks", summary="List task history")
def list_tasks(
    org_id: Optional[str] = Depends(get_org_id),
    role: Optional[str] = Query(default=None, description="Filter by agent role"),
    status: Optional[str] = Query(default=None, description="Filter by status: pending|running|completed|failed"),
    limit: int = Query(default=50, ge=1, le=500),
) -> Dict[str, Any]:
    """Return task history, optionally filtered by role and status."""
    try:
        orch = _require_orchestrator()
    except Exception:
        return {"tasks": [], "total": 0}

    role_filter = _parse_role(role) if role else None
    status_filter: Optional["TaskStatus"] = None
    if status:
        try:
            status_filter = TaskStatus(status.lower())
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid status {status!r}")

    try:
        tasks = orch.get_task_history(org_id=org_id, limit=limit, role=role_filter, status=status_filter)
        return {
            "tasks": [_task_to_response(t).model_dump() for t in tasks],
            "total": len(tasks),
        }
    except Exception:
        return {"tasks": [], "total": 0}


@router.post("/consensus", summary="Multi-agent consensus on a security decision")
def multi_agent_consensus(
    body: ConsensusRequest,
    org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    """Query multiple agent roles and return a consensus decision."""
    orch = _require_orchestrator()

    roles = None
    if body.roles:
        roles = [_parse_role(r) for r in body.roles]

    result = orch.multi_agent_consensus(body.prompt, roles=roles, context=body.context, org_id=org_id)
    return {
        "decision": result.decision,
        "confidence": result.confidence,
        "agents_agreed": result.agents_agreed,
        "agents_disagreed": result.agents_disagreed,
        "reasoning": result.reasoning,
    }


@router.post("/pipeline/chain", summary="Sequential agent pipeline")
def chain_pipeline(
    body: PipelineRequest,
    org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    """Execute tasks sequentially. Each task receives the previous result in its context."""
    orch = _require_orchestrator()

    # Validate roles before executing
    for td in body.tasks:
        if "role" not in td or "prompt" not in td:
            raise HTTPException(status_code=422, detail="Each task must have 'role' and 'prompt' fields")
        _parse_role(td["role"])

    results = orch.chain_agents(body.tasks, org_id=org_id)
    return {
        "pipeline_type": "chain",
        "tasks": [_task_to_response(t).model_dump() for t in results],
        "total": len(results),
    }


@router.post("/pipeline/parallel", summary="Parallel agent pipeline")
def parallel_pipeline(
    body: PipelineRequest,
    org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    """Execute all tasks concurrently and return results."""
    orch = _require_orchestrator()

    for td in body.tasks:
        if "role" not in td or "prompt" not in td:
            raise HTTPException(status_code=422, detail="Each task must have 'role' and 'prompt' fields")
        _parse_role(td["role"])

    results = orch.parallel_agents(body.tasks, org_id=org_id)
    return {
        "pipeline_type": "parallel",
        "tasks": [_task_to_response(t).model_dump() for t in results],
        "total": len(results),
    }


@router.get("/stats", summary="Consensus agreement statistics")
def consensus_stats(
    org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return consensus agreement rates and decision distribution for the org."""
    orch = _require_orchestrator()
    stats = orch.get_consensus_stats(org_id=org_id)
    return stats


# ---------------------------------------------------------------------------
# GAP-061: Tiered LLM context router (per-rule tier + pre-flight cost)
# ---------------------------------------------------------------------------


class ContextRequirementRequest(BaseModel):
    rule_key: str = Field(..., min_length=1, max_length=256)
    tier: str = Field(..., description="metadata|targeted|full_file")
    max_tokens: int = Field(..., gt=0, le=1_000_000)


class PreflightRequest(BaseModel):
    rule_keys: List[str] = Field(..., min_length=0, max_length=10_000)
    file_count: int = Field(default=1, ge=1, le=100_000)


_AI_GOV_SINGLETON: Optional[Any] = None


def _require_ai_gov() -> Any:
    """Lazy-load the AIGovernanceEngine singleton."""
    global _AI_GOV_SINGLETON
    if _AI_GOV_SINGLETON is not None:
        return _AI_GOV_SINGLETON
    try:
        from core.ai_governance_engine import AIGovernanceEngine
    except ImportError as exc:  # pragma: no cover — engine ships with core
        raise HTTPException(
            status_code=503,
            detail=f"AIGovernanceEngine not available: {exc}",
        )
    _AI_GOV_SINGLETON = AIGovernanceEngine()
    return _AI_GOV_SINGLETON


def _resolve_org_id(org_id: Optional[str], fallback: Optional[str]) -> str:
    """Pick explicit body/query org_id, else dependency-provided."""
    value = (fallback or org_id or "").strip() if isinstance(fallback, str) or isinstance(org_id, str) else ""
    if not value:
        raise HTTPException(status_code=400, detail="org_id is required")
    return value


@router.post(
    "/context-requirement",
    summary="GAP-061: Register/upsert per-rule LLM context tier",
)
def register_context_requirement(
    body: ContextRequirementRequest,
    org_id: Optional[str] = Query(default=None, description="Tenant org_id"),
    dep_org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    """Assign an LLM context tier (metadata/targeted/full_file) to a rule."""
    engine = _require_ai_gov()
    effective_org = _resolve_org_id(dep_org_id, org_id)
    try:
        return engine.register_rule_context_requirement(
            effective_org, body.rule_key, body.tier, body.max_tokens
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get(
    "/context-requirements",
    summary="GAP-061: List registered rule context requirements",
)
def list_context_requirements(
    org_id: Optional[str] = Query(default=None, description="Tenant org_id"),
    dep_org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    engine = _require_ai_gov()
    effective_org = _resolve_org_id(dep_org_id, org_id)
    items = engine.list_rule_context_requirements(effective_org)
    return {"org_id": effective_org, "total": len(items), "items": items}


@router.post(
    "/preflight-estimate",
    summary="GAP-061: Pre-flight LLM cost estimate for a set of rules",
)
def preflight_estimate(
    body: PreflightRequest,
    org_id: Optional[str] = Query(default=None, description="Tenant org_id"),
    dep_org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    engine = _require_ai_gov()
    effective_org = _resolve_org_id(dep_org_id, org_id)
    try:
        return engine.preflight_estimate(
            effective_org, body.rule_keys, file_count=body.file_count
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# GAP-044: AI Teammates UX
# ---------------------------------------------------------------------------

try:
    from apps.api.auth_deps import api_key_auth as _teammates_auth
except ImportError:  # pragma: no cover - safety net for test harnesses
    async def _teammates_auth() -> None:  # type: ignore
        return None


class SuggestFixBody(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=256)


class DraftExceptionBody(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=256)
    business_justification: str = Field(default="", max_length=10_000)


class AutoTriageBody(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=256)


_AI_ADVISOR_SINGLETON: Optional[Any] = None


def _require_ai_advisor() -> Any:
    global _AI_ADVISOR_SINGLETON
    if _AI_ADVISOR_SINGLETON is not None:
        return _AI_ADVISOR_SINGLETON
    try:
        from core.ai_security_advisor_engine import AISecurityAdvisorEngine
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"AISecurityAdvisorEngine not available: {exc}",
        )
    _AI_ADVISOR_SINGLETON = AISecurityAdvisorEngine()
    return _AI_ADVISOR_SINGLETON


teammates_router = APIRouter(
    prefix="/api/v1/teammates",
    tags=["ai-teammates"],
    dependencies=[Depends(_teammates_auth)],
)


@teammates_router.post(
    "/suggest-fix",
    summary="GAP-044: AI teammate suggests a fix with context",
)
def teammates_suggest_fix(
    body: SuggestFixBody,
    org_id: Optional[str] = Query(default=None, description="Tenant org_id"),
    dep_org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    engine = _require_ai_advisor()
    effective_org = _resolve_org_id(dep_org_id, org_id)
    try:
        return engine.suggest_fix_with_context(effective_org, body.finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@teammates_router.post(
    "/draft-exception",
    summary="GAP-044: AI teammate drafts a security exception request",
)
def teammates_draft_exception(
    body: DraftExceptionBody,
    org_id: Optional[str] = Query(default=None, description="Tenant org_id"),
    dep_org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    engine = _require_ai_advisor()
    effective_org = _resolve_org_id(dep_org_id, org_id)
    try:
        return engine.draft_exception_request(
            effective_org, body.finding_id, body.business_justification
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@teammates_router.post(
    "/auto-triage",
    summary="GAP-044: AI teammate auto-triages a finding",
)
def teammates_auto_triage(
    body: AutoTriageBody,
    org_id: Optional[str] = Query(default=None, description="Tenant org_id"),
    dep_org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    engine = _require_ai_advisor()
    effective_org = _resolve_org_id(dep_org_id, org_id)
    try:
        return engine.auto_triage(effective_org, body.finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# teammates_router is exported separately — app.py mounts it directly at
# /api/v1/teammates so the paths remain clean (not nested under
# /api/v1/ai-orchestrator).
