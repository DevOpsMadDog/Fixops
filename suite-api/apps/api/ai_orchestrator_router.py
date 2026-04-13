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

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.dependencies import get_org_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ai-orchestrator", tags=["ai-orchestrator"])

# ---------------------------------------------------------------------------
# Lazy import of AIOrchestrator (graceful degradation)
# ---------------------------------------------------------------------------

try:
    from core.ai_orchestrator import (
        AgentRole,
        AgentTask,
        ConsensusResult,
        TaskStatus,
        AIOrchestrator,
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
    orch = _require_orchestrator()

    role_filter = _parse_role(role) if role else None
    status_filter: Optional["TaskStatus"] = None
    if status:
        try:
            status_filter = TaskStatus(status.lower())
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid status {status!r}")

    tasks = orch.get_task_history(org_id=org_id, limit=limit, role=role_filter, status=status_filter)
    return {
        "tasks": [_task_to_response(t).model_dump() for t in tasks],
        "total": len(tasks),
    }


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
