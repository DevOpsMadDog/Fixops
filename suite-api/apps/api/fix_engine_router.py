"""FixEngine — Remediation Workflow Engine API endpoints.

Provides playbook management and execution lifecycle endpoints:
- Create/list/get playbooks
- List built-in templates
- Execute, approve, reject, rollback, cancel executions
- List/get executions
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

# Lazy import of engine (graceful degradation if pydantic not available)
try:
    from core.remediation_engine import (
        ExecutionStatus,
        PlaybookType,
        RemediationEngine,
    )

    _engine: Optional[RemediationEngine] = None

    def _get_engine() -> RemediationEngine:
        global _engine
        if _engine is None:
            _engine = RemediationEngine()
        return _engine

    _HAS_ENGINE = True
except ImportError as _exc:
    _logger.warning("fix_engine_router: remediation_engine unavailable: %s", _exc)
    _HAS_ENGINE = False

router = APIRouter(prefix="/api/v1/remediation", tags=["fix-engine"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreatePlaybookRequest(BaseModel):
    name: str
    type: str
    description: str = ""
    steps: List[Dict[str, Any]]
    requires_approval: bool = False
    auto_rollback: bool = True
    target_finding_id: Optional[str] = None
    org_id: str = "default"
    created_by: str = "system"


class ApproveRequest(BaseModel):
    approver_email: str
    comment: str = ""


class RejectRequest(BaseModel):
    approver_email: str
    reason: str = ""


# ---------------------------------------------------------------------------
# Playbook endpoints
# ---------------------------------------------------------------------------


@router.post("/playbooks")
def create_playbook(request: CreatePlaybookRequest) -> Dict[str, Any]:
    """Create a new remediation playbook."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    try:
        pb_type = PlaybookType(request.type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid playbook type '{request.type}'. Valid types: {[t.value for t in PlaybookType]}",
        )
    playbook = engine.create_playbook(
        name=request.name,
        type=pb_type,
        steps=request.steps,
        requires_approval=request.requires_approval,
        auto_rollback=request.auto_rollback,
        target_finding_id=request.target_finding_id,
        org_id=request.org_id,
        created_by=request.created_by,
        description=request.description,
    )
    return playbook.model_dump(mode="json")


@router.get("/playbooks")
def list_playbooks(
    org_id: Optional[str] = Query(default=None),
    type: Optional[str] = Query(default=None),  # noqa: A002
) -> Dict[str, Any]:
    """List playbooks with optional filters."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    type_filter: Optional[PlaybookType] = None
    if type:
        try:
            type_filter = PlaybookType(type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid playbook type '{type}'")
    playbooks = engine.list_playbooks(org_id=org_id, type_filter=type_filter)
    return {"playbooks": [p.model_dump(mode="json") for p in playbooks], "count": len(playbooks)}


@router.get("/playbooks/{playbook_id}")
def get_playbook(playbook_id: str) -> Dict[str, Any]:
    """Get a specific playbook by ID."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    playbook = engine.get_playbook(playbook_id)
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook.model_dump(mode="json")


@router.get("/templates")
def list_templates() -> Dict[str, Any]:
    """List built-in remediation playbook templates."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    templates = engine.get_playbook_templates()
    return {"templates": templates, "count": len(templates)}


# ---------------------------------------------------------------------------
# Execution endpoints
# ---------------------------------------------------------------------------


@router.post("/execute/{playbook_id}")
def execute_playbook(
    playbook_id: str,
    executed_by: str = Query(default="api"),
) -> Dict[str, Any]:
    """Start execution of a playbook."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    try:
        execution = engine.execute_playbook(playbook_id, executed_by=executed_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return execution.model_dump(mode="json")


@router.post("/executions/{execution_id}/approve")
def approve_execution(execution_id: str, request: ApproveRequest) -> Dict[str, Any]:
    """Approve an execution that is awaiting approval."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    try:
        engine.approve_execution(
            execution_id, approver_email=request.approver_email, comment=request.comment
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    execution = engine.get_execution(execution_id)
    return execution.model_dump(mode="json")  # type: ignore[union-attr]


@router.post("/executions/{execution_id}/reject")
def reject_execution(execution_id: str, request: RejectRequest) -> Dict[str, Any]:
    """Reject an execution gate."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    try:
        engine.reject_execution(
            execution_id, approver_email=request.approver_email, reason=request.reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    execution = engine.get_execution(execution_id)
    return execution.model_dump(mode="json")  # type: ignore[union-attr]


@router.post("/executions/{execution_id}/rollback")
def rollback_execution(execution_id: str) -> Dict[str, Any]:
    """Rollback a completed or failed execution."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    try:
        engine.rollback_execution(execution_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    execution = engine.get_execution(execution_id)
    return execution.model_dump(mode="json")  # type: ignore[union-attr]


@router.post("/executions/{execution_id}/cancel")
def cancel_execution(execution_id: str) -> Dict[str, Any]:
    """Cancel a pending or running execution."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    try:
        engine.cancel_execution(execution_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    execution = engine.get_execution(execution_id)
    return execution.model_dump(mode="json")  # type: ignore[union-attr]


@router.get("/executions")
def list_executions(
    org_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """List executions with optional filters."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    status_filter: Optional[ExecutionStatus] = None
    if status:
        try:
            status_filter = ExecutionStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status '{status}'")
    executions = engine.list_executions(org_id=org_id, status_filter=status_filter)
    return {
        "executions": [e.model_dump(mode="json") for e in executions],
        "count": len(executions),
    }


@router.get("/executions/{execution_id}")
def get_execution(execution_id: str) -> Dict[str, Any]:
    """Get a specific execution by ID."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="RemediationEngine not available")
    engine = _get_engine()
    execution = engine.get_execution(execution_id)
    if execution is None:
        raise HTTPException(status_code=404, detail="Execution not found")
    return execution.model_dump(mode="json")
