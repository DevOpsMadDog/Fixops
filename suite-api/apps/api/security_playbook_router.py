"""Security Playbook Router — ALDECI.

Endpoints for the security playbook automation engine.

Prefix: /api/v1/security-playbooks
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/security-playbooks/playbooks                   list_playbooks
  POST   /api/v1/security-playbooks/playbooks                   create_playbook
  GET    /api/v1/security-playbooks/playbooks/builtins          get_builtin_playbooks
  GET    /api/v1/security-playbooks/playbooks/{id}              get_playbook
  POST   /api/v1/security-playbooks/playbooks/{id}/execute      execute_playbook
  GET    /api/v1/security-playbooks/executions                  list_executions
  GET    /api/v1/security-playbooks/executions/{execution_id}   get_execution
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-playbooks",
    tags=["Security Playbook Engine"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_playbook_engine import SecurityPlaybookEngine
        _engine = SecurityPlaybookEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class PlaybookCreate(BaseModel):
    name: str
    trigger_type: str = "manual"  # manual | auto_alert | scheduled
    trigger_conditions: Dict[str, Any] = Field(default_factory=dict)
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    severity_filter: str = "medium"
    enabled: bool = True


class ExecuteRequest(BaseModel):
    context: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Routes — fixed paths before parameterised ones
# ---------------------------------------------------------------------------

@router.get("/playbooks/builtins", dependencies=[Depends(api_key_auth)])
def get_builtin_playbooks() -> List[Dict[str, Any]]:
    """Return the 5 built-in security response playbook templates."""
    return _get_engine().get_builtin_playbooks()


@router.get("/playbooks", dependencies=[Depends(api_key_auth)])
def list_playbooks(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    """List all playbooks for the org."""
    return _get_engine().list_playbooks(org_id)


@router.post("/playbooks", dependencies=[Depends(api_key_auth)], status_code=201)
def create_playbook(
    body: PlaybookCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Create a new playbook. Returns {playbook_id}."""
    try:
        playbook_id = _get_engine().create_playbook(org_id, body.model_dump())
        return {"playbook_id": playbook_id, "org_id": org_id}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/playbooks/{playbook_id}", dependencies=[Depends(api_key_auth)])
def get_playbook(
    playbook_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a single playbook by ID."""
    pb = _get_engine().get_playbook(playbook_id, org_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


@router.post(
    "/playbooks/{playbook_id}/execute",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def execute_playbook(
    playbook_id: str,
    body: ExecuteRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Execute a playbook sequentially, simulating each step."""
    try:
        return _get_engine().execute_playbook(playbook_id, org_id, body.context)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/executions", dependencies=[Depends(api_key_auth)])
def list_executions(
    org_id: str = Query(default="default"),
    limit: int = Query(default=50, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """Return execution history for the org, newest first."""
    return _get_engine().list_executions(org_id, limit=limit)


@router.get("/executions/{execution_id}", dependencies=[Depends(api_key_auth)])
def get_execution(
    execution_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a single execution record by ID."""
    exec_record = _get_engine().get_execution(execution_id, org_id)
    if not exec_record:
        raise HTTPException(status_code=404, detail="Execution not found")
    return exec_record
