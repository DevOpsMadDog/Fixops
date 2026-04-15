"""
Security Playbook Router — ALDECI.

7 endpoints under /api/v1/playbooks:
  GET    /                  list playbooks
  POST   /                  create playbook
  GET    /{id}              get playbook
  POST   /{id}/execute      execute playbook
  GET    /executions        list executions
  GET    /executions/{id}   get execution details
  GET    /builtin           get built-in playbook templates
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

# Ensure suite-core is importable when running outside the app
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "suite-core"))

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "playbook_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.security_playbook_engine import SecurityPlaybookEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/playbooks",
    tags=["playbooks"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[SecurityPlaybookEngine] = None


def _get_engine() -> SecurityPlaybookEngine:
    global _engine
    if _engine is None:
        _engine = SecurityPlaybookEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class PlaybookCreateRequest(BaseModel):
    name: str = Field(..., description="Human-readable playbook name")
    trigger_type: str = Field("manual", description="manual | auto_alert | scheduled")
    trigger_conditions: Dict[str, Any] = Field(default_factory=dict)
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    severity_filter: str = Field("medium", description="Minimum severity to trigger")
    enabled: bool = Field(True)
    org_id: str = Field("default", description="Organization identifier")


class PlaybookExecuteRequest(BaseModel):
    context: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = Field("default")


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.get("/builtin", summary="Get built-in playbook templates")
def get_builtin_playbooks(
    engine: SecurityPlaybookEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """Return the 5 pre-built security response playbook templates."""
    return engine.get_builtin_playbooks()


@router.get("/executions", summary="List execution history")
def list_executions(
    org_id: str = Query("default"),
    limit: int = Query(50, ge=1, le=500),
    engine: SecurityPlaybookEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List playbook execution history for an organization."""
    return engine.list_executions(org_id=org_id, limit=limit)


@router.get("/executions/{execution_id}", summary="Get execution details")
def get_execution(
    execution_id: str,
    org_id: str = Query("default"),
    engine: SecurityPlaybookEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Get details of a specific playbook execution."""
    result = engine.get_execution(execution_id=execution_id, org_id=org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Execution not found")
    return result


@router.get("", summary="List playbooks")
def list_playbooks(
    org_id: str = Query("default"),
    engine: SecurityPlaybookEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List all playbooks for an organization."""
    return engine.list_playbooks(org_id=org_id)


@router.post("", summary="Create playbook", status_code=201)
def create_playbook(
    body: PlaybookCreateRequest,
    engine: SecurityPlaybookEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Create a new security response playbook."""
    try:
        playbook_id = engine.create_playbook(
            org_id=body.org_id,
            playbook=body.model_dump(exclude={"org_id"}),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    pb = engine.get_playbook(playbook_id=playbook_id, org_id=body.org_id)
    return pb  # type: ignore[return-value]


@router.get("/{playbook_id}", summary="Get playbook")
def get_playbook(
    playbook_id: str,
    org_id: str = Query("default"),
    engine: SecurityPlaybookEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Get a specific playbook by ID."""
    pb = engine.get_playbook(playbook_id=playbook_id, org_id=org_id)
    if pb is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


@router.post("/{playbook_id}/execute", summary="Execute playbook")
def execute_playbook(
    playbook_id: str,
    body: PlaybookExecuteRequest,
    engine: SecurityPlaybookEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Trigger execution of a playbook with optional context."""
    try:
        return engine.execute_playbook(
            playbook_id=playbook_id,
            org_id=body.org_id,
            context=body.context,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
