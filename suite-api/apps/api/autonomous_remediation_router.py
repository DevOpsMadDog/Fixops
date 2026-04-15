"""Autonomous Remediation API Router — ALDECI.

Endpoints under /api/v1/autonomous-remediation:

  Workflows:
    POST   /workflows                  — create workflow
    GET    /workflows                  — list workflows (filter: trigger_type, status)
    GET    /workflows/{id}             — get workflow
    PUT    /workflows/{id}/activate    — activate workflow

  Executions:
    POST   /executions                 — record execution
    GET    /executions                 — list executions (filter: workflow_id, status)

  Playbooks:
    POST   /playbooks                  — create playbook
    GET    /playbooks                  — list playbooks (filter: target_type)
    PUT    /playbooks/{id}/run         — run playbook

  Stats:
    GET    /stats                      — remediation statistics

Auth: api_key_auth from apps.api.auth_deps
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/autonomous-remediation",
    tags=["Autonomous Remediation"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.autonomous_remediation_engine import AutonomousRemediationEngine
        _engine = AutonomousRemediationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateWorkflowIn(BaseModel):
    name: str = Field(..., description="Workflow name")
    trigger_type: str = Field("manual", description="vulnerability|alert|anomaly|policy_violation|incident|manual")
    trigger_condition: Dict[str, Any] = Field(default_factory=dict, description="JSON-serialized trigger rule")
    action_type: str = Field("notify", description="patch|isolate|block|notify|script|api_call|rollback|quarantine")
    target_type: str = Field("host", description="host|container|network|identity|application|cloud_resource")
    automation_level: str = Field("manual", description="full|semi|manual")


class RecordExecutionIn(BaseModel):
    workflow_id: str = Field(..., description="Workflow ID this execution belongs to")
    trigger_event: str = Field("", description="Event that triggered this execution")
    target_id: str = Field("", description="Target resource ID")
    target_type: str = Field("", description="Target resource type")
    status: str = Field("pending", description="pending|running|succeeded|failed|rolled_back|skipped")
    started_at: str = Field("", description="ISO 8601 start time")
    completed_at: str = Field("", description="ISO 8601 completion time")
    result: str = Field("", description="Execution result summary")
    error_message: str = Field("", description="Error detail if failed")


class CreatePlaybookIn(BaseModel):
    playbook_name: str = Field(..., description="Playbook name")
    steps: List[Any] = Field(default_factory=list, description="Ordered list of playbook steps")
    target_type: str = Field("host", description="host|container|network|identity|application|cloud_resource")
    estimated_duration_minutes: int = Field(0, ge=0, description="Estimated run time in minutes")


# ---------------------------------------------------------------------------
# Workflow endpoints
# ---------------------------------------------------------------------------

@router.post("/workflows", summary="Create remediation workflow")
def create_workflow(
    req: CreateWorkflowIn,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().create_workflow(org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create workflow: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/workflows", summary="List remediation workflows")
def list_workflows(
    org_id: str = Query("default", description="Organisation ID"),
    trigger_type: Optional[str] = Query(None, description="Filter by trigger_type"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_workflows(org_id, trigger_type=trigger_type, status=status)


@router.get("/workflows/{workflow_id}", summary="Get remediation workflow")
def get_workflow(
    workflow_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    result = _get_engine().get_workflow(org_id, workflow_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Workflow {workflow_id} not found.")
    return result


@router.put("/workflows/{workflow_id}/activate", summary="Activate workflow")
def activate_workflow(
    workflow_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().activate_workflow(org_id, workflow_id)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to activate workflow: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Execution endpoints
# ---------------------------------------------------------------------------

@router.post("/executions", summary="Record workflow execution")
def record_execution(
    req: RecordExecutionIn,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().record_execution(org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to record execution: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/executions", summary="List workflow executions")
def list_executions(
    org_id: str = Query("default", description="Organisation ID"),
    workflow_id: Optional[str] = Query(None, description="Filter by workflow_id"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_executions(org_id, workflow_id=workflow_id, status=status)


# ---------------------------------------------------------------------------
# Playbook endpoints
# ---------------------------------------------------------------------------

@router.post("/playbooks", summary="Create remediation playbook")
def create_playbook(
    req: CreatePlaybookIn,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().create_playbook(org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create playbook: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/playbooks", summary="List remediation playbooks")
def list_playbooks(
    org_id: str = Query("default", description="Organisation ID"),
    target_type: Optional[str] = Query(None, description="Filter by target_type"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_playbooks(org_id, target_type=target_type)


@router.put("/playbooks/{playbook_id}/run", summary="Run a playbook")
def run_playbook(
    playbook_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().run_playbook(org_id, playbook_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to run playbook: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", summary="Remediation statistics")
def get_remediation_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    return _get_engine().get_remediation_stats(org_id)
