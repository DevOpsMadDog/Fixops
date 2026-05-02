"""Cloud Incident Response Router — ALDECI.

Cloud-specific incident response with automated containment tracking.

Prefix: /api/v1/cloud-ir
Auth: api_key_auth on ALL endpoints (router-level dependency)

Routes:
  POST   /api/v1/cloud-ir/incidents                     create_incident
  GET    /api/v1/cloud-ir/incidents                     list_incidents
  GET    /api/v1/cloud-ir/incidents/{id}                get_incident
  POST   /api/v1/cloud-ir/incidents/{id}/contain        contain_incident
  POST   /api/v1/cloud-ir/incidents/{id}/actions        add_containment_action
  POST   /api/v1/cloud-ir/actions/{id}/complete         complete_action
  POST   /api/v1/cloud-ir/incidents/{id}/resolve        resolve_incident
  POST   /api/v1/cloud-ir/playbooks                     create_playbook
  GET    /api/v1/cloud-ir/playbooks                     list_playbooks
  POST   /api/v1/cloud-ir/playbooks/{id}/execute        execute_playbook
  GET    /api/v1/cloud-ir/metrics                       get_ir_metrics
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-ir",
    tags=["Cloud Incident Response"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cloud_incident_response_engine import CloudIncidentResponseEngine
        _engine = CloudIncidentResponseEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateIncidentRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    incident_name: str = Field(..., description="Descriptive incident name")
    cloud_provider: str = Field(default="aws", description="Cloud provider")
    incident_type: str = Field(..., description="Type of cloud incident")
    severity: str = Field(default="medium", description="Severity: critical/high/medium/low")
    affected_services: Optional[List[str]] = Field(default=None, description="List of affected services")
    affected_regions: Optional[List[str]] = Field(default=None, description="List of affected regions")


class ContainIncidentRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    blast_radius: str = Field(default="unknown", description="Blast radius description")


class AddActionRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    action_type: str = Field(..., description="Containment action type")
    resource_id: str = Field(default="", description="Affected resource identifier")
    description: str = Field(default="", description="Action description")
    automated: bool = Field(default=False, description="Whether action was automated")
    executed_by: str = Field(default="", description="Who executed the action")


class CompleteActionRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    result: str = Field(default="", description="Action result/outcome")


class ResolveIncidentRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    root_cause: str = Field(default="", description="Root cause analysis")


class CreatePlaybookRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    playbook_name: str = Field(..., description="Playbook name")
    cloud_provider: str = Field(..., description="Target cloud provider")
    incident_type: str = Field(..., description="Target incident type")
    steps: Optional[List[str]] = Field(default=None, description="Ordered playbook steps")
    estimated_mins: int = Field(default=30, ge=1, description="Estimated execution time in minutes")


class ExecutePlaybookRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", summary="Cloud IR root list (incidents) for landing pages")
def list_cloud_ir_root(
    org_id: str = Query("default"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(default=None),
    cloud_provider: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Root endpoint — returns paginated incidents for the org so landing pages don't 404."""
    rows = _get_engine().list_incidents(
        org_id=org_id, status=status, cloud_provider=cloud_provider
    )
    paged = rows[offset : offset + limit]
    return {
        "items": paged,
        "total": len(rows),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
    }


@router.post("/incidents", summary="Create a cloud incident")
def create_incident(req: CreateIncidentRequest) -> Dict[str, Any]:
    try:
        return _get_engine().create_incident(
            org_id=req.org_id,
            incident_name=req.incident_name,
            cloud_provider=req.cloud_provider,
            incident_type=req.incident_type,
            severity=req.severity,
            affected_services=req.affected_services,
            affected_regions=req.affected_regions,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/incidents", summary="List incidents for an org")
def list_incidents(
    org_id: str = Query(..., description="Organisation identifier"),
    status: Optional[str] = Query(default=None),
    cloud_provider: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List cloud IR incidents (canonical envelope, batch-7).

    Class-c contract: empty IS correct for fresh tenants — cloud IR incidents
    are triggered by detection events (CSPM/SIEM/runtime alerts), not derivable
    from any public source. Always returns full envelope with pagination
    context + filters echo + actionable hint when empty.
    """
    rows = _get_engine().list_incidents(
        org_id=org_id, status=status, cloud_provider=cloud_provider
    ) or []
    paged = rows[offset : offset + limit] if offset else rows[:limit]
    envelope: Dict[str, Any] = {
        "items": paged,
        "incidents": paged,  # legacy key preserved
        "total": len(rows),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
        "filters_applied": {
            "status": status,
            "cloud_provider": cloud_provider,
        },
    }
    if not rows:
        envelope["hint"] = (
            "Cloud IR incidents are triggered by detection events (CSPM/SIEM/runtime "
            "alerts). Create one via POST /api/v1/cloud-ir/incidents. Empty IS the "
            "correct response for a fresh tenant — no public source exists."
        )
    return envelope


@router.get("/incidents/{incident_id}", summary="Get a single incident with actions and playbooks")
def get_incident(incident_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().get_incident(incident_id=incident_id, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/incidents/{incident_id}/contain", summary="Mark incident as contained")
def contain_incident(incident_id: str, req: ContainIncidentRequest) -> Dict[str, Any]:
    try:
        return _get_engine().contain_incident(
            incident_id=incident_id,
            org_id=req.org_id,
            blast_radius=req.blast_radius,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/incidents/{incident_id}/actions", summary="Add a containment action to an incident")
def add_containment_action(incident_id: str, req: AddActionRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_containment_action(
            incident_id=incident_id,
            org_id=req.org_id,
            action_type=req.action_type,
            resource_id=req.resource_id,
            description=req.description,
            automated=req.automated,
            executed_by=req.executed_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/actions/{action_id}/complete", summary="Mark a containment action as completed")
def complete_action(action_id: str, req: CompleteActionRequest) -> Dict[str, Any]:
    try:
        return _get_engine().complete_action(
            action_id=action_id,
            org_id=req.org_id,
            result=req.result,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/incidents/{incident_id}/resolve", summary="Mark incident as resolved")
def resolve_incident(incident_id: str, req: ResolveIncidentRequest) -> Dict[str, Any]:
    try:
        return _get_engine().resolve_incident(
            incident_id=incident_id,
            org_id=req.org_id,
            root_cause=req.root_cause,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/playbooks", summary="Create an IR playbook")
def create_playbook(req: CreatePlaybookRequest) -> Dict[str, Any]:
    try:
        return _get_engine().create_playbook(
            org_id=req.org_id,
            playbook_name=req.playbook_name,
            cloud_provider=req.cloud_provider,
            incident_type=req.incident_type,
            steps=req.steps,
            estimated_mins=req.estimated_mins,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/playbooks", summary="List IR playbooks for an org")
def list_playbooks(org_id: str = Query(..., description="Organisation identifier")) -> List[Dict[str, Any]]:
    return _get_engine().list_playbooks(org_id=org_id)


@router.post("/playbooks/{playbook_id}/execute", summary="Execute a playbook (increments execution_count)")
def execute_playbook(playbook_id: str, req: ExecutePlaybookRequest) -> Dict[str, Any]:
    try:
        return _get_engine().execute_playbook(
            playbook_id=playbook_id,
            org_id=req.org_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/metrics", summary="Get IR metrics for an org")
def get_ir_metrics(org_id: str = Query(..., description="Organisation identifier")) -> Dict[str, Any]:
    return _get_engine().get_ir_metrics(org_id=org_id)
