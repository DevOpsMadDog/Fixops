"""Forensics Readiness Router — ALDECI.

Evidence source registration, readiness assessment, and collection plan management.

Prefix: /api/v1/forensics-readiness
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/forensics-readiness/sources                    register_evidence_source
  GET    /api/v1/forensics-readiness/sources                    list_evidence_sources
  POST   /api/v1/forensics-readiness/sources/{id}/assess        assess_readiness
  POST   /api/v1/forensics-readiness/plans                      create_collection_plan
  PUT    /api/v1/forensics-readiness/plans/{id}/execute         execute_collection_plan
  PUT    /api/v1/forensics-readiness/plans/{id}/complete        complete_collection_plan
  GET    /api/v1/forensics-readiness/stats                      get_readiness_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/forensics-readiness",
    tags=["Forensics Readiness"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.forensics_readiness_engine import ForensicsReadinessEngine
        _engine = ForensicsReadinessEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterSourceRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    name: str = Field(..., description="Evidence source name")
    source_type: str = Field(..., description="endpoint_logs/network_pcap/cloud_trail/email_archive/database_audit/identity_logs/application_logs")
    retention_days: int = Field(default=365, description="Data retention period in days")
    collection_method: str = Field(default="api", description="agent/api/syslog/manual")
    status: str = Field(default="active")


class AssessReadinessRequest(BaseModel):
    org_id: str = Field(default="default")
    encryption: bool = Field(default=False)
    integrity_check: bool = Field(default=False)
    chain_of_custody: bool = Field(default=False)
    offsite_backup: bool = Field(default=False)
    access_logging: bool = Field(default=False)


class CreatePlanRequest(BaseModel):
    org_id: str = Field(default="default")
    name: str = Field(..., description="Plan name")
    incident_type: str = Field(..., description="Type of incident")
    priority: str = Field(..., description="low/medium/high/critical")
    target_sources: List[str] = Field(default_factory=list, description="List of source IDs")
    collection_steps: List[str] = Field(default_factory=list, description="Collection procedure steps")


class ExecutePlanRequest(BaseModel):
    org_id: str = Field(default="default")
    executed_by: str = Field(..., description="User or system executing the plan")


class CompletePlanRequest(BaseModel):
    org_id: str = Field(default="default")
    items_collected: int = Field(..., description="Number of evidence items collected")
    notes: str = Field(default="", description="Completion notes")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/sources", dependencies=[Depends(api_key_auth)])
def register_evidence_source(req: RegisterSourceRequest) -> Dict[str, Any]:
    """Register a new evidence source."""
    try:
        data = req.model_dump(exclude={"org_id"})
        return _get_engine().register_evidence_source(req.org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_evidence_source failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/sources", dependencies=[Depends(api_key_auth)])
def list_evidence_sources(
    org_id: str = Query(default="default"),
    source_type: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List evidence sources for the org."""
    try:
        return _get_engine().list_evidence_sources(org_id, source_type=source_type)
    except Exception as exc:
        _logger.exception("list_evidence_sources failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/sources/{source_id}/assess", dependencies=[Depends(api_key_auth)])
def assess_readiness(source_id: str, req: AssessReadinessRequest) -> Dict[str, Any]:
    """Assess forensic readiness of an evidence source."""
    try:
        assessment_data = req.model_dump(exclude={"org_id"})
        return _get_engine().assess_readiness(req.org_id, source_id, assessment_data)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("assess_readiness failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/plans", dependencies=[Depends(api_key_auth)])
def create_collection_plan(req: CreatePlanRequest) -> Dict[str, Any]:
    """Create a forensic collection plan."""
    try:
        data = req.model_dump(exclude={"org_id"})
        return _get_engine().create_collection_plan(req.org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_collection_plan failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/plans/{plan_id}/execute", dependencies=[Depends(api_key_auth)])
def execute_collection_plan(plan_id: str, req: ExecutePlanRequest) -> Dict[str, Any]:
    """Mark a collection plan as executing."""
    try:
        return _get_engine().execute_collection_plan(req.org_id, plan_id, req.executed_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("execute_collection_plan failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/plans/{plan_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_collection_plan(plan_id: str, req: CompletePlanRequest) -> Dict[str, Any]:
    """Mark a collection plan as completed."""
    try:
        return _get_engine().complete_collection_plan(
            req.org_id, plan_id, req.items_collected, req.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("complete_collection_plan failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_readiness_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate forensics readiness statistics for the org."""
    try:
        return _get_engine().get_readiness_stats(org_id)
    except Exception as exc:
        _logger.exception("get_readiness_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
