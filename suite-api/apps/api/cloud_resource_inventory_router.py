"""Cloud Resource Inventory Router — ALDECI.

Tracks cloud resources across all major providers with security scoring
and compliance finding management.

Prefix: /api/v1/cloud-inventory
Auth:   api_key_auth dependency

Routes:
  POST   /resources                      register_resource
  GET    /resources                      list_resources
  GET    /resources/{id}                 get_resource
  PATCH  /resources/{id}/state           update_resource_state
  POST   /resources/{id}/findings        record_security_finding
  GET    /findings                       list_findings
  GET    /stats                          get_inventory_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-inventory",
    tags=["cloud-inventory"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy engine cache
# ---------------------------------------------------------------------------
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cloud_resource_inventory_engine import CloudResourceInventoryEngine
        _engine = CloudResourceInventoryEngine()
    return _engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ResourceCreate(BaseModel):
    resource_id: str = Field(..., description="Cloud provider resource identifier")
    resource_name: str = Field("", description="Human-readable resource name")
    provider: str = Field("aws", description="aws/azure/gcp/alibaba/oracle/ibm/digitalocean")
    resource_type: str = Field("compute", description="compute/storage/database/network/iam/container/serverless/cdn/dns/load_balancer")
    region: str = Field("", description="Cloud region")
    account_id: str = Field("", description="Cloud account/subscription ID")
    tags: Dict[str, Any] = Field(default_factory=dict, description="Resource tags")
    resource_state: str = Field("running", description="running/stopped/terminated/unknown/pending")


class ResourceStateUpdate(BaseModel):
    state: str = Field(..., description="running/stopped/terminated/unknown/pending")
    compliance_status: Optional[str] = Field(None, description="compliant/non_compliant/unknown/exempt")


class FindingCreate(BaseModel):
    severity: str = Field("medium", description="critical/high/medium/low")
    title: str = Field("", description="Finding title")
    compliance_check: str = Field("", description="Compliance control reference")
    remediation: str = Field("", description="Remediation guidance")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/resources", status_code=201)
def register_resource(
    body: ResourceCreate,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.register_resource(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/resources")
def list_resources(
    org_id: str = Query("default", description="Organization ID"),
    provider: Optional[str] = Query(None, description="Filter by provider"),
    resource_type: Optional[str] = Query(None, description="Filter by resource_type"),
    compliance_status: Optional[str] = Query(None, description="Filter by compliance_status"),
    resource_state: Optional[str] = Query(None, description="Filter by resource_state"),
) -> Dict[str, Any]:
    engine = _get_engine()
    resources = engine.list_resources(
        org_id,
        provider=provider,
        resource_type=resource_type,
        compliance_status=compliance_status,
        resource_state=resource_state,
    )
    return {"resources": resources, "total": len(resources)}


@router.get("/resources/{resource_id}")
def get_resource(
    resource_id: str,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine()
    resource = engine.get_resource(org_id, resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="resource not found")
    return resource


@router.patch("/resources/{resource_id}/state")
def update_resource_state(
    resource_id: str,
    body: ResourceStateUpdate,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.update_resource_state(
            org_id,
            resource_id,
            body.state,
            compliance_status=body.compliance_status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/resources/{resource_id}/findings", status_code=201)
def record_security_finding(
    resource_id: str,
    body: FindingCreate,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.record_security_finding(org_id, resource_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/findings")
def list_findings(
    org_id: str = Query("default", description="Organization ID"),
    cloud_resource_id: Optional[str] = Query(None, description="Filter by resource internal ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> Dict[str, Any]:
    engine = _get_engine()
    findings = engine.list_findings(
        org_id,
        cloud_resource_id=cloud_resource_id,
        severity=severity,
        status=status,
    )
    return {"findings": findings, "total": len(findings)}


@router.get("/stats")
def get_inventory_stats(
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine()
    return engine.get_inventory_stats(org_id)
