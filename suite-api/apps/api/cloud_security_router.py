"""Cloud Security Router — ALDECI.

Wraps CloudSecurityEngine for CSPM account/finding/resource/benchmark management.

Prefix: /api/v1/cloud-security
Auth:   api_key_auth

Routes:
  POST   /accounts                          -- register a cloud account
  GET    /accounts                          -- list accounts (opt. filter by provider)
  POST   /findings                          -- add a cloud security finding
  GET    /findings                          -- list findings (filter: severity, status, category)
  POST   /findings/{finding_id}/resolve     -- mark a finding resolved
  POST   /resources                         -- add a cloud resource
  GET    /resources                         -- list resources (opt. filter: is_public)
  POST   /benchmarks                        -- record a benchmark result
  GET    /benchmarks                        -- list benchmark results (opt. filter: account_id)
  GET    /stats                             -- aggregate cloud security stats
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-security",
    tags=["cloud-security"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine factory — per org_id, SQLite-backed, cheap to instantiate
# ---------------------------------------------------------------------------

@lru_cache(maxsize=64)
def _get_engine(org_id: str):
    from core.cloud_security_engine import CloudSecurityEngine
    return CloudSecurityEngine(org_id=org_id)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AddAccountBody(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=128)
    account_name: str = Field(default="", max_length=200)
    provider: str = Field(default="aws", description="aws | azure | gcp | alibaba")
    region: str = Field(default="", max_length=64)
    status: str = Field(default="healthy", description="healthy | warning | critical")
    resource_count: int = Field(default=0, ge=0)
    finding_count: int = Field(default=0, ge=0)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    last_scanned: Optional[str] = Field(default=None)


class AddFindingBody(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=128)
    resource_id: str = Field(default="", max_length=256)
    resource_type: str = Field(default="", max_length=128)
    resource_name: str = Field(default="", max_length=256)
    region: str = Field(default="", max_length=64)
    severity: str = Field(default="medium", description="critical | high | medium | low | info")
    category: str = Field(default="compliance", description="iam | network | storage | compute | logging | encryption | compliance")
    title: str = Field(default="", max_length=512)
    description: str = Field(default="", max_length=4096)
    recommendation: str = Field(default="", max_length=2048)
    rule_id: str = Field(default="", max_length=128)
    compliance_frameworks: List[str] = Field(default_factory=list)
    status: str = Field(default="open", description="open | suppressed | resolved")


class AddResourceBody(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=128)
    resource_id: str = Field(..., min_length=1, max_length=256)
    resource_type: str = Field(default="", max_length=128)
    resource_name: str = Field(default="", max_length=256)
    region: str = Field(default="", max_length=64)
    provider: str = Field(default="aws", description="aws | azure | gcp | alibaba")
    is_public: bool = Field(default=False)
    is_encrypted: bool = Field(default=True)
    tags: Dict[str, str] = Field(default_factory=dict)


class AddBenchmarkBody(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=128)
    benchmark: str = Field(..., description="cis_aws_v1.5 | azure_cis | gcp_cis | nist_800_53 | pci_dss")
    score: float = Field(..., ge=0.0, le=100.0)
    controls_passed: int = Field(default=0, ge=0)
    controls_failed: int = Field(default=0, ge=0)
    controls_total: int = Field(default=0, ge=0)
    notes: str = Field(default="", max_length=2048)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/accounts", status_code=201)
def add_account(
    body: AddAccountBody,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Register a cloud account in the CSPM engine."""
    try:
        return _get_engine(org_id).add_account(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/accounts")
def list_accounts(
    provider: Optional[str] = Query(default=None, description="aws | azure | gcp | alibaba"),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List cloud accounts, optionally filtered by provider."""
    return _get_engine(org_id).list_accounts(org_id, provider=provider)


@router.post("/findings", status_code=201)
def add_finding(
    body: AddFindingBody,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Record a new cloud security finding."""
    try:
        return _get_engine(org_id).add_finding(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/findings")
def list_findings(
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    account_id: Optional[str] = Query(default=None),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List cloud security findings with optional filters."""
    return _get_engine(org_id).list_findings(
        org_id,
        severity=severity,
        status=status,
        category=category,
        account_id=account_id,
    )


@router.post("/findings/{finding_id}/resolve")
def resolve_finding(
    finding_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Mark a cloud security finding as resolved."""
    ok = _get_engine(org_id).resolve_finding(org_id, finding_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    return {"finding_id": finding_id, "status": "resolved"}


@router.post("/resources", status_code=201)
def add_resource(
    body: AddResourceBody,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Register a cloud resource in the inventory."""
    try:
        return _get_engine(org_id).add_resource(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/resources")
def list_resources(
    is_public: Optional[bool] = Query(default=None),
    account_id: Optional[str] = Query(default=None),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List cloud resources, optionally filtered by public exposure or account."""
    return _get_engine(org_id).list_resources(org_id, account_id=account_id, is_public=is_public)


@router.post("/benchmarks", status_code=201)
def add_benchmark(
    body: AddBenchmarkBody,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Record a CIS/NIST/PCI benchmark result for a cloud account."""
    try:
        return _get_engine(org_id).add_benchmark_result(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/benchmarks")
def list_benchmarks(
    account_id: Optional[str] = Query(default=None),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List benchmark results, optionally filtered by account."""
    return _get_engine(org_id).list_benchmarks(org_id, account_id=account_id)


@router.get("/stats")
def get_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return aggregate cloud security statistics for the org."""
    return _get_engine(org_id).get_cloud_stats(org_id)


__all__ = ["router"]
