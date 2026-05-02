"""Cloud Security Engine Router — ALDECI.

Endpoints for CSPM + cloud misconfiguration tracking.

Prefix: /api/v1/cloud-security-engine
Auth:   api_key_auth dependency

Routes:
  POST   /accounts                         add_account
  GET    /accounts                         list_accounts
  POST   /findings                         add_finding
  GET    /findings                         list_findings
  PATCH  /findings/{finding_id}/resolve    resolve_finding
  POST   /resources                        add_resource
  GET    /resources                        list_resources
  POST   /benchmarks                       add_benchmark_result
  GET    /benchmarks                       list_benchmarks
  GET    /stats                            get_cloud_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-security-engine",
    tags=["cloud-security-engine"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------
_engine = None
_engine_org_cache: Dict[str, Any] = {}


def _get_engine(org_id: str):
    """Return (or create) a CloudSecurityEngine instance for the org."""
    if org_id not in _engine_org_cache:
        from core.cloud_security_engine import get_engine
        _engine_org_cache[org_id] = get_engine(org_id)
    return _engine_org_cache[org_id]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AccountIn(BaseModel):
    account_id: str
    account_name: str = ""
    provider: str = "aws"
    region: str = ""
    status: str = "healthy"
    resource_count: int = 0
    finding_count: int = 0
    risk_score: float = 0.0
    last_scanned: Optional[str] = None


class FindingIn(BaseModel):
    account_id: str
    resource_id: str = ""
    resource_type: str = ""
    resource_name: str = ""
    region: str = ""
    severity: str = "medium"
    category: str = "compliance"
    title: str = ""
    description: str = ""
    remediation: str = ""
    status: str = "open"
    cis_control: str = ""
    compliance_frameworks: List[str] = Field(default_factory=list)
    risk_score: float = 0.0


class ResourceIn(BaseModel):
    account_id: str
    resource_id: str = ""
    resource_type: str = ""
    resource_name: str = ""
    region: str = ""
    tags: Dict[str, str] = Field(default_factory=dict)
    security_score: float = 100.0
    finding_count: int = 0
    is_public: bool = False
    is_encrypted: bool = True


class BenchmarkIn(BaseModel):
    account_id: str
    benchmark: str = "cis_aws_v1.5"
    pass_count: int = 0
    fail_count: int = 0
    score: Optional[float] = None
    last_run: Optional[str] = None


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

@router.post("/accounts", summary="Register a cloud account")
def add_account(
    body: AccountIn,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    try:
        return engine.add_account(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/accounts", summary="List cloud accounts")
def list_accounts(
    org_id: str = Query(..., description="Organization ID"),
    provider: Optional[str] = Query(None, description="Filter by provider"),
) -> List[Dict[str, Any]]:
    engine = _get_engine(org_id)
    return engine.list_accounts(org_id, provider=provider)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@router.post("/findings", summary="Create a cloud security finding")
def add_finding(
    body: FindingIn,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    try:
        return engine.add_finding(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/findings", summary="List cloud security findings")
def list_findings(
    org_id: str = Query(..., description="Organization ID"),
    account_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    engine = _get_engine(org_id)
    return engine.list_findings(
        org_id,
        account_id=account_id,
        severity=severity,
        category=category,
        status=status,
        limit=limit,
    )


@router.patch("/findings/{finding_id}/resolve", summary="Resolve a cloud finding")
def resolve_finding(
    finding_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    updated = engine.resolve_finding(org_id, finding_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return {"finding_id": finding_id, "status": "resolved"}


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@router.post("/resources", summary="Register a cloud resource")
def add_resource(
    body: ResourceIn,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    try:
        return engine.add_resource(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/resources", summary="List cloud resources")
def list_resources(
    org_id: str = Query(..., description="Organization ID"),
    account_id: Optional[str] = Query(None),
    is_public: Optional[bool] = Query(None),
) -> List[Dict[str, Any]]:
    engine = _get_engine(org_id)
    return engine.list_resources(org_id, account_id=account_id, is_public=is_public)


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

@router.post("/benchmarks", summary="Save a benchmark run result")
def add_benchmark_result(
    body: BenchmarkIn,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    try:
        return engine.add_benchmark_result(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/benchmarks", summary="List benchmark results")
def list_benchmarks(
    org_id: str = Query(..., description="Organization ID"),
    account_id: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    engine = _get_engine(org_id)
    return engine.list_benchmarks(org_id, account_id=account_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", summary="Get cloud security stats for org")
def get_cloud_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    return engine.get_cloud_stats(org_id)
