"""Cloud Cost Security Router — ALDECI.

Endpoints for cloud cost anomaly detection and abandoned resource management.

Prefix: /api/v1/cloud-cost
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/cloud-cost/snapshots                    record_snapshot
  GET    /api/v1/cloud-cost/snapshots                    list_snapshots
  POST   /api/v1/cloud-cost/abandoned-resources          add_abandoned_resource
  GET    /api/v1/cloud-cost/abandoned-resources          list_abandoned_resources
  POST   /api/v1/cloud-cost/abandoned-resources/{id}/terminate  terminate_resource
  POST   /api/v1/cloud-cost/budgets                      create_budget
  GET    /api/v1/cloud-cost/budgets                      list_budgets
  POST   /api/v1/cloud-cost/anomalies                    record_anomaly
  GET    /api/v1/cloud-cost/anomalies                    list_anomalies
  POST   /api/v1/cloud-cost/anomalies/{id}/resolve       resolve_anomaly
  GET    /api/v1/cloud-cost/stats                        get_cost_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-cost",
    tags=["cloud-cost"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cloud_cost_security_engine import CloudCostSecurityEngine
        _engine = CloudCostSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SnapshotCreate(BaseModel):
    org_id: str = Field("default")
    account_id: str = Field("")
    provider: str = Field("aws")
    service_name: str = Field("")
    region: str = Field("")
    cost_usd: float = Field(0.0)
    previous_cost_usd: float = Field(0.0)
    change_pct: float = Field(0.0)
    snapshot_date: str = Field("")
    last_used: Optional[str] = None
    has_public_ip: bool = Field(False)
    is_idle: bool = Field(False)


class AbandonedResourceCreate(BaseModel):
    org_id: str = Field("default")
    account_id: str = Field("")
    resource_id: str = Field("")
    resource_type: str = Field("")
    resource_name: str = Field("")
    region: str = Field("")
    provider: str = Field("aws")
    last_used: Optional[str] = None
    monthly_cost_usd: float = Field(0.0)
    security_risk: bool = Field(False)
    risk_reason: str = Field("")


class BudgetCreate(BaseModel):
    org_id: str = Field("default")
    account_id: str = Field("")
    budget_name: str
    period: str = Field("monthly")
    limit_usd: float = Field(0.0)
    current_spend_usd: float = Field(0.0)
    alert_threshold_pct: int = Field(80)


class AnomalyCreate(BaseModel):
    org_id: str = Field("default")
    account_id: str = Field("")
    service_name: str = Field("")
    cost_usd: float = Field(0.0)
    expected_usd: float = Field(0.0)
    deviation_pct: float = Field(0.0)
    anomaly_type: str = Field("spike")
    severity: str = Field("medium")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/snapshots", summary="Record cost snapshot", dependencies=[Depends(api_key_auth)])
def record_snapshot(req: SnapshotCreate) -> Dict[str, Any]:
    """Record a cloud cost snapshot. Anomaly detection runs automatically."""
    engine = _get_engine()
    try:
        return engine.record_snapshot(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/snapshots", summary="List cost snapshots", dependencies=[Depends(api_key_auth)])
def list_snapshots(
    org_id: str = Query("default"),
    account_id: Optional[str] = Query(None),
    anomaly: Optional[bool] = Query(None),
) -> Dict[str, Any]:
    """List cost snapshots; falls back to AWS Cost Explorer.

    Type-a #18 wiring: when the org has no recorded snapshots, the engine
    falls back to AWS Cost Explorer (when AWS_ACCESS_KEY_ID/SECRET or
    AWS_PROFILE is set and boto3 is installed). Returns a 5-state envelope
    (org_registered / aws_cost_explorer / needs_credentials / needs_data /
    connector_error). NEVER mocks.
    """
    engine = _get_engine()
    return engine.list_snapshots_with_cost_explorer_fallback(
        org_id, account_id=account_id, anomaly=anomaly,
    )


@router.post("/abandoned-resources", summary="Register abandoned resource", dependencies=[Depends(api_key_auth)])
def add_abandoned_resource(req: AbandonedResourceCreate) -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.add_abandoned_resource(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/abandoned-resources", summary="List abandoned resources", dependencies=[Depends(api_key_auth)])
def list_abandoned_resources(
    org_id: str = Query("default"),
    provider: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    engine = _get_engine()
    return engine.list_abandoned_resources(org_id, provider=provider, status=status)


@router.post("/abandoned-resources/{resource_id}/terminate", summary="Terminate resource", dependencies=[Depends(api_key_auth)])
def terminate_resource(
    resource_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    engine = _get_engine()
    ok = engine.terminate_resource(org_id, resource_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Resource not found")
    return {"terminated": True}


@router.post("/budgets", summary="Create cost budget", dependencies=[Depends(api_key_auth)])
def create_budget(req: BudgetCreate) -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.create_budget(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/budgets", summary="List cost budgets", dependencies=[Depends(api_key_auth)])
def list_budgets(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    engine = _get_engine()
    return engine.list_budgets(org_id)


@router.post("/anomalies", summary="Record cost anomaly", dependencies=[Depends(api_key_auth)])
def record_anomaly(req: AnomalyCreate) -> Dict[str, Any]:
    engine = _get_engine()
    return engine.record_anomaly(req.org_id, req.model_dump())


@router.get("/anomalies", summary="List cost anomalies", dependencies=[Depends(api_key_auth)])
def list_anomalies(
    org_id: str = Query("default"),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    engine = _get_engine()
    return engine.list_anomalies(org_id, severity=severity, status=status)


@router.post("/anomalies/{anomaly_id}/resolve", summary="Resolve anomaly", dependencies=[Depends(api_key_auth)])
def resolve_anomaly(
    anomaly_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    engine = _get_engine()
    ok = engine.resolve_anomaly(org_id, anomaly_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return {"resolved": True}


@router.get("/stats", summary="Cloud cost security stats", dependencies=[Depends(api_key_auth)])
def get_cost_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    engine = _get_engine()
    return engine.get_cost_stats(org_id)


# ---------------------------------------------------------------------------
# Cost Items — security-lens resource cost tracking
# ---------------------------------------------------------------------------

class CostItemCreate(BaseModel):
    org_id: str = Field("default")
    cloud_provider: str = Field("aws")
    service: str = Field("")
    resource_id: str = Field("")
    monthly_cost_usd: float = Field(0.0)
    security_relevance: str = Field("low")
    tags: Dict[str, Any] = Field(default_factory=dict)


class CostPolicyCreate(BaseModel):
    org_id: str = Field("default")
    name: str
    max_monthly_usd: float = Field(0.0)
    resource_type: str = Field("")
    action: str = Field("alert")


class FlagResourceRequest(BaseModel):
    resource_id: str
    reason: str
    org_id: str = Field("default")


@router.post("/items", summary="Record cost item", dependencies=[Depends(api_key_auth)], status_code=201)
def record_cost_item(req: CostItemCreate) -> Dict[str, Any]:
    """Record a cloud resource cost item with security relevance tagging."""
    engine = _get_engine()
    try:
        return engine.record_cost_item(req.org_id, req.model_dump())
    except Exception as exc:
        _logger.exception("Error recording cost item")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/items", summary="List cost items", dependencies=[Depends(api_key_auth)])
def list_cost_items(
    org_id: str = Query("default"),
    cloud_provider: Optional[str] = Query(None),
    security_relevance: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    engine = _get_engine()
    return engine.list_cost_items(org_id, cloud_provider=cloud_provider, security_relevance=security_relevance)


@router.post("/items/flag", summary="Flag unused resource", dependencies=[Depends(api_key_auth)])
def flag_unused_resource(req: FlagResourceRequest) -> Dict[str, Any]:
    """Flag a resource for decommission review."""
    engine = _get_engine()
    return engine.flag_unused_resource(req.org_id, req.resource_id, req.reason)


@router.get("/items/spend-breakdown", summary="Security spend breakdown", dependencies=[Depends(api_key_auth)])
def get_security_spend_breakdown(org_id: str = Query("default")) -> Dict[str, Any]:
    engine = _get_engine()
    return engine.get_security_spend_breakdown(org_id)


@router.get("/items/anomalies", summary="Detect cost anomalies (MoM >50%)", dependencies=[Depends(api_key_auth)])
def detect_cost_anomalies(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    engine = _get_engine()
    return engine.detect_cost_anomalies(org_id)


@router.post("/policies", summary="Create cost policy", dependencies=[Depends(api_key_auth)], status_code=201)
def create_cost_policy(req: CostPolicyCreate) -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.create_cost_policy(req.org_id, req.model_dump())
    except Exception as exc:
        _logger.exception("Error creating cost policy")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/policies", summary="List cost policies", dependencies=[Depends(api_key_auth)])
def list_cost_policies(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    engine = _get_engine()
    return engine.list_cost_policies(org_id)
