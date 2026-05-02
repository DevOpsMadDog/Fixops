"""Cloud Drift Detection Router — ALDECI.

Detects configuration drift in cloud infrastructure (IaC vs actual state).

Prefix: /api/v1/cloud-drift
Auth:   api_key_auth dependency

Routes:
  GET    /baselines                         list_baselines
  POST   /baselines                         register_baseline
  GET    /drifts                            list_drifts
  POST   /drifts                            record_drift
  POST   /drifts/{drift_id}/acknowledge     acknowledge_drift
  POST   /drifts/{drift_id}/remediate       remediate_drift
  POST   /scan                              run_drift_scan
  GET    /stats                             get_drift_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-drift",
    tags=["cloud-drift"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy engine cache
# ---------------------------------------------------------------------------
_engine_cache: Dict[str, Any] = {}

_SIMULATION_WARNING: Dict[str, Any] = {
    "is_simulated": True,
    "engine": "cloud_drift_engine",
    "real_integration_required": "/api/v1/connectors/cspm-{aws,azure,gcp}/configure",
    "do_not_use_in_demo": True,
}


def _wrap(data: Any) -> Dict[str, Any]:
    """Wrap engine output with simulation warning envelope."""
    return {"data": data, "_simulation_warning": _SIMULATION_WARNING}


def _get_engine(org_id: str):
    if org_id not in _engine_cache:
        from core.cloud_drift_engine import CloudDriftDetectionEngine
        _engine_cache[org_id] = CloudDriftDetectionEngine()
    return _engine_cache[org_id]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class BaselineCreate(BaseModel):
    resource_id: str = Field(..., description="Cloud resource identifier")
    resource_type: str = Field("ec2", description="ec2 / s3 / rds / lambda / sg / vpc")
    resource_name: str = Field("", description="Human-readable resource name")
    expected_config: Dict[str, Any] = Field(default_factory=dict, description="Expected configuration from IaC")
    source: str = Field("terraform", description="terraform / cloudformation / manual")
    environment: str = Field("prod", description="prod / staging / dev")


class DriftCreate(BaseModel):
    resource_id: str = Field(..., description="Cloud resource identifier")
    drift_type: str = Field("config_changed", description="config_changed / resource_deleted / new_resource / tag_missing / permission_widened")
    severity: str = Field("medium", description="critical / high / medium / low")
    expected_value: str = Field("", description="Expected configuration value")
    actual_value: str = Field("", description="Actual observed configuration value")
    detected_at: Optional[str] = Field(None, description="ISO 8601 detection timestamp")


class AcknowledgeBody(BaseModel):
    acknowledged_by: str = Field(..., description="Identity of acknowledger")
    notes: str = Field("", description="Acknowledgement notes")


class RemediateBody(BaseModel):
    remediated_by: str = Field(..., description="Identity of remediator")
    method: str = Field("manual", description="manual / automated")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/baselines")
def list_baselines(
    org_id: str = Query("default", description="Organization ID"),
    environment: Optional[str] = Query(None, description="Filter by environment"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    baselines = engine.list_baselines(org_id, environment=environment)
    return _wrap({"baselines": baselines, "total": len(baselines)})


@router.post("/baselines", status_code=201)
def register_baseline(
    body: BaselineCreate,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    return _wrap(engine.register_baseline(org_id, body.model_dump()))


@router.get("/drifts")
def list_drifts(
    org_id: str = Query("default", description="Organization ID"),
    severity: Optional[str] = Query(None),
    drift_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None, description="open / acknowledged / remediated"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    drifts = engine.list_drifts(org_id, severity=severity, drift_type=drift_type, status=status)
    return _wrap({"drifts": drifts, "total": len(drifts)})


@router.post("/drifts", status_code=201)
def record_drift(
    body: DriftCreate,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    data = body.model_dump()
    if data.get("detected_at") is None:
        data.pop("detected_at", None)
    return _wrap(engine.record_drift(org_id, data))


@router.post("/drifts/{drift_id}/acknowledge")
def acknowledge_drift(
    drift_id: str,
    body: AcknowledgeBody,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    result = engine.acknowledge_drift(org_id, drift_id, body.acknowledged_by, body.notes)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return _wrap(result)


@router.post("/drifts/{drift_id}/remediate")
def remediate_drift(
    drift_id: str,
    body: RemediateBody,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    result = engine.remediate_drift(org_id, drift_id, body.remediated_by, body.method)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return _wrap(result)


@router.post("/scan")
def run_drift_scan(
    org_id: str = Query("default", description="Organization ID"),
    environment: Optional[str] = Query(None, description="Filter scan to environment"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    return _wrap(engine.run_drift_scan(org_id, environment=environment))


@router.get("/stats")
def get_drift_stats(
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine(org_id)
    return _wrap(engine.get_drift_stats(org_id))
