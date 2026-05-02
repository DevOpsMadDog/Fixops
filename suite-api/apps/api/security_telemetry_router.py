"""Security Telemetry Router — ALDECI.

Ingests and aggregates security telemetry datapoints with alert rule evaluation.

Prefix: /api/v1/security-telemetry
Auth:   api_key_auth dependency

Routes:
  POST   /datapoints          ingest_telemetry
  GET    /datapoints          list_telemetry
  GET    /datapoints/latest   get_latest
  POST   /aggregate           aggregate_telemetry
  POST   /rules               create_alert_rule
  GET    /rules               list_alert_rules
  POST   /rules/check         check_alert_rules
  GET    /stats               get_telemetry_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-telemetry",
    tags=["security-telemetry"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy engine cache
# ---------------------------------------------------------------------------
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_telemetry_engine import SecurityTelemetryEngine
        _engine = SecurityTelemetryEngine()
    return _engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class DatapointCreate(BaseModel):
    telemetry_type: str = Field("events_per_second", description="Type of telemetry metric")
    source: str = Field("siem", description="siem/edr/ndr/firewall/ids/cloud/custom")
    value: float = Field(0.0, description="Metric value")
    unit: str = Field("", description="Unit of measurement")
    tags: Dict[str, Any] = Field(default_factory=dict, description="Optional tags")
    collected_at: Optional[str] = Field(None, description="ISO 8601 collection timestamp")


class AggregateRequest(BaseModel):
    telemetry_type: str = Field(..., description="Type of telemetry metric")
    aggregation: str = Field("avg", description="avg/sum/max/min/count/p95/p99")
    source: Optional[str] = Field(None, description="Filter by source")
    hours: int = Field(24, description="Look-back window in hours", ge=1)


class AlertRuleCreate(BaseModel):
    name: str = Field(..., description="Alert rule name")
    telemetry_type: str = Field(..., description="Telemetry type to monitor")
    aggregation: str = Field("avg", description="avg/sum/max/min/count/p95/p99")
    threshold: float = Field(0.0, description="Threshold value")
    operator: str = Field("gt", description="gt/lt/gte/lte")
    source: str = Field("", description="Optional source filter")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/datapoints", status_code=201)
def ingest_telemetry(
    body: DatapointCreate,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine()
    try:
        data = body.model_dump()
        if data.get("collected_at") is None:
            data.pop("collected_at", None)
        return engine.ingest_telemetry(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/datapoints/latest")
def get_latest(
    org_id: str = Query("default", description="Organization ID"),
    telemetry_type: str = Query(..., description="Telemetry type"),
    source: Optional[str] = Query(None, description="Filter by source"),
) -> Dict[str, Any]:
    engine = _get_engine()
    result = engine.get_latest(org_id, telemetry_type, source=source)
    if not result:
        raise HTTPException(status_code=404, detail="no datapoints found")
    return result


@router.get("/datapoints")
def list_telemetry(
    org_id: str = Query("default", description="Organization ID"),
    telemetry_type: Optional[str] = Query(None, description="Filter by telemetry type"),
    source: Optional[str] = Query(None, description="Filter by source"),
    limit: int = Query(100, description="Maximum results", ge=1, le=1000),
) -> Dict[str, Any]:
    engine = _get_engine()
    datapoints = engine.list_telemetry(org_id, telemetry_type=telemetry_type, source=source, limit=limit)
    return {"datapoints": datapoints, "total": len(datapoints)}


@router.post("/aggregate")
def aggregate_telemetry(
    body: AggregateRequest,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.aggregate_telemetry(
            org_id,
            body.telemetry_type,
            body.aggregation,
            source=body.source,
            hours=body.hours,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/rules", status_code=201)
def create_alert_rule(
    body: AlertRuleCreate,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.create_alert_rule(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/rules")
def list_alert_rules(
    org_id: str = Query("default", description="Organization ID"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
) -> Dict[str, Any]:
    engine = _get_engine()
    rules = engine.list_alert_rules(org_id, enabled=enabled)
    return {"rules": rules, "total": len(rules)}


@router.post("/rules/check")
def check_alert_rules(
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine()
    triggered = engine.check_alert_rules(org_id)
    return {"triggered": triggered, "total": len(triggered)}


@router.get("/stats")
def get_telemetry_stats(
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    engine = _get_engine()
    return engine.get_telemetry_stats(org_id)
