"""Network Traffic Router — ALDECI.

FastAPI router for network flow analysis and anomaly detection.
Prefix: /api/v1/network-traffic
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(
    prefix="/api/v1/network-traffic",
    tags=["network-traffic"],
    dependencies=[Depends(api_key_auth)],
)

# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.network_traffic_engine import NetworkTrafficEngine
        _engine = NetworkTrafficEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class FlowIn(BaseModel):
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 0
    duration_ms: int = 0
    direction: str = "outbound"


class RuleIn(BaseModel):
    rule_name: str
    src_cidr: str = ""
    dst_cidr: str = ""
    port_range: str = ""
    protocol: str = "tcp"
    action: str = "monitor"
    priority: int = 100
    enabled: bool = True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/flows", summary="Record a network flow")
def record_flow(
    org_id: str,
    body: FlowIn,
) -> Dict[str, Any]:
    try:
        return _get_engine().record_flow(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/flows", summary="List network flows")
def list_flows(
    org_id: str,
    flagged: Optional[bool] = Query(None),
    anomaly_type: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    return _get_engine().list_flows(org_id, flagged=flagged, anomaly_type=anomaly_type, src_ip=src_ip, limit=limit)


@router.get("/flows/{flow_id}", summary="Get a single flow")
def get_flow(org_id: str, flow_id: str) -> Dict[str, Any]:
    result = _get_engine().get_flow(org_id, flow_id)
    if not result:
        raise HTTPException(status_code=404, detail="Flow not found.")
    return result


@router.get("/anomalies", summary="List traffic anomalies")
def list_anomalies(
    org_id: str,
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    return _get_engine().list_anomalies(org_id, severity=severity, status=status, limit=limit)


@router.post("/anomalies/{anomaly_id}/resolve", summary="Resolve an anomaly")
def resolve_anomaly(org_id: str, anomaly_id: str) -> Dict[str, Any]:
    found = _get_engine().resolve_anomaly(org_id, anomaly_id)
    if not found:
        raise HTTPException(status_code=404, detail="Anomaly not found.")
    return {"status": "resolved", "anomaly_id": anomaly_id}


@router.post("/rules", summary="Create a traffic rule")
def create_rule(org_id: str, body: RuleIn) -> Dict[str, Any]:
    try:
        return _get_engine().create_rule(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/rules", summary="List traffic rules")
def list_rules(org_id: str) -> List[Dict[str, Any]]:
    return _get_engine().list_rules(org_id)


@router.get("/stats", summary="Get traffic statistics")
def get_traffic_stats(org_id: str) -> Dict[str, Any]:
    return _get_engine().get_traffic_stats(org_id)


@router.get("/top-talkers", summary="Get top talkers by bytes")
def get_top_talkers(
    org_id: str,
    limit: int = Query(10, ge=1, le=100),
) -> List[Dict[str, Any]]:
    return _get_engine().get_top_talkers(org_id, limit=limit)
