"""CrowdStrike Falcon EDR Live REST Router — ALDECI.

Wraps ``core.falcon_edr_engine.FalconEDREngine`` with REST endpoints for
detections, incidents, and IoCs against the live Falcon API. Distinct
from ``crowdstrike_falcon_router.py`` (which ingests offline JSON dumps
via ``connectors/crowdstrike_falcon_connector.py``) — this router is the
*live OAuth2* surface.

Prefix: /api/v1/falcon
Auth:   api_key_auth dependency (mount layer adds read:scans scope)

Routes:
  GET  /api/v1/falcon/                                 capability summary
  GET  /api/v1/falcon/detects/queries/detects          list detection ids
  POST /api/v1/falcon/detects/entities/summaries       fetch detection details
  GET  /api/v1/falcon/incidents/queries/incidents      list incident ids
  GET  /api/v1/falcon/iocs/queries/indicators          list IoC ids by type
  POST /api/v1/falcon/iocs/entities/indicators         submit IoCs

NO MOCKS rule: when FALCON_CLIENT_ID/FALCON_CLIENT_SECRET are missing
the capability summary reports ``status="unavailable"`` and every live
endpoint returns HTTP 503. We do not fabricate detection ids, incidents,
or indicators ever.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/falcon",
    tags=["CrowdStrike Falcon EDR"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch via reset_falcon_edr_engine().
    from core.falcon_edr_engine import get_falcon_edr_engine
    return get_falcon_edr_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    client_id_present: bool
    client_secret_present: bool
    status: str  # ok | empty | unavailable


class DetectQueryResponse(BaseModel):
    meta: Dict[str, Any] = Field(default_factory=dict)
    resources: List[str] = Field(default_factory=list)


class SummariesRequest(BaseModel):
    ids: List[str] = Field(..., min_length=1, max_length=1000)


class DeviceInfo(BaseModel):
    hostname: str = ""
    platform_name: str = ""
    os_version: str = ""


class DetectSummary(BaseModel):
    detection_id: str = ""
    severity: int = 0
    severity_name: str = ""
    status: str = ""
    behaviors: List[Dict[str, Any]] = Field(default_factory=list)
    device: DeviceInfo = Field(default_factory=DeviceInfo)
    hostinfo: Dict[str, Any] = Field(default_factory=dict)


class SummariesResponse(BaseModel):
    meta: Dict[str, Any] = Field(default_factory=dict)
    resources: List[DetectSummary] = Field(default_factory=list)


class IncidentQueryResponse(BaseModel):
    meta: Dict[str, Any] = Field(default_factory=dict)
    resources: List[str] = Field(default_factory=list)


class IndicatorQueryResponse(BaseModel):
    meta: Dict[str, Any] = Field(default_factory=dict)
    resources: List[str] = Field(default_factory=list)


class IndicatorIn(BaseModel):
    type: str = Field(..., description="ipv4|ipv6|domain|md5|sha256|sha1")
    value: str = Field(..., min_length=1, max_length=4096)
    action: str = Field(default="detect", description="detect|prevent|allow|no_action")
    severity: Optional[str] = None
    source: Optional[str] = None
    description: Optional[str] = None
    expiration: Optional[str] = None
    platforms: Optional[List[str]] = None


class IndicatorSubmitRequest(BaseModel):
    indicators: List[IndicatorIn] = Field(..., min_length=1, max_length=200)


class IndicatorOut(BaseModel):
    id: str = ""
    value: str = ""
    action: str = ""


class IndicatorSubmitResponse(BaseModel):
    meta: Dict[str, Any] = Field(default_factory=dict)
    resources: List[IndicatorOut] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run a Falcon call, translating engine errors to HTTP responses.

    FalconUnavailableError -> 503 (auth missing, network, upstream error)
    ValueError             -> 422 (input validation)
    """
    from core.falcon_edr_engine import FalconUnavailableError
    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FalconUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service summary — safe to call without Falcon credentials."""
    eng = _engine()
    cid = eng.client_id_present()
    csec = eng.client_secret_present()
    if cid and csec:
        status = "ok"
    elif cid or csec:
        status = "empty"
    else:
        status = "unavailable"
    return CapabilityResponse(
        service="CrowdStrike Falcon",
        endpoints=[
            "/detects/queries/detects",
            "/detects/entities/summaries",
            "/incidents/queries/incidents",
            "/iocs/queries/indicators",
            "/iocs/entities/indicators",
        ],
        client_id_present=cid,
        client_secret_present=csec,
        status=status,
    )


@router.get("/detects/queries/detects", response_model=DetectQueryResponse)
async def query_detects(
    filter: Optional[str] = Query(None, alias="filter", description="Falcon FQL filter"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=100_000),
    sort: Optional[str] = Query(None, max_length=200),
) -> DetectQueryResponse:
    eng = _engine()
    data = _serve(lambda: eng.query_detects(fql=filter, limit=limit, offset=offset, sort=sort))
    return DetectQueryResponse(**data)


@router.post("/detects/entities/summaries", response_model=SummariesResponse)
async def get_detect_summaries(req: SummariesRequest) -> SummariesResponse:
    eng = _engine()
    data = _serve(lambda: eng.get_detect_summaries(req.ids))
    return SummariesResponse(**data)


@router.get("/incidents/queries/incidents", response_model=IncidentQueryResponse)
async def query_incidents(
    filter: Optional[str] = Query(None, alias="filter"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=100_000),
    sort: Optional[str] = Query(None, max_length=200),
) -> IncidentQueryResponse:
    eng = _engine()
    data = _serve(lambda: eng.query_incidents(fql=filter, limit=limit, offset=offset, sort=sort))
    return IncidentQueryResponse(**data)


@router.get("/iocs/queries/indicators", response_model=IndicatorQueryResponse)
async def query_indicators(
    type: str = Query(..., description="ipv4|ipv6|domain|md5|sha256|sha1"),
    limit: int = Query(50, ge=1, le=500),
) -> IndicatorQueryResponse:
    eng = _engine()
    data = _serve(lambda: eng.query_indicators(ioc_type=type, limit=limit))
    return IndicatorQueryResponse(**data)


@router.post("/iocs/entities/indicators", response_model=IndicatorSubmitResponse)
async def submit_indicators(req: IndicatorSubmitRequest) -> IndicatorSubmitResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.submit_indicators([i.model_dump() for i in req.indicators])
    )
    return IndicatorSubmitResponse(**data)


__all__ = ["router"]
