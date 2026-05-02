"""API Gateway Security Router — ALDECI.

Endpoints for registering gateways and APIs, recording security events,
and retrieving threat summaries and gateway statistics.

Prefix: /api/v1/api-gateway-security
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/api-gateway-security/gateways                       register_gateway
  GET    /api/v1/api-gateway-security/gateways                       list_gateways
  POST   /api/v1/api-gateway-security/apis                           register_api
  GET    /api/v1/api-gateway-security/apis                           list_apis
  POST   /api/v1/api-gateway-security/events                         record_security_event
  GET    /api/v1/api-gateway-security/events                         list_security_events
  GET    /api/v1/api-gateway-security/apis/{api_id}/threat-summary   get_api_threat_summary
  GET    /api/v1/api-gateway-security/stats                          get_gateway_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/api-gateway-security",
    tags=["API Gateway Security"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.api_gateway_security_engine import APIGatewaySecurityEngine
        _engine = APIGatewaySecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterGatewayRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    name: str = Field(..., description="Gateway name")
    base_url: str = Field(..., description="Base URL of the gateway")
    gateway_type: str = Field(..., description="kong | apigee | aws_api_gw | nginx | custom")
    environment: str = Field("prod", description="prod | staging | dev")


class RegisterApiRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    gateway_id: str = Field(..., description="Parent gateway UUID")
    name: str = Field(..., description="API name")
    version: str = Field("v1", description="API version string")
    path_prefix: str = Field(..., description="URL path prefix (e.g. /api/v1/payments)")
    auth_type: str = Field("api_key", description="api_key | oauth2 | jwt | none")
    rate_limit_rps: int = Field(100, gt=0, description="Requests per second rate limit")


class RecordSecurityEventRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    api_id: str = Field(..., description="API UUID")
    event_type: str = Field(..., description="auth_failure | rate_exceeded | injection | schema_violation | bot")
    source_ip: str = Field(..., description="Attacking source IP")
    request_path: str = Field("", description="Request path that triggered the event")
    severity: str = Field("medium", description="low | medium | high | critical")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/gateways",
    dependencies=[Depends(api_key_auth)],
    summary="Register an API gateway",
)
def register_gateway(req: RegisterGatewayRequest) -> Dict[str, Any]:
    try:
        return _get_engine().register_gateway(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_gateway_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/gateways",
    dependencies=[Depends(api_key_auth)],
    summary="List registered gateways",
)
def list_gateways(org_id: str = Query(..., description="Organisation identifier")) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_gateways(org_id)
    except Exception as exc:
        _logger.exception("list_gateways_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/apis",
    dependencies=[Depends(api_key_auth)],
    summary="Register an API on a gateway",
)
def register_api(req: RegisterApiRequest) -> Dict[str, Any]:
    try:
        return _get_engine().register_api(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_api_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/apis",
    dependencies=[Depends(api_key_auth)],
    summary="List registered APIs",
)
def list_apis(
    org_id: str = Query(..., description="Organisation identifier"),
    gateway_id: Optional[str] = Query(None, description="Filter by gateway UUID"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_apis(org_id, gateway_id=gateway_id)
    except Exception as exc:
        _logger.exception("list_apis_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/events",
    dependencies=[Depends(api_key_auth)],
    summary="Record a security event",
)
def record_security_event(req: RecordSecurityEventRequest) -> Dict[str, Any]:
    try:
        return _get_engine().record_security_event(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        _logger.exception("record_security_event_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/events",
    dependencies=[Depends(api_key_auth)],
    summary="List security events",
)
def list_security_events(
    org_id: str = Query(..., description="Organisation identifier"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_security_events(
            org_id, event_type=event_type, severity=severity, limit=limit
        )
    except Exception as exc:
        _logger.exception("list_security_events_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/apis/{api_id}/threat-summary",
    dependencies=[Depends(api_key_auth)],
    summary="Get threat summary for an API",
)
def get_api_threat_summary(
    api_id: str,
    org_id: str = Query(..., description="Organisation identifier"),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_api_threat_summary(org_id, api_id)
    except Exception as exc:
        _logger.exception("get_api_threat_summary_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/stats",
    dependencies=[Depends(api_key_auth)],
    summary="Get gateway security stats for an org",
)
def get_gateway_stats(org_id: str = Query(..., description="Organisation identifier")) -> Dict[str, Any]:
    try:
        return _get_engine().get_gateway_stats(org_id)
    except Exception as exc:
        _logger.exception("get_gateway_stats_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
