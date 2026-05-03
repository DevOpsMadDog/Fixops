"""
ALDECI OpenCTI Threat-Intel Router.

Proxies OpenCTI's GraphQL + REST API under /api/v1/opencti/* with auth + scope
guards.  OpenCTI is the source of truth — no SQLite cache, no fallback data.

Endpoints:
  GET  /api/v1/opencti/                    — capability summary
  GET  /api/v1/opencti/api/threat-actors   — list threat actors (paginated)
  GET  /api/v1/opencti/api/indicators      — lookup indicators by type+value
  POST /api/v1/opencti/api/stix-import     — import a STIX 2.1 bundle
  GET  /api/v1/opencti/api/intrusion-sets  — list intrusion sets (paginated)
  GET  /api/v1/opencti/api/malware         — lookup malware by family

NO MOCKS — when OPENCTI_URL or OPENCTI_TOKEN is unset, capability returns
status=unavailable and lookup endpoints return 503.

Vision Pillars: V2 (Threat Intelligence), V3 (Detection)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/opencti",
    tags=["opencti"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test override via monkeypatch)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.opencti_integration_engine import get_opencti_integration_engine

    return get_opencti_integration_engine()


def _engine_errors():
    from core.opencti_integration_engine import (
        OpenCTIUnavailableError,
        OpenCTIUpstreamError,
    )

    return OpenCTIUnavailableError, OpenCTIUpstreamError


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    opencti_url_present: bool
    opencti_token_present: bool
    status: str  # ok | empty | unavailable


class ThreatActor(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    sophistication: Optional[str] = None
    resource_level: Optional[str] = None
    primary_motivation: Optional[str] = None


class ThreatActorsResponse(BaseModel):
    threat_actors: List[ThreatActor]
    total: int


class KillChainPhase(BaseModel):
    kill_chain_name: Optional[str] = None
    phase_name: Optional[str] = None


class Indicator(BaseModel):
    id: Optional[str] = None
    pattern: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    labels: List[str] = Field(default_factory=list)
    kill_chain_phases: List[KillChainPhase] = Field(default_factory=list)


class IndicatorsResponse(BaseModel):
    indicators: List[Indicator]
    total: int


class StixImportRequest(BaseModel):
    bundle: Dict[str, Any] = Field(..., description="STIX 2.1 bundle dict (type=bundle, objects=[...])")


class StixImportResponse(BaseModel):
    imported_objects: int
    created_relationships: int
    work_id: Optional[str] = None


class IntrusionSet(ThreatActor):
    pass


class IntrusionSetsResponse(BaseModel):
    intrusion_sets: List[IntrusionSet]
    total: int


class MalwareItem(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    family: Optional[str] = None
    types: List[str] = Field(default_factory=list)


class MalwareResponse(BaseModel):
    malware: List[MalwareItem]
    total: int


_ALLOWED_INDICATOR_TYPES = {
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "file-sha256",
    "file-md5",
    "url",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_for_engine_error(exc: Exception) -> None:
    OpenCTIUnavailableError, OpenCTIUpstreamError = _engine_errors()
    if isinstance(exc, OpenCTIUnavailableError):
        raise HTTPException(
            status_code=503,
            detail="OpenCTI upstream unavailable: OPENCTI_URL or OPENCTI_TOKEN not configured",
        )
    if isinstance(exc, OpenCTIUpstreamError):
        upstream = getattr(exc, "status_code", 502)
        if upstream == 401:
            raise HTTPException(status_code=502, detail=f"OpenCTI upstream rejected auth: {exc.body[:200]}")
        if upstream == 404:
            raise HTTPException(status_code=404, detail=f"OpenCTI upstream 404: {exc.body[:200]}")
        raise HTTPException(status_code=502, detail=f"OpenCTI upstream {upstream}: {exc.body[:200]}")
    if isinstance(exc, ValueError):
        raise HTTPException(status_code=400, detail=str(exc))
    raise HTTPException(status_code=500, detail=f"OpenCTI integration error: {exc!s}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
def capability_summary() -> CapabilityResponse:
    eng = _get_engine()
    url_present = eng.opencti_url() is not None
    token_present = eng.opencti_token() is not None
    return CapabilityResponse(
        service="OpenCTI",
        endpoints=list(eng.SUPPORTED_ENDPOINTS),
        opencti_url_present=url_present,
        opencti_token_present=token_present,
        status="ok" if (url_present and token_present) else "unavailable",
    )


@router.get("/api/threat-actors", response_model=ThreatActorsResponse)
def list_threat_actors(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ThreatActorsResponse:
    eng = _get_engine()
    try:
        result = eng.list_threat_actors(limit=limit, offset=offset)
    except Exception as exc:
        _raise_for_engine_error(exc)
    return ThreatActorsResponse(
        threat_actors=[ThreatActor(**a) for a in (result.get("threat_actors") or [])],
        total=int(result.get("total") or 0),
    )


@router.get("/api/indicators", response_model=IndicatorsResponse)
def lookup_indicators(
    type: str = Query(..., description="ipv4-addr|ipv6-addr|domain-name|file-sha256|file-md5|url"),
    value: str = Query(..., min_length=1),
) -> IndicatorsResponse:
    if type not in _ALLOWED_INDICATOR_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"type must be one of: {sorted(_ALLOWED_INDICATOR_TYPES)}",
        )
    eng = _get_engine()
    try:
        result = eng.lookup_indicators(type_=type, value=value)
    except Exception as exc:
        _raise_for_engine_error(exc)
    return IndicatorsResponse(
        indicators=[Indicator(**i) for i in (result.get("indicators") or [])],
        total=int(result.get("total") or 0),
    )


@router.post("/api/stix-import", response_model=StixImportResponse)
def import_stix_bundle(payload: StixImportRequest = Body(...)) -> StixImportResponse:
    bundle = payload.bundle
    if not isinstance(bundle, dict):
        raise HTTPException(status_code=400, detail="bundle must be a JSON object")
    if bundle.get("type") != "bundle":
        raise HTTPException(status_code=400, detail="bundle.type must be 'bundle'")
    if not isinstance(bundle.get("objects"), list):
        raise HTTPException(status_code=400, detail="bundle.objects must be a list")
    eng = _get_engine()
    try:
        result = eng.import_stix_bundle(bundle)
    except Exception as exc:
        _raise_for_engine_error(exc)
    return StixImportResponse(
        imported_objects=int(result.get("imported_objects") or 0),
        created_relationships=int(result.get("created_relationships") or 0),
        work_id=result.get("work_id"),
    )


@router.get("/api/intrusion-sets", response_model=IntrusionSetsResponse)
def list_intrusion_sets(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> IntrusionSetsResponse:
    eng = _get_engine()
    try:
        result = eng.list_intrusion_sets(limit=limit, offset=offset)
    except Exception as exc:
        _raise_for_engine_error(exc)
    return IntrusionSetsResponse(
        intrusion_sets=[IntrusionSet(**a) for a in (result.get("intrusion_sets") or [])],
        total=int(result.get("total") or 0),
    )


@router.get("/api/malware", response_model=MalwareResponse)
def lookup_malware(
    family: Optional[str] = Query(default=None, description="malware family name (substring match)"),
) -> MalwareResponse:
    eng = _get_engine()
    try:
        result = eng.lookup_malware(family=family)
    except Exception as exc:
        _raise_for_engine_error(exc)
    return MalwareResponse(
        malware=[MalwareItem(**m) for m in (result.get("malware") or [])],
        total=int(result.get("total") or 0),
    )


__all__ = ["router"]
