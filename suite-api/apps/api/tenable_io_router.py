"""Tenable.io Vulnerability Scanner Router — ALDECI.

REST surface under prefix ``/api/v1/tenable-io`` wrapping
``core.tenable_io_engine``.

Endpoints
---------
* GET  /                                        — capability summary
* GET  /scans                                   — list scans
* GET  /scans/{scan_id}                         — scan detail (info + hosts + vulns)
* GET  /scans/{scan_id}/hosts/{host_id}         — per-host vulns + compliance
* GET  /agents                                  — agent inventory (limit/offset)
* GET  /policies                                — scan policies
* POST /workbenches/vulnerabilities             — workbench query (date_range, severity, vpr_score)

Auth
----
api_key_auth dependency (mount layer adds scope checks — read:scans).

NO MOCKS rule
-------------
* When TENABLE_ACCESS_KEY or TENABLE_SECRET_KEY is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenable-io",
    tags=["Tenable.io"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.tenable_io_engine import get_tenable_io_engine

    return get_tenable_io_engine()


def _serve(callable_):
    """Run a Tenable call, translating engine errors to HTTP responses."""
    from core.tenable_io_engine import TenableUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except TenableUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    tenable_access_key_present: bool
    tenable_secret_key_present: bool
    status: str  # ok | empty | unavailable


class ScanEntry(BaseModel):
    id: int = 0
    uuid: str = ""
    name: str = ""
    type: str = ""
    status: str = ""
    owner: str = ""
    creation_date: int = 0
    last_modification_date: int = 0
    starttime: str = ""
    schedule_uuid: str = ""
    has_triggers: bool = False
    scan_uuid: str = ""


class ScansResponse(BaseModel):
    scans: List[ScanEntry] = Field(default_factory=list)


class ScanInfo(BaseModel):
    name: str = ""
    status: str = ""
    scan_start: int = 0
    scan_end: int = 0
    targets: str = ""
    hostcount: int = 0
    severity_processed: int = 0
    hosts_processed: int = 0
    scan_type: str = ""


class ScanHostEntry(BaseModel):
    host_id: int = 0
    hostname: str = ""
    score: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanVulnEntry(BaseModel):
    count: int = 0
    severity: int = 0
    plugin_id: int = 0
    plugin_name: str = ""
    plugin_family: str = ""


class ScanDetailResponse(BaseModel):
    info: ScanInfo = Field(default_factory=ScanInfo)
    hosts: List[ScanHostEntry] = Field(default_factory=list)
    vulnerabilities: List[ScanVulnEntry] = Field(default_factory=list)


class HostInfo(BaseModel):
    host_start: str = ""
    host_end: str = ""
    host_fqdn: str = ""
    host_ip: str = ""
    mac_address: str = ""
    operating_system: str = ""


class HostVulnEntry(BaseModel):
    vuln_index: int = 0
    plugin_id: int = 0
    plugin_name: str = ""
    severity: int = 0
    count: int = 0
    cve: List[str] = Field(default_factory=list)


class HostComplianceEntry(BaseModel):
    check_id: str = ""
    severity: int = 0
    count: int = 0


class HostDetailResponse(BaseModel):
    info: HostInfo = Field(default_factory=HostInfo)
    vulnerabilities: List[HostVulnEntry] = Field(default_factory=list)
    compliance: List[HostComplianceEntry] = Field(default_factory=list)


class AgentEntry(BaseModel):
    id: int = 0
    uuid: str = ""
    name: str = ""
    platform: str = ""
    distro: str = ""
    ip: str = ""
    last_scanned: int = 0
    plugin_feed_id: str = ""
    core_version: str = ""
    status: str = ""
    network_uuid: str = ""


class AgentsResponse(BaseModel):
    agents: List[AgentEntry] = Field(default_factory=list)


class PolicyEntry(BaseModel):
    id: int = 0
    template_uuid: str = ""
    name: str = ""
    description: str = ""
    owner: str = ""
    visibility: str = ""
    shared: int = 0
    user_permissions: int = 0
    last_modification_date: int = 0


class PoliciesResponse(BaseModel):
    policies: List[PolicyEntry] = Field(default_factory=list)


class WorkbenchRequest(BaseModel):
    date_range: Optional[int] = Field(
        default=None, description="Lookback window in days"
    )
    severity: Optional[List[int]] = Field(
        default=None, description="Severity filter (0=info..4=critical)"
    )
    vpr_score: Optional[Dict[str, Any]] = Field(
        default=None,
        description='VPR predicate, e.g. {"gte": 7.0}',
    )


class WorkbenchVulnVPR(BaseModel):
    score: float = 0.0
    drivers: Dict[str, Any] = Field(default_factory=dict)


class WorkbenchVulnEntry(BaseModel):
    count: int = 0
    plugin_id: int = 0
    severity: int = 0
    plugin_name: str = ""
    plugin_family: str = ""
    vpr_score: WorkbenchVulnVPR = Field(default_factory=WorkbenchVulnVPR)


class WorkbenchResponse(BaseModel):
    vulnerabilities: List[WorkbenchVulnEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="Tenable.io capability summary",
)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without credentials."""
    eng = _engine()
    ak = eng.access_key_present()
    sk = eng.secret_key_present()
    if not (ak and sk):
        status = "unavailable"
    else:
        status = "ok"
    return CapabilityResponse(
        service="Tenable.io",
        endpoints=[
            "/scans",
            "/scans/{scan_id}",
            "/scans/{scan_id}/hosts/{host_id}",
            "/agents",
            "/policies",
            "/workbenches/vulnerabilities",
        ],
        tenable_access_key_present=ak,
        tenable_secret_key_present=sk,
        status=status,
    )


@router.get(
    "/scans",
    response_model=ScansResponse,
    summary="List Tenable.io scans",
)
async def list_scans() -> ScansResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_scans())
    return ScansResponse(**data)


@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Tenable.io scan detail (info + hosts + vulns)",
)
async def scan_detail(
    scan_id: str = Path(..., description="Tenable scan id"),
    history_id: Optional[int] = Query(
        default=None, description="Optional historical run id"
    ),
) -> ScanDetailResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.scan_detail(scan_id=scan_id, history_id=history_id)
    )
    return ScanDetailResponse(**data)


@router.get(
    "/scans/{scan_id}/hosts/{host_id}",
    response_model=HostDetailResponse,
    summary="Tenable.io per-host vulnerabilities + compliance",
)
async def host_detail(
    scan_id: str = Path(..., description="Tenable scan id"),
    host_id: str = Path(..., description="Tenable host id"),
) -> HostDetailResponse:
    eng = _engine()
    data = _serve(lambda: eng.host_detail(scan_id=scan_id, host_id=host_id))
    return HostDetailResponse(**data)


@router.get(
    "/agents",
    response_model=AgentsResponse,
    summary="List Tenable.io agents",
)
async def list_agents(
    limit: int = Query(default=50, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> AgentsResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_agents(limit=limit, offset=offset))
    return AgentsResponse(**data)


@router.get(
    "/policies",
    response_model=PoliciesResponse,
    summary="List Tenable.io scan policies",
)
async def list_policies() -> PoliciesResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_policies())
    return PoliciesResponse(**data)


@router.post(
    "/workbenches/vulnerabilities",
    response_model=WorkbenchResponse,
    summary="Tenable.io workbench vulnerability query",
)
async def workbench_vulnerabilities(
    body: WorkbenchRequest = Body(default_factory=WorkbenchRequest),
) -> WorkbenchResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.workbench_vulnerabilities(
            date_range=body.date_range,
            severity=body.severity,
            vpr_score=body.vpr_score,
        )
    )
    return WorkbenchResponse(**data)


__all__ = ["router"]
