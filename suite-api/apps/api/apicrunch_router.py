"""42Crunch API Security Router — ALDECI.

REST surface under prefix ``/api/v1/apicrunch`` wrapping ``core.apicrunch_engine``.

Endpoints
---------
* GET  /                                                        — capability summary
* GET  /api/v2/collections                                      — list collections
* GET  /api/v2/collections/{coll_id}                            — single collection
* GET  /api/v2/collections/{coll_id}/apis                       — list APIs
* GET  /api/v2/apis/{api_id}                                    — single API
* GET  /api/v2/apis/{api_id}/auditReport                        — audit report
* POST /api/v2/apis/{api_id}/scan                               — trigger scan
* GET  /api/v2/apis/{api_id}/scanReport                         — latest scan report
* GET  /api/v2/apis/{api_id}/scanReport/{scan_id}               — specific scan report

Auth
----
api_key_auth dependency (mount layer adds scope checks — read:scans).

NO MOCKS rule
-------------
* When APICRUNCH_API_TOKEN is unset:
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
    prefix="/api/v1/apicrunch",
    tags=["42Crunch"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.apicrunch_engine import get_apicrunch_engine

    return get_apicrunch_engine()


def _serve(callable_):
    """Run a 42Crunch call, translating engine errors to HTTP responses."""
    from core.apicrunch_engine import ApicrunchUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ApicrunchUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    apicrunch_api_token_present: bool
    status: str  # ok | empty | unavailable


class OwnerEntry(BaseModel):
    id: str = ""
    name: str = ""
    email: str = ""


class CollSummary(BaseModel):
    apis: int = 0
    requirements: int = 0


class CollDesc(BaseModel):
    id: str = ""
    name: str = ""
    description: str = ""
    source: str = ""
    owner: OwnerEntry = Field(default_factory=OwnerEntry)
    source_id: str = ""
    source_name: str = ""
    summary: CollSummary = Field(default_factory=CollSummary)


class GroupShare(BaseModel):
    group_id: str = ""
    name: str = ""
    scope: str = ""


class UserShare(BaseModel):
    user_id: str = ""
    scope: str = ""


class SharingBlock(BaseModel):
    groups: List[GroupShare] = Field(default_factory=list)
    users: List[UserShare] = Field(default_factory=list)


class CollectionEntry(BaseModel):
    desc: CollDesc = Field(default_factory=CollDesc)
    sharing: SharingBlock = Field(default_factory=SharingBlock)
    write: bool = False
    read: bool = False
    requirements: List[Any] = Field(default_factory=list)


class CollectionsResponse(BaseModel):
    list: List[CollectionEntry] = Field(default_factory=list)
    totalCount: int = 0


class ApiSummary(BaseModel):
    errors: int = 0
    warnings: int = 0
    info: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class AuditBlock(BaseModel):
    score: float = 0.0
    latestAuditId: str = ""
    latestAuditDate: str = ""
    lastAuditScore: float = 0.0


class ScanBlock(BaseModel):
    conformanceScore: float = 0.0
    latestScanId: str = ""
    latestScanDate: str = ""


class ApiDesc(BaseModel):
    id: str = ""
    name: str = ""
    cid: str = ""
    technicalName: str = ""
    description: str = ""
    owner: OwnerEntry = Field(default_factory=OwnerEntry)
    summary: ApiSummary = Field(default_factory=ApiSummary)
    score: float = 0.0
    audit: AuditBlock = Field(default_factory=AuditBlock)
    scan: Optional[ScanBlock] = None


class ApiEntry(BaseModel):
    desc: ApiDesc = Field(default_factory=ApiDesc)


class ApiListEntry(BaseModel):
    desc: ApiDesc = Field(default_factory=ApiDesc)
    write: bool = False
    read: bool = False


class ApiListResponse(BaseModel):
    list: List[ApiListEntry] = Field(default_factory=list)
    totalCount: int = 0


class FindingEntry(BaseModel):
    id: str = ""
    severity: str = ""
    code: str = ""
    message: str = ""
    pointer: str = ""
    requirementId: str = ""
    severityRationale: str = ""


class AuditSummary(BaseModel):
    score: float = 0.0
    criticality: str = ""
    errors: List[FindingEntry] = Field(default_factory=list)
    warnings: List[FindingEntry] = Field(default_factory=list)
    info: List[FindingEntry] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    scoringRules: Dict[str, Any] = Field(default_factory=dict)


class AuditReportInner(BaseModel):
    summary: AuditSummary = Field(default_factory=AuditSummary)


class AuditReportData(BaseModel):
    report: AuditReportInner = Field(default_factory=AuditReportInner)


class AuditReportResponse(BaseModel):
    data: AuditReportData = Field(default_factory=AuditReportData)


class ScanRequestBody(BaseModel):
    scanConfiguration: Optional[Dict[str, Any]] = None


class ScanTriggerResponse(BaseModel):
    scanId: str = ""
    status: str = "queued"


class ScanFindingEntry(BaseModel):
    type: str = ""
    severity: str = ""
    status: str = ""
    message: str = ""
    request: Dict[str, Any] = Field(default_factory=dict)
    response: Dict[str, Any] = Field(default_factory=dict)
    cwe: str = ""
    owasp: List[str] = Field(default_factory=list)
    description: str = ""


class ScanPathEntry(BaseModel):
    path: str = ""
    method: str = ""
    statusCode: str = ""
    expectations: List[Any] = Field(default_factory=list)
    findings: List[ScanFindingEntry] = Field(default_factory=list)


class ScanSummary(BaseModel):
    conformanceScore: float = 0.0
    errors: int = 0
    warnings: int = 0
    vulnerabilities: int = 0
    executionTime: float = 0.0
    totalRequests: int = 0
    totalIssues: int = 0


class ScanReportData(BaseModel):
    summary: ScanSummary = Field(default_factory=ScanSummary)
    paths: List[ScanPathEntry] = Field(default_factory=list)


class ScanReportResponse(BaseModel):
    data: ScanReportData = Field(default_factory=ScanReportData)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="42Crunch capability summary",
)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without a token."""
    eng = _engine()
    token_present = eng.api_key_present()
    status = "ok" if token_present else "unavailable"
    return CapabilityResponse(
        service="42Crunch",
        endpoints=[
            "/api/v2/collections",
            "/api/v2/apis",
            "/api/v2/apis/{id}/auditReport",
            "/api/v2/apis/{id}/scan",
            "/api/v2/apis/{id}/scanReport",
        ],
        apicrunch_api_token_present=token_present,
        status=status,
    )


@router.get(
    "/api/v2/collections",
    response_model=CollectionsResponse,
    summary="List 42Crunch collections",
)
async def list_collections(
    listOption: str = Query(
        "ALL",
        pattern="^(ALL|MINE|SHARED|PROVIDED)$",
        description="Filter scope of returned collections",
    ),
    limit: Optional[int] = Query(default=None, ge=1, le=500),
    page: Optional[int] = Query(default=None, ge=0),
) -> CollectionsResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_collections(
            list_option=listOption, limit=limit, page=page
        )
    )
    return CollectionsResponse(**data)


@router.get(
    "/api/v2/collections/{coll_id}",
    response_model=CollectionEntry,
    summary="Get a single 42Crunch collection",
)
async def get_collection(
    coll_id: str = Path(..., description="42Crunch collection id"),
) -> CollectionEntry:
    eng = _engine()
    data = _serve(lambda: eng.get_collection(coll_id))
    return CollectionEntry(**data)


@router.get(
    "/api/v2/collections/{coll_id}/apis",
    response_model=ApiListResponse,
    summary="List APIs in a 42Crunch collection",
)
async def list_collection_apis(
    coll_id: str = Path(..., description="42Crunch collection id"),
    limit: Optional[int] = Query(default=None, ge=1, le=500),
    page: Optional[int] = Query(default=None, ge=0),
) -> ApiListResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_collection_apis(coll_id, limit=limit, page=page)
    )
    return ApiListResponse(**data)


@router.get(
    "/api/v2/apis/{api_id}",
    response_model=ApiEntry,
    summary="Get a single 42Crunch API descriptor",
)
async def get_api(
    api_id: str = Path(..., description="42Crunch API id"),
) -> ApiEntry:
    eng = _engine()
    data = _serve(lambda: eng.get_api(api_id))
    return ApiEntry(**data)


@router.get(
    "/api/v2/apis/{api_id}/auditReport",
    response_model=AuditReportResponse,
    summary="Get the latest audit report for an API",
)
async def get_audit_report(
    api_id: str = Path(..., description="42Crunch API id"),
    reportType: str = Query(
        "REPORT",
        pattern="^(FINDINGS|REPORT)$",
        description="Audit report type",
    ),
) -> AuditReportResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.get_audit_report(api_id, report_type=reportType)
    )
    return AuditReportResponse(**data)


@router.post(
    "/api/v2/apis/{api_id}/scan",
    response_model=ScanTriggerResponse,
    summary="Trigger a 42Crunch conformance scan",
)
async def trigger_scan(
    api_id: str = Path(..., description="42Crunch API id"),
    body: ScanRequestBody = Body(default_factory=ScanRequestBody),
) -> ScanTriggerResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.trigger_scan(
            api_id, scan_configuration=body.scanConfiguration
        )
    )
    return ScanTriggerResponse(**data)


@router.get(
    "/api/v2/apis/{api_id}/scanReport",
    response_model=ScanReportResponse,
    summary="Get the latest scan report for an API",
)
async def get_scan_report_latest(
    api_id: str = Path(..., description="42Crunch API id"),
) -> ScanReportResponse:
    eng = _engine()
    data = _serve(lambda: eng.get_scan_report(api_id))
    return ScanReportResponse(**data)


@router.get(
    "/api/v2/apis/{api_id}/scanReport/{scan_id}",
    response_model=ScanReportResponse,
    summary="Get a specific 42Crunch scan report",
)
async def get_scan_report_by_id(
    api_id: str = Path(..., description="42Crunch API id"),
    scan_id: str = Path(..., description="42Crunch scan id"),
) -> ScanReportResponse:
    eng = _engine()
    data = _serve(lambda: eng.get_scan_report(api_id, scan_id=scan_id))
    return ScanReportResponse(**data)


__all__ = ["router"]
