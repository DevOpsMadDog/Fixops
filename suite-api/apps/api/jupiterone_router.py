"""JupiterOne Asset Graph Router — ALDECI.

Wraps ``core.jupiterone_engine`` under prefix ``/api/v1/jupiterone``:

  GET  /                                                        capability summary
  POST /graphql                                                  J1QL graphql query
  GET  /persister/synchronization/jobs                          list sync jobs
  POST /persister/synchronization/jobs                          create sync job
  POST /persister/synchronization/jobs/{job_id}/upload          upload entities/edges
  POST /persister/synchronization/jobs/{job_id}/finalize        finalize sync job
  GET  /alerts                                                  list alerts
  GET  /alerts/{instance_id}                                    single alert detail
  POST /alerts/{instance_id}/dismiss                            dismiss alert
  POST /alerts/{instance_id}/snooze                             snooze alert
  GET  /accounts/{account_id}/integrations                      list integrations

NO MOCKS rule
-------------
* When JUPITERONE_API_KEY or JUPITERONE_ACCOUNT is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints → HTTP 503.
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
    prefix="/api/v1/jupiterone",
    tags=["JupiterOne"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.jupiterone_engine import get_jupiterone_engine

    return get_jupiterone_engine()


def _serve(callable_):
    """Run a JupiterOne call, translating engine errors to HTTP responses.

    JupiterOneUnavailableError -> 503 (key/account missing, network, upstream)
    ValueError                 -> 422 (input validation)
    """
    from core.jupiterone_engine import JupiterOneUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except JupiterOneUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    jupiterone_account_present: bool
    jupiterone_api_key_present: bool
    status: str  # ok | empty | unavailable


class ScopeFilter(BaseModel):
    property: str
    value: Any


class GraphqlRequest(BaseModel):
    query: str = Field(..., description="J1QL query string")
    variables: Optional[Dict[str, Any]] = None
    includeDeleted: Optional[bool] = None
    scopeFilters: Optional[List[ScopeFilter]] = None
    deferredResponse: Optional[str] = Field(
        None,
        description="DISABLED | FORCE",
    )


class GraphqlError(BaseModel):
    message: str = ""
    locations: List[Any] = Field(default_factory=list)
    path: List[Any] = Field(default_factory=list)


class GraphqlResponse(BaseModel):
    data: Optional[Dict[str, Any]] = None
    errors: List[GraphqlError] = Field(default_factory=list)


class PartialDatasets(BaseModel):
    deletedTypes: List[Any] = Field(default_factory=list)
    updatedEntities: List[Any] = Field(default_factory=list)
    createdEntities: List[Any] = Field(default_factory=list)


class IntegrationDefinitionDescription(BaseModel):
    name: str = ""
    type: str = ""
    integrationClass: str = ""
    integrationCategory: List[str] = Field(default_factory=list)


class SyncJob(BaseModel):
    id: str = ""
    type: str = ""
    source: str = ""
    scope: str = ""
    status: str = ""
    partialDatasets: PartialDatasets = Field(default_factory=PartialDatasets)
    integrationInstanceId: str = ""
    integrationJobId: str = ""
    syncMode: str = ""
    createDate: str = ""
    lastModifyDate: str = ""
    finishDate: str = ""
    etcdEpoch: int = 0
    integrationDefinitionId: str = ""
    batchSize: int = 0
    integrationDefinitionDescription: IntegrationDefinitionDescription = Field(
        default_factory=IntegrationDefinitionDescription
    )
    jobMetadata: Dict[str, Any] = Field(default_factory=dict)


class SyncJobsResponse(BaseModel):
    jobs: List[SyncJob] = Field(default_factory=list)


class CreateSyncJobRequest(BaseModel):
    source: str = Field(
        ..., description="integration-managed | api-managed"
    )
    scope: str
    properties: Optional[Dict[str, Any]] = None


class CreateSyncJobResponse(BaseModel):
    job: SyncJob = Field(default_factory=SyncJob)


class SyncUploadRequest(BaseModel):
    entities: List[Dict[str, Any]] = Field(default_factory=list)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)


class OkResponse(BaseModel):
    ok: bool = True
    status_code: int = 200


class RawDataDescriptor(BaseModel):
    name: str = ""
    query: str = ""
    persist: bool = False


class LastEvaluationResult(BaseModel):
    rawDataDescriptors: List[RawDataDescriptor] = Field(default_factory=list)


class AlertQuery(BaseModel):
    name: str = ""
    query: str = ""


class AlertQuestion(BaseModel):
    queries: List[AlertQuery] = Field(default_factory=list)


class QuestionRuleInstance(BaseModel):
    question: AlertQuestion = Field(default_factory=AlertQuestion)


class Alert(BaseModel):
    id: str = ""
    accountId: str = ""
    ruleId: str = ""
    ruleName: str = ""
    ruleVersion: int = 0
    ruleSpec: Dict[str, Any] = Field(default_factory=dict)
    level: str = ""
    type: str = ""
    status: str = ""
    lastEvaluationStartOn: str = ""
    lastEvaluationEndOn: str = ""
    lastEvaluationResult: LastEvaluationResult = Field(
        default_factory=LastEvaluationResult
    )
    dismissedOn: str = ""
    dismissedReason: str = ""
    mutedUntil: str = ""
    alertedAt: str = ""
    resolvedAt: str = ""
    questionRuleInstance: QuestionRuleInstance = Field(
        default_factory=QuestionRuleInstance
    )


class AlertsResponse(BaseModel):
    alerts: List[Alert] = Field(default_factory=list)
    totalCount: int = 0
    cursor: str = ""


class AlertResponse(BaseModel):
    alert: Alert = Field(default_factory=Alert)


class DismissAlertRequest(BaseModel):
    reason: str


class SnoozeAlertRequest(BaseModel):
    until: str = Field(..., description="ISO-8601 timestamp")


class Integration(BaseModel):
    id: str = ""
    name: str = ""
    type: str = ""
    accountId: str = ""
    definitionId: str = ""
    config: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    createdAt: str = ""
    updatedAt: str = ""


class IntegrationsResponse(BaseModel):
    integrations: List[Integration] = Field(default_factory=list)
    cursor: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="JupiterOne capability summary",
)
async def capability_summary() -> CapabilityResponse:
    """Capability summary — safe to call without configured credentials."""
    eng = _engine()
    api_key_present = eng.api_key_present()
    account_present = eng.account_present()
    if not api_key_present or not account_present:
        status = "unavailable"
    else:
        status = "ok"
    return CapabilityResponse(
        service="JupiterOne",
        endpoints=[
            "/graphql",
            "/persister/synchronization/jobs",
            "/alerts",
            "/alerts/{instance_id}",
            "/accounts/{accountId}/integrations",
        ],
        jupiterone_account_present=account_present,
        jupiterone_api_key_present=api_key_present,
        status=status,
    )


@router.post("/graphql", response_model=GraphqlResponse)
async def graphql_endpoint(body: GraphqlRequest = Body(...)) -> GraphqlResponse:
    """Execute a J1QL query."""
    eng = _engine()
    scope_filters = (
        [sf.dict() for sf in body.scopeFilters] if body.scopeFilters else None
    )
    raw = _serve(
        lambda: eng.graphql(
            query=body.query,
            variables=body.variables,
            include_deleted=body.includeDeleted,
            scope_filters=scope_filters,
            deferred_response=body.deferredResponse,
        )
    )
    return GraphqlResponse(**raw)


@router.get(
    "/persister/synchronization/jobs",
    response_model=SyncJobsResponse,
)
async def list_sync_jobs_endpoint(
    from_: Optional[str] = Query(None, alias="from"),
    size: Optional[int] = Query(None, ge=1, le=10000),
    pageNumber: Optional[int] = Query(None, ge=0),
    type: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    scope: Optional[str] = Query(None),
) -> SyncJobsResponse:
    eng = _engine()
    raw = _serve(
        lambda: eng.list_sync_jobs(
            from_iso=from_,
            size=size,
            page_number=pageNumber,
            type_=type,
            source=source,
            scope=scope,
        )
    )
    return SyncJobsResponse(**raw)


@router.post(
    "/persister/synchronization/jobs",
    response_model=CreateSyncJobResponse,
)
async def create_sync_job_endpoint(
    body: CreateSyncJobRequest = Body(...),
) -> CreateSyncJobResponse:
    eng = _engine()
    raw = _serve(
        lambda: eng.create_sync_job(
            source=body.source,
            scope=body.scope,
            properties=body.properties,
        )
    )
    return CreateSyncJobResponse(**raw)


@router.post(
    "/persister/synchronization/jobs/{job_id}/upload",
    response_model=OkResponse,
)
async def upload_sync_job_endpoint(
    job_id: str = Path(..., description="Sync job ID"),
    body: SyncUploadRequest = Body(...),
) -> OkResponse:
    eng = _engine()
    raw = _serve(
        lambda: eng.upload_sync_job(
            job_id=job_id,
            entities=body.entities,
            relationships=body.relationships,
        )
    )
    return OkResponse(**raw)


@router.post(
    "/persister/synchronization/jobs/{job_id}/finalize",
    response_model=OkResponse,
)
async def finalize_sync_job_endpoint(
    job_id: str = Path(..., description="Sync job ID"),
) -> OkResponse:
    eng = _engine()
    raw = _serve(lambda: eng.finalize_sync_job(job_id=job_id))
    return OkResponse(**raw)


@router.get("/alerts", response_model=AlertsResponse)
async def list_alerts_endpoint(
    fromDate: Optional[str] = Query(None),
    toDate: Optional[str] = Query(None),
    questionId: Optional[str] = Query(None),
    pageNumber: Optional[int] = Query(None, ge=0),
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    statuses: Optional[str] = Query(
        None, description="Comma-separated: ALERTED|RESOLVED|DISMISSED|MUTED"
    ),
    severities: Optional[str] = Query(
        None, description="Comma-separated: CRITICAL|HIGH|MEDIUM|LOW|INFO"
    ),
) -> AlertsResponse:
    eng = _engine()
    statuses_list = [s.strip() for s in statuses.split(",")] if statuses else None
    severities_list = (
        [s.strip() for s in severities.split(",")] if severities else None
    )
    raw = _serve(
        lambda: eng.list_alerts(
            from_date=fromDate,
            to_date=toDate,
            question_id=questionId,
            page_number=pageNumber,
            page_size=pageSize,
            statuses=statuses_list,
            severities=severities_list,
        )
    )
    return AlertsResponse(**raw)


@router.get("/alerts/{instance_id}", response_model=AlertResponse)
async def get_alert_endpoint(
    instance_id: str = Path(..., description="Alert instance ID"),
) -> AlertResponse:
    eng = _engine()
    raw = _serve(lambda: eng.get_alert(instance_id))
    return AlertResponse(**raw)


@router.post("/alerts/{instance_id}/dismiss", response_model=OkResponse)
async def dismiss_alert_endpoint(
    instance_id: str = Path(..., description="Alert instance ID"),
    body: DismissAlertRequest = Body(...),
) -> OkResponse:
    eng = _engine()
    raw = _serve(lambda: eng.dismiss_alert(instance_id, body.reason))
    return OkResponse(**raw)


@router.post("/alerts/{instance_id}/snooze", response_model=OkResponse)
async def snooze_alert_endpoint(
    instance_id: str = Path(..., description="Alert instance ID"),
    body: SnoozeAlertRequest = Body(...),
) -> OkResponse:
    eng = _engine()
    raw = _serve(lambda: eng.snooze_alert(instance_id, body.until))
    return OkResponse(**raw)


@router.get(
    "/accounts/{account_id}/integrations",
    response_model=IntegrationsResponse,
)
async def list_integrations_endpoint(
    account_id: str = Path(..., description="JupiterOne account ID"),
    cursor: Optional[str] = Query(None),
    limit: Optional[int] = Query(None, ge=1, le=1000),
    type: Optional[str] = Query(None),
) -> IntegrationsResponse:
    eng = _engine()
    raw = _serve(
        lambda: eng.list_integrations(
            account_id=account_id, cursor=cursor, limit=limit, type_=type
        )
    )
    return IntegrationsResponse(**raw)


__all__ = ["router"]
