"""Tanium Endpoint Platform Live REST Router — ALDECI.

Wraps ``core.tanium_endpoint_engine.TaniumEndpointEngine`` with REST
endpoints for sessions, system status, question parsing, question
issuance, result data, sensors, and the saved-question library against
the live Tanium Server REST API.

Prefix: /api/v1/tanium
Auth:   api_key_auth dependency (mount layer adds read:scans scope)

Routes:
  GET  /api/v1/tanium/                                capability summary
  POST /api/v1/tanium/api/v2/sessions                 open session
  GET  /api/v1/tanium/api/v2/system_status            cluster health
  POST /api/v1/tanium/api/v2/parse_question           NLP parser
  POST /api/v1/tanium/api/v2/questions                issue question
  GET  /api/v1/tanium/api/v2/result_data              fetch results
  GET  /api/v1/tanium/api/v2/sensors                  list sensors
  GET  /api/v1/tanium/api/v2/saved_questions          saved-question library

NO MOCKS rule: when TANIUM_URL/TANIUM_USER/TANIUM_PASSWORD are missing
the capability summary reports ``status="unavailable"`` and every live
endpoint returns HTTP 503. We never fabricate clusters, sensors, rows,
or saved questions.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tanium",
    tags=["Tanium Endpoint Platform"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch via reset_tanium_endpoint_engine().
    from core.tanium_endpoint_engine import get_tanium_endpoint_engine
    return get_tanium_endpoint_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    tanium_url_present: bool
    tanium_user_present: bool
    tanium_password_present: bool
    status: str  # ok | empty | unavailable


class SessionRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=200)
    password: str = Field(..., min_length=1, max_length=4096)
    domain: Optional[str] = Field(default=None, max_length=200)


class SessionData(BaseModel):
    session: str
    expiration: str = ""
    persistent: bool = False


class SessionResponse(BaseModel):
    data: SessionData


class ClusterEntry(BaseModel):
    name: str = ""
    ip: str = ""
    status: str = ""


class SystemStatusData(BaseModel):
    server_clusters: List[ClusterEntry] = Field(default_factory=list)
    dependent_clusters: List[ClusterEntry] = Field(default_factory=list)


class SystemStatusResponse(BaseModel):
    data: SystemStatusData


class ParseQuestionRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=4096)


class SensorRef(BaseModel):
    name: str = ""
    real_ms_avg: int = 0
    source_hash: str = ""


class SensorBrief(BaseModel):
    name: str = ""
    source_hash: str = ""


class SelectEntry(BaseModel):
    aggregation: str = ""
    max_data_age_seconds: int = 0
    sensor: SensorBrief = Field(default_factory=SensorBrief)


class ResultGroup(BaseModel):
    select: List[SelectEntry] = Field(default_factory=list)


class ParsedItem(BaseModel):
    from_canonical_text: bool = False
    parameter_values: List[Any] = Field(default_factory=list)
    picked_intrinsic_type: str = ""
    question_text: str = ""
    parsed_text: str = ""
    sensor_references: List[SensorRef] = Field(default_factory=list)
    result_groups: List[ResultGroup] = Field(default_factory=list)
    score: int = 0
    source: str = ""


class ParseQuestionResponse(BaseModel):
    data: List[ParsedItem] = Field(default_factory=list)


class QuestionRequest(BaseModel):
    query_text: str = Field(..., min_length=1, max_length=4096)
    expire_seconds: Optional[int] = Field(default=None, ge=1, le=86_400)
    force_computer_id_flag: Optional[bool] = None
    expiration: Optional[str] = Field(default=None, max_length=64)


class QuestionData(BaseModel):
    id: int = 0
    query_text: str = ""
    action_tracking_flag: bool = False
    expiration: str = ""
    expire_seconds: int = 0
    question_id: int = 0

    model_config = {"extra": "allow"}


class QuestionResponse(BaseModel):
    data: QuestionData


class ColumnEntry(BaseModel):
    name: str = ""
    hash: str = ""
    type: str = ""


class RowEntry(BaseModel):
    id: int = 0
    cid: int = 0
    data: List[Any] = Field(default_factory=list)


class ResultSet(BaseModel):
    age: int = 0
    archived_question_id: int = 0
    cache_id: str = ""
    error_count: int = 0
    estimated_total: int = 0
    expiration: int = 0
    columns: List[ColumnEntry] = Field(default_factory=list)
    rows: List[RowEntry] = Field(default_factory=list)
    no_results_count: int = 0
    mr_passed: int = 0
    mr_tested: int = 0
    passed: int = 0
    tested: int = 0
    question_id: int = 0
    report_count: int = 0
    row_count: int = 0
    saved_question_id: int = 0
    seconds_since_issued: int = 0
    select_count: int = 0


class ResultData(BaseModel):
    result_sets: List[ResultSet] = Field(default_factory=list)


class ResultDataResponse(BaseModel):
    data: ResultData


class SensorQuery(BaseModel):
    platform: str = ""
    script: str = ""
    script_type: str = ""
    signature: str = ""


class SensorParameter(BaseModel):
    key: str = ""
    default_value: Any = ""
    type: str = ""
    label: str = ""
    value_type: str = ""
    allow_set_multiple_flags: bool = False


class SensorEntry(BaseModel):
    id: int = 0
    name: str = ""
    hash: str = ""
    source_hash: str = ""
    source_id: int = 0
    max_age_seconds: int = 0
    hidden_flag: bool = False
    ignore_case_flag: bool = False
    exclude_from_parse_flag: bool = False
    value_type: str = ""
    queries: List[SensorQuery] = Field(default_factory=list)
    parameters: List[SensorParameter] = Field(default_factory=list)
    category: str = ""


class SensorsResponse(BaseModel):
    data: List[SensorEntry] = Field(default_factory=list)


class SavedQuestion(BaseModel):
    id: int = 0
    name: str = ""
    query_text: str = ""
    action_tracking_flag: bool = False
    archive_enabled_flag: bool = False
    expire_seconds: int = 0
    hidden_flag: bool = False
    public_flag: bool = False


class SavedQuestionsResponse(BaseModel):
    data: List[SavedQuestion] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run a Tanium call, translating engine errors to HTTP responses.

    TaniumUnavailableError -> 503 (auth missing, network, upstream error)
    ValueError             -> 422 (input validation)
    """
    from core.tanium_endpoint_engine import TaniumUnavailableError
    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except TaniumUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service summary — safe to call without Tanium credentials."""
    eng = _engine()
    url_present = eng.url_present()
    user_present = eng.user_present()
    pw_present = eng.password_present()
    if url_present and user_present and pw_present:
        status = "ok"
    elif url_present or user_present or pw_present:
        status = "empty"
    else:
        status = "unavailable"
    return CapabilityResponse(
        service="Tanium",
        endpoints=[
            "/api/v2/sessions",
            "/api/v2/parse_question",
            "/api/v2/result_data",
            "/api/v2/sensors",
            "/api/v2/saved_questions",
            "/api/v2/system_status",
        ],
        tanium_url_present=url_present,
        tanium_user_present=user_present,
        tanium_password_present=pw_present,
        status=status,
    )


@router.post("/api/v2/sessions", response_model=SessionResponse)
async def open_session(req: SessionRequest) -> SessionResponse:
    eng = _engine()
    data = _serve(lambda: eng.open_session(req.username, req.password, req.domain))
    return SessionResponse(**data)


@router.get("/api/v2/system_status", response_model=SystemStatusResponse)
async def system_status() -> SystemStatusResponse:
    eng = _engine()
    data = _serve(lambda: eng.system_status())
    return SystemStatusResponse(**data)


@router.post("/api/v2/parse_question", response_model=ParseQuestionResponse)
async def parse_question(req: ParseQuestionRequest) -> ParseQuestionResponse:
    eng = _engine()
    data = _serve(lambda: eng.parse_question(req.text))
    return ParseQuestionResponse(**data)


@router.post("/api/v2/questions", response_model=QuestionResponse)
async def issue_question(req: QuestionRequest) -> QuestionResponse:
    eng = _engine()
    data = _serve(lambda: eng.issue_question(
        query_text=req.query_text,
        expire_seconds=req.expire_seconds,
        force_computer_id_flag=req.force_computer_id_flag,
        expiration=req.expiration,
    ))
    return QuestionResponse(**data)


@router.get("/api/v2/result_data", response_model=ResultDataResponse)
async def get_result_data(
    question_id: int = Query(..., ge=0),
    hide_no_results_flag: int = Query(1, ge=0, le=1),
) -> ResultDataResponse:
    eng = _engine()
    data = _serve(lambda: eng.get_result_data(question_id, hide_no_results_flag))
    return ResultDataResponse(**data)


@router.get("/api/v2/sensors", response_model=SensorsResponse)
async def list_sensors(
    max_age_seconds: Optional[int] = Query(None, ge=0, le=86_400 * 365),
) -> SensorsResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_sensors(max_age_seconds))
    return SensorsResponse(**data)


@router.get("/api/v2/saved_questions", response_model=SavedQuestionsResponse)
async def list_saved_questions(
    max_age_seconds: Optional[int] = Query(None, ge=0, le=86_400 * 365),
) -> SavedQuestionsResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_saved_questions(max_age_seconds))
    return SavedQuestionsResponse(**data)


__all__ = ["router"]
