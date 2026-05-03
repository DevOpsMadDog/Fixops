"""ALDECI Snowflake SQL API router — REAL httpx + JWT only, NO MOCKS.

Mounted at ``/api/v1/snowflake`` under the ``read:scans`` scope.

Endpoints
---------
GET    /                                                — capability summary
POST   /api/v2/statements                               — submit a SQL statement
GET    /api/v2/statements/{statement_handle}            — fetch result/status (paginated via ?partition=)
DELETE /api/v2/statements/{statement_handle}            — cancel a statement (204)
GET    /api/v2/databases                                — wrapper around ``SHOW DATABASES``
GET    /api/v2/databases/{db_name}/schemas              — wrapper around ``SHOW SCHEMAS IN DATABASE``
GET    /api/v2/users                                    — wrapper around ``SHOW USERS``
GET    /api/v2/warehouses                               — wrapper around ``SHOW WAREHOUSES``
GET    /api/v2/roles                                    — wrapper around ``SHOW ROLES``

When SNOWFLAKE_ACCOUNT/SNOWFLAKE_USER/SNOWFLAKE_PRIVATE_KEY are not set, every
lookup endpoint returns HTTP 503 and the capability summary still responds 200
with ``status="unavailable"``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/snowflake",
    tags=["snowflake"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam — engine_module imported at call time so
# tests that monkeypatch env vars + reset the singleton see the fresh state)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.snowflake_engine import get_snowflake_engine
    return get_snowflake_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    snowflake_account_present: bool
    snowflake_user_present: bool
    snowflake_private_key_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class _ResultSetMetaDataReq(BaseModel):
    format: Optional[str] = Field(None, description="json | jsonv2")


class StatementRequest(BaseModel):
    statement: str = Field(..., description="SQL statement to execute")
    role: Optional[str] = None
    warehouse: Optional[str] = None
    database: Optional[str] = None
    schema_: Optional[str] = Field(default=None, alias="schema")
    parameters: Optional[Dict[str, Any]] = None
    timeout: Optional[int] = Field(default=None, ge=0)
    resultSetMetaData: Optional[_ResultSetMetaDataReq] = None
    asyncExec: Optional[bool] = False

    model_config = {"populate_by_name": True}


class _RowTypeColumn(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    scale: Optional[int] = None
    precision: Optional[int] = None
    nullable: Optional[bool] = None


class _ResultSetMetaData(BaseModel):
    numRows: int = 0
    format: str = "json"
    partitionInfo: List[Dict[str, Any]] = []
    rowType: List[_RowTypeColumn] = []


class StatementResponse(BaseModel):
    statementHandle: Optional[str] = None
    code: Optional[str] = None
    sqlState: Optional[str] = None
    message: Optional[str] = None
    statementStatusUrl: Optional[str] = None
    resultSetMetaData: _ResultSetMetaData = Field(default_factory=_ResultSetMetaData)
    data: List[List[Any]] = []
    partition_data: List[Any] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_503(exc: Exception) -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={
            "error": "snowflake_unavailable",
            "message": str(exc),
        },
    )


def _map_http_error(exc: Exception) -> HTTPException:
    """Translate a SnowflakeHTTPError into a passthrough/502 HTTPException."""
    from core.snowflake_engine import SnowflakeHTTPError, SnowflakeUnavailableError

    if isinstance(exc, SnowflakeUnavailableError):
        return _to_503(exc)
    if isinstance(exc, SnowflakeHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "snowflake_upstream_error",
                "upstream_status": exc.status_code,
                "message": str(exc),
                "payload": exc.payload,
            },
        )
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="Snowflake SQL API capability summary",
)
def capability_summary() -> CapabilitySummary:
    eng = _get_engine()
    return CapabilitySummary(**eng.capability_summary())


@router.post(
    "/api/v2/statements",
    response_model=StatementResponse,
    summary="Submit a SQL statement",
)
def submit_statement(req: StatementRequest = Body(...)) -> StatementResponse:
    eng = _get_engine()
    if not eng.is_configured():
        raise _to_503(
            Exception(
                "SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER and SNOWFLAKE_PRIVATE_KEY must "
                "all be set to call the Snowflake SQL API"
            )
        )
    try:
        rsmd = req.resultSetMetaData.dict(exclude_none=True) if req.resultSetMetaData else None
        out = eng.submit_statement(
            req.statement,
            role=req.role,
            warehouse=req.warehouse,
            database=req.database,
            schema=req.schema_,
            parameters=req.parameters,
            timeout=req.timeout,
            result_set_metadata=rsmd,
            async_exec=bool(req.asyncExec),
        )
    except Exception as exc:
        raise _map_http_error(exc) from exc
    return StatementResponse(**out)


@router.get(
    "/api/v2/statements/{statement_handle}",
    response_model=StatementResponse,
    summary="Fetch the result/status of a statement (use ?partition= for paging)",
)
def get_statement(statement_handle: str, partition: int = Query(0, ge=0)) -> StatementResponse:
    eng = _get_engine()
    if not eng.is_configured():
        raise _to_503(Exception("Snowflake credentials not configured"))
    try:
        out = eng.get_statement(statement_handle, partition=partition)
    except Exception as exc:
        raise _map_http_error(exc) from exc
    return StatementResponse(**out)


@router.delete(
    "/api/v2/statements/{statement_handle}",
    status_code=204,
    summary="Cancel a running statement",
)
def cancel_statement(statement_handle: str) -> None:
    eng = _get_engine()
    if not eng.is_configured():
        raise _to_503(Exception("Snowflake credentials not configured"))
    try:
        eng.cancel_statement(statement_handle)
    except Exception as exc:
        raise _map_http_error(exc) from exc
    return None


@router.get(
    "/api/v2/databases",
    summary="List databases (SHOW DATABASES)",
)
def list_databases(asyncExec: bool = Query(False)) -> Dict[str, Any]:
    eng = _get_engine()
    if not eng.is_configured():
        raise _to_503(Exception("Snowflake credentials not configured"))
    try:
        return eng.list_databases(async_exec=asyncExec)
    except Exception as exc:
        raise _map_http_error(exc) from exc


@router.get(
    "/api/v2/databases/{db_name}/schemas",
    summary="List schemas in a database (SHOW SCHEMAS IN DATABASE)",
)
def list_schemas(db_name: str) -> Dict[str, Any]:
    eng = _get_engine()
    if not eng.is_configured():
        raise _to_503(Exception("Snowflake credentials not configured"))
    try:
        return eng.list_schemas(db_name)
    except Exception as exc:
        raise _map_http_error(exc) from exc


@router.get(
    "/api/v2/users",
    summary="List users (SHOW USERS — requires SECURITYADMIN+)",
)
def list_users() -> Dict[str, Any]:
    eng = _get_engine()
    if not eng.is_configured():
        raise _to_503(Exception("Snowflake credentials not configured"))
    try:
        return eng.list_users()
    except Exception as exc:
        raise _map_http_error(exc) from exc


@router.get(
    "/api/v2/warehouses",
    summary="List warehouses (SHOW WAREHOUSES)",
)
def list_warehouses() -> Dict[str, Any]:
    eng = _get_engine()
    if not eng.is_configured():
        raise _to_503(Exception("Snowflake credentials not configured"))
    try:
        return eng.list_warehouses()
    except Exception as exc:
        raise _map_http_error(exc) from exc


@router.get(
    "/api/v2/roles",
    summary="List roles (SHOW ROLES)",
)
def list_roles() -> Dict[str, Any]:
    eng = _get_engine()
    if not eng.is_configured():
        raise _to_503(Exception("Snowflake credentials not configured"))
    try:
        return eng.list_roles()
    except Exception as exc:
        raise _map_http_error(exc) from exc


__all__ = ["router"]
