"""AWS Redshift Data API Connector Router — ALDECI (2026-05-31).

Wraps the AWS Redshift and Redshift Data API via boto3 for cluster discovery,
SQL statement execution, and result retrieval against a real AWS account.

Prefix: /api/v1/aws-redshift
Auth:   api_key_auth dependency (read:scans scope at registration)

Routes:
  GET  /api/v1/aws-redshift/                              connector info / configured-status
  GET  /api/v1/aws-redshift/clusters                      redshift.describe_clusters()
  POST /api/v1/aws-redshift/queries                       redshift_data.execute_statement()
  GET  /api/v1/aws-redshift/queries/{statement_id}        redshift_data.describe_statement()
  GET  /api/v1/aws-redshift/queries/{statement_id}/result redshift_data.get_statement_result()

NO MOCKS rule: when AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, or AWS_REGION
are missing every live endpoint returns HTTP 503 with
``{"error":"redshift_not_configured","needed":[...]}``. We do not fabricate
cluster lists, statement statuses, or query result rows ever.

Credentials
-----------
  AWS_ACCESS_KEY_ID          — AWS access key
  AWS_SECRET_ACCESS_KEY      — AWS secret key
  AWS_REGION                 — AWS region (e.g. us-east-1)
  REDSHIFT_CLUSTER_IDENTIFIER — optional cluster ID used for query path
  REDSHIFT_DATABASE           — optional database name used for query path
  REDSHIFT_DB_USER            — optional database user used for query path
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import boto3
from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_NOT_CONFIGURED_ERROR = "redshift_not_configured"
_NEEDED_VARS = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"]

router = APIRouter(
    prefix="/api/v1/aws-redshift",
    tags=["AWS Redshift"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_creds() -> tuple[str, str, str] | tuple[None, None, None]:
    """Return (access_key, secret_key, region) or (None, None, None) if any missing."""
    key = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    region = os.environ.get("AWS_REGION", "").strip()
    if not key or not secret or not region:
        return None, None, None
    return key, secret, region


def _require_creds() -> tuple[str, str, str]:
    """Return (access_key, secret_key, region) or raise HTTP 503."""
    key, secret, region = _get_creds()
    if key is None or secret is None or region is None:
        raise HTTPException(
            status_code=503,
            detail={
                "error": _NOT_CONFIGURED_ERROR,
                "needed": _NEEDED_VARS,
            },
        )
    return key, secret, region  # type: ignore[return-value]


def _boto_client(service: str, key: str, secret: str, region: str) -> Any:
    """Create a boto3 client for the given service."""
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=key,
        aws_secret_access_key=secret,
    )


def _handle_boto_error(exc: Exception, operation: str) -> None:
    """Translate boto3 ClientError / BotoCoreError to HTTPException."""
    try:
        from botocore.exceptions import BotoCoreError, ClientError  # noqa: PLC0415

        if isinstance(exc, ClientError):
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"]["Message"]
            status = 400
            if code in ("AuthFailure", "InvalidClientTokenId", "AccessDenied"):
                status = 403
            elif code in ("ClusterNotFound", "StatementNotFound"):
                status = 404
            _logger.warning("redshift_client_error op=%s code=%s", operation, code)
            raise HTTPException(
                status_code=status,
                detail={"error": "redshift_client_error", "code": code, "message": message},
            ) from exc
        if isinstance(exc, BotoCoreError):
            _logger.warning("redshift_botocore_error op=%s exc=%s", operation, exc)
            raise HTTPException(
                status_code=502,
                detail={"error": "redshift_botocore_error", "operation": operation},
            ) from exc
    except ImportError:
        pass

    # Fallback for unexpected errors
    _logger.warning("redshift_unexpected_error op=%s exc=%s", operation, exc)
    raise HTTPException(
        status_code=502,
        detail={"error": "redshift_unexpected_error", "operation": operation},
    ) from exc


# ---------------------------------------------------------------------------
# Pydantic response schemas
# ---------------------------------------------------------------------------


class ConnectorInfoResponse(BaseModel):
    service: str = "AWS Redshift Data API"
    version: str = "boto3"
    endpoints: List[str]
    access_key_present: bool
    secret_key_present: bool
    region_present: bool
    region: Optional[str]
    cluster_identifier: Optional[str]
    database: Optional[str]
    status: str  # ok | partial | unavailable


class ClustersResponse(BaseModel):
    clusters: List[Dict[str, Any]] = Field(default_factory=list)


class ExecuteStatementResponse(BaseModel):
    model_config = {"extra": "allow"}


class DescribeStatementResponse(BaseModel):
    model_config = {"extra": "allow"}


class StatementResultResponse(BaseModel):
    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# GET / — connector info (always returns 200, no creds required)
# ---------------------------------------------------------------------------


@router.get("/", response_model=ConnectorInfoResponse)
async def connector_info() -> ConnectorInfoResponse:
    """Connector capability summary — safe to call without credentials.

    Returns configured-status so the UI can surface actionable setup guidance
    without requiring a live AWS account.
    """
    key_raw = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret_raw = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    region_raw = os.environ.get("AWS_REGION", "").strip()
    cluster_id = os.environ.get("REDSHIFT_CLUSTER_IDENTIFIER", "").strip() or None
    database = os.environ.get("REDSHIFT_DATABASE", "").strip() or None

    key_present = bool(key_raw)
    secret_present = bool(secret_raw)
    region_present = bool(region_raw)

    if key_present and secret_present and region_present:
        status = "ok"
    elif key_present or secret_present or region_present:
        status = "partial"
    else:
        status = "unavailable"

    _logger.info(
        "redshift_connector_info key=%s secret=%s region=%s status=%s",
        key_present, secret_present, region_present, status,
    )
    return ConnectorInfoResponse(
        endpoints=[
            "/clusters",
            "/queries",
            "/queries/{statement_id}",
            "/queries/{statement_id}/result",
        ],
        access_key_present=key_present,
        secret_key_present=secret_present,
        region_present=region_present,
        region=region_raw or None,
        cluster_identifier=cluster_id,
        database=database,
        status=status,
    )


# ---------------------------------------------------------------------------
# GET /clusters — redshift.describe_clusters()
# ---------------------------------------------------------------------------


@router.get("/clusters", response_model=ClustersResponse)
async def list_clusters() -> ClustersResponse:
    """List all Redshift clusters in the configured AWS region.

    Uses the classic `redshift` (management plane) client, not redshift-data.
    Returns 503 when AWS credentials or region are unset.
    """
    key, secret, region = _require_creds()
    try:
        client = _boto_client("redshift", key, secret, region)
        resp = client.describe_clusters()
    except HTTPException:
        raise
    except Exception as exc:
        _handle_boto_error(exc, "describe_clusters")
        raise  # unreachable — _handle_boto_error always raises

    clusters = resp.get("Clusters", [])
    _logger.info("redshift_list_clusters region=%s count=%d", region, len(clusters))
    return ClustersResponse(clusters=clusters)


# ---------------------------------------------------------------------------
# POST /queries — redshift_data.execute_statement()
# ---------------------------------------------------------------------------


@router.post("/queries", response_model=ExecuteStatementResponse)
async def execute_statement(
    body: Dict[str, Any] = Body(
        ...,
        examples=[
            {
                "sql": "SELECT * FROM pg_tables LIMIT 10",
            }
        ],
    ),
) -> ExecuteStatementResponse:
    """Execute a SQL statement via the Redshift Data API.

    Required body field: sql (str).
    Optional overrides: ClusterIdentifier, Database, DbUser (fall back to env).
    Returns 503 when AWS credentials or region are unset.
    """
    key, secret, region = _require_creds()

    sql = body.get("sql", "").strip()
    if not sql:
        raise HTTPException(status_code=422, detail={"error": "sql_required"})

    cluster_id = (
        body.get("ClusterIdentifier")
        or os.environ.get("REDSHIFT_CLUSTER_IDENTIFIER", "").strip()
        or None
    )
    database = (
        body.get("Database")
        or os.environ.get("REDSHIFT_DATABASE", "").strip()
        or None
    )
    db_user = (
        body.get("DbUser")
        or os.environ.get("REDSHIFT_DB_USER", "").strip()
        or None
    )

    if not cluster_id or not database or not db_user:
        missing = [
            v for v, val in [
                ("REDSHIFT_CLUSTER_IDENTIFIER", cluster_id),
                ("REDSHIFT_DATABASE", database),
                ("REDSHIFT_DB_USER", db_user),
            ] if not val
        ]
        raise HTTPException(
            status_code=503,
            detail={
                "error": "redshift_query_not_configured",
                "needed": missing,
            },
        )

    try:
        client = _boto_client("redshift-data", key, secret, region)
        resp = client.execute_statement(
            ClusterIdentifier=cluster_id,
            Database=database,
            DbUser=db_user,
            Sql=sql,
        )
    except HTTPException:
        raise
    except Exception as exc:
        _handle_boto_error(exc, "execute_statement")
        raise  # unreachable

    _logger.info(
        "redshift_execute_statement cluster=%s db=%s statement_id=%s",
        cluster_id, database, resp.get("Id"),
    )
    # boto3 returns datetime objects — convert to str for JSON serialisation
    return ExecuteStatementResponse(
        **{k: str(v) if hasattr(v, "isoformat") else v for k, v in resp.items()
           if k != "ResponseMetadata"}
    )


# ---------------------------------------------------------------------------
# GET /queries/{statement_id} — redshift_data.describe_statement()
# ---------------------------------------------------------------------------


@router.get("/queries/{statement_id}", response_model=DescribeStatementResponse)
async def describe_statement(
    statement_id: str = Path(..., min_length=1, max_length=256, description="Redshift Data API statement ID"),
) -> DescribeStatementResponse:
    """Describe the status of a previously submitted SQL statement.

    Upstream: redshift_data.describe_statement(Id=statement_id)
    Returns 503 when AWS credentials or region are unset.
    """
    key, secret, region = _require_creds()
    try:
        client = _boto_client("redshift-data", key, secret, region)
        resp = client.describe_statement(Id=statement_id)
    except HTTPException:
        raise
    except Exception as exc:
        _handle_boto_error(exc, "describe_statement")
        raise  # unreachable

    _logger.info(
        "redshift_describe_statement statement_id=%s status=%s",
        statement_id, resp.get("Status"),
    )
    return DescribeStatementResponse(
        **{k: str(v) if hasattr(v, "isoformat") else v for k, v in resp.items()
           if k != "ResponseMetadata"}
    )


# ---------------------------------------------------------------------------
# GET /queries/{statement_id}/result — redshift_data.get_statement_result()
# ---------------------------------------------------------------------------


@router.get("/queries/{statement_id}/result", response_model=StatementResultResponse)
async def get_statement_result(
    statement_id: str = Path(..., min_length=1, max_length=256, description="Redshift Data API statement ID"),
) -> StatementResultResponse:
    """Retrieve the result rows of a completed SQL statement.

    Upstream: redshift_data.get_statement_result(Id=statement_id)
    Returns 503 when AWS credentials or region are unset.
    Returns 400 from AWS if the statement has not yet completed.
    """
    key, secret, region = _require_creds()
    try:
        client = _boto_client("redshift-data", key, secret, region)
        resp = client.get_statement_result(Id=statement_id)
    except HTTPException:
        raise
    except Exception as exc:
        _handle_boto_error(exc, "get_statement_result")
        raise  # unreachable

    _logger.info(
        "redshift_get_statement_result statement_id=%s total_rows=%s",
        statement_id, resp.get("TotalNumRows"),
    )
    return StatementResultResponse(
        **{k: str(v) if hasattr(v, "isoformat") else v for k, v in resp.items()
           if k != "ResponseMetadata"}
    )


__all__ = ["router"]
