"""ALDECI AWS Security Hub router — REAL boto3 only, NO MOCKS.

Mounted at ``/api/v1/aws-securityhub`` under the ``read:scans`` scope.

Endpoints
---------
GET   /                       — capability summary (incl. status: ok|empty|unavailable)
GET   /findings               — list ASFF findings (Filters, NextToken, MaxResults)
GET   /insights               — list Security Hub insights
GET   /standards              — list standards catalog
GET   /enabled-products       — list enabled product subscriptions ARNs
GET   /control-status         — list standards subscriptions / control status
POST  /findings/batch         — lookup findings by (Id, ProductArn) identifiers

When AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are not set, every lookup
endpoint returns HTTP 503. The capability summary still responds 200 with
``status="unavailable"``.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from core.aws_securityhub_engine import (
    AWSSecurityHubUnavailableError,
    get_aws_securityhub_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/aws-securityhub",
    tags=["aws-securityhub"],
    dependencies=[Depends(api_key_auth)],
)


# --------------------------------------------------------------- Pydantic


class _FindingIdentifier(BaseModel):
    Id: str
    ProductArn: str


class BatchGetFindingsRequest(BaseModel):
    FindingIdentifiers: List[_FindingIdentifier] = Field(default_factory=list)


# ------------------------------------------------------------------ helpers


def _to_503(exc: AWSSecurityHubUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


def _parse_filters(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422, detail=f"Filters must be valid JSON: {exc}"
        )
    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=422, detail="Filters must be a JSON object"
        )
    return parsed


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="AWS Security Hub capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_aws_securityhub_engine()
    summary = eng.capability_summary()
    # Override status to ``empty`` when configured but no findings would
    # be available — we cannot tell without a call, so we keep ``ok|unavailable``
    # at the engine level. ``empty`` is reserved for a future health probe.
    return summary


@router.get("/findings", summary="List AWS Security Hub findings (ASFF)")
def list_findings(
    Filters: Optional[str] = Query(
        None, description="JSON-encoded ASFF Filters object"
    ),
    NextToken: Optional[str] = Query(None, description="Pagination token"),
    MaxResults: Optional[int] = Query(
        None, ge=1, le=100, description="Max items per page (1-100)"
    ),
) -> Dict[str, Any]:
    filters = _parse_filters(Filters)
    eng = get_aws_securityhub_engine()
    try:
        return eng.get_findings(
            filters=filters, next_token=NextToken, max_results=MaxResults
        )
    except AWSSecurityHubUnavailableError as exc:
        raise _to_503(exc)


@router.post(
    "/findings/batch",
    summary="Batch lookup AWS Security Hub findings by identifier",
)
def batch_get_findings(
    body: BatchGetFindingsRequest = Body(...),
) -> Dict[str, Any]:
    eng = get_aws_securityhub_engine()
    identifiers = [ident.model_dump() for ident in body.FindingIdentifiers]
    try:
        return eng.batch_get_findings(identifiers)
    except AWSSecurityHubUnavailableError as exc:
        raise _to_503(exc)


@router.get("/insights", summary="List AWS Security Hub insights")
def list_insights() -> Dict[str, Any]:
    eng = get_aws_securityhub_engine()
    try:
        return eng.get_insights()
    except AWSSecurityHubUnavailableError as exc:
        raise _to_503(exc)


@router.get("/standards", summary="List AWS Security Hub standards catalog")
def list_standards() -> Dict[str, Any]:
    eng = get_aws_securityhub_engine()
    try:
        return eng.get_standards()
    except AWSSecurityHubUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/enabled-products",
    summary="List enabled AWS Security Hub product subscriptions",
)
def list_enabled_products() -> Dict[str, Any]:
    eng = get_aws_securityhub_engine()
    try:
        return eng.list_enabled_products()
    except AWSSecurityHubUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/control-status",
    summary="List AWS Security Hub standards subscriptions / control status",
)
def control_status() -> Dict[str, Any]:
    eng = get_aws_securityhub_engine()
    try:
        return eng.get_control_status()
    except AWSSecurityHubUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
