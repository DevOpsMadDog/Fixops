"""ALDECI Amazon Inspector v2 router — REAL boto3 only, NO MOCKS.

Mounted at ``/api/v1/amazon-inspector`` under the ``read:scans`` scope.

Endpoints
---------
GET   /                      — capability summary
GET   /findings              — ListFindings (filterCriteria, sortCriteria, nextToken, maxResults)
GET   /findings/{arn}        — BatchGetFindingDetails for a single finding ARN
GET   /coverage              — ListCoverage (filterCriteria, nextToken, maxResults)
GET   /configuration         — GetConfiguration (ec2 + ecr)
GET   /usage                 — ListUsageTotals (accountIds, nextToken, maxResults)

When AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are not set, every lookup
endpoint returns HTTP 503. The capability summary still responds 200 with
``status="unavailable"``.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query

from core.amazon_inspector_engine import (
    AmazonInspectorUnavailableError,
    get_amazon_inspector_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/amazon-inspector",
    tags=["amazon-inspector"],
    dependencies=[Depends(api_key_auth)],
)


# ------------------------------------------------------------------ helpers


def _to_503(exc: AmazonInspectorUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


def _parse_json_param(raw: Optional[str], name: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422, detail=f"{name} must be valid JSON: {exc}"
        )
    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=422, detail=f"{name} must be a JSON object"
        )
    return parsed


def _parse_account_ids(raw: Optional[str]) -> Optional[List[str]]:
    if not raw:
        return None
    items = [s.strip() for s in raw.split(",") if s.strip()]
    return items or None


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="Amazon Inspector v2 capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_amazon_inspector_engine()
    return eng.capability_summary()


@router.get("/findings", summary="List Amazon Inspector v2 findings")
def list_findings(
    nextToken: Optional[str] = Query(None, description="Pagination token"),
    maxResults: Optional[int] = Query(
        None, ge=1, le=100, description="Max items per page (1-100)"
    ),
    filterCriteria: Optional[str] = Query(
        None, description="JSON-encoded Inspector2 filterCriteria object"
    ),
    sortCriteria: Optional[str] = Query(
        None, description="JSON-encoded Inspector2 sortCriteria object"
    ),
) -> Dict[str, Any]:
    filt = _parse_json_param(filterCriteria, "filterCriteria")
    sort = _parse_json_param(sortCriteria, "sortCriteria")
    eng = get_amazon_inspector_engine()
    try:
        return eng.list_findings(
            filter_criteria=filt,
            sort_criteria=sort,
            next_token=nextToken,
            max_results=maxResults,
        )
    except AmazonInspectorUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/findings/{finding_arn:path}",
    summary="Get a single Amazon Inspector v2 finding via BatchGetFindingDetails",
)
def get_finding(
    finding_arn: str = Path(..., description="Finding ARN"),
) -> Dict[str, Any]:
    eng = get_amazon_inspector_engine()
    try:
        return eng.get_finding(finding_arn)
    except AmazonInspectorUnavailableError as exc:
        raise _to_503(exc)


@router.get("/coverage", summary="List Amazon Inspector v2 coverage")
def list_coverage(
    nextToken: Optional[str] = Query(None, description="Pagination token"),
    maxResults: Optional[int] = Query(
        None, ge=1, le=100, description="Max items per page (1-100)"
    ),
    filterCriteria: Optional[str] = Query(
        None, description="JSON-encoded Inspector2 coverage filterCriteria object"
    ),
) -> Dict[str, Any]:
    filt = _parse_json_param(filterCriteria, "filterCriteria")
    eng = get_amazon_inspector_engine()
    try:
        return eng.list_coverage(
            filter_criteria=filt,
            next_token=nextToken,
            max_results=maxResults,
        )
    except AmazonInspectorUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/configuration",
    summary="Get Amazon Inspector v2 EC2 / ECR scan configuration",
)
def get_configuration() -> Dict[str, Any]:
    eng = get_amazon_inspector_engine()
    try:
        return eng.get_configuration()
    except AmazonInspectorUnavailableError as exc:
        raise _to_503(exc)


@router.get("/usage", summary="List Amazon Inspector v2 usage totals")
def list_usage(
    accountIds: Optional[str] = Query(
        None, description="Comma-separated AWS account IDs"
    ),
    nextToken: Optional[str] = Query(None, description="Pagination token"),
    maxResults: Optional[int] = Query(
        None, ge=1, le=100, description="Max items per page (1-100)"
    ),
) -> Dict[str, Any]:
    accounts = _parse_account_ids(accountIds)
    eng = get_amazon_inspector_engine()
    try:
        return eng.list_usage_totals(
            account_ids=accounts,
            next_token=nextToken,
            max_results=maxResults,
        )
    except AmazonInspectorUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
