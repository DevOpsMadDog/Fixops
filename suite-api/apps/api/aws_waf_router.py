"""ALDECI AWS WAFv2 router — REAL boto3 only, NO MOCKS.

Mounted at ``/api/v1/aws-waf`` under the ``read:scans`` scope.

Endpoints
---------
GET   /                                                     — capability summary
GET   /web-acls                                             — ListWebACLs
GET   /web-acls/{Scope}/{Id}/{Name}                         — GetWebACL
GET   /rule-groups                                          — ListRuleGroups
GET   /rule-groups/{Scope}/{Id}/{Name}                      — GetRuleGroup
GET   /ip-sets                                              — ListIPSets
GET   /ip-sets/{Scope}/{Id}/{Name}                          — GetIPSet
GET   /regex-pattern-sets                                   — ListRegexPatternSets
GET   /managed-rule-groups                                  — ListAvailableManagedRuleGroups
POST  /sampled-requests                                     — GetSampledRequests

When AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are not set, every lookup
endpoint returns HTTP 503. The capability summary still responds 200 with
``status="unavailable"``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query

from core.aws_waf_engine import (
    AWSWAFUnavailableError,
    get_aws_waf_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/aws-waf",
    tags=["aws-waf"],
    dependencies=[Depends(api_key_auth)],
)


# ------------------------------------------------------------------ helpers


def _to_503(exc: AWSWAFUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


_SCOPE_RE = "^(REGIONAL|CLOUDFRONT)$"


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="AWS WAFv2 capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_aws_waf_engine()
    return eng.capability_summary()


# ----------------- web ACLs -----------------------------------------------


@router.get("/web-acls", summary="List Web ACLs (WAFv2)")
def list_web_acls(
    Scope: str = Query(..., pattern=_SCOPE_RE, description="REGIONAL|CLOUDFRONT"),
    NextMarker: Optional[str] = Query(None, description="Pagination marker"),
    Limit: Optional[int] = Query(None, ge=1, le=100),
) -> Dict[str, Any]:
    eng = get_aws_waf_engine()
    try:
        return eng.list_web_acls(
            scope=Scope, next_marker=NextMarker, limit=Limit
        )
    except AWSWAFUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/web-acls/{Scope}/{Id}/{Name}",
    summary="Get a Web ACL (WAFv2)",
)
def get_web_acl(
    Scope: str = Path(..., pattern=_SCOPE_RE),
    Id: str = Path(..., min_length=1, max_length=128),
    Name: str = Path(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    eng = get_aws_waf_engine()
    try:
        return eng.get_web_acl(scope=Scope, acl_id=Id, name=Name)
    except AWSWAFUnavailableError as exc:
        raise _to_503(exc)


# ----------------- rule groups --------------------------------------------


@router.get("/rule-groups", summary="List Rule Groups (WAFv2)")
def list_rule_groups(
    Scope: str = Query(..., pattern=_SCOPE_RE),
    NextMarker: Optional[str] = Query(None),
    Limit: Optional[int] = Query(None, ge=1, le=100),
) -> Dict[str, Any]:
    eng = get_aws_waf_engine()
    try:
        return eng.list_rule_groups(
            scope=Scope, next_marker=NextMarker, limit=Limit
        )
    except AWSWAFUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/rule-groups/{Scope}/{Id}/{Name}",
    summary="Get a Rule Group (WAFv2)",
)
def get_rule_group(
    Scope: str = Path(..., pattern=_SCOPE_RE),
    Id: str = Path(..., min_length=1, max_length=128),
    Name: str = Path(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    eng = get_aws_waf_engine()
    try:
        return eng.get_rule_group(scope=Scope, group_id=Id, name=Name)
    except AWSWAFUnavailableError as exc:
        raise _to_503(exc)


# ----------------- IP sets ------------------------------------------------


@router.get("/ip-sets", summary="List IP Sets (WAFv2)")
def list_ip_sets(
    Scope: str = Query(..., pattern=_SCOPE_RE),
    NextMarker: Optional[str] = Query(None),
    Limit: Optional[int] = Query(None, ge=1, le=100),
) -> Dict[str, Any]:
    eng = get_aws_waf_engine()
    try:
        return eng.list_ip_sets(
            scope=Scope, next_marker=NextMarker, limit=Limit
        )
    except AWSWAFUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/ip-sets/{Scope}/{Id}/{Name}",
    summary="Get an IP Set (WAFv2)",
)
def get_ip_set(
    Scope: str = Path(..., pattern=_SCOPE_RE),
    Id: str = Path(..., min_length=1, max_length=128),
    Name: str = Path(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    eng = get_aws_waf_engine()
    try:
        return eng.get_ip_set(scope=Scope, ip_set_id=Id, name=Name)
    except AWSWAFUnavailableError as exc:
        raise _to_503(exc)


# ----------------- regex pattern sets -------------------------------------


@router.get(
    "/regex-pattern-sets",
    summary="List Regex Pattern Sets (WAFv2)",
)
def list_regex_pattern_sets(
    Scope: str = Query(..., pattern=_SCOPE_RE),
    NextMarker: Optional[str] = Query(None),
    Limit: Optional[int] = Query(None, ge=1, le=100),
) -> Dict[str, Any]:
    eng = get_aws_waf_engine()
    try:
        return eng.list_regex_pattern_sets(
            scope=Scope, next_marker=NextMarker, limit=Limit
        )
    except AWSWAFUnavailableError as exc:
        raise _to_503(exc)


# ----------------- managed rule groups ------------------------------------


@router.get(
    "/managed-rule-groups",
    summary="List Available Managed Rule Groups (WAFv2)",
)
def list_managed_rule_groups(
    Scope: str = Query(..., pattern=_SCOPE_RE),
    NextMarker: Optional[str] = Query(None),
    Limit: Optional[int] = Query(None, ge=1, le=100),
) -> Dict[str, Any]:
    eng = get_aws_waf_engine()
    try:
        return eng.list_available_managed_rule_groups(
            scope=Scope, next_marker=NextMarker, limit=Limit
        )
    except AWSWAFUnavailableError as exc:
        raise _to_503(exc)


# ----------------- sampled requests ---------------------------------------


@router.post(
    "/sampled-requests",
    summary="Get a sample of requests inspected by a WAFv2 rule",
)
def get_sampled_requests(
    body: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    eng = get_aws_waf_engine()
    try:
        web_acl_arn = body.get("WebAclArn") or ""
        rule_metric_name = body.get("RuleMetricName") or ""
        scope = body.get("Scope") or ""
        time_window = body.get("TimeWindow") or {}
        start_time = time_window.get("StartTime") or ""
        end_time = time_window.get("EndTime") or ""
        max_items = int(body.get("MaxItems", 100))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"bad body: {exc}")

    if not all([web_acl_arn, rule_metric_name, scope, start_time, end_time]):
        raise HTTPException(
            status_code=400,
            detail=(
                "WebAclArn, RuleMetricName, Scope, "
                "TimeWindow.StartTime and TimeWindow.EndTime are required"
            ),
        )

    try:
        return eng.get_sampled_requests(
            web_acl_arn=web_acl_arn,
            rule_metric_name=rule_metric_name,
            scope=scope,
            start_time=start_time,
            end_time=end_time,
            max_items=max_items,
        )
    except AWSWAFUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
