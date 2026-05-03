"""ALDECI AWS IAM router — REAL boto3 only, NO MOCKS.

Mounted at ``/api/v1/aws-iam`` under the ``read:scans`` scope.

Endpoints
---------
GET   /                                      — capability summary
GET   /users                                 — list IAM users (paginated)
GET   /users/{user_name}                     — get a specific IAM user
GET   /users/{user_name}/access-keys         — list access keys
GET   /users/{user_name}/policies            — inline policy names
GET   /users/{user_name}/attached-policies   — managed policies attached
GET   /roles                                 — list IAM roles (paginated)
GET   /roles/{role_name}                     — get a specific IAM role
GET   /policies                              — list managed policies
GET   /policies/{policy_arn:path}            — get a managed policy
GET   /policies/{policy_arn:path}/versions/{version_id} — get policy version
POST  /credential-report/generate            — kick off credential-report build
GET   /credential-report                     — fetch latest credential report

When AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are not set, every lookup
endpoint returns HTTP 503. The capability summary still responds 200 with
``status="unavailable"``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response

from core.aws_iam_engine import (
    AWSIAMUnavailableError,
    get_aws_iam_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/aws-iam",
    tags=["aws-iam"],
    dependencies=[Depends(api_key_auth)],
)


# ------------------------------------------------------------------ helpers


def _to_503(exc: AWSIAMUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="AWS IAM capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    return eng.capability_summary()


# ----------- users ---------------------------------------------------------


@router.get("/users", summary="List IAM users")
def list_users(
    Marker: Optional[str] = Query(None, description="Pagination marker"),
    MaxItems: Optional[int] = Query(
        None, ge=1, le=1000, description="Max items per page (1-1000)"
    ),
    PathPrefix: Optional[str] = Query(None, description="IAM path prefix filter"),
) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.list_users(
            marker=Marker, max_items=MaxItems, path_prefix=PathPrefix
        )
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


@router.get("/users/{user_name}", summary="Get an IAM user")
def get_user(user_name: str = Path(..., min_length=1, max_length=64)) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.get_user(user_name)
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/users/{user_name}/access-keys",
    summary="List access keys for an IAM user",
)
def list_user_access_keys(
    user_name: str = Path(..., min_length=1, max_length=64),
) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.list_access_keys(user_name)
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/users/{user_name}/policies",
    summary="List inline policy names for an IAM user",
)
def list_user_inline_policies(
    user_name: str = Path(..., min_length=1, max_length=64),
) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.list_user_policies(user_name)
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/users/{user_name}/attached-policies",
    summary="List managed policies attached to an IAM user",
)
def list_user_attached_policies(
    user_name: str = Path(..., min_length=1, max_length=64),
) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.list_attached_user_policies(user_name)
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


# ----------- roles ---------------------------------------------------------


@router.get("/roles", summary="List IAM roles")
def list_roles(
    Marker: Optional[str] = Query(None, description="Pagination marker"),
    MaxItems: Optional[int] = Query(
        None, ge=1, le=1000, description="Max items per page (1-1000)"
    ),
    PathPrefix: Optional[str] = Query(None, description="IAM path prefix filter"),
) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.list_roles(
            marker=Marker, max_items=MaxItems, path_prefix=PathPrefix
        )
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


@router.get("/roles/{role_name}", summary="Get an IAM role")
def get_role(role_name: str = Path(..., min_length=1, max_length=64)) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.get_role(role_name)
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


# ----------- policies ------------------------------------------------------


@router.get("/policies", summary="List managed IAM policies")
def list_policies(
    Scope: str = Query("All", pattern="^(All|AWS|Local)$"),
    OnlyAttached: bool = Query(False),
    PathPrefix: Optional[str] = Query(None),
    Marker: Optional[str] = Query(None),
    MaxItems: Optional[int] = Query(None, ge=1, le=1000),
) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.list_policies(
            scope=Scope,
            only_attached=OnlyAttached,
            path_prefix=PathPrefix,
            marker=Marker,
            max_items=MaxItems,
        )
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/policies/{policy_arn:path}/versions/{version_id}",
    summary="Get a specific managed policy version",
)
def get_policy_version(
    policy_arn: str = Path(..., min_length=1),
    version_id: str = Path(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.get_policy_version(policy_arn, version_id)
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/policies/{policy_arn:path}",
    summary="Get a managed IAM policy",
)
def get_policy(policy_arn: str = Path(..., min_length=1)) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.get_policy(policy_arn)
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


# ----------- credential report --------------------------------------------


@router.post(
    "/credential-report/generate",
    summary="Generate an IAM credential report (async)",
    status_code=202,
)
def generate_credential_report(response: Response) -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        out = eng.generate_credential_report()
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)
    response.status_code = 202
    return out


@router.get(
    "/credential-report",
    summary="Fetch the latest IAM credential report",
)
def get_credential_report() -> Dict[str, Any]:
    eng = get_aws_iam_engine()
    try:
        return eng.get_credential_report()
    except AWSIAMUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
