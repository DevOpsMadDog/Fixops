"""ALDECI AWS EKS inventory router.

Surfaces cluster + nodegroup + addon + fargate + access-entry data from the
suite-core ``AWSEKSEngine``. NO mocks: when AWS env vars are unset every
lookup endpoint returns HTTP 503.

Endpoints (all under ``/api/v1/aws-eks``):

  GET  /                                                capability summary
  GET  /clusters                                        ListClusters
  GET  /clusters/{cluster_name}                         DescribeCluster
  GET  /clusters/{cluster_name}/nodegroups              ListNodegroups
  GET  /clusters/{cluster_name}/nodegroups/{ng}         DescribeNodegroup
  GET  /clusters/{cluster_name}/addons                  ListAddons
  GET  /clusters/{cluster_name}/addons/{addon}          DescribeAddon
  GET  /clusters/{cluster_name}/fargate-profiles        ListFargateProfiles
  GET  /clusters/{cluster_name}/access-entries          ListAccessEntries

Auth: mounted under ``read:scans`` scope by ``platform_app.py``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Path, Query

from core.aws_eks_engine import (
    AWSEKSNotFoundError,
    AWSEKSUnavailableError,
    get_aws_eks_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/aws-eks", tags=["aws-eks"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _engine():
    return get_aws_eks_engine()


# EKS cluster names: 1-100 chars, alnum + hyphen + underscore.
# AWS spec: ^[0-9A-Za-z][A-Za-z0-9\-_]*$
_CLUSTER_NAME_PATTERN = r"^[0-9A-Za-z][A-Za-z0-9\-_]{0,99}$"

# Nodegroup names follow the same convention.
_NODEGROUP_NAME_PATTERN = _CLUSTER_NAME_PATTERN

# Addon names: lowercase service id like 'vpc-cni', 'coredns', 'kube-proxy'.
_ADDON_NAME_PATTERN = r"^[a-z][a-z0-9\-_.]{0,99}$"


def _cluster_path() -> Any:
    return Path(
        ...,
        min_length=1,
        max_length=100,
        pattern=_CLUSTER_NAME_PATTERN,
        description="EKS cluster name (1-100 chars).",
    )


def _nodegroup_path() -> Any:
    return Path(
        ...,
        min_length=1,
        max_length=100,
        pattern=_NODEGROUP_NAME_PATTERN,
        description="EKS managed nodegroup name (1-100 chars).",
    )


def _addon_path() -> Any:
    return Path(
        ...,
        min_length=1,
        max_length=100,
        pattern=_ADDON_NAME_PATTERN,
        description="EKS managed addon name.",
    )


def _handle_unavailable(exc: AWSEKSUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


def _handle_not_found(exc: AWSEKSNotFoundError, what: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": exc.code, "message": str(exc), "resource": what},
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/", summary="AWS EKS capability summary")
def capability_summary() -> Dict[str, Any]:
    """Return service identity, endpoint catalog, env-presence flags, status."""
    return _engine().capability_summary()


@router.get("/clusters", summary="List EKS clusters in this region")
def list_clusters(
    maxResults: Optional[int] = Query(
        None, ge=1, le=100, description="EKS page size (1-100)."
    ),
    nextToken: Optional[str] = Query(None, description="Pagination cursor."),
    include: Optional[str] = Query(
        None, description="Comma-separated cluster types to include (e.g. 'all')."
    ),
) -> Dict[str, Any]:
    try:
        return _engine().list_clusters(
            max_results=maxResults, next_token=nextToken, include=include
        )
    except AWSEKSUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/clusters/{cluster_name}",
    summary="Describe EKS cluster (control plane, networking, identity, logging)",
)
def describe_cluster(cluster_name: str = _cluster_path()) -> Dict[str, Any]:
    try:
        return _engine().describe_cluster(cluster_name)
    except AWSEKSNotFoundError as exc:
        raise _handle_not_found(exc, f"cluster:{cluster_name}") from exc
    except AWSEKSUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


# ----- nodegroups ----------------------------------------------------------


@router.get(
    "/clusters/{cluster_name}/nodegroups",
    summary="List managed nodegroups for the cluster",
)
def list_nodegroups(
    cluster_name: str = _cluster_path(),
    maxResults: Optional[int] = Query(None, ge=1, le=100),
    nextToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    try:
        return _engine().list_nodegroups(
            cluster_name, max_results=maxResults, next_token=nextToken
        )
    except AWSEKSNotFoundError as exc:
        raise _handle_not_found(exc, f"cluster:{cluster_name}") from exc
    except AWSEKSUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/clusters/{cluster_name}/nodegroups/{nodegroup_name}",
    summary="Describe a managed nodegroup (capacity, scaling, AMI, taints)",
)
def describe_nodegroup(
    cluster_name: str = _cluster_path(),
    nodegroup_name: str = _nodegroup_path(),
) -> Dict[str, Any]:
    try:
        return _engine().describe_nodegroup(cluster_name, nodegroup_name)
    except AWSEKSNotFoundError as exc:
        raise _handle_not_found(
            exc, f"nodegroup:{cluster_name}/{nodegroup_name}"
        ) from exc
    except AWSEKSUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


# ----- addons --------------------------------------------------------------


@router.get(
    "/clusters/{cluster_name}/addons",
    summary="List managed addons for the cluster",
)
def list_addons(
    cluster_name: str = _cluster_path(),
    maxResults: Optional[int] = Query(None, ge=1, le=100),
    nextToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    try:
        return _engine().list_addons(
            cluster_name, max_results=maxResults, next_token=nextToken
        )
    except AWSEKSNotFoundError as exc:
        raise _handle_not_found(exc, f"cluster:{cluster_name}") from exc
    except AWSEKSUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/clusters/{cluster_name}/addons/{addon_name}",
    summary="Describe a managed addon (version, marketplace, IRSA roleArn)",
)
def describe_addon(
    cluster_name: str = _cluster_path(),
    addon_name: str = _addon_path(),
) -> Dict[str, Any]:
    try:
        return _engine().describe_addon(cluster_name, addon_name)
    except AWSEKSNotFoundError as exc:
        raise _handle_not_found(
            exc, f"addon:{cluster_name}/{addon_name}"
        ) from exc
    except AWSEKSUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


# ----- fargate-profiles ----------------------------------------------------


@router.get(
    "/clusters/{cluster_name}/fargate-profiles",
    summary="List Fargate profile names for the cluster",
)
def list_fargate_profiles(
    cluster_name: str = _cluster_path(),
    maxResults: Optional[int] = Query(None, ge=1, le=100),
    nextToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    try:
        return _engine().list_fargate_profiles(
            cluster_name, max_results=maxResults, next_token=nextToken
        )
    except AWSEKSNotFoundError as exc:
        raise _handle_not_found(exc, f"cluster:{cluster_name}") from exc
    except AWSEKSUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


# ----- access-entries ------------------------------------------------------


@router.get(
    "/clusters/{cluster_name}/access-entries",
    summary="List EKS access entries (cluster access management)",
)
def list_access_entries(
    cluster_name: str = _cluster_path(),
    maxResults: Optional[int] = Query(None, ge=1, le=100),
    nextToken: Optional[str] = Query(None),
    associatedPolicyArn: Optional[str] = Query(
        None, description="Filter to entries associated with this policy ARN."
    ),
) -> Dict[str, Any]:
    try:
        return _engine().list_access_entries(
            cluster_name,
            max_results=maxResults,
            next_token=nextToken,
            associated_policy_arn=associatedPolicyArn,
        )
    except AWSEKSNotFoundError as exc:
        raise _handle_not_found(exc, f"cluster:{cluster_name}") from exc
    except AWSEKSUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


__all__ = ["router"]
