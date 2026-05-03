"""ALDECI AWS ECR (Elastic Container Registry) router.

Surfaces repository inventory + image inventory + Inspector/basic scan
findings + lifecycle/policy configuration from the suite-core
``AWSECREngine``. NO mocks: when AWS env vars are unset every lookup
endpoint returns HTTP 503.

Endpoints (all under ``/api/v1/aws-ecr``):

  GET  /                                                             capability summary
  GET  /repositories                                                 DescribeRepositories
  GET  /repositories/{name}/images                                   ListImages
  POST /repositories/{name}/images/batch-describe                    BatchDescribeImages
  GET  /repositories/{name}/images/{image_id:path}/scan-findings     DescribeImageScanFindings
  GET  /repositories/{name}/lifecycle-policy                         GetLifecyclePolicy
  GET  /repositories/{name}/policy                                   GetRepositoryPolicy
  GET  /registry-scanning-config                                     GetRegistryScanningConfiguration

Auth: mounted under ``read:scans`` scope by ``platform_app.py``.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException, Path, Query

from core.aws_ecr_engine import (
    AWSECRNotFoundError,
    AWSECRUnavailableError,
    get_aws_ecr_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/aws-ecr", tags=["aws-ecr"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _engine():
    return get_aws_ecr_engine()


def _repo_path() -> Any:
    """Path constraint for ECR repository names.

    AWS allows lowercase letters, digits, hyphens, underscores, dots,
    forward slashes (for namespacing), 2-256 chars total.
    """
    return Path(
        ...,
        min_length=2,
        max_length=256,
        pattern=r"^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*$",
        description="ECR repository name (2-256 chars, AWS naming rules).",
    )


def _handle_unavailable(exc: AWSECRUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


def _handle_not_found(exc: AWSECRNotFoundError, what: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": exc.code, "message": str(exc), "resource": what},
    )


def _parse_repo_names(repository_names: Optional[str]) -> Optional[List[str]]:
    if not repository_names:
        return None
    return [s.strip() for s in repository_names.split(",") if s.strip()]


def _parse_filter(filter_str: Optional[str]) -> Optional[Dict[str, Any]]:
    if not filter_str:
        return None
    try:
        parsed = json.loads(filter_str)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"filter must be valid JSON: {exc}",
        ) from exc
    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=422,
            detail="filter must be a JSON object",
        )
    return parsed


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/", summary="AWS ECR capability summary")
def capability_summary() -> Dict[str, Any]:
    """Return service identity, endpoint catalog, env-presence flags, status."""
    return _engine().capability_summary()


@router.get("/repositories", summary="DescribeRepositories — list ECR repos")
def list_repositories(
    maxResults: Optional[int] = Query(None, ge=1, le=1000),
    nextToken: Optional[str] = Query(None),
    registryId: Optional[str] = Query(None, pattern=r"^[0-9]{12}$"),
    repositoryNames: Optional[str] = Query(
        None, description="Comma-separated list of repository names to filter"
    ),
) -> Dict[str, Any]:
    try:
        return _engine().describe_repositories(
            max_results=maxResults,
            next_token=nextToken,
            registry_id=registryId,
            repository_names=_parse_repo_names(repositoryNames),
        )
    except AWSECRNotFoundError as exc:
        raise _handle_not_found(exc, "repositories") from exc
    except AWSECRUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/repositories/{repository_name}/images",
    summary="ListImages for a repository",
)
def list_images(
    repository_name: str = _repo_path(),
    maxResults: Optional[int] = Query(None, ge=1, le=1000),
    nextToken: Optional[str] = Query(None),
    filter: Optional[str] = Query(
        None, description="JSON-encoded ListImagesFilter (e.g. {\"tagStatus\": \"TAGGED\"})"
    ),
) -> Dict[str, Any]:
    try:
        return _engine().list_images(
            repository_name=repository_name,
            max_results=maxResults,
            next_token=nextToken,
            filter_obj=_parse_filter(filter),
        )
    except AWSECRNotFoundError as exc:
        raise _handle_not_found(exc, f"repository:{repository_name}") from exc
    except AWSECRUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.post(
    "/repositories/{repository_name}/images/batch-describe",
    summary="BatchDescribeImages — fetch image metadata + scan summary",
)
def batch_describe_images(
    repository_name: str = _repo_path(),
    body: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    image_ids = body.get("imageIds")
    if not isinstance(image_ids, list) or not image_ids:
        raise HTTPException(
            status_code=422,
            detail="body must contain non-empty 'imageIds' list of {imageDigest|imageTag}",
        )
    cleaned: List[Dict[str, str]] = []
    for entry in image_ids:
        if not isinstance(entry, dict):
            raise HTTPException(
                status_code=422,
                detail="each imageIds entry must be an object",
            )
        digest = entry.get("imageDigest")
        tag = entry.get("imageTag")
        if not digest and not tag:
            raise HTTPException(
                status_code=422,
                detail="each imageIds entry needs imageDigest and/or imageTag",
            )
        item: Dict[str, str] = {}
        if digest:
            item["imageDigest"] = str(digest)
        if tag:
            item["imageTag"] = str(tag)
        cleaned.append(item)
    try:
        return _engine().batch_describe_images(
            repository_name=repository_name,
            image_ids=cleaned,
        )
    except AWSECRNotFoundError as exc:
        raise _handle_not_found(exc, f"repository:{repository_name}") from exc
    except AWSECRUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/repositories/{repository_name}/images/{image_id:path}/scan-findings",
    summary="DescribeImageScanFindings (basic + Inspector enhanced)",
)
def describe_image_scan_findings(
    repository_name: str = _repo_path(),
    image_id: str = Path(..., description="image_id is either 'sha256:...' or a tag"),
    maxResults: Optional[int] = Query(None, ge=1, le=1000),
    nextToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    image_digest: Optional[str] = None
    image_tag: Optional[str] = None
    if image_id.startswith("sha256:"):
        image_digest = image_id
    else:
        image_tag = image_id
    try:
        return _engine().describe_image_scan_findings(
            repository_name=repository_name,
            image_digest=image_digest,
            image_tag=image_tag,
            max_results=maxResults,
            next_token=nextToken,
        )
    except AWSECRNotFoundError as exc:
        raise _handle_not_found(
            exc, f"scan-findings:{repository_name}/{image_id}"
        ) from exc
    except AWSECRUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/repositories/{repository_name}/lifecycle-policy",
    summary="GetLifecyclePolicy (404 if unset)",
)
def get_lifecycle_policy(repository_name: str = _repo_path()) -> Dict[str, Any]:
    try:
        return _engine().get_lifecycle_policy(repository_name)
    except AWSECRNotFoundError as exc:
        raise _handle_not_found(
            exc, f"lifecycle-policy:{repository_name}"
        ) from exc
    except AWSECRUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/repositories/{repository_name}/policy",
    summary="GetRepositoryPolicy — resource-based JSON policy (404 if unset)",
)
def get_repository_policy(repository_name: str = _repo_path()) -> Dict[str, Any]:
    try:
        return _engine().get_repository_policy(repository_name)
    except AWSECRNotFoundError as exc:
        raise _handle_not_found(
            exc, f"repo-policy:{repository_name}"
        ) from exc
    except AWSECRUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/registry-scanning-config",
    summary="GetRegistryScanningConfiguration (BASIC vs ENHANCED + rules)",
)
def get_registry_scanning_config() -> Dict[str, Any]:
    try:
        return _engine().get_registry_scanning_configuration()
    except AWSECRUnavailableError as exc:
        raise _handle_unavailable(exc) from exc


__all__ = ["router"]
