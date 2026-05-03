"""ALDECI AWS S3 inventory + posture router.

Surfaces bucket-level posture data from the suite-core ``AWSS3Engine``. NO
mocks: when AWS env vars are unset every lookup endpoint returns HTTP 503.

Endpoints (all under ``/api/v1/aws-s3``):

  GET  /                                       capability summary
  GET  /buckets                                ListBuckets
  GET  /buckets/{name}/policy                  GetBucketPolicy        (404 if unset)
  GET  /buckets/{name}/encryption              GetBucketEncryption    (404 if unset)
  GET  /buckets/{name}/acl                     GetBucketAcl
  GET  /buckets/{name}/public-access-block     GetPublicAccessBlock   (404 if unset)
  GET  /buckets/{name}/versioning              GetBucketVersioning
  GET  /buckets/{name}/logging                 GetBucketLogging
  GET  /buckets/{name}/lifecycle               GetBucketLifecycleConfiguration (404 if unset)

Auth: mounted under ``read:scans`` scope by ``platform_app.py``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Path

from core.aws_s3_engine import (
    AWSS3NotFoundError,
    AWSS3UnavailableError,
    get_aws_s3_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/aws-s3", tags=["aws-s3"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _engine():
    return get_aws_s3_engine()


def _bucket_path() -> Any:
    """Path constraint for bucket names (3-63 chars, RFC-3986-safe subset).

    AWS allows lowercase letters, digits, dot, hyphen. We accept the same
    plus uppercase to surface mis-named legacy buckets in 404s rather than 422s.
    """
    return Path(
        ...,
        min_length=3,
        max_length=63,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9.\-]{1,61}[A-Za-z0-9]$",
        description="S3 bucket name (3-63 chars, AWS naming rules).",
    )


def _handle_unavailable(exc: AWSS3UnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


def _handle_not_found(exc: AWSS3NotFoundError, what: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": exc.code, "message": str(exc), "resource": what},
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/", summary="AWS S3 capability summary")
def capability_summary() -> Dict[str, Any]:
    """Return service identity, endpoint catalog, env-presence flags, status."""
    return _engine().capability_summary()


@router.get("/buckets", summary="List S3 buckets owned by the account")
def list_buckets() -> Dict[str, Any]:
    try:
        return _engine().list_buckets()
    except AWSS3UnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/buckets/{name}/policy",
    summary="Get bucket resource policy (404 if unset)",
)
def get_bucket_policy(name: str = _bucket_path()) -> Dict[str, Any]:
    try:
        return _engine().get_bucket_policy(name)
    except AWSS3NotFoundError as exc:
        raise _handle_not_found(exc, f"bucket-policy:{name}") from exc
    except AWSS3UnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/buckets/{name}/encryption",
    summary="Get server-side encryption configuration (404 if unset)",
)
def get_bucket_encryption(name: str = _bucket_path()) -> Dict[str, Any]:
    try:
        return _engine().get_bucket_encryption(name)
    except AWSS3NotFoundError as exc:
        raise _handle_not_found(exc, f"bucket-encryption:{name}") from exc
    except AWSS3UnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/buckets/{name}/acl",
    summary="Get bucket ACL (canonical Owner + Grants)",
)
def get_bucket_acl(name: str = _bucket_path()) -> Dict[str, Any]:
    try:
        return _engine().get_bucket_acl(name)
    except AWSS3UnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/buckets/{name}/public-access-block",
    summary="Get public-access-block (404 if unset)",
)
def get_public_access_block(name: str = _bucket_path()) -> Dict[str, Any]:
    try:
        return _engine().get_public_access_block(name)
    except AWSS3NotFoundError as exc:
        raise _handle_not_found(exc, f"public-access-block:{name}") from exc
    except AWSS3UnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/buckets/{name}/versioning",
    summary="Get bucket versioning state + MFADelete",
)
def get_bucket_versioning(name: str = _bucket_path()) -> Dict[str, Any]:
    try:
        return _engine().get_bucket_versioning(name)
    except AWSS3UnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/buckets/{name}/logging",
    summary="Get server access logging target",
)
def get_bucket_logging(name: str = _bucket_path()) -> Dict[str, Any]:
    try:
        return _engine().get_bucket_logging(name)
    except AWSS3UnavailableError as exc:
        raise _handle_unavailable(exc) from exc


@router.get(
    "/buckets/{name}/lifecycle",
    summary="Get bucket lifecycle rules (404 if unset)",
)
def get_bucket_lifecycle(name: str = _bucket_path()) -> Dict[str, Any]:
    try:
        return _engine().get_bucket_lifecycle(name)
    except AWSS3NotFoundError as exc:
        raise _handle_not_found(exc, f"bucket-lifecycle:{name}") from exc
    except AWSS3UnavailableError as exc:
        raise _handle_unavailable(exc) from exc


__all__ = ["router"]
