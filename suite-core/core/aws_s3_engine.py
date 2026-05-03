"""ALDECI AWS S3 inventory + posture engine — REAL boto3 only, NO MOCKS.

Wraps the AWS S3 control-plane (bucket-level posture) via boto3. Exists so
the platform can answer:

  * what buckets does this account own?
  * for a given bucket, what is its posture footprint?
    - bucket policy (resource-policy)
    - server-side encryption configuration (SSE-S3 / SSE-KMS / SSE-DSSE-KMS)
    - bucket ACL (canonical Owner + Grants)
    - public-access-block (the four-flag override)
    - versioning + MFA-Delete
    - server access logging target
    - lifecycle rules (transitions / expiration)

Capability summary returns ``status="unavailable"`` and lookup endpoints
raise ``AWSS3UnavailableError`` (HTTP 503 at the router) when
``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` are not configured.

NO SQLite cache. NO mock data.

Singleton:
    eng = get_aws_s3_engine()

Reset (tests):
    reset_aws_s3_engine()
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (optional, never blocks)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Best-effort TrustGraph emit. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        emit(event_type, payload)
    except Exception:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# botocore ClientError sniffing (no hard import — degrade gracefully)
# ---------------------------------------------------------------------------
def _is_client_error(exc: BaseException) -> bool:
    try:
        from botocore.exceptions import ClientError  # type: ignore
        return isinstance(exc, ClientError)
    except Exception:  # pragma: no cover
        return False


def _client_error_code(exc: BaseException) -> str:
    """Pull the AWS error code (e.g. 'NoSuchBucketPolicy') off a ClientError."""
    try:
        return str(exc.response["Error"]["Code"])  # type: ignore[attr-defined,index]
    except Exception:  # pragma: no cover
        return ""


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class AWSS3UnavailableError(RuntimeError):
    """Raised when AWS S3 cannot be reached or is misconfigured."""


class AWSS3NotFoundError(RuntimeError):
    """Raised when a bucket-level resource isn't configured (404 to the router).

    Carries the upstream error code (e.g. ``NoSuchBucketPolicy``) so the router
    can return a structured 404 body that mirrors the AWS API.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class AWSS3Engine:
    """Real boto3-backed AWS S3 control-plane client.

    All public methods raise :class:`AWSS3UnavailableError` when the
    credentials are not configured. Routers translate this to HTTP 503.

    Tests can inject a stubbed boto3 client via the ``client=`` kwarg or by
    setting ``engine._client`` after construction.
    """

    DEFAULT_REGION = "us-east-1"

    def __init__(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        region: Optional[str] = None,
        client: Any = None,
    ) -> None:
        self._access_key: str = (
            access_key
            or os.environ.get("AWS_ACCESS_KEY_ID", "")
            or ""
        ).strip()
        self._secret_key: str = (
            secret_key
            or os.environ.get("AWS_SECRET_ACCESS_KEY", "")
            or ""
        ).strip()
        self._region: str = (
            region
            or os.environ.get("AWS_REGION", "")
            or os.environ.get("AWS_DEFAULT_REGION", "")
            or self.DEFAULT_REGION
        ).strip()
        # Allow tests to inject a botocore-Stubbed client directly.
        self._client: Any = client

    # ------------------------------------------------------------------ utils

    def is_configured(self) -> bool:
        return bool(self._access_key and self._secret_key)

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise AWSS3UnavailableError(
                "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set — "
                "set both env vars to call AWS S3"
            )

    def _ensure_client(self) -> Any:
        """Lazily build a boto3 s3 client. Raises on failure."""
        if self._client is not None:
            return self._client

        self._require_configured()

        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover - boto3 is in requirements
            raise AWSS3UnavailableError(
                "boto3 is not installed — pip install boto3"
            ) from exc

        try:
            self._client = boto3.client(
                "s3",
                region_name=self._region,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )
        except Exception as exc:  # noqa: BLE001
            raise AWSS3UnavailableError(
                f"Failed to build boto3 s3 client: {exc}"
            ) from exc
        return self._client

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Return capability metadata for the GET / endpoint."""
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "AWS S3",
            "endpoints": [
                "/buckets",
                "/buckets/{name}/policy",
                "/buckets/{name}/encryption",
                "/buckets/{name}/acl",
                "/buckets/{name}/public-access-block",
                "/buckets/{name}/versioning",
                "/buckets/{name}/logging",
                "/buckets/{name}/lifecycle",
            ],
            "aws_access_key_present": bool(self._access_key),
            "aws_region": self._region,
            "status": status,
        }

    # -------------------------------------------------------- helper for AWS

    def _call(
        self,
        api_name: str,
        not_found_codes: Optional[set] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Invoke a boto3 method and translate ClientError into our exceptions.

        ``not_found_codes`` lists AWS error codes that mean "the bucket exists
        but this configuration is unset" — these raise :class:`AWSS3NotFoundError`
        which the router maps to HTTP 404.
        """
        client = self._ensure_client()
        method = getattr(client, api_name, None)
        if method is None:  # pragma: no cover - guard
            raise AWSS3UnavailableError(
                f"boto3 s3 client has no method '{api_name}'"
            )
        try:
            resp = method(**kwargs)
        except Exception as exc:  # noqa: BLE001
            if not_found_codes and _is_client_error(exc):
                code = _client_error_code(exc)
                if code in not_found_codes:
                    raise AWSS3NotFoundError(code, str(exc)) from exc
            raise AWSS3UnavailableError(
                f"AWS S3 {api_name} failed: {exc}"
            ) from exc
        # ResponseMetadata is noisy + non-deterministic; strip it.
        if isinstance(resp, dict):
            resp.pop("ResponseMetadata", None)
        return resp or {}

    # ----------------------------------------------------------------- buckets

    def list_buckets(self) -> Dict[str, Any]:
        """Wrap S3 ListBuckets — returns Buckets[] + Owner."""
        resp = self._call("list_buckets")
        out = {
            "Buckets": list(resp.get("Buckets", [])),
            "Owner": resp.get("Owner", {}) or {},
        }
        try:
            _emit_event(
                "aws_s3.buckets_listed",
                {"count": len(out["Buckets"]), "region": self._region},
            )
        except Exception:  # pragma: no cover
            pass
        return out

    # ------------------------------------------------------ bucket: policy

    def get_bucket_policy(self, name: str) -> Dict[str, Any]:
        """Wrap GetBucketPolicy. Raises AWSS3NotFoundError on NoSuchBucketPolicy."""
        return self._call(
            "get_bucket_policy",
            not_found_codes={"NoSuchBucketPolicy"},
            Bucket=name,
        )

    # -------------------------------------------------- bucket: encryption

    def get_bucket_encryption(self, name: str) -> Dict[str, Any]:
        """Wrap GetBucketEncryption. 404 on ServerSideEncryptionConfigurationNotFoundError."""
        return self._call(
            "get_bucket_encryption",
            not_found_codes={"ServerSideEncryptionConfigurationNotFoundError"},
            Bucket=name,
        )

    # -------------------------------------------------------- bucket: acl

    def get_bucket_acl(self, name: str) -> Dict[str, Any]:
        return self._call("get_bucket_acl", Bucket=name)

    # ------------------------------------------- bucket: public-access-block

    def get_public_access_block(self, name: str) -> Dict[str, Any]:
        """Wrap GetPublicAccessBlock. 404 on NoSuchPublicAccessBlockConfiguration."""
        return self._call(
            "get_public_access_block",
            not_found_codes={"NoSuchPublicAccessBlockConfiguration"},
            Bucket=name,
        )

    # ---------------------------------------------------- bucket: versioning

    def get_bucket_versioning(self, name: str) -> Dict[str, Any]:
        return self._call("get_bucket_versioning", Bucket=name)

    # ------------------------------------------------------- bucket: logging

    def get_bucket_logging(self, name: str) -> Dict[str, Any]:
        return self._call("get_bucket_logging", Bucket=name)

    # ----------------------------------------------------- bucket: lifecycle

    def get_bucket_lifecycle(self, name: str) -> Dict[str, Any]:
        """Wrap GetBucketLifecycleConfiguration. 404 on NoSuchLifecycleConfiguration."""
        return self._call(
            "get_bucket_lifecycle_configuration",
            not_found_codes={"NoSuchLifecycleConfiguration"},
            Bucket=name,
        )


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[AWSS3Engine] = None
_singleton_lock = threading.RLock()


def get_aws_s3_engine(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: Optional[str] = None,
    client: Any = None,
    force_refresh: bool = False,
) -> AWSS3Engine:
    """Return the process-wide AWSS3Engine singleton.

    Tests may pass ``force_refresh=True`` (or call ``reset_aws_s3_engine()``)
    to bind a stubbed boto3 client.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (access_key, secret_key, region, client)
        ):
            _singleton = AWSS3Engine(
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                client=client,
            )
        return _singleton


def reset_aws_s3_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` re-reads env."""
    global _singleton
    with _singleton_lock:
        _singleton = None


__all__ = [
    "AWSS3Engine",
    "AWSS3UnavailableError",
    "AWSS3NotFoundError",
    "get_aws_s3_engine",
    "reset_aws_s3_engine",
]
