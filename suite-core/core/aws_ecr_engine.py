"""ALDECI AWS ECR (Elastic Container Registry) inventory + scan-findings engine.

REAL boto3 only — NO MOCKS. NO SQLite cache.

Wraps the AWS ECR control-plane via boto3. Exists so the platform can answer:

  * what container repositories does this account own?
  * what images live in a given repository?
  * what scan findings (basic + enhanced/Inspector) exist for an image?
  * what is the lifecycle policy / repo policy / registry-scanning configuration?

Capability summary returns ``status="unavailable"`` and lookup endpoints raise
``AWSECRUnavailableError`` (HTTP 503 at the router) when ``AWS_ACCESS_KEY_ID`` /
``AWS_SECRET_ACCESS_KEY`` are not configured.

Singleton:
    eng = get_aws_ecr_engine()

Reset (tests):
    reset_aws_ecr_engine()
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
# botocore ClientError sniffing (no hard import)
# ---------------------------------------------------------------------------
def _is_client_error(exc: BaseException) -> bool:
    try:
        from botocore.exceptions import ClientError  # type: ignore
        return isinstance(exc, ClientError)
    except Exception:  # pragma: no cover
        return False


def _client_error_code(exc: BaseException) -> str:
    try:
        return str(exc.response["Error"]["Code"])  # type: ignore[attr-defined,index]
    except Exception:  # pragma: no cover
        return ""


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class AWSECRUnavailableError(RuntimeError):
    """Raised when AWS ECR cannot be reached or is misconfigured."""


class AWSECRNotFoundError(RuntimeError):
    """Raised when an ECR resource isn't configured (404 to the router)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class AWSECREngine:
    """Real boto3-backed AWS ECR client.

    All public methods raise :class:`AWSECRUnavailableError` when the
    credentials are not configured. Routers translate this to HTTP 503.

    Tests can inject a stubbed boto3 client via the ``client=`` kwarg.
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
        self._client: Any = client

    # ------------------------------------------------------------------ utils

    def is_configured(self) -> bool:
        return bool(self._access_key and self._secret_key)

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise AWSECRUnavailableError(
                "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set — "
                "set both env vars to call AWS ECR"
            )

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        self._require_configured()
        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise AWSECRUnavailableError(
                "boto3 is not installed — pip install boto3"
            ) from exc
        try:
            self._client = boto3.client(
                "ecr",
                region_name=self._region,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )
        except Exception as exc:  # noqa: BLE001
            raise AWSECRUnavailableError(
                f"Failed to build boto3 ecr client: {exc}"
            ) from exc
        return self._client

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "AWS ECR",
            "endpoints": [
                "/repositories",
                "/repositories/{name}/images",
                "/repositories/{name}/scan-findings",
                "/repositories/{name}/lifecycle-policy",
                "/repositories/{name}/policy",
                "/registry-scanning-config",
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

        ``not_found_codes`` lists AWS error codes that mean "resource not
        configured" — these raise :class:`AWSECRNotFoundError` which the
        router maps to HTTP 404.
        """
        client = self._ensure_client()
        method = getattr(client, api_name, None)
        if method is None:  # pragma: no cover
            raise AWSECRUnavailableError(
                f"boto3 ecr client has no method '{api_name}'"
            )
        try:
            resp = method(**kwargs)
        except Exception as exc:  # noqa: BLE001
            if not_found_codes and _is_client_error(exc):
                code = _client_error_code(exc)
                if code in not_found_codes:
                    raise AWSECRNotFoundError(code, str(exc)) from exc
            raise AWSECRUnavailableError(
                f"AWS ECR {api_name} failed: {exc}"
            ) from exc
        if isinstance(resp, dict):
            resp.pop("ResponseMetadata", None)
        return resp or {}

    # --------------------------------------------------------- repositories

    def describe_repositories(
        self,
        max_results: Optional[int] = None,
        next_token: Optional[str] = None,
        registry_id: Optional[str] = None,
        repository_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """DescribeRepositories — returns {repositories:[], nextToken}."""
        kwargs: Dict[str, Any] = {}
        if max_results is not None:
            kwargs["maxResults"] = int(max_results)
        if next_token:
            kwargs["nextToken"] = next_token
        if registry_id:
            kwargs["registryId"] = registry_id
        if repository_names:
            kwargs["repositoryNames"] = list(repository_names)
        resp = self._call(
            "describe_repositories",
            not_found_codes={"RepositoryNotFoundException"},
            **kwargs,
        )
        out = {
            "repositories": list(resp.get("repositories", [])),
            "nextToken": resp.get("nextToken"),
        }
        try:
            _emit_event(
                "aws_ecr.repositories_listed",
                {"count": len(out["repositories"]), "region": self._region},
            )
        except Exception:  # pragma: no cover
            pass
        return out

    # ---------------------------------------------------------------- images

    def list_images(
        self,
        repository_name: str,
        max_results: Optional[int] = None,
        next_token: Optional[str] = None,
        filter_obj: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """ListImages — returns {imageIds:[], nextToken}."""
        kwargs: Dict[str, Any] = {"repositoryName": repository_name}
        if max_results is not None:
            kwargs["maxResults"] = int(max_results)
        if next_token:
            kwargs["nextToken"] = next_token
        if filter_obj:
            kwargs["filter"] = filter_obj
        resp = self._call(
            "list_images",
            not_found_codes={"RepositoryNotFoundException"},
            **kwargs,
        )
        return {
            "imageIds": list(resp.get("imageIds", [])),
            "nextToken": resp.get("nextToken"),
        }

    def batch_describe_images(
        self,
        repository_name: str,
        image_ids: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """BatchDescribeImages — returns {imageDetails:[], failures:[]}."""
        kwargs: Dict[str, Any] = {
            "repositoryName": repository_name,
            "imageIds": list(image_ids or []),
        }
        resp = self._call(
            "describe_images",
            not_found_codes={"RepositoryNotFoundException"},
            **kwargs,
        )
        return {
            "imageDetails": list(resp.get("imageDetails", [])),
            "failures": list(resp.get("failures", [])),
        }

    # -------------------------------------------------------- scan findings

    def describe_image_scan_findings(
        self,
        repository_name: str,
        image_digest: Optional[str] = None,
        image_tag: Optional[str] = None,
        max_results: Optional[int] = None,
        next_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """DescribeImageScanFindings — returns full findings payload."""
        image_id: Dict[str, str] = {}
        if image_digest:
            image_id["imageDigest"] = image_digest
        if image_tag:
            image_id["imageTag"] = image_tag
        if not image_id:
            raise AWSECRUnavailableError(
                "describe_image_scan_findings requires image_digest or image_tag"
            )
        kwargs: Dict[str, Any] = {
            "repositoryName": repository_name,
            "imageId": image_id,
        }
        if max_results is not None:
            kwargs["maxResults"] = int(max_results)
        if next_token:
            kwargs["nextToken"] = next_token
        resp = self._call(
            "describe_image_scan_findings",
            not_found_codes={
                "RepositoryNotFoundException",
                "ImageNotFoundException",
                "ScanNotFoundException",
            },
            **kwargs,
        )
        return resp

    # ----------------------------------------------------- lifecycle policy

    def get_lifecycle_policy(self, repository_name: str) -> Dict[str, Any]:
        """GetLifecyclePolicy — 404 on LifecyclePolicyNotFoundException."""
        return self._call(
            "get_lifecycle_policy",
            not_found_codes={
                "LifecyclePolicyNotFoundException",
                "RepositoryNotFoundException",
            },
            repositoryName=repository_name,
        )

    # ------------------------------------------------------- repo policy

    def get_repository_policy(self, repository_name: str) -> Dict[str, Any]:
        """GetRepositoryPolicy — 404 on RepositoryPolicyNotFoundException."""
        return self._call(
            "get_repository_policy",
            not_found_codes={
                "RepositoryPolicyNotFoundException",
                "RepositoryNotFoundException",
            },
            repositoryName=repository_name,
        )

    # ------------------------------------------------- registry scanning cfg

    def get_registry_scanning_configuration(self) -> Dict[str, Any]:
        """GetRegistryScanningConfiguration — returns {scanType, rules:[]}."""
        resp = self._call("get_registry_scanning_configuration")
        cfg = resp.get("scanningConfiguration") or {}
        return {
            "scanType": cfg.get("scanType", "BASIC"),
            "rules": list(cfg.get("rules", [])),
        }


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[AWSECREngine] = None
_singleton_lock = threading.RLock()


def get_aws_ecr_engine(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: Optional[str] = None,
    client: Any = None,
    force_refresh: bool = False,
) -> AWSECREngine:
    """Return the process-wide AWSECREngine singleton.

    Tests may pass ``force_refresh=True`` (or call ``reset_aws_ecr_engine()``)
    to bind a stubbed boto3 client.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (access_key, secret_key, region, client)
        ):
            _singleton = AWSECREngine(
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                client=client,
            )
        return _singleton


def reset_aws_ecr_engine() -> None:
    """Test helper — drop the cached singleton."""
    global _singleton
    with _singleton_lock:
        _singleton = None


__all__ = [
    "AWSECREngine",
    "AWSECRUnavailableError",
    "AWSECRNotFoundError",
    "get_aws_ecr_engine",
    "reset_aws_ecr_engine",
]
