"""ALDECI AWS EKS inventory engine — REAL boto3 only, NO MOCKS.

Wraps the AWS EKS control-plane via boto3. Exists so the platform can answer:

  * what EKS clusters does this account own (in this region)?
  * for a given cluster, what is its full posture footprint?
    - DescribeCluster (control plane, networking, logging, encryption,
      access-config, identity/oidc, outpost, connector)
    - ListNodegroups + DescribeNodegroup (capacity, scaling, AMI, taints,
      launch-template, update-config)
    - ListAddons + DescribeAddon (managed addon version, marketplace,
      service-account roleArn)
    - ListFargateProfiles
    - ListAccessEntries (cluster access management)

Capability summary returns ``status="unavailable"`` and lookup endpoints
raise ``AWSEKSUnavailableError`` (HTTP 503 at the router) when
``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` are not configured.

NO SQLite cache. NO mock data.

Singleton:
    eng = get_aws_eks_engine()

Reset (tests):
    reset_aws_eks_engine()
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
    """Pull the AWS error code (e.g. 'ResourceNotFoundException') off a ClientError."""
    try:
        return str(exc.response["Error"]["Code"])  # type: ignore[attr-defined,index]
    except Exception:  # pragma: no cover
        return ""


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class AWSEKSUnavailableError(RuntimeError):
    """Raised when AWS EKS cannot be reached or is misconfigured."""


class AWSEKSNotFoundError(RuntimeError):
    """Raised when a cluster-level resource isn't found (404 to the router)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class AWSEKSEngine:
    """Real boto3-backed AWS EKS control-plane client.

    All public methods raise :class:`AWSEKSUnavailableError` when the
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
            raise AWSEKSUnavailableError(
                "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set — "
                "set both env vars to call AWS EKS"
            )

    def _ensure_client(self) -> Any:
        """Lazily build a boto3 eks client. Raises on failure."""
        if self._client is not None:
            return self._client

        self._require_configured()

        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover - boto3 is in requirements
            raise AWSEKSUnavailableError(
                "boto3 is not installed — pip install boto3"
            ) from exc

        try:
            self._client = boto3.client(
                "eks",
                region_name=self._region,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )
        except Exception as exc:  # noqa: BLE001
            raise AWSEKSUnavailableError(
                f"Failed to build boto3 eks client: {exc}"
            ) from exc
        return self._client

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Return capability metadata for the GET / endpoint."""
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "AWS EKS",
            "endpoints": [
                "/clusters",
                "/clusters/{name}",
                "/clusters/{name}/nodegroups",
                "/clusters/{name}/addons",
                "/clusters/{name}/fargate-profiles",
                "/clusters/{name}/access-entries",
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
        """Invoke a boto3 method and translate ClientError into our exceptions."""
        client = self._ensure_client()
        method = getattr(client, api_name, None)
        if method is None:  # pragma: no cover - guard
            raise AWSEKSUnavailableError(
                f"boto3 eks client has no method '{api_name}'"
            )
        try:
            resp = method(**kwargs)
        except Exception as exc:  # noqa: BLE001
            if not_found_codes and _is_client_error(exc):
                code = _client_error_code(exc)
                if code in not_found_codes:
                    raise AWSEKSNotFoundError(code, str(exc)) from exc
            raise AWSEKSUnavailableError(
                f"AWS EKS {api_name} failed: {exc}"
            ) from exc
        # ResponseMetadata is noisy + non-deterministic; strip it.
        if isinstance(resp, dict):
            resp.pop("ResponseMetadata", None)
        return resp or {}

    @staticmethod
    def _build_pager_kwargs(
        max_results: Optional[int],
        next_token: Optional[str],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build kwargs for paginated EKS list APIs (maxResults / nextToken)."""
        kw: Dict[str, Any] = {}
        if max_results is not None:
            kw["maxResults"] = int(max_results)
        if next_token:
            kw["nextToken"] = next_token
        if extra:
            for k, v in extra.items():
                if v is not None and v != "":
                    kw[k] = v
        return kw

    # ----------------------------------------------------------------- clusters

    def list_clusters(
        self,
        max_results: Optional[int] = None,
        next_token: Optional[str] = None,
        include: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Wrap EKS ListClusters — returns clusters[] + nextToken."""
        extra: Dict[str, Any] = {}
        if include:
            # API expects a list[str]
            extra["include"] = [s.strip() for s in include.split(",") if s.strip()]
        kw = self._build_pager_kwargs(max_results, next_token, extra)
        resp = self._call("list_clusters", **kw)
        out = {
            "clusters": list(resp.get("clusters", [])),
            "nextToken": resp.get("nextToken"),
        }
        try:
            _emit_event(
                "aws_eks.clusters_listed",
                {"count": len(out["clusters"]), "region": self._region},
            )
        except Exception:  # pragma: no cover
            pass
        return out

    def describe_cluster(self, name: str) -> Dict[str, Any]:
        """Wrap DescribeCluster. 404 on ResourceNotFoundException."""
        return self._call(
            "describe_cluster",
            not_found_codes={"ResourceNotFoundException"},
            name=name,
        )

    # ---------------------------------------------------------------- nodegroups

    def list_nodegroups(
        self,
        cluster_name: str,
        max_results: Optional[int] = None,
        next_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Wrap ListNodegroups."""
        kw = self._build_pager_kwargs(max_results, next_token)
        kw["clusterName"] = cluster_name
        resp = self._call(
            "list_nodegroups",
            not_found_codes={"ResourceNotFoundException"},
            **kw,
        )
        return {
            "nodegroups": list(resp.get("nodegroups", [])),
            "nextToken": resp.get("nextToken"),
        }

    def describe_nodegroup(
        self, cluster_name: str, nodegroup_name: str
    ) -> Dict[str, Any]:
        """Wrap DescribeNodegroup. 404 on ResourceNotFoundException."""
        return self._call(
            "describe_nodegroup",
            not_found_codes={"ResourceNotFoundException"},
            clusterName=cluster_name,
            nodegroupName=nodegroup_name,
        )

    # -------------------------------------------------------------------- addons

    def list_addons(
        self,
        cluster_name: str,
        max_results: Optional[int] = None,
        next_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Wrap ListAddons."""
        kw = self._build_pager_kwargs(max_results, next_token)
        kw["clusterName"] = cluster_name
        resp = self._call(
            "list_addons",
            not_found_codes={"ResourceNotFoundException"},
            **kw,
        )
        return {
            "addons": list(resp.get("addons", [])),
            "nextToken": resp.get("nextToken"),
        }

    def describe_addon(
        self, cluster_name: str, addon_name: str
    ) -> Dict[str, Any]:
        """Wrap DescribeAddon. 404 on ResourceNotFoundException."""
        return self._call(
            "describe_addon",
            not_found_codes={"ResourceNotFoundException"},
            clusterName=cluster_name,
            addonName=addon_name,
        )

    # ------------------------------------------------------------- fargate-profiles

    def list_fargate_profiles(
        self,
        cluster_name: str,
        max_results: Optional[int] = None,
        next_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Wrap ListFargateProfiles."""
        kw = self._build_pager_kwargs(max_results, next_token)
        kw["clusterName"] = cluster_name
        resp = self._call(
            "list_fargate_profiles",
            not_found_codes={"ResourceNotFoundException"},
            **kw,
        )
        return {
            "fargateProfileNames": list(resp.get("fargateProfileNames", [])),
            "nextToken": resp.get("nextToken"),
        }

    # -------------------------------------------------------------- access-entries

    def list_access_entries(
        self,
        cluster_name: str,
        max_results: Optional[int] = None,
        next_token: Optional[str] = None,
        associated_policy_arn: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Wrap ListAccessEntries."""
        extra: Dict[str, Any] = {}
        if associated_policy_arn:
            extra["associatedPolicyArn"] = associated_policy_arn
        kw = self._build_pager_kwargs(max_results, next_token, extra)
        kw["clusterName"] = cluster_name
        resp = self._call(
            "list_access_entries",
            not_found_codes={"ResourceNotFoundException"},
            **kw,
        )
        return {
            "accessEntries": list(resp.get("accessEntries", [])),
            "nextToken": resp.get("nextToken"),
        }


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[AWSEKSEngine] = None
_singleton_lock = threading.RLock()


def get_aws_eks_engine(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: Optional[str] = None,
    client: Any = None,
    force_refresh: bool = False,
) -> AWSEKSEngine:
    """Return the process-wide AWSEKSEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (access_key, secret_key, region, client)
        ):
            _singleton = AWSEKSEngine(
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                client=client,
            )
        return _singleton


def reset_aws_eks_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` re-reads env."""
    global _singleton
    with _singleton_lock:
        _singleton = None


__all__ = [
    "AWSEKSEngine",
    "AWSEKSUnavailableError",
    "AWSEKSNotFoundError",
    "get_aws_eks_engine",
    "reset_aws_eks_engine",
]
