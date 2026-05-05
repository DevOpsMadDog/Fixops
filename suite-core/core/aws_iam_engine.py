"""ALDECI AWS IAM engine — REAL boto3 only, NO MOCKS.

Wraps the AWS Identity & Access Management (IAM) API via boto3.

Capability summary returns ``status="unavailable"`` and lookup endpoints
raise ``AWSIAMUnavailableError`` (HTTP 503 at the router) when
``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` are not configured.

NO SQLite cache. NO mock data.

Singleton:
    eng = get_aws_iam_engine()

Reset (tests):
    reset_aws_iam_engine()
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
    """Best-effort TrustGraph emit. Never raises. Handles async bus.emit safely."""
    if _get_tg_bus is None:
        return
    try:
        import asyncio
        import inspect
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        if inspect.isawaitable(result):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(result)
            except RuntimeError:
                result.close()
    except Exception:  # pragma: no cover
        pass


class AWSIAMUnavailableError(RuntimeError):
    """Raised when AWS IAM cannot be reached or is misconfigured."""


def _serialise(value: Any) -> Any:
    """Make boto3 responses JSON-safe (datetimes -> isoformat)."""
    from datetime import date, datetime
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _serialise(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_serialise(item) for item in value]
    if isinstance(value, tuple):
        return [_serialise(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        import base64
        return base64.b64encode(bytes(value)).decode("ascii")
    return value


class AWSIAMEngine:
    """Real boto3-backed AWS IAM client.

    All public methods raise ``AWSIAMUnavailableError`` when the credentials
    are not configured. Routers translate this to HTTP 503.

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
        self._client: Any = client

    # ------------------------------------------------------------------ utils

    def is_configured(self) -> bool:
        return bool(self._access_key and self._secret_key)

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise AWSIAMUnavailableError(
                "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set — "
                "set both env vars to call AWS IAM"
            )

    def _ensure_client(self) -> Any:
        """Lazily build a boto3 iam client. Raises on failure."""
        if self._client is not None:
            return self._client

        self._require_configured()

        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover - boto3 in requirements
            raise AWSIAMUnavailableError(
                "boto3 is not installed — pip install boto3"
            ) from exc

        try:
            # IAM is a global service but boto3 still wants a region.
            self._client = boto3.client(
                "iam",
                region_name=self._region,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"Failed to build boto3 iam client: {exc}"
            ) from exc
        return self._client

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Return capability metadata for the GET / endpoint."""
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "AWS IAM",
            "endpoints": [
                "/users",
                "/users/{name}",
                "/users/{name}/access-keys",
                "/roles",
                "/roles/{name}",
                "/policies",
                "/policies/{arn}",
                "/credential-report",
            ],
            "aws_access_key_present": bool(self._access_key),
            "aws_region": self._region,
            "status": status,
        }

    # ----------------------------------------------------------------- users

    def list_users(
        self,
        marker: Optional[str] = None,
        max_items: Optional[int] = None,
        path_prefix: Optional[str] = None,
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs: Dict[str, Any] = {}
        if marker:
            kwargs["Marker"] = marker
        if max_items is not None:
            kwargs["MaxItems"] = int(max_items)
        if path_prefix:
            kwargs["PathPrefix"] = path_prefix
        try:
            resp = client.list_users(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM list_users failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "Users": _serialise(list(resp.get("Users", []))),
            "IsTruncated": bool(resp.get("IsTruncated", False)),
        }
        nm = resp.get("Marker")
        if nm:
            out["Marker"] = nm
        try:
            _emit_event(
                "aws_iam.users_page",
                {
                    "count": len(out["Users"]),
                    "region": self._region,
                    "marker_present": bool(nm),
                },
            )
        except Exception:  # pragma: no cover
            pass
        return out

    def get_user(self, user_name: str) -> Dict[str, Any]:
        client = self._ensure_client()
        try:
            resp = client.get_user(UserName=user_name)
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM get_user failed: {exc}"
            ) from exc
        return {"User": _serialise(resp.get("User", {}))}

    def list_access_keys(self, user_name: str) -> Dict[str, Any]:
        client = self._ensure_client()
        try:
            resp = client.list_access_keys(UserName=user_name)
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM list_access_keys failed: {exc}"
            ) from exc
        return {
            "AccessKeyMetadata": _serialise(
                list(resp.get("AccessKeyMetadata", []))
            ),
        }

    def list_user_policies(self, user_name: str) -> Dict[str, Any]:
        client = self._ensure_client()
        try:
            resp = client.list_user_policies(UserName=user_name)
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM list_user_policies failed: {exc}"
            ) from exc
        return {
            "PolicyNames": list(resp.get("PolicyNames", [])),
        }

    def list_attached_user_policies(self, user_name: str) -> Dict[str, Any]:
        client = self._ensure_client()
        try:
            resp = client.list_attached_user_policies(UserName=user_name)
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM list_attached_user_policies failed: {exc}"
            ) from exc
        return {
            "AttachedPolicies": _serialise(
                list(resp.get("AttachedPolicies", []))
            ),
        }

    # ----------------------------------------------------------------- roles

    def list_roles(
        self,
        marker: Optional[str] = None,
        max_items: Optional[int] = None,
        path_prefix: Optional[str] = None,
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs: Dict[str, Any] = {}
        if marker:
            kwargs["Marker"] = marker
        if max_items is not None:
            kwargs["MaxItems"] = int(max_items)
        if path_prefix:
            kwargs["PathPrefix"] = path_prefix
        try:
            resp = client.list_roles(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM list_roles failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "Roles": _serialise(list(resp.get("Roles", []))),
            "IsTruncated": bool(resp.get("IsTruncated", False)),
        }
        nm = resp.get("Marker")
        if nm:
            out["Marker"] = nm
        return out

    def get_role(self, role_name: str) -> Dict[str, Any]:
        client = self._ensure_client()
        try:
            resp = client.get_role(RoleName=role_name)
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM get_role failed: {exc}"
            ) from exc
        return {"Role": _serialise(resp.get("Role", {}))}

    # ----------------------------------------------------------------- policies

    def list_policies(
        self,
        scope: str = "All",
        only_attached: bool = False,
        path_prefix: Optional[str] = None,
        marker: Optional[str] = None,
        max_items: Optional[int] = None,
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs: Dict[str, Any] = {
            "Scope": scope,
            "OnlyAttached": bool(only_attached),
        }
        if path_prefix:
            kwargs["PathPrefix"] = path_prefix
        if marker:
            kwargs["Marker"] = marker
        if max_items is not None:
            kwargs["MaxItems"] = int(max_items)
        try:
            resp = client.list_policies(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM list_policies failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "Policies": _serialise(list(resp.get("Policies", []))),
            "IsTruncated": bool(resp.get("IsTruncated", False)),
        }
        nm = resp.get("Marker")
        if nm:
            out["Marker"] = nm
        return out

    def get_policy(self, policy_arn: str) -> Dict[str, Any]:
        client = self._ensure_client()
        try:
            resp = client.get_policy(PolicyArn=policy_arn)
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM get_policy failed: {exc}"
            ) from exc
        return {"Policy": _serialise(resp.get("Policy", {}))}

    def get_policy_version(
        self, policy_arn: str, version_id: str
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        try:
            resp = client.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM get_policy_version failed: {exc}"
            ) from exc
        return {"PolicyVersion": _serialise(resp.get("PolicyVersion", {}))}

    # ------------------------------------------------------- credential report

    def generate_credential_report(self) -> Dict[str, Any]:
        client = self._ensure_client()
        try:
            resp = client.generate_credential_report()
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM generate_credential_report failed: {exc}"
            ) from exc
        return {
            "State": resp.get("State", "STARTED"),
            "Description": resp.get("Description", ""),
        }

    def get_credential_report(self) -> Dict[str, Any]:
        client = self._ensure_client()
        try:
            resp = client.get_credential_report()
        except Exception as exc:  # noqa: BLE001
            raise AWSIAMUnavailableError(
                f"AWS IAM get_credential_report failed: {exc}"
            ) from exc
        content = resp.get("Content", b"")
        if isinstance(content, (bytes, bytearray)):
            import base64
            content_b64 = base64.b64encode(bytes(content)).decode("ascii")
        else:
            content_b64 = str(content)
        return {
            "Content": content_b64,
            "ReportFormat": resp.get("ReportFormat", "text/csv"),
            "GeneratedTime": _serialise(resp.get("GeneratedTime")),
        }


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[AWSIAMEngine] = None
_singleton_lock = threading.RLock()


def get_aws_iam_engine(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: Optional[str] = None,
    client: Any = None,
    force_refresh: bool = False,
) -> AWSIAMEngine:
    """Return the process-wide AWSIAMEngine singleton.

    Tests may pass ``force_refresh=True`` (or call ``reset_aws_iam_engine()``)
    to bind a stubbed boto3 client.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (access_key, secret_key, region, client)
        ):
            _singleton = AWSIAMEngine(
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                client=client,
            )
        return _singleton


def reset_aws_iam_engine() -> None:
    global _singleton
    with _singleton_lock:
        _singleton = None


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

__all__ = [
    "AWSIAMEngine",
    "AWSIAMUnavailableError",
    "get_aws_iam_engine",
    "reset_aws_iam_engine",
]
