"""ALDECI AWS WAFv2 engine — REAL boto3 only, NO MOCKS.

Wraps the AWS WAFv2 API (Web ACLs, Rule Groups, IP Sets, Regex Pattern
Sets, Managed Rule Groups, Sampled Requests) via boto3.

Capability summary returns ``status="unavailable"`` and lookup endpoints
raise ``AWSWAFUnavailableError`` (HTTP 503 at the router) when
``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` are not configured.

NO SQLite cache. NO mock data.

Singleton:
    eng = get_aws_waf_engine()

Reset (tests):
    reset_aws_waf_engine()
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional

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


class AWSWAFUnavailableError(RuntimeError):
    """Raised when AWS WAFv2 cannot be reached or is misconfigured."""


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


class AWSWAFEngine:
    """Real boto3-backed AWS WAFv2 client.

    All public methods raise ``AWSWAFUnavailableError`` when the credentials
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
            raise AWSWAFUnavailableError(
                "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set — "
                "set both env vars to call AWS WAFv2"
            )

    def _ensure_client(self) -> Any:
        """Lazily build a boto3 wafv2 client. Raises on failure."""
        if self._client is not None:
            return self._client

        self._require_configured()

        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover - boto3 in requirements
            raise AWSWAFUnavailableError(
                "boto3 is not installed — pip install boto3"
            ) from exc

        try:
            # CLOUDFRONT scope must be invoked against us-east-1; REGIONAL is
            # bound to the caller's region. We bind to the configured region
            # and trust the caller to pass Scope=CLOUDFRONT when needed.
            self._client = boto3.client(
                "wafv2",
                region_name=self._region,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )
        except Exception as exc:  # noqa: BLE001
            raise AWSWAFUnavailableError(
                f"Failed to build boto3 wafv2 client: {exc}"
            ) from exc
        return self._client

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Return capability metadata for the GET / endpoint."""
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "AWS WAFv2",
            "endpoints": [
                "/web-acls",
                "/web-acls/{Scope}/{Id}/{Name}",
                "/rule-groups",
                "/ip-sets",
                "/regex-pattern-sets",
                "/sampled-requests",
            ],
            "aws_access_key_present": bool(self._access_key),
            "aws_region": self._region,
            "status": status,
        }

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _validate_scope(scope: str) -> str:
        s = (scope or "").strip().upper()
        if s not in ("REGIONAL", "CLOUDFRONT"):
            raise AWSWAFUnavailableError(
                f"Scope must be REGIONAL or CLOUDFRONT (got {scope!r})"
            )
        return s

    def _list_kwargs(
        self,
        scope: str,
        next_marker: Optional[str],
        limit: Optional[int],
    ) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {"Scope": self._validate_scope(scope)}
        if next_marker:
            kwargs["NextMarker"] = next_marker
        if limit is not None:
            kwargs["Limit"] = int(limit)
        return kwargs

    # ---------------------------------------------------------------- web ACLs

    def list_web_acls(
        self,
        scope: str,
        next_marker: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs = self._list_kwargs(scope, next_marker, limit)
        try:
            resp = client.list_web_acls(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSWAFUnavailableError(
                f"AWS WAFv2 list_web_acls failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "WebACLs": _serialise(list(resp.get("WebACLs", []))),
        }
        nm = resp.get("NextMarker")
        if nm:
            out["NextMarker"] = nm
        try:
            _emit_event(
                "aws_waf.web_acls_page",
                {
                    "count": len(out["WebACLs"]),
                    "scope": kwargs["Scope"],
                    "region": self._region,
                    "marker_present": bool(nm),
                },
            )
        except Exception:  # pragma: no cover
            pass
        return out

    def get_web_acl(self, scope: str, acl_id: str, name: str) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs = {
            "Scope": self._validate_scope(scope),
            "Id": acl_id,
            "Name": name,
        }
        try:
            resp = client.get_web_acl(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSWAFUnavailableError(
                f"AWS WAFv2 get_web_acl failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "WebACL": _serialise(resp.get("WebACL", {})),
        }
        for opt in ("LockToken", "ApplicationIntegrationURL"):
            v = resp.get(opt)
            if v is not None:
                out[opt] = v
        return out

    # -------------------------------------------------------------- rule groups

    def list_rule_groups(
        self,
        scope: str,
        next_marker: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs = self._list_kwargs(scope, next_marker, limit)
        try:
            resp = client.list_rule_groups(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSWAFUnavailableError(
                f"AWS WAFv2 list_rule_groups failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "RuleGroups": _serialise(list(resp.get("RuleGroups", []))),
        }
        nm = resp.get("NextMarker")
        if nm:
            out["NextMarker"] = nm
        return out

    def get_rule_group(
        self, scope: str, group_id: str, name: str
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs = {
            "Scope": self._validate_scope(scope),
            "Id": group_id,
            "Name": name,
        }
        try:
            resp = client.get_rule_group(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSWAFUnavailableError(
                f"AWS WAFv2 get_rule_group failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "RuleGroup": _serialise(resp.get("RuleGroup", {})),
        }
        v = resp.get("LockToken")
        if v is not None:
            out["LockToken"] = v
        return out

    # ------------------------------------------------------------------ ip sets

    def list_ip_sets(
        self,
        scope: str,
        next_marker: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs = self._list_kwargs(scope, next_marker, limit)
        try:
            resp = client.list_ip_sets(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSWAFUnavailableError(
                f"AWS WAFv2 list_ip_sets failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "IPSets": _serialise(list(resp.get("IPSets", []))),
        }
        nm = resp.get("NextMarker")
        if nm:
            out["NextMarker"] = nm
        return out

    def get_ip_set(
        self, scope: str, ip_set_id: str, name: str
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs = {
            "Scope": self._validate_scope(scope),
            "Id": ip_set_id,
            "Name": name,
        }
        try:
            resp = client.get_ip_set(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSWAFUnavailableError(
                f"AWS WAFv2 get_ip_set failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "IPSet": _serialise(resp.get("IPSet", {})),
        }
        v = resp.get("LockToken")
        if v is not None:
            out["LockToken"] = v
        return out

    # --------------------------------------------------------- regex pattern sets

    def list_regex_pattern_sets(
        self,
        scope: str,
        next_marker: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs = self._list_kwargs(scope, next_marker, limit)
        try:
            resp = client.list_regex_pattern_sets(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSWAFUnavailableError(
                f"AWS WAFv2 list_regex_pattern_sets failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "RegexPatternSets": _serialise(
                list(resp.get("RegexPatternSets", []))
            ),
        }
        nm = resp.get("NextMarker")
        if nm:
            out["NextMarker"] = nm
        return out

    # ------------------------------------------------------ managed rule groups

    def list_available_managed_rule_groups(
        self,
        scope: str,
        next_marker: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        client = self._ensure_client()
        kwargs = self._list_kwargs(scope, next_marker, limit)
        try:
            resp = client.list_available_managed_rule_groups(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSWAFUnavailableError(
                f"AWS WAFv2 list_available_managed_rule_groups failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "ManagedRuleGroups": _serialise(
                list(resp.get("ManagedRuleGroups", []))
            ),
        }
        nm = resp.get("NextMarker")
        if nm:
            out["NextMarker"] = nm
        return out

    # ---------------------------------------------------------- sampled requests

    def get_sampled_requests(
        self,
        web_acl_arn: str,
        rule_metric_name: str,
        scope: str,
        start_time: str,
        end_time: str,
        max_items: int,
    ) -> Dict[str, Any]:
        if not web_acl_arn:
            raise AWSWAFUnavailableError("WebAclArn is required")
        if not rule_metric_name:
            raise AWSWAFUnavailableError("RuleMetricName is required")
        if max_items < 1 or max_items > 500:
            raise AWSWAFUnavailableError(
                f"MaxItems must be 1..500 (got {max_items})"
            )
        client = self._ensure_client()
        kwargs: Dict[str, Any] = {
            "WebAclArn": web_acl_arn,
            "RuleMetricName": rule_metric_name,
            "Scope": self._validate_scope(scope),
            "TimeWindow": {
                "StartTime": start_time,
                "EndTime": end_time,
            },
            "MaxItems": int(max_items),
        }
        try:
            resp = client.get_sampled_requests(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSWAFUnavailableError(
                f"AWS WAFv2 get_sampled_requests failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "SampledRequests": _serialise(
                list(resp.get("SampledRequests", []))
            ),
            "PopulationSize": int(resp.get("PopulationSize", 0)),
            "TimeWindow": _serialise(resp.get("TimeWindow", {})),
        }
        try:
            _emit_event(
                "aws_waf.sampled_requests",
                {
                    "count": len(out["SampledRequests"]),
                    "population": out["PopulationSize"],
                    "scope": kwargs["Scope"],
                    "region": self._region,
                },
            )
        except Exception:  # pragma: no cover
            pass
        return out


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[AWSWAFEngine] = None
_singleton_lock = threading.RLock()


def get_aws_waf_engine(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: Optional[str] = None,
    client: Any = None,
    force_refresh: bool = False,
) -> AWSWAFEngine:
    """Return the process-wide AWSWAFEngine singleton.

    Tests may pass ``force_refresh=True`` (or call ``reset_aws_waf_engine()``)
    to bind a stubbed boto3 client.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (access_key, secret_key, region, client)
        ):
            _singleton = AWSWAFEngine(
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                client=client,
            )
        return _singleton


def reset_aws_waf_engine() -> None:
    global _singleton
    with _singleton_lock:
        _singleton = None


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

__all__ = [
    "AWSWAFEngine",
    "AWSWAFUnavailableError",
    "get_aws_waf_engine",
    "reset_aws_waf_engine",
]
