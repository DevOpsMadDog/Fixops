"""ALDECI Amazon Inspector v2 engine — REAL boto3 only, NO MOCKS.

Wraps the AWS Inspector2 API via boto3 (the official client). NO SQLite cache.
NO mock data. When ``AWS_ACCESS_KEY_ID``/``AWS_SECRET_ACCESS_KEY`` are not
configured the capability summary returns ``status="unavailable"`` and every
lookup endpoint raises :class:`AmazonInspectorUnavailableError` (HTTP 503 at
the router layer).

Singleton::

    eng = get_amazon_inspector_engine()

Reset (tests)::

    reset_amazon_inspector_engine()
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


class AmazonInspectorUnavailableError(RuntimeError):
    """Raised when Amazon Inspector v2 cannot be reached or is misconfigured."""


class AmazonInspectorEngine:
    """Real boto3-backed Amazon Inspector v2 client.

    All public methods raise :class:`AmazonInspectorUnavailableError` when
    credentials are not configured. Routers translate this to HTTP 503.

    Tests can inject a stubbed boto3 client via the ``client=`` kwarg or by
    setting ``engine._client`` after construction.
    """

    DEFAULT_REGION = "us-east-1"
    SERVICE_NAME = "inspector2"

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
            raise AmazonInspectorUnavailableError(
                "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set — "
                "set both env vars to call Amazon Inspector v2"
            )

    def _ensure_client(self) -> Any:
        """Lazily build a boto3 inspector2 client. Raises on failure."""
        if self._client is not None:
            return self._client

        self._require_configured()

        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover - boto3 is in requirements
            raise AmazonInspectorUnavailableError(
                "boto3 is not installed — pip install boto3"
            ) from exc

        try:
            self._client = boto3.client(
                self.SERVICE_NAME,
                region_name=self._region,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )
        except Exception as exc:  # noqa: BLE001
            raise AmazonInspectorUnavailableError(
                f"Failed to build boto3 inspector2 client: {exc}"
            ) from exc
        return self._client

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Return capability metadata for the GET / endpoint."""
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "Amazon Inspector v2",
            "endpoints": [
                "/findings",
                "/findings/{id}",
                "/coverage",
                "/configuration",
                "/usage",
            ],
            "aws_access_key_present": bool(self._access_key),
            "aws_region": self._region,
            "status": status,
        }

    # ----------------------------------------------------------------- findings

    def list_findings(
        self,
        filter_criteria: Optional[Dict[str, Any]] = None,
        sort_criteria: Optional[Dict[str, Any]] = None,
        next_token: Optional[str] = None,
        max_results: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Call Inspector2 ListFindings and return a single page.

        The caller drives ``NextToken`` so the router returns one page to the
        UI. ``filterCriteria`` / ``sortCriteria`` follow the official AWS shape
        (see boto3 docs — both are dicts).
        """
        client = self._ensure_client()
        kwargs: Dict[str, Any] = {}
        if filter_criteria:
            kwargs["filterCriteria"] = filter_criteria
        if sort_criteria:
            kwargs["sortCriteria"] = sort_criteria
        if next_token:
            kwargs["nextToken"] = next_token
        if max_results is not None:
            kwargs["maxResults"] = int(max_results)
        try:
            resp = client.list_findings(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AmazonInspectorUnavailableError(
                f"Amazon Inspector v2 list_findings failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "findings": list(resp.get("findings", [])),
        }
        nt = resp.get("nextToken")
        if nt:
            out["nextToken"] = nt
        try:
            _emit_event(
                "amazon_inspector.findings_page",
                {
                    "count": len(out["findings"]),
                    "region": self._region,
                    "next_token_present": bool(nt),
                },
            )
        except Exception:  # pragma: no cover
            pass
        return out

    def get_finding(self, finding_arn: str) -> Dict[str, Any]:
        """Look up one finding via BatchGetFindingDetails.

        Inspector2 has no GetFinding shape — BatchGetFindingDetails is the
        canonical single-arn lookup.
        """
        if not finding_arn:
            raise AmazonInspectorUnavailableError("finding_arn is required")
        client = self._ensure_client()
        try:
            resp = client.batch_get_finding_details(findingArns=[finding_arn])
        except Exception as exc:  # noqa: BLE001
            raise AmazonInspectorUnavailableError(
                f"Amazon Inspector v2 batch_get_finding_details failed: {exc}"
            ) from exc
        details = list(resp.get("findingDetails", []))
        errors = list(resp.get("errors", []))
        return {
            "findingArn": finding_arn,
            "findingDetails": details,
            "errors": errors,
        }

    # ----------------------------------------------------------------- coverage

    def list_coverage(
        self,
        filter_criteria: Optional[Dict[str, Any]] = None,
        next_token: Optional[str] = None,
        max_results: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Call Inspector2 ListCoverage and return one page."""
        client = self._ensure_client()
        kwargs: Dict[str, Any] = {}
        if filter_criteria:
            kwargs["filterCriteria"] = filter_criteria
        if next_token:
            kwargs["nextToken"] = next_token
        if max_results is not None:
            kwargs["maxResults"] = int(max_results)
        try:
            resp = client.list_coverage(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AmazonInspectorUnavailableError(
                f"Amazon Inspector v2 list_coverage failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "coveredResources": list(resp.get("coveredResources", [])),
        }
        nt = resp.get("nextToken")
        if nt:
            out["nextToken"] = nt
        return out

    # ------------------------------------------------------------- configuration

    def get_configuration(self) -> Dict[str, Any]:
        """Return the EC2/ECR scan configuration via GetConfiguration."""
        client = self._ensure_client()
        try:
            resp = client.get_configuration()
        except Exception as exc:  # noqa: BLE001
            raise AmazonInspectorUnavailableError(
                f"Amazon Inspector v2 get_configuration failed: {exc}"
            ) from exc
        # Drop the boto3 ``ResponseMetadata`` envelope before returning.
        out = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
        # Ensure both top-level configuration objects always appear so the
        # UI can render fields even when AWS omits unset blocks.
        out.setdefault("ec2Configuration", {})
        out.setdefault("ecrConfiguration", {})
        return out

    # ------------------------------------------------------------------- usage

    def list_usage_totals(
        self,
        account_ids: Optional[List[str]] = None,
        next_token: Optional[str] = None,
        max_results: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Call Inspector2 ListUsageTotals and return one page."""
        client = self._ensure_client()
        kwargs: Dict[str, Any] = {}
        if account_ids:
            kwargs["accountIds"] = list(account_ids)
        if next_token:
            kwargs["nextToken"] = next_token
        if max_results is not None:
            kwargs["maxResults"] = int(max_results)
        try:
            resp = client.list_usage_totals(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AmazonInspectorUnavailableError(
                f"Amazon Inspector v2 list_usage_totals failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "usageTotals": list(resp.get("totals", []) or resp.get("usageTotals", [])),
        }
        nt = resp.get("nextToken")
        if nt:
            out["nextToken"] = nt
        return out


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[AmazonInspectorEngine] = None
_singleton_lock = threading.RLock()


def get_amazon_inspector_engine(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: Optional[str] = None,
    client: Any = None,
    force_refresh: bool = False,
) -> AmazonInspectorEngine:
    """Return the process-wide AmazonInspectorEngine singleton.

    Tests may pass ``force_refresh=True`` (or call
    :func:`reset_amazon_inspector_engine`) to bind a stubbed boto3 client.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (access_key, secret_key, region, client)
        ):
            _singleton = AmazonInspectorEngine(
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                client=client,
            )
        return _singleton


def reset_amazon_inspector_engine() -> None:
    global _singleton
    with _singleton_lock:
        _singleton = None


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

__all__ = [
    "AmazonInspectorEngine",
    "AmazonInspectorUnavailableError",
    "get_amazon_inspector_engine",
    "reset_amazon_inspector_engine",
]
