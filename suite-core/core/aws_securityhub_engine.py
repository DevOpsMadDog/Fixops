"""ALDECI AWS Security Hub engine — REAL boto3 only, NO MOCKS.

Wraps the AWS Security Hub API via boto3 (preferred) with a pure-httpx
fallback path *not* implemented here — boto3 ships with botocore SigV4 so
the dependency is already vendored in `requirements.txt` (boto3==1.40.61).

Capability summary returns ``status="unavailable"`` and lookup endpoints
raise ``AWSSecurityHubUnavailableError`` (HTTP 503 at the router) when
``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` are not configured.

NO SQLite cache. NO mock data.

Singleton:
    eng = get_aws_securityhub_engine()

Reset (tests):
    reset_aws_securityhub_engine()
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


class AWSSecurityHubUnavailableError(RuntimeError):
    """Raised when AWS Security Hub cannot be reached or is misconfigured."""


class AWSSecurityHubEngine:
    """Real boto3-backed AWS Security Hub client.

    All public methods raise ``AWSSecurityHubUnavailableError`` when the
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
            raise AWSSecurityHubUnavailableError(
                "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set — "
                "set both env vars to call AWS Security Hub"
            )

    def _ensure_client(self) -> Any:
        """Lazily build a boto3 securityhub client. Raises on failure."""
        if self._client is not None:
            return self._client

        self._require_configured()

        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover - boto3 is in requirements
            raise AWSSecurityHubUnavailableError(
                "boto3 is not installed — pip install boto3"
            ) from exc

        try:
            self._client = boto3.client(
                "securityhub",
                region_name=self._region,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )
        except Exception as exc:  # noqa: BLE001
            raise AWSSecurityHubUnavailableError(
                f"Failed to build boto3 securityhub client: {exc}"
            ) from exc
        return self._client

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Return capability metadata for the GET / endpoint."""
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "AWS Security Hub",
            "endpoints": [
                "/findings",
                "/insights",
                "/standards",
                "/enabled-products",
                "/control-status",
            ],
            "aws_access_key_present": bool(self._access_key),
            "aws_region": self._region,
            "status": status,
        }

    # ----------------------------------------------------------------- findings

    def get_findings(
        self,
        filters: Optional[Dict[str, Any]] = None,
        next_token: Optional[str] = None,
        max_results: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Call the Security Hub GetFindings API once and return the raw page.

        Pagination is *not* aggregated here — the caller drives NextToken so
        the router can pass a single page back through to the UI.
        """
        client = self._ensure_client()
        kwargs: Dict[str, Any] = {}
        if filters:
            kwargs["Filters"] = filters
        if next_token:
            kwargs["NextToken"] = next_token
        if max_results is not None:
            kwargs["MaxResults"] = int(max_results)
        try:
            resp = client.get_findings(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise AWSSecurityHubUnavailableError(
                f"AWS Security Hub get_findings failed: {exc}"
            ) from exc
        out: Dict[str, Any] = {
            "Findings": list(resp.get("Findings", [])),
        }
        nt = resp.get("NextToken")
        if nt:
            out["NextToken"] = nt
        try:
            _emit_event(
                "aws_securityhub.findings_page",
                {
                    "count": len(out["Findings"]),
                    "region": self._region,
                    "next_token_present": bool(nt),
                },
            )
        except Exception:  # pragma: no cover
            pass
        return out

    def batch_get_findings(
        self, finding_identifiers: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Lookup specific findings by (Id, ProductArn) tuples."""
        client = self._ensure_client()
        if not finding_identifiers:
            return {"Findings": []}
        try:
            # ``GetFindings`` with an Id filter is the supported way to look
            # up by identifier — boto3 has no batch_get_findings call. We
            # build a Filters dict with Id == each provided value.
            ids = [
                {"Value": ident.get("Id", ""), "Comparison": "EQUALS"}
                for ident in finding_identifiers
                if ident.get("Id")
            ]
            if not ids:
                return {"Findings": []}
            resp = client.get_findings(Filters={"Id": ids})
        except Exception as exc:  # noqa: BLE001
            raise AWSSecurityHubUnavailableError(
                f"AWS Security Hub batch get_findings failed: {exc}"
            ) from exc
        return {"Findings": list(resp.get("Findings", []))}

    # ----------------------------------------------------------------- insights

    def get_insights(self) -> Dict[str, Any]:
        """Return the (paginated) list of Security Hub insights."""
        client = self._ensure_client()
        try:
            resp = client.get_insights()
        except Exception as exc:  # noqa: BLE001
            raise AWSSecurityHubUnavailableError(
                f"AWS Security Hub get_insights failed: {exc}"
            ) from exc
        return {"Insights": list(resp.get("Insights", []))}

    # ---------------------------------------------------------------- standards

    def get_standards(self) -> Dict[str, Any]:
        """Return the catalog of Security Hub standards (DescribeStandards)."""
        client = self._ensure_client()
        try:
            resp = client.describe_standards()
        except Exception as exc:  # noqa: BLE001
            raise AWSSecurityHubUnavailableError(
                f"AWS Security Hub describe_standards failed: {exc}"
            ) from exc
        return {"Standards": list(resp.get("Standards", []))}

    # --------------------------------------------------------- enabled products

    def list_enabled_products(self) -> Dict[str, Any]:
        """Return the list of enabled product subscriptions ARNs."""
        client = self._ensure_client()
        try:
            resp = client.list_enabled_products_for_import()
        except Exception as exc:  # noqa: BLE001
            raise AWSSecurityHubUnavailableError(
                f"AWS Security Hub list_enabled_products failed: {exc}"
            ) from exc
        return {
            "ProductSubscriptions": list(resp.get("ProductSubscriptions", [])),
        }

    # ------------------------------------------------------------ control status

    def get_control_status(self) -> Dict[str, Any]:
        """Return control status across enabled standards."""
        client = self._ensure_client()
        try:
            resp = client.get_enabled_standards()
        except Exception as exc:  # noqa: BLE001
            raise AWSSecurityHubUnavailableError(
                f"AWS Security Hub get_enabled_standards failed: {exc}"
            ) from exc
        return {
            "StandardsSubscriptions": list(resp.get("StandardsSubscriptions", [])),
        }


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[AWSSecurityHubEngine] = None
_singleton_lock = threading.RLock()


def get_aws_securityhub_engine(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: Optional[str] = None,
    client: Any = None,
    force_refresh: bool = False,
) -> AWSSecurityHubEngine:
    """Return the process-wide AWSSecurityHubEngine singleton.

    Tests may pass ``force_refresh=True`` (or call
    ``reset_aws_securityhub_engine()``) to bind a stubbed boto3 client.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (access_key, secret_key, region, client)
        ):
            _singleton = AWSSecurityHubEngine(
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                client=client,
            )
        return _singleton


def reset_aws_securityhub_engine() -> None:
    global _singleton
    with _singleton_lock:
        _singleton = None


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

__all__ = [
    "AWSSecurityHubEngine",
    "AWSSecurityHubUnavailableError",
    "get_aws_securityhub_engine",
    "reset_aws_securityhub_engine",
]
