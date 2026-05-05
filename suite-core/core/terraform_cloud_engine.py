"""ALDECI Terraform Cloud engine - REAL httpx only, NO MOCKS, NO CACHE.

Wraps the Terraform Cloud v2 REST API (https://app.terraform.io). Singleton
keyed by env (TFC_TOKEN / TFC_ORG). When credentials are absent the
capability summary returns ``status="unavailable"`` and every lookup
endpoint raises ``TerraformCloudUnavailableError`` which the router
translates to HTTP 503.

NO SQLite cache. NO mock fallback.

Singleton:
    eng = get_terraform_cloud_engine()

Reset (tests):
    reset_terraform_cloud_engine()
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 8.0
DEFAULT_BASE_URL = "https://app.terraform.io"
JSONAPI_CONTENT_TYPE = "application/vnd.api+json"


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


class TerraformCloudUnavailableError(RuntimeError):
    """Raised when Terraform Cloud credentials are unset or the API rejected the call."""


class TerraformCloudEngine:
    """Real httpx-backed Terraform Cloud client.

    All public methods raise ``TerraformCloudUnavailableError`` when
    TFC_TOKEN is not configured. Routers translate this to HTTP 503.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        org: Optional[str] = None,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_token = token
        self._explicit_org = org
        self._explicit_base_url = base_url

        self._client: Optional[httpx.Client] = client
        self._owns_client: bool = client is None
        self._timeout: float = timeout

        self._lock = threading.RLock()

    # ------------------------------------------------------------------ creds

    def _token(self) -> str:
        if self._explicit_token is not None:
            return self._explicit_token.strip()
        return (os.environ.get("TFC_TOKEN") or "").strip()

    def _org(self) -> str:
        if self._explicit_org is not None:
            return self._explicit_org.strip()
        return (os.environ.get("TFC_ORG") or "").strip()

    def _base_url(self) -> str:
        if self._explicit_base_url is not None:
            raw = self._explicit_base_url
        else:
            raw = os.environ.get("TFC_BASE_URL", "")
        url = (raw or "").strip() or DEFAULT_BASE_URL
        return url.rstrip("/")

    def token_present(self) -> bool:
        return bool(self._token())

    def org_present(self) -> bool:
        return bool(self._org())

    def is_configured(self) -> bool:
        return self.token_present()

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise TerraformCloudUnavailableError(
                "TFC_TOKEN not set - set TFC_TOKEN env var to call "
                "Terraform Cloud"
            )

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
            self._owns_client = True
        return self._client

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token()}",
            "Content-Type": JSONAPI_CONTENT_TYPE,
            "Accept": JSONAPI_CONTENT_TYPE,
        }

    # ---------------------------------------------------------------- request

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        expect_status: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        client = self._ensure_client()
        url = f"{self._base_url()}{path}"
        try:
            if method == "GET":
                resp = client.get(url, headers=self._headers(), params=params or None)
            elif method == "POST":
                resp = client.post(
                    url,
                    headers=self._headers(),
                    json=json_body,
                    params=params or None,
                )
            elif method == "DELETE":
                resp = client.delete(url, headers=self._headers(), params=params or None)
            else:
                raise TerraformCloudUnavailableError(
                    f"Unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise TerraformCloudUnavailableError(
                f"Terraform Cloud request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise TerraformCloudUnavailableError(
                f"Terraform Cloud rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise TerraformCloudUnavailableError(
                f"Terraform Cloud returned 404 for {path}"
            )

        accepted = expect_status or [200, 201, 202, 204]
        if resp.status_code not in accepted and resp.status_code >= 400:
            raise TerraformCloudUnavailableError(
                f"Terraform Cloud returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        # 202/204 may be empty
        if resp.status_code in (202, 204):
            text = (getattr(resp, "text", "") or "").strip()
            if not text:
                return {"status": "accepted", "code": resp.status_code}

        try:
            payload = resp.json()
        except ValueError as exc:
            # Empty 200 OK is acceptable too
            text = (getattr(resp, "text", "") or "").strip()
            if not text:
                return {"status": "ok", "code": resp.status_code}
            raise TerraformCloudUnavailableError(
                f"Terraform Cloud returned non-JSON response: {exc}"
            ) from exc
        return payload if isinstance(payload, dict) else {"data": payload}

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "Terraform Cloud",
            "endpoints": [
                "/api/v2/organizations/{org}/workspaces",
                "/api/v2/workspaces/{id}/runs",
                "/api/v2/runs",
                "/api/v2/workspaces/{id}/current-state-version",
                "/api/v2/policies",
                "/api/v2/policy-checks",
            ],
            "tfc_token_present": self.token_present(),
            "tfc_org_present": self.org_present(),
            "status": status,
        }

    # ------------------------------------------------------------- workspaces

    def list_workspaces(
        self,
        org: str,
        page_number: Optional[int] = None,
        page_size: Optional[int] = None,
        search_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not org:
            raise ValueError("org must not be empty")
        params: Dict[str, Any] = {}
        if page_number is not None:
            params["page[number]"] = int(page_number)
        if page_size is not None:
            params["page[size]"] = int(page_size)
        if search_name:
            params["search[name]"] = search_name
        out = self._request(
            "GET",
            f"/api/v2/organizations/{org}/workspaces",
            params=params,
        )
        try:
            count = len(out.get("data") or [])
            _emit_event(
                "terraform_cloud.workspaces_listed",
                {"org": org, "count": count},
            )
        except Exception:  # pragma: no cover
            pass
        return out

    # -------------------------------------------------------------------- runs

    def list_workspace_runs(
        self,
        ws_id: str,
        page_size: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not ws_id:
            raise ValueError("ws_id must not be empty")
        params: Dict[str, Any] = {}
        if page_size is not None:
            params["page[size]"] = int(page_size)
        return self._request(
            "GET",
            f"/api/v2/workspaces/{ws_id}/runs",
            params=params,
        )

    def create_run(self, body: Dict[str, Any]) -> Dict[str, Any]:
        out = self._request(
            "POST",
            "/api/v2/runs",
            json_body=body or {},
            expect_status=[200, 201, 202],
        )
        try:
            data = out.get("data") or {}
            _emit_event(
                "terraform_cloud.run_created",
                {"run_id": data.get("id"), "type": data.get("type")},
            )
        except Exception:  # pragma: no cover
            pass
        return out

    def apply_run(self, run_id: str, comment: Optional[str] = None) -> Dict[str, Any]:
        if not run_id:
            raise ValueError("run_id must not be empty")
        body: Dict[str, Any] = {}
        if comment:
            body = {"comment": comment}
        return self._request(
            "POST",
            f"/api/v2/runs/{run_id}/actions/apply",
            json_body=body or None,
            expect_status=[200, 202],
        )

    def cancel_run(self, run_id: str, comment: Optional[str] = None) -> Dict[str, Any]:
        if not run_id:
            raise ValueError("run_id must not be empty")
        body: Dict[str, Any] = {}
        if comment:
            body = {"comment": comment}
        return self._request(
            "POST",
            f"/api/v2/runs/{run_id}/actions/cancel",
            json_body=body or None,
            expect_status=[200, 202],
        )

    def discard_run(self, run_id: str, comment: Optional[str] = None) -> Dict[str, Any]:
        if not run_id:
            raise ValueError("run_id must not be empty")
        body: Dict[str, Any] = {}
        if comment:
            body = {"comment": comment}
        return self._request(
            "POST",
            f"/api/v2/runs/{run_id}/actions/discard",
            json_body=body or None,
            expect_status=[200, 202],
        )

    # ----------------------------------------------------------- state version

    def current_state_version(self, ws_id: str) -> Dict[str, Any]:
        if not ws_id:
            raise ValueError("ws_id must not be empty")
        return self._request(
            "GET",
            f"/api/v2/workspaces/{ws_id}/current-state-version",
        )

    # -------------------------------------------------------------- policies

    def list_policies(self, org: Optional[str] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        org = org or self._org()
        if org:
            params["filter[organization][name]"] = org
        return self._request(
            "GET",
            "/api/v2/policies",
            params=params,
        )

    # ----------------------------------------------------------------- close

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            try:
                self._client.close()
            except Exception:  # pragma: no cover
                pass


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[TerraformCloudEngine] = None
_singleton_lock = threading.RLock()


def get_terraform_cloud_engine(
    token: Optional[str] = None,
    org: Optional[str] = None,
    base_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    force_refresh: bool = False,
) -> TerraformCloudEngine:
    """Return the process-wide TerraformCloudEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (token, org, base_url, client)
        ):
            if _singleton is not None:
                _singleton.close()
            _singleton = TerraformCloudEngine(
                token=token,
                org=org,
                base_url=base_url,
                client=client,
            )
        return _singleton


def reset_terraform_cloud_engine() -> None:
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

__all__ = [
    "TerraformCloudEngine",
    "TerraformCloudUnavailableError",
    "get_terraform_cloud_engine",
    "reset_terraform_cloud_engine",
]
