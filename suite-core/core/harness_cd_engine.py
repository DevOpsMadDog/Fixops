"""Harness CD Platform Engine — ALDECI.

Wraps the Harness CD (NextGen) REST surface and exposes a process-wide
singleton.  Configuration is purely env-driven:

  HARNESS_API_KEY      Personal Access Token (sent as ``x-api-key`` header)
  HARNESS_ACCOUNT_ID   Harness account identifier (URL discriminator)
  HARNESS_BASE_URL     Optional; defaults to ``https://app.harness.io``

NO MOCKS rule
-------------
When ``HARNESS_API_KEY`` and/or ``HARNESS_ACCOUNT_ID`` are unset the engine
is still constructible (capability summary still renders) but every live
Harness call raises ``HarnessUnavailableError`` which the router translates
to HTTP 503 with status="unavailable".  No SQLite cache, no fabricated
data.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://app.harness.io"
DEFAULT_TIMEOUT_SECONDS = 8.0


class HarnessUnavailableError(RuntimeError):
    """Raised when Harness credentials are absent or upstream is unrecoverable."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class HarnessCDEngine:
    """Thread-safe Harness CD client with no SQLite cache."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        account_id: Optional[str] = None,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_api_key = api_key
        self._explicit_account_id = account_id
        self._explicit_base_url = base_url
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- env

    def api_key(self) -> Optional[str]:
        v = self._explicit_api_key or os.environ.get("HARNESS_API_KEY")
        return v.strip() if v else None

    def account_id(self) -> Optional[str]:
        v = self._explicit_account_id or os.environ.get("HARNESS_ACCOUNT_ID")
        return v.strip() if v else None

    def base_url(self) -> str:
        v = (
            self._explicit_base_url
            or os.environ.get("HARNESS_BASE_URL")
            or DEFAULT_BASE_URL
        )
        return v.rstrip("/")

    def api_key_present(self) -> bool:
        return bool(self.api_key())

    def account_id_present(self) -> bool:
        return bool(self.account_id())

    # ------------------------------------------------------------ helpers

    def _ensure_available(self) -> None:
        if not self.api_key_present():
            raise HarnessUnavailableError(
                "HARNESS_API_KEY unset — configure a Harness PAT to enable "
                "Harness CD."
            )
        if not self.account_id_present():
            raise HarnessUnavailableError(
                "HARNESS_ACCOUNT_ID unset — configure the Harness account "
                "identifier to enable Harness CD."
            )

    def _headers(self) -> Dict[str, str]:
        return {
            "x-api-key": self.api_key() or "",
            "Content-Type": "application/json",
        }

    # -------------------------------------------------------------- HTTP

    def _http_get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = f"{self.base_url()}{path}"
        try:
            resp = self._client.get(
                url, params=params or {}, headers=self._headers()
            )
        except httpx.HTTPError as exc:
            raise HarnessUnavailableError(
                f"Harness GET {path} transport failure: {exc}"
            ) from exc
        return self._handle_response(path, resp)

    def _http_post(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Any] = None,
        content_type: str = "application/json",
    ) -> Dict[str, Any]:
        url = f"{self.base_url()}{path}"
        headers = self._headers()
        headers["Content-Type"] = content_type
        try:
            if content_type == "application/json":
                resp = self._client.post(
                    url, params=params or {}, json=body, headers=headers
                )
            else:
                # YAML / raw content (e.g. pipeline runtime variables YAML)
                resp = self._client.post(
                    url,
                    params=params or {},
                    content=body if isinstance(body, (str, bytes)) else str(body or ""),
                    headers=headers,
                )
        except httpx.HTTPError as exc:
            raise HarnessUnavailableError(
                f"Harness POST {path} transport failure: {exc}"
            ) from exc
        return self._handle_response(path, resp)

    def _handle_response(self, path: str, resp: Any) -> Dict[str, Any]:
        status = getattr(resp, "status_code", 0)
        if status == 401:
            raise HarnessUnavailableError(
                f"Harness rejected credentials (401) at {path}."
            )
        if status == 403:
            raise HarnessUnavailableError(
                f"Harness permission denied (403) at {path} — check PAT scopes."
            )
        if status >= 400:
            text = getattr(resp, "text", "")
            raise HarnessUnavailableError(
                f"Harness {path} returned {status}: {text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:
            raise HarnessUnavailableError(
                f"Harness {path} returned non-JSON payload: {exc}"
            ) from exc

    # -------------------------------------------------------- public API

    def list_pipelines(
        self,
        account_identifier: Optional[str] = None,
        project_identifier: Optional[str] = None,
        org_identifier: Optional[str] = None,
        size: Optional[int] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project_identifier:
            raise ValueError("projectIdentifier is required.")
        if not org_identifier:
            raise ValueError("orgIdentifier is required.")
        params: Dict[str, Any] = {
            "accountIdentifier": account_identifier or self.account_id(),
            "projectIdentifier": project_identifier,
            "orgIdentifier": org_identifier,
        }
        if size is not None:
            params["size"] = int(size)
        if page is not None:
            params["page"] = int(page)
        body = self._http_get("/pipeline/api/pipelines", params=params)
        return body

    def execute_pipeline(
        self,
        pipeline_id: str,
        account_identifier: Optional[str] = None,
        project_identifier: Optional[str] = None,
        org_identifier: Optional[str] = None,
        runtime_yaml: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not pipeline_id:
            raise ValueError("pipeline_id is required.")
        if not project_identifier:
            raise ValueError("projectIdentifier is required.")
        if not org_identifier:
            raise ValueError("orgIdentifier is required.")
        params: Dict[str, Any] = {
            "accountIdentifier": account_identifier or self.account_id(),
            "projectIdentifier": project_identifier,
            "orgIdentifier": org_identifier,
        }
        path = f"/pipeline/api/pipelines/execute/{pipeline_id}"
        return self._http_post(
            path,
            params=params,
            body=runtime_yaml or "",
            content_type="application/yaml",
        )

    def get_execution(
        self,
        exec_id: str,
        account_identifier: Optional[str] = None,
        project_identifier: Optional[str] = None,
        org_identifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not exec_id:
            raise ValueError("exec_id is required.")
        params: Dict[str, Any] = {
            "accountIdentifier": account_identifier or self.account_id(),
        }
        if project_identifier:
            params["projectIdentifier"] = project_identifier
        if org_identifier:
            params["orgIdentifier"] = org_identifier
        path = f"/pipeline/api/pipelines/execution/{exec_id}"
        return self._http_get(path, params=params)

    def list_services(
        self,
        account_identifier: Optional[str] = None,
        project_identifier: Optional[str] = None,
        org_identifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project_identifier:
            raise ValueError("projectIdentifier is required.")
        if not org_identifier:
            raise ValueError("orgIdentifier is required.")
        params = {
            "accountIdentifier": account_identifier or self.account_id(),
            "orgIdentifier": org_identifier,
            "projectIdentifier": project_identifier,
        }
        return self._http_get("/ng/api/services", params=params)

    def list_environments(
        self,
        account_identifier: Optional[str] = None,
        project_identifier: Optional[str] = None,
        org_identifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project_identifier:
            raise ValueError("projectIdentifier is required.")
        if not org_identifier:
            raise ValueError("orgIdentifier is required.")
        params = {
            "accountIdentifier": account_identifier or self.account_id(),
            "orgIdentifier": org_identifier,
            "projectIdentifier": project_identifier,
        }
        return self._http_get("/ng/api/environments", params=params)

    def create_connector(
        self,
        connector: Dict[str, Any],
        account_identifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not connector:
            raise ValueError("connector body is required.")
        params = {"accountIdentifier": account_identifier or self.account_id()}
        return self._http_post(
            "/ng/api/connectors", params=params, body=connector
        )

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_engine_lock = threading.Lock()
_engine_instance: Optional[HarnessCDEngine] = None


def get_harness_cd_engine(
    api_key: Optional[str] = None,
    account_id: Optional[str] = None,
    base_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> HarnessCDEngine:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = HarnessCDEngine(
                api_key=api_key,
                account_id=account_id,
                base_url=base_url,
                client=client,
                timeout=timeout,
            )
        return _engine_instance


def reset_harness_cd_engine() -> None:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is not None:
            _engine_instance.close()
        _engine_instance = None
