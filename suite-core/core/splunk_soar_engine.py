"""Splunk SOAR (Phantom) Engine — ALDECI.

Live Splunk SOAR REST client. Token auth via ``ph-auth-token`` header.
NO SQLite cache. NO MOCKS — when env unset, capability_summary returns
``status=unavailable`` and lookup endpoints raise ``RuntimeError``.

Env:
  SPLUNK_SOAR_URL    — base URL, e.g. https://soar.example.com
  SPLUNK_SOAR_TOKEN  — REST API auth token

Compliance: NIST CSF RS.RP, ISO/IEC 27001 A.16.1, SOC 2 CC7.4
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

try:  # pragma: no cover - bus optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover
    _get_tg_bus = None

_logger = logging.getLogger(__name__)


class SplunkSOAREngine:
    """Live Splunk SOAR (Phantom) REST client.

    All endpoints expected by the router map 1:1 onto Splunk SOAR REST
    resources under ``{base_url}/rest/...``. The auth header is
    ``ph-auth-token: {SPLUNK_SOAR_TOKEN}``.
    """

    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        verify_tls: bool = False,
    ) -> None:
        self._base_url = (base_url or os.environ.get("SPLUNK_SOAR_URL", "")).rstrip("/")
        self._token = token or os.environ.get("SPLUNK_SOAR_TOKEN", "")
        self._timeout = timeout
        # Splunk SOAR commonly uses self-signed certs; default to verify=False.
        self._verify_tls = verify_tls
        self._lock = threading.RLock()
        self._client: Optional[httpx.Client] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def base_url_present(self) -> bool:
        return bool(self._base_url)

    @property
    def token_present(self) -> bool:
        return bool(self._token)

    @property
    def configured(self) -> bool:
        return self.base_url_present and self.token_present

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------

    def _client_inst(self) -> httpx.Client:
        if self._client is None:
            with self._lock:
                if self._client is None:
                    self._client = httpx.Client(
                        timeout=self._timeout,
                        verify=self._verify_tls,
                    )
        return self._client

    def _require_configured(self) -> None:
        if not self.configured:
            raise RuntimeError(
                "Splunk SOAR not configured: SPLUNK_SOAR_URL and "
                "SPLUNK_SOAR_TOKEN must be set"
            )

    def _headers(self) -> Dict[str, str]:
        return {
            "ph-auth-token": self._token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._require_configured()
        resp = self._client_inst().get(
            f"{self._base_url}{path}",
            params=params,
            headers=self._headers(),
        )
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError:
            payload = {"data": [], "raw": resp.text}
        if not isinstance(payload, dict):
            payload = {"data": payload}
        self._emit("splunk_soar.get", {"path": path, "params": params or {}})
        return payload

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        self._require_configured()
        resp = self._client_inst().post(
            f"{self._base_url}{path}",
            json=body,
            headers=self._headers(),
        )
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError:
            payload = {"raw": resp.text}
        if not isinstance(payload, dict):
            payload = {"data": payload}
        self._emit("splunk_soar.post", {"path": path})
        return payload

    @staticmethod
    def _emit(event: str, data: Dict[str, Any]) -> None:
        try:
            if _get_tg_bus is not None:
                bus = _get_tg_bus()
                if bus is not None:
                    bus.emit_event(event, data)
        except Exception:  # pragma: no cover
            pass

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------

    def capability_summary(self) -> Dict[str, Any]:
        status = "ok" if self.configured else "unavailable"
        return {
            "service": "Splunk SOAR (Phantom)",
            "endpoints": [
                "/rest/playbook",
                "/rest/container",
                "/rest/playbook_run",
                "/rest/action_run",
                "/rest/asset",
            ],
            "splunk_soar_url_present": self.base_url_present,
            "splunk_soar_token_present": self.token_present,
            "status": status,
        }

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    def list_playbooks(
        self,
        active: Optional[bool] = True,
        page: int = 0,
        page_size: int = 100,
        include_expensive: bool = False,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if active is not None:
            params["_filter_active"] = str(bool(active)).lower()
        if include_expensive:
            params["include_expensive"] = "true"
        return self._get("/rest/playbook", params=params)

    # ------------------------------------------------------------------
    # Containers (incidents)
    # ------------------------------------------------------------------

    def list_containers(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        page: int = 0,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if status:
            params["_filter_status"] = status
        if severity:
            params["_filter_severity"] = severity
        return self._get("/rest/container", params=params)

    def get_container(self, container_id: str) -> Dict[str, Any]:
        return self._get(f"/rest/container/{container_id}")

    # ------------------------------------------------------------------
    # Playbook runs
    # ------------------------------------------------------------------

    def trigger_playbook_run(
        self,
        playbook_id: int,
        container_id: int,
        scope: str = "new",
        run: bool = True,
    ) -> Dict[str, Any]:
        body = {
            "playbook_id": playbook_id,
            "container_id": container_id,
            "scope": scope,
            "run": bool(run),
        }
        return self._post("/rest/playbook_run", body)

    def get_playbook_run(self, run_id: str) -> Dict[str, Any]:
        return self._get(f"/rest/playbook_run/{run_id}")

    # ------------------------------------------------------------------
    # Action runs
    # ------------------------------------------------------------------

    def list_action_runs(
        self,
        status: Optional[str] = None,
        container_id: Optional[int] = None,
        page: int = 0,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if status:
            params["_filter_status"] = status
        if container_id is not None:
            params["_filter_container_id"] = container_id
        return self._get("/rest/action_run", params=params)

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def list_assets(
        self,
        active: Optional[bool] = True,
        page: int = 0,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if active is not None:
            params["_filter_active"] = str(bool(active)).lower()
        return self._get("/rest/asset", params=params)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            if self._client is not None:
                try:
                    self._client.close()
                finally:
                    self._client = None


# ----------------------------------------------------------------------
# Singleton accessor
# ----------------------------------------------------------------------

_singleton_lock = threading.RLock()
_singleton: Optional[SplunkSOAREngine] = None


def get_splunk_soar_engine() -> SplunkSOAREngine:
    """Return process-wide SplunkSOAREngine singleton (reads env)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SplunkSOAREngine()
    return _singleton


def reset_splunk_soar_engine() -> None:
    """Reset singleton (test helper)."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            try:
                _singleton.close()
            except Exception:
                pass
        _singleton = None


__all__ = [
    "SplunkSOAREngine",
    "get_splunk_soar_engine",
    "reset_splunk_soar_engine",
]
