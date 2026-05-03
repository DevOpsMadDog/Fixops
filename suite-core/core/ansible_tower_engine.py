"""ALDECI Ansible Tower / AWX Engine.

Thin pass-through client for the Ansible Tower (AWX) REST API v2 — designed for
direct automation workflows (inventory introspection, job-template launches,
job-event tailing) from ALDECI personas.

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env vars are unset the engine reports ``status="unavailable"`` and
lookup endpoints respond with HTTP 503.

Environment variables
---------------------
TOWER_HOST          base URL of Tower/AWX, e.g. ``https://tower.example.com``
TOWER_OAUTH_TOKEN   Bearer OAuth2 token (Tower/AWX personal access token)
TOWER_VERIFY_SSL    optional ("0"/"false"/"no" disables TLS verification —
                    Tower lab installs frequently use self-signed certs)

The engine is a process-level singleton accessible via
:func:`get_ansible_tower_engine`.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

_API_PATH = "/api/v2/"

# Endpoints we surface via GET / capability summary
_ENDPOINT_CATALOG: List[str] = [
    "/api/v2/inventories",
    "/api/v2/job_templates",
    "/api/v2/jobs",
    "/api/v2/projects",
    "/api/v2/credentials",
]

_FALSY = {"0", "false", "no", "off", ""}


def _ssl_verify_default() -> bool:
    raw = os.environ.get("TOWER_VERIFY_SSL", "").strip().lower()
    if raw in _FALSY:
        # Default is False — Tower lab installs are commonly self-signed.
        # Operators in production should set TOWER_VERIFY_SSL=1.
        return False
    return raw not in {"0", "false", "no", "off"}


class AnsibleTowerUnavailable(RuntimeError):
    """Raised when TOWER_HOST or TOWER_OAUTH_TOKEN are not configured."""


class AnsibleTowerHTTPError(RuntimeError):
    """Raised when Tower returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (401/403/404/409/422/429 surface verbatim, otherwise 502).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class AnsibleTowerEngine:
    """Pass-through Ansible Tower / AWX client backed by ``httpx.Client``."""

    def __init__(
        self,
        tower_host: Optional[str] = None,
        tower_oauth_token: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: float = 30.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._tower_host = (tower_host if tower_host is not None else os.environ.get("TOWER_HOST", "")).strip()
        self._tower_token = (
            tower_oauth_token if tower_oauth_token is not None else os.environ.get("TOWER_OAUTH_TOKEN", "")
        ).strip()
        self._verify_ssl = verify_ssl if verify_ssl is not None else _ssl_verify_default()
        self._timeout = timeout
        # Allow tests to inject a stub httpx.Client
        self._client = client or httpx.Client(timeout=timeout, verify=self._verify_ssl)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def tower_host_present(self) -> bool:
        return bool(self._tower_host)

    @property
    def tower_oauth_token_present(self) -> bool:
        return bool(self._tower_token)

    @property
    def configured(self) -> bool:
        return self.tower_host_present and self.tower_oauth_token_present

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Ansible Tower/AWX",
            "endpoints": list(_ENDPOINT_CATALOG),
            "tower_host_present": self.tower_host_present,
            "tower_oauth_token_present": self.tower_oauth_token_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise AnsibleTowerUnavailable(
                "TOWER_HOST and TOWER_OAUTH_TOKEN must be set to call Ansible Tower endpoints"
            )

    def _url(self, path: str) -> str:
        base = self._tower_host.rstrip("/") + _API_PATH
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._tower_token}",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        self._require_configured()
        url = self._url(path)
        try:
            resp = self._client.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            logger.warning("ansible-tower upstream error %s %s: %s", method, path, type(exc).__name__)
            raise AnsibleTowerHTTPError(
                502, f"Upstream Tower request failed: {type(exc).__name__}"
            ) from exc

        if 200 <= resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw": resp.text}

        # Non-2xx — surface upstream payload when JSON
        payload: Any
        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text or None
        raise AnsibleTowerHTTPError(
            resp.status_code, f"Tower returned {resp.status_code}", payload
        )

    # ------------------------------------------------------------------ ops

    def list_inventories(
        self,
        page: int = 1,
        page_size: int = 25,
        search: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if search:
            params["search"] = search
        return self._request("GET", "inventories/", params=params) or {}

    def list_job_templates(
        self,
        page: int = 1,
        page_size: int = 25,
        search: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if search:
            params["search"] = search
        return self._request("GET", "job_templates/", params=params) or {}

    def launch_job_template(self, template_id: int, body: Dict[str, Any]) -> Dict[str, Any]:
        # Tower's launch endpoint accepts: extra_vars, limit, job_tags, skip_tags,
        # inventory, credentials, etc. We pass them through after stripping Nones.
        clean = {k: v for k, v in (body or {}).items() if v is not None}
        return self._request(
            "POST", f"job_templates/{int(template_id)}/launch/", json_body=clean
        ) or {}

    def get_job(self, job_id: int) -> Dict[str, Any]:
        return self._request("GET", f"jobs/{int(job_id)}/") or {}

    def list_job_events(
        self,
        job_id: int,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        return self._request(
            "GET", f"jobs/{int(job_id)}/job_events/", params=params
        ) or {}

    def list_projects(
        self,
        page: int = 1,
        page_size: int = 25,
        search: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if search:
            params["search"] = search
        return self._request("GET", "projects/", params=params) or {}

    def list_credentials(
        self,
        page: int = 1,
        page_size: int = 25,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        return self._request("GET", "credentials/", params=params) or {}

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:  # pragma: no cover - defensive
                pass


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[AnsibleTowerEngine] = None
_engine_lock = Lock()


def get_ansible_tower_engine() -> AnsibleTowerEngine:
    """Return (or create) the process-wide AnsibleTowerEngine singleton.

    Picks up env vars lazily so tests that monkeypatch TOWER_HOST /
    TOWER_OAUTH_TOKEN before first call get a fresh, env-aligned engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = AnsibleTowerEngine()
    return _engine


def reset_ansible_tower_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
