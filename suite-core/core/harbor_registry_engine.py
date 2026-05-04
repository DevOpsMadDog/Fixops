"""ALDECI Harbor Container Registry Engine.

Thin pass-through client for the **Harbor v2.0 REST API** — image-vuln scanning,
project/repo/artifact catalog, scanner registry. Designed for direct registry
introspection from ALDECI personas (DevSecOps, container-platform owner,
supply-chain auditor, image-promotion gatekeeper).

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env vars are unset the engine reports ``status="unavailable"`` and
lookup endpoints return HTTP 503.

Environment variables
---------------------
HARBOR_URL       — base Harbor URL, e.g. ``https://harbor.example.com``
HARBOR_USERNAME  — Harbor user name (HTTP Basic auth)
HARBOR_PASSWORD  — Harbor password / robot token (HTTP Basic auth)

The engine is a process-level singleton accessible via
:func:`get_harbor_registry_engine`.

This engine is intentionally minimal — Pydantic models live in the router; the
engine just shapes auth headers, forwards query params, and returns parsed JSON
or raises HTTP errors.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urljoin

import httpx

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

logger = logging.getLogger(__name__)

# Endpoints we expose — surfaced via the capability summary GET /
_ENDPOINT_CATALOG: List[str] = [
    "/api/v2.0/projects",
    "/api/v2.0/projects/{name}/repositories",
    "/api/v2.0/projects/{name}/repositories/{repo}/artifacts",
    "/api/v2.0/scanners",
    "/api/v2.0/health",
]


class HarborRegistryUnavailable(RuntimeError):
    """Raised when HARBOR_URL / HARBOR_USERNAME / HARBOR_PASSWORD are not configured."""


class HarborRegistryHTTPError(RuntimeError):
    """Raised when Harbor returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (e.g. 401/403/404/409/422/429 surfaced verbatim, everything
    else collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class HarborRegistryEngine:
    """Pass-through Harbor v2.0 client backed by ``httpx.Client``."""

    def __init__(
        self,
        harbor_url: Optional[str] = None,
        harbor_username: Optional[str] = None,
        harbor_password: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._harbor_url = (
            harbor_url if harbor_url is not None else os.environ.get("HARBOR_URL", "")
        ).strip()
        self._harbor_username = (
            harbor_username
            if harbor_username is not None
            else os.environ.get("HARBOR_USERNAME", "")
        ).strip()
        self._harbor_password = (
            harbor_password
            if harbor_password is not None
            else os.environ.get("HARBOR_PASSWORD", "")
        ).strip()
        self._timeout = timeout
        # Allow tests to inject a stub httpx.Client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def harbor_url_present(self) -> bool:
        return bool(self._harbor_url)

    @property
    def harbor_username_present(self) -> bool:
        return bool(self._harbor_username)

    @property
    def harbor_password_present(self) -> bool:
        return bool(self._harbor_password)

    @property
    def configured(self) -> bool:
        return (
            self.harbor_url_present
            and self.harbor_username_present
            and self.harbor_password_present
        )

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Harbor",
            "endpoints": list(_ENDPOINT_CATALOG),
            "harbor_url_present": self.harbor_url_present,
            "harbor_username_present": self.harbor_username_present,
            "harbor_password_present": self.harbor_password_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise HarborRegistryUnavailable(
                "HARBOR_URL, HARBOR_USERNAME and HARBOR_PASSWORD must be set "
                "to call Harbor endpoints"
            )

    def _url(self, path: str) -> str:
        base = self._harbor_url.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def _auth(self) -> httpx.BasicAuth:
        return httpx.BasicAuth(self._harbor_username, self._harbor_password)

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        expect_202: bool = False,
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
                auth=self._auth(),
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "harbor upstream error %s %s: %s", method, path, type(exc).__name__
            )
            raise HarborRegistryHTTPError(
                502, f"Upstream Harbor request failed: {type(exc).__name__}"
            ) from exc

        if expect_202 and resp.status_code in (200, 201, 202, 204):
            return {"accepted": True, "status_code": resp.status_code}

        if 200 <= resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw": resp.text}

        # Non-2xx: surface upstream payload when it's JSON
        payload: Any
        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text or None
        raise HarborRegistryHTTPError(
            resp.status_code, f"Harbor returned {resp.status_code}", payload
        )

    # ------------------------------------------------------------------ ops

    def health(self) -> Dict[str, Any]:
        """GET /api/v2.0/health — overall + per-component health."""
        return self._request("GET", "api/v2.0/health") or {
            "status": "unhealthy",
            "components": [],
        }

    def list_projects(
        self,
        *,
        page: int = 1,
        page_size: int = 10,
        name: Optional[str] = None,
        owner: Optional[str] = None,
        public: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if name:
            params["name"] = name
        if owner:
            params["owner"] = owner
        if public is not None:
            params["public"] = "true" if public else "false"
        body = self._request("GET", "api/v2.0/projects", params=params) or []
        return body if isinstance(body, list) else []

    def list_repositories(
        self,
        project_name: str,
        *,
        page: int = 1,
        page_size: int = 10,
        q: Optional[str] = None,
        sort: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if q:
            params["q"] = q
        if sort:
            params["sort"] = sort
        body = (
            self._request(
                "GET",
                f"api/v2.0/projects/{quote(project_name, safe='')}/repositories",
                params=params,
            )
            or []
        )
        return body if isinstance(body, list) else []

    def list_artifacts(
        self,
        project_name: str,
        repository_name: str,
        *,
        page: int = 1,
        page_size: int = 10,
        q: Optional[str] = None,
        sort: Optional[str] = None,
        with_tag: Optional[bool] = None,
        with_scan_overview: Optional[bool] = None,
        with_signature: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if q:
            params["q"] = q
        if sort:
            params["sort"] = sort
        if with_tag is not None:
            params["with_tag"] = "true" if with_tag else "false"
        if with_scan_overview is not None:
            params["with_scan_overview"] = "true" if with_scan_overview else "false"
        if with_signature is not None:
            params["with_signature"] = "true" if with_signature else "false"
        # Harbor URL-encodes "/" inside repository names as %2F
        repo_encoded = quote(repository_name, safe="")
        body = (
            self._request(
                "GET",
                f"api/v2.0/projects/{quote(project_name, safe='')}/repositories/"
                f"{repo_encoded}/artifacts",
                params=params,
            )
            or []
        )
        return body if isinstance(body, list) else []

    def get_artifact_vulnerabilities(
        self,
        project_name: str,
        repository_name: str,
        digest: str,
    ) -> Dict[str, Any]:
        repo_encoded = quote(repository_name, safe="")
        return (
            self._request(
                "GET",
                f"api/v2.0/projects/{quote(project_name, safe='')}/repositories/"
                f"{repo_encoded}/artifacts/{quote(digest, safe=':')}/additions/vulnerabilities",
            )
            or {}
        )

    def trigger_scan(
        self,
        project_name: str,
        repository_name: str,
        digest: str,
    ) -> Dict[str, Any]:
        repo_encoded = quote(repository_name, safe="")
        result = self._request(
            "POST",
            f"api/v2.0/projects/{quote(project_name, safe='')}/repositories/"
            f"{repo_encoded}/artifacts/{quote(digest, safe=':')}/scan",
            expect_202=True,
        ) or {"accepted": True, "status_code": 202}
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "scan.completed",
                        {
                            "entity_id": digest,
                            "type": "harbor_container_scan",
                            "severity": "unknown",
                            "source_engine": "harbor_registry",
                            "project": project_name,
                            "repository": repository_name,
                        },
                    )
            except Exception:
                pass
        return result

    def delete_artifact(
        self,
        project_name: str,
        repository_name: str,
        digest: str,
    ) -> Dict[str, Any]:
        repo_encoded = quote(repository_name, safe="")
        self._request(
            "DELETE",
            f"api/v2.0/projects/{quote(project_name, safe='')}/repositories/"
            f"{repo_encoded}/artifacts/{quote(digest, safe=':')}",
        )
        return {"deleted": True}

    def list_scanners(
        self,
        *,
        page: int = 1,
        page_size: int = 10,
        q: Optional[str] = None,
        sort: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if q:
            params["q"] = q
        if sort:
            params["sort"] = sort
        body = self._request("GET", "api/v2.0/scanners", params=params) or []
        return body if isinstance(body, list) else []

    def set_project_scanner(
        self,
        project_name: str,
        scanner_id: str,
    ) -> Dict[str, Any]:
        self._request(
            "POST",
            f"api/v2.0/projects/{quote(project_name, safe='')}/scanner",
            json_body={"scanner_id": scanner_id},
        )
        return {"updated": True, "scanner_id": scanner_id}

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

_engine: Optional[HarborRegistryEngine] = None
_engine_lock = Lock()


def get_harbor_registry_engine() -> HarborRegistryEngine:
    """Return (or create) the process-wide HarborRegistryEngine singleton.

    Picks up ``HARBOR_URL`` / ``HARBOR_USERNAME`` / ``HARBOR_PASSWORD`` lazily
    from the environment so tests that monkeypatch env vars before first call
    get a fresh, env-aligned engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = HarborRegistryEngine()
    return _engine


def reset_harbor_registry_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` call re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
