"""ALDECI Jenkins CI Engine.

Thin pass-through client for the **Jenkins REST API** (the JSON API exposed by
every Jenkins endpoint via the trailing ``/api/json`` suffix), designed for
direct CI introspection from ALDECI personas (DevSecOps engineer, release
manager, build-health auditor, etc.).

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env vars are unset the engine reports ``status="unavailable"`` and
lookup endpoints return HTTP 503.

Environment variables
---------------------
JENKINS_URL    — base Jenkins URL, e.g. ``https://jenkins.example.com``
JENKINS_USER   — Jenkins user name (Basic auth)
JENKINS_TOKEN  — Jenkins API token (Basic auth — see /me/configure)

The engine is a process-level singleton accessible via
:func:`get_jenkins_ci_engine`.

This engine is intentionally minimal — Pydantic models live in the router; the
engine just shapes auth headers and returns parsed JSON / raises HTTP errors.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urljoin

import httpx

logger = logging.getLogger(__name__)

# Endpoints we expose — surfaced via the capability summary GET /
_ENDPOINT_CATALOG: List[str] = [
    "/api/json",
    "/job/{name}/api/json",
    "/queue/api/json",
    "/computer/api/json",
    "/job/{name}/build",
]


class JenkinsCIUnavailable(RuntimeError):
    """Raised when JENKINS_URL / JENKINS_USER / JENKINS_TOKEN are not configured."""


class JenkinsCIHTTPError(RuntimeError):
    """Raised when Jenkins returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (e.g. 401/403/404/409/429 are surfaced verbatim, everything
    else collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class JenkinsCIEngine:
    """Pass-through Jenkins CI client backed by ``httpx.Client``."""

    def __init__(
        self,
        jenkins_url: Optional[str] = None,
        jenkins_user: Optional[str] = None,
        jenkins_token: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._jenkins_url = (
            jenkins_url if jenkins_url is not None else os.environ.get("JENKINS_URL", "")
        ).strip()
        self._jenkins_user = (
            jenkins_user if jenkins_user is not None else os.environ.get("JENKINS_USER", "")
        ).strip()
        self._jenkins_token = (
            jenkins_token if jenkins_token is not None else os.environ.get("JENKINS_TOKEN", "")
        ).strip()
        self._timeout = timeout
        # Allow tests to inject a stub httpx.Client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def jenkins_url_present(self) -> bool:
        return bool(self._jenkins_url)

    @property
    def jenkins_user_present(self) -> bool:
        return bool(self._jenkins_user)

    @property
    def jenkins_token_present(self) -> bool:
        return bool(self._jenkins_token)

    @property
    def configured(self) -> bool:
        return (
            self.jenkins_url_present
            and self.jenkins_user_present
            and self.jenkins_token_present
        )

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Jenkins",
            "endpoints": list(_ENDPOINT_CATALOG),
            "jenkins_url_present": self.jenkins_url_present,
            "jenkins_user_present": self.jenkins_user_present,
            "jenkins_token_present": self.jenkins_token_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise JenkinsCIUnavailable(
                "JENKINS_URL, JENKINS_USER and JENKINS_TOKEN must be set to call Jenkins endpoints"
            )

    def _url(self, path: str) -> str:
        base = self._jenkins_url.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def _auth(self) -> httpx.BasicAuth:
        return httpx.BasicAuth(self._jenkins_user, self._jenkins_token)

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
        expect_201: bool = False,
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
                "jenkins-ci upstream error %s %s: %s", method, path, type(exc).__name__
            )
            raise JenkinsCIHTTPError(
                502, f"Upstream Jenkins request failed: {type(exc).__name__}"
            ) from exc

        if expect_201 and resp.status_code in (200, 201, 202):
            # Jenkins returns 201 with Location header for queued builds; 202 historically
            return {"queued": True, "location": resp.headers.get("Location", "")}

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
        raise JenkinsCIHTTPError(
            resp.status_code, f"Jenkins returned {resp.status_code}", payload
        )

    # ------------------------------------------------------------------ ops

    def root(self) -> Dict[str, Any]:
        """GET /api/json — Jenkins instance root."""
        return self._request("GET", "api/json") or {}

    def get_job(self, name: str) -> Dict[str, Any]:
        """GET /job/{name}/api/json — single job summary."""
        return self._request("GET", f"job/{quote(name, safe='')}/api/json") or {}

    def get_build(self, name: str, build_num: int) -> Dict[str, Any]:
        """GET /job/{name}/{build_num}/api/json — single build summary."""
        return (
            self._request(
                "GET", f"job/{quote(name, safe='')}/{int(build_num)}/api/json"
            )
            or {}
        )

    def get_queue(self) -> Dict[str, Any]:
        """GET /queue/api/json — current queue."""
        return self._request("GET", "queue/api/json") or {"items": []}

    def get_computer(self) -> Dict[str, Any]:
        """GET /computer/api/json — node / executor summary."""
        return self._request("GET", "computer/api/json") or {"computer": []}

    def trigger_build(self, name: str, token: Optional[str] = None) -> Dict[str, Any]:
        """POST /job/{name}/build — trigger a build (201 Created with Location)."""
        params: Dict[str, Any] = {}
        if token:
            params["token"] = token
        return (
            self._request(
                "POST",
                f"job/{quote(name, safe='')}/build",
                params=params or None,
                expect_201=True,
            )
            or {"queued": True, "location": ""}
        )

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

_engine: Optional[JenkinsCIEngine] = None
_engine_lock = Lock()


def get_jenkins_ci_engine() -> JenkinsCIEngine:
    """Return (or create) the process-wide JenkinsCIEngine singleton.

    Picks up ``JENKINS_URL`` / ``JENKINS_USER`` / ``JENKINS_TOKEN`` lazily from
    the environment so tests that monkeypatch env vars before first call get a
    fresh, env-aligned engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = JenkinsCIEngine()
    return _engine


def reset_jenkins_ci_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` call re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
