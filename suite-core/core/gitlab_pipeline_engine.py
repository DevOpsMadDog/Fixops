"""ALDECI GitLab CI/CD Engine.

Thin pass-through client for the **GitLab CI/CD REST API** (the v4 JSON API
exposed under ``/api/v4/projects``), designed for direct CI introspection from
ALDECI personas (DevSecOps engineer, release manager, build-health auditor).

This is a pass-through facade — distinct from the legacy GitLab repository
*connector* (issues/MR/repo sync). It surfaces project + pipeline + job state
under the dedicated router prefix ``/api/v1/gitlab-pipeline`` to avoid any
path collision with that connector.

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env vars are unset the engine reports ``status="unavailable"`` and
lookup endpoints return HTTP 503.

Environment variables
---------------------
GITLAB_URL     — base GitLab URL (default: ``https://gitlab.com``)
GITLAB_TOKEN   — Personal/Project/Group access token used as ``PRIVATE-TOKEN``

The engine is a process-level singleton accessible via
:func:`get_gitlab_pipeline_engine`.

The engine is intentionally minimal — Pydantic validation lives in the router;
the engine just shapes auth headers and returns parsed JSON / raises HTTP errors.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urljoin

import httpx

logger = logging.getLogger(__name__)

# Endpoints surfaced via GET / capability summary
_ENDPOINT_CATALOG: List[str] = [
    "/api/v4/projects",
    "/api/v4/projects/{id}/pipelines",
    "/api/v4/projects/{id}/jobs",
    "/api/v4/projects/{id}/pipelines/{pid}/jobs",
    "/api/v4/projects/{id}/pipeline (POST trigger)",
]


class GitLabPipelineUnavailable(RuntimeError):
    """Raised when GITLAB_URL / GITLAB_TOKEN are not configured."""


class GitLabPipelineHTTPError(RuntimeError):
    """Raised when GitLab returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (401/403/404/409/422/429 are surfaced verbatim, everything
    else collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class GitLabPipelineEngine:
    """Pass-through GitLab CI/CD client backed by ``httpx.Client``."""

    _DEFAULT_URL = "https://gitlab.com"

    def __init__(
        self,
        gitlab_url: Optional[str] = None,
        gitlab_token: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        env_url = os.environ.get("GITLAB_URL", "").strip()
        if gitlab_url is not None:
            self._gitlab_url = gitlab_url.strip()
        elif env_url:
            self._gitlab_url = env_url
        else:
            self._gitlab_url = self._DEFAULT_URL
        # Track whether GITLAB_URL was explicitly supplied (non-default)
        self._gitlab_url_explicit = bool(
            (gitlab_url is not None and gitlab_url.strip()) or env_url
        )
        self._gitlab_token = (
            gitlab_token if gitlab_token is not None else os.environ.get("GITLAB_TOKEN", "")
        ).strip()
        self._timeout = timeout
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def gitlab_url_present(self) -> bool:
        """True when GITLAB_URL is explicitly set (env or ctor)."""
        return self._gitlab_url_explicit

    @property
    def gitlab_token_present(self) -> bool:
        return bool(self._gitlab_token)

    @property
    def configured(self) -> bool:
        # Token is the gating credential — URL has a sensible default
        return self.gitlab_token_present

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "GitLab CI/CD",
            "endpoints": list(_ENDPOINT_CATALOG),
            "gitlab_url_present": self.gitlab_url_present,
            "gitlab_token_present": self.gitlab_token_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise GitLabPipelineUnavailable(
                "GITLAB_TOKEN must be set to call GitLab CI/CD endpoints"
            )

    def _url(self, path: str) -> str:
        base = self._gitlab_url.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "PRIVATE-TOKEN": self._gitlab_token,
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        expect_204: bool = False,
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
            logger.warning(
                "gitlab-pipeline upstream error %s %s: %s", method, path, type(exc).__name__
            )
            raise GitLabPipelineHTTPError(
                502, f"Upstream GitLab request failed: {type(exc).__name__}"
            ) from exc

        if expect_204 and resp.status_code == 204:
            return None

        if 200 <= resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw": resp.text}

        # Non-2xx
        payload: Any
        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text or None
        raise GitLabPipelineHTTPError(
            resp.status_code, f"GitLab returned {resp.status_code}", payload
        )

    # --------------------------------------------------------------- helpers

    @staticmethod
    def _project_id_segment(project_id: Any) -> str:
        """A project id can be numeric OR a URL-encoded path (group/repo)."""
        s = str(project_id)
        if s.isdigit():
            return s
        return quote(s, safe="")

    @staticmethod
    def _strip_none(d: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in d.items() if v is not None}

    # ------------------------------------------------------------------ ops

    # --- projects -----------------------------------------------------------

    def list_projects(
        self,
        *,
        membership: Optional[bool] = True,
        per_page: Optional[int] = 20,
        page: Optional[int] = 1,
        search: Optional[str] = None,
        order_by: Optional[str] = None,
        sort: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params = self._strip_none(
            {
                "membership": str(bool(membership)).lower() if membership is not None else None,
                "per_page": per_page,
                "page": page,
                "search": search,
                "order_by": order_by,
                "sort": sort,
            }
        )
        body = self._request("GET", "api/v4/projects", params=params or None)
        return body if isinstance(body, list) else []

    # --- pipelines ----------------------------------------------------------

    def list_pipelines(
        self,
        project_id: Any,
        *,
        per_page: Optional[int] = 20,
        page: Optional[int] = 1,
        status: Optional[str] = None,
        ref: Optional[str] = None,
        order_by: Optional[str] = None,
        sort: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params = self._strip_none(
            {
                "per_page": per_page,
                "page": page,
                "status": status,
                "ref": ref,
                "order_by": order_by,
                "sort": sort,
            }
        )
        seg = self._project_id_segment(project_id)
        body = self._request("GET", f"api/v4/projects/{seg}/pipelines", params=params or None)
        return body if isinstance(body, list) else []

    def get_pipeline(self, project_id: Any, pipeline_id: int) -> Dict[str, Any]:
        seg = self._project_id_segment(project_id)
        return (
            self._request("GET", f"api/v4/projects/{seg}/pipelines/{int(pipeline_id)}") or {}
        )

    def create_pipeline(
        self,
        project_id: Any,
        *,
        ref: str,
        variables: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        seg = self._project_id_segment(project_id)
        body: Dict[str, Any] = {"ref": ref}
        if variables:
            body["variables"] = variables
        return (
            self._request("POST", f"api/v4/projects/{seg}/pipeline", json_body=body) or {}
        )

    def cancel_pipeline(self, project_id: Any, pipeline_id: int) -> Dict[str, Any]:
        seg = self._project_id_segment(project_id)
        return (
            self._request(
                "POST", f"api/v4/projects/{seg}/pipelines/{int(pipeline_id)}/cancel"
            )
            or {}
        )

    def retry_pipeline(self, project_id: Any, pipeline_id: int) -> Dict[str, Any]:
        seg = self._project_id_segment(project_id)
        return (
            self._request(
                "POST", f"api/v4/projects/{seg}/pipelines/{int(pipeline_id)}/retry"
            )
            or {}
        )

    def delete_pipeline(self, project_id: Any, pipeline_id: int) -> None:
        seg = self._project_id_segment(project_id)
        self._request(
            "DELETE",
            f"api/v4/projects/{seg}/pipelines/{int(pipeline_id)}",
            expect_204=True,
        )

    # --- jobs ---------------------------------------------------------------

    def list_jobs(
        self,
        project_id: Any,
        *,
        per_page: Optional[int] = 20,
        page: Optional[int] = 1,
        scope: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params = self._strip_none(
            {
                "per_page": per_page,
                "page": page,
                "scope": scope,
            }
        )
        seg = self._project_id_segment(project_id)
        body = self._request("GET", f"api/v4/projects/{seg}/jobs", params=params or None)
        return body if isinstance(body, list) else []

    def list_pipeline_jobs(
        self,
        project_id: Any,
        pipeline_id: int,
        *,
        include_retried: Optional[bool] = False,
        per_page: Optional[int] = 20,
    ) -> List[Dict[str, Any]]:
        params = self._strip_none(
            {
                "include_retried": (
                    str(bool(include_retried)).lower() if include_retried is not None else None
                ),
                "per_page": per_page,
            }
        )
        seg = self._project_id_segment(project_id)
        body = self._request(
            "GET",
            f"api/v4/projects/{seg}/pipelines/{int(pipeline_id)}/jobs",
            params=params or None,
        )
        return body if isinstance(body, list) else []

    def get_job(self, project_id: Any, job_id: int) -> Dict[str, Any]:
        seg = self._project_id_segment(project_id)
        return (
            self._request("GET", f"api/v4/projects/{seg}/jobs/{int(job_id)}") or {}
        )

    def retry_job(self, project_id: Any, job_id: int) -> Dict[str, Any]:
        seg = self._project_id_segment(project_id)
        return (
            self._request("POST", f"api/v4/projects/{seg}/jobs/{int(job_id)}/retry")
            or {}
        )

    def cancel_job(self, project_id: Any, job_id: int) -> Dict[str, Any]:
        seg = self._project_id_segment(project_id)
        return (
            self._request("POST", f"api/v4/projects/{seg}/jobs/{int(job_id)}/cancel")
            or {}
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

_engine: Optional[GitLabPipelineEngine] = None
_engine_lock = Lock()


def get_gitlab_pipeline_engine() -> GitLabPipelineEngine:
    """Return (or create) the process-wide GitLabPipelineEngine singleton."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = GitLabPipelineEngine()
    return _engine


def reset_gitlab_pipeline_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
