"""ALDECI CircleCI v2 Engine.

Thin pass-through client for the **CircleCI v2 REST API**, designed for
direct CI introspection from ALDECI personas (DevSecOps engineer, release
manager, build-health auditor, etc.).

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env var is unset the engine reports ``status="unavailable"`` and
lookup endpoints return HTTP 503.

Environment variables
---------------------
CIRCLECI_TOKEN — CircleCI personal API token (sent as ``Circle-Token`` header)

Optional:
CIRCLECI_BASE_URL — override base URL (default ``https://circleci.com``)

The engine is a process-level singleton accessible via
:func:`get_circleci_engine`.

Pydantic models live in the router; the engine just shapes auth headers and
returns parsed JSON / raises HTTP errors.
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
    "/api/v2/project/{slug}/pipeline",
    "/api/v2/pipeline/{id}/workflow",
    "/api/v2/workflow/{id}/job",
    "/api/v2/insights/workflows",
]


class CircleCIUnavailable(RuntimeError):
    """Raised when CIRCLECI_TOKEN is not configured."""


class CircleCIHTTPError(RuntimeError):
    """Raised when CircleCI returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (e.g. 401/403/404/409/422/429 are surfaced verbatim,
    everything else collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class CircleCIEngine:
    """Pass-through CircleCI v2 client backed by ``httpx.Client``."""

    DEFAULT_BASE_URL = "https://circleci.com"

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._token = (
            token if token is not None else os.environ.get("CIRCLECI_TOKEN", "")
        ).strip()
        env_base = os.environ.get("CIRCLECI_BASE_URL", "")
        self._base_url = (
            (base_url if base_url is not None else env_base) or self.DEFAULT_BASE_URL
        ).strip()
        self._timeout = timeout
        # Allow tests to inject a stub httpx.Client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def token_present(self) -> bool:
        return bool(self._token)

    @property
    def configured(self) -> bool:
        return self.token_present

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "CircleCI v2",
            "endpoints": list(_ENDPOINT_CATALOG),
            "token_present": self.token_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise CircleCIUnavailable(
                "CIRCLECI_TOKEN must be set to call CircleCI endpoints"
            )

    def _url(self, path: str) -> str:
        base = self._base_url.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Circle-Token": self._token,
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
            logger.warning(
                "circleci upstream error %s %s: %s", method, path, type(exc).__name__
            )
            raise CircleCIHTTPError(
                502, f"Upstream CircleCI request failed: {type(exc).__name__}"
            ) from exc

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
        raise CircleCIHTTPError(
            resp.status_code, f"CircleCI returned {resp.status_code}", payload
        )

    # ------------------------------------------------------------------ ops

    @staticmethod
    def _quote_slug(slug: str) -> str:
        # Project slug is e.g. "gh/MyOrg/my-repo". Forward slashes are
        # significant — keep them. Encode anything else.
        return quote(slug, safe="/")

    def list_pipelines(
        self,
        project_slug: str,
        *,
        branch: Optional[str] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if branch:
            params["branch"] = branch
        if page_token:
            params["page-token"] = page_token
        return self._request(
            "GET",
            f"api/v2/project/{self._quote_slug(project_slug)}/pipeline",
            params=params or None,
        ) or {"items": [], "next_page_token": None}

    def trigger_pipeline(
        self,
        project_slug: str,
        *,
        branch: Optional[str] = None,
        tag: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {}
        if branch:
            body["branch"] = branch
        if tag:
            body["tag"] = tag
        if parameters:
            body["parameters"] = parameters
        return self._request(
            "POST",
            f"api/v2/project/{self._quote_slug(project_slug)}/pipeline",
            json_body=body or None,
        ) or {}

    def get_pipeline(self, pipeline_id: str) -> Dict[str, Any]:
        return self._request(
            "GET", f"api/v2/pipeline/{quote(pipeline_id, safe='')}"
        ) or {}

    def list_workflows(self, pipeline_id: str) -> Dict[str, Any]:
        return self._request(
            "GET", f"api/v2/pipeline/{quote(pipeline_id, safe='')}/workflow"
        ) or {"items": [], "next_page_token": None}

    def get_workflow(self, workflow_id: str) -> Dict[str, Any]:
        return self._request(
            "GET", f"api/v2/workflow/{quote(workflow_id, safe='')}"
        ) or {}

    def cancel_workflow(self, workflow_id: str) -> Dict[str, Any]:
        return self._request(
            "POST", f"api/v2/workflow/{quote(workflow_id, safe='')}/cancel"
        ) or {"message": "Accepted."}

    def rerun_workflow(
        self,
        workflow_id: str,
        *,
        jobs: Optional[List[str]] = None,
        from_failed: Optional[bool] = None,
        sparse_tree: Optional[bool] = None,
        enable_ssh: Optional[bool] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {}
        if jobs is not None:
            body["jobs"] = jobs
        if from_failed is not None:
            body["from_failed"] = from_failed
        if sparse_tree is not None:
            body["sparse_tree"] = sparse_tree
        if enable_ssh is not None:
            body["enable_ssh"] = enable_ssh
        return self._request(
            "POST",
            f"api/v2/workflow/{quote(workflow_id, safe='')}/rerun",
            json_body=body or None,
        ) or {}

    def list_workflow_jobs(self, workflow_id: str) -> Dict[str, Any]:
        return self._request(
            "GET", f"api/v2/workflow/{quote(workflow_id, safe='')}/job"
        ) or {"items": [], "next_page_token": None}

    def insights_workflows(
        self,
        project_slug: str,
        workflow_name: str,
        *,
        branch: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if branch:
            params["branch"] = branch
        if start_date:
            params["start-date"] = start_date
        if end_date:
            params["end-date"] = end_date
        return self._request(
            "GET",
            f"api/v2/insights/{self._quote_slug(project_slug)}/workflows/"
            f"{quote(workflow_name, safe='')}",
            params=params or None,
        ) or {"items": []}

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

_engine: Optional[CircleCIEngine] = None
_engine_lock = Lock()


def get_circleci_engine() -> CircleCIEngine:
    """Return (or create) the process-wide CircleCIEngine singleton.

    Picks up ``CIRCLECI_TOKEN`` lazily from the environment so tests that
    monkeypatch env vars before first call get a fresh, env-aligned engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = CircleCIEngine()
    return _engine


def reset_circleci_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` call re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
