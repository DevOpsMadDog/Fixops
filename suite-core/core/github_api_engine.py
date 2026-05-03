"""ALDECI GitHub REST v3 Engine.

Thin pass-through client for the **GitHub REST v3 API**, designed for direct
GitHub introspection from ALDECI personas (DevSecOps engineer, AppSec
auditor, supply-chain owner, repo curator, etc.).

This engine is **distinct from** the existing `github_security`,
`github_app_*`, and `github_issues_integration` modules — those serve
specialised flows (Advanced Security ingestion, GitHub App webhook handler,
issue auto-creation). This engine is a *generic* REST v3 pass-through:
``/user/repos``, ``/repos/{owner}/{repo}``, ``/repos/{owner}/{repo}/pulls``,
``/repos/{owner}/{repo}/security-advisories``,
``/repos/{owner}/{repo}/dependabot/alerts``,
``/repos/{owner}/{repo}/code-scanning/alerts``, ``/search/repositories``,
``/search/code``.

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env var is unset the engine reports ``status="unavailable"`` and
lookup endpoints return HTTP 503.

Environment variables
---------------------
GITHUB_TOKEN — GitHub personal access token (PAT, fine-grained or classic),
                or GitHub App installation token. Sent as
                ``Authorization: Bearer <token>`` header.

Optional:
GITHUB_API_URL — override base URL for GitHub Enterprise Server
                  (default ``https://api.github.com``)

The engine is a process-level singleton accessible via
:func:`get_github_api_engine`.
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
    "/user/repos",
    "/repos/{owner}/{repo}",
    "/repos/{owner}/{repo}/pulls",
    "/repos/{owner}/{repo}/security-advisories",
    "/repos/{owner}/{repo}/dependabot/alerts",
    "/repos/{owner}/{repo}/code-scanning/alerts",
    "/search/repositories",
    "/search/code",
]

# GitHub REST API version pin (per docs.github.com — May 2026 stable)
_GH_API_VERSION = "2022-11-28"


class GitHubAPIUnavailable(RuntimeError):
    """Raised when GITHUB_TOKEN is not configured."""


class GitHubAPIHTTPError(RuntimeError):
    """Raised when GitHub returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (401/403/404/409/422/429 surface verbatim, everything
    else collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class GitHubAPIEngine:
    """Pass-through GitHub REST v3 client backed by ``httpx.Client``."""

    DEFAULT_BASE_URL = "https://api.github.com"

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._token = (
            token if token is not None else os.environ.get("GITHUB_TOKEN", "")
        ).strip()
        env_base = os.environ.get("GITHUB_API_URL", "")
        self._base_url = (
            (base_url if base_url is not None else env_base)
            or self.DEFAULT_BASE_URL
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

    @property
    def base_url(self) -> str:
        return self._base_url

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "GitHub REST v3",
            "endpoints": list(_ENDPOINT_CATALOG),
            "github_token_present": self.token_present,
            "base_url": self._base_url,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise GitHubAPIUnavailable(
                "GITHUB_TOKEN must be set to call GitHub REST v3 endpoints"
            )

    def _url(self, path: str) -> str:
        base = self._base_url.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": _GH_API_VERSION,
            "User-Agent": "ALDECI-FixOps/1.0",
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
                "github upstream error %s %s: %s",
                method,
                path,
                type(exc).__name__,
            )
            raise GitHubAPIHTTPError(
                502, f"Upstream GitHub request failed: {type(exc).__name__}"
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
        raise GitHubAPIHTTPError(
            resp.status_code,
            f"GitHub returned {resp.status_code}",
            payload,
        )

    # ------------------------------------------------------------------ ops

    @staticmethod
    def _seg(value: str) -> str:
        """URL-segment encode (no slash safe)."""
        return quote(value, safe="")

    def list_user_repos(
        self,
        *,
        affiliation: Optional[str] = None,
        visibility: Optional[str] = None,
        sort: Optional[str] = None,
        direction: Optional[str] = None,
        per_page: Optional[int] = None,
        page: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if affiliation:
            params["affiliation"] = affiliation
        if visibility:
            params["visibility"] = visibility
        if sort:
            params["sort"] = sort
        if direction:
            params["direction"] = direction
        if per_page is not None:
            params["per_page"] = per_page
        if page is not None:
            params["page"] = page
        result = self._request("GET", "user/repos", params=params or None)
        if isinstance(result, list):
            return result
        return []

    def get_repo(self, owner: str, repo: str) -> Dict[str, Any]:
        return self._request(
            "GET", f"repos/{self._seg(owner)}/{self._seg(repo)}"
        ) or {}

    def list_pulls(
        self,
        owner: str,
        repo: str,
        *,
        state: Optional[str] = None,
        head: Optional[str] = None,
        base: Optional[str] = None,
        sort: Optional[str] = None,
        direction: Optional[str] = None,
        per_page: Optional[int] = None,
        page: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if state:
            params["state"] = state
        if head:
            params["head"] = head
        if base:
            params["base"] = base
        if sort:
            params["sort"] = sort
        if direction:
            params["direction"] = direction
        if per_page is not None:
            params["per_page"] = per_page
        if page is not None:
            params["page"] = page
        result = self._request(
            "GET",
            f"repos/{self._seg(owner)}/{self._seg(repo)}/pulls",
            params=params or None,
        )
        if isinstance(result, list):
            return result
        return []

    def list_security_advisories(
        self,
        owner: str,
        repo: str,
        *,
        state: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if state:
            params["state"] = state
        result = self._request(
            "GET",
            f"repos/{self._seg(owner)}/{self._seg(repo)}/security-advisories",
            params=params or None,
        )
        if isinstance(result, list):
            return result
        return []

    def list_dependabot_alerts(
        self,
        owner: str,
        repo: str,
        *,
        state: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if state:
            params["state"] = state
        if severity:
            params["severity"] = severity
        result = self._request(
            "GET",
            f"repos/{self._seg(owner)}/{self._seg(repo)}/dependabot/alerts",
            params=params or None,
        )
        if isinstance(result, list):
            return result
        return []

    def list_code_scanning_alerts(
        self,
        owner: str,
        repo: str,
        *,
        state: Optional[str] = None,
        severity: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if state:
            params["state"] = state
        if severity:
            params["severity"] = severity
        if tool_name:
            params["tool_name"] = tool_name
        result = self._request(
            "GET",
            f"repos/{self._seg(owner)}/{self._seg(repo)}/code-scanning/alerts",
            params=params or None,
        )
        if isinstance(result, list):
            return result
        return []

    def search_repositories(
        self,
        q: str,
        *,
        sort: Optional[str] = None,
        order: Optional[str] = None,
        per_page: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"q": q}
        if sort:
            params["sort"] = sort
        if order:
            params["order"] = order
        if per_page is not None:
            params["per_page"] = per_page
        return self._request("GET", "search/repositories", params=params) or {
            "total_count": 0,
            "incomplete_results": False,
            "items": [],
        }

    def search_code(
        self,
        q: str,
        *,
        sort: Optional[str] = None,
        order: Optional[str] = None,
        per_page: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"q": q}
        if sort:
            params["sort"] = sort
        if order:
            params["order"] = order
        if per_page is not None:
            params["per_page"] = per_page
        return self._request("GET", "search/code", params=params) or {
            "total_count": 0,
            "incomplete_results": False,
            "items": [],
        }

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

_engine: Optional[GitHubAPIEngine] = None
_engine_lock = Lock()


def get_github_api_engine() -> GitHubAPIEngine:
    """Return (or create) the process-wide GitHubAPIEngine singleton.

    Picks up ``GITHUB_TOKEN`` / ``GITHUB_API_URL`` lazily from the environment
    so tests that monkeypatch env vars before first call get a fresh,
    env-aligned engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = GitHubAPIEngine()
    return _engine


def reset_github_api_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` call re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
