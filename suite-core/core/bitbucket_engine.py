"""ALDECI Bitbucket Cloud Engine.

Thin pass-through client for the **Bitbucket Cloud REST API v2.0**, designed
for direct introspection from ALDECI personas (DevSecOps engineer, release
manager, build-health auditor) via the dedicated router prefix
``/api/v1/bitbucket``.

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env vars are unset the engine reports ``status="unavailable"`` and
lookup endpoints return HTTP 503.

Environment variables
---------------------
BITBUCKET_USER         — Bitbucket Cloud username
BITBUCKET_APP_PASSWORD — Bitbucket Cloud app password (HTTP basic auth)

The engine is a process-level singleton accessible via
:func:`get_bitbucket_engine`.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# Endpoints surfaced via GET / capability summary
_ENDPOINT_CATALOG: List[str] = [
    "/2.0/workspaces",
    "/2.0/workspaces/{ws}/repositories",
    "/2.0/repositories/{ws}/{repo}/pipelines",
    "/2.0/repositories/{ws}/{repo}/pullrequests",
    "/2.0/repositories/{ws}/{repo}/branches",
]


class BitbucketUnavailable(RuntimeError):
    """Raised when BITBUCKET_USER / BITBUCKET_APP_PASSWORD are not configured."""


class BitbucketHTTPError(RuntimeError):
    """Raised when Bitbucket returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (400/401/403/404/409/422/429 are surfaced verbatim, everything
    else collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class BitbucketEngine:
    """Pass-through Bitbucket Cloud client backed by ``httpx.Client``."""

    _BASE_URL = "https://api.bitbucket.org"

    def __init__(
        self,
        bitbucket_user: Optional[str] = None,
        bitbucket_app_password: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
        base_url: Optional[str] = None,
    ) -> None:
        self._bitbucket_user = (
            bitbucket_user
            if bitbucket_user is not None
            else os.environ.get("BITBUCKET_USER", "")
        ).strip()
        self._bitbucket_app_password = (
            bitbucket_app_password
            if bitbucket_app_password is not None
            else os.environ.get("BITBUCKET_APP_PASSWORD", "")
        ).strip()
        self._base_url = (base_url or self._BASE_URL).rstrip("/")
        self._timeout = timeout
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def bitbucket_user_present(self) -> bool:
        return bool(self._bitbucket_user)

    @property
    def bitbucket_app_password_present(self) -> bool:
        return bool(self._bitbucket_app_password)

    @property
    def configured(self) -> bool:
        return self.bitbucket_user_present and self.bitbucket_app_password_present

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Bitbucket Cloud",
            "endpoints": list(_ENDPOINT_CATALOG),
            "bitbucket_user_present": self.bitbucket_user_present,
            "bitbucket_app_password_present": self.bitbucket_app_password_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise BitbucketUnavailable(
                "BITBUCKET_USER and BITBUCKET_APP_PASSWORD must be set to call "
                "Bitbucket Cloud endpoints"
            )

    def _url(self, path: str) -> str:
        base = self._base_url.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _auth(self) -> tuple:
        return (self._bitbucket_user, self._bitbucket_app_password)

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
                auth=self._auth(),
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "bitbucket upstream error %s %s: %s", method, path, type(exc).__name__
            )
            raise BitbucketHTTPError(
                502, f"Upstream Bitbucket request failed: {type(exc).__name__}"
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
        raise BitbucketHTTPError(
            resp.status_code, f"Bitbucket returned {resp.status_code}", payload
        )

    # --------------------------------------------------------------- helpers

    @staticmethod
    def _strip_none(d: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in d.items() if v is not None}

    # ------------------------------------------------------------------ ops

    # --- workspaces ---------------------------------------------------------

    def list_workspaces(
        self,
        *,
        pagelen: Optional[int] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        params = self._strip_none({"pagelen": pagelen, "page": page})
        body = self._request("GET", "2.0/workspaces", params=params or None)
        return body if isinstance(body, dict) else {}

    # --- repositories -------------------------------------------------------

    def list_repositories(
        self,
        workspace: str,
        *,
        role: Optional[str] = None,
        q: Optional[str] = None,
        sort: Optional[str] = None,
        pagelen: Optional[int] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        params = self._strip_none(
            {
                "role": role,
                "q": q,
                "sort": sort,
                "pagelen": pagelen,
                "page": page,
            }
        )
        body = self._request(
            "GET",
            f"2.0/workspaces/{workspace}/repositories",
            params=params or None,
        )
        return body if isinstance(body, dict) else {}

    # --- pipelines ----------------------------------------------------------

    def list_pipelines(
        self,
        workspace: str,
        repo_slug: str,
        *,
        sort: Optional[str] = None,
        pagelen: Optional[int] = None,
        page: Optional[int] = None,
        q: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._strip_none(
            {"sort": sort, "pagelen": pagelen, "page": page, "q": q}
        )
        body = self._request(
            "GET",
            f"2.0/repositories/{workspace}/{repo_slug}/pipelines",
            params=params or None,
        )
        return body if isinstance(body, dict) else {}

    def trigger_pipeline(
        self,
        workspace: str,
        repo_slug: str,
        *,
        target: Dict[str, Any],
        variables: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"target": target}
        if variables:
            body["variables"] = variables
        return (
            self._request(
                "POST",
                f"2.0/repositories/{workspace}/{repo_slug}/pipelines",
                json_body=body,
            )
            or {}
        )

    def stop_pipeline(
        self,
        workspace: str,
        repo_slug: str,
        pipeline_uuid: str,
    ) -> None:
        self._request(
            "POST",
            f"2.0/repositories/{workspace}/{repo_slug}/pipelines/{pipeline_uuid}/stopPipeline",
            expect_204=True,
        )

    def list_pipeline_steps(
        self,
        workspace: str,
        repo_slug: str,
        pipeline_uuid: str,
    ) -> Dict[str, Any]:
        body = self._request(
            "GET",
            f"2.0/repositories/{workspace}/{repo_slug}/pipelines/{pipeline_uuid}/steps",
        )
        return body if isinstance(body, dict) else {}

    # --- pull requests ------------------------------------------------------

    def list_pull_requests(
        self,
        workspace: str,
        repo_slug: str,
        *,
        state: Optional[str] = None,
        pagelen: Optional[int] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        params = self._strip_none(
            {"state": state, "pagelen": pagelen, "page": page}
        )
        body = self._request(
            "GET",
            f"2.0/repositories/{workspace}/{repo_slug}/pullrequests",
            params=params or None,
        )
        return body if isinstance(body, dict) else {}

    # --- branches -----------------------------------------------------------

    def list_branches(
        self,
        workspace: str,
        repo_slug: str,
        *,
        pagelen: Optional[int] = None,
    ) -> Dict[str, Any]:
        params = self._strip_none({"pagelen": pagelen})
        body = self._request(
            "GET",
            f"2.0/repositories/{workspace}/{repo_slug}/refs/branches",
            params=params or None,
        )
        return body if isinstance(body, dict) else {}

    # --- commit statuses ----------------------------------------------------

    def list_commit_statuses(
        self,
        workspace: str,
        repo_slug: str,
        commit_sha: str,
    ) -> Dict[str, Any]:
        body = self._request(
            "GET",
            f"2.0/repositories/{workspace}/{repo_slug}/commit/{commit_sha}/statuses",
        )
        return body if isinstance(body, dict) else {}

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

_engine: Optional[BitbucketEngine] = None
_engine_lock = Lock()


def get_bitbucket_engine() -> BitbucketEngine:
    """Return (or create) the process-wide BitbucketEngine singleton."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = BitbucketEngine()
    return _engine


def reset_bitbucket_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
