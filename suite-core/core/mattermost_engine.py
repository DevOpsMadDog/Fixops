"""ALDECI Mattermost Engine.

Thin pass-through client for the **Mattermost REST API v4**, exposing the
endpoints needed for posts, users, teams, channels, and file attachments.

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env vars are unset the engine reports ``status="unavailable"`` and
lookup endpoints return HTTP 503.

Environment variables
---------------------
MATTERMOST_URL    — base Mattermost URL, e.g. ``https://mm.example.com``
MATTERMOST_TOKEN  — bot/personal access token (sent as ``Bearer <token>``)

The engine is a process-level singleton accessible via
:func:`get_mattermost_engine`.

This engine is intentionally minimal — Pydantic models live in the router; the
engine just shapes auth headers, forwards JSON / multipart, and returns parsed
JSON or raises HTTP errors that the router maps to FastAPI ``HTTPException``.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

_API_PATH = "/api/v4/"

# Endpoints we expose — surfaced via the capability summary GET /
_ENDPOINT_CATALOG: List[str] = [
    "/api/v4/posts",
    "/api/v4/users",
    "/api/v4/teams",
    "/api/v4/channels",
    "/api/v4/files",
]


class MattermostUnavailable(RuntimeError):
    """Raised when MATTERMOST_URL or MATTERMOST_TOKEN are not configured."""


class MattermostHTTPError(RuntimeError):
    """Raised when Mattermost returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (401/403/404/409/422/429 are surfaced verbatim, everything
    else collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class MattermostEngine:
    """Pass-through Mattermost client backed by ``httpx.Client``."""

    def __init__(
        self,
        mattermost_url: Optional[str] = None,
        mattermost_token: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._url = (
            mattermost_url if mattermost_url is not None else os.environ.get("MATTERMOST_URL", "")
        ).strip()
        self._token = (
            mattermost_token if mattermost_token is not None else os.environ.get("MATTERMOST_TOKEN", "")
        ).strip()
        self._timeout = timeout
        # Allow tests to inject a stub httpx.Client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def mattermost_url_present(self) -> bool:
        return bool(self._url)

    @property
    def mattermost_token_present(self) -> bool:
        return bool(self._token)

    @property
    def configured(self) -> bool:
        return self.mattermost_url_present and self.mattermost_token_present

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Mattermost",
            "endpoints": list(_ENDPOINT_CATALOG),
            "mattermost_url_present": self.mattermost_url_present,
            "mattermost_token_present": self.mattermost_token_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise MattermostUnavailable(
                "MATTERMOST_URL and MATTERMOST_TOKEN must be set to call Mattermost endpoints"
            )

    def _build_url(self, path: str) -> str:
        base = self._url.rstrip("/") + _API_PATH
        return urljoin(base, path.lstrip("/"))

    def _headers(self, *, json_content: bool = True) -> Dict[str, str]:
        h: Dict[str, str] = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._token}",
        }
        if json_content:
            h["Content-Type"] = "application/json"
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        files: Optional[List[Tuple[str, Tuple[str, bytes, str]]]] = None,
        data: Optional[Dict[str, Any]] = None,
        expect_no_content: bool = False,
    ) -> Any:
        self._require_configured()
        url = self._build_url(path)
        try:
            if files is not None:
                # multipart upload — drop json content-type, let httpx set boundary
                resp = self._client.request(
                    method,
                    url,
                    files=files,
                    data=data,
                    headers=self._headers(json_content=False),
                )
            else:
                resp = self._client.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=self._headers(),
                )
        except httpx.HTTPError as exc:
            logger.warning("mattermost upstream error %s %s: %s", method, path, type(exc).__name__)
            raise MattermostHTTPError(502, f"Upstream Mattermost request failed: {type(exc).__name__}") from exc

        if expect_no_content and resp.status_code in (200, 204):
            # Mattermost DELETE /posts/{id} returns {"status": "OK"} — preserve when present
            if resp.status_code == 200 and resp.content:
                try:
                    return resp.json()
                except ValueError:
                    pass
            return None

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
        raise MattermostHTTPError(
            resp.status_code, f"Mattermost returned {resp.status_code}", payload
        )

    # ------------------------------------------------------------------ posts

    def create_post(
        self,
        channel_id: str,
        message: str,
        *,
        props: Optional[Dict[str, Any]] = None,
        file_ids: Optional[List[str]] = None,
        root_id: Optional[str] = None,
        type: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"channel_id": channel_id, "message": message}
        if props is not None:
            body["props"] = props
        if file_ids is not None:
            body["file_ids"] = file_ids
        if root_id is not None:
            body["root_id"] = root_id
        if type is not None:
            body["type"] = type
        return self._request("POST", "posts", json_body=body) or {}

    def get_post(self, post_id: str, include_deleted: bool = False) -> Dict[str, Any]:
        params = {"include_deleted": "true" if include_deleted else "false"}
        return self._request("GET", f"posts/{post_id}", params=params) or {}

    def update_post(
        self,
        post_id: str,
        *,
        message: str,
        file_ids: Optional[List[str]] = None,
        has_reactions: Optional[bool] = None,
        props: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"id": post_id, "message": message}
        if file_ids is not None:
            body["file_ids"] = file_ids
        if has_reactions is not None:
            body["has_reactions"] = has_reactions
        if props is not None:
            body["props"] = props
        return self._request("PUT", f"posts/{post_id}", json_body=body) or {}

    def delete_post(self, post_id: str) -> Dict[str, Any]:
        result = self._request("DELETE", f"posts/{post_id}", expect_no_content=True)
        if isinstance(result, dict):
            return result
        return {"status": "OK"}

    # ------------------------------------------------------------------ users / teams / channels

    def get_user_teams(self, user_id: str) -> List[Dict[str, Any]]:
        result = self._request("GET", f"users/{user_id}/teams") or []
        return list(result) if isinstance(result, list) else []

    def get_team_channels(
        self,
        team_id: str,
        *,
        per_page: Optional[int] = None,
        page: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if per_page is not None:
            params["per_page"] = per_page
        if page is not None:
            params["page"] = page
        result = self._request(
            "GET", f"teams/{team_id}/channels", params=params or None
        ) or []
        return list(result) if isinstance(result, list) else []

    def get_channel_posts(
        self,
        channel_id: str,
        *,
        since: Optional[int] = None,
        before: Optional[str] = None,
        after: Optional[str] = None,
        page: Optional[int] = None,
        per_page: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if since is not None:
            params["since"] = since
        if before is not None:
            params["before"] = before
        if after is not None:
            params["after"] = after
        if page is not None:
            params["page"] = page
        if per_page is not None:
            params["per_page"] = per_page
        return self._request(
            "GET", f"channels/{channel_id}/posts", params=params or None
        ) or {"order": [], "posts": {}, "prev_post_id": "", "next_post_id": ""}

    # ------------------------------------------------------------------ files

    def upload_files(
        self,
        channel_id: str,
        files: List[Tuple[str, bytes, str]],
    ) -> Dict[str, Any]:
        """Upload one or more files to a channel.

        ``files`` is a list of ``(filename, content_bytes, content_type)`` tuples.
        Returns the full Mattermost response: ``{file_infos: [...], client_ids: [...]}``.
        """
        multipart: List[Tuple[str, Tuple[str, bytes, str]]] = []
        for filename, content, content_type in files:
            multipart.append(("files", (filename, content, content_type or "application/octet-stream")))
        data = {"channel_id": channel_id}
        return self._request("POST", "files", files=multipart, data=data) or {
            "file_infos": [],
            "client_ids": [],
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

_engine: Optional[MattermostEngine] = None
_engine_lock = Lock()


def get_mattermost_engine() -> MattermostEngine:
    """Return (or create) the process-wide MattermostEngine singleton.

    Picks up MATTERMOST_URL / MATTERMOST_TOKEN lazily from the environment so
    tests that monkeypatch env vars before first call get a fresh, env-aligned
    engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = MattermostEngine()
    return _engine


def reset_mattermost_engine() -> None:
    """Test helper — drop the cached singleton so the next get_* call re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
