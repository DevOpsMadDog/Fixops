"""ALDECI Slack ChatOps engine - REAL httpx only, NO MOCKS, NO CACHE.

Wraps the Slack Web API (https://slack.com/api/...). Singleton keyed by
SLACK_BOT_TOKEN env var. When the token is absent the capability summary
returns ``status="unavailable"`` and every operation raises
``SlackChatOpsUnavailableError`` which the router translates to HTTP 503.

NO SQLite cache. NO mock fallback.

Singleton:
    eng = get_slack_chatops_engine()

Reset (tests):
    reset_slack_chatops_engine()
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 8.0
DEFAULT_BASE_URL = "https://slack.com"


# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (optional, never blocks)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Best-effort TrustGraph emit. Never raises. Handles async bus.emit safely."""
    if _get_tg_bus is None:
        return
    try:
        import asyncio
        import inspect
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        if inspect.isawaitable(result):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(result)
            except RuntimeError:
                result.close()
    except Exception:  # pragma: no cover
        pass


class SlackChatOpsUnavailableError(RuntimeError):
    """Raised when SLACK_BOT_TOKEN is unset or the Slack API rejected the call."""


class SlackChatOpsEngine:
    """Real httpx-backed Slack Web API client.

    All public methods raise ``SlackChatOpsUnavailableError`` when
    SLACK_BOT_TOKEN is not configured (HTTP 503 at the router boundary).
    """

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_token = token
        self._explicit_base_url = base_url

        self._client: Optional[httpx.Client] = client
        self._owns_client: bool = client is None
        self._timeout: float = timeout

        self._lock = threading.RLock()

    # ------------------------------------------------------------------ creds

    def _token(self) -> str:
        if self._explicit_token is not None:
            return self._explicit_token.strip()
        return (os.environ.get("SLACK_BOT_TOKEN") or "").strip()

    def _base_url(self) -> str:
        if self._explicit_base_url is not None:
            raw = self._explicit_base_url
        else:
            raw = os.environ.get("SLACK_BASE_URL", "")
        url = (raw or "").strip() or DEFAULT_BASE_URL
        return url.rstrip("/")

    def token_present(self) -> bool:
        return bool(self._token())

    def is_configured(self) -> bool:
        return self.token_present()

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise SlackChatOpsUnavailableError(
                "SLACK_BOT_TOKEN not set - set SLACK_BOT_TOKEN env var to call Slack"
            )

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
            self._owns_client = True
        return self._client

    def _bearer_headers(self, content_type: str = "application/json; charset=utf-8") -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token()}",
            "Content-Type": content_type,
            "Accept": "application/json",
        }

    def _multipart_headers(self) -> Dict[str, str]:
        # httpx sets Content-Type automatically for multipart; only Auth is needed
        return {
            "Authorization": f"Bearer {self._token()}",
            "Accept": "application/json",
        }

    # ---------------------------------------------------------------- request

    def _post_json(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        client = self._ensure_client()
        url = f"{self._base_url()}{path}"
        try:
            resp = client.post(
                url,
                headers=self._bearer_headers(),
                json=body or {},
            )
        except httpx.HTTPError as exc:
            raise SlackChatOpsUnavailableError(
                f"Slack request failed: {exc}"
            ) from exc

        return self._parse_slack_response(resp, path)

    def _get_json(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        client = self._ensure_client()
        url = f"{self._base_url()}{path}"
        try:
            resp = client.get(
                url,
                headers=self._bearer_headers(),
                params=params or None,
            )
        except httpx.HTTPError as exc:
            raise SlackChatOpsUnavailableError(
                f"Slack request failed: {exc}"
            ) from exc

        return self._parse_slack_response(resp, path)

    def _post_multipart(
        self,
        path: str,
        data: Dict[str, Any],
        files: Optional[Dict[str, Tuple[str, Any, str]]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        client = self._ensure_client()
        url = f"{self._base_url()}{path}"
        try:
            resp = client.post(
                url,
                headers=self._multipart_headers(),
                data={k: v for k, v in (data or {}).items() if v is not None},
                files=files or None,
            )
        except httpx.HTTPError as exc:
            raise SlackChatOpsUnavailableError(
                f"Slack request failed: {exc}"
            ) from exc

        return self._parse_slack_response(resp, path)

    def _parse_slack_response(self, resp: Any, path: str) -> Dict[str, Any]:
        status_code = getattr(resp, "status_code", 0)
        if status_code in (401, 403):
            raise SlackChatOpsUnavailableError(
                f"Slack rejected credentials (HTTP {status_code})"
            )
        if status_code == 429:
            raise SlackChatOpsUnavailableError(
                f"Slack rate-limited the request (HTTP 429) for {path}"
            )
        if status_code >= 500:
            raise SlackChatOpsUnavailableError(
                f"Slack returned HTTP {status_code} for {path}"
            )
        try:
            payload = resp.json()
        except Exception as exc:  # noqa: BLE001
            text = (getattr(resp, "text", "") or "").strip()
            if not text:
                return {"ok": False, "error": "empty_response"}
            raise SlackChatOpsUnavailableError(
                f"Slack returned non-JSON response for {path}: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            return {"ok": False, "error": "non_object_response", "data": payload}

        # Slack returns ok=false with an "error" string for app-level failures.
        # We return the payload as-is so the router/test can inspect it.
        if payload.get("ok") is False:
            err = payload.get("error") or "unknown_error"
            if err in ("invalid_auth", "not_authed", "token_revoked", "account_inactive"):
                raise SlackChatOpsUnavailableError(
                    f"Slack rejected credentials: {err}"
                )
        return payload

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "Slack ChatOps",
            "endpoints": [
                "/api/chat.postMessage",
                "/api/chat.update",
                "/api/chat.delete",
                "/api/users.list",
                "/api/conversations.list",
                "/api/files.upload",
                "/api/reactions.add",
            ],
            "slack_bot_token_present": self.token_present(),
            "status": status,
        }

    # ------------------------------------------------------------ chat methods

    def chat_post_message(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if not body.get("channel"):
            raise ValueError("channel must not be empty")
        out = self._post_json("/api/chat.postMessage", body=body)
        try:
            _emit_event(
                "slack_chatops.message_posted",
                {
                    "channel": body.get("channel"),
                    "ts": out.get("ts"),
                    "ok": out.get("ok"),
                },
            )
        except Exception:  # pragma: no cover
            pass
        return out

    def chat_update(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if not body.get("channel") or not body.get("ts"):
            raise ValueError("channel and ts must not be empty")
        return self._post_json("/api/chat.update", body=body)

    def chat_delete(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if not body.get("channel") or not body.get("ts"):
            raise ValueError("channel and ts must not be empty")
        return self._post_json("/api/chat.delete", body=body)

    # ----------------------------------------------------------- listing

    def users_list(
        self,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if limit is not None:
            params["limit"] = int(limit)
        if cursor:
            params["cursor"] = cursor
        return self._get_json("/api/users.list", params=params or None)

    def conversations_list(
        self,
        types: Optional[str] = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        exclude_archived: Optional[bool] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if types:
            params["types"] = types
        if limit is not None:
            params["limit"] = int(limit)
        if cursor:
            params["cursor"] = cursor
        if exclude_archived is not None:
            params["exclude_archived"] = "true" if exclude_archived else "false"
        return self._get_json("/api/conversations.list", params=params or None)

    # ----------------------------------------------------------- files

    def files_upload(
        self,
        channels: str,
        content: Optional[str] = None,
        file_bytes: Optional[bytes] = None,
        filename: Optional[str] = None,
        filetype: Optional[str] = None,
        initial_comment: Optional[str] = None,
        thread_ts: Optional[str] = None,
        title: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not channels:
            raise ValueError("channels must not be empty")
        data: Dict[str, Any] = {
            "channels": channels,
            "filename": filename,
            "filetype": filetype,
            "initial_comment": initial_comment,
            "thread_ts": thread_ts,
            "title": title,
        }
        files = None
        if file_bytes is not None:
            files = {
                "file": (
                    filename or "upload.bin",
                    file_bytes,
                    filetype or "application/octet-stream",
                )
            }
        elif content is not None:
            data["content"] = content
        else:
            raise ValueError("either content or file_bytes must be provided")
        return self._post_multipart("/api/files.upload", data=data, files=files)

    # ----------------------------------------------------------- reactions

    def reactions_add(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if not body.get("channel") or not body.get("name") or not body.get("timestamp"):
            raise ValueError("channel, name, timestamp must not be empty")
        return self._post_json("/api/reactions.add", body=body)

    # ----------------------------------------------------------------- close

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            try:
                self._client.close()
            except Exception:  # pragma: no cover
                pass


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[SlackChatOpsEngine] = None
_singleton_lock = threading.RLock()


def get_slack_chatops_engine(
    token: Optional[str] = None,
    base_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    force_refresh: bool = False,
) -> SlackChatOpsEngine:
    """Return the process-wide SlackChatOpsEngine singleton."""
    global _singleton
    with _singleton_lock:
        if (
            _singleton is None
            or force_refresh
            or any(v is not None for v in (token, base_url, client))
        ):
            if _singleton is not None:
                _singleton.close()
            _singleton = SlackChatOpsEngine(
                token=token,
                base_url=base_url,
                client=client,
            )
        return _singleton


def reset_slack_chatops_engine() -> None:
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

__all__ = [
    "SlackChatOpsEngine",
    "SlackChatOpsUnavailableError",
    "get_slack_chatops_engine",
    "reset_slack_chatops_engine",
]
