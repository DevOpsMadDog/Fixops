"""ALDECI Discord Integration Engine — REAL API only, NO MOCKS.

Wraps Discord's webhook + bot REST API (v10) via httpx. Returns
``status="unavailable"`` in the capability summary and raises
``DiscordUnavailableError`` (mapped to HTTP 503 at the router) when neither
``DISCORD_WEBHOOK_URL`` nor ``DISCORD_BOT_TOKEN`` is set.

Two distinct credential surfaces:
  - Webhook (no auth):  ``DISCORD_WEBHOOK_URL`` (or per-call wh_id/wh_token)
  - Bot REST API v10:    ``DISCORD_BOT_TOKEN``  (sent as ``Authorization: Bot <token>``)

Singleton accessor: ``get_discord_integration_engine(...)``
Reset (for tests):  ``reset_discord_integration_engine()``
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

DISCORD_API_BASE = "https://discord.com/api/v10"
DISCORD_WEBHOOK_BASE = "https://discord.com/api/webhooks"


class DiscordUnavailableError(RuntimeError):
    """Raised when Discord API/webhook cannot be reached or is misconfigured."""


class DiscordIntegrationEngine:
    """Thin httpx-backed client for Discord REST API v10 + Webhooks.

    All bot endpoints raise ``DiscordUnavailableError`` when the bot token is
    missing. Webhook proxy raises only when both webhook URL is missing AND
    no per-request wh_id/wh_token are supplied.
    """

    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        bot_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._webhook_url = (webhook_url or os.environ.get("DISCORD_WEBHOOK_URL") or "").strip()
        self._bot_token = (bot_token or os.environ.get("DISCORD_BOT_TOKEN") or "").strip()
        self._timeout = timeout
        self._client = client

    # ------------------------------------------------------------- utils

    def webhook_present(self) -> bool:
        return bool(self._webhook_url)

    def bot_token_present(self) -> bool:
        return bool(self._bot_token)

    def is_configured(self) -> bool:
        return self.webhook_present() or self.bot_token_present()

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def _require_bot_token(self) -> None:
        if not self._bot_token:
            raise DiscordUnavailableError(
                "DISCORD_BOT_TOKEN not set — required for /api/v10/* endpoints"
            )

    def _bot_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bot {self._bot_token}",
            "Content-Type": "application/json",
            "User-Agent": "ALDECI-Discord/1.0 (+https://aldeci.io)",
        }

    @staticmethod
    def _webhook_headers() -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "User-Agent": "ALDECI-Discord/1.0 (+https://aldeci.io)",
        }

    def _check_resp(self, resp: Any, op: str) -> Any:
        status = getattr(resp, "status_code", 0)
        if status == 401:
            raise DiscordUnavailableError(f"Discord 401 (invalid token) for {op}")
        if status == 403:
            raise DiscordUnavailableError(f"Discord 403 (forbidden) for {op}")
        if status == 404:
            raise DiscordUnavailableError(f"Discord 404 for {op}")
        if status == 429:
            raise DiscordUnavailableError(f"Discord 429 (rate-limit) for {op}")
        if status >= 500:
            raise DiscordUnavailableError(f"Discord {status} (upstream error) for {op}")
        if status >= 400:
            text = getattr(resp, "text", "") or ""
            raise DiscordUnavailableError(f"Discord {status} for {op}: {text[:200]}")
        # 204 No Content has no body
        if status == 204:
            return {}
        try:
            return resp.json()
        except Exception as exc:
            raise DiscordUnavailableError(
                f"Discord returned non-JSON for {op}: {exc}"
            ) from exc

    # --------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Return capability metadata for the GET / endpoint."""
        if not self.is_configured():
            status = "unavailable"
        elif self.webhook_present() and not self.bot_token_present():
            # Only webhook configured — partial capability
            status = "empty"
        else:
            status = "ok"
        return {
            "service": "Discord",
            "endpoints": [
                "/webhooks/{wh_id}/{wh_token}",
                "/api/v10/channels/{channel_id}/messages",
                "/api/v10/guilds/{guild_id}/channels",
                "/api/v10/users/@me/guilds",
            ],
            "webhook_url_present": self.webhook_present(),
            "bot_token_present": self.bot_token_present(),
            "status": status,
        }

    # --------------------------------------------------------- webhook

    def post_webhook(
        self,
        wh_id: str,
        wh_token: str,
        body: Dict[str, Any],
        wait: bool = False,
    ) -> Dict[str, Any]:
        """Proxy POST /webhooks/{wh_id}/{wh_token}.

        Returns ``{}`` for the default 204 path or the message dict when
        ``wait=true``.
        """
        if not wh_id or not str(wh_id).strip():
            raise ValueError("wh_id required")
        if not wh_token or not str(wh_token).strip():
            raise ValueError("wh_token required")
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
        # Either content or embeds is required by Discord
        has_content = bool(str(body.get("content") or "").strip())
        has_embeds = bool(body.get("embeds"))
        if not has_content and not has_embeds:
            raise ValueError("body.content or body.embeds is required")
        client = self._ensure_client()
        url = f"{DISCORD_WEBHOOK_BASE}/{wh_id}/{wh_token}"
        params: List[tuple] = []
        if wait:
            params.append(("wait", "true"))
        resp = client.post(
            url,
            headers=self._webhook_headers(),
            json=body,
            params=params or None,
        )
        data = self._check_resp(resp, f"POST /webhooks/{wh_id}/<token>")
        if wait:
            return data if isinstance(data, dict) else {"message": data}
        return {}

    # --------------------------------------------------- channel messages

    def list_channel_messages(
        self,
        channel_id: str,
        *,
        limit: int = 50,
        before: Optional[str] = None,
        after: Optional[str] = None,
        around: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._require_bot_token()
        if not channel_id or not str(channel_id).strip():
            raise ValueError("channel_id required")
        params: List[tuple] = [("limit", str(min(max(limit, 1), 100)))]
        if before:
            params.append(("before", before))
        if after:
            params.append(("after", after))
        if around:
            params.append(("around", around))
        client = self._ensure_client()
        resp = client.get(
            f"{DISCORD_API_BASE}/channels/{channel_id}/messages",
            headers=self._bot_headers(),
            params=params,
        )
        data = self._check_resp(resp, f"GET /channels/{channel_id}/messages")
        if not isinstance(data, list):
            data = []
        return {"messages": data}

    def create_channel_message(
        self,
        channel_id: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        self._require_bot_token()
        if not channel_id or not str(channel_id).strip():
            raise ValueError("channel_id required")
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
        has_content = bool(str(body.get("content") or "").strip())
        has_embeds = bool(body.get("embeds"))
        has_stickers = bool(body.get("sticker_ids"))
        if not (has_content or has_embeds or has_stickers):
            raise ValueError("body.content, body.embeds, or body.sticker_ids required")
        client = self._ensure_client()
        resp = client.post(
            f"{DISCORD_API_BASE}/channels/{channel_id}/messages",
            headers=self._bot_headers(),
            json=body,
        )
        data = self._check_resp(resp, f"POST /channels/{channel_id}/messages")
        if not isinstance(data, dict):
            data = {}
        return {"message": data}

    # ----------------------------------------------------- guild channels

    def list_guild_channels(self, guild_id: str) -> Dict[str, Any]:
        self._require_bot_token()
        if not guild_id or not str(guild_id).strip():
            raise ValueError("guild_id required")
        client = self._ensure_client()
        resp = client.get(
            f"{DISCORD_API_BASE}/guilds/{guild_id}/channels",
            headers=self._bot_headers(),
        )
        data = self._check_resp(resp, f"GET /guilds/{guild_id}/channels")
        if not isinstance(data, list):
            data = []
        return {"channels": data}

    # -------------------------------------------------------- user guilds

    def list_user_guilds(
        self,
        *,
        limit: int = 200,
        before: Optional[str] = None,
        after: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._require_bot_token()
        params: List[tuple] = [("limit", str(min(max(limit, 1), 200)))]
        if before:
            params.append(("before", before))
        if after:
            params.append(("after", after))
        client = self._ensure_client()
        resp = client.get(
            f"{DISCORD_API_BASE}/users/@me/guilds",
            headers=self._bot_headers(),
            params=params,
        )
        data = self._check_resp(resp, "GET /users/@me/guilds")
        if not isinstance(data, list):
            data = []
        return {"guilds": data}

    # ------------------------------------------------------------- close

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass


# ----------------------------------------------------------- singleton

_singleton: Optional[DiscordIntegrationEngine] = None
_singleton_lock = threading.Lock()


def get_discord_integration_engine(
    webhook_url: Optional[str] = None,
    bot_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> DiscordIntegrationEngine:
    """Process-wide singleton accessor."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = DiscordIntegrationEngine(
                webhook_url=webhook_url,
                bot_token=bot_token,
                client=client,
            )
        return _singleton


def reset_discord_integration_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "DiscordIntegrationEngine",
    "DiscordUnavailableError",
    "get_discord_integration_engine",
    "reset_discord_integration_engine",
]
