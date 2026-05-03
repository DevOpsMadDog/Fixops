"""ALDECI Microsoft Teams Engine — REAL API only, NO MOCKS.

Wraps the Microsoft Teams Incoming Webhook channel + Microsoft Graph v1.0
Teams APIs via httpx. Two independent capabilities:

1. Webhook channel: POST a MessageCard or Adaptive Card to a configured
   ``TEAMS_WEBHOOK_URL``. No auth required by the URL itself; the URL embeds
   a signed token. Available when ``TEAMS_WEBHOOK_URL`` is set.
2. Microsoft Graph: GET joinedTeams / channels / messages and POST messages
   under ``https://graph.microsoft.com/v1.0/...`` with an ``Authorization:
   Bearer <token>`` header. Available when ``TEAMS_GRAPH_TOKEN`` is set.

Status taxonomy (capability_summary):
  * ``ok``          — both webhook and graph token present
  * ``empty``       — only one of the two configured
  * ``unavailable`` — neither configured (engine returns 503 for any call)

Singleton: ``get_microsoft_teams_engine(webhook_url=..., graph_token=..., client=...)``
Reset:     ``reset_microsoft_teams_engine()``
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class MicrosoftTeamsUnavailableError(RuntimeError):
    """Raised when the Microsoft Teams API cannot be reached or is misconfigured."""


class MicrosoftTeamsEngine:
    """Thin httpx-backed client for Microsoft Teams webhooks + Graph v1.0.

    NO MOCKS — all methods raise ``MicrosoftTeamsUnavailableError`` (HTTP 503
    at the router layer) when the corresponding credential is missing.
    """

    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        graph_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._webhook_url = (webhook_url or os.environ.get("TEAMS_WEBHOOK_URL") or "").strip()
        self._graph_token = (graph_token or os.environ.get("TEAMS_GRAPH_TOKEN") or "").strip()
        self._timeout = timeout
        self._client = client

    # ---------------------------------------------------------------- utils

    def webhook_configured(self) -> bool:
        return bool(self._webhook_url)

    def graph_configured(self) -> bool:
        return bool(self._graph_token)

    def is_configured(self) -> bool:
        return self.webhook_configured() or self.graph_configured()

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def _require_webhook(self) -> None:
        if not self._webhook_url:
            raise MicrosoftTeamsUnavailableError(
                "TEAMS_WEBHOOK_URL not set — set the env var to deliver to Teams"
            )

    def _require_graph(self) -> None:
        if not self._graph_token:
            raise MicrosoftTeamsUnavailableError(
                "TEAMS_GRAPH_TOKEN not set — set the env var to call Microsoft Graph"
            )

    def _graph_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._graph_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _check_resp(self, resp: Any, op: str) -> Any:
        status = getattr(resp, "status_code", 0)
        if status in (200, 201, 202):
            try:
                return resp.json()
            except Exception as exc:
                raise MicrosoftTeamsUnavailableError(
                    f"Microsoft Teams returned non-JSON for {op}: {exc}"
                ) from exc
        if status == 204:
            return {}
        if status == 401:
            raise MicrosoftTeamsUnavailableError(
                f"Microsoft Teams 401 (invalid token) for {op}"
            )
        if status == 403:
            raise MicrosoftTeamsUnavailableError(
                f"Microsoft Teams 403 (forbidden) for {op}"
            )
        if status == 404:
            raise MicrosoftTeamsUnavailableError(f"Microsoft Teams 404 for {op}")
        if status == 429:
            raise MicrosoftTeamsUnavailableError(
                f"Microsoft Teams 429 (rate-limit) for {op}"
            )
        if status >= 500:
            raise MicrosoftTeamsUnavailableError(
                f"Microsoft Teams {status} (upstream error) for {op}"
            )
        if status >= 400:
            text = getattr(resp, "text", "") or ""
            raise MicrosoftTeamsUnavailableError(
                f"Microsoft Teams {status} for {op}: {text[:200]}"
            )
        raise MicrosoftTeamsUnavailableError(
            f"Microsoft Teams unexpected status {status} for {op}"
        )

    # --------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Capability metadata for GET /."""
        wh = self.webhook_configured()
        gr = self.graph_configured()
        if wh and gr:
            status = "ok"
        elif wh or gr:
            status = "empty"
        else:
            status = "unavailable"
        return {
            "service": "Microsoft Teams",
            "endpoints": [
                "/webhook",
                "/v1.0/teams/{team_id}/channels",
                "/v1.0/teams/{team_id}/channels/{channel_id}/messages",
                "/v1.0/me/joinedTeams",
            ],
            "webhook_url_present": wh,
            "graph_token_present": gr,
            "status": status,
        }

    # --------------------------------------------------------------- webhook

    def post_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Proxy a MessageCard / Adaptive Card payload to TEAMS_WEBHOOK_URL.

        Microsoft Teams webhook returns ``200`` with body ``"1"`` (legacy
        connectors) or ``200``/``204`` with empty/JSON body (Power Automate
        adaptive cards). We normalise to ``{"delivered": True, "status": ...}``.
        """
        self._require_webhook()
        if not isinstance(payload, dict) or not payload:
            raise ValueError("payload must be a non-empty dict")
        client = self._ensure_client()
        resp = client.post(
            self._webhook_url,
            headers={"Content-Type": "application/json"},
            json=payload,
        )
        status = getattr(resp, "status_code", 0)
        if status not in (200, 202, 204):
            text = getattr(resp, "text", "") or ""
            raise MicrosoftTeamsUnavailableError(
                f"Microsoft Teams webhook delivery failed {status}: {text[:200]}"
            )
        return {"delivered": True, "status": status}

    # ---------------------------------------------------------------- graph

    def list_joined_teams(self) -> Dict[str, Any]:
        self._require_graph()
        client = self._ensure_client()
        resp = client.get(
            f"{GRAPH_BASE}/me/joinedTeams",
            headers=self._graph_headers(),
        )
        data = self._check_resp(resp, "GET /v1.0/me/joinedTeams")
        if not isinstance(data, dict):
            data = {}
        return {"value": list(data.get("value") or [])}

    def list_channels(self, team_id: str) -> Dict[str, Any]:
        self._require_graph()
        if not team_id or not str(team_id).strip():
            raise ValueError("team_id required")
        client = self._ensure_client()
        resp = client.get(
            f"{GRAPH_BASE}/teams/{team_id}/channels",
            headers=self._graph_headers(),
        )
        data = self._check_resp(resp, f"GET /v1.0/teams/{team_id}/channels")
        if not isinstance(data, dict):
            data = {}
        return {"value": list(data.get("value") or [])}

    def list_channel_messages(
        self,
        team_id: str,
        channel_id: str,
        top: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._require_graph()
        if not team_id or not str(team_id).strip():
            raise ValueError("team_id required")
        if not channel_id or not str(channel_id).strip():
            raise ValueError("channel_id required")
        client = self._ensure_client()
        params: Dict[str, Any] = {}
        if top is not None:
            params["$top"] = int(top)
        resp = client.get(
            f"{GRAPH_BASE}/teams/{team_id}/channels/{channel_id}/messages",
            headers=self._graph_headers(),
            params=params or None,
        )
        data = self._check_resp(
            resp,
            f"GET /v1.0/teams/{team_id}/channels/{channel_id}/messages",
        )
        if not isinstance(data, dict):
            data = {}
        out: Dict[str, Any] = {"value": list(data.get("value") or [])}
        # Preserve Graph paging hints
        if "@odata.nextLink" in data:
            out["@odata.nextLink"] = data["@odata.nextLink"]
        if "@odata.count" in data:
            out["@odata.count"] = data["@odata.count"]
        return out

    def post_channel_message(
        self,
        team_id: str,
        channel_id: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        self._require_graph()
        if not team_id or not str(team_id).strip():
            raise ValueError("team_id required")
        if not channel_id or not str(channel_id).strip():
            raise ValueError("channel_id required")
        if not isinstance(body, dict) or "body" not in body:
            raise ValueError("body.body required (with contentType + content)")
        client = self._ensure_client()
        resp = client.post(
            f"{GRAPH_BASE}/teams/{team_id}/channels/{channel_id}/messages",
            headers=self._graph_headers(),
            json=body,
        )
        data = self._check_resp(
            resp,
            f"POST /v1.0/teams/{team_id}/channels/{channel_id}/messages",
        )
        if not isinstance(data, dict):
            data = {}
        return data

    # ------------------------------------------------------------------ close

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass


# -------------------------------------------------------------- singleton

_singleton: Optional[MicrosoftTeamsEngine] = None
_singleton_lock = threading.Lock()


def get_microsoft_teams_engine(
    webhook_url: Optional[str] = None,
    graph_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> MicrosoftTeamsEngine:
    """Process-wide singleton accessor."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = MicrosoftTeamsEngine(
                webhook_url=webhook_url,
                graph_token=graph_token,
                client=client,
            )
        return _singleton


def reset_microsoft_teams_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "MicrosoftTeamsEngine",
    "MicrosoftTeamsUnavailableError",
    "get_microsoft_teams_engine",
    "reset_microsoft_teams_engine",
]
