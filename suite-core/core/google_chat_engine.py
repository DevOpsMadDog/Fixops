"""ALDECI Google Chat Engine — REAL API only, NO MOCKS.

Wraps two Google Chat capabilities:

1. Incoming Webhook channel: POST a text or card payload to a configured
   ``GCHAT_WEBHOOK_URL`` (https://chat.googleapis.com/v1/spaces/.../messages?key=...&token=...).
   No external auth required by the URL itself; the URL embeds a key + token.
   Available when ``GCHAT_WEBHOOK_URL`` is set.

2. Google Chat REST API v1: GET spaces, list members, POST messages via
   ``https://chat.googleapis.com/v1/...`` with an ``Authorization: Bearer
   <access_token>`` header. The access token is obtained by signing a JWT
   with the service-account private key (loaded from
   ``GOOGLE_APPLICATION_CREDENTIALS``) and exchanging it at
   ``https://oauth2.googleapis.com/token`` for a token with the
   ``https://www.googleapis.com/auth/chat.bot`` scope.

Status taxonomy (capability_summary):
  * ``ok``          — both webhook and service-account credentials present
  * ``empty``       — only one of the two configured
  * ``unavailable`` — neither configured (engine returns 503 for any call)

Singleton: ``get_google_chat_engine(webhook_url=..., creds_path=..., client=...)``
Reset:     ``reset_google_chat_engine()``
"""
from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

CHAT_API_BASE = "https://chat.googleapis.com/v1"
TOKEN_URL = "https://oauth2.googleapis.com/token"
CHAT_BOT_SCOPE = "https://www.googleapis.com/auth/chat.bot"
TOKEN_TTL_SECONDS = 3600


class GoogleChatUnavailableError(RuntimeError):
    """Raised when the Google Chat API cannot be reached or is misconfigured."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class GoogleChatEngine:
    """Thin httpx-backed client for Google Chat webhooks + REST v1.

    NO MOCKS — all methods raise ``GoogleChatUnavailableError`` (HTTP 503 at
    the router layer) when the corresponding credential is missing.
    """

    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        creds_path: Optional[str] = None,
        creds_data: Optional[Dict[str, Any]] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._webhook_url = (webhook_url or os.environ.get("GCHAT_WEBHOOK_URL") or "").strip()
        self._creds_path = (
            creds_path or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or ""
        ).strip()
        self._creds_data: Optional[Dict[str, Any]] = creds_data
        self._timeout = timeout
        self._client = client
        self._access_token: Optional[str] = None
        self._access_token_expiry: float = 0.0
        self._creds_loaded: bool = False

    # ---------------------------------------------------------------- utils

    def _try_load_creds(self) -> Optional[Dict[str, Any]]:
        if self._creds_data is not None:
            return self._creds_data
        if not self._creds_path:
            return None
        try:
            with open(self._creds_path, "r", encoding="utf-8") as fh:
                self._creds_data = json.load(fh)
            self._creds_loaded = True
            return self._creds_data
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("Failed to load Google service account creds: %s", exc)
            return None

    def webhook_configured(self) -> bool:
        return bool(self._webhook_url)

    def creds_configured(self) -> bool:
        if self._creds_data is not None:
            return True
        return bool(self._creds_path) and os.path.exists(self._creds_path)

    def is_configured(self) -> bool:
        return self.webhook_configured() or self.creds_configured()

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def _require_webhook(self) -> None:
        if not self._webhook_url:
            raise GoogleChatUnavailableError(
                "GCHAT_WEBHOOK_URL not set — set the env var to deliver to Google Chat"
            )

    def _require_creds(self) -> None:
        if not self.creds_configured():
            raise GoogleChatUnavailableError(
                "GOOGLE_APPLICATION_CREDENTIALS not set or unreadable — set the env var to a service-account JSON path"
            )

    # ---------------------------------------------------------------- JWT

    def _build_jwt_assertion(self, creds: Dict[str, Any]) -> str:
        """Build a signed JWT bearer assertion for the OAuth2 token exchange.

        Requires PyJWT + cryptography for RS256 signing.
        """
        try:
            import jwt  # type: ignore
        except ImportError as exc:
            raise GoogleChatUnavailableError(
                "PyJWT (with RS256/cryptography support) required for Google Chat service-account auth"
            ) from exc

        client_email = creds.get("client_email")
        private_key = creds.get("private_key")
        if not client_email or not private_key:
            raise GoogleChatUnavailableError(
                "Service-account JSON missing client_email or private_key"
            )

        now = int(time.time())
        payload = {
            "iss": client_email,
            "scope": CHAT_BOT_SCOPE,
            "aud": TOKEN_URL,
            "iat": now,
            "exp": now + TOKEN_TTL_SECONDS,
        }
        try:
            assertion = jwt.encode(payload, private_key, algorithm="RS256")
        except Exception as exc:  # pragma: no cover - signing failure path
            raise GoogleChatUnavailableError(
                f"Failed to sign service-account JWT: {exc}"
            ) from exc
        if isinstance(assertion, bytes):  # PyJWT <2 returns bytes
            assertion = assertion.decode("ascii")
        return assertion

    def _exchange_jwt_for_access_token(self) -> str:
        """Exchange the service-account JWT for a Google OAuth2 access token."""
        creds = self._try_load_creds()
        if creds is None:
            raise GoogleChatUnavailableError(
                "Service-account JSON not loadable from GOOGLE_APPLICATION_CREDENTIALS"
            )
        assertion = self._build_jwt_assertion(creds)
        client = self._ensure_client()
        resp = client.post(
            TOKEN_URL,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
        )
        status = getattr(resp, "status_code", 0)
        if status != 200:
            text = getattr(resp, "text", "") or ""
            raise GoogleChatUnavailableError(
                f"Google OAuth2 token exchange failed {status}: {text[:200]}"
            )
        try:
            data = resp.json()
        except Exception as exc:
            raise GoogleChatUnavailableError(
                f"Google OAuth2 returned non-JSON: {exc}"
            ) from exc
        token = data.get("access_token")
        ttl = int(data.get("expires_in") or 3600)
        if not token:
            raise GoogleChatUnavailableError(
                "Google OAuth2 response missing access_token"
            )
        self._access_token = token
        # Refresh 60s before actual expiry.
        self._access_token_expiry = time.time() + max(60, ttl - 60)
        return token

    def _get_access_token(self) -> str:
        if self._access_token and time.time() < self._access_token_expiry:
            return self._access_token
        return self._exchange_jwt_for_access_token()

    def _api_headers(self) -> Dict[str, str]:
        token = self._get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _check_resp(self, resp: Any, op: str) -> Any:
        status = getattr(resp, "status_code", 0)
        if status in (200, 201, 202):
            try:
                return resp.json()
            except Exception as exc:
                raise GoogleChatUnavailableError(
                    f"Google Chat returned non-JSON for {op}: {exc}"
                ) from exc
        if status == 204:
            return {}
        if status == 401:
            raise GoogleChatUnavailableError(
                f"Google Chat 401 (invalid token) for {op}"
            )
        if status == 403:
            raise GoogleChatUnavailableError(
                f"Google Chat 403 (forbidden) for {op}"
            )
        if status == 404:
            raise GoogleChatUnavailableError(f"Google Chat 404 for {op}")
        if status == 429:
            raise GoogleChatUnavailableError(
                f"Google Chat 429 (rate-limit) for {op}"
            )
        if status >= 500:
            raise GoogleChatUnavailableError(
                f"Google Chat {status} (upstream error) for {op}"
            )
        if status >= 400:
            text = getattr(resp, "text", "") or ""
            raise GoogleChatUnavailableError(
                f"Google Chat {status} for {op}: {text[:200]}"
            )
        raise GoogleChatUnavailableError(
            f"Google Chat unexpected status {status} for {op}"
        )

    # --------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Capability metadata for GET /."""
        wh = self.webhook_configured()
        cr = self.creds_configured()
        if wh and cr:
            status = "ok"
        elif wh or cr:
            status = "empty"
        else:
            status = "unavailable"
        return {
            "service": "Google Chat",
            "endpoints": [
                "/webhook",
                "/v1/spaces",
                "/v1/spaces/{space}/messages",
                "/v1/spaces/{space}/members",
            ],
            "gchat_webhook_url_present": wh,
            "google_app_creds_present": cr,
            "status": status,
        }

    # --------------------------------------------------------------- webhook

    def post_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Proxy a text- or card-payload to GCHAT_WEBHOOK_URL.

        Google Chat incoming webhooks return ``200`` with a JSON message
        resource on success. We normalise to ``{"delivered": True, "status":
        ..., "response": <json|None>}``.
        """
        self._require_webhook()
        if not isinstance(payload, dict) or not payload:
            raise ValueError("payload must be a non-empty dict")
        client = self._ensure_client()
        resp = client.post(
            self._webhook_url,
            headers={"Content-Type": "application/json; charset=UTF-8"},
            json=payload,
        )
        status = getattr(resp, "status_code", 0)
        if status not in (200, 202, 204):
            text = getattr(resp, "text", "") or ""
            raise GoogleChatUnavailableError(
                f"Google Chat webhook delivery failed {status}: {text[:200]}"
            )
        body: Optional[Any] = None
        try:
            body = resp.json()
        except Exception:
            body = None
        return {"delivered": True, "status": status, "response": body}

    # ---------------------------------------------------------------- API

    def list_spaces(
        self,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._require_creds()
        client = self._ensure_client()
        params: Dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = int(page_size)
        if page_token:
            params["pageToken"] = page_token
        resp = client.get(
            f"{CHAT_API_BASE}/spaces",
            headers=self._api_headers(),
            params=params or None,
        )
        data = self._check_resp(resp, "GET /v1/spaces")
        if not isinstance(data, dict):
            data = {}
        out: Dict[str, Any] = {"spaces": list(data.get("spaces") or [])}
        if data.get("nextPageToken"):
            out["nextPageToken"] = data["nextPageToken"]
        return out

    def list_members(
        self,
        space: str,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._require_creds()
        if not space or not str(space).strip():
            raise ValueError("space required")
        client = self._ensure_client()
        params: Dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = int(page_size)
        if page_token:
            params["pageToken"] = page_token
        resp = client.get(
            f"{CHAT_API_BASE}/spaces/{space}/members",
            headers=self._api_headers(),
            params=params or None,
        )
        data = self._check_resp(resp, f"GET /v1/spaces/{space}/members")
        if not isinstance(data, dict):
            data = {}
        out: Dict[str, Any] = {"memberships": list(data.get("memberships") or [])}
        if data.get("nextPageToken"):
            out["nextPageToken"] = data["nextPageToken"]
        return out

    def post_message(
        self,
        space: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        self._require_creds()
        if not space or not str(space).strip():
            raise ValueError("space required")
        if not isinstance(body, dict) or not body:
            raise ValueError("message body required (text, cards, or cardsV2)")
        # Google Chat requires at least text, cards, or cardsV2.
        if not (body.get("text") or body.get("cards") or body.get("cardsV2")):
            raise ValueError(
                "message must include at least one of: text, cards, cardsV2"
            )
        client = self._ensure_client()
        params: Dict[str, Any] = {}
        thread = body.get("thread") or {}
        if isinstance(thread, dict) and thread.get("threadKey"):
            params["messageReplyOption"] = "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
        resp = client.post(
            f"{CHAT_API_BASE}/spaces/{space}/messages",
            headers=self._api_headers(),
            json=body,
            params=params or None,
        )
        data = self._check_resp(resp, f"POST /v1/spaces/{space}/messages")
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

_singleton: Optional[GoogleChatEngine] = None
_singleton_lock = threading.Lock()


def get_google_chat_engine(
    webhook_url: Optional[str] = None,
    creds_path: Optional[str] = None,
    creds_data: Optional[Dict[str, Any]] = None,
    client: Optional[httpx.Client] = None,
) -> GoogleChatEngine:
    """Process-wide singleton accessor."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = GoogleChatEngine(
                webhook_url=webhook_url,
                creds_path=creds_path,
                creds_data=creds_data,
                client=client,
            )
        return _singleton


def reset_google_chat_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "GoogleChatEngine",
    "GoogleChatUnavailableError",
    "get_google_chat_engine",
    "reset_google_chat_engine",
    "CHAT_API_BASE",
    "TOKEN_URL",
    "CHAT_BOT_SCOPE",
]
