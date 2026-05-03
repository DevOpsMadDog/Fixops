"""Okta IAM — REAL SSWS-token REST API client (NEW — 2026-05-04).

Live counterpart to ``connectors/okta_connector.py`` (which feeds the
identity-inventory triage pipeline). This engine exposes the documented
Okta REST surface 1:1 for the ``/api/v1/okta`` router so consumers can
read Users / Groups / Apps / System Logs / Sessions directly.

Endpoints (all prefixed with the Okta tenant base URL):

  GET  /api/v1/users                    list users
  GET  /api/v1/groups                   list groups
  GET  /api/v1/apps                     list applications
  GET  /api/v1/logs                     System Log events
  GET  /api/v1/sessions/{session_id}    fetch a session
  POST /api/v1/sessions/me/lifecycle/refresh   refresh current session

Required env vars
-----------------
    OKTA_DOMAIN     Bare host or full URL — e.g. ``mycorp.okta.com`` or
                    ``https://mycorp.okta.com``.
    OKTA_API_TOKEN  SSWS API token. Sent as ``Authorization: SSWS {token}``.

NO MOCKS rule
-------------
* If either env var is unset the engine reports
  ``credentials_present()=False`` and every live call raises
  ``OktaUnavailableError`` (router translates to HTTP 503).
* No fabricated users / groups / apps / log events / sessions — ever.
* No SQLite cache — pure HTTP passthrough.

Pagination
----------
Okta returns the ``Link`` header with ``rel="next"``. We parse it and
expose the cursor portion (``after=...``) as ``next_cursor`` in the
response so callers can resume.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0


class OktaUnavailableError(RuntimeError):
    """Raised when Okta credentials are missing or upstream call fails."""


def _normalize_domain(raw: Optional[str]) -> Optional[str]:
    """Accept ``acme.okta.com`` or ``https://acme.okta.com`` — return host."""
    if not raw:
        return None
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host = parsed.netloc or parsed.path
        return host.strip("/").strip() or None
    return raw.strip("/").strip() or None


def _extract_next_cursor(link_header: Optional[str]) -> Optional[str]:
    """Pull the ``after=`` query param out of an Okta ``Link: ...; rel="next"``
    header. Returns None when no next link present.
    """
    if not link_header:
        return None
    # Header is: <https://...?after=ABC>; rel="next", <https://...>; rel="self"
    parts = re.findall(r'<([^>]+)>;\s*rel="([^"]+)"', link_header)
    for url, rel in parts:
        if rel == "next":
            try:
                qs = parse_qs(urlparse(url).query)
            except (ValueError, TypeError):
                return None
            after = qs.get("after")
            if after:
                return after[0]
    return None


class OktaIAMEngine:
    """Live Okta REST API client.

    Stateless. Designed to be used as a process-wide singleton via
    ``get_okta_iam_engine()``.
    """

    def __init__(
        self,
        okta_domain: Optional[str] = None,
        okta_api_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._domain = _normalize_domain(
            okta_domain if okta_domain is not None else os.getenv("OKTA_DOMAIN")
        )
        self._token = (
            okta_api_token
            if okta_api_token is not None
            else os.getenv("OKTA_API_TOKEN")
        )
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public introspection
    # ------------------------------------------------------------------
    def domain_present(self) -> bool:
        return bool(self._domain)

    def token_present(self) -> bool:
        return bool(self._token and str(self._token).strip())

    def credentials_present(self) -> bool:
        return self.domain_present() and self.token_present()

    def base_url(self) -> Optional[str]:
        if not self._domain:
            return None
        return f"https://{self._domain}/api/v1"

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"SSWS {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _ensure_creds(self) -> None:
        if not self.credentials_present():
            raise OktaUnavailableError(
                "OKTA_DOMAIN and OKTA_API_TOKEN must be set"
            )

    def _get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Tuple[Any, Optional[str]]:
        self._ensure_creds()
        url = f"{self.base_url()}{path}"
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            resp = self._client.get(
                url, params=clean_params, headers=self._headers()
            )
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover
            raise OktaUnavailableError(f"GET {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    def _post(
        self, path: str, json_body: Optional[Dict[str, Any]] = None
    ) -> Tuple[Any, Optional[str]]:
        self._ensure_creds()
        url = f"{self.base_url()}{path}"
        try:
            resp = self._client.post(
                url, json=json_body or {}, headers=self._headers()
            )
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover
            raise OktaUnavailableError(f"POST {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    @staticmethod
    def _unwrap(resp: Any, path: str) -> Tuple[Any, Optional[str]]:
        status = getattr(resp, "status_code", 500)
        if status >= 400:
            text = (getattr(resp, "text", "") or "")[:300]
            raise OktaUnavailableError(f"{path} returned {status}: {text}")
        try:
            data = resp.json()
        except (ValueError, TypeError) as exc:
            raise OktaUnavailableError(
                f"{path} returned non-JSON: {exc}"
            ) from exc
        # Headers may be dict-like (real httpx) or plain dict (stub).
        headers = getattr(resp, "headers", {}) or {}
        try:
            link = headers.get("Link") or headers.get("link")
        except AttributeError:
            link = None
        return data, _extract_next_cursor(link)

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------
    def list_users(
        self,
        q: Optional[str] = None,
        filter_: Optional[str] = None,
        search: Optional[str] = None,
        limit: Optional[int] = None,
        after: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = {
            "q": q,
            "filter": filter_,
            "search": search,
            "limit": limit,
            "after": after,
        }
        data, next_cursor = self._get("/users", params=params)
        users = data if isinstance(data, list) else []
        return {"users": users, "next_cursor": next_cursor}

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------
    def list_groups(
        self,
        q: Optional[str] = None,
        filter_: Optional[str] = None,
        limit: Optional[int] = None,
        after: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = {
            "q": q,
            "filter": filter_,
            "limit": limit,
            "after": after,
        }
        data, next_cursor = self._get("/groups", params=params)
        groups = data if isinstance(data, list) else []
        return {"groups": groups, "next_cursor": next_cursor}

    # ------------------------------------------------------------------
    # Apps
    # ------------------------------------------------------------------
    def list_apps(
        self,
        filter_: Optional[str] = None,
        limit: Optional[int] = None,
        after: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = {
            "filter": filter_,
            "limit": limit,
            "after": after,
        }
        data, next_cursor = self._get("/apps", params=params)
        apps = data if isinstance(data, list) else []
        return {"apps": apps, "next_cursor": next_cursor}

    # ------------------------------------------------------------------
    # System Log events
    # ------------------------------------------------------------------
    def list_logs(
        self,
        since: Optional[str] = None,
        until: Optional[str] = None,
        filter_: Optional[str] = None,
        q: Optional[str] = None,
        limit: Optional[int] = None,
        after: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = {
            "since": since,
            "until": until,
            "filter": filter_,
            "q": q,
            "limit": limit,
            "after": after,
        }
        data, next_cursor = self._get("/logs", params=params)
        events = data if isinstance(data, list) else []
        return {"events": events, "next_cursor": next_cursor}

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------
    def get_session(self, session_id: str) -> Dict[str, Any]:
        if not session_id or not str(session_id).strip():
            raise ValueError("session_id is required")
        data, _ = self._get(f"/sessions/{session_id}")
        if not isinstance(data, dict):
            raise OktaUnavailableError("/sessions returned non-object payload")
        return data

    def refresh_session_me(self) -> Dict[str, Any]:
        data, _ = self._post("/sessions/me/lifecycle/refresh")
        if not isinstance(data, dict):
            raise OktaUnavailableError(
                "/sessions/me/lifecycle/refresh returned non-object payload"
            )
        return data

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except (RuntimeError, OSError):
                pass


# --------------------------------------------------------------- singleton
_singleton: Optional[OktaIAMEngine] = None
_singleton_lock = threading.Lock()


def get_okta_iam_engine(
    okta_domain: Optional[str] = None,
    okta_api_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> OktaIAMEngine:
    """Return the process-wide OktaIAMEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = OktaIAMEngine(
                okta_domain=okta_domain,
                okta_api_token=okta_api_token,
                client=client,
            )
        return _singleton


def reset_okta_iam_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "OktaIAMEngine",
    "OktaUnavailableError",
    "get_okta_iam_engine",
    "reset_okta_iam_engine",
]
