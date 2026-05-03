"""
Auth0 Management API Engine — ALDECI.

Wraps the Auth0 Management API v2 (https://{AUTH0_DOMAIN}/api/v2/) and provides
a process-wide singleton with an in-memory access-token cache (~24h TTL).

Endpoint coverage
-----------------
* GET /api/v2/users                          (list users with lucene query)
* GET /api/v2/users/{user_id}                (single user)
* GET /api/v2/users/{user_id}/roles          (roles assigned to user)
* GET /api/v2/users/{user_id}/permissions    (permissions assigned to user)
* GET /api/v2/clients                        (applications / clients)
* GET /api/v2/connections                    (identity providers)
* GET /api/v2/logs                           (tenant log events)
* GET /api/v2/roles                          (roles)
* GET /api/v2/roles/{role_id}/permissions    (permissions in role)

Authentication
--------------
OAuth2 client_credentials flow against ``https://{AUTH0_DOMAIN}/oauth/token``::

    POST /oauth/token
    {
        "audience":      "https://{AUTH0_DOMAIN}/api/v2/",
        "grant_type":    "client_credentials",
        "client_id":     "{AUTH0_CLIENT_ID}",
        "client_secret": "{AUTH0_CLIENT_SECRET}"
    }

The returned access_token is cached in-memory until ``expires_in - 60s``.
Default TTL is ~24h (Auth0 returns 86400).

NO MOCKS rule
-------------
* When AUTH0_DOMAIN, AUTH0_CLIENT_ID, or AUTH0_CLIENT_SECRET is unset:
    - All live endpoints raise ``Auth0UnavailableError`` (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response is what Auth0 actually returned.
* No SQLite cache — token lives in process memory only (per task spec).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 8.0
_TOKEN_REFRESH_LEEWAY = 60  # refresh token 60s before expiry


class Auth0UnavailableError(RuntimeError):
    """Raised when Auth0 credentials missing, network failed, or upstream
    returned an unrecoverable status."""


class Auth0Engine:
    """Thread-safe Auth0 Management API client with in-memory token cache."""

    def __init__(
        self,
        domain: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit credentials win over env (re-read each call so tests can monkeypatch).
        self._explicit_domain = domain
        self._explicit_client_id = client_id
        self._explicit_client_secret = client_secret

        # HTTP client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        # Token cache
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

        self._lock = threading.RLock()

    # ----------------------------------------------------------- env helpers

    def _domain(self) -> Optional[str]:
        if self._explicit_domain:
            return self._explicit_domain
        v = os.environ.get("AUTH0_DOMAIN")
        return v or None

    def _client_id(self) -> Optional[str]:
        if self._explicit_client_id:
            return self._explicit_client_id
        v = os.environ.get("AUTH0_CLIENT_ID")
        return v or None

    def _client_secret(self) -> Optional[str]:
        if self._explicit_client_secret:
            return self._explicit_client_secret
        v = os.environ.get("AUTH0_CLIENT_SECRET")
        return v or None

    def domain_present(self) -> bool:
        return bool(self._domain())

    def client_id_present(self) -> bool:
        return bool(self._client_id())

    def client_secret_present(self) -> bool:
        return bool(self._client_secret())

    def credentials_present(self) -> bool:
        return (
            self.domain_present()
            and self.client_id_present()
            and self.client_secret_present()
        )

    def has_token(self) -> bool:
        """True when an unexpired access token is cached."""
        with self._lock:
            return bool(self._token) and time.time() < self._token_expires_at

    # ----------------------------------------------------------- token mgmt

    def _ensure_token(self) -> str:
        """Return a valid access_token, fetching a new one if missing/expired."""
        with self._lock:
            if self._token and time.time() < self._token_expires_at:
                return self._token

            if not self.credentials_present():
                raise Auth0UnavailableError(
                    "AUTH0_DOMAIN / AUTH0_CLIENT_ID / AUTH0_CLIENT_SECRET not set"
                )

            domain = self._domain()
            url = f"https://{domain}/oauth/token"
            payload = {
                "audience":      f"https://{domain}/api/v2/",
                "grant_type":    "client_credentials",
                "client_id":     self._client_id(),
                "client_secret": self._client_secret(),
            }
            try:
                resp = self._client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                )
            except Exception as exc:  # noqa: BLE001
                raise Auth0UnavailableError(f"Auth0 token endpoint unreachable: {exc}") from exc

            if resp.status_code != 200:
                raise Auth0UnavailableError(
                    f"Auth0 token endpoint returned HTTP {resp.status_code}: {resp.text[:200]}"
                )

            try:
                body = resp.json()
            except Exception as exc:  # noqa: BLE001
                raise Auth0UnavailableError(
                    f"Auth0 token endpoint returned non-JSON: {exc}"
                ) from exc

            access_token = body.get("access_token")
            expires_in = int(body.get("expires_in") or 86400)
            if not access_token:
                raise Auth0UnavailableError("Auth0 token response missing access_token")

            self._token = access_token
            self._token_expires_at = time.time() + max(expires_in - _TOKEN_REFRESH_LEEWAY, 60)
            return self._token

    # ----------------------------------------------------------- request

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Issue an authenticated request to the Management API and return JSON."""
        token = self._ensure_token()
        domain = self._domain()
        url = f"https://{domain}{path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept":        "application/json",
        }
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params or {})
            else:
                raise ValueError(f"Unsupported method: {method}")
        except Exception as exc:  # noqa: BLE001
            raise Auth0UnavailableError(f"Auth0 API unreachable: {exc}") from exc

        if resp.status_code == 401:
            # Token may have been revoked — clear cache and let caller retry.
            with self._lock:
                self._token = None
                self._token_expires_at = 0.0
            raise Auth0UnavailableError("Auth0 returned 401 (token revoked or invalid)")
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise Auth0UnavailableError(
                f"Auth0 {path} returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise Auth0UnavailableError(
                f"Auth0 {path} returned non-JSON: {exc}"
            ) from exc

    # ----------------------------------------------------------- public API

    # --- Users ---------------------------------------------------------------

    def list_users(
        self,
        per_page: int = 50,
        page: int = 0,
        include_totals: bool = False,
        search_engine: str = "v3",
        q: Optional[str] = None,
        sort: Optional[str] = None,
        fields: Optional[str] = None,
        include_fields: bool = True,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "per_page": per_page,
            "page": page,
            "include_totals": str(include_totals).lower(),
            "search_engine": search_engine,
            "include_fields": str(include_fields).lower(),
        }
        if q:
            params["q"] = q
        if sort:
            params["sort"] = sort
        if fields:
            params["fields"] = fields

        body = self._request("GET", "/api/v2/users", params=params)
        if isinstance(body, list):
            # When include_totals=false, Auth0 returns a bare list.
            return {
                "start": page * per_page,
                "limit": per_page,
                "length": len(body),
                "total": len(body),
                "users": body,
            }
        if isinstance(body, dict):
            return {
                "start":  body.get("start", page * per_page),
                "limit":  body.get("limit", per_page),
                "length": body.get("length", len(body.get("users") or [])),
                "total":  body.get("total", 0),
                "users":  body.get("users") or [],
            }
        return {"start": 0, "limit": per_page, "length": 0, "total": 0, "users": []}

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        if not user_id:
            raise ValueError("user_id is required")
        return self._request("GET", f"/api/v2/users/{user_id}")

    def get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        if not user_id:
            raise ValueError("user_id is required")
        body = self._request("GET", f"/api/v2/users/{user_id}/roles")
        if isinstance(body, list):
            return body
        if isinstance(body, dict):
            return body.get("roles") or []
        return []

    def get_user_permissions(self, user_id: str) -> List[Dict[str, Any]]:
        if not user_id:
            raise ValueError("user_id is required")
        body = self._request("GET", f"/api/v2/users/{user_id}/permissions")
        if isinstance(body, list):
            return body
        if isinstance(body, dict):
            return body.get("permissions") or []
        return []

    # --- Clients -------------------------------------------------------------

    def list_clients(
        self,
        fields: Optional[str] = None,
        include_fields: bool = True,
        page: int = 0,
        per_page: int = 50,
        include_totals: bool = False,
        is_global: Optional[bool] = None,
        is_first_party: Optional[bool] = None,
        app_type: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "page": page,
            "per_page": per_page,
            "include_totals": str(include_totals).lower(),
            "include_fields": str(include_fields).lower(),
        }
        if fields:
            params["fields"] = fields
        if is_global is not None:
            params["is_global"] = str(is_global).lower()
        if is_first_party is not None:
            params["is_first_party"] = str(is_first_party).lower()
        if app_type:
            params["app_type"] = app_type
        if client_id:
            params["client_id"] = client_id

        body = self._request("GET", "/api/v2/clients", params=params)
        if isinstance(body, list):
            return {
                "start": page * per_page,
                "limit": per_page,
                "length": len(body),
                "total": len(body),
                "clients": body,
            }
        if isinstance(body, dict):
            return {
                "start":   body.get("start", page * per_page),
                "limit":   body.get("limit", per_page),
                "length":  body.get("length", len(body.get("clients") or [])),
                "total":   body.get("total", 0),
                "clients": body.get("clients") or [],
            }
        return {"start": 0, "limit": per_page, "length": 0, "total": 0, "clients": []}

    # --- Connections ---------------------------------------------------------

    def list_connections(
        self,
        strategy: Optional[str] = None,
        name: Optional[str] = None,
        fields: Optional[str] = None,
        include_fields: bool = True,
        page: int = 0,
        per_page: int = 50,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {
            "page": page,
            "per_page": per_page,
            "include_fields": str(include_fields).lower(),
        }
        if strategy:
            params["strategy"] = strategy
        if name:
            params["name"] = name
        if fields:
            params["fields"] = fields

        body = self._request("GET", "/api/v2/connections", params=params)
        if isinstance(body, list):
            return body
        if isinstance(body, dict):
            return body.get("connections") or []
        return []

    # --- Logs ----------------------------------------------------------------

    def list_logs(
        self,
        per_page: int = 50,
        page: int = 0,
        q: Optional[str] = None,
        from_log_id: Optional[str] = None,
        take: Optional[int] = None,
        include_totals: bool = False,
        fields: Optional[str] = None,
        include_fields: bool = True,
        sort: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {
            "per_page": per_page,
            "page": page,
            "include_totals": str(include_totals).lower(),
            "include_fields": str(include_fields).lower(),
        }
        if q:
            params["q"] = q
        if from_log_id:
            params["from"] = from_log_id
        if take is not None:
            params["take"] = take
        if fields:
            params["fields"] = fields
        if sort:
            params["sort"] = sort

        body = self._request("GET", "/api/v2/logs", params=params)
        if isinstance(body, list):
            return body
        if isinstance(body, dict):
            return body.get("logs") or []
        return []

    # --- Roles ---------------------------------------------------------------

    def list_roles(
        self,
        per_page: int = 50,
        page: int = 0,
        name_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "per_page": per_page,
            "page": page,
        }
        if name_filter:
            params["name_filter"] = name_filter

        body = self._request("GET", "/api/v2/roles", params=params)
        if isinstance(body, list):
            return {"roles": body}
        if isinstance(body, dict):
            return {"roles": body.get("roles") or []}
        return {"roles": []}

    def get_role_permissions(self, role_id: str) -> List[Dict[str, Any]]:
        if not role_id:
            raise ValueError("role_id is required")
        body = self._request("GET", f"/api/v2/roles/{role_id}/permissions")
        if isinstance(body, list):
            return body
        if isinstance(body, dict):
            return body.get("permissions") or []
        return []

    # ----------------------------------------------------------- lifecycle

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine: Optional[Auth0Engine] = None
_engine_lock = threading.Lock()


def get_auth0_engine(
    domain: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> Auth0Engine:
    """Return the process-wide singleton, building it on first call.

    The first caller may inject ``domain``, ``client_id``, ``client_secret``,
    or ``client`` for testing. Subsequent calls ignore those args. Use
    :func:`reset_auth0_engine` between tests to rebuild with new injections.
    """
    global _engine  # noqa: PLW0603
    with _engine_lock:
        if _engine is None:
            _engine = Auth0Engine(
                domain=domain,
                client_id=client_id,
                client_secret=client_secret,
                client=client,
            )
        return _engine


def reset_auth0_engine() -> None:
    """Drop the singleton (testing helper)."""
    global _engine  # noqa: PLW0603
    with _engine_lock:
        if _engine is not None:
            try:
                _engine.close()
            except Exception:  # noqa: BLE001
                pass
        _engine = None


__all__ = [
    "Auth0Engine",
    "Auth0UnavailableError",
    "get_auth0_engine",
    "reset_auth0_engine",
]
