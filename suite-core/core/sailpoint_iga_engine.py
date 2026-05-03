"""SailPoint IdentityNow IGA — REAL OAuth2 client_credentials REST API client.

NEW — 2026-05-04. Live counterpart for the ``/api/v1/sailpoint-iga``
router. Exposes the documented IdentityNow v3 surface 1:1 so consumers
can read Identities / Access Profiles / Roles / Certification Campaigns /
Access Requests directly.

Endpoints (all prefixed with the IdentityNow tenant base URL, e.g.
``https://acme.api.identitynow.com``):

  GET  /v3/identities                          list identities
  GET  /v3/identities/{identity_id}            single identity
  GET  /v3/identities/{identity_id}/account-summary  identity accounts
  GET  /v3/access-profiles                     list access profiles
  GET  /v3/roles                               list roles
  GET  /v3/certification-campaigns             list campaigns
  GET  /v3/access-requests                     list access requests

Required env vars
-----------------
    SAILPOINT_TENANT_URL    Full base URL — e.g.
                            ``https://acme.api.identitynow.com``.
                            Trailing slash optional.
    SAILPOINT_CLIENT_ID     OAuth2 client ID (PAT or service identity).
    SAILPOINT_CLIENT_SECRET OAuth2 client secret.

OAuth2 flow
-----------
``POST {SAILPOINT_TENANT_URL}/oauth/token`` with form body
``grant_type=client_credentials&client_id=...&client_secret=...``.
Response gives ``access_token`` + ``expires_in`` (seconds — typically
43200 / 12h). We cache the token in-memory and refresh shortly before
expiry. NO SQLite cache.

NO MOCKS rule
-------------
* If any of the three env vars is unset the engine reports
  ``credentials_present()=False`` and every live call raises
  ``SailPointUnavailableError`` (router translates to HTTP 503).
* No fabricated identities / access profiles / roles / campaigns /
  access requests — ever.
* Pure HTTP passthrough — no SQLite cache.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0
# Refresh slightly before real expiry so we don't get caught mid-request.
TOKEN_REFRESH_SKEW_SEC = 60.0


class SailPointUnavailableError(RuntimeError):
    """Raised when SailPoint creds are missing or upstream call fails."""


def _normalize_tenant_url(raw: Optional[str]) -> Optional[str]:
    """Accept ``https://acme.api.identitynow.com`` (with optional trailing
    slash). Returns the URL with trailing slashes stripped, or None if
    blank.
    """
    if not raw:
        return None
    raw = raw.strip()
    if not raw:
        return None
    return raw.rstrip("/") or None


class SailPointIGAEngine:
    """Live SailPoint IdentityNow REST API client.

    Stateless aside from the cached OAuth2 token. Designed to be used as
    a process-wide singleton via ``get_sailpoint_iga_engine()``.
    """

    def __init__(
        self,
        sailpoint_tenant_url: Optional[str] = None,
        sailpoint_client_id: Optional[str] = None,
        sailpoint_client_secret: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._tenant_url = _normalize_tenant_url(
            sailpoint_tenant_url
            if sailpoint_tenant_url is not None
            else os.getenv("SAILPOINT_TENANT_URL")
        )
        self._client_id = (
            sailpoint_client_id
            if sailpoint_client_id is not None
            else os.getenv("SAILPOINT_CLIENT_ID")
        )
        self._client_secret = (
            sailpoint_client_secret
            if sailpoint_client_secret is not None
            else os.getenv("SAILPOINT_CLIENT_SECRET")
        )
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._lock = threading.RLock()
        # OAuth2 token cache.
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------
    # Public introspection
    # ------------------------------------------------------------------
    def tenant_url_present(self) -> bool:
        return bool(self._tenant_url)

    def client_id_present(self) -> bool:
        return bool(self._client_id and str(self._client_id).strip())

    def client_secret_present(self) -> bool:
        return bool(self._client_secret and str(self._client_secret).strip())

    def credentials_present(self) -> bool:
        return (
            self.tenant_url_present()
            and self.client_id_present()
            and self.client_secret_present()
        )

    def base_url(self) -> Optional[str]:
        return self._tenant_url

    # ------------------------------------------------------------------
    # OAuth2 token plumbing
    # ------------------------------------------------------------------
    def _ensure_creds(self) -> None:
        if not self.credentials_present():
            raise SailPointUnavailableError(
                "SAILPOINT_TENANT_URL, SAILPOINT_CLIENT_ID and "
                "SAILPOINT_CLIENT_SECRET must be set"
            )

    def _token_valid(self) -> bool:
        return bool(
            self._access_token
            and time.time() < (self._token_expires_at - TOKEN_REFRESH_SKEW_SEC)
        )

    def _fetch_token(self) -> str:
        """POST /oauth/token to mint a fresh client_credentials token."""
        self._ensure_creds()
        url = f"{self._tenant_url}/oauth/token"
        form = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        try:
            resp = self._client.post(url, data=form)
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover
            raise SailPointUnavailableError(
                f"OAuth2 token fetch failed: {exc}"
            ) from exc
        status = getattr(resp, "status_code", 500)
        if status >= 400:
            text = (getattr(resp, "text", "") or "")[:300]
            raise SailPointUnavailableError(
                f"/oauth/token returned {status}: {text}"
            )
        try:
            payload = resp.json()
        except (ValueError, TypeError) as exc:
            raise SailPointUnavailableError(
                f"/oauth/token returned non-JSON: {exc}"
            ) from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not token:
            raise SailPointUnavailableError(
                "/oauth/token response missing access_token"
            )
        # ``expires_in`` is in seconds; default to 12h if absent.
        expires_in = (
            payload.get("expires_in", 43200) if isinstance(payload, dict) else 43200
        )
        try:
            expires_in_f = float(expires_in)
        except (TypeError, ValueError):
            expires_in_f = 43200.0
        self._access_token = str(token)
        self._token_expires_at = time.time() + expires_in_f
        return self._access_token

    def _get_token(self) -> str:
        with self._lock:
            if self._token_valid():
                return self._access_token  # type: ignore[return-value]
            return self._fetch_token()

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        self._ensure_creds()
        url = f"{self._tenant_url}{path}"
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            resp = self._client.get(
                url, params=clean_params, headers=self._headers()
            )
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover
            raise SailPointUnavailableError(f"GET {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    @staticmethod
    def _unwrap(resp: Any, path: str) -> Any:
        status = getattr(resp, "status_code", 500)
        if status >= 400:
            text = (getattr(resp, "text", "") or "")[:300]
            raise SailPointUnavailableError(f"{path} returned {status}: {text}")
        try:
            return resp.json()
        except (ValueError, TypeError) as exc:
            raise SailPointUnavailableError(
                f"{path} returned non-JSON: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Identities
    # ------------------------------------------------------------------
    def list_identities(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        filters: Optional[str] = None,
        sorters: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params = {
            "limit": limit,
            "offset": offset,
            "filters": filters,
            "sorters": sorters,
        }
        data = self._get("/v3/identities", params=params)
        return data if isinstance(data, list) else []

    def get_identity(self, identity_id: str) -> Dict[str, Any]:
        if not identity_id or not str(identity_id).strip():
            raise ValueError("identity_id is required")
        data = self._get(f"/v3/identities/{identity_id}")
        if not isinstance(data, dict):
            raise SailPointUnavailableError(
                "/v3/identities/{id} returned non-object payload"
            )
        return data

    def get_identity_account_summary(
        self, identity_id: str
    ) -> Dict[str, Any]:
        if not identity_id or not str(identity_id).strip():
            raise ValueError("identity_id is required")
        data = self._get(f"/v3/identities/{identity_id}/account-summary")
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return {"accounts": data}
        raise SailPointUnavailableError(
            "/v3/identities/{id}/account-summary returned unexpected payload"
        )

    # ------------------------------------------------------------------
    # Access profiles
    # ------------------------------------------------------------------
    def list_access_profiles(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        filters: Optional[str] = None,
        sorters: Optional[str] = None,
        for_subadmin: Optional[str] = None,
        include_deleted: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {
            "limit": limit,
            "offset": offset,
            "filters": filters,
            "sorters": sorters,
            "for-subadmin": for_subadmin,
        }
        if include_deleted is not None:
            params["include-deleted"] = "true" if include_deleted else "false"
        data = self._get("/v3/access-profiles", params=params)
        return data if isinstance(data, list) else []

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------
    def list_roles(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        filters: Optional[str] = None,
        sorters: Optional[str] = None,
        for_subadmin: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params = {
            "limit": limit,
            "offset": offset,
            "filters": filters,
            "sorters": sorters,
            "for-subadmin": for_subadmin,
        }
        data = self._get("/v3/roles", params=params)
        return data if isinstance(data, list) else []

    # ------------------------------------------------------------------
    # Certification campaigns
    # ------------------------------------------------------------------
    def list_certification_campaigns(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        filters: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params = {"limit": limit, "offset": offset, "filters": filters}
        data = self._get("/v3/certification-campaigns", params=params)
        return data if isinstance(data, list) else []

    # ------------------------------------------------------------------
    # Access requests
    # ------------------------------------------------------------------
    def list_access_requests(
        self,
        requested_for: Optional[str] = None,
        requested_by: Optional[str] = None,
        regarding_identity: Optional[str] = None,
        assigned_to: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        params = {
            "requested-for": requested_for,
            "requested-by": requested_by,
            "regarding-identity": regarding_identity,
            "assigned-to": assigned_to,
            "limit": limit,
            "offset": offset,
        }
        data = self._get("/v3/access-requests", params=params)
        return data if isinstance(data, list) else []

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
_singleton: Optional[SailPointIGAEngine] = None
_singleton_lock = threading.Lock()


def get_sailpoint_iga_engine(
    sailpoint_tenant_url: Optional[str] = None,
    sailpoint_client_id: Optional[str] = None,
    sailpoint_client_secret: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> SailPointIGAEngine:
    """Return the process-wide SailPointIGAEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SailPointIGAEngine(
                sailpoint_tenant_url=sailpoint_tenant_url,
                sailpoint_client_id=sailpoint_client_id,
                sailpoint_client_secret=sailpoint_client_secret,
                client=client,
            )
        return _singleton


def reset_sailpoint_iga_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "SailPointIGAEngine",
    "SailPointUnavailableError",
    "get_sailpoint_iga_engine",
    "reset_sailpoint_iga_engine",
]
