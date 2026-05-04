"""CyberArk PAM (PVWA REST) Engine — ALDECI.

Wraps the CyberArk Password Vault Web Access (PVWA) HTTP API and exposes a
process-wide singleton.

Configuration (env)
-------------------
  CYBERARK_URL        Base URL of the PVWA server
                      (e.g. https://pvwa.example.com — no trailing slash needed)
  CYBERARK_USERNAME   Vault user used for /Logon
  CYBERARK_PASSWORD   Password (or API key) for /Logon
  CYBERARK_VERIFY_SSL Optional ("0"/"false" disables TLS verification — CyberArk
                      lab installs frequently ship with self-signed certs).

Two-phase auth
--------------
  1. POST /PasswordVault/API/auth/Cyberark/Logon  (username, password,
     concurrentSession?) -> raw quoted JSON string token.
  2. Subsequent calls send ``Authorization: <token>`` header. Token is cached
     in-process for ~30 minutes (CyberArk default). ``logoff()`` invalidates.

NO MOCKS rule
-------------
When ``CYBERARK_URL``, ``CYBERARK_USERNAME`` or ``CYBERARK_PASSWORD`` is unset
the engine is still constructible (capability summary still renders) but every
live call raises ``CyberArkPAMUnavailableError`` which the router translates
to HTTP 503 with ``status="unavailable"``. We never fabricate accounts, safes,
sessions or recordings. There is no SQLite cache.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0
DEFAULT_TOKEN_TTL_SECONDS = 25 * 60  # CyberArk session timeout default ~30 min


class CyberArkPAMUnavailableError(RuntimeError):
    """Raised when CyberArk env is not configured or PVWA returned an unrecoverable error."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class CyberArkPAMEngine:
    """Thread-safe CyberArk PVWA REST client. No SQLite cache."""

    def __init__(
        self,
        cyberark_url: Optional[str] = None,
        cyberark_username: Optional[str] = None,
        cyberark_password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
    ) -> None:
        self._explicit_url = cyberark_url
        self._explicit_user = cyberark_username
        self._explicit_pass = cyberark_password
        self._explicit_verify = verify_ssl
        self._timeout = timeout
        self._token_ttl = token_ttl_seconds
        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                timeout=timeout, verify=self._verify_setting()
            )
            self._owns_client = True
        self._lock = threading.RLock()
        self._cached_token: Optional[str] = None
        self._token_acquired_at: float = 0.0

    # ---------------------------------------------------------------- env

    def cyberark_url(self) -> Optional[str]:
        v = self._explicit_url or os.environ.get("CYBERARK_URL")
        if not v:
            return None
        v = v.strip()
        return v.rstrip("/") if v else None

    def cyberark_username(self) -> Optional[str]:
        v = self._explicit_user or os.environ.get("CYBERARK_USERNAME")
        return v.strip() if v else None

    def cyberark_password(self) -> Optional[str]:
        v = self._explicit_pass or os.environ.get("CYBERARK_PASSWORD")
        return v if v else None

    def cyberark_url_present(self) -> bool:
        return bool(self.cyberark_url())

    def cyberark_username_present(self) -> bool:
        return bool(self.cyberark_username())

    def cyberark_password_present(self) -> bool:
        return bool(self.cyberark_password())

    def _verify_setting(self) -> bool:
        if self._explicit_verify is not None:
            return bool(self._explicit_verify)
        v = os.environ.get("CYBERARK_VERIFY_SSL")
        if v is None:
            return False  # CyberArk often self-signed — default off
        return v.strip().lower() not in {"0", "false", "no", "off"}

    # ------------------------------------------------------------ helpers

    def _ensure_available(self) -> None:
        if not self.cyberark_url_present():
            raise CyberArkPAMUnavailableError(
                "CYBERARK_URL unset — configure the PVWA server URL to enable CyberArk PAM."
            )
        if not self.cyberark_username_present():
            raise CyberArkPAMUnavailableError(
                "CYBERARK_USERNAME unset — configure a vault user to enable CyberArk PAM."
            )
        if not self.cyberark_password_present():
            raise CyberArkPAMUnavailableError(
                "CYBERARK_PASSWORD unset — configure a vault password to enable CyberArk PAM."
            )

    def _url(self, path: str) -> str:
        addr = self.cyberark_url() or ""
        if not path.startswith("/"):
            path = "/" + path
        return addr + path

    def _check_response(self, resp: Any) -> Any:
        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            # Invalidate cached token so next call re-logons.
            with self._lock:
                self._cached_token = None
                self._token_acquired_at = 0.0
            raise CyberArkPAMUnavailableError(
                f"CyberArk rejected token ({sc})."
            )
        if sc == 404:
            raise CyberArkPAMUnavailableError("CyberArk path not found (404).")
        if sc >= 500:
            raise CyberArkPAMUnavailableError(
                f"CyberArk upstream error ({sc}): {getattr(resp, 'text', '')[:200]}"
            )
        if sc >= 400:
            raise CyberArkPAMUnavailableError(
                f"CyberArk client error ({sc}): {getattr(resp, 'text', '')[:200]}"
            )
        # 204 No Content
        if sc == 204:
            return None
        try:
            return resp.json()
        except Exception as exc:
            raise CyberArkPAMUnavailableError(
                f"CyberArk returned non-JSON payload: {exc}"
            ) from exc

    # --------------------------------------------------------- auth (token)

    def logon(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        concurrent_session: Optional[bool] = None,
    ) -> str:
        """``POST /PasswordVault/API/auth/Cyberark/Logon`` — returns raw quoted token string.

        CyberArk's PVWA logon endpoint returns the session token as a JSON
        string literal, e.g. ``"eyJhbG..."``. We preserve the quoted form so
        callers can use the value directly in the ``Authorization`` header
        per CyberArk docs.
        """
        self._ensure_available()
        u = (username or self.cyberark_username() or "").strip()
        p = password if password is not None else (self.cyberark_password() or "")
        if not u or not p:
            raise CyberArkPAMUnavailableError(
                "username/password required for CyberArk logon."
            )
        body: Dict[str, Any] = {"username": u, "password": p}
        if concurrent_session is not None:
            body["concurrentSession"] = bool(concurrent_session)
        try:
            resp = self._client.post(
                self._url("/PasswordVault/API/auth/Cyberark/Logon"),
                json=body,
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise CyberArkPAMUnavailableError(
                f"CyberArk HTTP error during logon: {exc}"
            ) from exc
        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            raise CyberArkPAMUnavailableError(
                f"CyberArk logon rejected ({sc})."
            )
        if sc >= 400:
            raise CyberArkPAMUnavailableError(
                f"CyberArk logon failed ({sc}): {getattr(resp, 'text', '')[:200]}"
            )
        text = (getattr(resp, "text", "") or "").strip()
        if not text:
            try:
                token_val = resp.json()
            except Exception as exc:
                raise CyberArkPAMUnavailableError(
                    f"CyberArk logon returned empty body: {exc}"
                ) from exc
            text = '"' + str(token_val) + '"'
        # If the body is bare (no quotes), re-wrap so it matches CyberArk's contract.
        if not (text.startswith('"') and text.endswith('"')):
            text = '"' + text.strip('"') + '"'
        with self._lock:
            self._cached_token = text
            self._token_acquired_at = time.time()
        return text

    def logoff(self) -> None:
        """``POST /PasswordVault/API/auth/Logoff`` — invalidates token."""
        self._ensure_available()
        token = self._token()
        try:
            resp = self._client.post(
                self._url("/PasswordVault/API/auth/Logoff"),
                headers={"Authorization": token, "Content-Type": "application/json"},
                json={},
            )
        except httpx.HTTPError as exc:
            raise CyberArkPAMUnavailableError(
                f"CyberArk HTTP error during logoff: {exc}"
            ) from exc
        sc = getattr(resp, "status_code", 0)
        with self._lock:
            self._cached_token = None
            self._token_acquired_at = 0.0
        if sc not in (200, 204):
            raise CyberArkPAMUnavailableError(
                f"CyberArk logoff failed ({sc}): {getattr(resp, 'text', '')[:200]}"
            )

    def _token(self) -> str:
        """Return cached token or call logon() to get a fresh one."""
        with self._lock:
            now = time.time()
            if (
                self._cached_token
                and (now - self._token_acquired_at) < self._token_ttl
            ):
                return self._cached_token
        return self.logon()

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "Authorization": self._token(),
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------ HTTP

    def _http_get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        try:
            resp = self._client.get(
                self._url(path),
                params=params or {},
                headers=self._auth_headers(),
            )
        except httpx.HTTPError as exc:
            raise CyberArkPAMUnavailableError(
                f"CyberArk HTTP error: {exc}"
            ) from exc
        return self._check_response(resp)

    def _http_post(
        self, path: str, body: Optional[Dict[str, Any]] = None
    ) -> Any:
        try:
            resp = self._client.post(
                self._url(path),
                json=body or {},
                headers=self._auth_headers(),
            )
        except httpx.HTTPError as exc:
            raise CyberArkPAMUnavailableError(
                f"CyberArk HTTP error: {exc}"
            ) from exc
        return self._check_response(resp)

    # ------------------------------------------------------- normalisers

    @staticmethod
    def _norm_secret_management(sm: Any) -> Dict[str, Any]:
        sm = sm or {}
        return {
            "automaticManagementEnabled": bool(sm.get("automaticManagementEnabled", False)),
            "status": sm.get("status", ""),
            "lastModifiedTime": sm.get("lastModifiedTime", 0),
            "lastReconciledTime": sm.get("lastReconciledTime", 0),
            "lastVerifiedTime": sm.get("lastVerifiedTime", 0),
        }

    @staticmethod
    def _norm_remote_machines(rm: Any) -> Dict[str, Any]:
        rm = rm or {}
        return {
            "remoteMachines": rm.get("remoteMachines", ""),
            "accessRestrictedToRemoteMachines": bool(
                rm.get("accessRestrictedToRemoteMachines", False)
            ),
        }

    @classmethod
    def _norm_account(cls, a: Any) -> Dict[str, Any]:
        a = a or {}
        return {
            "id": a.get("id", ""),
            "name": a.get("name", ""),
            "address": a.get("address", ""),
            "userName": a.get("userName", ""),
            "platformId": a.get("platformId", ""),
            "safeName": a.get("safeName", ""),
            "secretType": a.get("secretType", ""),
            "secretManagement": cls._norm_secret_management(
                a.get("secretManagement")
            ),
            "platformAccountProperties": a.get("platformAccountProperties") or {},
            "createdTime": a.get("createdTime", 0),
            "categoryModificationTime": a.get("categoryModificationTime", 0),
            "secretMode": a.get("secretMode") or {},
            "remoteMachinesAccess": cls._norm_remote_machines(
                a.get("remoteMachinesAccess")
            ),
            "status": a.get("status", ""),
            "owners": list(a.get("owners") or []),
        }

    @staticmethod
    def _norm_creator(c: Any) -> Dict[str, Any]:
        c = c or {}
        return {"id": c.get("id", ""), "name": c.get("name", "")}

    @classmethod
    def _norm_safe(cls, s: Any) -> Dict[str, Any]:
        s = s or {}
        return {
            "safeUrlId": s.get("safeUrlId", ""),
            "safeName": s.get("safeName", ""),
            "safeNumber": int(s.get("safeNumber", 0) or 0),
            "description": s.get("description", ""),
            "location": s.get("location", ""),
            "creator": cls._norm_creator(s.get("creator")),
            "olacEnabled": bool(s.get("olacEnabled", False)),
            "managingCPM": s.get("managingCPM", ""),
            "numberOfVersionsRetention": int(
                s.get("numberOfVersionsRetention", 0) or 0
            ),
            "numberOfDaysRetention": int(s.get("numberOfDaysRetention", 0) or 0),
            "autoPurgeEnabled": bool(s.get("autoPurgeEnabled", False)),
            "creationTime": s.get("creationTime", 0),
            "lastModificationTime": s.get("lastModificationTime", 0),
            "accounts": list(s.get("accounts") or []),
        }

    @staticmethod
    def _norm_session(sess: Any) -> Dict[str, Any]:
        sess = sess or {}
        return {
            "sessionID": sess.get("sessionID", ""),
            "safeName": sess.get("safeName", ""),
            "accountID": sess.get("accountID", ""),
            "user": sess.get("user", ""),
            "source": sess.get("source", ""),
            "target": sess.get("target", ""),
            "accountUsername": sess.get("accountUsername", ""),
            "accountAddress": sess.get("accountAddress", ""),
            "platform": sess.get("platform", ""),
            "connectionComponentID": sess.get("connectionComponentID", ""),
            "protocol": sess.get("protocol", ""),
            "applicativeUsername": sess.get("applicativeUsername", ""),
            "command": sess.get("command", ""),
            "accountVerificationStatus": sess.get(
                "accountVerificationStatus", ""
            ),
            "totalCommands": int(sess.get("totalCommands", 0) or 0),
            "completedCommands": int(sess.get("completedCommands", 0) or 0),
            "sessionDuration": int(sess.get("sessionDuration", 0) or 0),
            "startTime": sess.get("startTime", 0),
            "endTime": sess.get("endTime", 0),
            "riskScore": sess.get("riskScore", 0),
            "fromIP": sess.get("fromIP", ""),
            "ticketID": sess.get("ticketID", ""),
            "sessionGuid": sess.get("sessionGuid", ""),
        }

    # -------------------------------------------------------- public API

    def list_accounts(
        self,
        search: Optional[str] = None,
        filter: Optional[str] = None,  # noqa: A002
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        savedfilter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """``GET /PasswordVault/API/Accounts`` — paginated account list."""
        self._ensure_available()
        params: Dict[str, Any] = {}
        if search:
            params["search"] = search
        if filter:
            params["filter"] = filter
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        if sort:
            params["sort"] = sort
        if savedfilter:
            params["savedfilter"] = savedfilter
        body = self._http_get("/PasswordVault/API/Accounts", params=params) or {}
        items = [self._norm_account(a) for a in (body.get("value") or [])]
        return {
            "value": items,
            "count": int(body.get("count", len(items)) or 0),
            "nextLink": body.get("nextLink", ""),
        }

    def get_account(self, account_id: str) -> Dict[str, Any]:
        """``GET /PasswordVault/API/Accounts/{id}``"""
        self._ensure_available()
        if not account_id:
            raise ValueError("account_id is required.")
        body = self._http_get(
            f"/PasswordVault/API/Accounts/{quote(account_id, safe='')}"
        )
        return self._norm_account(body or {})

    def retrieve_password(
        self,
        account_id: str,
        reason: str,
        ticketing_system_name: Optional[str] = None,
        ticket_id: Optional[str] = None,
        version: Optional[int] = None,
        action_type: Optional[str] = None,
        is_use: Optional[bool] = None,
        machine: Optional[str] = None,
        use_double_auth: Optional[bool] = None,
    ) -> str:
        """``POST /PasswordVault/API/Accounts/{id}/Password/Retrieve``.

        Returns the raw quoted JSON string CyberArk emits — callers receive
        the password verbatim per CyberArk's API contract.
        """
        self._ensure_available()
        if not account_id:
            raise ValueError("account_id is required.")
        if not reason or not reason.strip():
            raise ValueError("reason is required for password retrieval.")
        body: Dict[str, Any] = {"reason": reason}
        if ticketing_system_name:
            body["ticketingSystemName"] = ticketing_system_name
        if ticket_id:
            body["ticketId"] = ticket_id
        if version is not None:
            body["version"] = int(version)
        if action_type:
            body["actionType"] = action_type
        if is_use is not None:
            body["isUse"] = bool(is_use)
        if machine:
            body["machine"] = machine
        if use_double_auth is not None:
            body["useDoubleAuth"] = bool(use_double_auth)
        path = (
            f"/PasswordVault/API/Accounts/"
            f"{quote(account_id, safe='')}/Password/Retrieve"
        )
        try:
            resp = self._client.post(
                self._url(path),
                json=body,
                headers=self._auth_headers(),
            )
        except httpx.HTTPError as exc:
            raise CyberArkPAMUnavailableError(
                f"CyberArk HTTP error during password retrieval: {exc}"
            ) from exc
        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            with self._lock:
                self._cached_token = None
                self._token_acquired_at = 0.0
            raise CyberArkPAMUnavailableError(
                f"CyberArk rejected password retrieval ({sc})."
            )
        if sc >= 400:
            raise CyberArkPAMUnavailableError(
                f"CyberArk password retrieval failed ({sc}): "
                f"{getattr(resp, 'text', '')[:200]}"
            )
        text = (getattr(resp, "text", "") or "").strip()
        if not text:
            raise CyberArkPAMUnavailableError(
                "CyberArk returned empty password body."
            )
        if not (text.startswith('"') and text.endswith('"')):
            text = '"' + text.strip('"') + '"'
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "asset.discovered",
                        {
                            "entity_id": account_id,
                            "type": "cyberark_credential_retrieval",
                            "severity": "high",
                            "source_engine": "cyberark_pam",
                            "reason": reason,
                        },
                    )
            except Exception:
                pass
        return text

    def list_safes(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        extended_details: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """``GET /PasswordVault/API/Safes``"""
        self._ensure_available()
        params: Dict[str, Any] = {}
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        if sort:
            params["sort"] = sort
        if search:
            params["search"] = search
        if extended_details is not None:
            params["extendedDetails"] = "true" if extended_details else "false"
        body = self._http_get("/PasswordVault/API/Safes", params=params) or {}
        items = [self._norm_safe(s) for s in (body.get("value") or [])]
        return {
            "value": items,
            "count": int(body.get("count", len(items)) or 0),
            "nextLink": body.get("nextLink", ""),
        }

    def list_safe_members(
        self,
        safe_url_id: str,
        search: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        filter: Optional[str] = None,  # noqa: A002
        member_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """``GET /PasswordVault/API/Safes/{safe_url_id}/Members``"""
        self._ensure_available()
        if not safe_url_id:
            raise ValueError("safe_url_id is required.")
        if member_type and member_type not in {"User", "Group", "Role"}:
            raise ValueError("memberType must be one of User|Group|Role.")
        params: Dict[str, Any] = {}
        if search:
            params["search"] = search
        if sort:
            params["sort"] = sort
        if offset is not None:
            params["offset"] = int(offset)
        if limit is not None:
            params["limit"] = int(limit)
        if filter:
            params["filter"] = filter
        if member_type:
            params["memberType"] = member_type
        body = self._http_get(
            f"/PasswordVault/API/Safes/{quote(safe_url_id, safe='')}/Members",
            params=params,
        ) or {}
        members = list(body.get("value") or [])
        return {
            "value": members,
            "count": int(body.get("count", len(members)) or 0),
            "nextLink": body.get("nextLink", ""),
        }

    def list_psm_sessions(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        search: Optional[str] = None,
        sort: Optional[str] = None,
        filter: Optional[str] = None,  # noqa: A002
    ) -> Dict[str, Any]:
        """``GET /PasswordVault/API/PSM/Sessions``"""
        self._ensure_available()
        params: Dict[str, Any] = {}
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        if search:
            params["search"] = search
        if sort:
            params["sort"] = sort
        if filter:
            params["filter"] = filter
        body = self._http_get(
            "/PasswordVault/API/PSM/Sessions", params=params
        ) or {}
        items = [self._norm_session(s) for s in (body.get("value") or [])]
        return {"value": items}

    def list_psm_recordings(
        self,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        search: Optional[str] = None,
    ) -> Dict[str, Any]:
        """``GET /PasswordVault/API/PSM/Recordings``"""
        self._ensure_available()
        params: Dict[str, Any] = {}
        if from_date:
            params["fromDate"] = from_date
        if to_date:
            params["toDate"] = to_date
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        if search:
            params["search"] = search
        body = self._http_get(
            "/PasswordVault/API/PSM/Recordings", params=params
        ) or {}
        items: List[Dict[str, Any]] = list(body.get("value") or body.get("Recordings") or [])
        return {"value": items}

    # ------------------------------------------------------------- close

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_engine_lock = threading.Lock()
_engine_instance: Optional[CyberArkPAMEngine] = None


def get_cyberark_pam_engine(
    cyberark_url: Optional[str] = None,
    cyberark_username: Optional[str] = None,
    cyberark_password: Optional[str] = None,
    verify_ssl: Optional[bool] = None,
    client: Optional[httpx.Client] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
) -> CyberArkPAMEngine:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = CyberArkPAMEngine(
                cyberark_url=cyberark_url,
                cyberark_username=cyberark_username,
                cyberark_password=cyberark_password,
                verify_ssl=verify_ssl,
                client=client,
                timeout=timeout,
                token_ttl_seconds=token_ttl_seconds,
            )
        return _engine_instance


def reset_cyberark_pam_engine() -> None:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is not None:
            _engine_instance.close()
        _engine_instance = None
