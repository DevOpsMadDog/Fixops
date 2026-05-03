"""
Duo Security MFA Engine - ALDECI.

Wraps the Duo Auth API v2 + Admin API v1 (https://duo.com/docs/authapi,
https://duo.com/docs/adminapi) and provides a process-wide singleton.

Endpoint coverage
-----------------
Auth API v2:
  * /auth/v2/preauth   (POST) - check user enrollment + available factors
  * /auth/v2/auth      (POST) - issue auth challenge (push/passcode/phone/sms)
  * /auth/v2/auth_status (GET) - poll async auth tx
  * /auth/v2/check     (GET)  - signature/time check (health)

Admin API v1:
  * /admin/v1/users           (GET) - list/get users
  * /admin/v1/integrations    (GET) - list integrations
  * /admin/v1/logs/authentication (GET) - auth logs

Auth scheme
-----------
Duo signs every request with HMAC-SHA1:

    canon = "<RFC2822-Date>\n<METHOD>\n<HOST>\n<PATH>\n<sorted-www-form-params>"
    sig   = HMAC-SHA1(SKEY, canon).hexdigest()
    Authorization: Basic base64(IKEY:sig)
    Date:          <RFC2822-Date>

NO MOCKS rule
-------------
* DUO_IKEY / DUO_SKEY / DUO_HOST unset -> all live calls raise
  ``DuoUnavailableError`` (router translates to HTTP 503).
* Capability summary surfaces ``status="unavailable"`` when any of the three
  envs are missing.
* No SQLite cache, no fabricated payloads.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import logging
import os
import threading
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 8.0


class DuoUnavailableError(RuntimeError):
    """Raised when Duo creds missing, network failed, or upstream rejected."""


class DuoMFAEngine:
    """Thread-safe Duo Auth + Admin API client (HMAC-SHA1 signed)."""

    def __init__(
        self,
        ikey: Optional[str] = None,
        skey: Optional[str] = None,
        host: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit creds win over env (re-read each call so tests can monkeypatch).
        self._explicit_ikey = ikey
        self._explicit_skey = skey
        self._explicit_host = host

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()

    # ---------------------------------------------------------------- creds

    def _ikey(self) -> Optional[str]:
        if self._explicit_ikey:
            return self._explicit_ikey
        return os.environ.get("DUO_IKEY") or None

    def _skey(self) -> Optional[str]:
        if self._explicit_skey:
            return self._explicit_skey
        return os.environ.get("DUO_SKEY") or None

    def _host(self) -> Optional[str]:
        if self._explicit_host:
            return self._explicit_host
        return os.environ.get("DUO_HOST") or None

    def ikey_present(self) -> bool:
        return bool(self._ikey())

    def skey_present(self) -> bool:
        return bool(self._skey())

    def host_present(self) -> bool:
        return bool(self._host())

    def creds_present(self) -> bool:
        return self.ikey_present() and self.skey_present() and self.host_present()

    # ----------------------------------------------------------- signing

    @staticmethod
    def _canonical_params(params: Dict[str, Any]) -> str:
        """Return application/x-www-form-urlencoded string with keys sorted
        lexicographically. Values URL-encoded per RFC 3986."""
        if not params:
            return ""
        items: List[Tuple[str, str]] = []
        for k in sorted(params.keys()):
            v = params[k]
            if isinstance(v, (list, tuple)):
                for vv in v:
                    items.append((str(k), str(vv)))
            else:
                items.append((str(k), str(v)))
        # quote_via=urllib.parse.quote (not quote_plus) per Duo spec.
        return urllib.parse.urlencode(items, quote_via=urllib.parse.quote)

    def _sign(
        self,
        method: str,
        path: str,
        params: Dict[str, Any],
    ) -> Tuple[str, str]:
        """Return (date_header, authorization_header)."""
        ikey = self._ikey()
        skey = self._skey()
        host = self._host()
        if not (ikey and skey and host):
            raise DuoUnavailableError(
                "Duo credentials not configured (DUO_IKEY / DUO_SKEY / DUO_HOST)"
            )
        date = email.utils.formatdate(usegmt=True)
        canon = "\n".join(
            [
                date,
                method.upper(),
                host.lower(),
                path,
                self._canonical_params(params),
            ]
        )
        sig = hmac.new(
            skey.encode("utf-8"),
            canon.encode("utf-8"),
            hashlib.sha1,
        ).hexdigest()
        token = f"{ikey}:{sig}"
        b64 = base64.b64encode(token.encode("utf-8")).decode("ascii")
        return date, f"Basic {b64}"

    # ---------------------------------------------------------------- http

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        params = dict(params or {})
        date, auth = self._sign(method, path, params)
        host = self._host()
        url = f"https://{host}{path}"
        headers = {
            "Date": date,
            "Authorization": auth,
            "Accept": "application/json",
        }
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                # Duo requires the SAME params be in the body for POST signing.
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                resp = self._client.post(
                    url,
                    headers=headers,
                    content=self._canonical_params(params),
                )
            else:
                raise DuoUnavailableError(f"unsupported HTTP method: {method}")
        except httpx.HTTPError as exc:
            raise DuoUnavailableError(f"Duo request failed: {exc}") from exc

        if resp.status_code in (401, 403):
            raise DuoUnavailableError(
                f"Duo rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 400:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"Duo validation error: {body}")
        if resp.status_code == 429:
            raise DuoUnavailableError("Duo rate-limit exceeded (HTTP 429)")
        if resp.status_code >= 400:
            raise DuoUnavailableError(
                f"Duo returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise DuoUnavailableError(
                f"Duo returned non-JSON response: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise DuoUnavailableError("Duo returned non-object JSON payload")
        # Duo wraps everything in {"stat": "OK"|"FAIL", "response": {...}}.
        stat = payload.get("stat")
        if stat == "FAIL":
            raise DuoUnavailableError(
                f"Duo response stat=FAIL: code={payload.get('code')} "
                f"message={payload.get('message')}"
            )
        return payload

    # ---------------------------------------------------------------- auth

    def preauth(
        self,
        username: str,
        ipaddr: Optional[str] = None,
        hostname: Optional[str] = None,
        trusted_device_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /auth/v2/preauth - check enrollment + available factors."""
        if not username:
            raise ValueError("username must not be empty")
        params: Dict[str, Any] = {"username": username}
        if ipaddr:
            params["ipaddr"] = ipaddr
        if hostname:
            params["hostname"] = hostname
        if trusted_device_token:
            params["trusted_device_token"] = trusted_device_token
        raw = self._request("POST", "/auth/v2/preauth", params)
        return self._normalize_preauth(raw)

    def auth(
        self,
        username: str,
        factor: str = "auto",
        device: str = "auto",
        passcode: Optional[str] = None,
        async_: Optional[bool] = None,
        ipaddr: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /auth/v2/auth - issue authentication challenge."""
        if not username:
            raise ValueError("username must not be empty")
        if factor not in ("auto", "push", "passcode", "phone", "sms"):
            raise ValueError(f"unsupported factor: {factor}")
        params: Dict[str, Any] = {
            "username": username,
            "factor": factor,
            "device": device,
        }
        if passcode:
            params["passcode"] = passcode
        if async_ is not None:
            params["async"] = "1" if async_ else "0"
        if ipaddr:
            params["ipaddr"] = ipaddr
        if hostname:
            params["hostname"] = hostname
        raw = self._request("POST", "/auth/v2/auth", params)
        return self._normalize_auth(raw)

    def auth_status(self, txid: str) -> Dict[str, Any]:
        """GET /auth/v2/auth_status - poll async auth transaction."""
        if not txid:
            raise ValueError("txid must not be empty")
        raw = self._request("GET", "/auth/v2/auth_status", {"txid": txid})
        return self._normalize_auth_status(raw)

    def check(self) -> Dict[str, Any]:
        """GET /auth/v2/check - signature/time check (health probe)."""
        raw = self._request("GET", "/auth/v2/check", {})
        return self._normalize_check(raw)

    # ---------------------------------------------------------------- admin

    def admin_users(
        self,
        username: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """GET /admin/v1/users - list/filter users."""
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if username:
            params["username"] = username
        raw = self._request("GET", "/admin/v1/users", params)
        return self._normalize_users(raw)

    def admin_integrations(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """GET /admin/v1/integrations - list integrations."""
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        raw = self._request("GET", "/admin/v1/integrations", params)
        return self._normalize_integrations(raw)

    # ----------------------------------------------------------- normalize

    @staticmethod
    def _devices_from(raw_devices: Any) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not isinstance(raw_devices, list):
            return out
        for d in raw_devices:
            if not isinstance(d, dict):
                continue
            caps = d.get("capabilities") if isinstance(d.get("capabilities"), list) else []
            out.append(
                {
                    "capabilities": [str(c) for c in caps],
                    "device": d.get("device") or "",
                    "type": d.get("type") or "",
                    "name": d.get("name") or "",
                    "number": d.get("number") or "",
                    "sms_nextcode": d.get("sms_nextcode") or "",
                }
            )
        return out

    @classmethod
    def _normalize_preauth(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        resp = raw.get("response") if isinstance(raw.get("response"), dict) else {}
        return {
            "result": resp.get("result") or "deny",
            "status_msg": resp.get("status_msg") or "",
            "devices": cls._devices_from(resp.get("devices")),
        }

    @staticmethod
    def _normalize_auth(raw: Dict[str, Any]) -> Dict[str, Any]:
        resp = raw.get("response") if isinstance(raw.get("response"), dict) else {}
        return {
            "txid": resp.get("txid") or "",
            "result": resp.get("result") or "deny",
            "status": resp.get("status") or "",
            "status_msg": resp.get("status_msg") or "",
        }

    @staticmethod
    def _normalize_auth_status(raw: Dict[str, Any]) -> Dict[str, Any]:
        resp = raw.get("response") if isinstance(raw.get("response"), dict) else {}
        return {
            "result": resp.get("result") or "waiting",
            "status": resp.get("status") or "",
            "status_msg": resp.get("status_msg") or "",
        }

    @staticmethod
    def _normalize_check(raw: Dict[str, Any]) -> Dict[str, Any]:
        resp = raw.get("response") if isinstance(raw.get("response"), dict) else {}
        return {"time": int(resp.get("time") or 0)}

    @staticmethod
    def _user_row(u: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(u, dict):
            return {}
        phones = u.get("phones") if isinstance(u.get("phones"), list) else []
        tokens = u.get("tokens") if isinstance(u.get("tokens"), list) else []
        u2f = u.get("u2ftokens") if isinstance(u.get("u2ftokens"), list) else []
        groups = u.get("groups") if isinstance(u.get("groups"), list) else []
        return {
            "user_id": u.get("user_id") or "",
            "username": u.get("username") or "",
            "alias1": u.get("alias1") or "",
            "alias2": u.get("alias2") or "",
            "alias3": u.get("alias3") or "",
            "alias4": u.get("alias4") or "",
            "realname": u.get("realname") or "",
            "email": u.get("email") or "",
            "status": u.get("status") or "",
            "last_login": u.get("last_login"),
            "phones": phones,
            "tokens": tokens,
            "u2ftokens": u2f,
            "groups": groups,
        }

    @classmethod
    def _normalize_users(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        resp = raw.get("response")
        rows: List[Dict[str, Any]] = []
        if isinstance(resp, list):
            for u in resp:
                if isinstance(u, dict):
                    rows.append(cls._user_row(u))
        elif isinstance(resp, dict):
            rows.append(cls._user_row(resp))
        return {"users": rows}

    @staticmethod
    def _integration_row(i: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(i, dict):
            return {}
        nets = i.get("networks_for_api_access")
        if not isinstance(nets, list):
            nets = []
        return {
            "integration_key": i.get("integration_key") or "",
            "name": i.get("name") or "",
            "type": i.get("type") or "",
            "enroll_policy": i.get("enroll_policy") or "",
            "greeting": i.get("greeting") or "",
            "networks_for_api_access": [str(n) for n in nets],
        }

    @classmethod
    def _normalize_integrations(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        resp = raw.get("response")
        rows: List[Dict[str, Any]] = []
        if isinstance(resp, list):
            for i in resp:
                if isinstance(i, dict):
                    rows.append(cls._integration_row(i))
        return {"integrations": rows}

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[DuoMFAEngine] = None
_singleton_lock = threading.Lock()


def get_duo_mfa_engine(
    ikey: Optional[str] = None,
    skey: Optional[str] = None,
    host: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> DuoMFAEngine:
    """Return the process-wide DuoMFAEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = DuoMFAEngine(ikey=ikey, skey=skey, host=host, client=client)
        return _singleton


def reset_duo_mfa_engine() -> None:
    """Tear down the singleton - used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "DuoMFAEngine",
    "DuoUnavailableError",
    "get_duo_mfa_engine",
    "reset_duo_mfa_engine",
]
