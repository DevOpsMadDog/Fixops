"""
Zscaler ZIA (Zscaler Internet Access) Engine — ALDECI.

Wraps Zscaler ZIA's REST surfaces under a single in-process engine. Two-phase
auth: first POST /authenticatedSession with an obfuscated API key derived
from the API_KEY string and the current millisecond timestamp, second the
returned JSESSIONID cookie is reused (cached ~30 min) on subsequent calls.

Endpoint coverage
-----------------
* POST   /api/v1/authenticatedSession        — login (cookie-based session)
* DELETE /api/v1/authenticatedSession        — logout
* GET    /api/v1/sandbox/report/{md5}?details=summary|full
* GET    /api/v1/urlCategories?customOnly=&includeOnlyUrlKeywordCounts=&includeIcap=
* GET    /api/v1/firewallFilteringRules
* GET    /api/v1/users?name=&dept=&group=&page=&pageSize=
* GET    /api/v1/locations?search=&page=&pageSize=

Auth
----
4-element creds: ZSCALER_ZIA_BASE_URL, ZSCALER_ZIA_USERNAME,
ZSCALER_ZIA_PASSWORD, ZSCALER_ZIA_API_KEY.

API key obfuscation (per Zscaler docs):
    1. ms_ts  = str(int(time.time() * 1000))
    2. n      = ms_ts[-6:]
    3. r      = str(int(n) >> 1).zfill(6)
    4. key    = "" + for i in n: key += API_KEY[int(i)]
                    + for i in r: key += API_KEY[int(i) + 2]
    5. POST {timestamp: ms_ts, apiKey: key, username, password} → JSESSIONID

Cache
-----
NO SQLite cache. Session cookie is held in-memory with a soft TTL (~30 min).
Re-login transparently when the cookie expires or is rejected.

NO MOCKS rule
-------------
* If any of the four env vars is unset:
    - Live endpoints raise ZscalerZIAUnavailableError → router HTTP 503.
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Zscaler ZIA.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0
SESSION_TTL_SECONDS = 30 * 60  # Zscaler default: ~30 min
DEFAULT_USER_AGENT = "ALDECI-ZIA-Connector/1.0"


class ZscalerZIAUnavailableError(RuntimeError):
    """Raised when ZIA creds are missing, network failed, or upstream returned
    an unrecoverable status."""


# ---------------------------------------------------------------------------
# API key obfuscation — Zscaler's official scheme
# ---------------------------------------------------------------------------


def obfuscate_api_key(api_key: str, timestamp_ms: Optional[str] = None) -> Dict[str, str]:
    """Return ``{"obfuscatedKey": str, "timestamp": str}`` per Zscaler spec.

    Algorithm:
      1. ts = current ms (or supplied)
      2. n  = ts[-6:]                      # last 6 chars
      3. r  = str(int(n) >> 1).zfill(6)    # bit-shift right by 1, zero-padded
      4. key  = ""
         for i in n: key += api_key[int(i)]
         for i in r: key += api_key[int(i) + 2]
    """
    if not api_key or len(api_key) < 12:
        # Zscaler API keys are typically >= 12 chars. Anything shorter would
        # break the offset-character indexing below.
        raise ZscalerZIAUnavailableError(
            "ZSCALER_ZIA_API_KEY too short for obfuscation (need >= 12 chars)"
        )
    ts = timestamp_ms or str(int(time.time() * 1000))
    n = ts[-6:]
    try:
        r = str(int(n) >> 1).zfill(6)
    except ValueError as exc:
        raise ZscalerZIAUnavailableError(
            f"timestamp suffix is not numeric: {n}"
        ) from exc
    key_chars: List[str] = []
    for ch in n:
        idx = int(ch)
        if idx >= len(api_key):
            raise ZscalerZIAUnavailableError(
                f"API key index {idx} out of range (len={len(api_key)})"
            )
        key_chars.append(api_key[idx])
    for ch in r:
        idx = int(ch) + 2
        if idx >= len(api_key):
            raise ZscalerZIAUnavailableError(
                f"API key index {idx} out of range (len={len(api_key)})"
            )
        key_chars.append(api_key[idx])
    return {"obfuscatedKey": "".join(key_chars), "timestamp": ts}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ZscalerZIAEngine:
    """Thread-safe ZIA REST client with cookie-based session caching."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        session_ttl_seconds: int = SESSION_TTL_SECONDS,
    ) -> None:
        self._explicit_base_url = base_url
        self._explicit_username = username
        self._explicit_password = password
        self._explicit_api_key = api_key

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._session_ttl = session_ttl_seconds

        self._lock = threading.RLock()
        self._jsessionid: Optional[str] = None
        self._session_expires_at: float = 0.0

    # ----------------------------------------------------------- creds

    def _base_url(self) -> Optional[str]:
        return self._explicit_base_url or os.environ.get("ZSCALER_ZIA_BASE_URL") or None

    def _username(self) -> Optional[str]:
        return self._explicit_username or os.environ.get("ZSCALER_ZIA_USERNAME") or None

    def _password(self) -> Optional[str]:
        return self._explicit_password or os.environ.get("ZSCALER_ZIA_PASSWORD") or None

    def _api_key(self) -> Optional[str]:
        return self._explicit_api_key or os.environ.get("ZSCALER_ZIA_API_KEY") or None

    def base_url_present(self) -> bool:
        return bool(self._base_url())

    def username_present(self) -> bool:
        return bool(self._username())

    def password_present(self) -> bool:
        return bool(self._password())

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def creds_complete(self) -> bool:
        return (
            self.base_url_present()
            and self.username_present()
            and self.password_present()
            and self.api_key_present()
        )

    # --------------------------------------------------------- url

    def _build_url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        base = self._base_url()
        if not base:
            raise ZscalerZIAUnavailableError("ZSCALER_ZIA_BASE_URL is not configured")
        # Normalize: strip trailing slash, ensure scheme
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        base = base.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        url = f"{base}{path}"
        if params:
            qs = urlencode(
                [
                    (k, _stringify_query(v))
                    for k, v in params.items()
                    if v is not None and v != ""
                ]
            )
            if qs:
                url = f"{url}?{qs}"
        return url

    # ------------------------------------------------------- session

    def _session_active(self) -> bool:
        return bool(self._jsessionid) and time.time() < self._session_expires_at

    def login(self) -> Dict[str, Any]:
        """POST /api/v1/authenticatedSession — returns parsed body + sets cookie."""
        if not self.creds_complete():
            raise self._missing_creds_error()
        with self._lock:
            api_key = self._api_key() or ""
            obf = obfuscate_api_key(api_key)
            body = {
                "apiKey": obf["obfuscatedKey"],
                "username": self._username() or "",
                "password": self._password() or "",
                "timestamp": obf["timestamp"],
            }
            url = self._build_url("/api/v1/authenticatedSession")
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": DEFAULT_USER_AGENT,
            }
            try:
                resp = self._client.post(url, headers=headers, json=body)
            except httpx.HTTPError as exc:
                raise ZscalerZIAUnavailableError(
                    f"Zscaler ZIA login failed: {exc}"
                ) from exc

            sc = getattr(resp, "status_code", 0)
            if sc in (401, 403):
                raise ZscalerZIAUnavailableError(
                    f"Zscaler ZIA rejected credentials (HTTP {sc})"
                )
            if sc >= 400:
                raise ZscalerZIAUnavailableError(
                    f"Zscaler ZIA login returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
                )

            jsess = _extract_jsessionid(resp)
            if not jsess:
                raise ZscalerZIAUnavailableError(
                    "Zscaler ZIA login did not return JSESSIONID cookie"
                )
            self._jsessionid = jsess
            self._session_expires_at = time.time() + self._session_ttl
            try:
                parsed = resp.json()
                if not isinstance(parsed, dict):
                    parsed = {}
            except ValueError:
                parsed = {}
            return {
                "authType": parsed.get("authType") or "ADMIN_LOGIN",
                "obfuscateApiKey": True,
            }

    def logout(self) -> Dict[str, Any]:
        """DELETE /api/v1/authenticatedSession — invalidates server-side session."""
        with self._lock:
            if not self._jsessionid:
                # Idempotent: nothing to do.
                return {"loggedOut": True}
            if not self.creds_complete():
                raise self._missing_creds_error()
            url = self._build_url("/api/v1/authenticatedSession")
            headers = self._auth_headers()
            try:
                resp = self._client.request("DELETE", url, headers=headers)
            except httpx.HTTPError as exc:
                # Best-effort: still clear local state.
                self._jsessionid = None
                self._session_expires_at = 0.0
                raise ZscalerZIAUnavailableError(
                    f"Zscaler ZIA logout failed: {exc}"
                ) from exc
            sc = getattr(resp, "status_code", 0)
            self._jsessionid = None
            self._session_expires_at = 0.0
            if sc >= 400 and sc not in (401, 403, 404):
                raise ZscalerZIAUnavailableError(
                    f"Zscaler ZIA logout returned HTTP {sc}"
                )
            return {"loggedOut": True}

    def _ensure_session(self) -> None:
        if self._session_active():
            return
        self.login()

    def _auth_headers(self) -> Dict[str, str]:
        h = {
            "Accept": "application/json",
            "User-Agent": DEFAULT_USER_AGENT,
        }
        if self._jsessionid:
            h["Cookie"] = f"JSESSIONID={self._jsessionid}"
        return h

    def _missing_creds_error(self) -> ZscalerZIAUnavailableError:
        missing: List[str] = []
        if not self.base_url_present():
            missing.append("ZSCALER_ZIA_BASE_URL")
        if not self.username_present():
            missing.append("ZSCALER_ZIA_USERNAME")
        if not self.password_present():
            missing.append("ZSCALER_ZIA_PASSWORD")
        if not self.api_key_present():
            missing.append("ZSCALER_ZIA_API_KEY")
        return ZscalerZIAUnavailableError(
            "Zscaler ZIA credentials missing: " + ",".join(missing)
        )

    # ------------------------------------------------------- request

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        retry_on_auth: bool = True,
    ) -> Any:
        if not self.creds_complete():
            raise self._missing_creds_error()
        self._ensure_session()
        url = self._build_url(path, params=params)
        headers = self._auth_headers()
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers)
            elif method.upper() == "POST":
                resp = self._client.post(url, headers=headers, json=json_body)
            elif method.upper() == "PUT":
                resp = self._client.put(url, headers=headers, json=json_body)
            elif method.upper() == "DELETE":
                resp = self._client.request("DELETE", url, headers=headers)
            else:
                raise ZscalerZIAUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise ZscalerZIAUnavailableError(
                f"Zscaler ZIA request failed: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            if retry_on_auth:
                # Session may have expired server-side; re-login + retry once.
                self._jsessionid = None
                self._session_expires_at = 0.0
                self.login()
                return self._request(
                    method,
                    path,
                    params=params,
                    json_body=json_body,
                    retry_on_auth=False,
                )
            raise ZscalerZIAUnavailableError(
                f"Zscaler ZIA rejected session (HTTP {sc})"
            )
        if sc == 404:
            # Some endpoints (sandbox report on unknown md5) legitimately 404
            # for callers — surface as upstream "not found" via 503-mappable
            # error so the router can decide.
            raise ZscalerZIAUnavailableError(
                f"Zscaler ZIA resource not found (HTTP 404): {path}"
            )
        if sc == 429:
            raise ZscalerZIAUnavailableError(
                "Zscaler ZIA rate-limit exceeded (HTTP 429)"
            )
        if sc == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": getattr(resp, "text", "")[:200]}
            raise ValueError(f"Zscaler ZIA validation error: {body}")
        if sc >= 400:
            raise ZscalerZIAUnavailableError(
                f"Zscaler ZIA returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise ZscalerZIAUnavailableError(
                f"Zscaler ZIA returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------- endpoints

    def sandbox_report(self, md5_hash: str, details: str = "summary") -> Dict[str, Any]:
        if not md5_hash or len(md5_hash) != 32:
            raise ValueError("md5_hash must be a 32-character md5 digest")
        if details not in ("summary", "full"):
            raise ValueError("details must be 'summary' or 'full'")
        raw = self._request(
            "GET",
            f"/api/v1/sandbox/report/{md5_hash}",
            params={"details": details},
        )
        return self._normalize_sandbox_report(raw)

    def url_categories(
        self,
        custom_only: Optional[bool] = None,
        include_only_url_keyword_counts: Optional[bool] = None,
        include_icap: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if custom_only is not None:
            params["customOnly"] = _bool_str(custom_only)
        if include_only_url_keyword_counts is not None:
            params["includeOnlyUrlKeywordCounts"] = _bool_str(
                include_only_url_keyword_counts
            )
        if include_icap is not None:
            params["includeIcap"] = _bool_str(include_icap)
        raw = self._request("GET", "/api/v1/urlCategories", params=params or None)
        return self._normalize_url_categories(raw)

    def firewall_filtering_rules(self) -> List[Dict[str, Any]]:
        raw = self._request("GET", "/api/v1/firewallFilteringRules")
        return self._normalize_firewall_rules(raw)

    def users(
        self,
        name: Optional[str] = None,
        dept: Optional[str] = None,
        group: Optional[str] = None,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if name:
            params["name"] = name
        if dept:
            params["dept"] = dept
        if group:
            params["group"] = group
        if page is not None:
            params["page"] = int(page)
        if page_size is not None:
            params["pageSize"] = int(page_size)
        raw = self._request("GET", "/api/v1/users", params=params or None)
        return self._normalize_users(raw)

    def locations(
        self,
        search: Optional[str] = None,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if search:
            params["search"] = search
        if page is not None:
            params["page"] = int(page)
        if page_size is not None:
            params["pageSize"] = int(page_size)
        raw = self._request("GET", "/api/v1/locations", params=params or None)
        return self._normalize_locations(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_sandbox_report(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        # Zscaler sandbox returns either a "Full Details" or "Summary" wrapper.
        full = raw.get("Full Details") if isinstance(raw.get("Full Details"), dict) else None
        summary = raw.get("Summary") if isinstance(raw.get("Summary"), dict) else None
        # If "Full Details" present, the inner Summary lives there.
        inner = full or raw
        s = inner.get("Summary") if isinstance(inner.get("Summary"), dict) else (summary or {})
        c = inner.get("Classification") if isinstance(inner.get("Classification"), dict) else {}
        fp = (
            inner.get("FileProperties")
            if isinstance(inner.get("FileProperties"), dict)
            else {}
        )
        origin = inner.get("Origin") if isinstance(inner.get("Origin"), dict) else {}
        digital_sig = (
            inner.get("DigitalSignature")
            if isinstance(inner.get("DigitalSignature"), dict)
            else {}
        )
        return {
            "Summary": {
                "Status": s.get("Status") or "",
                "Category": s.get("Category") or "",
                "Score": s.get("Score") or 0,
                "FileType": s.get("FileType") or "",
                "StartTime": s.get("StartTime") or 0,
                "Duration": s.get("Duration") or 0,
            },
            "Classification": {
                "Type": c.get("Type") or "",
                "Category": c.get("Category") or "",
                "Score": c.get("Score") or 0,
                "DetectedMalware": c.get("DetectedMalware") or "",
            },
            "FileProperties": {
                "FileType": fp.get("FileType") or "",
                "FileSize": fp.get("FileSize") or 0,
                "MD5": fp.get("MD5") or "",
                "SHA1": fp.get("SHA1") or "",
                "SHA256": fp.get("SHA256") or "",
                "IssuerName": fp.get("IssuerName") or "",
                "RootCAVerified": bool(fp.get("RootCAVerified") or False),
                "ExtractionMime": fp.get("ExtractionMime") or "",
                "FileFamily": fp.get("FileFamily") or "",
            },
            "ConnectionsMade": list(inner.get("ConnectionsMade") or []),
            "DnsRequests": list(inner.get("DnsRequests") or []),
            "FilesCreated": list(inner.get("FilesCreated") or []),
            "FilesModified": list(inner.get("FilesModified") or []),
            "FilesDeleted": list(inner.get("FilesDeleted") or []),
            "RegistryChanges": list(inner.get("RegistryChanges") or []),
            "MutexesCreated": list(inner.get("MutexesCreated") or []),
            "ProcessesCreated": list(inner.get("ProcessesCreated") or []),
            "DigitalSignature": dict(digital_sig),
            "ReportSummary": inner.get("ReportSummary") or "",
            "Origin": {
                "Country": origin.get("Country") or "",
                "Risk": origin.get("Risk") or "",
                "ASN": origin.get("ASN") or 0,
                "ASNName": origin.get("ASNName") or "",
            },
        }

    @staticmethod
    def _normalize_url_categories(raw: Any) -> List[Dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        out: List[Dict[str, Any]] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            scopes_raw = entry.get("scopes") if isinstance(entry.get("scopes"), list) else []
            scopes_norm = []
            for sc in scopes_raw:
                if not isinstance(sc, dict):
                    continue
                scopes_norm.append(
                    {
                        "Type": sc.get("Type") or sc.get("scopeType") or "",
                        "ScopeGroupMemberEntities": list(
                            sc.get("ScopeGroupMemberEntities")
                            or sc.get("scopeGroupMemberEntities")
                            or []
                        ),
                        "ScopeEntities": list(
                            sc.get("ScopeEntities") or sc.get("scopeEntities") or []
                        ),
                    }
                )
            out.append(
                {
                    "id": entry.get("id") or "",
                    "configuredName": entry.get("configuredName") or "",
                    "urls": list(entry.get("urls") or []),
                    "dbCategorizedUrls": list(entry.get("dbCategorizedUrls") or []),
                    "type": entry.get("type") or "URL_CATEGORY",
                    "customCategory": bool(entry.get("customCategory") or False),
                    "scopes": scopes_norm,
                    "editable": bool(entry.get("editable") or False),
                    "description": entry.get("description") or "",
                    "customUrlsCount": entry.get("customUrlsCount") or 0,
                    "urlsRetainingParentCategoryCount": entry.get(
                        "urlsRetainingParentCategoryCount"
                    )
                    or 0,
                    "customIpRangesCount": entry.get("customIpRangesCount") or 0,
                    "ipRangesRetainingParentCategoryCount": entry.get(
                        "ipRangesRetainingParentCategoryCount"
                    )
                    or 0,
                    "ipRanges": list(entry.get("ipRanges") or []),
                    "ipRangesRetainingParentCategory": list(
                        entry.get("ipRangesRetainingParentCategory") or []
                    ),
                    "superCategory": entry.get("superCategory") or "",
                    "keywords": list(entry.get("keywords") or []),
                    "keywordsRetainingParentCategory": list(
                        entry.get("keywordsRetainingParentCategory") or []
                    ),
                }
            )
        return out

    @staticmethod
    def _normalize_firewall_rules(raw: Any) -> List[Dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        out: List[Dict[str, Any]] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "id": entry.get("id") or 0,
                    "name": entry.get("name") or "",
                    "order": entry.get("order") or 0,
                    "rank": entry.get("rank") or 0,
                    "action": entry.get("action") or "ALLOW",
                    "state": entry.get("state") or "ENABLED",
                    "defaultRule": bool(entry.get("defaultRule") or False),
                    "predefined": bool(entry.get("predefined") or False),
                    "srcIps": list(entry.get("srcIps") or []),
                    "destAddresses": list(entry.get("destAddresses") or []),
                    "destIpCategories": list(entry.get("destIpCategories") or []),
                    "destCountries": list(entry.get("destCountries") or []),
                    "srcIpGroups": list(entry.get("srcIpGroups") or []),
                    "destIpGroups": list(entry.get("destIpGroups") or []),
                    "departments": list(entry.get("departments") or []),
                    "users": list(entry.get("users") or []),
                    "groups": list(entry.get("groups") or []),
                    "appServices": list(entry.get("appServices") or []),
                    "appServiceGroups": list(entry.get("appServiceGroups") or []),
                    "srcIpv6Groups": list(entry.get("srcIpv6Groups") or []),
                    "destIpv6Groups": list(entry.get("destIpv6Groups") or []),
                    "description": entry.get("description") or "",
                    "lastModifiedTime": entry.get("lastModifiedTime") or 0,
                    "lastModifiedBy": entry.get("lastModifiedBy") or {},
                    "accessControl": entry.get("accessControl") or "READ_WRITE",
                }
            )
        return out

    @staticmethod
    def _normalize_users(raw: Any) -> List[Dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        out: List[Dict[str, Any]] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            groups_raw = entry.get("groups") if isinstance(entry.get("groups"), list) else []
            groups_norm = [
                {"id": g.get("id") or 0, "name": g.get("name") or ""}
                for g in groups_raw
                if isinstance(g, dict)
            ]
            dept = entry.get("department") if isinstance(entry.get("department"), dict) else {}
            out.append(
                {
                    "id": entry.get("id") or 0,
                    "name": entry.get("name") or "",
                    "email": entry.get("email") or "",
                    "groups": groups_norm,
                    "department": {
                        "id": dept.get("id") or 0,
                        "name": dept.get("name") or "",
                    },
                    "comments": entry.get("comments") or "",
                    "tempAuthEmail": entry.get("tempAuthEmail") or "",
                    "adminUser": bool(entry.get("adminUser") or False),
                    "type": entry.get("type") or "USER",
                }
            )
        return out

    @staticmethod
    def _normalize_locations(raw: Any) -> List[Dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        out: List[Dict[str, Any]] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "id": entry.get("id") or 0,
                    "name": entry.get("name") or "",
                    "parentId": entry.get("parentId") or 0,
                    "upBandwidth": entry.get("upBandwidth") or 0,
                    "dnBandwidth": entry.get("dnBandwidth") or 0,
                    "country": entry.get("country") or "",
                    "tz": entry.get("tz") or "",
                    "ipAddresses": list(entry.get("ipAddresses") or []),
                    "ports": list(entry.get("ports") or []),
                    "vpnCredentials": list(entry.get("vpnCredentials") or []),
                    "authRequired": bool(entry.get("authRequired") or False),
                    "sslScanEnabled": bool(entry.get("sslScanEnabled") or False),
                    "zappSSLScanEnabled": bool(entry.get("zappSSLScanEnabled") or False),
                    "xffForwardEnabled": bool(entry.get("xffForwardEnabled") or False),
                    "surrogateIP": bool(entry.get("surrogateIP") or False),
                    "idleTimeInMinutes": entry.get("idleTimeInMinutes") or 0,
                    "displayTimeUnit": entry.get("displayTimeUnit") or "MINUTE",
                    "surrogateIPEnforcedForKnownBrowsers": bool(
                        entry.get("surrogateIPEnforcedForKnownBrowsers") or False
                    ),
                    "surrogatePAC": bool(entry.get("surrogatePAC") or False),
                    "surrogateRefreshTimeInMinutes": entry.get(
                        "surrogateRefreshTimeInMinutes"
                    )
                    or 0,
                    "surrogateRefreshTimeUnit": entry.get("surrogateRefreshTimeUnit")
                    or "MINUTE",
                    "ofwEnabled": bool(entry.get("ofwEnabled") or False),
                    "ipsControl": bool(entry.get("ipsControl") or False),
                    "aupEnabled": bool(entry.get("aupEnabled") or False),
                    "cautionEnabled": bool(entry.get("cautionEnabled") or False),
                    "aupBlockInternetUntilAccepted": bool(
                        entry.get("aupBlockInternetUntilAccepted") or False
                    ),
                    "aupForceSslInspection": bool(
                        entry.get("aupForceSslInspection") or False
                    ),
                    "aupTimeoutInDays": entry.get("aupTimeoutInDays") or 0,
                    "profile": entry.get("profile") or "CORPORATE",
                    "description": entry.get("description") or "",
                }
            )
        return out

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bool_str(b: bool) -> str:
    return "true" if b else "false"


def _stringify_query(v: Any) -> str:
    if isinstance(v, bool):
        return _bool_str(v)
    return str(v)


def _extract_jsessionid(resp: Any) -> Optional[str]:
    """Pull JSESSIONID out of an httpx-style response.

    Handles both the structured ``cookies`` mapping and a raw
    ``Set-Cookie`` header (test stubs typically use the latter).
    """
    cookies = getattr(resp, "cookies", None)
    if cookies is not None:
        try:
            jsess = cookies.get("JSESSIONID")
            if jsess:
                return jsess
        except Exception:
            pass
    headers = getattr(resp, "headers", None) or {}
    set_cookie = ""
    if isinstance(headers, dict):
        set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    else:
        try:
            set_cookie = headers.get("set-cookie", "") or ""
        except Exception:
            set_cookie = ""
    if not set_cookie:
        return None
    # Set-Cookie may bundle multiple cookies; we just need JSESSIONID=...
    for piece in set_cookie.split(","):
        for kv in piece.split(";"):
            kv = kv.strip()
            if kv.upper().startswith("JSESSIONID="):
                return kv.split("=", 1)[1]
    return None


# --------------------------------------------------------------- singleton

_singleton: Optional[ZscalerZIAEngine] = None
_singleton_lock = threading.Lock()


def get_zscaler_zia_engine(
    base_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> ZscalerZIAEngine:
    """Return the process-wide ZscalerZIAEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ZscalerZIAEngine(
                base_url=base_url,
                username=username,
                password=password,
                api_key=api_key,
                client=client,
            )
        return _singleton


def reset_zscaler_zia_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "ZscalerZIAEngine",
    "ZscalerZIAUnavailableError",
    "obfuscate_api_key",
    "get_zscaler_zia_engine",
    "reset_zscaler_zia_engine",
]
