"""
Salt Security Engine — ALDECI.

Wraps Salt Security's REST API for API discovery + protection telemetry.

Endpoint coverage
-----------------
* Auth
    - POST /api/oauth/token                (client_credentials flow)
* API security telemetry
    - GET  /api/v1/incidents               (paged, filterable)
    - GET  /api/v1/api-catalog             (paged, filterable)
    - GET  /api/v1/api-catalog/{id}
    - GET  /api/v1/api-catalog/{id}/endpoints
    - GET  /api/v1/attackers               (paged via pageToken)
    - GET  /api/v1/policies

Auth
----
OAuth2 client_credentials at ``{SALT_API_BASE}/api/oauth/token``. Tokens are
cached in-process for ~50 minutes (stored expiry minus 60s safety) and
refreshed automatically on next call.

Cache
-----
NO SQLite cache (per task spec). Every call hits Salt live.

NO MOCKS rule
-------------
* If any of SALT_API_BASE / SALT_CLIENT_ID / SALT_CLIENT_SECRET is unset:
    - All live endpoints raise ``SaltUnavailableError`` (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Salt.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0
TOKEN_TTL_FALLBACK = 3600  # seconds
TOKEN_REFRESH_SAFETY = 60  # refresh 60s before expiry


class SaltUnavailableError(RuntimeError):
    """Raised when Salt creds are missing, network failed, or upstream
    returned an unrecoverable status."""


class SaltSecurityEngine:
    """Thread-safe Salt Security REST client (no on-disk cache)."""

    def __init__(
        self,
        api_base: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit values win over env (re-read each call so tests can monkeypatch).
        self._explicit_api_base = api_base
        self._explicit_client_id = client_id
        self._explicit_client_secret = client_secret

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()
        self._cached_token: Optional[str] = None
        self._cached_token_expires_at: float = 0.0

    # ----------------------------------------------------------- creds

    def _api_base(self) -> Optional[str]:
        base = self._explicit_api_base or os.environ.get("SALT_API_BASE") or None
        if base:
            base = base.rstrip("/")
        return base or None

    def _client_id(self) -> Optional[str]:
        return self._explicit_client_id or os.environ.get("SALT_CLIENT_ID") or None

    def _client_secret(self) -> Optional[str]:
        return (
            self._explicit_client_secret
            or os.environ.get("SALT_CLIENT_SECRET")
            or None
        )

    def api_base_present(self) -> bool:
        return bool(self._api_base())

    def client_id_present(self) -> bool:
        return bool(self._client_id())

    def client_secret_present(self) -> bool:
        return bool(self._client_secret())

    def creds_complete(self) -> bool:
        return (
            self.api_base_present()
            and self.client_id_present()
            and self.client_secret_present()
        )

    # ------------------------------------------------------------- token

    def _now(self) -> float:
        return time.time()

    def _ensure_creds(self) -> None:
        if not self.creds_complete():
            missing = []
            if not self.api_base_present():
                missing.append("SALT_API_BASE")
            if not self.client_id_present():
                missing.append("SALT_CLIENT_ID")
            if not self.client_secret_present():
                missing.append("SALT_CLIENT_SECRET")
            raise SaltUnavailableError(
                "Salt Security credentials missing: " + ",".join(missing)
            )

    def fetch_token(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        grant_type: str = "client_credentials",
    ) -> Dict[str, Any]:
        """Fetch a fresh token via client_credentials. Bypasses the cache."""
        self._ensure_creds()
        cid = client_id or self._client_id()
        cs = client_secret or self._client_secret()
        url = f"{self._api_base()}/api/oauth/token"
        body = {
            "client_id": cid,
            "client_secret": cs,
            "grant_type": grant_type,
        }
        try:
            resp = self._client.post(
                url,
                json=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise SaltUnavailableError(
                f"Salt token request failed: {exc}"
            ) from exc
        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            raise SaltUnavailableError(
                f"Salt rejected credentials (HTTP {sc})"
            )
        if sc >= 400:
            raise SaltUnavailableError(
                f"Salt token endpoint returned HTTP {sc}: "
                f"{getattr(resp, 'text', '')[:200]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise SaltUnavailableError(
                f"Salt token endpoint returned non-JSON: {exc}"
            ) from exc
        access_token = payload.get("access_token") or ""
        if not access_token:
            raise SaltUnavailableError(
                "Salt token response missing access_token"
            )
        expires_in = int(payload.get("expires_in") or TOKEN_TTL_FALLBACK)
        token_type = payload.get("token_type") or "Bearer"
        with self._lock:
            self._cached_token = access_token
            self._cached_token_expires_at = self._now() + max(
                0, expires_in - TOKEN_REFRESH_SAFETY
            )
        return {
            "access_token": access_token,
            "expires_in": expires_in,
            "token_type": token_type,
        }

    def _bearer(self) -> str:
        with self._lock:
            tok = self._cached_token
            exp = self._cached_token_expires_at
        if tok and self._now() < exp:
            return tok
        self.fetch_token()
        with self._lock:
            return self._cached_token or ""

    # --------------------------------------------------------- request

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._ensure_creds()
        url = f"{self._api_base()}{path}"
        token = self._bearer()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        if json_body is not None:
            headers["Content-Type"] = "application/json"

        # Drop None / empty params
        clean_params = (
            {k: v for k, v in params.items() if v is not None and v != ""}
            if params
            else None
        )

        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=clean_params)
            elif method.upper() == "POST":
                resp = self._client.post(
                    url, headers=headers, json=json_body, params=clean_params
                )
            else:
                raise SaltUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise SaltUnavailableError(
                f"Salt request failed: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            # Token may have expired between calls — invalidate cache once.
            with self._lock:
                self._cached_token = None
                self._cached_token_expires_at = 0.0
            raise SaltUnavailableError(
                f"Salt rejected credentials (HTTP {sc})"
            )
        if sc == 404:
            raise SaltUnavailableError(
                f"Salt resource not found (HTTP 404): {path}"
            )
        if sc == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": getattr(resp, "text", "")[:200]}
            raise ValueError(f"Salt validation error: {body}")
        if sc == 429:
            raise SaltUnavailableError(
                "Salt rate-limit exceeded (HTTP 429)"
            )
        if sc >= 400:
            raise SaltUnavailableError(
                f"Salt returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise SaltUnavailableError(
                f"Salt returned non-JSON response: {exc}"
            ) from exc

    # --------------------------------------------------------- INCIDENTS

    def list_incidents(
        self,
        *,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        api_id: Optional[str] = None,
        attacker_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        params: Dict[str, Any] = {
            "severity": severity,
            "status": status,
            "limit": limit,
            "offset": offset,
            "fromDate": from_date,
            "toDate": to_date,
            "apiId": api_id,
            "attackerId": attacker_id,
        }
        raw = self._request("GET", "/api/v1/incidents", params=params)
        return self._normalize_incidents(raw, limit=limit, offset=offset)

    # ------------------------------------------------------- API CATALOG

    def list_api_catalog(
        self,
        *,
        limit: int = 50,
        page: int = 1,
        search: Optional[str] = None,
        risk_score_gte: Optional[int] = None,
        has_sensitive_data: Optional[bool] = None,
        environment: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> Dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if page < 1:
            raise ValueError("page must be >= 1")
        params: Dict[str, Any] = {
            "limit": limit,
            "page": page,
            "search": search,
            "riskScoreGte": risk_score_gte,
            "hasSensitiveData": (
                str(bool(has_sensitive_data)).lower()
                if has_sensitive_data is not None
                else None
            ),
            "environment": environment,
            "classification": classification,
        }
        raw = self._request("GET", "/api/v1/api-catalog", params=params)
        return self._normalize_catalog(raw, limit=limit, page=page)

    def get_api(self, api_id: str) -> Dict[str, Any]:
        if not api_id:
            raise ValueError("api_id must not be empty")
        raw = self._request("GET", f"/api/v1/api-catalog/{api_id}")
        return self._normalize_catalog_entry(raw)

    def list_api_endpoints(
        self,
        api_id: str,
        *,
        limit: int = 50,
        page: int = 1,
    ) -> Dict[str, Any]:
        if not api_id:
            raise ValueError("api_id must not be empty")
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if page < 1:
            raise ValueError("page must be >= 1")
        raw = self._request(
            "GET",
            f"/api/v1/api-catalog/{api_id}/endpoints",
            params={"limit": limit, "page": page},
        )
        return self._normalize_endpoints(
            raw, api_id=api_id, limit=limit, page=page
        )

    # --------------------------------------------------------- ATTACKERS

    def list_attackers(
        self,
        *,
        status: Optional[str] = None,
        risk_score_gte: Optional[int] = None,
        first_seen_gte: Optional[str] = None,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        if page_size < 1 or page_size > 1000:
            raise ValueError("pageSize must be between 1 and 1000")
        params: Dict[str, Any] = {
            "status": status,
            "riskScoreGte": risk_score_gte,
            "firstSeenGte": first_seen_gte,
            "pageSize": page_size,
            "pageToken": page_token,
        }
        raw = self._request("GET", "/api/v1/attackers", params=params)
        return self._normalize_attackers(raw)

    # --------------------------------------------------------- POLICIES

    def list_policies(
        self,
        *,
        type_: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "type": type_,
            "enabled": (
                str(bool(enabled)).lower() if enabled is not None else None
            ),
        }
        raw = self._request("GET", "/api/v1/policies", params=params)
        return self._normalize_policies(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_incidents(
        raw: Dict[str, Any], *, limit: int, offset: int
    ) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("data") if isinstance(raw.get("data"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            evidence = (
                entry.get("evidence")
                if isinstance(entry.get("evidence"), list)
                else []
            )
            mitigated = (
                entry.get("mitigatedBy")
                if isinstance(entry.get("mitigatedBy"), dict)
                else {}
            )
            out.append(
                {
                    "id": entry.get("id") or "",
                    "title": entry.get("title") or "",
                    "description": entry.get("description") or "",
                    "severity": entry.get("severity") or "low",
                    "status": entry.get("status") or "open",
                    "attackType": entry.get("attackType") or "",
                    "firstSeen": entry.get("firstSeen") or "",
                    "lastSeen": entry.get("lastSeen") or "",
                    "resolvedAt": entry.get("resolvedAt"),
                    "apiId": entry.get("apiId") or "",
                    "apiName": entry.get("apiName") or "",
                    "endpoint": entry.get("endpoint") or "",
                    "attackerIp": entry.get("attackerIp") or "",
                    "attackerUserAgent": entry.get("attackerUserAgent") or "",
                    "requestCount": entry.get("requestCount") or 0,
                    "anomalyScore": entry.get("anomalyScore") or 0,
                    "evidence": [
                        {
                            "requestId": e.get("requestId") or "",
                            "timestamp": e.get("timestamp") or "",
                            "payload": e.get("payload") or "",
                            "indicators": list(e.get("indicators") or []),
                        }
                        for e in evidence
                        if isinstance(e, dict)
                    ],
                    "recommendation": entry.get("recommendation") or "",
                    "assignee": entry.get("assignee") or "",
                    "mitigatedBy": {
                        "type": mitigated.get("type") or "",
                        "action": mitigated.get("action") or "",
                    },
                }
            )
        total = raw.get("totalCount")
        if total is None:
            total = len(out)
        page_size = raw.get("pageSize") or limit
        # offset-based pagination → derive page index
        page = raw.get("page")
        if page is None:
            page = (offset // page_size) + 1 if page_size else 1
        return {
            "data": out,
            "totalCount": int(total),
            "page": int(page),
            "pageSize": int(page_size),
        }

    @staticmethod
    def _normalize_catalog_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(entry, dict):
            entry = {}
        owners = (
            entry.get("owners") if isinstance(entry.get("owners"), list) else []
        )
        sens_types = (
            entry.get("sensitiveDataTypes")
            if isinstance(entry.get("sensitiveDataTypes"), list)
            else []
        )
        incidents = (
            entry.get("totalIncidents")
            if isinstance(entry.get("totalIncidents"), dict)
            else {}
        )
        return {
            "id": entry.get("id") or "",
            "name": entry.get("name") or "",
            "baseUrl": entry.get("baseUrl") or "",
            "environment": entry.get("environment") or "production",
            "classification": entry.get("classification") or "internal",
            "type": entry.get("type") or "REST",
            "totalEndpoints": entry.get("totalEndpoints") or 0,
            "riskScore": entry.get("riskScore") or 0,
            "hasSensitiveData": bool(entry.get("hasSensitiveData") or False),
            "sensitiveDataTypes": [str(s) for s in sens_types],
            "totalRequests30d": entry.get("totalRequests30d") or 0,
            "totalIncidents": {
                "open": incidents.get("open") or 0,
                "resolved": incidents.get("resolved") or 0,
            },
            "firstDiscovered": entry.get("firstDiscovered") or "",
            "lastSeen": entry.get("lastSeen") or "",
            "owners": [
                {
                    "name": o.get("name") or "",
                    "email": o.get("email") or "",
                }
                for o in owners
                if isinstance(o, dict)
            ],
        }

    @staticmethod
    def _normalize_catalog(
        raw: Dict[str, Any], *, limit: int, page: int
    ) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("data") if isinstance(raw.get("data"), list) else []
        out = [
            SaltSecurityEngine._normalize_catalog_entry(entry)
            for entry in items
            if isinstance(entry, dict)
        ]
        total = raw.get("totalCount")
        if total is None:
            total = len(out)
        page_size = raw.get("pageSize") or limit
        page_out = raw.get("page") or page
        return {
            "data": out,
            "totalCount": int(total),
            "page": int(page_out),
            "pageSize": int(page_size),
        }

    @staticmethod
    def _normalize_endpoints(
        raw: Dict[str, Any], *, api_id: str, limit: int, page: int
    ) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("data") if isinstance(raw.get("data"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            sens_types = (
                entry.get("sensitiveDataTypes")
                if isinstance(entry.get("sensitiveDataTypes"), list)
                else []
            )
            out.append(
                {
                    "id": entry.get("id") or "",
                    "apiId": entry.get("apiId") or api_id,
                    "method": entry.get("method") or "GET",
                    "path": entry.get("path") or "",
                    "fullUrl": entry.get("fullUrl") or "",
                    "authenticated": bool(entry.get("authenticated") or False),
                    "hasSensitiveData": bool(
                        entry.get("hasSensitiveData") or False
                    ),
                    "sensitiveDataTypes": [str(s) for s in sens_types],
                    "riskScore": entry.get("riskScore") or 0,
                    "totalRequests30d": entry.get("totalRequests30d") or 0,
                    "totalIncidents": entry.get("totalIncidents") or 0,
                    "firstSeen": entry.get("firstSeen") or "",
                    "lastSeen": entry.get("lastSeen") or "",
                }
            )
        total = raw.get("totalCount")
        if total is None:
            total = len(out)
        page_size = raw.get("pageSize") or limit
        page_out = raw.get("page") or page
        return {
            "data": out,
            "totalCount": int(total),
            "page": int(page_out),
            "pageSize": int(page_size),
        }

    @staticmethod
    def _normalize_attackers(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("data") if isinstance(raw.get("data"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            geo = (
                entry.get("geolocation")
                if isinstance(entry.get("geolocation"), dict)
                else {}
            )
            out.append(
                {
                    "id": entry.get("id") or "",
                    "ipAddress": entry.get("ipAddress") or "",
                    "country": entry.get("country") or "",
                    "asn": entry.get("asn") or "",
                    "isp": entry.get("isp") or "",
                    "status": entry.get("status") or "active",
                    "riskScore": entry.get("riskScore") or 0,
                    "firstSeen": entry.get("firstSeen") or "",
                    "lastSeen": entry.get("lastSeen") or "",
                    "totalRequests": entry.get("totalRequests") or 0,
                    "totalIncidents": entry.get("totalIncidents") or 0,
                    "attackTypes": list(entry.get("attackTypes") or []),
                    "userAgents": list(entry.get("userAgents") or []),
                    "geolocation": {
                        "lat": geo.get("lat") or 0.0,
                        "lng": geo.get("lng") or 0.0,
                    },
                    "blockedAt": entry.get("blockedAt"),
                    "blockReason": entry.get("blockReason") or "",
                }
            )
        pagination = (
            raw.get("pagination")
            if isinstance(raw.get("pagination"), dict)
            else {}
        )
        return {
            "data": out,
            "pagination": {
                "nextPageToken": pagination.get("nextPageToken") or "",
            },
        }

    @staticmethod
    def _normalize_policies(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("data") if isinstance(raw.get("data"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "id": entry.get("id") or "",
                    "name": entry.get("name") or "",
                    "description": entry.get("description") or "",
                    "type": entry.get("type") or "detection",
                    "enabled": bool(entry.get("enabled") or False),
                    "severity": entry.get("severity") or "medium",
                    "action": entry.get("action") or "",
                    "ruleCount": entry.get("ruleCount") or 0,
                    "createdAt": entry.get("createdAt") or "",
                    "updatedAt": entry.get("updatedAt") or "",
                }
            )
        return {"data": out, "totalCount": int(raw.get("totalCount") or len(out))}

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[SaltSecurityEngine] = None
_singleton_lock = threading.Lock()


def get_salt_security_engine(
    api_base: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> SaltSecurityEngine:
    """Return the process-wide SaltSecurityEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SaltSecurityEngine(
                api_base=api_base,
                client_id=client_id,
                client_secret=client_secret,
                client=client,
            )
        return _singleton


def reset_salt_security_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "SaltSecurityEngine",
    "SaltUnavailableError",
    "get_salt_security_engine",
    "reset_salt_security_engine",
]
