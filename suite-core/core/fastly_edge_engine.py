"""
Fastly Edge Engine — ALDECI.

Wraps the Fastly REST API (https://api.fastly.com) for service inventory,
versions, dictionaries, ACLs, backends, snippets, purge, and stats.

NO MOCKS rule
-------------
* FASTLY_API_TOKEN unset:
    - All live methods raise FastlyUnavailableError (router -> HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No SQLite cache. No fabricated payloads.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

FASTLY_API_BASE = "https://api.fastly.com"
DEFAULT_TIMEOUT_SECONDS = 10.0


class FastlyUnavailableError(RuntimeError):
    """Raised when FASTLY_API_TOKEN is missing, network failed, or upstream
    returned an unrecoverable status."""


class FastlyEdgeEngine:
    """Thread-safe Fastly REST client (no on-disk cache)."""

    def __init__(
        self,
        api_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_token = api_token
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def _api_token(self) -> Optional[str]:
        if self._explicit_token:
            return self._explicit_token
        v = os.environ.get("FASTLY_API_TOKEN")
        return v or None

    def api_token_present(self) -> bool:
        return bool(self._api_token())

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers_extra: Optional[Dict[str, str]] = None,
    ) -> Any:
        token = self._api_token()
        if not token:
            raise FastlyUnavailableError("FASTLY_API_TOKEN is not configured")
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Fastly-Key": token,
        }
        if headers_extra:
            headers.update(headers_extra)
        url = f"{FASTLY_API_BASE}{path}"
        try:
            method_u = method.upper()
            if method_u == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            elif method_u == "POST":
                resp = self._client.post(
                    url, headers=headers, params=params, data=data
                )
            elif method_u == "PURGE":
                # Fastly accepts plain POST against /purge/* — keep the option
                # for direct PURGE method should the underlying client allow.
                resp = self._client.request(
                    "PURGE", url, headers=headers, params=params
                )
            else:
                raise FastlyUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise FastlyUnavailableError(
                f"Fastly request failed: {exc}"
            ) from exc
        if resp.status_code in (401, 403):
            raise FastlyUnavailableError(
                f"Fastly rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise FastlyUnavailableError(
                f"Fastly resource not found: {path}"
            )
        if resp.status_code == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"Fastly validation error: {body}")
        if resp.status_code == 429:
            raise FastlyUnavailableError(
                "Fastly rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise FastlyUnavailableError(
                f"Fastly returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise FastlyUnavailableError(
                f"Fastly returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- services

    def list_services(
        self,
        page: int = 1,
        per_page: int = 20,
        direction: str = "ascend",
        sort: str = "created",
    ) -> List[Dict[str, Any]]:
        if direction not in ("ascend", "descend"):
            raise ValueError("direction must be 'ascend' or 'descend'")
        if page < 1:
            raise ValueError("page must be >= 1")
        if per_page < 1 or per_page > 100:
            raise ValueError("per_page must be between 1 and 100")
        raw = self._request(
            "GET",
            "/service",
            params={
                "page": str(page),
                "per_page": str(per_page),
                "direction": direction,
                "sort": sort,
            },
        )
        return self._normalize_services(raw)

    def get_service(self, service_id: str) -> Dict[str, Any]:
        if not service_id:
            raise ValueError("service_id must not be empty")
        raw = self._request("GET", f"/service/{service_id}")
        return self._normalize_service(raw)

    def get_service_details(self, service_id: str) -> Dict[str, Any]:
        if not service_id:
            raise ValueError("service_id must not be empty")
        raw = self._request("GET", f"/service/{service_id}/details")
        # Details endpoint already returns the active_version expanded.
        svc = self._normalize_service(raw)
        active = raw.get("active_version") if isinstance(raw, dict) else None
        environments = raw.get("environments") if isinstance(raw, dict) else None
        if isinstance(active, dict):
            svc["active_version"] = self._normalize_version(active)
        if isinstance(environments, list):
            svc["environments"] = environments
        return svc

    def list_versions(self, service_id: str) -> List[Dict[str, Any]]:
        if not service_id:
            raise ValueError("service_id must not be empty")
        raw = self._request("GET", f"/service/{service_id}/version")
        if not isinstance(raw, list):
            return []
        return [
            self._normalize_version(v)
            for v in raw
            if isinstance(v, dict)
        ]

    # ------------------------------------------------------- dictionaries

    def list_dictionaries(
        self, service_id: str, version: int
    ) -> List[Dict[str, Any]]:
        if not service_id:
            raise ValueError("service_id must not be empty")
        raw = self._request(
            "GET",
            f"/service/{service_id}/version/{int(version)}/dictionary",
        )
        if not isinstance(raw, list):
            return []
        return [
            {
                "id": d.get("id") or "",
                "service_id": d.get("service_id") or service_id,
                "version": int(d.get("version") or version),
                "name": d.get("name") or "",
                "write_only": bool(d.get("write_only", False)),
                "created_at": d.get("created_at") or "",
                "updated_at": d.get("updated_at") or "",
            }
            for d in raw
            if isinstance(d, dict)
        ]

    def list_dictionary_items(
        self,
        service_id: str,
        version: int,
        name: str,
        page: int = 1,
        per_page: int = 100,
    ) -> List[Dict[str, Any]]:
        if not service_id:
            raise ValueError("service_id must not be empty")
        if not name:
            raise ValueError("dictionary name must not be empty")
        raw = self._request(
            "GET",
            f"/service/{service_id}/version/{int(version)}/dictionary/{name}/items",
            params={"page": str(page), "per_page": str(per_page)},
        )
        if not isinstance(raw, list):
            return []
        return [
            {
                "dictionary_id": item.get("dictionary_id") or "",
                "item_key": item.get("item_key") or "",
                "item_value": item.get("item_value") or "",
                "created_at": item.get("created_at") or "",
                "updated_at": item.get("updated_at") or "",
            }
            for item in raw
            if isinstance(item, dict)
        ]

    # ---------------------------------------------------------------- ACL

    def list_acls(
        self, service_id: str, version: int
    ) -> List[Dict[str, Any]]:
        if not service_id:
            raise ValueError("service_id must not be empty")
        raw = self._request(
            "GET",
            f"/service/{service_id}/version/{int(version)}/acl",
        )
        if not isinstance(raw, list):
            return []
        return [
            {
                "id": a.get("id") or "",
                "service_id": a.get("service_id") or service_id,
                "version": int(a.get("version") or version),
                "name": a.get("name") or "",
                "created_at": a.get("created_at") or "",
                "updated_at": a.get("updated_at") or "",
            }
            for a in raw
            if isinstance(a, dict)
        ]

    def list_acl_entries(
        self,
        service_id: str,
        version: int,
        name: str,
        page: int = 1,
        per_page: int = 100,
    ) -> List[Dict[str, Any]]:
        if not service_id:
            raise ValueError("service_id must not be empty")
        if not name:
            raise ValueError("ACL name must not be empty")
        raw = self._request(
            "GET",
            f"/service/{service_id}/version/{int(version)}/acl/{name}/entries",
            params={"page": str(page), "per_page": str(per_page)},
        )
        if not isinstance(raw, list):
            return []
        return [
            {
                "id": e.get("id") or "",
                "acl_id": e.get("acl_id") or "",
                "ip": e.get("ip") or "",
                "subnet": e.get("subnet"),
                "negated": bool(e.get("negated", False)),
                "comment": e.get("comment") or "",
                "created_at": e.get("created_at") or "",
                "updated_at": e.get("updated_at") or "",
            }
            for e in raw
            if isinstance(e, dict)
        ]

    # ----------------------------------------------------------- backends

    def list_backends(
        self, service_id: str, version: int
    ) -> List[Dict[str, Any]]:
        if not service_id:
            raise ValueError("service_id must not be empty")
        raw = self._request(
            "GET",
            f"/service/{service_id}/version/{int(version)}/backend",
        )
        if not isinstance(raw, list):
            return []
        return [b for b in raw if isinstance(b, dict)]

    # ---------------------------------------------------------- snippets

    def list_snippets(
        self, service_id: str, version: int
    ) -> List[Dict[str, Any]]:
        if not service_id:
            raise ValueError("service_id must not be empty")
        raw = self._request(
            "GET",
            f"/service/{service_id}/version/{int(version)}/snippet",
        )
        if not isinstance(raw, list):
            return []
        return [s for s in raw if isinstance(s, dict)]

    # ------------------------------------------------------------ purge

    def purge_key_or_url(
        self,
        key_or_url: str,
        soft: bool = False,
        surrogate_keys: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not key_or_url:
            raise ValueError("key_or_url must not be empty")
        headers: Dict[str, str] = {}
        if soft:
            headers["Fastly-Soft-Purge"] = "1"
        if surrogate_keys:
            headers["Surrogate-Key"] = surrogate_keys
        raw = self._request(
            "POST",
            f"/purge/{key_or_url.lstrip('/')}",
            headers_extra=headers,
        )
        if not isinstance(raw, dict):
            raw = {}
        return {
            "status": raw.get("status") or "ok",
            "id": raw.get("id") or "",
        }

    def purge_all(self, service_id: str) -> Dict[str, Any]:
        if not service_id:
            raise ValueError("service_id must not be empty")
        raw = self._request("POST", f"/service/{service_id}/purge_all")
        if not isinstance(raw, dict):
            raw = {}
        return {"status": raw.get("status") or "ok"}

    # ------------------------------------------------------------ stats

    def stats(
        self,
        from_ts: str,
        to_ts: str,
        by: str = "hour",
        region: Optional[str] = None,
    ) -> Dict[str, Any]:
        if by not in ("hour", "minute", "day"):
            raise ValueError("by must be one of: hour, minute, day")
        if region is not None and region not in (
            "usa",
            "europe",
            "asia",
            "africa",
            "sa",
            "au",
        ):
            raise ValueError(
                "region must be one of: usa, europe, asia, africa, sa, au"
            )
        params: Dict[str, Any] = {
            "from": from_ts,
            "to": to_ts,
            "by": by,
        }
        if region:
            params["region"] = region
        raw = self._request("GET", "/stats", params=params)
        if not isinstance(raw, dict):
            raw = {}
        data = raw.get("data") if isinstance(raw.get("data"), list) else []
        rows: List[Dict[str, Any]] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            rows.append(self._normalize_stats_row(entry))
        meta = {
            "from": from_ts,
            "to": to_ts,
            "by": by,
        }
        if region:
            meta["region"] = region
        return {"data": rows, "meta": meta}

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_version(v: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "number": int(v.get("number") or 0),
            "active": bool(v.get("active", False)),
            "locked": bool(v.get("locked", False)),
            "staging": bool(v.get("staging", False)),
            "deployed": bool(v.get("deployed", False)),
            "comment": v.get("comment") or "",
            "deployed_at": v.get("deployed_at") or "",
            "created_at": v.get("created_at") or "",
            "updated_at": v.get("updated_at") or "",
        }

    @classmethod
    def _normalize_service(cls, svc: Any) -> Dict[str, Any]:
        if not isinstance(svc, dict):
            svc = {}
        versions = svc.get("versions") if isinstance(svc.get("versions"), list) else []
        return {
            "id": svc.get("id") or "",
            "name": svc.get("name") or "",
            "comment": svc.get("comment") or "",
            "customer_id": svc.get("customer_id") or "",
            "type": svc.get("type") or "vcl",
            "deleted_at": svc.get("deleted_at"),
            "created_at": svc.get("created_at") or "",
            "updated_at": svc.get("updated_at") or "",
            "versions": [
                cls._normalize_version(v) for v in versions if isinstance(v, dict)
            ],
            "publish_key": svc.get("publish_key") or "",
        }

    @classmethod
    def _normalize_services(cls, raw: Any) -> List[Dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        return [cls._normalize_service(s) for s in raw if isinstance(s, dict)]

    @staticmethod
    def _normalize_stats_row(entry: Dict[str, Any]) -> Dict[str, Any]:
        def _i(key: str) -> int:
            try:
                return int(entry.get(key) or 0)
            except (TypeError, ValueError):
                return 0

        return {
            "service_id": entry.get("service_id") or "",
            "hits": _i("hits"),
            "miss": _i("miss"),
            "status_2xx": _i("status_2xx"),
            "status_3xx": _i("status_3xx"),
            "status_4xx": _i("status_4xx"),
            "status_5xx": _i("status_5xx"),
            "bandwidth": _i("bandwidth"),
            "requests": _i("requests"),
            "status_200": _i("status_200"),
            "status_204": _i("status_204"),
            "status_206": _i("status_206"),
            "status_301": _i("status_301"),
            "status_302": _i("status_302"),
            "status_304": _i("status_304"),
            "status_400": _i("status_400"),
            "status_401": _i("status_401"),
            "status_403": _i("status_403"),
            "status_404": _i("status_404"),
            "status_416": _i("status_416"),
            "status_500": _i("status_500"),
            "status_501": _i("status_501"),
            "status_502": _i("status_502"),
            "status_503": _i("status_503"),
            "status_504": _i("status_504"),
            "status_505": _i("status_505"),
            "ipv6_bandwidth": _i("ipv6_bandwidth"),
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[FastlyEdgeEngine] = None
_singleton_lock = threading.Lock()


def get_fastly_edge_engine(
    api_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> FastlyEdgeEngine:
    """Return the process-wide FastlyEdgeEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = FastlyEdgeEngine(api_token=api_token, client=client)
        return _singleton


def reset_fastly_edge_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "FastlyEdgeEngine",
    "FastlyUnavailableError",
    "get_fastly_edge_engine",
    "reset_fastly_edge_engine",
]
