"""
Qualys VMDR Engine - ALDECI.

Wraps the Qualys VMDR / VM/PC API (https://qualysapi.qualys.com or per-region
shard) and provides a process-wide singleton. NO SQLite cache - Qualys host /
detection / scan / policy / report responses are large, frequently updated, and
licence-restricted; we forward live every call.

Endpoint coverage
-----------------
* GET  /api/2.0/fo/asset/host/?action=list                  - host inventory
* GET  /api/2.0/fo/asset/host/vm/detection/?action=list     - host vuln detections
* GET  /api/2.0/fo/scan/?action=list                        - scan list
* POST /api/2.0/fo/scan/?action=launch                      - launch a scan
* GET  /api/2.0/fo/compliance/policy/?action=list           - PC policy list
* GET  /api/2.0/fo/report/?action=list                      - report list

Auth
----
HTTP Basic (HTTPBasicAuth(USER, PASS)) plus the Qualys-required
``X-Requested-With: ALDECI Qualys Connector`` header on every call. Env vars:
``QUALYS_USERNAME``, ``QUALYS_PASSWORD``, ``QUALYS_API_BASE``.

NO MOCKS rule
-------------
* Any of QUALYS_USERNAME / QUALYS_PASSWORD / QUALYS_API_BASE unset:
    - All live endpoints raise QualysUnavailableError (router -> HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads - every response was actually returned by Qualys.

Output format
-------------
Some Qualys endpoints return XML by default. Where the upstream supports the
``output_format=JSON`` query param we forward it and parse JSON; otherwise we
return the raw XML body wrapped as ``{"xml": "<...>"}`` so callers can decide
how to parse downstream.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0
QUALYS_REQUESTED_WITH = "ALDECI Qualys Connector"


class QualysUnavailableError(RuntimeError):
    """Raised when env vars are missing, network failed, or upstream returned an
    unrecoverable status."""


try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore


class QualysEngine:
    """Thread-safe Qualys VMDR REST client (no cache)."""

    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_base: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_username = username
        self._explicit_password = password
        self._explicit_api_base = api_base
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def _username(self) -> Optional[str]:
        if self._explicit_username:
            return self._explicit_username
        v = os.environ.get("QUALYS_USERNAME")
        return v or None

    def _password(self) -> Optional[str]:
        if self._explicit_password:
            return self._explicit_password
        v = os.environ.get("QUALYS_PASSWORD")
        return v or None

    def _api_base(self) -> Optional[str]:
        if self._explicit_api_base:
            return self._explicit_api_base.rstrip("/")
        v = os.environ.get("QUALYS_API_BASE")
        return v.rstrip("/") if v else None

    def username_present(self) -> bool:
        return bool(self._username())

    def password_present(self) -> bool:
        return bool(self._password())

    def api_base_present(self) -> bool:
        return bool(self._api_base())

    def credentials_present(self) -> bool:
        return self.username_present() and self.password_present() and self.api_base_present()

    def _auth_and_headers(self):
        u = self._username()
        p = self._password()
        b = self._api_base()
        if not u or not p or not b:
            raise QualysUnavailableError(
                "QUALYS_USERNAME, QUALYS_PASSWORD, or QUALYS_API_BASE is not configured"
            )
        return (
            httpx.BasicAuth(u, p),
            {
                "X-Requested-With": QUALYS_REQUESTED_WITH,
                "Accept": "application/json, application/xml;q=0.8, */*;q=0.5",
            },
            b,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        prefer_json: bool = True,
    ) -> Dict[str, Any]:
        auth, headers, base = self._auth_and_headers()
        url = f"{base}{path}"
        if params is None:
            params = {}
        # Qualys ``output_format`` only works on endpoints that support it. The
        # router decides; engine just forwards.
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params, auth=auth)
            elif method.upper() == "POST":
                resp = self._client.post(
                    url, headers=headers, params=params, data=data or {}, auth=auth
                )
            else:
                raise QualysUnavailableError(f"unsupported HTTP method: {method}")
        except httpx.HTTPError as exc:
            raise QualysUnavailableError(f"Qualys request failed: {exc}") from exc

        if resp.status_code in (401, 403):
            raise QualysUnavailableError(
                f"Qualys rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise QualysUnavailableError(f"Qualys resource not found: {path}")
        if resp.status_code == 409:
            # Qualys 409 = "concurrent request limit" - treat as rate limit
            raise QualysUnavailableError(
                "Qualys concurrency limit hit (HTTP 409)"
            )
        if resp.status_code == 429:
            raise QualysUnavailableError(
                "Qualys rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code == 422:
            raise ValueError(
                f"Qualys validation error (HTTP 422): {resp.text[:200]}"
            )
        if resp.status_code >= 400:
            raise QualysUnavailableError(
                f"Qualys returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        # Try JSON first when caller asked for it; fall back to raw XML envelope.
        if prefer_json:
            try:
                return resp.json()
            except ValueError:
                pass
        text = getattr(resp, "text", "") or ""
        return {"xml": text}

    # ----------------------------------------------------------- API calls

    def list_hosts(
        self,
        *,
        truncation_limit: Optional[int] = None,
        id_min: Optional[int] = None,
        ids: Optional[str] = None,
        details: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /api/2.0/fo/asset/host/?action=list - host inventory.

        Returns the raw HOST_LIST_OUTPUT envelope (JSON when Qualys responds with
        JSON; otherwise wrapped XML).
        """
        params: Dict[str, Any] = {"action": "list"}
        if truncation_limit is not None:
            if truncation_limit < 0:
                raise ValueError("truncation_limit must be >= 0")
            params["truncation_limit"] = int(truncation_limit)
        if id_min is not None:
            params["id_min"] = int(id_min)
        if ids:
            params["ids"] = str(ids)
        if details:
            if details not in ("All", "Basic", "None"):
                raise ValueError("details must be one of All|Basic|None")
            params["details"] = details
        return self._request("GET", "/api/2.0/fo/asset/host/", params=params)

    def list_host_detections(
        self,
        *,
        truncation_limit: Optional[int] = None,
        qids: Optional[str] = None,
        severities: Optional[str] = None,
        ids: Optional[str] = None,
        include_search_list_titles: Optional[bool] = None,
        output_format: str = "JSON",
    ) -> Dict[str, Any]:
        """GET /api/2.0/fo/asset/host/vm/detection/?action=list - per-host vuln
        detection list with QDS scoring."""
        params: Dict[str, Any] = {"action": "list"}
        if truncation_limit is not None:
            if truncation_limit < 0:
                raise ValueError("truncation_limit must be >= 0")
            params["truncation_limit"] = int(truncation_limit)
        if qids:
            params["qids"] = str(qids)
        if severities:
            params["severities"] = str(severities)
        if ids:
            params["ids"] = str(ids)
        if include_search_list_titles:
            params["include_search_list_titles"] = "1"
        if output_format:
            if output_format not in ("JSON", "XML", "CSV"):
                raise ValueError("output_format must be one of JSON|XML|CSV")
            params["output_format"] = output_format
        return self._request(
            "GET",
            "/api/2.0/fo/asset/host/vm/detection/",
            params=params,
            prefer_json=(output_format == "JSON"),
        )

    def list_scans(
        self,
        *,
        launched_after_datetime: Optional[str] = None,
        launched_before_datetime: Optional[str] = None,
        state: Optional[str] = None,
        processed: Optional[int] = None,
        scan_type: Optional[str] = None,
        output_format: str = "JSON",
    ) -> Dict[str, Any]:
        """GET /api/2.0/fo/scan/?action=list - scan list."""
        params: Dict[str, Any] = {"action": "list"}
        if launched_after_datetime:
            params["launched_after_datetime"] = launched_after_datetime
        if launched_before_datetime:
            params["launched_before_datetime"] = launched_before_datetime
        if state:
            allowed = {"Submitted", "Running", "Finished", "Cancelled", "Error", "Paused"}
            if state not in allowed:
                raise ValueError(f"state must be one of {sorted(allowed)}")
            params["state"] = state
        if processed is not None:
            if processed not in (0, 1):
                raise ValueError("processed must be 0 or 1")
            params["processed"] = int(processed)
        if scan_type:
            allowed_t = {"Vulnerability", "Compliance", "Discovery", "VM", "PC"}
            if scan_type not in allowed_t:
                raise ValueError(f"type must be one of {sorted(allowed_t)}")
            params["type"] = scan_type
        if output_format:
            params["output_format"] = output_format
        return self._request(
            "GET",
            "/api/2.0/fo/scan/",
            params=params,
            prefer_json=(output_format == "JSON"),
        )

    def launch_scan(
        self,
        *,
        scan_title: str,
        ip: Optional[str] = None,
        asset_groups: Optional[str] = None,
        asset_group_ids: Optional[str] = None,
        option_id: Optional[int] = None,
        option_title: Optional[str] = None,
        iscanner_id: Optional[int] = None,
        iscanner_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /api/2.0/fo/scan/?action=launch - launch a Qualys scan."""
        if not scan_title:
            raise ValueError("scan_title must not be empty")
        if not (ip or asset_groups or asset_group_ids):
            raise ValueError(
                "one of ip, asset_groups, or asset_group_ids must be supplied"
            )
        if not (option_id or option_title):
            raise ValueError(
                "one of option_id or option_title must be supplied"
            )
        params = {"action": "launch"}
        form: Dict[str, Any] = {"scan_title": scan_title}
        if ip:
            form["ip"] = ip
        if asset_groups:
            form["asset_groups"] = asset_groups
        if asset_group_ids:
            form["asset_group_ids"] = asset_group_ids
        if option_id is not None:
            form["option_id"] = int(option_id)
        if option_title:
            form["option_title"] = option_title
        if iscanner_id is not None:
            form["iscanner_id"] = int(iscanner_id)
        if iscanner_name:
            form["iscanner_name"] = iscanner_name
        result = self._request(
            "POST",
            "/api/2.0/fo/scan/",
            params=params,
            data=form,
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "scan.completed",
                        {
                            "entity_id": scan_title,
                            "type": "qualys_vmdr_scan",
                            "severity": "unknown",
                            "source_engine": "qualys",
                            "target_ip": ip or asset_groups or asset_group_ids or "",
                        },
                    )
            except Exception:
                pass
        return result

    def list_compliance_policies(
        self,
        *,
        policy_id: Optional[int] = None,
        output_format: str = "JSON",
    ) -> Dict[str, Any]:
        """GET /api/2.0/fo/compliance/policy/?action=list - PC policy list."""
        params: Dict[str, Any] = {"action": "list"}
        if policy_id is not None:
            params["id"] = int(policy_id)
        if output_format:
            params["output_format"] = output_format
        return self._request(
            "GET",
            "/api/2.0/fo/compliance/policy/",
            params=params,
            prefer_json=(output_format == "JSON"),
        )

    def list_reports(
        self,
        *,
        report_id: Optional[int] = None,
        state: Optional[str] = None,
        user_login: Optional[str] = None,
        expires_before: Optional[str] = None,
        expires_after: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /api/2.0/fo/report/?action=list - report list."""
        params: Dict[str, Any] = {"action": "list"}
        if report_id is not None:
            params["id"] = int(report_id)
        if state:
            allowed = {"Running", "Finished", "Submitted", "Canceled", "Errors"}
            if state not in allowed:
                raise ValueError(f"state must be one of {sorted(allowed)}")
            params["state"] = state
        if user_login:
            params["user_login"] = user_login
        if expires_before:
            params["expires_before"] = expires_before
        if expires_after:
            params["expires_after"] = expires_after
        return self._request("GET", "/api/2.0/fo/report/", params=params)

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[QualysEngine] = None
_singleton_lock = threading.Lock()


def get_qualys_engine(
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_base: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> QualysEngine:
    """Return the process-wide QualysEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = QualysEngine(
                username=username,
                password=password,
                api_base=api_base,
                client=client,
            )
        return _singleton


def reset_qualys_engine() -> None:
    """Tear down the singleton - used by tests with stub clients."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "QualysEngine",
    "QualysUnavailableError",
    "get_qualys_engine",
    "reset_qualys_engine",
]
