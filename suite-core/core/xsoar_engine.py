"""Palo Alto Cortex XSOAR (Demisto) Engine — ALDECI.

Wraps Cortex XSOAR's REST API surfaces for incident management, playbook
discovery, and integration configuration:

  * POST /incidents/search                 — list/filter incidents
  * GET  /incident/load/{id}               — fetch one incident
  * POST /incident/playbook/{id}/run       — trigger a playbook on incident
  * POST /entry                            — add a war-room note/entry
  * POST /playbook/search                  — list/filter playbooks
  * POST /settings/integration/search      — list integration instances
  * POST /settings/integration/test        — test an integration

Auth
----
XSOAR v6 uses an opaque API key in the ``Authorization`` header. v8/Cortex XSOAR
adds an additional ``x-xdr-auth-id`` (key-id) header. Env vars:
  * XSOAR_BASE_URL          (e.g. https://xsoar.example.com)
  * XSOAR_API_KEY           — required
  * XSOAR_API_KEY_ID        — optional (v8 only)

Cache
-----
NO SQLite cache. Every call hits XSOAR live.

NO MOCKS rule
-------------
* If XSOAR_BASE_URL or XSOAR_API_KEY is unset:
    - Live endpoints raise ``XsoarUnavailableError`` (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads.
"""

from __future__ import annotations

import json as _json
import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0


class XsoarUnavailableError(RuntimeError):
    """Raised when XSOAR creds/base URL are missing or upstream failed."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class XsoarEngine:
    """Thread-safe Cortex XSOAR REST client (no cache)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        api_key_id: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_base_url = base_url
        self._explicit_api_key = api_key
        self._explicit_api_key_id = api_key_id

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()

    # ---------------------------------------------------------------- creds

    def _base_url(self) -> Optional[str]:
        return self._explicit_base_url or os.environ.get("XSOAR_BASE_URL") or None

    def _api_key(self) -> Optional[str]:
        return self._explicit_api_key or os.environ.get("XSOAR_API_KEY") or None

    def _api_key_id(self) -> Optional[str]:
        return self._explicit_api_key_id or os.environ.get("XSOAR_API_KEY_ID") or None

    def base_url_present(self) -> bool:
        return bool(self._base_url())

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def api_key_id_present(self) -> bool:
        return bool(self._api_key_id())

    def creds_complete(self) -> bool:
        return self.base_url_present() and self.api_key_present()

    # ---------------------------------------------------------------- url

    def _build_url(self, path: str) -> str:
        base = self._base_url()
        if not base:
            raise XsoarUnavailableError("XSOAR_BASE_URL is not configured")
        base = base.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        return f"{base}{path}"

    def _headers(self) -> Dict[str, str]:
        key = self._api_key()
        if not key:
            raise XsoarUnavailableError("XSOAR_API_KEY is not configured")
        h: Dict[str, str] = {
            "Accept": "application/json",
            "Authorization": key,
        }
        kid = self._api_key_id()
        if kid:
            h["x-xdr-auth-id"] = kid
        return h

    # ------------------------------------------------------------ request

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        if not self.creds_complete():
            missing: List[str] = []
            if not self.base_url_present():
                missing.append("XSOAR_BASE_URL")
            if not self.api_key_present():
                missing.append("XSOAR_API_KEY")
            raise XsoarUnavailableError(
                "XSOAR credentials missing: " + ",".join(missing)
            )
        url = self._build_url(path)
        headers = self._headers()
        body_bytes: Optional[bytes] = None
        if json_body is not None:
            body_bytes = _json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers)
            elif method.upper() == "POST":
                resp = self._client.post(
                    url, headers=headers, content=body_bytes
                )
            else:
                raise XsoarUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise XsoarUnavailableError(
                f"XSOAR request failed: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            raise XsoarUnavailableError(
                f"XSOAR rejected credentials (HTTP {sc})"
            )
        if sc == 404:
            raise XsoarUnavailableError(
                f"XSOAR resource not found (HTTP 404): {path}"
            )
        if sc == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": getattr(resp, "text", "")[:200]}
            raise ValueError(f"XSOAR validation error: {body}")
        if sc == 429:
            raise XsoarUnavailableError(
                "XSOAR rate-limit exceeded (HTTP 429)"
            )
        if sc == 204 or method.upper() == "POST" and path.endswith("/run") and sc in (200, 201, 204):
            # Playbook trigger may return empty 204
            if sc == 204:
                return {}
        if sc >= 400:
            raise XsoarUnavailableError(
                f"XSOAR returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        # Some endpoints return empty body
        text = getattr(resp, "text", "") or ""
        if not text.strip():
            return {}
        try:
            return resp.json()
        except ValueError as exc:
            raise XsoarUnavailableError(
                f"XSOAR returned non-JSON response: {exc}"
            ) from exc

    # ------------------------------------------------------------- API

    def search_incidents(
        self,
        query: Optional[str] = None,
        page: int = 0,
        size: int = 50,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        status: Optional[List[int]] = None,
        severity: Optional[List[int]] = None,
        ascending: bool = False,
        sort: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if size < 1 or size > 1000:
            raise ValueError("size must be between 1 and 1000")
        if page < 0:
            raise ValueError("page must be >= 0")
        if status:
            for s in status:
                if int(s) not in (0, 1, 2, 3):
                    raise ValueError("status entries must be in 0|1|2|3")
        if severity:
            for s in severity:
                if int(s) not in (0, 1, 2, 3, 4):
                    raise ValueError("severity entries must be in 0|1|2|3|4")
        flt: Dict[str, Any] = {"page": page, "size": size}
        if query:
            flt["query"] = query
        if from_date:
            flt["fromDate"] = from_date
        if to_date:
            flt["toDate"] = to_date
        if status is not None:
            flt["status"] = list(status)
        if severity is not None:
            flt["severity"] = list(severity)
        body: Dict[str, Any] = {"filter": flt, "userFilter": False}
        if ascending is not None:
            body["ascending"] = bool(ascending)
        if sort is not None:
            body["sort"] = list(sort)
        raw = self._request("POST", "/incidents/search", json_body=body)
        return self._normalize_incident_search(raw)

    def get_incident(self, incident_id: str) -> Dict[str, Any]:
        if not incident_id or not str(incident_id).strip():
            raise ValueError("incident_id is required")
        raw = self._request("POST", f"/incident/load/{incident_id}", json_body={})
        if isinstance(raw, dict) and not raw:
            # Some XSOAR builds prefer GET for load — try that
            raw = self._request("GET", f"/incident/load/{incident_id}")
        return self._normalize_incident(raw)

    def run_playbook(self, incident_id: str, playbook_id: str) -> Dict[str, Any]:
        if not incident_id or not str(incident_id).strip():
            raise ValueError("incident_id is required")
        if not playbook_id or not str(playbook_id).strip():
            raise ValueError("playbookId is required")
        body = {"playbookId": playbook_id}
        raw = self._request(
            "POST",
            f"/incident/playbook/{incident_id}/run",
            json_body=body,
        )
        if not isinstance(raw, dict):
            raw = {}
        return {"status": "triggered", "incidentId": incident_id, "playbookId": playbook_id, "raw": raw}

    def add_entry(
        self,
        investigation_id: str,
        data: str,
        format: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not investigation_id or not str(investigation_id).strip():
            raise ValueError("investigationId is required")
        if data is None:
            raise ValueError("data is required")
        if format is not None and format not in (
            "text", "markdown", "html", "json", "table",
        ):
            raise ValueError("format must be text|markdown|html|json|table")
        body: Dict[str, Any] = {
            "investigationId": investigation_id,
            "data": data,
        }
        if format:
            body["format"] = format
        raw = self._request("POST", "/entry", json_body=body)
        return self._normalize_entry(raw)

    def search_playbooks(
        self,
        query: Optional[str] = None,
        page: int = 0,
        size: int = 50,
    ) -> Dict[str, Any]:
        if size < 1 or size > 1000:
            raise ValueError("size must be between 1 and 1000")
        if page < 0:
            raise ValueError("page must be >= 0")
        body: Dict[str, Any] = {"page": page, "size": size}
        if query:
            body["query"] = query
        raw = self._request("POST", "/playbook/search", json_body=body)
        return self._normalize_playbook_search(raw)

    def search_integrations(
        self,
        query: Optional[str] = None,
        page: int = 0,
        size: int = 50,
    ) -> Dict[str, Any]:
        if size < 1 or size > 1000:
            raise ValueError("size must be between 1 and 1000")
        if page < 0:
            raise ValueError("page must be >= 0")
        body: Dict[str, Any] = {"page": page, "size": size}
        if query:
            body["query"] = query
        raw = self._request("POST", "/settings/integration/search", json_body=body)
        return self._normalize_integration_search(raw)

    def test_integration(
        self,
        name: str,
        brand: str,
        configuration: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if not name or not str(name).strip():
            raise ValueError("name is required")
        if not brand or not str(brand).strip():
            raise ValueError("brand is required")
        if configuration is None or not isinstance(configuration, list):
            raise ValueError("configuration must be a list")
        body = {
            "name": name,
            "brand": brand,
            "data": list(configuration),
        }
        raw = self._request("POST", "/settings/integration/test", json_body=body)
        return self._normalize_integration_test(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_incident(entry: Any) -> Dict[str, Any]:
        if not isinstance(entry, dict):
            return {}
        cf = entry.get("CustomFields") if isinstance(entry.get("CustomFields"), dict) else (
            entry.get("customFields") if isinstance(entry.get("customFields"), dict) else {}
        )
        labels_raw = entry.get("labels") if isinstance(entry.get("labels"), list) else []
        labels: List[Dict[str, Any]] = []
        for lab in labels_raw:
            if isinstance(lab, dict):
                labels.append({
                    "type": lab.get("type") or "",
                    "value": lab.get("value") or "",
                })
        return {
            "id": entry.get("id") or "",
            "version": entry.get("version") or 0,
            "name": entry.get("name") or "",
            "type": entry.get("type") or "",
            "severity": entry.get("severity") or 0,
            "status": entry.get("status") or 0,
            "category": entry.get("category") or "",
            "occurred": entry.get("occurred") or "",
            "modified": entry.get("modified") or "",
            "created": entry.get("created") or "",
            "sourceBrand": entry.get("sourceBrand") or "",
            "sourceInstance": entry.get("sourceInstance") or "",
            "hasRole": bool(entry.get("hasRole")),
            "owner": entry.get("owner") or "",
            "sla": entry.get("sla") or 0,
            "dueDate": entry.get("dueDate") or "",
            "closeReason": entry.get("closeReason") or "",
            "closeNotes": entry.get("closeNotes") or "",
            "runStatus": entry.get("runStatus") or "",
            "openDuration": entry.get("openDuration") or 0,
            "closingUserId": entry.get("closingUserId") or "",
            "lastOpen": entry.get("lastOpen") or "",
            "autime": entry.get("autime") or 0,
            "account": entry.get("account") or "",
            "customFields": cf,
            "labels": labels,
        }

    @classmethod
    def _normalize_incident_search(cls, raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("data") if isinstance(raw.get("data"), list) else []
        out = [cls._normalize_incident(item) for item in items if isinstance(item, dict)]
        return {
            "total": raw.get("total") if isinstance(raw.get("total"), int) else len(out),
            "data": out,
        }

    @staticmethod
    def _normalize_entry(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"id": "", "investigationId": "", "type": 0, "format": ""}
        return {
            "id": raw.get("id") or "",
            "investigationId": raw.get("investigationId") or "",
            "type": raw.get("type") or 0,
            "format": raw.get("format") or "",
            "contents": raw.get("contents") or "",
            "created": raw.get("created") or "",
        }

    @staticmethod
    def _normalize_playbook_search(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("playbooks") if isinstance(raw.get("playbooks"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            inputs_raw = entry.get("inputs") if isinstance(entry.get("inputs"), list) else []
            outputs_raw = entry.get("outputs") if isinstance(entry.get("outputs"), list) else []
            inputs: List[Dict[str, Any]] = []
            for ip in inputs_raw:
                if isinstance(ip, dict):
                    inputs.append({
                        "key": ip.get("key") or "",
                        "value": ip.get("value") or "",
                        "required": bool(ip.get("required")),
                        "description": ip.get("description") or "",
                    })
            outputs: List[Dict[str, Any]] = []
            for op in outputs_raw:
                if isinstance(op, dict):
                    outputs.append({
                        "contextPath": op.get("contextPath") or "",
                        "description": op.get("description") or "",
                        "type": op.get("type") or "",
                    })
            tasks = entry.get("tasks") if isinstance(entry.get("tasks"), dict) else {}
            task_ids = entry.get("taskIds") if isinstance(entry.get("taskIds"), list) else []
            missing_scripts = (
                entry.get("missingScripts") if isinstance(entry.get("missingScripts"), list) else []
            )
            commands = entry.get("commands") if isinstance(entry.get("commands"), list) else []
            tags = entry.get("tags") if isinstance(entry.get("tags"), list) else []
            out.append({
                "id": entry.get("id") or "",
                "version": entry.get("version") or 0,
                "name": entry.get("name") or "",
                "description": entry.get("description") or "",
                "missingScripts": list(missing_scripts),
                "tasks": tasks,
                "taskIds": list(task_ids),
                "inputs": inputs,
                "outputs": outputs,
                "commands": list(commands),
                "tags": list(tags),
            })
        saved = raw.get("savedFilters") if isinstance(raw.get("savedFilters"), list) else []
        return {
            "playbooks": out,
            "total": raw.get("total") if isinstance(raw.get("total"), int) else len(out),
            "savedFilters": list(saved),
        }

    @staticmethod
    def _normalize_integration_search(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("instances") if isinstance(raw.get("instances"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            cfgs = entry.get("data") if isinstance(entry.get("data"), list) else (
                entry.get("configurations") if isinstance(entry.get("configurations"), list) else []
            )
            out.append({
                "name": entry.get("name") or "",
                "brand": entry.get("brand") or "",
                "category": entry.get("category") or "",
                "configurations": list(cfgs),
                "canSample": bool(entry.get("canSample")),
                "isLongRunning": bool(entry.get("isLongRunning")),
                "defaultMapperIn": entry.get("defaultMapperIn") or "",
                "defaultMapperOut": entry.get("defaultMapperOut") or "",
                "longRunningEnabled": bool(entry.get("longRunningEnabled")),
                "mappingId": entry.get("mappingId") or "",
                "hidden": bool(entry.get("hidden")),
                "version": entry.get("version") or 0,
            })
        confs = raw.get("configurations") if isinstance(raw.get("configurations"), dict) else {}
        return {
            "instances": out,
            "total": raw.get("total") if isinstance(raw.get("total"), int) else len(out),
            "configurations": confs,
        }

    @staticmethod
    def _normalize_integration_test(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"success": False, "message": ""}
        success_raw = raw.get("success")
        if success_raw is None:
            success_raw = raw.get("ok")
        return {
            "success": bool(success_raw) if success_raw is not None else True,
            "message": raw.get("message") or raw.get("error") or "",
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[XsoarEngine] = None
_singleton_lock = threading.Lock()


def get_xsoar_engine(
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    api_key_id: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> XsoarEngine:
    """Return the process-wide XsoarEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = XsoarEngine(
                base_url=base_url,
                api_key=api_key,
                api_key_id=api_key_id,
                client=client,
            )
        return _singleton


def reset_xsoar_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "XsoarEngine",
    "XsoarUnavailableError",
    "get_xsoar_engine",
    "reset_xsoar_engine",
]
