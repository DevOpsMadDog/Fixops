"""
Tenable.io Vulnerability Scanner Engine — ALDECI.

Wraps the Tenable.io REST API (https://cloud.tenable.com) and provides a
process-wide singleton. NO SQLite cache — Tenable scan/host/vuln responses
are large, frequently-updated, and licence-restricted; we forward live every
call.

Endpoint coverage
-----------------
* GET  /scans                                                 — list scans
* GET  /scans/{scan_id}                                       — single scan + hosts + vulns
* GET  /scans/{scan_id}/hosts/{host_id}                       — per-host details
* GET  /scanners/agents (with limit/offset)                   — agent inventory
* GET  /policies                                              — scan policies
* POST /workbenches/vulnerabilities                           — workbench query

Auth
----
``X-ApiKeys: accessKey={ak}; secretKey={sk}`` (env vars TENABLE_ACCESS_KEY +
TENABLE_SECRET_KEY).

NO MOCKS rule
-------------
* TENABLE_ACCESS_KEY or TENABLE_SECRET_KEY env unset:
    - All live endpoints raise TenableUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Tenable.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

TENABLE_API_BASE = "https://cloud.tenable.com"
DEFAULT_TIMEOUT_SECONDS = 12.0


class TenableUnavailableError(RuntimeError):
    """Raised when access/secret keys are missing, network failed, or upstream
    returned an unrecoverable status."""


class TenableIOEngine:
    """Thread-safe Tenable.io REST client (no cache)."""

    def __init__(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_access_key = access_key
        self._explicit_secret_key = secret_key
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def _access_key(self) -> Optional[str]:
        if self._explicit_access_key:
            return self._explicit_access_key
        v = os.environ.get("TENABLE_ACCESS_KEY")
        return v or None

    def _secret_key(self) -> Optional[str]:
        if self._explicit_secret_key:
            return self._explicit_secret_key
        v = os.environ.get("TENABLE_SECRET_KEY")
        return v or None

    def access_key_present(self) -> bool:
        return bool(self._access_key())

    def secret_key_present(self) -> bool:
        return bool(self._secret_key())

    def credentials_present(self) -> bool:
        return self.access_key_present() and self.secret_key_present()

    def _headers(self) -> Dict[str, str]:
        ak = self._access_key()
        sk = self._secret_key()
        if not ak or not sk:
            raise TenableUnavailableError(
                "TENABLE_ACCESS_KEY or TENABLE_SECRET_KEY is not configured"
            )
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": f"accessKey={ak}; secretKey={sk}",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        headers = self._headers()
        url = f"{TENABLE_API_BASE}{path}"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                resp = self._client.post(
                    url, headers=headers, params=params, json=json_body
                )
            else:
                raise TenableUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise TenableUnavailableError(
                f"Tenable request failed: {exc}"
            ) from exc
        if resp.status_code in (401, 403):
            raise TenableUnavailableError(
                f"Tenable rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise TenableUnavailableError(
                f"Tenable resource not found: {path}"
            )
        if resp.status_code == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"Tenable validation error: {body}")
        if resp.status_code == 429:
            raise TenableUnavailableError(
                "Tenable rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise TenableUnavailableError(
                f"Tenable returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise TenableUnavailableError(
                f"Tenable returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- API calls

    def list_scans(self) -> Dict[str, Any]:
        """GET /scans — list all scans."""
        raw = self._request("GET", "/scans")
        return self._normalize_scans(raw)

    def scan_detail(
        self, scan_id: str, *, history_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """GET /scans/{scan_id}?history_id=... — single scan with hosts + vulns."""
        if not scan_id:
            raise ValueError("scan_id must not be empty")
        params: Dict[str, Any] = {}
        if history_id is not None:
            params["history_id"] = int(history_id)
        raw = self._request(
            "GET", f"/scans/{scan_id}", params=params or None
        )
        return self._normalize_scan_detail(raw)

    def host_detail(self, scan_id: str, host_id: str) -> Dict[str, Any]:
        """GET /scans/{scan_id}/hosts/{host_id} — per-host vulns + compliance."""
        if not scan_id:
            raise ValueError("scan_id must not be empty")
        if not host_id:
            raise ValueError("host_id must not be empty")
        raw = self._request(
            "GET", f"/scans/{scan_id}/hosts/{host_id}"
        )
        return self._normalize_host_detail(raw)

    def list_agents(
        self, *, limit: int = 50, offset: int = 0
    ) -> Dict[str, Any]:
        """GET /scanners/agents — agent inventory.

        Tenable's agent listing lives under /scanners/null/agents in the modern
        API (where ``null`` aggregates across all scanners). Both work.
        """
        if limit <= 0 or limit > 5000:
            raise ValueError("limit must be between 1 and 5000")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        raw = self._request(
            "GET",
            "/scanners/null/agents",
            params={"limit": int(limit), "offset": int(offset)},
        )
        return self._normalize_agents(raw)

    def list_policies(self) -> Dict[str, Any]:
        """GET /policies — scan policies."""
        raw = self._request("GET", "/policies")
        return self._normalize_policies(raw)

    def workbench_vulnerabilities(
        self,
        *,
        date_range: Optional[int] = None,
        severity: Optional[List[int]] = None,
        vpr_score: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """POST /workbenches/vulnerabilities — workbench query.

        Tenable's workbench endpoint accepts ``date_range`` (days),
        ``severity`` filter, and a ``filter.search_type``-style VPR
        descriptor.
        """
        params: Dict[str, Any] = {}
        if date_range is not None:
            params["date_range"] = int(date_range)
        if severity:
            params["filter.0.filter"] = "severity"
            params["filter.0.quality"] = "eq"
            params["filter.0.value"] = ",".join(str(s) for s in severity)
        if vpr_score and isinstance(vpr_score, dict):
            params["filter.search_type"] = "and"
            for idx, (op, val) in enumerate(vpr_score.items(), start=1):
                params[f"filter.{idx}.filter"] = "vpr_score"
                params[f"filter.{idx}.quality"] = str(op)
                params[f"filter.{idx}.value"] = str(val)
        raw = self._request(
            "GET",
            "/workbenches/vulnerabilities",
            params=params or None,
        )
        return self._normalize_workbench(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_scans(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        scans_in = raw.get("scans") if isinstance(raw.get("scans"), list) else []
        scans_out: List[Dict[str, Any]] = []
        for s in scans_in:
            if not isinstance(s, dict):
                continue
            scans_out.append(
                {
                    "id": s.get("id") or 0,
                    "uuid": s.get("uuid") or "",
                    "name": s.get("name") or "",
                    "type": s.get("type") or "",
                    "status": s.get("status") or "",
                    "owner": s.get("owner") or "",
                    "creation_date": int(s.get("creation_date") or 0),
                    "last_modification_date": int(
                        s.get("last_modification_date") or 0
                    ),
                    "starttime": s.get("starttime") or "",
                    "schedule_uuid": s.get("schedule_uuid") or "",
                    "has_triggers": bool(s.get("has_triggers", False)),
                    "scan_uuid": s.get("scan_uuid") or s.get("uuid") or "",
                }
            )
        return {"scans": scans_out}

    @staticmethod
    def _normalize_scan_detail(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
        hosts_in = raw.get("hosts") if isinstance(raw.get("hosts"), list) else []
        vulns_in = (
            raw.get("vulnerabilities")
            if isinstance(raw.get("vulnerabilities"), list)
            else []
        )
        info_out = {
            "name": info.get("name") or "",
            "status": info.get("status") or "",
            "scan_start": int(info.get("scan_start") or 0),
            "scan_end": int(info.get("scan_end") or 0),
            "targets": info.get("targets") or "",
            "hostcount": int(info.get("hostcount") or 0),
            "severity_processed": int(info.get("severity_processed") or 0),
            "hosts_processed": int(info.get("hosts_processed") or 0),
            "scan_type": info.get("scan_type") or "",
        }
        hosts_out: List[Dict[str, Any]] = []
        for h in hosts_in:
            if not isinstance(h, dict):
                continue
            hosts_out.append(
                {
                    "host_id": int(h.get("host_id") or 0),
                    "hostname": h.get("hostname") or "",
                    "score": int(h.get("score") or 0),
                    "critical": int(h.get("critical") or 0),
                    "high": int(h.get("high") or 0),
                    "medium": int(h.get("medium") or 0),
                    "low": int(h.get("low") or 0),
                    "info": int(h.get("info") or 0),
                }
            )
        vulns_out: List[Dict[str, Any]] = []
        for v in vulns_in:
            if not isinstance(v, dict):
                continue
            vulns_out.append(
                {
                    "count": int(v.get("count") or 0),
                    "severity": int(v.get("severity") or 0),
                    "plugin_id": int(v.get("plugin_id") or 0),
                    "plugin_name": v.get("plugin_name") or "",
                    "plugin_family": v.get("plugin_family") or "",
                }
            )
        return {
            "info": info_out,
            "hosts": hosts_out,
            "vulnerabilities": vulns_out,
        }

    @staticmethod
    def _normalize_host_detail(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
        vulns_in = (
            raw.get("vulnerabilities")
            if isinstance(raw.get("vulnerabilities"), list)
            else []
        )
        compliance_in = (
            raw.get("compliance")
            if isinstance(raw.get("compliance"), list)
            else []
        )
        info_out = {
            "host_start": info.get("host_start") or "",
            "host_end": info.get("host_end") or "",
            "host_fqdn": info.get("host_fqdn") or "",
            "host_ip": info.get("host_ip") or "",
            "mac_address": info.get("mac-address") or info.get("mac_address") or "",
            "operating_system": (
                info.get("operating-system")
                if isinstance(info.get("operating-system"), list)
                else (
                    [info.get("operating_system")]
                    if info.get("operating_system")
                    else []
                )
            ),
        }
        # Coerce operating_system to a single string for client friendliness
        os_val = info_out["operating_system"]
        if isinstance(os_val, list):
            info_out["operating_system"] = "; ".join(
                str(x) for x in os_val if x
            )
        vulns_out: List[Dict[str, Any]] = []
        for v in vulns_in:
            if not isinstance(v, dict):
                continue
            cve_val = v.get("cve")
            if isinstance(cve_val, list):
                cve_norm = [str(c) for c in cve_val if c]
            elif cve_val:
                cve_norm = [str(cve_val)]
            else:
                cve_norm = []
            vulns_out.append(
                {
                    "vuln_index": int(v.get("vuln_index") or 0),
                    "plugin_id": int(v.get("plugin_id") or 0),
                    "plugin_name": v.get("plugin_name") or "",
                    "severity": int(v.get("severity") or 0),
                    "count": int(v.get("count") or 0),
                    "cve": cve_norm,
                }
            )
        compliance_out: List[Dict[str, Any]] = []
        for c in compliance_in:
            if not isinstance(c, dict):
                continue
            compliance_out.append(
                {
                    "check_id": str(c.get("check_id") or c.get("checkpoint_id") or ""),
                    "severity": int(c.get("severity") or 0),
                    "count": int(c.get("count") or 0),
                }
            )
        return {
            "info": info_out,
            "vulnerabilities": vulns_out,
            "compliance": compliance_out,
        }

    @staticmethod
    def _normalize_agents(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        agents_in = (
            raw.get("agents") if isinstance(raw.get("agents"), list) else []
        )
        agents_out: List[Dict[str, Any]] = []
        for a in agents_in:
            if not isinstance(a, dict):
                continue
            agents_out.append(
                {
                    "id": int(a.get("id") or 0),
                    "uuid": a.get("uuid") or "",
                    "name": a.get("name") or "",
                    "platform": a.get("platform") or "",
                    "distro": a.get("distro") or "",
                    "ip": a.get("ip") or "",
                    "last_scanned": int(a.get("last_scanned") or 0),
                    "plugin_feed_id": a.get("plugin_feed_id") or "",
                    "core_version": a.get("core_version") or "",
                    "status": a.get("status") or "",
                    "network_uuid": a.get("network_uuid") or "",
                }
            )
        return {"agents": agents_out}

    @staticmethod
    def _normalize_policies(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        policies_in = (
            raw.get("policies") if isinstance(raw.get("policies"), list) else []
        )
        policies_out: List[Dict[str, Any]] = []
        for p in policies_in:
            if not isinstance(p, dict):
                continue
            policies_out.append(
                {
                    "id": int(p.get("id") or 0),
                    "template_uuid": p.get("template_uuid") or "",
                    "name": p.get("name") or "",
                    "description": p.get("description") or "",
                    "owner": p.get("owner") or "",
                    "visibility": p.get("visibility") or "",
                    "shared": int(p.get("shared") or 0),
                    "user_permissions": int(p.get("user_permissions") or 0),
                    "last_modification_date": int(
                        p.get("last_modification_date") or 0
                    ),
                }
            )
        return {"policies": policies_out}

    @staticmethod
    def _normalize_workbench(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        vulns_in = (
            raw.get("vulnerabilities")
            if isinstance(raw.get("vulnerabilities"), list)
            else []
        )
        vulns_out: List[Dict[str, Any]] = []
        for v in vulns_in:
            if not isinstance(v, dict):
                continue
            vpr_in = v.get("vpr_score") if isinstance(v.get("vpr_score"), dict) else {}
            drivers = (
                vpr_in.get("drivers")
                if isinstance(vpr_in.get("drivers"), dict)
                else {}
            )
            vulns_out.append(
                {
                    "count": int(v.get("count") or 0),
                    "plugin_id": int(v.get("plugin_id") or 0),
                    "severity": int(v.get("severity") or 0),
                    "plugin_name": v.get("plugin_name") or "",
                    "plugin_family": v.get("plugin_family") or "",
                    "vpr_score": {
                        "score": float(vpr_in.get("score") or 0.0),
                        "drivers": drivers,
                    },
                }
            )
        return {"vulnerabilities": vulns_out}

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[TenableIOEngine] = None
_singleton_lock = threading.Lock()


def get_tenable_io_engine(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> TenableIOEngine:
    """Return the process-wide TenableIOEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = TenableIOEngine(
                access_key=access_key,
                secret_key=secret_key,
                client=client,
            )
        return _singleton


def reset_tenable_io_engine() -> None:
    """Tear down the singleton — used by tests with stub clients."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "TenableIOEngine",
    "TenableUnavailableError",
    "get_tenable_io_engine",
    "reset_tenable_io_engine",
]
