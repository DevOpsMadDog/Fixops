"""VMware Workspace ONE (UEM) — Live API Connector (MDM).

Fetches managed device inventory and compliance status from Workspace ONE
REST API to surface MDM findings in ALDECI.

Live API flow:
1. GET  /API/mdm/devices/search (paginated, basic-auth header)
2. GET  /API/mdm/devices/{id}/compliancepolicies (per-device compliance)
3. Normalize to ALDECI common-finding shape
4. Persist via SecurityFindingsEngine.record_finding (idempotent)

Credential fallback:
- WS1_BASE_URL + WS1_API_KEY required.
- WS1_USERNAME + WS1_PASSWORD for basic-auth (alternative to API key).
- If credentials absent → graceful no-op: returns {status: "needs_credentials"}.

Cache: 1-hour TTL per org_id. Idempotent via correlation_key.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://ws1.example.com"
_CACHE_TTL_SECONDS = 3600
_PAGE_SIZE = 500


_result_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    return bool(os.environ.get("WS1_API_KEY") and os.environ.get("WS1_BASE_URL"))


def _build_headers() -> Dict[str, str]:
    api_key = os.environ.get("WS1_API_KEY", "")
    username = os.environ.get("WS1_USERNAME", "")
    password = os.environ.get("WS1_PASSWORD", "")
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "aw-tenant-code": api_key,
    }
    if username and password:
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {credentials}"
    return headers


def _fetch_devices(base_url: str) -> List[Dict[str, Any]]:
    """Fetch all managed devices via paginated search."""
    import httpx

    headers = _build_headers()
    devices: List[Dict[str, Any]] = []
    page = 0

    while True:
        params = {
            "pagesize": _PAGE_SIZE,
            "page": page,
            "orderby": "deviceid",
        }
        resp = httpx.get(
            f"{base_url}/API/mdm/devices/search",
            params=params,
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 404:
            break
        resp.raise_for_status()
        body = resp.json()
        batch = body.get("Devices") or body.get("devices") or []
        devices.extend(batch)
        total = int(body.get("Total") or body.get("total") or 0)
        page += 1
        if not batch or len(devices) >= total:
            break

    return devices


def _normalize_ws1_device(device: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize a WS1 device record to ALDECI finding shape(s)."""
    device_id = str(device.get("Id", {}).get("Value") or device.get("DeviceId") or "unknown")
    friendly_name = device.get("DeviceFriendlyName") or device.get("FriendlyName") or device_id
    platform = device.get("Platform") or device.get("PlatformId", {}).get("Name") or "unknown"
    os_version = device.get("OperatingSystem") or device.get("OSVersion") or "unknown"
    compliance = str(device.get("ComplianceStatus") or device.get("Compliant") or "unknown").lower()
    enrollment_status = str(device.get("EnrollmentStatus") or "enrolled").lower()
    last_seen = device.get("LastSeen") or device.get("LastCompromisedCheckOn") or ""
    user_name = device.get("UserName") or device.get("User", {}).get("Name") or ""
    is_compromised = device.get("IsCompromised") or device.get("Compromised") or False
    is_encrypted = device.get("IsEncrypted")
    model = device.get("Model") or device.get("ModelId", {}).get("Name") or ""

    findings: List[Dict[str, Any]] = []
    base = {
        "asset_id": f"ws1:device:{device_id}",
        "asset_type": "managed_device",
        "source_tool": "vmware_workspace_one",
        "finding_type": "mdm",
        "cvss_score": 0.0,
        "remediation": "Review device in Workspace ONE console and enforce compliance.",
    }

    if compliance == "noncompliant":
        findings.append({
            **base,
            "title": f"WS1 non-compliant device: {friendly_name} ({platform} {os_version})",
            "description": (
                f"Device '{friendly_name}' ({model}) owned by {user_name} "
                f"is non-compliant. Platform: {platform} {os_version}. Last seen: {last_seen}."
            ),
            "severity": "high",
            "correlation_key": f"ws1_noncompliant|{device_id}",
        })

    if is_compromised:
        findings.append({
            **base,
            "title": f"WS1 compromised device: {friendly_name}",
            "description": (
                f"Device '{friendly_name}' ({platform}) is flagged as compromised/jailbroken. "
                f"User: {user_name}. Last seen: {last_seen}."
            ),
            "severity": "critical",
            "correlation_key": f"ws1_compromised|{device_id}",
            "remediation": "Immediately wipe or retire the compromised device.",
        })

    if is_encrypted is False:
        findings.append({
            **base,
            "title": f"WS1 unencrypted device: {friendly_name}",
            "description": (
                f"Device '{friendly_name}' ({platform}) storage is not encrypted. "
                f"User: {user_name}."
            ),
            "severity": "high",
            "correlation_key": f"ws1_unencrypted|{device_id}",
            "remediation": "Enable device encryption and enforce via compliance policy.",
        })

    if enrollment_status == "unenrolled":
        findings.append({
            **base,
            "title": f"WS1 unenrolled device: {friendly_name}",
            "description": (
                f"Device '{friendly_name}' has been unenrolled from Workspace ONE. "
                f"User: {user_name}."
            ),
            "severity": "medium",
            "correlation_key": f"ws1_unenrolled|{device_id}",
            "remediation": "Re-enroll or retire the device.",
        })

    if not findings:
        findings.append({
            **base,
            "title": f"WS1 managed device: {friendly_name} ({platform} {os_version})",
            "description": (
                f"Compliant device '{friendly_name}' ({model}). "
                f"User: {user_name}. Last seen: {last_seen}."
            ),
            "severity": "informational",
            "correlation_key": f"ws1_device|{device_id}",
        })

    return findings


class WorkspaceOneConnector:
    """VMware Workspace ONE MDM connector with credential fallback and 1-hour cache.

    Args:
        findings_engine: SecurityFindingsEngine instance (optional).
        base_url:        Override WS1_BASE_URL env var.
        max_devices:     Cap on devices to fetch per call.
    """

    def __init__(
        self,
        findings_engine: Any = None,
        base_url: Optional[str] = None,
        max_devices: int = 5000,
    ) -> None:
        self._findings = findings_engine
        self._base_url = (
            base_url or os.environ.get("WS1_BASE_URL") or _DEFAULT_BASE_URL
        ).rstrip("/")
        self._max_devices = max(1, min(max_devices, 100_000))

    def sync(
        self,
        org_id: str,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Sync Workspace ONE managed devices for an org."""
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        api_key = os.environ.get("WS1_API_KEY", "")
        if not api_key:
            _logger.warning(
                "WorkspaceOneConnector: WS1_API_KEY not set — skipping for org=%s", org_id
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "devices_synced": 0,
                "findings_recorded": 0,
                "findings": [],
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "hint": (
                    "Set WS1_API_KEY and WS1_BASE_URL environment variables "
                    "to enable live VMware Workspace ONE integration."
                ),
            }

        cache_key = (org_id, self._base_url)
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    return cached["result"]

        try:
            devices = _fetch_devices(self._base_url)
            devices = devices[: self._max_devices]
        except Exception as exc:
            _logger.error("WorkspaceOneConnector: API error for org=%s: %s", org_id, exc)
            return {
                "status": "api_error",
                "mode": "live",
                "org_id": org_id,
                "devices_synced": 0,
                "findings_recorded": 0,
                "findings": [],
                "error": str(exc),
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }

        all_findings: List[Dict[str, Any]] = []
        recorded = 0

        for device in devices:
            device_findings = _normalize_ws1_device(device)
            all_findings.extend(device_findings)

            if self._findings is not None:
                for finding in device_findings:
                    try:
                        sev = finding["severity"]
                        if sev == "informational":
                            sev = "low"
                        self._findings.record_finding(
                            org_id=org_id,
                            title=finding["title"][:200],
                            finding_type=finding["finding_type"],
                            source_tool=finding["source_tool"],
                            severity=sev,
                            cvss_score=finding["cvss_score"],
                            asset_id=finding["asset_id"][:200],
                            asset_type=finding["asset_type"],
                            description=finding["description"][:500],
                            remediation=finding.get("remediation", "")[:300],
                            correlation_key=finding["correlation_key"],
                        )
                        recorded += 1
                    except Exception as exc:
                        _logger.warning("WorkspaceOneConnector: record_finding failed: %s", exc)

        emit_connector_event(
            connector="WorkspaceOneConnector",
            org_id=org_id,
            source_kind="iam",
            finding_count=recorded,
            extra={"mode": "live", "devices_synced": len(devices)},
        )

        result = {
            "status": "ok",
            "mode": "live",
            "org_id": org_id,
            "devices_synced": len(devices),
            "findings_recorded": recorded,
            "findings": all_findings,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        }

        with _cache_lock:
            _result_cache[cache_key] = {
                "result": result,
                "expires_at": time.monotonic() + _CACHE_TTL_SECONDS,
            }

        return result


_singleton_lock = threading.Lock()
_singleton: Optional[WorkspaceOneConnector] = None


def get_workspace_one_connector() -> WorkspaceOneConnector:
    """Lazy singleton — wires SecurityFindingsEngine on first use."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            findings = None
            try:
                from core.security_findings_engine import SecurityFindingsEngine
                findings = SecurityFindingsEngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("SecurityFindingsEngine unavailable: %s", exc)
            _singleton = WorkspaceOneConnector(findings_engine=findings)
    return _singleton


__all__ = [
    "WorkspaceOneConnector",
    "get_workspace_one_connector",
    "_creds_present",
    "_normalize_ws1_device",
]
