"""Jamf Pro MDM Connector — ALDECI.

Wires the `/api/v1/mdm/devices` endpoint (triage item #24) with real
device inventory data from Jamf Pro.

Data sources:
1. **Jamf Pro Classic API** — GET /JSSResource/computers (XML; all managed Macs)
2. **Jamf Pro Classic API** — GET /JSSResource/mobiledevices (XML; iOS/iPadOS)

Both return a roster with id, name, serial_number, last_contact_time, managed,
supervised, os_version, model, username, department.

Security findings generated:
- Device not checked in for >7 days → medium finding
- OS version flagged as out of date (heuristic: major.minor < threshold) → medium
- Device unmanaged/unenrolled → high finding
- Supervised = false for corporate-issued → low finding

Required env vars:
    JAMF_BASE_URL   e.g. https://mycompany.jamfcloud.com  (no trailing slash)
    JAMF_API_KEY    Jamf Pro API bearer token  OR
    JAMF_USERNAME   Basic-auth username (used only if JAMF_API_KEY absent)
    JAMF_PASSWORD   Basic-auth password

Credential fallback: if JAMF_BASE_URL absent OR neither JAMF_API_KEY
nor (JAMF_USERNAME + JAMF_PASSWORD) are set →
    {status: "needs_credentials"} — no crash.

Cache: 1-hour TTL per org_id.
Idempotent: correlation_key="jamf_device|{serial_number}".
"""

from __future__ import annotations

import base64
import logging
import os
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 3600
_DEFAULT_MAX_DEVICES = 2000
_STALE_DAYS = 7          # devices not seen in 7 days → medium finding
_MIN_MACOS_MAJOR = 13    # macOS Ventura — older → out-of-date finding
_MIN_IOS_MAJOR = 16      # iOS 16 — older → out-of-date finding

# Module-level cache
_result_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    base = os.environ.get("JAMF_BASE_URL", "")
    if not base:
        return False
    if os.environ.get("JAMF_API_KEY"):
        return True
    return bool(os.environ.get("JAMF_USERNAME") and os.environ.get("JAMF_PASSWORD"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_auth_headers(api_key: str, username: str, password: str) -> Dict[str, str]:
    """Build Authorization header: prefer bearer token, fall back to Basic."""
    if api_key:
        return {"Authorization": f"Bearer {api_key}", "Accept": "application/xml"}
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {creds}", "Accept": "application/xml"}


def _jamf_get(base_url: str, path: str, headers: Dict[str, str]) -> ET.Element:
    """GET {base_url}{path} and return parsed XML root element."""
    import httpx

    url = f"{base_url}{path}"
    resp = httpx.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return ET.fromstring(resp.content)


def _xml_text(elem: ET.Element, tag: str, default: str = "") -> str:
    """Safely extract text from a child element."""
    child = elem.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def _parse_computers(root: ET.Element) -> List[Dict[str, Any]]:
    """Parse /JSSResource/computers XML response into device dicts."""
    devices: List[Dict[str, Any]] = []
    for comp in root.findall(".//computer"):
        serial = _xml_text(comp, "serial_number")
        devices.append({
            "device_id": _xml_text(comp, "id"),
            "name": _xml_text(comp, "name"),
            "serial_number": serial,
            "udid": _xml_text(comp, "udid"),
            "mac_address": _xml_text(comp, "mac_address"),
            "model": _xml_text(comp, "model"),
            "os_version": _xml_text(comp, "os_version"),
            "last_contact_time": _xml_text(comp, "last_contact_time"),
            "managed": _xml_text(comp, "managed", "false").lower() == "true",
            "supervised": None,   # computers don't have supervised flag
            "username": _xml_text(comp, "username"),
            "department": _xml_text(comp, "department"),
            "building": _xml_text(comp, "building"),
            "platform": "macOS",
        })
    return devices


def _parse_mobile_devices(root: ET.Element) -> List[Dict[str, Any]]:
    """Parse /JSSResource/mobiledevices XML response into device dicts."""
    devices: List[Dict[str, Any]] = []
    for dev in root.findall(".//mobile_device"):
        serial = _xml_text(dev, "serial_number")
        devices.append({
            "device_id": _xml_text(dev, "id"),
            "name": _xml_text(dev, "name"),
            "serial_number": serial,
            "udid": _xml_text(dev, "udid"),
            "mac_address": _xml_text(dev, "wifi_mac_address"),
            "model": _xml_text(dev, "model"),
            "os_version": _xml_text(dev, "os_version"),
            "last_contact_time": _xml_text(dev, "last_inventory_update"),
            "managed": _xml_text(dev, "managed", "false").lower() == "true",
            "supervised": _xml_text(dev, "supervised", "false").lower() == "true",
            "username": _xml_text(dev, "username"),
            "department": _xml_text(dev, "department"),
            "building": _xml_text(dev, "building"),
            "platform": "iOS",
        })
    return devices


def _parse_jamf_date(date_str: str) -> Optional[datetime]:
    """Parse Jamf date strings: 'YYYY-MM-DD HH:MM:SS' or ISO-8601."""
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _device_findings(device: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate security findings for a single Jamf device record.

    Returns a (possibly empty) list of finding dicts.
    """
    findings: List[Dict[str, Any]] = []
    serial = device.get("serial_number") or device.get("udid") or device.get("device_id") or "unknown"
    name = device.get("name") or serial
    platform = device.get("platform", "macOS")
    managed = device.get("managed", True)
    supervised = device.get("supervised")

    # 1. Unmanaged device — high severity
    if not managed:
        findings.append({
            "title": f"Jamf MDM: Unmanaged Device [{name}]",
            "finding_type": "policy-violation",
            "source_tool": "jamf_mdm",
            "severity": "high",
            "cvss_score": 7.2,
            "asset_id": serial[:200],
            "asset_type": "device",
            "description": (
                f"Device '{name}' (serial={serial}, platform={platform}) "
                "is enrolled in Jamf but management is disabled. "
                "MDM profile may have been removed."
            ),
            "remediation": (
                "Re-enroll the device in Jamf MDM or mark as retired. "
                "Unmanaged corporate devices violate endpoint compliance policy."
            ),
            "correlation_key": f"jamf_device|{serial}|unmanaged",
        })

    # 2. Stale check-in — medium severity
    last_contact_str = device.get("last_contact_time") or ""
    last_dt = _parse_jamf_date(last_contact_str)
    if last_dt is not None:
        now_utc = datetime.now(timezone.utc)
        delta = now_utc - last_dt
        if delta > timedelta(days=_STALE_DAYS):
            days_ago = delta.days
            findings.append({
                "title": f"Jamf MDM: Device Not Checked In [{name}] ({days_ago}d ago)",
                "finding_type": "anomaly",
                "source_tool": "jamf_mdm",
                "severity": "medium",
                "cvss_score": 5.3,
                "asset_id": serial[:200],
                "asset_type": "device",
                "description": (
                    f"Device '{name}' (serial={serial}) last contacted Jamf "
                    f"{days_ago} days ago ({last_contact_str}). "
                    f"Stale devices may have missed critical security patches."
                ),
                "remediation": (
                    f"Locate device '{name}' and verify it is powered on and "
                    "connected to the network. Push a check-in command from "
                    "Jamf Pro Management > Send Commands."
                ),
                "correlation_key": f"jamf_device|{serial}|stale",
            })

    # 3. Out-of-date OS — medium severity
    os_ver_str = device.get("os_version") or ""
    if os_ver_str:
        try:
            major_str = os_ver_str.split(".")[0]
            major = int(major_str)
            if platform == "macOS" and major < _MIN_MACOS_MAJOR:
                findings.append({
                    "title": f"Jamf MDM: Outdated macOS [{name}] (v{os_ver_str})",
                    "finding_type": "vulnerability",
                    "source_tool": "jamf_mdm",
                    "severity": "medium",
                    "cvss_score": 5.0,
                    "asset_id": serial[:200],
                    "asset_type": "device",
                    "description": (
                        f"Device '{name}' is running macOS {os_ver_str} "
                        f"(minimum required: {_MIN_MACOS_MAJOR}.x). "
                        "Older macOS versions lack current security patches."
                    ),
                    "remediation": (
                        f"Upgrade to macOS {_MIN_MACOS_MAJOR}.x or later via "
                        "Jamf Remote Commands > Install macOS Update."
                    ),
                    "correlation_key": f"jamf_device|{serial}|outdated_os",
                })
            elif platform == "iOS" and major < _MIN_IOS_MAJOR:
                findings.append({
                    "title": f"Jamf MDM: Outdated iOS [{name}] (v{os_ver_str})",
                    "finding_type": "vulnerability",
                    "source_tool": "jamf_mdm",
                    "severity": "medium",
                    "cvss_score": 5.0,
                    "asset_id": serial[:200],
                    "asset_type": "device",
                    "description": (
                        f"Device '{name}' is running iOS {os_ver_str} "
                        f"(minimum required: {_MIN_IOS_MAJOR}.x)."
                    ),
                    "remediation": (
                        "Push an MDM update command via Jamf Pro: "
                        "Management > Send Commands > Update iOS."
                    ),
                    "correlation_key": f"jamf_device|{serial}|outdated_ios",
                })
        except (ValueError, IndexError):
            pass

    # 4. Unsupervised corporate iOS — low severity
    if platform == "iOS" and supervised is False:
        findings.append({
            "title": f"Jamf MDM: Unsupervised iOS Device [{name}]",
            "finding_type": "policy-violation",
            "source_tool": "jamf_mdm",
            "severity": "low",
            "cvss_score": 2.5,
            "asset_id": serial[:200],
            "asset_type": "device",
            "description": (
                f"iOS device '{name}' (serial={serial}) is enrolled but not supervised. "
                "Supervised mode is required for full MDM control (DEP enrollment)."
            ),
            "remediation": (
                "Re-enroll device through Apple Business Manager (ABM) / "
                "Device Enrollment Program (DEP) to enable supervision."
            ),
            "correlation_key": f"jamf_device|{serial}|unsupervised",
        })

    return findings


# ---------------------------------------------------------------------------
# Public connector class
# ---------------------------------------------------------------------------
class JamfConnector:
    """Jamf Pro MDM connector — syncs device inventory and generates findings.

    Args:
        findings_engine: SecurityFindingsEngine instance (optional).
        max_devices:     Cap on devices to process (default 2000).
    """

    def __init__(
        self,
        findings_engine: Any = None,
        max_devices: int = _DEFAULT_MAX_DEVICES,
    ) -> None:
        self._findings = findings_engine
        self._max_devices = max(1, min(max_devices, 50_000))

    def sync(
        self,
        org_id: str,
        force_refresh: bool = False,
        include_mobile: bool = True,
    ) -> Dict[str, Any]:
        """Sync Jamf device inventory and push findings for org_id.

        Returns:
            {status, mode, org_id, devices_synced, findings_recorded,
             devices, device_findings, ingested_at}
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        base_url = os.environ.get("JAMF_BASE_URL", "").rstrip("/")
        api_key = os.environ.get("JAMF_API_KEY", "")
        username = os.environ.get("JAMF_USERNAME", "")
        password = os.environ.get("JAMF_PASSWORD", "")

        if not base_url or (not api_key and not (username and password)):
            _logger.warning(
                "JamfConnector: JAMF_BASE_URL / JAMF_API_KEY (or JAMF_USERNAME+PASSWORD) "
                "not set — skipping live fetch for org=%s", org_id
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "devices_synced": 0,
                "findings_recorded": 0,
                "devices": [],
                "device_findings": [],
                "ingested_at": _now_iso(),
                "hint": (
                    "Set JAMF_BASE_URL and JAMF_API_KEY (or JAMF_USERNAME + JAMF_PASSWORD) "
                    "environment variables to enable live Jamf MDM integration."
                ),
            }

        cache_key = (org_id, base_url)
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    _logger.debug("JamfConnector: returning cached result for org=%s", org_id)
                    return cached["result"]

        headers = _build_auth_headers(api_key, username, password)
        all_devices: List[Dict[str, Any]] = []
        errors: List[str] = []

        # Fetch computers
        try:
            root = _jamf_get(base_url, "/JSSResource/computers", headers)
            computers = _parse_computers(root)
            all_devices.extend(computers)
        except Exception as exc:
            _logger.error("JamfConnector: computers fetch failed for org=%s: %s", org_id, exc)
            errors.append(f"computers: {exc}")

        # Fetch mobile devices
        if include_mobile:
            try:
                root = _jamf_get(base_url, "/JSSResource/mobiledevices", headers)
                mobiles = _parse_mobile_devices(root)
                all_devices.extend(mobiles)
            except Exception as exc:
                _logger.error("JamfConnector: mobiledevices fetch failed for org=%s: %s", org_id, exc)
                errors.append(f"mobiledevices: {exc}")

        # Cap device count
        all_devices = all_devices[: self._max_devices]

        # Generate + persist findings
        all_device_findings: List[Dict[str, Any]] = []
        recorded = 0

        for device in all_devices:
            findings = _device_findings(device)
            all_device_findings.extend(findings)

            if self._findings is not None:
                for f in findings:
                    try:
                        self._findings.record_finding(
                            org_id=org_id,
                            title=f["title"],
                            finding_type=f["finding_type"],
                            source_tool=f["source_tool"],
                            severity=f["severity"],
                            cvss_score=f["cvss_score"],
                            asset_id=f["asset_id"],
                            asset_type=f["asset_type"],
                            description=f["description"],
                            remediation=f["remediation"],
                            correlation_key=f["correlation_key"],
                        )
                        recorded += 1
                    except (ValueError, TypeError, AttributeError) as exc:
                        _logger.warning(
                            "JamfConnector: record_finding failed for %s: %s",
                            f.get("correlation_key", "?"), exc,
                        )

        emit_connector_event(
            connector="JamfConnector",
            org_id=org_id,
            source_kind="asset",
            finding_count=recorded,
            extra={
                "mode": "live",
                "devices_synced": len(all_devices),
                "findings_generated": len(all_device_findings),
                "errors": errors,
            },
        )

        result = {
            "status": "ok" if not errors else "partial",
            "mode": "live",
            "org_id": org_id,
            "devices_synced": len(all_devices),
            "findings_recorded": recorded,
            "devices": all_devices,
            "device_findings": all_device_findings,
            "errors": errors,
            "ingested_at": _now_iso(),
        }

        with _cache_lock:
            _result_cache[cache_key] = {
                "result": result,
                "expires_at": time.monotonic() + _CACHE_TTL_SECONDS,
            }

        return result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_singleton_lock = threading.Lock()
_singleton: Optional[JamfConnector] = None


def get_jamf_connector() -> JamfConnector:
    """Lazy singleton wired to SecurityFindingsEngine."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            findings = None
            try:
                from core.security_findings_engine import SecurityFindingsEngine
                findings = SecurityFindingsEngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("SecurityFindingsEngine unavailable: %s", exc)
            _singleton = JamfConnector(findings_engine=findings)
    return _singleton


__all__ = [
    "JamfConnector",
    "get_jamf_connector",
    "_creds_present",
    "_normalize_user",
    "_parse_computers",
    "_parse_mobile_devices",
    "_device_findings",
]
