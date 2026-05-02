"""Microsoft Intune — Live API Connector (MDM).

Fetches managed device inventory from Microsoft Graph API and surfaces
MDM compliance/configuration findings in ALDECI.

Live API flow:
1. POST /oauth2/v2.0/token (client_credentials) → bearer token
2. GET  /v1.0/deviceManagement/managedDevices (paginated via @odata.nextLink)
3. GET  /v1.0/deviceManagement/managedDevices/{id}/deviceCompliancePolicyStates
4. Normalize to ALDECI common-finding shape
5. Persist via SecurityFindingsEngine.record_finding (idempotent)

Credential fallback:
- INTUNE_TENANT_ID + INTUNE_CLIENT_ID + INTUNE_CLIENT_SECRET required.
- If credentials absent → graceful no-op: returns {status: "needs_credentials"}.

Cache: 1-hour TTL per org_id. Idempotent via correlation_key.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com"
_TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_CACHE_TTL_SECONDS = 3600
_TOKEN_TTL_SECONDS = 3540  # 59 min; Graph tokens last 60 min
_PAGE_SIZE = 999            # Graph max $top


_token_cache: Dict[str, Any] = {}
_result_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    return bool(
        os.environ.get("INTUNE_TENANT_ID")
        and os.environ.get("INTUNE_CLIENT_ID")
        and os.environ.get("INTUNE_CLIENT_SECRET")
    )


def _get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain or reuse a cached Graph API bearer token."""
    cache_key = (tenant_id, client_id)
    with _cache_lock:
        cached = _token_cache.get(cache_key)
        if cached and time.monotonic() < cached["expires_at"]:
            return cached["token"]

    import httpx

    url = _TOKEN_URL_TMPL.format(tenant_id=tenant_id)
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": _GRAPH_SCOPE,
    }
    resp = httpx.post(url, data=data, timeout=15)
    resp.raise_for_status()
    body = resp.json()
    token = body.get("access_token", "")
    if not token:
        raise ValueError("Intune/Graph OAuth2 returned no access_token")
    expires_in = int(body.get("expires_in", _TOKEN_TTL_SECONDS))

    with _cache_lock:
        _token_cache[cache_key] = {
            "token": token,
            "expires_at": time.monotonic() + expires_in - 60,
        }
    return token


def _graph_get_all(token: str, url: str) -> List[Dict[str, Any]]:
    """Follow @odata.nextLink pagination to collect all items."""
    import httpx

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    items: List[Dict[str, Any]] = []
    next_url: Optional[str] = url

    while next_url:
        resp = httpx.get(next_url, headers=headers, timeout=30)
        resp.raise_for_status()
        body = resp.json()
        items.extend(body.get("value", []))
        next_url = body.get("@odata.nextLink")

    return items


def _compliance_severity(states: List[Dict[str, Any]]) -> str:
    """Derive finding severity from compliance policy states."""
    if not states:
        return "informational"
    non_compliant = [s for s in states if s.get("state") == "nonCompliant"]
    if non_compliant:
        return "high"
    error_states = [s for s in states if s.get("state") == "error"]
    if error_states:
        return "medium"
    return "low"


def _normalize_device(device: Dict[str, Any], compliance_states: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize an Intune managed device to ALDECI finding shape(s)."""
    device_id = device.get("id", "unknown")
    device_name = device.get("deviceName") or device.get("managedDeviceName") or device_id
    os_name = device.get("operatingSystem", "unknown")
    os_version = device.get("osVersion", "unknown")
    compliance = device.get("complianceState", "unknown")
    enrolled_at = device.get("enrolledDateTime", "")
    last_sync = device.get("lastSyncDateTime", "")
    user_principal = device.get("userPrincipalName", "")
    manufacturer = device.get("manufacturer", "")
    model = device.get("model", "")
    device.get("managementAgent") != "unknown"
    is_encrypted = device.get("isEncrypted", True)
    jailbroken = device.get("jailBroken", "Unknown")

    findings: List[Dict[str, Any]] = []
    base = {
        "asset_id": f"intune:device:{device_id}",
        "asset_type": "managed_device",
        "source_tool": "microsoft_intune",
        "finding_type": "mdm",
        "cvss_score": 0.0,
        "remediation": "Review device in Intune portal and enforce compliance policies.",
    }

    # Non-compliant device
    if compliance == "noncompliant":
        sev = _compliance_severity(compliance_states)
        findings.append({
            **base,
            "title": f"Intune non-compliant device: {device_name} ({os_name} {os_version})",
            "description": (
                f"Device '{device_name}' ({manufacturer} {model}) owned by {user_principal} "
                f"is non-compliant. OS: {os_name} {os_version}. Last sync: {last_sync}."
            ),
            "severity": sev,
            "correlation_key": f"intune_noncompliant|{device_id}",
        })

    # Unencrypted device
    if not is_encrypted:
        findings.append({
            **base,
            "title": f"Intune unencrypted device: {device_name}",
            "description": (
                f"Device '{device_name}' ({os_name}) is not encrypted. "
                f"User: {user_principal}. Enrolled: {enrolled_at}."
            ),
            "severity": "high",
            "correlation_key": f"intune_unencrypted|{device_id}",
            "remediation": "Enable BitLocker/FileVault encryption and enforce via compliance policy.",
        })

    # Jailbroken/rooted
    if jailbroken and jailbroken not in ("Unknown", "False", False, None):
        findings.append({
            **base,
            "title": f"Intune jailbroken/rooted device: {device_name}",
            "description": (
                f"Device '{device_name}' ({os_name}) is reported as jailbroken/rooted. "
                f"User: {user_principal}."
            ),
            "severity": "critical",
            "correlation_key": f"intune_jailbroken|{device_id}",
            "remediation": "Remotely wipe or retire the device immediately.",
        })

    # If no findings, emit an informational record for inventory
    if not findings:
        findings.append({
            **base,
            "title": f"Intune managed device: {device_name} ({os_name} {os_version})",
            "description": (
                f"Compliant device '{device_name}' ({manufacturer} {model}). "
                f"User: {user_principal}. Last sync: {last_sync}."
            ),
            "severity": "informational",
            "correlation_key": f"intune_device|{device_id}",
        })

    return findings


class IntuneConnector:
    """Microsoft Intune MDM connector with credential fallback and 1-hour cache.

    Args:
        findings_engine:  SecurityFindingsEngine instance (optional).
        max_devices:      Cap on devices to fetch per call.
    """

    def __init__(
        self,
        findings_engine: Any = None,
        max_devices: int = 5000,
    ) -> None:
        self._findings = findings_engine
        self._max_devices = max(1, min(max_devices, 100_000))

    def sync(
        self,
        org_id: str,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Sync Intune managed devices for an org.

        Returns normalized ALDECI findings. Gracefully returns
        {status: "needs_credentials"} when env vars are absent.
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        tenant_id = os.environ.get("INTUNE_TENANT_ID", "")
        client_id = os.environ.get("INTUNE_CLIENT_ID", "")
        client_secret = os.environ.get("INTUNE_CLIENT_SECRET", "")

        if not tenant_id or not client_id or not client_secret:
            _logger.warning(
                "IntuneConnector: INTUNE_* creds not set — skipping for org=%s", org_id
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
                    "Set INTUNE_TENANT_ID, INTUNE_CLIENT_ID, and INTUNE_CLIENT_SECRET "
                    "environment variables to enable live Microsoft Intune integration."
                ),
            }

        cache_key = (org_id, tenant_id)
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    return cached["result"]

        try:
            token = _get_token(tenant_id, client_id, client_secret)
            devices_url = (
                f"{_GRAPH_BASE}/v1.0/deviceManagement/managedDevices"
                f"?$top={_PAGE_SIZE}"
            )
            devices = _graph_get_all(token, devices_url)
            devices = devices[: self._max_devices]
        except Exception as exc:
            _logger.error("IntuneConnector: API error for org=%s: %s", org_id, exc)
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
            device_id = device.get("id", "unknown")
            # Fetch compliance states per device (best-effort)
            compliance_states: List[Dict[str, Any]] = []
            try:
                cs_url = (
                    f"{_GRAPH_BASE}/v1.0/deviceManagement/managedDevices"
                    f"/{device_id}/deviceCompliancePolicyStates"
                )
                import httpx
                headers = {"Authorization": f"Bearer {token}"}
                cs_resp = httpx.get(cs_url, headers=headers, timeout=10)
                if cs_resp.status_code == 200:
                    compliance_states = cs_resp.json().get("value", [])
            except Exception:
                pass

            device_findings = _normalize_device(device, compliance_states)
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
                        _logger.warning("IntuneConnector: record_finding failed: %s", exc)

        emit_connector_event(
            connector="IntuneConnector",
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
_singleton: Optional[IntuneConnector] = None


def get_intune_connector() -> IntuneConnector:
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
            _singleton = IntuneConnector(findings_engine=findings)
    return _singleton


__all__ = [
    "IntuneConnector",
    "get_intune_connector",
    "_creds_present",
    "_normalize_device",
]
