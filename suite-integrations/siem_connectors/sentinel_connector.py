"""Microsoft Sentinel Connector — ALDECI.

Sends security findings, alerts, and events to Microsoft Sentinel
via the Azure Monitor Data Collection API (DCR-based ingestion).

Auth: Azure AD client credentials (tenant_id, client_id, client_secret).
Reference: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import httpx

    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity mapping: ALDECI → Sentinel InformationalSeverity
# ---------------------------------------------------------------------------
_SEVERITY_MAP: Dict[str, str] = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}

_ALDECI_TO_SENTINEL_STATUS: Dict[str, str] = {
    "open": "New",
    "acknowledged": "InProgress",
    "in_progress": "InProgress",
    "resolved": "Closed",
    "closed": "Closed",
}


@dataclass
class SentinelConfig:
    """Configuration for Microsoft Sentinel Data Collection API."""

    # Azure AD credentials
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""  # will be hashed at rest

    # Data Collection Rule (DCR)
    dcr_endpoint: str = ""  # e.g. https://my-dcr.eastus-1.ingest.monitor.azure.com
    dcr_rule_id: str = ""  # DCR immutable ID (dcr-...)
    stream_name: str = "Custom-ALDECISecurityEvents_CL"

    # Workspace (for legacy Log Analytics API fallback)
    workspace_id: str = ""
    log_type: str = "ALDECISecurityEvents"

    max_retries: int = 3
    base_delay_s: float = 1.0
    timeout_s: float = 30.0
    batch_size: int = 100

    _secret_hash: str = field(default="", repr=False, init=False)

    def __post_init__(self) -> None:
        if self.client_secret:
            self._secret_hash = hashlib.sha256(self.client_secret.encode()).hexdigest()

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return config without raw secrets."""
        return {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "secret_hash": self._secret_hash,
            "dcr_endpoint": self.dcr_endpoint,
            "dcr_rule_id": self.dcr_rule_id,
            "stream_name": self.stream_name,
            "workspace_id": self.workspace_id,
            "log_type": self.log_type,
            "max_retries": self.max_retries,
            "batch_size": self.batch_size,
            "timeout_s": self.timeout_s,
        }


@dataclass
class SentinelDeliveryResult:
    """Result of a delivery attempt to Sentinel."""

    batch_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    events_sent: int = 0
    events_failed: int = 0
    success: bool = False
    status_code: int = 0
    error: str = ""
    duration_ms: float = 0.0
    retries_used: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "events_sent": self.events_sent,
            "events_failed": self.events_failed,
            "success": self.success,
            "status_code": self.status_code,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
            "retries_used": self.retries_used,
        }


class SentinelConnector:
    """Sends ALDECI events to Microsoft Sentinel via Data Collection API.

    Features:
    - Azure AD client-credentials auth (OAuth2 token auto-refresh)
    - Maps ALDECI severity to Sentinel severity
    - Batched delivery with exponential backoff retry
    - DCR-based ingestion (preferred) with Log Analytics fallback
    """

    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        self.config = config or SentinelConfig()
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._stats = {
            "total_sent": 0,
            "total_failed": 0,
            "total_batches": 0,
            "total_retries": 0,
            "last_send_at": "",
            "last_error": "",
        }

    # ------------------------------------------------------------------
    # Azure AD token
    # ------------------------------------------------------------------

    def _acquire_token(self) -> str:
        """Acquire Azure AD access token via client credentials grant."""
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token

        if not _HTTPX_AVAILABLE:
            raise RuntimeError("httpx not installed — cannot authenticate with Azure AD")

        token_url = (
            f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
        )
        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "scope": "https://monitor.azure.com/.default",
        }

        try:
            with httpx.Client(timeout=self.config.timeout_s) as client:
                resp = client.post(token_url, data=data)
                resp.raise_for_status()
                body = resp.json()
        except httpx.HTTPStatusError as exc:
            # Re-raise without the request object to avoid leaking client_secret
            # that may appear in the httpx exception repr/request body.
            raise RuntimeError(
                f"Azure AD token request failed: HTTP {exc.response.status_code}"
            ) from None
        except httpx.RequestError as exc:
            raise RuntimeError(
                f"Azure AD token request network error: {type(exc).__name__}"
            ) from None

        self._access_token = body["access_token"]
        self._token_expires_at = time.time() + body.get("expires_in", 3600)
        return self._access_token

    # ------------------------------------------------------------------
    # Event mapping
    # ------------------------------------------------------------------

    def map_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Map an ALDECI event to Sentinel custom log schema.

        Fields are prefixed with ALDECI_ for clarity in Sentinel KQL queries.
        """
        severity_str = event.get("severity", "info").lower()
        ts = event.get("timestamp", datetime.now(timezone.utc).isoformat())
        status = event.get("status", "open").lower()

        return {
            "TimeGenerated": ts,
            "ALDECI_EventId": event.get("event_id", uuid.uuid4().hex),
            "ALDECI_EventType": event.get("event_type", ""),
            "ALDECI_Severity": _SEVERITY_MAP.get(severity_str, "Informational"),
            "ALDECI_SeverityRaw": severity_str,
            "ALDECI_Status": _ALDECI_TO_SENTINEL_STATUS.get(status, "New"),
            "ALDECI_Source": event.get("source", "aldeci"),
            "ALDECI_Message": event.get("message", ""),
            "ALDECI_SrcIP": event.get("src_ip", ""),
            "ALDECI_DstIP": event.get("dst_ip", ""),
            "ALDECI_UserId": event.get("user_id", ""),
            "ALDECI_FindingId": event.get("finding_id", ""),
            "ALDECI_CVE": event.get("cve_id", ""),
            "ALDECI_Action": event.get("action", ""),
            "ALDECI_Outcome": event.get("outcome", ""),
            "ALDECI_OrgId": event.get("org_id", "default"),
            "ALDECI_Metadata": json.dumps(event.get("metadata", {}), default=str),
        }

    # ------------------------------------------------------------------
    # Delivery — DCR-based ingestion (preferred)
    # ------------------------------------------------------------------

    def send_events(self, events: List[Dict[str, Any]]) -> List[SentinelDeliveryResult]:
        """Send events to Sentinel, batched with retry."""
        if not events:
            return []

        if not _HTTPX_AVAILABLE:
            _logger.error("httpx not installed — cannot send to Sentinel")
            return [
                SentinelDeliveryResult(
                    events_failed=len(events),
                    error="httpx library not installed",
                )
            ]

        results: List[SentinelDeliveryResult] = []
        bs = max(1, self.config.batch_size)

        for i in range(0, len(events), bs):
            batch = events[i : i + bs]
            result = self._send_batch(batch)
            results.append(result)
            self._stats["total_batches"] += 1
            if result.success:
                self._stats["total_sent"] += result.events_sent
            else:
                self._stats["total_failed"] += result.events_failed
                self._stats["last_error"] = result.error
            self._stats["total_retries"] += result.retries_used

        self._stats["last_send_at"] = datetime.now(timezone.utc).isoformat()
        return results

    def _send_batch(self, events: List[Dict[str, Any]]) -> SentinelDeliveryResult:
        """Send a single batch via DCR ingestion endpoint with retry."""
        mapped = [self.map_event(e) for e in events]
        payload = json.dumps(mapped, default=str)

        url = (
            f"{self.config.dcr_endpoint.rstrip('/')}"
            f"/dataCollectionRules/{self.config.dcr_rule_id}"
            f"/streams/{self.config.stream_name}?api-version=2023-01-01"
        )

        result = SentinelDeliveryResult(events_sent=0, events_failed=len(events))
        start = time.monotonic()

        for attempt in range(self.config.max_retries + 1):
            try:
                token = self._acquire_token()
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }

                with httpx.Client(timeout=self.config.timeout_s) as client:
                    resp = client.post(url, content=payload, headers=headers)

                result.status_code = resp.status_code

                # 204 No Content = success for DCR ingestion
                if resp.status_code in (200, 204):
                    result.success = True
                    result.events_sent = len(events)
                    result.events_failed = 0
                    result.retries_used = attempt
                    break

                # Token expired — force refresh and retry
                if resp.status_code == 401:
                    self._access_token = None
                    self._token_expires_at = 0.0
                    result.retries_used = attempt + 1
                    continue

                # Retriable
                if resp.status_code in (429, 500, 502, 503, 504):
                    delay = self.config.base_delay_s * (2**attempt)
                    _logger.warning(
                        "Sentinel %s (attempt %d/%d) — retrying in %.1fs",
                        resp.status_code,
                        attempt + 1,
                        self.config.max_retries + 1,
                        delay,
                    )
                    time.sleep(delay)
                    result.retries_used = attempt + 1
                    continue

                # Non-retriable
                result.error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                break

            except Exception as exc:  # noqa: BLE001
                delay = self.config.base_delay_s * (2**attempt)
                result.error = f"{type(exc).__name__}: {exc}"
                if attempt < self.config.max_retries:
                    _logger.warning(
                        "Sentinel connection error (attempt %d/%d): %s — retrying in %.1fs",
                        attempt + 1,
                        self.config.max_retries + 1,
                        exc,
                        delay,
                    )
                    time.sleep(delay)
                    result.retries_used = attempt + 1
                else:
                    _logger.error("Sentinel failed after %d retries: %s", self.config.max_retries, exc)
                    break

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def check_health(self) -> Dict[str, Any]:
        """Check connectivity by attempting to acquire a token."""
        if not _HTTPX_AVAILABLE:
            return {"healthy": False, "error": "httpx not installed"}

        try:
            self._acquire_token()
            return {
                "healthy": True,
                "token_valid": True,
                "dcr_endpoint": self.config.dcr_endpoint,
                "stream": self.config.stream_name,
            }
        except Exception as exc:  # noqa: BLE001
            return {"healthy": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Test event
    # ------------------------------------------------------------------

    def send_test_event(self) -> SentinelDeliveryResult:
        """Send a single test event to verify connectivity."""
        test_event = {
            "event_type": "test",
            "severity": "info",
            "message": "ALDECI connectivity test event",
            "source": "aldeci-test",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test": True,
        }
        results = self.send_events([test_event])
        return results[0] if results else SentinelDeliveryResult(error="No result")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return delivery statistics."""
        return {**self._stats, "config": self.config.to_safe_dict()}
