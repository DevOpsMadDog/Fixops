"""ALdeci SIEM Integration Engine.

Provides unified SIEM forwarding for security events:
- Syslog (TCP/UDP, RFC 5424)
- Splunk HEC (HTTP Event Collector)
- CEF (Common Event Format - ArcSight)
- LEEF (Log Event Extended Format - QRadar)
- JSON (generic structured logging)

Events are collected from the EventBus and forwarded to configured SIEM targets.
"""

from __future__ import annotations

import json
import logging
import socket
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ── Enums ────────────────────────────────────────────────────────────


class SIEMOutputFormat(str, Enum):
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"


class SIEMTransport(str, Enum):
    SYSLOG_TCP = "syslog_tcp"
    SYSLOG_UDP = "syslog_udp"
    SPLUNK_HEC = "splunk_hec"
    WEBHOOK = "webhook"


class SIEMSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def to_cef_severity(self) -> int:
        return {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}.get(self.value, 1)

    def to_syslog_severity(self) -> int:
        return {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}.get(self.value, 6)


# ── Data Classes ─────────────────────────────────────────────────────


@dataclass
class SIEMTarget:
    """A configured SIEM forwarding target."""
    target_id: str = field(default_factory=lambda: f"siem-{uuid.uuid4().hex[:8]}")
    name: str = ""
    transport: SIEMTransport = SIEMTransport.SYSLOG_TCP
    output_format: SIEMOutputFormat = SIEMOutputFormat.CEF
    host: str = "localhost"
    port: int = 514
    token: str = ""  # For Splunk HEC / webhook auth
    url: str = ""    # For Splunk HEC / webhook
    index: str = "fixops"  # Splunk index
    source: str = "aldeci-ctem"
    sourcetype: str = "aldeci:security"
    enabled: bool = True
    event_filters: List[str] = field(default_factory=list)  # Empty = all events
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "name": self.name,
            "transport": self.transport.value,
            "output_format": self.output_format.value,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "index": self.index,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "enabled": self.enabled,
            "event_filters": self.event_filters,
            "created_at": self.created_at,
        }


@dataclass
class SIEMEvent:
    """A security event to forward to SIEM targets."""
    event_id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    event_type: str = ""
    severity: SIEMSeverity = SIEMSeverity.INFO
    source: str = "aldeci"
    action: str = ""
    outcome: str = ""
    message: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    user_id: str = ""
    app_id: str = ""
    finding_id: str = ""
    cve_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "source": self.source,
            "action": self.action,
            "outcome": self.outcome,
            "message": self.message,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "user_id": self.user_id,
            "app_id": self.app_id,
            "finding_id": self.finding_id,
            "cve_id": self.cve_id,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class ForwardResult:
    """Result of forwarding an event to a SIEM target."""
    target_id: str = ""
    success: bool = False
    error: str = ""
    bytes_sent: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "success": self.success,
            "error": self.error,
            "bytes_sent": self.bytes_sent,
            "duration_ms": round(self.duration_ms, 2),
        }


# ── Format Encoders ──────────────────────────────────────────────────


def _sanitize_cef(val: str) -> str:
    """Escape CEF special characters."""
    return val.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")


def format_cef(event: SIEMEvent) -> str:
    """Format event as CEF (Common Event Format) for ArcSight/generic SIEM.

    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    ext_parts = []
    if event.src_ip:
        ext_parts.append(f"src={_sanitize_cef(event.src_ip)}")
    if event.dst_ip:
        ext_parts.append(f"dst={_sanitize_cef(event.dst_ip)}")
    if event.user_id:
        ext_parts.append(f"duser={_sanitize_cef(event.user_id)}")
    if event.app_id:
        ext_parts.append(f"cs1={_sanitize_cef(event.app_id)} cs1Label=ApplicationID")
    if event.finding_id:
        ext_parts.append(f"cs2={_sanitize_cef(event.finding_id)} cs2Label=FindingID")
    if event.cve_id:
        ext_parts.append(f"cs3={_sanitize_cef(event.cve_id)} cs3Label=CVE")
    if event.outcome:
        ext_parts.append(f"outcome={_sanitize_cef(event.outcome)}")
    ext_parts.append(f"msg={_sanitize_cef(event.message)}")
    ext_parts.append(f"rt={event.timestamp}")

    extension = " ".join(ext_parts)
    sev = event.severity.to_cef_severity()

    return (
        f"CEF:0|ALdeci|CTEM+|1.0"
        f"|{_sanitize_cef(event.event_type)}"
        f"|{_sanitize_cef(event.action or event.event_type)}"
        f"|{sev}|{extension}"
    )


def format_leef(event: SIEMEvent) -> str:
    """Format event as LEEF (Log Event Extended Format) for IBM QRadar.

    LEEF:Version|Vendor|Product|Version|EventID|Key=Value pairs
    """
    kv_parts = [
        f"cat={event.event_type}",
        f"sev={event.severity.to_cef_severity()}",
    ]
    if event.src_ip:
        kv_parts.append(f"src={event.src_ip}")
    if event.dst_ip:
        kv_parts.append(f"dst={event.dst_ip}")
    if event.user_id:
        kv_parts.append(f"usrName={event.user_id}")
    if event.app_id:
        kv_parts.append(f"appId={event.app_id}")
    if event.finding_id:
        kv_parts.append(f"findingId={event.finding_id}")
    if event.cve_id:
        kv_parts.append(f"cveId={event.cve_id}")
    kv_parts.append(f"msg={event.message}")
    kv_parts.append(f"devTime={event.timestamp}")

    kv_str = "\t".join(kv_parts)
    return f"LEEF:2.0|ALdeci|CTEM+|1.0|{event.event_type}|{kv_str}"


def format_json(event: SIEMEvent) -> str:
    """Format event as structured JSON."""
    return json.dumps(event.to_dict(), default=str)


_FORMAT_FUNCS = {
    SIEMOutputFormat.CEF: format_cef,
    SIEMOutputFormat.LEEF: format_leef,
    SIEMOutputFormat.JSON: format_json,
}


# ── SIEM Engine ──────────────────────────────────────────────────────


class SIEMEngine:
    """Manages SIEM targets and forwards security events.

    Supports:
    - Syslog TCP/UDP (RFC 5424 framing)
    - Splunk HEC (HTTP Event Collector)
    - Webhook (generic HTTP POST)
    - CEF, LEEF, JSON output formats
    """

    def __init__(self):
        self._targets: Dict[str, SIEMTarget] = {}
        self._event_log: List[Dict[str, Any]] = []  # Recent forwarded events ring buffer
        self._max_log_size = 1000
        self._stats = {
            "events_forwarded": 0,
            "events_failed": 0,
            "bytes_sent": 0,
        }

    def add_target(self, target: SIEMTarget) -> SIEMTarget:
        """Add or update a SIEM forwarding target."""
        self._targets[target.target_id] = target
        logger.info("SIEM target added: %s (%s/%s)", target.name, target.transport.value, target.output_format.value)
        return target

    def remove_target(self, target_id: str) -> bool:
        """Remove a SIEM target by ID."""
        if target_id in self._targets:
            del self._targets[target_id]
            return True
        return False

    def get_target(self, target_id: str) -> Optional[SIEMTarget]:
        return self._targets.get(target_id)

    def list_targets(self) -> List[SIEMTarget]:
        return list(self._targets.values())

    def forward_event(self, event: SIEMEvent) -> List[ForwardResult]:
        """Forward an event to all enabled SIEM targets."""
        results: List[ForwardResult] = []

        for target in self._targets.values():
            if not target.enabled:
                continue

            # Apply event filter
            if target.event_filters and event.event_type not in target.event_filters:
                continue

            result = self._send_to_target(target, event)
            results.append(result)

            if result.success:
                self._stats["events_forwarded"] += 1
                self._stats["bytes_sent"] += result.bytes_sent
            else:
                self._stats["events_failed"] += 1

        # Log to ring buffer
        self._event_log.append({
            "event_id": event.event_id,
            "event_type": event.event_type,
            "targets": len(results),
            "success": sum(1 for r in results if r.success),
            "timestamp": event.timestamp,
        })
        if len(self._event_log) > self._max_log_size:
            self._event_log = self._event_log[-self._max_log_size:]

        return results

    def _send_to_target(self, target: SIEMTarget, event: SIEMEvent) -> ForwardResult:
        """Send a formatted event to a specific target."""
        t0 = time.time()
        result = ForwardResult(target_id=target.target_id)

        try:
            # Format the event
            formatter = _FORMAT_FUNCS.get(target.output_format, format_json)
            formatted = formatter(event)
            payload = formatted.encode("utf-8")

            if target.transport == SIEMTransport.SYSLOG_TCP:
                result = self._send_syslog_tcp(target, payload)
            elif target.transport == SIEMTransport.SYSLOG_UDP:
                result = self._send_syslog_udp(target, payload)
            elif target.transport == SIEMTransport.SPLUNK_HEC:
                result = self._send_splunk_hec(target, event)
            elif target.transport == SIEMTransport.WEBHOOK:
                result = self._send_webhook(target, event)
            else:
                result.error = f"Unknown transport: {target.transport}"

            result.target_id = target.target_id
        except Exception as e:
            result.error = str(e)
            logger.warning("SIEM forward failed for %s: %s", target.name, e)

        result.duration_ms = (time.time() - t0) * 1000
        return result

    def _send_syslog_tcp(self, target: SIEMTarget, payload: bytes) -> ForwardResult:
        """Send via syslog TCP (RFC 5424 octet-counting framing)."""
        result = ForwardResult(target_id=target.target_id)
        try:
            framed = f"{len(payload)} ".encode("utf-8") + payload
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target.host, target.port))
            sock.sendall(framed)
            sock.close()
            result.success = True
            result.bytes_sent = len(framed)
        except (OSError, socket.error) as e:
            result.error = f"Syslog TCP error: {e}"
        return result

    def _send_syslog_udp(self, target: SIEMTarget, payload: bytes) -> ForwardResult:
        """Send via syslog UDP."""
        result = ForwardResult(target_id=target.target_id)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.sendto(payload, (target.host, target.port))
            sock.close()
            result.success = True
            result.bytes_sent = len(payload)
        except (OSError, socket.error) as e:
            result.error = f"Syslog UDP error: {e}"
        return result

    def _send_splunk_hec(self, target: SIEMTarget, event: SIEMEvent) -> ForwardResult:
        """Send via Splunk HEC (HTTP Event Collector)."""
        result = ForwardResult(target_id=target.target_id)
        try:
            import urllib.request
            import urllib.error

            hec_payload = json.dumps({
                "time": time.time(),
                "host": "aldeci",
                "source": target.source,
                "sourcetype": target.sourcetype,
                "index": target.index,
                "event": event.to_dict(),
            }).encode("utf-8")

            url = f"{target.url.rstrip('/')}/services/collector/event"
            req = urllib.request.Request(
                url,
                data=hec_payload,
                headers={
                    "Authorization": f"Splunk {target.token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result.success = resp.status == 200
                result.bytes_sent = len(hec_payload)
        except (OSError, urllib.error.URLError, ValueError) as e:
            result.error = f"Splunk HEC error: {e}"
        return result

    def _send_webhook(self, target: SIEMTarget, event: SIEMEvent) -> ForwardResult:
        """Send via generic webhook (HTTP POST)."""
        result = ForwardResult(target_id=target.target_id)
        try:
            import urllib.request
            import urllib.error

            payload = json.dumps(event.to_dict()).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if target.token:
                headers["Authorization"] = f"Bearer {target.token}"

            req = urllib.request.Request(
                target.url,
                data=payload,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result.success = resp.status in (200, 201, 202, 204)
                result.bytes_sent = len(payload)
        except (OSError, urllib.error.URLError, ValueError) as e:
            result.error = f"Webhook error: {e}"
        return result

    def get_stats(self) -> Dict[str, Any]:
        """Return forwarding statistics."""
        return {
            **self._stats,
            "active_targets": sum(1 for t in self._targets.values() if t.enabled),
            "total_targets": len(self._targets),
        }

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recently forwarded events."""
        return self._event_log[-limit:]

    def test_target(self, target_id: str) -> ForwardResult:
        """Send a test event to verify SIEM target connectivity."""
        target = self._targets.get(target_id)
        if not target:
            return ForwardResult(target_id=target_id, error="Target not found")

        test_event = SIEMEvent(
            event_type="siem.test",
            severity=SIEMSeverity.INFO,
            action="connectivity_test",
            outcome="success",
            message="ALdeci SIEM integration test event",
        )
        return self._send_to_target(target, test_event)


# ── Module-level singleton ────────────────────────────────────────────

_engine: Optional[SIEMEngine] = None


def get_siem_engine() -> SIEMEngine:
    """Get or create the singleton SIEMEngine."""
    global _engine
    if _engine is None:
        _engine = SIEMEngine()
    return _engine

