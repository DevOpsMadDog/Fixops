"""Splunk HTTP Event Collector (HEC) Connector — ALDECI.

Sends security findings, alerts, and events to Splunk via HEC.
Supports batched delivery, retry with exponential backoff, and
TLS verification.

Reference: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
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
# Severity mapping: ALDECI → Splunk severity field
# ---------------------------------------------------------------------------
_SEVERITY_MAP: Dict[str, int] = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}


@dataclass
class SplunkHECConfig:
    """Configuration for a Splunk HEC target."""

    url: str = ""  # e.g. https://splunk.example.com:8088
    token: str = ""  # HEC token (will be SHA-256 hashed at rest)
    index: str = "aldeci"
    source: str = "aldeci-ctem"
    sourcetype: str = "aldeci:security"
    host: str = ""  # optional override; defaults to ALDECI hostname
    verify_ssl: bool = True
    batch_size: int = 50
    max_retries: int = 3
    base_delay_s: float = 1.0  # exponential backoff base
    timeout_s: float = 30.0

    # Computed at runtime — not serialised
    _token_hash: str = field(default="", repr=False, init=False)

    def __post_init__(self) -> None:
        if self.token:
            self._token_hash = hashlib.sha256(self.token.encode()).hexdigest()

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return config without the raw token (hash only)."""
        return {
            "url": self.url,
            "token_hash": self._token_hash,
            "index": self.index,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "host": self.host,
            "verify_ssl": self.verify_ssl,
            "batch_size": self.batch_size,
            "max_retries": self.max_retries,
            "timeout_s": self.timeout_s,
        }


@dataclass
class SplunkDeliveryResult:
    """Result of a batch delivery attempt."""

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


class SplunkHECConnector:
    """Sends ALDECI events to Splunk via HTTP Event Collector.

    Features:
    - Formats events in Splunk-compatible JSON
    - Batches events for efficiency (configurable batch_size)
    - Retry logic with exponential backoff (2^attempt * base_delay)
    - TLS verification (configurable)
    - Connection health check via HEC /services/collector/health
    """

    def __init__(self, config: Optional[SplunkHECConfig] = None) -> None:
        self.config = config or SplunkHECConfig()
        self._stats = {
            "total_sent": 0,
            "total_failed": 0,
            "total_batches": 0,
            "total_retries": 0,
            "last_send_at": "",
            "last_error": "",
        }

    # ------------------------------------------------------------------
    # Event formatting
    # ------------------------------------------------------------------

    def format_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format a single ALDECI event into Splunk HEC JSON envelope.

        Splunk HEC expects:
        {
            "time": <epoch>,
            "host": "...",
            "source": "...",
            "sourcetype": "...",
            "index": "...",
            "event": { ... }
        }
        """
        ts = event.get("timestamp", datetime.now(timezone.utc).isoformat())
        try:
            epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except (ValueError, AttributeError):
            epoch = time.time()

        severity_str = event.get("severity", "info").lower()
        enriched = {
            **event,
            "severity_num": _SEVERITY_MAP.get(severity_str, 5),
            "aldeci_source": "aldeci-ctem",
        }

        return {
            "time": epoch,
            "host": self.config.host or "aldeci",
            "source": self.config.source,
            "sourcetype": self.config.sourcetype,
            "index": self.config.index,
            "event": enriched,
        }

    def format_batch(self, events: List[Dict[str, Any]]) -> str:
        """Format multiple events for Splunk HEC batch endpoint.

        HEC batch = newline-delimited JSON (NDJSON).
        """
        lines: List[str] = []
        for evt in events:
            formatted = self.format_event(evt)
            lines.append(json.dumps(formatted, default=str))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Delivery
    # ------------------------------------------------------------------

    def send_events(self, events: List[Dict[str, Any]]) -> List[SplunkDeliveryResult]:
        """Send events to Splunk HEC, batched and with retry.

        Returns a list of SplunkDeliveryResult (one per batch).
        """
        if not events:
            return []

        if not _HTTPX_AVAILABLE:
            _logger.error("httpx not installed — cannot send to Splunk HEC")
            return [
                SplunkDeliveryResult(
                    events_failed=len(events),
                    error="httpx library not installed",
                )
            ]

        results: List[SplunkDeliveryResult] = []
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

    def _send_batch(self, events: List[Dict[str, Any]]) -> SplunkDeliveryResult:
        """Send a single batch with exponential backoff retry."""
        payload = self.format_batch(events)
        url = f"{self.config.url.rstrip('/')}/services/collector/event"
        headers = {
            "Authorization": f"Splunk {self.config.token}",
            "Content-Type": "application/json",
        }

        result = SplunkDeliveryResult(events_sent=0, events_failed=len(events))
        start = time.monotonic()

        for attempt in range(self.config.max_retries + 1):
            try:
                with httpx.Client(
                    verify=self.config.verify_ssl,
                    timeout=self.config.timeout_s,
                ) as client:
                    resp = client.post(url, content=payload, headers=headers)

                result.status_code = resp.status_code
                if resp.status_code == 200:
                    result.success = True
                    result.events_sent = len(events)
                    result.events_failed = 0
                    result.retries_used = attempt
                    break

                # Retriable status codes
                if resp.status_code in (429, 500, 502, 503, 504):
                    delay = self.config.base_delay_s * (2**attempt)
                    _logger.warning(
                        "Splunk HEC %s (attempt %d/%d) — retrying in %.1fs",
                        resp.status_code,
                        attempt + 1,
                        self.config.max_retries + 1,
                        delay,
                    )
                    time.sleep(delay)
                    result.retries_used = attempt + 1
                    continue

                # Non-retriable error
                result.error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                break

            except Exception as exc:  # noqa: BLE001
                delay = self.config.base_delay_s * (2**attempt)
                result.error = f"{type(exc).__name__}: {exc}"
                if attempt < self.config.max_retries:
                    _logger.warning(
                        "Splunk HEC connection error (attempt %d/%d): %s — retrying in %.1fs",
                        attempt + 1,
                        self.config.max_retries + 1,
                        exc,
                        delay,
                    )
                    time.sleep(delay)
                    result.retries_used = attempt + 1
                else:
                    _logger.error("Splunk HEC failed after %d retries: %s", self.config.max_retries, exc)
                    break

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def check_health(self) -> Dict[str, Any]:
        """Check Splunk HEC health endpoint."""
        if not _HTTPX_AVAILABLE:
            return {"healthy": False, "error": "httpx not installed"}

        url = f"{self.config.url.rstrip('/')}/services/collector/health"
        try:
            with httpx.Client(
                verify=self.config.verify_ssl,
                timeout=10.0,
            ) as client:
                resp = client.get(url)
                return {
                    "healthy": resp.status_code == 200,
                    "status_code": resp.status_code,
                    "response": resp.text[:500],
                }
        except Exception as exc:  # noqa: BLE001
            return {"healthy": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Test event
    # ------------------------------------------------------------------

    def send_test_event(self) -> SplunkDeliveryResult:
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
        return results[0] if results else SplunkDeliveryResult(error="No result")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return delivery statistics."""
        return {**self._stats, "config": self.config.to_safe_dict()}
