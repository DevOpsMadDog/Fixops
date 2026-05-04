"""
Webhook Notifier — Real HTTP webhook delivery and SOAR integration for ALDECI.

Provides:
- WebhookNotifier: configurable webhook delivery with HMAC-SHA256 signing
- NtfyNotifier: push notifications via ntfy.sh (free, no account required)
- DeliveryLog: SQLite-backed delivery tracking with circuit breaker
- Exponential backoff retry (1s, 2s, 4s, max 3 retries)
- Circuit breaker: disable after 5 consecutive failures

All HTTP calls use urllib.request (stdlib only, zero external deps).

Compliance: SOC2 CC7.2, NIST CSF RS.AN-1
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "webhook_notifier.db")

NTFY_BASE_URL = "https://ntfy.sh"

# Retry schedule (seconds between attempts)
RETRY_DELAYS: Tuple[float, ...] = (1.0, 2.0, 4.0)
MAX_RETRIES = 3

# Circuit breaker threshold
CIRCUIT_BREAKER_THRESHOLD = 5

# Request timeout (seconds)
REQUEST_TIMEOUT = 10

# Max payload size (bytes)
MAX_PAYLOAD_BYTES = 512 * 1024  # 512 KB

# Schema
_SCHEMA = """
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id          TEXT PRIMARY KEY,
    webhook_id  TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    payload_sha TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    attempts    INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER,
    response_ms REAL,
    last_error  TEXT,
    created_at  TEXT NOT NULL,
    completed_at TEXT,
    org_id      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wn_status    ON webhook_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_wn_org       ON webhook_deliveries(org_id);
CREATE INDEX IF NOT EXISTS idx_wn_webhook   ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_wn_created   ON webhook_deliveries(created_at);

CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id              TEXT PRIMARY KEY,
    url             TEXT NOT NULL,
    secret          TEXT,
    org_id          TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    circuit_open    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_we_org ON webhook_endpoints(org_id);
"""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DeliveryStatus(str, Enum):
    """Lifecycle states for a webhook delivery attempt."""

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    CIRCUIT_OPEN = "circuit_open"
    SKIPPED = "skipped"


class FindingSeverity(str, Enum):
    """Finding severity levels — maps to ntfy priority."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def ntfy_priority(self) -> int:
        """Map ALDECI severity to ntfy.sh priority (1-5)."""
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }[self.value]

    @property
    def ntfy_tags(self) -> List[str]:
        """Emoji tags for ntfy.sh notification."""
        return {
            "critical": ["rotating_light", "skull"],
            "high": ["warning", "fire"],
            "medium": ["large_orange_circle"],
            "low": ["large_blue_circle"],
            "info": ["information_source"],
        }[self.value]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class FindingPayload:
    """
    Normalized finding payload sent via webhooks and notifications.

    Attributes:
        finding_id: Unique finding identifier
        title: Human-readable finding title
        severity: FindingSeverity string
        affected_asset: Asset or file affected
        source: Scanner/connector that produced the finding
        cve_id: Optional CVE identifier
        cvss_score: Optional CVSS numeric score
        description: Optional detailed description
        org_id: Organization identifier
        detected_at: ISO-8601 timestamp when finding was detected
        event_type: Event that triggered delivery (e.g., "finding.created")
    """

    finding_id: str
    title: str
    severity: str
    affected_asset: str
    source: str
    org_id: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str = "finding.created"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to webhook JSON payload dict."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class DeliveryRecord:
    """Result of a single webhook delivery attempt."""

    delivery_id: str
    webhook_id: str
    endpoint: str
    event_type: str
    status: DeliveryStatus
    attempts: int
    status_code: Optional[int]
    response_ms: Optional[float]
    last_error: Optional[str]
    created_at: str
    completed_at: Optional[str]
    org_id: str


@dataclass
class WebhookEndpoint:
    """Registered webhook endpoint configuration."""

    id: str
    url: str
    org_id: str
    secret: Optional[str] = None
    enabled: bool = True
    consecutive_failures: int = 0
    circuit_open: bool = False
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------


def _build_signature(payload_bytes: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for a payload."""
    return hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


def _post_json(
    url: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: float = REQUEST_TIMEOUT,
) -> Tuple[int, float, Optional[str]]:
    """
    POST JSON payload to url using stdlib urllib.

    Returns:
        (status_code, elapsed_ms, error_message_or_None)
    """
    body = json.dumps(payload, default=str).encode("utf-8")
    return _post_json_bytes(url, body, headers=headers, timeout=timeout)


def _post_json_bytes(
    url: str,
    body: bytes,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = REQUEST_TIMEOUT,
) -> Tuple[int, float, Optional[str]]:
    """
    POST pre-encoded JSON bytes to url using stdlib urllib.

    Avoids redundant json.dumps/encode when the caller already has the
    serialized bytes (e.g. for HMAC signing).  Called by _post_json and
    directly by _deliver_with_retry.

    Returns:
        (status_code, elapsed_ms, error_message_or_None)
    """
    if len(body) > MAX_PAYLOAD_BYTES:
        return 0, 0.0, f"Payload too large: {len(body)} bytes"

    req_headers = {
        "Content-Type": "application/json",
        "User-Agent": "ALDECI-WebhookNotifier/1.0",
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")  # nosemgrep: dynamic-urllib-use-detected
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
            elapsed = (time.monotonic() - t0) * 1000
            return resp.status, elapsed, None
    except urllib.error.HTTPError as exc:
        elapsed = (time.monotonic() - t0) * 1000
        return exc.code, elapsed, f"HTTP {exc.code}: {exc.reason}"
    except urllib.error.URLError as exc:
        elapsed = (time.monotonic() - t0) * 1000
        return 0, elapsed, f"URLError: {exc.reason}"
    except Exception as exc:  # noqa: BLE001
        elapsed = (time.monotonic() - t0) * 1000
        return 0, elapsed, str(exc)


def _post_ntfy(
    url: str,
    title: str,
    body: str,
    priority: int,
    tags: List[str],
    actions: Optional[List[Dict[str, str]]] = None,
    timeout: float = REQUEST_TIMEOUT,
) -> Tuple[int, float, Optional[str]]:
    """
    POST a notification to ntfy.sh using their plain-text API with headers.

    ntfy.sh accepts body as raw text + metadata in headers.
    Ref: https://docs.ntfy.sh/publish/

    Returns:
        (status_code, elapsed_ms, error_message_or_None)
    """
    body_bytes = body.encode("utf-8")
    headers: Dict[str, str] = {
        "Title": title,
        "Priority": str(priority),
        "Tags": ",".join(tags),
        "Content-Type": "text/plain",
        "User-Agent": "ALDECI-WebhookNotifier/1.0",
    }
    # Action buttons (view/dismiss)
    if actions:
        # ntfy action format: "view, Label, URL; view, Label2, URL2"
        action_parts = []
        for act in actions:
            act_type = act.get("action", "view")
            label = act.get("label", "View")
            act_url = act.get("url", "")
            if act_url:
                action_parts.append(f"{act_type}, {label}, {act_url}")
        if action_parts:
            headers["Actions"] = "; ".join(action_parts)

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")  # nosemgrep: dynamic-urllib-use-detected
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
            elapsed = (time.monotonic() - t0) * 1000
            return resp.status, elapsed, None
    except urllib.error.HTTPError as exc:
        elapsed = (time.monotonic() - t0) * 1000
        return exc.code, elapsed, f"HTTP {exc.code}: {exc.reason}"
    except urllib.error.URLError as exc:
        elapsed = (time.monotonic() - t0) * 1000
        return 0, elapsed, f"URLError: {exc.reason}"
    except Exception as exc:  # noqa: BLE001
        elapsed = (time.monotonic() - t0) * 1000
        return 0, elapsed, str(exc)


# ---------------------------------------------------------------------------
# DeliveryLog — SQLite-backed delivery tracking
# ---------------------------------------------------------------------------


class DeliveryLog:
    """
    SQLite-backed log of all webhook delivery attempts.

    Thread-safe via threading.Lock. Supports filtering by org_id,
    status, or webhook_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Endpoint management
    # ------------------------------------------------------------------

    def register_endpoint(
        self,
        url: str,
        org_id: str,
        secret: Optional[str] = None,
        endpoint_id: Optional[str] = None,
    ) -> WebhookEndpoint:
        """Register a webhook endpoint and return its config."""
        ep = WebhookEndpoint(
            id=endpoint_id or f"wh-{uuid.uuid4().hex[:12]}",
            url=url,
            org_id=org_id,
            secret=secret,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO webhook_endpoints
                   (id, url, secret, org_id, enabled, consecutive_failures,
                    circuit_open, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ep.id, ep.url, ep.secret, ep.org_id,
                    int(ep.enabled), ep.consecutive_failures,
                    int(ep.circuit_open), ep.created_at,
                ),
            )
        return ep

    def get_endpoint(self, endpoint_id: str) -> Optional[WebhookEndpoint]:
        """Retrieve a registered endpoint by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM webhook_endpoints WHERE id = ?", (endpoint_id,)
            ).fetchone()
        if row is None:
            return None
        return WebhookEndpoint(
            id=row["id"],
            url=row["url"],
            org_id=row["org_id"],
            secret=row["secret"],
            enabled=bool(row["enabled"]),
            consecutive_failures=row["consecutive_failures"],
            circuit_open=bool(row["circuit_open"]),
            created_at=row["created_at"],
        )

    def list_endpoints(self, org_id: str) -> List[WebhookEndpoint]:
        """List all endpoints for an organization."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM webhook_endpoints WHERE org_id = ?", (org_id,)
            ).fetchall()
        return [
            WebhookEndpoint(
                id=r["id"], url=r["url"], org_id=r["org_id"], secret=r["secret"],
                enabled=bool(r["enabled"]),
                consecutive_failures=r["consecutive_failures"],
                circuit_open=bool(r["circuit_open"]),
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def _update_circuit(self, endpoint_id: str, success: bool) -> None:
        """Update consecutive failure count and circuit breaker state."""
        with self._lock, self._connect() as conn:
            if success:
                conn.execute(
                    """UPDATE webhook_endpoints
                       SET consecutive_failures = 0, circuit_open = 0
                       WHERE id = ?""",
                    (endpoint_id,),
                )
            else:
                conn.execute(
                    """UPDATE webhook_endpoints
                       SET consecutive_failures = consecutive_failures + 1,
                           circuit_open = CASE
                               WHEN consecutive_failures + 1 >= ? THEN 1
                               ELSE 0
                           END
                       WHERE id = ?""",
                    (CIRCUIT_BREAKER_THRESHOLD, endpoint_id),
                )

    def reset_circuit(self, endpoint_id: str) -> None:
        """Manually reset circuit breaker for an endpoint."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE webhook_endpoints SET consecutive_failures=0, circuit_open=0 WHERE id=?",
                (endpoint_id,),
            )

    # ------------------------------------------------------------------
    # Delivery records
    # ------------------------------------------------------------------

    def record_delivery(
        self,
        webhook_id: str,
        endpoint: str,
        event_type: str,
        payload: Dict[str, Any],
        status: DeliveryStatus,
        attempts: int,
        org_id: str,
        status_code: Optional[int] = None,
        response_ms: Optional[float] = None,
        last_error: Optional[str] = None,
    ) -> DeliveryRecord:
        """Insert a delivery record and return it."""
        now = datetime.now(timezone.utc).isoformat()
        payload_sha = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
        completed_at = now if status in (DeliveryStatus.DELIVERED, DeliveryStatus.FAILED, DeliveryStatus.CIRCUIT_OPEN) else None
        rec = DeliveryRecord(
            delivery_id=f"dlv-{uuid.uuid4().hex[:12]}",
            webhook_id=webhook_id,
            endpoint=endpoint,
            event_type=event_type,
            status=status,
            attempts=attempts,
            status_code=status_code,
            response_ms=response_ms,
            last_error=last_error,
            created_at=now,
            completed_at=completed_at,
            org_id=org_id,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO webhook_deliveries
                   (id, webhook_id, endpoint, event_type, payload_sha,
                    status, attempts, status_code, response_ms,
                    last_error, created_at, completed_at, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rec.delivery_id, rec.webhook_id, rec.endpoint,
                    rec.event_type, payload_sha, rec.status.value,
                    rec.attempts, rec.status_code, rec.response_ms,
                    rec.last_error, rec.created_at, rec.completed_at,
                    rec.org_id,
                ),
            )
        return rec

    def list_deliveries(
        self,
        org_id: str,
        status: Optional[DeliveryStatus] = None,
        limit: int = 100,
    ) -> List[DeliveryRecord]:
        """List delivery records for an org, optionally filtered by status."""
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    """SELECT * FROM webhook_deliveries
                       WHERE org_id = ? AND status = ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (org_id, status.value, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM webhook_deliveries
                       WHERE org_id = ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (org_id, limit),
                ).fetchall()
        return [
            DeliveryRecord(
                delivery_id=r["id"], webhook_id=r["webhook_id"],
                endpoint=r["endpoint"], event_type=r["event_type"],
                status=DeliveryStatus(r["status"]), attempts=r["attempts"],
                status_code=r["status_code"], response_ms=r["response_ms"],
                last_error=r["last_error"], created_at=r["created_at"],
                completed_at=r["completed_at"], org_id=r["org_id"],
            )
            for r in rows
        ]

    def delivery_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate delivery statistics for an org."""
        with self._connect() as conn:
            totals = conn.execute(
                """SELECT status, COUNT(*) as cnt
                   FROM webhook_deliveries WHERE org_id = ?
                   GROUP BY status""",
                (org_id,),
            ).fetchall()
            avg_ms = conn.execute(
                """SELECT AVG(response_ms) as avg_ms
                   FROM webhook_deliveries
                   WHERE org_id = ? AND status = 'delivered'""",
                (org_id,),
            ).fetchone()
        stats: Dict[str, Any] = {s.value: 0 for s in DeliveryStatus}
        for row in totals:
            stats[row["status"]] = row["cnt"]
        stats["avg_response_ms"] = round(avg_ms["avg_ms"] or 0.0, 2)
        return stats


# ---------------------------------------------------------------------------
# WebhookNotifier — core delivery engine
# ---------------------------------------------------------------------------


class WebhookNotifier:
    """
    Delivers finding notifications via real HTTP POST to registered endpoints.

    Features:
    - HMAC-SHA256 signed payloads (X-ALDECI-Signature header)
    - Exponential backoff retry: 1s → 2s → 4s (max 3 retries)
    - Circuit breaker: disables endpoint after 5 consecutive failures
    - Full delivery tracking via DeliveryLog

    Usage::

        notifier = WebhookNotifier(db_path="/data/webhook_notifier.db")
        ep = notifier.register_endpoint(
            url="https://your-server.example.com/hook",
            org_id="acme",
            secret=os.getenv("ALDECI_WEBHOOK_SECRET", ""),  # set via env, never hardcode
        )
        finding = FindingPayload(
            finding_id="F-001",
            title="SQL Injection in login endpoint",
            severity="critical",
            affected_asset="src/auth/login.py",
            source="semgrep",
            org_id="acme",
        )
        record = notifier.deliver(ep.id, finding)
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._log = DeliveryLog(db_path=db_path)

    # ------------------------------------------------------------------
    # Endpoint management (delegated to DeliveryLog)
    # ------------------------------------------------------------------

    def register_endpoint(
        self,
        url: str,
        org_id: str,
        secret: Optional[str] = None,
        endpoint_id: Optional[str] = None,
    ) -> WebhookEndpoint:
        """Register a webhook endpoint."""
        ep = self._log.register_endpoint(url, org_id, secret, endpoint_id)
        self._emit_event(
            "webhook.endpoint.registered",
            {"endpoint_id": ep.id, "url": ep.url, "org_id": org_id},
        )
        return ep

    def get_endpoint(self, endpoint_id: str) -> Optional[WebhookEndpoint]:
        return self._log.get_endpoint(endpoint_id)

    def list_endpoints(self, org_id: str) -> List[WebhookEndpoint]:
        return self._log.list_endpoints(org_id)

    def reset_circuit(self, endpoint_id: str) -> None:
        """Manually reset a circuit-broken endpoint."""
        self._log.reset_circuit(endpoint_id)

    # ------------------------------------------------------------------
    # Delivery
    # ------------------------------------------------------------------

    def deliver(
        self,
        endpoint_id: str,
        finding: FindingPayload,
        retry_delays: Tuple[float, ...] = RETRY_DELAYS,
    ) -> DeliveryRecord:
        """
        Deliver a finding notification to a registered endpoint.

        Retries with exponential backoff on failure. Respects circuit breaker.
        Returns a DeliveryRecord reflecting the final delivery outcome.
        """
        ep = self._log.get_endpoint(endpoint_id)
        if ep is None:
            raise ValueError(f"Endpoint not found: {endpoint_id}")

        # Circuit breaker check
        if ep.circuit_open:
            _logger.warning(
                "webhook.circuit_open",
                endpoint_id=endpoint_id,
                url=ep.url,
            )
            return self._log.record_delivery(
                webhook_id=endpoint_id,
                endpoint=ep.url,
                event_type=finding.event_type,
                payload=finding.to_dict(),
                status=DeliveryStatus.CIRCUIT_OPEN,
                attempts=0,
                org_id=finding.org_id,
                last_error="Circuit breaker open",
            )

        if not ep.enabled:
            return self._log.record_delivery(
                webhook_id=endpoint_id,
                endpoint=ep.url,
                event_type=finding.event_type,
                payload=finding.to_dict(),
                status=DeliveryStatus.SKIPPED,
                attempts=0,
                org_id=finding.org_id,
                last_error="Endpoint disabled",
            )

        payload = finding.to_dict()
        payload["webhook_id"] = endpoint_id
        payload["delivered_at"] = datetime.now(timezone.utc).isoformat()

        record = self._deliver_with_retry(ep, payload, finding.event_type, finding.org_id, retry_delays)
        self._emit_event(
            "webhook.delivered",
            {
                "endpoint_id": endpoint_id,
                "event_type": finding.event_type,
                "org_id": finding.org_id,
                "status": getattr(record, "status", "unknown") if record else "unknown",
                "attempts": getattr(record, "attempts", 0) if record else 0,
            },
        )
        return record

    def _deliver_with_retry(
        self,
        ep: WebhookEndpoint,
        payload: Dict[str, Any],
        event_type: str,
        org_id: str,
        retry_delays: Tuple[float, ...],
    ) -> DeliveryRecord:
        """Internal: attempt delivery with exponential backoff retry."""
        payload_bytes = json.dumps(payload, default=str).encode("utf-8")
        extra_headers: Dict[str, str] = {}
        if ep.secret:
            sig = _build_signature(payload_bytes, ep.secret)
            extra_headers["X-ALDECI-Signature"] = f"sha256={sig}"
            extra_headers["X-ALDECI-Timestamp"] = datetime.now(timezone.utc).isoformat()

        attempts = 0
        last_status_code: Optional[int] = None
        last_response_ms: Optional[float] = None
        last_error: Optional[str] = None

        # payload_bytes already encoded once above — reuse directly to avoid
        # a second json.dumps/encode inside _post_json (hotspot fix #1).
        max_attempts = 1 + len(retry_delays)

        for attempt in range(max_attempts):
            attempts = attempt + 1
            _logger.info(
                "webhook.attempt",
                endpoint_id=ep.id,
                url=ep.url,
                attempt=attempts,
            )
            status_code, response_ms, error = _post_json_bytes(
                ep.url, payload_bytes, headers=extra_headers
            )
            last_status_code = status_code
            last_response_ms = response_ms
            last_error = error

            if error is None and 200 <= status_code < 300:
                _logger.info(
                    "webhook.delivered",
                    endpoint_id=ep.id,
                    status_code=status_code,
                    response_ms=round(response_ms, 1),
                    attempts=attempts,
                )
                self._log._update_circuit(ep.id, success=True)
                return self._log.record_delivery(
                    webhook_id=ep.id,
                    endpoint=ep.url,
                    event_type=event_type,
                    payload=payload,
                    status=DeliveryStatus.DELIVERED,
                    attempts=attempts,
                    org_id=org_id,
                    status_code=status_code,
                    response_ms=response_ms,
                )

            # Failed — log and retry if attempts remain
            _logger.warning(
                "webhook.attempt_failed",
                endpoint_id=ep.id,
                attempt=attempts,
                status_code=status_code,
                error=error,
            )
            if attempt < len(retry_delays):
                time.sleep(retry_delays[attempt])

        # All attempts exhausted
        self._log._update_circuit(ep.id, success=False)
        return self._log.record_delivery(
            webhook_id=ep.id,
            endpoint=ep.url,
            event_type=event_type,
            payload=payload,
            status=DeliveryStatus.FAILED,
            attempts=attempts,
            org_id=org_id,
            status_code=last_status_code,
            response_ms=last_response_ms,
            last_error=last_error,
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def deliver_to_all(
        self,
        finding: FindingPayload,
        max_workers: int = 10,
    ) -> List[DeliveryRecord]:
        """Deliver a finding to all enabled endpoints for the finding's org.

        Fan-out is parallelized via ThreadPoolExecutor (hotspot fix #2).
        Each HTTP POST runs concurrently; results are collected in
        endpoint registration order.  max_workers caps thread count so
        a tenant with hundreds of endpoints cannot exhaust the OS thread
        limit.
        """
        endpoints = [ep for ep in self._log.list_endpoints(finding.org_id) if ep.enabled]
        if not endpoints:
            return []
        if len(endpoints) == 1:
            # Fast path: skip executor overhead for single endpoint
            return [self.deliver(endpoints[0].id, finding)]

        workers = min(max_workers, len(endpoints))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(self.deliver, ep.id, finding) for ep in endpoints]
            results = [f.result() for f in futures]
        return results

    def delivery_stats(self, org_id: str) -> Dict[str, Any]:
        return self._log.delivery_stats(org_id)

    def list_deliveries(
        self,
        org_id: str,
        status: Optional[DeliveryStatus] = None,
        limit: int = 100,
    ) -> List[DeliveryRecord]:
        return self._log.list_deliveries(org_id, status, limit)


# ---------------------------------------------------------------------------
# NtfyNotifier — ntfy.sh push notifications (free, no account needed)
# ---------------------------------------------------------------------------

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: "dict[str, Any]") -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
            if emit is None:
                return
            result = emit(event_type, payload)
            try:
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            pass



class NtfyNotifier:
    """
    Sends real push notifications via ntfy.sh (https://ntfy.sh).

    No account or API key required. Notifications go to:
        https://ntfy.sh/aldeci-{org_id}

    Subscribe on any device via the ntfy app or:
        curl -s https://ntfy.sh/aldeci-{org_id}/json

    Priority mapping:
        critical → 5 (urgent)
        high     → 4 (high)
        medium   → 3 (default)
        low      → 2 (low)
        info     → 1 (min)

    Usage::

        notifier = NtfyNotifier(base_url="https://ntfy.sh")
        result = notifier.notify(finding)
    """

    def __init__(
        self,
        base_url: str = NTFY_BASE_URL,
        topic_prefix: str = "aldeci",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._topic_prefix = topic_prefix

    def _topic_url(self, org_id: str) -> str:
        """Build the full ntfy.sh topic URL for an org."""
        topic = f"{self._topic_prefix}-{org_id}"
        return f"{self._base_url}/{topic}"

    def notify(
        self,
        finding: FindingPayload,
        actions: Optional[List[Dict[str, str]]] = None,
    ) -> Tuple[int, float, Optional[str]]:
        """
        Send a push notification for a finding.

        Args:
            finding: The FindingPayload to notify about
            actions: Optional list of action buttons, e.g.:
                     [{"action": "view", "label": "View Finding", "url": "https://..."}]

        Returns:
            (status_code, elapsed_ms, error_or_None)
        """
        try:
            sev = FindingSeverity(finding.severity.lower())
        except ValueError:
            sev = FindingSeverity.MEDIUM

        url = self._topic_url(finding.org_id)
        title = f"[{sev.value.upper()}] {finding.title}"
        body_parts = [
            f"Asset: {finding.affected_asset}",
            f"Source: {finding.source}",
        ]
        if finding.cve_id:
            body_parts.append(f"CVE: {finding.cve_id}")
        if finding.cvss_score is not None:
            body_parts.append(f"CVSS: {finding.cvss_score}")
        if finding.description:
            body_parts.append(finding.description[:200])

        body = "\n".join(body_parts)

        _logger.info(
            "ntfy.notify",
            url=url,
            severity=sev.value,
            priority=sev.ntfy_priority,
            finding_id=finding.finding_id,
        )

        return _post_ntfy(
            url=url,
            title=title,
            body=body,
            priority=sev.ntfy_priority,
            tags=sev.ntfy_tags,
            actions=actions,
        )

    def notify_bulk(
        self,
        findings: List[FindingPayload],
    ) -> List[Tuple[str, int, float, Optional[str]]]:
        """
        Send notifications for multiple findings.

        Returns list of (finding_id, status_code, elapsed_ms, error) tuples.
        """
        results = []
        for f in findings:
            code, ms, err = self.notify(f)
            results.append((f.finding_id, code, ms, err))
        return results


# ---------------------------------------------------------------------------
# ALDECISelfIntegration — round-trip test against our own FastAPI server
# ---------------------------------------------------------------------------


class ALDECISelfIntegration:
    """
    Posts findings to ALDECI's own /api/v1/findings endpoint.

    Used to verify the round-trip: scanner produces finding →
    webhook fires → ALDECI receives and stores it.

    Can operate against a running server (base_url) or inject a
    custom transport callable for testing (e.g., wrapping TestClient).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_token: str = "",
        transport: Optional[Any] = None,
    ) -> None:
        """
        Args:
            base_url: Base URL of the ALDECI API server
            api_token: Bearer token for authentication
            transport: Optional callable(url, payload, headers) → (status_code, ms, error)
                       Injected for testing; uses real HTTP if None
        """
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._transport = transport

    def post_finding(self, finding: FindingPayload) -> Tuple[int, float, Optional[str]]:
        """
        POST a finding to /api/v1/findings on the ALDECI server.

        Returns:
            (status_code, elapsed_ms, error_or_None)
        """
        url = f"{self._base_url}/api/v1/findings"
        headers: Dict[str, str] = {}
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"

        payload = finding.to_dict()
        payload["source_system"] = "webhook_notifier"

        if self._transport is not None:
            return self._transport(url, payload, headers)

        return _post_json(url, payload, headers=headers)

    def verify_round_trip(self, finding: FindingPayload) -> Dict[str, Any]:
        """
        Full round-trip verification:
        1. POST finding to /api/v1/findings
        2. Return verification result dict

        Returns:
            Dict with keys: success, status_code, elapsed_ms, error, finding_id
        """
        status_code, elapsed_ms, error = self.post_finding(finding)
        success = error is None and 200 <= status_code < 300
        return {
            "success": success,
            "status_code": status_code,
            "elapsed_ms": round(elapsed_ms, 2),
            "error": error,
            "finding_id": finding.finding_id,
        }


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------


def deliver_finding_notification(
    finding: FindingPayload,
    webhook_urls: List[str],
    secret: Optional[str] = None,
    org_id: str = "default",
    db_path: str = _DEFAULT_DB,
    ntfy_base_url: str = NTFY_BASE_URL,
    send_ntfy: bool = True,
) -> Dict[str, Any]:
    """
    One-shot convenience: deliver a finding to webhook URLs + ntfy.sh.

    Args:
        finding: The finding to deliver
        webhook_urls: List of webhook URLs to POST to
        secret: Optional HMAC secret (applied to all URLs)
        org_id: Organization identifier
        db_path: Path to the SQLite delivery log
        ntfy_base_url: ntfy.sh base URL (override for testing)
        send_ntfy: Whether to also send an ntfy.sh notification

    Returns:
        Dict with 'webhook_records' and 'ntfy_result' keys
    """
    notifier = WebhookNotifier(db_path=db_path)
    records = []
    for url in webhook_urls:
        ep = notifier.register_endpoint(url=url, org_id=org_id, secret=secret)
        record = notifier.deliver(ep.id, finding)
        records.append(record)

    ntfy_result = None
    if send_ntfy:
        ntfy = NtfyNotifier(base_url=ntfy_base_url)
        code, ms, err = ntfy.notify(finding)
        ntfy_result = {"status_code": code, "elapsed_ms": round(ms, 2), "error": err}

    return {
        "webhook_records": records,
        "ntfy_result": ntfy_result,
    }
