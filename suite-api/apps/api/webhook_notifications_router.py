"""Configurable Webhook Notification System — ALDECI.

Outbound webhook notifications for external integrations. When internal
events fire (alert created, incident, compliance failure), POST to all
matching registered webhook URLs with HMAC-SHA256 signatures.

Prefix: /api/v1/webhooks/notifications
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/webhooks/notifications/register        -- register a webhook URL with event filter
  GET    /api/v1/webhooks/notifications                 -- list registered webhooks
  DELETE /api/v1/webhooks/notifications/{id}            -- remove a webhook
  POST   /api/v1/webhooks/notifications/test/{id}       -- send test payload to webhook
  POST   /api/v1/webhooks/notifications/dispatch        -- fire an event to matching webhooks (internal)
  GET    /api/v1/webhooks/notifications/events          -- list supported event types

Storage: SQLite WAL at data/webhook_notifications.db
Retry:   3 attempts with exponential back-off per delivery
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_EVENTS = frozenset({
    "alert.created",
    "alert.resolved",
    "alert.escalated",
    "incident.created",
    "incident.updated",
    "incident.resolved",
    "compliance.failure",
    "compliance.passed",
    "finding.critical",
    "finding.created",
    "finding.resolved",
    "sla.breach",
    "vulnerability.discovered",
})

_MAX_RETRIES = 3
_RETRY_DELAYS = (1, 3, 7)  # seconds between retry attempts
_DELIVERY_TIMEOUT_S = 5
_MAX_WEBHOOKS_PER_ORG = 50

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_DB_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "..", "data", "webhook_notifications.db",
    )
)
_db_lock = threading.RLock()
_DB_PATH_OVERRIDE: Optional[str] = None


def _get_db_path() -> str:
    return _DB_PATH_OVERRIDE if _DB_PATH_OVERRIDE else _DB_PATH


_SCHEMA = """
CREATE TABLE IF NOT EXISTS webhooks (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    url         TEXT NOT NULL,
    secret      TEXT NOT NULL,
    events      TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at  TEXT NOT NULL,
    last_fired  TEXT,
    fail_count  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_wn_org    ON webhooks(org_id);
CREATE INDEX IF NOT EXISTS idx_wn_active ON webhooks(active);

CREATE TABLE IF NOT EXISTS delivery_attempts (
    id              TEXT PRIMARY KEY,
    webhook_id      TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    attempt_number  INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL,
    http_status     INTEGER,
    error           TEXT,
    attempted_at    TEXT NOT NULL,
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
);
CREATE INDEX IF NOT EXISTS idx_da_webhook ON delivery_attempts(webhook_id);
"""


def _open_db() -> sqlite3.Connection:
    path = _get_db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    return conn


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["events"] = json.loads(d["events"]) if d.get("events") else []
    d["active"] = bool(d.get("active", 1))
    return d


# ---------------------------------------------------------------------------
# HMAC signing
# ---------------------------------------------------------------------------

def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Delivery engine with retry
# ---------------------------------------------------------------------------

def _deliver_once(
    url: str,
    secret: str,
    event_type: str,
    payload: Dict[str, Any],
    attempt: int,
) -> Dict[str, Any]:
    """Attempt a single HTTP POST delivery. Returns result dict."""
    try:
        import requests as _req
    except ImportError:
        return {"status": "failed", "http_status": None, "error": "requests library not available"}

    body = json.dumps(payload, default=str).encode("utf-8")
    sig = _sign(secret, body)
    headers = {
        "Content-Type": "application/json",
        "X-ALdeci-Signature": sig,
        "X-ALdeci-Event": event_type,
        "X-ALdeci-Attempt": str(attempt),
        "User-Agent": "ALdeci-Webhook-Notifier/1.0",
    }
    try:
        resp = _req.post(
            url,
            data=body,
            headers=headers,
            timeout=_DELIVERY_TIMEOUT_S,
            allow_redirects=False,
        )
        success = 200 <= resp.status_code < 300
        return {
            "status": "success" if success else "failed",
            "http_status": resp.status_code,
            "error": None if success else f"HTTP {resp.status_code}",
        }
    except _req.Timeout:
        return {"status": "failed", "http_status": None, "error": "Timeout"}
    except _req.ConnectionError:
        return {"status": "failed", "http_status": None, "error": "ConnectionError"}
    except Exception as exc:  # pragma: no cover
        return {"status": "failed", "http_status": None, "error": type(exc).__name__}


def _deliver_with_retry(
    webhook: Dict[str, Any],
    event_type: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Deliver with up to _MAX_RETRIES attempts. Returns final result."""
    url = webhook["url"]
    secret = webhook["secret"]
    final: Dict[str, Any] = {"status": "failed", "http_status": None, "error": "never_attempted"}

    for attempt in range(1, _MAX_RETRIES + 1):
        result = _deliver_once(url, secret, event_type, payload, attempt)
        final = result

        # Persist attempt log
        now = datetime.now(timezone.utc).isoformat()
        try:
            with _db_lock:
                conn = _open_db()
                try:
                    conn.execute(
                        "INSERT INTO delivery_attempts "
                        "(id, webhook_id, event_type, attempt_number, status, http_status, error, attempted_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            str(uuid.uuid4()),
                            webhook["id"],
                            event_type,
                            attempt,
                            result["status"],
                            result["http_status"],
                            result["error"],
                            now,
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
        except (sqlite3.Error, OSError) as exc:
            _logger.warning("Failed to log delivery attempt: %s", exc)

        if result["status"] == "success":
            break

        if attempt < _MAX_RETRIES:
            time.sleep(_RETRY_DELAYS[attempt - 1])

    return final


def _update_webhook_state(webhook_id: str, success: bool) -> None:
    """Update last_fired / fail_count / active after a delivery attempt."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        with _db_lock:
            conn = _open_db()
            try:
                if success:
                    conn.execute(
                        "UPDATE webhooks SET last_fired=?, fail_count=0 WHERE id=?",
                        (now, webhook_id),
                    )
                else:
                    conn.execute(
                        "UPDATE webhooks SET fail_count=fail_count+1, last_fired=? WHERE id=?",
                        (now, webhook_id),
                    )
                    row = conn.execute(
                        "SELECT fail_count FROM webhooks WHERE id=?", (webhook_id,)
                    ).fetchone()
                    if row and row["fail_count"] >= _MAX_RETRIES:
                        conn.execute(
                            "UPDATE webhooks SET active=0 WHERE id=?", (webhook_id,)
                        )
                        _logger.warning("Webhook %s disabled after %d failures", webhook_id, row["fail_count"])
                conn.commit()
            finally:
                conn.close()
    except (sqlite3.Error, OSError) as exc:
        _logger.error("Failed to update webhook state for %s: %s", webhook_id, exc)


# ---------------------------------------------------------------------------
# Public dispatch function (called by other engine routers on events)
# ---------------------------------------------------------------------------

def fire_event(event_type: str, payload: Dict[str, Any], org_id: str) -> List[Dict[str, Any]]:
    """Fire an event to all active matching webhooks for the given org.

    Called from alert, incident, and compliance routers when events occur.
    Returns a list of delivery results.
    """
    if event_type not in SUPPORTED_EVENTS:
        _logger.warning("fire_event: unsupported event type %r", event_type)
        return []

    try:
        with _db_lock:
            conn = _open_db()
            try:
                rows = conn.execute(
                    "SELECT * FROM webhooks WHERE org_id=? AND active=1",
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
    except (sqlite3.Error, OSError) as exc:
        _logger.error("fire_event: DB query failed: %s", exc)
        return []

    enriched_payload = {
        "event_type": event_type,
        "org_id": org_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **payload,
    }

    results: List[Dict[str, Any]] = []
    for row in rows:
        wh = _row_to_dict(row)
        if event_type not in wh.get("events", []):
            continue
        result = _deliver_with_retry(wh, event_type, enriched_payload)
        result["webhook_id"] = wh["id"]
        _update_webhook_state(wh["id"], result["status"] == "success")
        results.append(result)

    return results


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/webhooks/notifications",
    tags=["Webhook Notifications"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class RegisterWebhookRequest(BaseModel):
    org_id: str = Field(..., description="Organization identifier")
    url: str = Field(..., max_length=2048, description="Target HTTPS URL")
    events: List[str] = Field(..., min_length=1, max_length=20, description="Event types to subscribe to")
    description: Optional[str] = Field(default=None, max_length=512)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v = v.strip()
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use http or https scheme")
        if not parsed.hostname:
            raise ValueError("URL must include a hostname")
        return v

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: List[str]) -> List[str]:
        invalid = [e for e in v if e not in SUPPORTED_EVENTS]
        if invalid:
            raise ValueError(f"Unsupported event types: {invalid}. Supported: {sorted(SUPPORTED_EVENTS)}")
        return list(set(v))


class DispatchRequest(BaseModel):
    org_id: str
    event_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/events", summary="List supported event types")
async def list_supported_events() -> Dict[str, Any]:
    """Return all event types that can trigger webhook notifications."""
    return {"events": sorted(SUPPORTED_EVENTS), "count": len(SUPPORTED_EVENTS)}


@router.post("/register", status_code=201, summary="Register a webhook URL")
async def register_webhook(req: RegisterWebhookRequest) -> Dict[str, Any]:
    """Register a new webhook URL with an event filter. Returns the webhook ID and signing secret."""
    try:
        with _db_lock:
            conn = _open_db()
            try:
                count = conn.execute(
                    "SELECT COUNT(*) FROM webhooks WHERE org_id=? AND active=1",
                    (req.org_id,),
                ).fetchone()[0]
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Database error")

    if count >= _MAX_WEBHOOKS_PER_ORG:
        raise HTTPException(429, f"Maximum {_MAX_WEBHOOKS_PER_ORG} active webhooks per organization")

    wh_id = str(uuid.uuid4())
    secret = hashlib.sha256(os.urandom(32)).hexdigest()
    now = datetime.now(timezone.utc).isoformat()

    try:
        with _db_lock:
            conn = _open_db()
            try:
                conn.execute(
                    "INSERT INTO webhooks (id, org_id, url, secret, events, active, description, created_at, fail_count) "
                    "VALUES (?, ?, ?, ?, ?, 1, ?, ?, 0)",
                    (wh_id, req.org_id, req.url, secret, json.dumps(req.events), req.description, now),
                )
                conn.commit()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Database error")

    return {
        "id": wh_id,
        "org_id": req.org_id,
        "url": req.url,
        "secret": secret,
        "events": req.events,
        "active": True,
        "description": req.description,
        "created_at": now,
    }


@router.get("", summary="List registered webhooks")
async def list_webhooks(
    org_id: str = Query(..., description="Organization ID"),
    active_only: bool = Query(default=True, description="Return only active webhooks"),
) -> Dict[str, Any]:
    """List all registered webhooks for an organization."""
    try:
        with _db_lock:
            conn = _open_db()
            try:
                sql = "SELECT * FROM webhooks WHERE org_id=?"
                params: List[Any] = [org_id]
                if active_only:
                    sql += " AND active=1"
                sql += " ORDER BY created_at DESC"
                rows = conn.execute(sql, params).fetchall()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Database error")

    webhooks = [_row_to_dict(r) for r in rows]
    # Strip secrets from list response
    for wh in webhooks:
        wh.pop("secret", None)
    return {"webhooks": webhooks, "total": len(webhooks)}


@router.delete("/{webhook_id}", summary="Remove a webhook")
async def delete_webhook(
    webhook_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Permanently remove a registered webhook."""
    try:
        with _db_lock:
            conn = _open_db()
            try:
                cur = conn.execute(
                    "DELETE FROM webhooks WHERE id=? AND org_id=?",
                    (webhook_id, org_id),
                )
                conn.commit()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Database error")

    if cur.rowcount == 0:
        raise HTTPException(404, "Webhook not found")
    return {"id": webhook_id, "status": "deleted"}


@router.post("/test/{webhook_id}", summary="Send test payload to a webhook")
async def test_webhook(
    webhook_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Send a test payload to verify the webhook endpoint is reachable."""
    try:
        with _db_lock:
            conn = _open_db()
            try:
                row = conn.execute(
                    "SELECT * FROM webhooks WHERE id=? AND org_id=?",
                    (webhook_id, org_id),
                ).fetchone()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Database error")

    if not row:
        raise HTTPException(404, "Webhook not found")

    wh = _row_to_dict(row)
    test_payload = {
        "event_type": "test",
        "webhook_id": webhook_id,
        "org_id": org_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "Test delivery from ALdeci Webhook Notifications.",
    }
    result = _deliver_with_retry(wh, "test", test_payload)
    return {
        "webhook_id": webhook_id,
        "status": result["status"],
        "http_status": result["http_status"],
        "error": result["error"],
    }


class TestFireRequest(BaseModel):
    org_id: str = Field(..., description="Organization identifier")
    event_type: str = Field(
        default="finding.created",
        description="Event type to simulate. Must be a supported event type.",
    )
    preview_only: bool = Field(
        default=False,
        description=(
            "If true, build and return the payload that would be sent without "
            "actually POSTing to the webhook URL."
        ),
    )
    custom_fields: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional extra fields merged into the test payload.",
    )

    @field_validator("event_type")
    @classmethod
    def _validate_event_type(cls, v: str) -> str:
        if v not in SUPPORTED_EVENTS:
            raise ValueError(
                f"Unsupported event type: {v!r}. Supported: {sorted(SUPPORTED_EVENTS)}"
            )
        return v


def _build_test_fire_payload(
    webhook_id: str,
    org_id: str,
    event_type: str,
    custom_fields: Dict[str, Any],
) -> Dict[str, Any]:
    """Build the canonical test-fire envelope payload."""
    now = datetime.now(timezone.utc).isoformat()
    base: Dict[str, Any] = {
        "event_type": event_type,
        "webhook_id": webhook_id,
        "org_id": org_id,
        "timestamp": now,
        "test_fire": True,
        "sample_data": {
            "finding_id": "test-finding-001",
            "title": "SQL Injection in login endpoint",
            "severity": "critical",
            "affected_asset": "src/auth/login.py",
            "source": "semgrep",
            "cve_id": "CVE-2024-99999",
            "cvss_score": 9.8,
            "description": "Test-fire event generated by ALdeci webhook test-fire endpoint.",
        },
    }
    if custom_fields:
        base.update(custom_fields)
    return base


@router.post("/test-fire/{webhook_id}", summary="Fire a test payload with preview support")
async def test_fire_webhook(
    webhook_id: str,
    req: TestFireRequest,
) -> Dict[str, Any]:
    """Send a structured test-fire payload to a registered webhook.

    Supports two modes:
    - preview_only=false (default): builds the canonical test payload and POSTs
      it to the webhook URL via the same retry engine used for real events.
      Returns delivery status, HTTP status code, and the payload that was sent.
    - preview_only=true: returns the payload that *would* be sent without making
      any outbound HTTP call. Useful for UI previews before enabling a webhook.

    The payload envelope always includes test_fire=true so receivers can
    distinguish test deliveries from real events.
    """
    try:
        with _db_lock:
            conn = _open_db()
            try:
                row = conn.execute(
                    "SELECT * FROM webhooks WHERE id=? AND org_id=?",
                    (webhook_id, req.org_id),
                ).fetchone()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Database error")

    if not row:
        raise HTTPException(404, "Webhook not found")

    wh = _row_to_dict(row)
    payload = _build_test_fire_payload(
        webhook_id=webhook_id,
        org_id=req.org_id,
        event_type=req.event_type,
        custom_fields=req.custom_fields,
    )

    if req.preview_only:
        return {
            "webhook_id": webhook_id,
            "mode": "preview",
            "event_type": req.event_type,
            "payload": payload,
            "delivery_skipped": True,
        }

    result = _deliver_with_retry(wh, req.event_type, payload)
    _update_webhook_state(webhook_id, result["status"] == "success")

    return {
        "webhook_id": webhook_id,
        "mode": "live",
        "event_type": req.event_type,
        "status": result["status"],
        "http_status": result["http_status"],
        "error": result["error"],
        "payload_sent": payload,
    }


@router.post("/dispatch", summary="Dispatch an internal event to matching webhooks")
async def dispatch_event(req: DispatchRequest) -> Dict[str, Any]:
    """Fire an event to all matching active webhooks. Used by internal systems."""
    if req.event_type not in SUPPORTED_EVENTS:
        raise HTTPException(
            422,
            f"Unsupported event type: {req.event_type!r}. Supported: {sorted(SUPPORTED_EVENTS)}",
        )
    results = fire_event(req.event_type, req.payload, req.org_id)
    success_count = sum(1 for r in results if r.get("status") == "success")
    return {
        "event_type": req.event_type,
        "org_id": req.org_id,
        "webhooks_notified": len(results),
        "success_count": success_count,
        "failure_count": len(results) - success_count,
        "results": results,
    }
