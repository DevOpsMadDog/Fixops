"""ALdeci Webhook Subscriptions -- push-based event notifications with HMAC signing.

8 endpoints: CRUD + test + health/status. SSRF-protected, org-scoped, SQLite-backed.
Pillars: V3 (Decision Intelligence), V7 (MCP-Native), V9 (Air-Gapped).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets as _secrets
import socket
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from apps.api.auth_deps import require_role
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

_ADMIN_ROLES = ("admin", "org_admin", "super_admin")

router = APIRouter(
    prefix="/api/v1/webhook-subscriptions",
    tags=["webhook-subscriptions"],
    dependencies=[require_role(*_ADMIN_ROLES)],
)

# -- Constants ----------------------------------------------------------------

ALLOWED_EVENT_TYPES = frozenset({
    "finding.created", "finding.critical", "finding.resolved", "sla.breach",
    "pipeline.completed", "autofix.applied", "compliance.violation",
    "attack_path.discovered",
})
_MAX_URL_LEN = 2048
_MAX_SUBS_PER_ORG = 100
_DELIVERY_TIMEOUT_S = 5
_BLOCKED_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10",
    )
]
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# -- Pydantic Models ---------------------------------------------------------

class CreateSubscriptionRequest(BaseModel):
    url: str = Field(..., max_length=_MAX_URL_LEN)
    events: List[str] = Field(..., min_length=1, max_length=20)
    max_retries: int = Field(default=3, ge=0, le=10)
    description: Optional[str] = Field(default=None, max_length=512)

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        p = urlparse(v.strip())
        if p.scheme != "https":
            raise ValueError("Only HTTPS URLs are allowed")
        if not p.hostname:
            raise ValueError("URL must include a hostname")
        return v.strip()

    @field_validator("events")
    @classmethod
    def _events(cls, v: List[str]) -> List[str]:
        bad = [e for e in v if e not in ALLOWED_EVENT_TYPES]
        if bad:
            raise ValueError(f"Invalid event types: {bad}. Allowed: {sorted(ALLOWED_EVENT_TYPES)}")
        return list(set(v))


class UpdateSubscriptionRequest(BaseModel):
    url: Optional[str] = Field(default=None, max_length=_MAX_URL_LEN)
    events: Optional[List[str]] = Field(default=None, min_length=1, max_length=20)
    active: Optional[bool] = None
    max_retries: Optional[int] = Field(default=None, ge=0, le=10)
    description: Optional[str] = Field(default=None, max_length=512)

    @field_validator("url")
    @classmethod
    def _url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        p = urlparse(v.strip())
        if p.scheme != "https":
            raise ValueError("Only HTTPS URLs are allowed")
        if not p.hostname:
            raise ValueError("URL must include a hostname")
        return v.strip()

    @field_validator("events")
    @classmethod
    def _events(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        bad = [e for e in v if e not in ALLOWED_EVENT_TYPES]
        if bad:
            raise ValueError(f"Invalid event types: {bad}")
        return list(set(v))

# -- SSRF Protection ---------------------------------------------------------

def _is_private_ip(hostname: str) -> bool:
    """Resolve hostname and check if any resolved IP is private/reserved."""
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return True  # unresolvable = blocked
    for _, _, _, _, sockaddr in infos:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if any(addr in net for net in _BLOCKED_NETS):
            return True
    return False


def _validate_webhook_url(url: str) -> None:
    """Validate URL is HTTPS and does not resolve to a private IP."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise HTTPException(422, "Only HTTPS URLs are allowed")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(422, "URL must include a hostname")
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):  # nosec B104 — SSRF check, not a bind call
        raise HTTPException(422, "Localhost URLs are not allowed")
    try:
        addr = ipaddress.ip_address(hostname)
        if any(addr in net for net in _BLOCKED_NETS):
            raise HTTPException(422, "Private/reserved IP addresses are not allowed")
    except ValueError:
        pass
    if _is_private_ip(hostname):
        raise HTTPException(422, "URL resolves to a private/reserved IP address")

# -- SQLite Database ----------------------------------------------------------

_DB_PATH = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "data", "webhook_subscriptions.db",
))
_db_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, url TEXT NOT NULL,
    secret TEXT NOT NULL, events TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, last_triggered TEXT, failure_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3, description TEXT
);
CREATE INDEX IF NOT EXISTS idx_sub_org ON subscriptions(org_id);
CREATE INDEX IF NOT EXISTS idx_sub_active ON subscriptions(active);
CREATE TABLE IF NOT EXISTS delivery_log (
    id TEXT PRIMARY KEY, subscription_id TEXT NOT NULL, event_type TEXT NOT NULL,
    status TEXT NOT NULL, response_code INTEGER, attempted_at TEXT NOT NULL,
    delivery_id TEXT NOT NULL, error_message TEXT,
    FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
);
CREATE INDEX IF NOT EXISTS idx_dl_sub ON delivery_log(subscription_id);
CREATE INDEX IF NOT EXISTS idx_dl_time ON delivery_log(attempted_at);
"""

def _get_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    return conn


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["events"] = json.loads(d["events"]) if d.get("events") else []
    d["active"] = bool(d.get("active", 0))
    return d


def _validate_sub_id(sub_id: str) -> str:
    s = sub_id.strip().lower()
    if not _UUID_RE.match(s):
        raise HTTPException(422, "Invalid subscription ID format")
    return s

# -- HMAC Signing -------------------------------------------------------------

def _sign_payload(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

# -- Webhook Delivery Engine --------------------------------------------------

def _deliver_webhook(sub: Dict[str, Any], event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """HTTP POST with HMAC-SHA256 signature. Returns delivery result dict."""
    import requests as _req

    delivery_id = str(uuid.uuid4())
    body = json.dumps(payload, default=str).encode("utf-8")
    sig = _sign_payload(sub["secret"], body)
    headers = {
        "Content-Type": "application/json",
        "X-ALdeci-Signature": f"sha256={sig}",
        "X-ALdeci-Event": event_type,
        "X-ALdeci-Delivery-ID": delivery_id,
        "User-Agent": "ALdeci-Webhook/1.0",
    }
    result: Dict[str, Any] = {"delivery_id": delivery_id, "status": "failed", "response_code": None, "error": None}
    try:
        resp = _req.post(sub["url"], data=body, headers=headers, timeout=_DELIVERY_TIMEOUT_S, allow_redirects=False)
        result["response_code"] = resp.status_code
        result["status"] = "success" if 200 <= resp.status_code < 300 else "failed"
        if result["status"] == "failed":
            result["error"] = f"HTTP {resp.status_code}"
    except _req.Timeout:
        result["error"] = "Timeout"
    except _req.ConnectionError:
        result["error"] = "ConnectionError"
    except _req.RequestException as exc:
        result["error"] = type(exc).__name__

    # Persist delivery log
    now = datetime.now(timezone.utc).isoformat()
    try:
        with _db_lock:
            conn = _get_db()
            try:
                conn.execute(
                    "INSERT INTO delivery_log (id,subscription_id,event_type,status,response_code,attempted_at,delivery_id,error_message) VALUES (?,?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()), sub["id"], event_type, result["status"], result["response_code"], now, delivery_id, result["error"]),
                )
                conn.commit()
            finally:
                conn.close()
    except (sqlite3.Error, OSError) as exc:
        logger.warning("Failed to log delivery: %s", type(exc).__name__)
    return result


def dispatch_event(event_type: str, payload: Dict[str, Any], org_id: str) -> List[Dict[str, Any]]:
    """Find matching active subscriptions, deliver webhooks, track failures."""
    if event_type not in ALLOWED_EVENT_TYPES:
        logger.warning("Unknown event type dispatched: %s", event_type)
        return []
    try:
        with _db_lock:
            conn = _get_db()
            try:
                rows = conn.execute("SELECT * FROM subscriptions WHERE org_id=? AND active=1", (org_id,)).fetchall()
            finally:
                conn.close()
    except (sqlite3.Error, OSError) as exc:
        logger.error("Failed to query subscriptions: %s", type(exc).__name__)
        return []

    results: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for row in rows:
        sub = _row_to_dict(row)
        if event_type not in sub.get("events", []):
            continue
        result = _deliver_webhook(sub, event_type, payload)
        results.append(result)
        # Update subscription state
        try:
            with _db_lock:
                conn = _get_db()
                try:
                    if result["status"] == "success":
                        conn.execute("UPDATE subscriptions SET last_triggered=?, failure_count=0 WHERE id=?", (now, sub["id"]))
                    else:
                        new_count = sub["failure_count"] + 1
                        if new_count >= sub["max_retries"]:
                            conn.execute("UPDATE subscriptions SET failure_count=?, active=0 WHERE id=?", (new_count, sub["id"]))
                            logger.warning("Webhook %s disabled after %d failures", sub["id"], new_count)
                        else:
                            conn.execute("UPDATE subscriptions SET failure_count=?, last_triggered=? WHERE id=?", (new_count, now, sub["id"]))
                    conn.commit()
                finally:
                    conn.close()
        except (sqlite3.Error, OSError) as exc:
            logger.error("Failed to update subscription: %s", type(exc).__name__)
    return results

# -- Endpoints ----------------------------------------------------------------

@router.get("/health")
async def webhook_subscriptions_health() -> Dict[str, Any]:
    return {"status": "healthy", "engine": "webhook-subscriptions", "version": "1.0.0", "supported_events": sorted(ALLOWED_EVENT_TYPES)}

@router.get("/status")
async def webhook_subscriptions_status() -> Dict[str, Any]:
    return await webhook_subscriptions_health()

@router.post("/", status_code=201)
async def create_subscription(req: CreateSubscriptionRequest, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Create a new webhook subscription. Validates HTTPS URL, generates HMAC secret."""
    _validate_webhook_url(req.url)
    try:
        with _db_lock:
            conn = _get_db()
            try:
                count = conn.execute("SELECT COUNT(*) FROM subscriptions WHERE org_id=? AND active=1", (org_id,)).fetchone()[0]
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Internal database error")
    if count >= _MAX_SUBS_PER_ORG:
        raise HTTPException(429, f"Maximum {_MAX_SUBS_PER_ORG} active subscriptions per organization")

    sub_id = str(uuid.uuid4())
    secret = _secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc).isoformat()
    try:
        with _db_lock:
            conn = _get_db()
            try:
                conn.execute(
                    "INSERT INTO subscriptions (id,org_id,url,secret,events,active,created_at,failure_count,max_retries,description) VALUES (?,?,?,?,?,1,?,0,?,?)",
                    (sub_id, org_id, req.url, secret, json.dumps(req.events), now, req.max_retries, req.description),
                )
                conn.commit()
            finally:
                conn.close()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Subscription already exists")
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Internal database error")
    return {"id": sub_id, "org_id": org_id, "url": req.url, "secret": secret, "events": req.events,
            "active": True, "created_at": now, "last_triggered": None, "failure_count": 0,
            "max_retries": req.max_retries, "description": req.description}


@router.get("/")
async def list_subscriptions(org_id: str = Depends(get_org_id)) -> List[Dict[str, Any]]:
    """List all webhook subscriptions for the current organization."""
    try:
        with _db_lock:
            conn = _get_db()
            try:
                rows = conn.execute("SELECT * FROM subscriptions WHERE org_id=? ORDER BY created_at DESC", (org_id,)).fetchall()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Internal database error")
    return [_row_to_dict(r) for r in rows]


@router.get("/{sub_id}")
async def get_subscription(sub_id: str, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Get details of a specific webhook subscription."""
    sub_id = _validate_sub_id(sub_id)
    try:
        with _db_lock:
            conn = _get_db()
            try:
                row = conn.execute("SELECT * FROM subscriptions WHERE id=? AND org_id=?", (sub_id, org_id)).fetchone()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Internal database error")
    if not row:
        raise HTTPException(404, "Subscription not found")
    return _row_to_dict(row)


@router.put("/{sub_id}")
async def update_subscription(sub_id: str, req: UpdateSubscriptionRequest, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Update a webhook subscription."""
    sub_id = _validate_sub_id(sub_id)
    if req.url is not None:
        _validate_webhook_url(req.url)
    updates: List[str] = []
    params: List[Any] = []
    if req.url is not None:
        updates.append("url=?"); params.append(req.url)
    if req.events is not None:
        updates.append("events=?"); params.append(json.dumps(req.events))
    if req.active is not None:
        updates.append("active=?"); params.append(1 if req.active else 0)
        if req.active:
            updates.append("failure_count=0")
    if req.max_retries is not None:
        updates.append("max_retries=?"); params.append(req.max_retries)
    if req.description is not None:
        updates.append("description=?"); params.append(req.description)
    if not updates:
        raise HTTPException(422, "No fields to update")
    params.extend([sub_id, org_id])
    sql = f"UPDATE subscriptions SET {', '.join(updates)} WHERE id=? AND org_id=?"  # nosec B608
    try:
        with _db_lock:
            conn = _get_db()
            try:
                cur = conn.execute(sql, params)
                if cur.rowcount == 0:
                    raise HTTPException(404, "Subscription not found")
                conn.commit()
                row = conn.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
            finally:
                conn.close()
    except HTTPException:
        raise
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Internal database error")
    return _row_to_dict(row)


@router.delete("/{sub_id}")
async def delete_subscription(sub_id: str, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Soft-delete (deactivate) a webhook subscription."""
    sub_id = _validate_sub_id(sub_id)
    try:
        with _db_lock:
            conn = _get_db()
            try:
                cur = conn.execute("UPDATE subscriptions SET active=0 WHERE id=? AND org_id=?", (sub_id, org_id))
                if cur.rowcount == 0:
                    raise HTTPException(404, "Subscription not found")
                conn.commit()
            finally:
                conn.close()
    except HTTPException:
        raise
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Internal database error")
    return {"id": sub_id, "status": "deactivated"}


@router.post("/{sub_id}/test")
async def test_subscription(sub_id: str, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Send a test payload to verify the webhook endpoint is reachable."""
    sub_id = _validate_sub_id(sub_id)
    try:
        with _db_lock:
            conn = _get_db()
            try:
                row = conn.execute("SELECT * FROM subscriptions WHERE id=? AND org_id=?", (sub_id, org_id)).fetchone()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Internal database error")
    if not row:
        raise HTTPException(404, "Subscription not found")
    sub = _row_to_dict(row)
    test_payload = {"event": "test", "subscription_id": sub_id, "org_id": org_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "message": "This is a test webhook delivery from ALdeci."}
    result = _deliver_webhook(sub, "test", test_payload)
    return {"subscription_id": sub_id, "delivery_id": result["delivery_id"],
            "status": result["status"], "response_code": result["response_code"], "error": result["error"]}



@router.get("/delivery-log")
async def delivery_log(
    subscription_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Delivery retry dashboard — list all webhook delivery attempts.

    Supports filtering by subscription_id and status (success/failed).
    Returns chronological delivery log with response codes and errors.
    """
    try:
        with _db_lock:
            conn = _get_db()
            try:
                # Only show deliveries for subscriptions owned by this org
                query = """
                    SELECT dl.* FROM delivery_log dl
                    JOIN subscriptions s ON dl.subscription_id = s.id
                    WHERE s.org_id = ?
                """
                params: list = [org_id]
                if subscription_id:
                    query += " AND dl.subscription_id = ?"
                    params.append(subscription_id)
                if status:
                    query += " AND dl.status = ?"
                    params.append(status)
                query += " ORDER BY dl.attempted_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])

                rows = conn.execute(query, params).fetchall()
                # Get total count
                count_query = """
                    SELECT COUNT(*) FROM delivery_log dl
                    JOIN subscriptions s ON dl.subscription_id = s.id
                    WHERE s.org_id = ?
                """
                count_params: list = [org_id]
                if subscription_id:
                    count_query += " AND dl.subscription_id = ?"
                    count_params.append(subscription_id)
                if status:
                    count_query += " AND dl.status = ?"
                    count_params.append(status)
                total = conn.execute(count_query, count_params).fetchone()[0]
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Internal database error")

    return {
        "deliveries": [dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/dead-letter")
async def dead_letter_queue(
    limit: int = 50,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Dead letter queue — subscriptions disabled due to repeated delivery failures.

    Returns subscriptions where active=0 AND failure_count >= max_retries,
    along with their most recent delivery errors.
    """
    try:
        with _db_lock:
            conn = _get_db()
            try:
                rows = conn.execute(
                    """
                    SELECT s.*, (
                        SELECT dl.error_message FROM delivery_log dl
                        WHERE dl.subscription_id = s.id
                        ORDER BY dl.attempted_at DESC LIMIT 1
                    ) as last_error_message,
                    (
                        SELECT dl.attempted_at FROM delivery_log dl
                        WHERE dl.subscription_id = s.id
                        ORDER BY dl.attempted_at DESC LIMIT 1
                    ) as last_attempt_at
                    FROM subscriptions s
                    WHERE s.org_id = ? AND s.active = 0 AND s.failure_count >= s.max_retries
                    ORDER BY s.last_triggered DESC
                    LIMIT ?
                    """,
                    (org_id, limit),
                ).fetchall()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Internal database error")

    items = []
    for r in rows:
        d = _row_to_dict(r)
        d["last_error_message"] = r["last_error_message"]
        d["last_attempt_at"] = r["last_attempt_at"]
        items.append(d)

    return {"dead_letters": items, "count": len(items)}


@router.post("/dead-letter/{sub_id}/retry")
async def    retry_dead_letter(sub_id: str, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Retry a dead-lettered subscription — reactivate it and reset failure count.

    Sends a test delivery to verify the endpoint is now reachable.
    If the test succeeds, the subscription is reactivated.
    If it fails again, it stays in the dead letter queue.
    """
    sub_id = _validate_sub_id(sub_id)
    try:
        with _db_lock:
            conn = _get_db()
            try:
                row = conn.execute(
                    "SELECT * FROM subscriptions WHERE id=? AND org_id=? AND active=0",
                    (sub_id, org_id),
                ).fetchone()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Internal database error")

    if not row:
        raise HTTPException(404, "or subscription is not in dead letter queue")

    sub = _row_to_dict(row)

    # Try a test delivery first
    test_payload = {
        "event": "dead_letter_retry",
        "subscription_id": sub_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "Dead letter retry test from ALdeci.",
    }
    result = _deliver_webhook(sub, "dead_letter_retry", test_payload)

    if result["status"] == "success":
        # Reactivate the subscription
        try:
            with _db_lock:
                conn = _get_db()
                try:
                    conn.execute(
                        "UPDATE subscriptions SET active=1, failure_count=0 WHERE id=?",
                        (sub_id,),
                    )
                    conn.commit()
                finally:
                    conn.close()
        except (sqlite3.Error, OSError):
            raise HTTPException(500, "Internal database error")

        return {
            "subscription_id": sub_id,
            "status": "reactivated",
            "delivery_result": result,
            "message": "Subscription reactivated after successful test delivery.",
        }
    else:
        return {
            "subscription_id": sub_id,
            "status": "still_dead",
            "delivery_result": result,
            "message": "Test delivery failed. Subscription remains in dead letter queue.",
        }