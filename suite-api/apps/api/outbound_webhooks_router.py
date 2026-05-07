"""
Outbound Webhooks — per-org subscriptions to ALdeci event topics.

POST   /api/v1/webhooks/outbound/           — create subscription
GET    /api/v1/webhooks/outbound/           — list org subscriptions
DELETE /api/v1/webhooks/outbound/{sub_id}  — revoke subscription
GET    /api/v1/webhooks/outbound/health    — health alias
GET    /api/v1/webhooks/outbound/status    — status alias

Supported topics: finding.created.critical, incident.opened, council.escalated

On matching TrustGraph emit, dispatcher signs the payload with HMAC-SHA256
and HTTP-POSTs it to each subscribed URL via httpx async.

Storage: SQLite WAL at data/outbound_webhooks.db
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

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_TOPICS = frozenset({
    "finding.created.critical",
    "incident.opened",
    "council.escalated",
})

_MAX_URL_LEN = 2048
_MAX_SUBS_PER_ORG = 50
_DELIVERY_TIMEOUT_S = 10
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

_BLOCKED_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10",
    )
]

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/webhooks/outbound",
    tags=["outbound-webhooks"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class CreateOutboundWebhookRequest(BaseModel):
    url: str = Field(..., max_length=_MAX_URL_LEN, description="HTTPS target URL")
    secret: Optional[str] = Field(
        default=None,
        description="Shared HMAC secret (auto-generated if omitted)",
        max_length=256,
    )
    topics: List[str] = Field(
        ...,
        min_length=1,
        max_length=10,
        description=f"Event topics to subscribe. Allowed: {sorted(SUPPORTED_TOPICS)}",
    )
    description: Optional[str] = Field(default=None, max_length=512)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v = v.strip()
        parsed = urlparse(v)
        if parsed.scheme != "https":
            raise ValueError("Only HTTPS URLs are allowed")
        if not parsed.hostname:
            raise ValueError("URL must include a hostname")
        return v

    @field_validator("topics")
    @classmethod
    def _validate_topics(cls, v: List[str]) -> List[str]:
        bad = [t for t in v if t not in SUPPORTED_TOPICS]
        if bad:
            raise ValueError(
                f"Unsupported topics: {bad}. Allowed: {sorted(SUPPORTED_TOPICS)}"
            )
        return list(dict.fromkeys(v))  # deduplicate, preserve order


class OutboundWebhookOut(BaseModel):
    id: str
    org_id: str
    url: str
    topics: List[str]
    description: Optional[str]
    active: bool
    created_at: str
    last_triggered: Optional[str]
    failure_count: int


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

def _is_private_ip(hostname: str) -> bool:
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


def _validate_ssrf(url: str) -> None:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):  # nosec B104
        raise HTTPException(422, "Localhost URLs are not permitted")
    try:
        addr = ipaddress.ip_address(hostname)
        if any(addr in net for net in _BLOCKED_NETS):
            raise HTTPException(422, "Private/reserved IP addresses are not permitted")
    except ValueError:
        pass
    if _is_private_ip(hostname):
        raise HTTPException(422, "URL resolves to a private/reserved IP — SSRF blocked")


# ---------------------------------------------------------------------------
# SQLite storage
# ---------------------------------------------------------------------------

_DB_PATH = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "data", "outbound_webhooks.db",
))
_db_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbound_subscriptions (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL,
    url           TEXT NOT NULL,
    secret        TEXT NOT NULL,
    topics        TEXT NOT NULL,
    description   TEXT,
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    last_triggered TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_osub_org    ON outbound_subscriptions(org_id);
CREATE INDEX IF NOT EXISTS idx_osub_active ON outbound_subscriptions(active);
"""


def _get_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    return conn


def _row_to_out(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["topics"] = json.loads(d["topics"]) if d.get("topics") else []
    d["active"] = bool(d.get("active", 0))
    d.pop("secret", None)  # never expose secret in list/get responses
    return d


def _validate_sub_id(sub_id: str) -> str:
    s = sub_id.strip().lower()
    if not _UUID_RE.match(s):
        raise HTTPException(422, "Invalid subscription ID format")
    return s


# ---------------------------------------------------------------------------
# HMAC signing
# ---------------------------------------------------------------------------

def sign_payload(secret: str, body: bytes) -> str:
    """Return hex digest of HMAC-SHA256(secret, body)."""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Async dispatcher (called from TrustGraph event bus or internal triggers)
# ---------------------------------------------------------------------------

async def dispatch_outbound(topic: str, payload: Dict[str, Any], org_id: str) -> List[Dict[str, Any]]:
    """
    Find active subscriptions for (org_id, topic), sign the payload, and
    HTTP-POST to each subscribed URL.  Returns list of delivery result dicts.

    Safe to call from async context (uses httpx.AsyncClient).
    """
    if topic not in SUPPORTED_TOPICS:
        logger.warning("dispatch_outbound: unknown topic %s", topic)
        return []

    try:
        with _db_lock:
            conn = _get_db()
            try:
                rows = conn.execute(
                    "SELECT * FROM outbound_subscriptions WHERE org_id=? AND active=1",
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
    except (sqlite3.Error, OSError) as exc:
        logger.error("dispatch_outbound: db query failed: %s", exc)
        return []

    results: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    async with httpx.AsyncClient(timeout=_DELIVERY_TIMEOUT_S, follow_redirects=False) as client:
        for row in rows:
            sub = dict(row)
            sub_topics: List[str] = json.loads(sub.get("topics") or "[]")
            if topic not in sub_topics:
                continue

            delivery_id = str(uuid.uuid4())
            envelope = {
                "id": delivery_id,
                "topic": topic,
                "org_id": org_id,
                "timestamp": now,
                "payload": payload,
            }
            body = json.dumps(envelope, default=str).encode("utf-8")
            sig = sign_payload(sub["secret"], body)
            headers = {
                "Content-Type": "application/json",
                "X-ALdeci-Signature": f"sha256={sig}",
                "X-ALdeci-Topic": topic,
                "X-ALdeci-Delivery-ID": delivery_id,
                "User-Agent": "ALdeci-OutboundWebhook/1.0",
            }
            result: Dict[str, Any] = {
                "subscription_id": sub["id"],
                "delivery_id": delivery_id,
                "status": "failed",
                "response_code": None,
                "error": None,
            }
            try:
                resp = await client.post(sub["url"], content=body, headers=headers)
                result["response_code"] = resp.status_code
                result["status"] = "success" if 200 <= resp.status_code < 300 else "failed"
                if result["status"] == "failed":
                    result["error"] = f"HTTP {resp.status_code}"
            except httpx.TimeoutException:
                result["error"] = "Timeout"
            except httpx.ConnectError:
                result["error"] = "ConnectError"
            except httpx.HTTPError as exc:
                result["error"] = type(exc).__name__

            # Update subscription state
            try:
                with _db_lock:
                    conn = _get_db()
                    try:
                        if result["status"] == "success":
                            conn.execute(
                                "UPDATE outbound_subscriptions SET last_triggered=?, failure_count=0 WHERE id=?",
                                (now, sub["id"]),
                            )
                        else:
                            new_count = sub["failure_count"] + 1
                            if new_count >= 5:
                                conn.execute(
                                    "UPDATE outbound_subscriptions SET failure_count=?, active=0 WHERE id=?",
                                    (new_count, sub["id"]),
                                )
                                logger.warning("outbound webhook %s disabled after %d failures", sub["id"], new_count)
                            else:
                                conn.execute(
                                    "UPDATE outbound_subscriptions SET failure_count=?, last_triggered=? WHERE id=?",
                                    (new_count, now, sub["id"]),
                                )
                        conn.commit()
                    finally:
                        conn.close()
            except (sqlite3.Error, OSError) as exc:
                logger.error("dispatch_outbound: state update failed: %s", exc)

            results.append(result)

    return results


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
async def outbound_webhooks_health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "engine": "outbound-webhooks",
        "version": "1.0.0",
        "supported_topics": sorted(SUPPORTED_TOPICS),
    }


@router.get("/status")
async def outbound_webhooks_status() -> Dict[str, Any]:
    return await outbound_webhooks_health()


@router.post("/", status_code=201)
async def create_outbound_webhook(
    req: CreateOutboundWebhookRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a per-org outbound webhook subscription."""
    _validate_ssrf(req.url)

    try:
        with _db_lock:
            conn = _get_db()
            try:
                count = conn.execute(
                    "SELECT COUNT(*) FROM outbound_subscriptions WHERE org_id=? AND active=1",
                    (org_id,),
                ).fetchone()[0]
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Database error")

    if count >= _MAX_SUBS_PER_ORG:
        raise HTTPException(429, f"Maximum {_MAX_SUBS_PER_ORG} active subscriptions per org")

    sub_id = str(uuid.uuid4())
    secret = req.secret or _secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc).isoformat()

    try:
        with _db_lock:
            conn = _get_db()
            try:
                conn.execute(
                    "INSERT INTO outbound_subscriptions "
                    "(id, org_id, url, secret, topics, description, active, created_at, failure_count) "
                    "VALUES (?, ?, ?, ?, ?, ?, 1, ?, 0)",
                    (sub_id, org_id, req.url, secret, json.dumps(req.topics), req.description, now),
                )
                conn.commit()
            finally:
                conn.close()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Subscription already exists")
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Database error")

    return {
        "id": sub_id,
        "org_id": org_id,
        "url": req.url,
        "secret": secret,  # returned once on creation only
        "topics": req.topics,
        "description": req.description,
        "active": True,
        "created_at": now,
        "last_triggered": None,
        "failure_count": 0,
    }


@router.get("/")
async def list_outbound_webhooks(org_id: str = Depends(get_org_id)) -> List[Dict[str, Any]]:
    """List all outbound webhook subscriptions for the current org."""
    try:
        with _db_lock:
            conn = _get_db()
            try:
                rows = conn.execute(
                    "SELECT * FROM outbound_subscriptions WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Database error")
    return [_row_to_out(r) for r in rows]


@router.delete("/{sub_id}")
async def revoke_outbound_webhook(
    sub_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Revoke (soft-delete) an outbound webhook subscription."""
    sub_id = _validate_sub_id(sub_id)
    try:
        with _db_lock:
            conn = _get_db()
            try:
                cur = conn.execute(
                    "UPDATE outbound_subscriptions SET active=0 WHERE id=? AND org_id=?",
                    (sub_id, org_id),
                )
                if cur.rowcount == 0:
                    raise HTTPException(404, "Subscription not found")
                conn.commit()
            finally:
                conn.close()
    except HTTPException:
        raise
    except (sqlite3.Error, OSError):
        raise HTTPException(500, "Database error")
    return {"id": sub_id, "status": "revoked"}
