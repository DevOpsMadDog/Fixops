"""
Webhook Router — Okta Event Hook receiver + generic webhook ingestion.

Endpoints:
  GET  /api/v1/webhooks/okta/verify          — Okta one-time verification challenge
  POST /api/v1/webhooks/okta/events          — Okta Event Hook payload receiver
  POST /api/v1/webhooks/generic/{source}     — Accept any JSON webhook payload
  GET  /api/v1/webhooks/events               — List recent events (last 100)

Storage: SQLite WAL at data/webhook_events.db

Compliance: SOC2 CC6.1, ISO27001 A.9.4, NIST SP 800-53 AU-2
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

_DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "data", "webhook_events.db"
)


def _get_db(db_path: str = _DB_PATH) -> sqlite3.Connection:
    """Open (or create) the webhook events SQLite database with WAL mode."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webhook_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id    TEXT NOT NULL,
            source      TEXT NOT NULL DEFAULT 'unknown',
            event_type  TEXT NOT NULL,
            actor_email TEXT,
            ip_address  TEXT,
            outcome     TEXT,
            raw_json    TEXT NOT NULL,
            received_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_we_source ON webhook_events(source)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_we_event_type ON webhook_events(event_type)"
    )
    conn.commit()
    return conn


# Module-level DB singleton (path can be overridden in tests via _override_db_path)
_DB_PATH_OVERRIDE: Optional[str] = None


def _db() -> sqlite3.Connection:
    path = _DB_PATH_OVERRIDE if _DB_PATH_OVERRIDE else _DB_PATH
    return _get_db(path)


def _store_event(
    *,
    event_id: str,
    source: str,
    event_type: str,
    actor_email: Optional[str],
    ip_address: Optional[str],
    outcome: Optional[str],
    raw_json: str,
    received_at: str,
) -> None:
    conn = _db()
    try:
        conn.execute(
            """
            INSERT INTO webhook_events
                (event_id, source, event_type, actor_email, ip_address, outcome, raw_json, received_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, source, event_type, actor_email, ip_address, outcome, raw_json, received_at),
        )
        conn.commit()
    finally:
        conn.close()


def _list_events(
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    conn = _db()
    try:
        clauses: List[str] = []
        params: List[Any] = []
        if source:
            clauses.append("source = ?")
            params.append(source)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = conn.execute(
            f"SELECT * FROM webhook_events {where} ORDER BY id DESC LIMIT ?",  # nosec B608
            params,
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Okta event handlers
# ---------------------------------------------------------------------------

_OKTA_HANDLED_TYPES = {
    "user.session.start",
    "user.lifecycle.create",
    "user.lifecycle.deactivate",
    "user.lifecycle.suspend",
    "user.authentication.sso",
    "user.account.update_profile",
}


def _handle_okta_event(event: Dict[str, Any], source: str) -> None:
    """Persist a single Okta log event entry to the database."""
    event_type: str = event.get("eventType", "unknown")
    actor: Dict[str, Any] = event.get("actor") or {}
    client: Dict[str, Any] = event.get("client") or {}
    outcome_obj: Dict[str, Any] = event.get("outcome") or {}

    actor_email: Optional[str] = actor.get("alternateId") or actor.get("id")
    ip_address: Optional[str] = client.get("ipAddress")
    outcome: Optional[str] = outcome_obj.get("result")
    event_id: str = event.get("uuid") or str(uuid4())
    published: str = event.get("published") or datetime.now(timezone.utc).isoformat()

    if event_type not in _OKTA_HANDLED_TYPES:
        logger.info("okta_event_unhandled", extra={"event_type": event_type})

    logger.info(
        "okta_event_received",
        extra={
            "event_type": event_type,
            "actor_email": actor_email,
            "outcome": outcome,
        },
    )

    _store_event(
        event_id=event_id,
        source=source,
        event_type=event_type,
        actor_email=actor_email,
        ip_address=ip_address,
        outcome=outcome,
        raw_json=json.dumps(event),
        received_at=published,
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/webhooks",
    tags=["Webhooks"],
)

# NOTE: No global auth dependency — Okta verification endpoint must be unauthenticated.
# Individual sensitive endpoints can add auth as needed.


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class OktaVerifyResponse(BaseModel):
    verification: str


class OktaEventsResponse(BaseModel):
    received: int = Field(description="Number of events ingested from this request")
    event_types: List[str] = Field(description="Event types processed")


class WebhookEventOut(BaseModel):
    id: int
    event_id: str
    source: str
    event_type: str
    actor_email: Optional[str] = None
    ip_address: Optional[str] = None
    outcome: Optional[str] = None
    received_at: str


class EventsListResponse(BaseModel):
    total: int
    events: List[WebhookEventOut]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/okta/verify",
    response_model=OktaVerifyResponse,
    summary="Okta Event Hook verification challenge",
    description=(
        "Okta sends a GET with x-okta-verification-challenge header during hook registration. "
        "This endpoint echoes the challenge value back so Okta can confirm ownership."
    ),
)
async def okta_verify(
    x_okta_verification_challenge: Optional[str] = Header(
        default=None, alias="x-okta-verification-challenge"
    ),
) -> OktaVerifyResponse:
    if not x_okta_verification_challenge:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing x-okta-verification-challenge header",
        )
    return OktaVerifyResponse(verification=x_okta_verification_challenge)


@router.post(
    "/okta/events",
    response_model=OktaEventsResponse,
    summary="Receive Okta Event Hook payload",
    description=(
        "Receives batched Okta system log events. "
        "Handled event types: user.session.start, user.lifecycle.*, "
        "user.authentication.sso, user.account.update_profile."
    ),
    status_code=status.HTTP_200_OK,
)
async def okta_events(request: Request) -> OktaEventsResponse:
    try:
        body: Dict[str, Any] = await request.json()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON body: {exc}",
        )

    source: str = str(body.get("source", "okta"))
    data: Dict[str, Any] = body.get("data") or {}
    events: List[Dict[str, Any]] = data.get("events") or []

    if not events:
        logger.warning("okta_events_empty_payload", extra={"body_keys": list(body.keys())})
        return OktaEventsResponse(received=0, event_types=[])

    event_types: List[str] = []
    for event in events:
        _handle_okta_event(event, source=source)
        event_types.append(event.get("eventType", "unknown"))

    return OktaEventsResponse(received=len(events), event_types=event_types)


@router.post(
    "/generic/{source}",
    summary="Generic webhook receiver",
    description="Accept any JSON payload from an arbitrary source and store it verbatim.",
    status_code=status.HTTP_202_ACCEPTED,
)
async def generic_webhook(
    request: Request,
    source: str = Path(description="Identifies the webhook source (e.g. 'github', 'pagerduty')"),
) -> Dict[str, Any]:
    try:
        body: Any = await request.json()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON body: {exc}",
        )

    event_id = str(uuid4())
    received_at = datetime.now(timezone.utc).isoformat()
    raw = json.dumps(body) if not isinstance(body, str) else body

    _store_event(
        event_id=event_id,
        source=source,
        event_type="generic",
        actor_email=None,
        ip_address=None,
        outcome=None,
        raw_json=raw,
        received_at=received_at,
    )

    logger.info("generic_webhook_received", extra={"source": source, "event_id": event_id})
    return {"status": "accepted", "event_id": event_id, "source": source}


@router.get(
    "/events",
    response_model=EventsListResponse,
    summary="List recent webhook events",
    description="Return the last 100 stored webhook events, optionally filtered by source or event_type.",
)
async def list_events(
    source: Optional[str] = Query(default=None, description="Filter by webhook source"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
    limit: int = Query(default=100, ge=1, le=500, description="Max events to return"),
) -> EventsListResponse:
    try:
        rows = _list_events(source=source, event_type=event_type, limit=limit)
        events = [WebhookEventOut(**r) for r in rows]
        return EventsListResponse(total=len(events), events=events)
    except Exception as exc:
        logger.error("list_events_error", exc_info=exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@router.get("/", summary="Webhooks index", tags=["webhooks"])
async def webhooks_index(
    org_id: str = Query(default="default"),
    limit: int = Query(default=20, ge=1, le=200),
) -> Dict[str, Any]:
    """Return recent webhook events from the SQLite store."""
    try:
        items = _list_events(limit=limit)
    except Exception:
        items = []
    return {"router": "webhooks", "org_id": org_id, "items": items, "count": len(items)}
