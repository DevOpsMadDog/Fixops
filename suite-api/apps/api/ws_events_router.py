"""
ws_events_router.py — Real-time security event streaming via WebSocket.

Endpoint:
    WS  /api/v1/ws/events — Unified security event stream (alerts, findings, incidents)

Auth:
    WebSocket auth via ?api_key= query param (checked before accept()).
    Falls back to ?token= for compatibility with websocket_alerts_router clients.
    In dev/demo mode (FIXOPS_MODE=dev) with no credentials configured, all
    connections are accepted.

Protocol:
    On connect:  {"type": "connected", "connection_id": "...", "message": "ALDECI event stream active"}
    Heartbeat:   {"type": "ping", "timestamp": "..."} every 30 s
    Client pong: {"type": "pong"} — resets missed-pong counter
    Close:       after 3 consecutive missed pongs
    Event frame: {
        "type": "event",
        "event_id": "<uuid>",
        "event_type": "alert|finding|incident|...",
        "severity": "critical|high|medium|low|info",
        "title": "...",
        "message": "...",
        "payload": {...},
        "org_id": "...",
        "timestamp": "2026-..."
    }

Filters (query params):
    event_type  — Comma-separated event types to receive, e.g. "alert,finding"
                  Omit to receive all event types.
    org_id      — Restrict to a specific tenant/org (optional).
    api_key     — API key for authentication.
    token       — JWT or API key alias (for client compatibility).

Supported event_type values:
    alert, finding, incident, sla_breach, anomaly, threat, compliance, audit
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

from apps.api.auth_deps import (
    _DEV_MODE,
    _HAS_JWT_AUTH,
    _decode_jwt,
    _load_api_tokens,
    api_key_auth,
)
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
)

_logger = logging.getLogger(__name__)

router = APIRouter(tags=["ws-events"])

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HEARTBEAT_INTERVAL = 30  # seconds between server pings
_MAX_MISSED_PONGS = 3     # close connection after this many consecutive missed pongs

#: All recognised security event types. Used for filter validation.
SECURITY_EVENT_TYPES: Set[str] = {
    "alert",
    "finding",
    "incident",
    "sla_breach",
    "anomaly",
    "threat",
    "compliance",
    "audit",
}


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------


def _authenticate_ws(api_key: Optional[str], token: Optional[str]) -> bool:
    """Validate an API key or JWT token passed via WebSocket query params.

    Accepts:
        - Any configured FIXOPS_API_TOKEN value
        - A valid JWT signed with FIXOPS_JWT_SECRET
        - Everything in dev/demo mode when no credentials are configured

    Returns:
        True if the credential is valid or auth is not required.
    """
    expected_tokens = _load_api_tokens()

    # Dev pass-through: no credentials configured and running in dev mode
    if _DEV_MODE and not expected_tokens and not _HAS_JWT_AUTH:
        return True

    credential = api_key or token
    if not credential:
        return False

    # Direct API token check
    if credential in expected_tokens:
        return True

    # JWT validation
    if _HAS_JWT_AUTH:
        try:
            _decode_jwt(credential)
            return True
        except HTTPException:
            pass

    return False


# ---------------------------------------------------------------------------
# Filter helpers
# ---------------------------------------------------------------------------


def _parse_event_type_filter(raw: Optional[str]) -> Optional[Set[str]]:
    """Parse comma-separated event_type filter string.

    Returns None (accept all) if the string is empty or contains no valid types.
    Returns a set of valid event types that matched SECURITY_EVENT_TYPES.
    """
    if not raw:
        return None
    parts = {t.strip().lower() for t in raw.split(",") if t.strip()}
    valid = parts & SECURITY_EVENT_TYPES
    return valid or None


def _event_matches(event: Dict[str, Any], event_type_filter: Optional[Set[str]]) -> bool:
    """Return True if *event* passes the optional event_type filter."""
    if event_type_filter and event.get("event_type") not in event_type_filter:
        return False
    return True


# ---------------------------------------------------------------------------
# Broadcaster adapter
# ---------------------------------------------------------------------------


def _get_broadcaster():
    """Return the singleton AlertBroadcaster, mapping alerts → security events."""
    try:
        from core.alert_broadcaster import get_alert_broadcaster
    except ImportError:
        from suite_core.core.alert_broadcaster import (
            get_alert_broadcaster,  # type: ignore[no-redef]
        )
    return get_alert_broadcaster()


def _alert_to_security_event(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Wrap an AlertBroadcaster alert dict into the unified security event envelope."""
    alert_type = alert.get("type", "alert")
    # Map alert types that correspond to security event types
    event_type_map = {
        "finding_created": "finding",
        "finding_updated": "finding",
        "sla_breach": "sla_breach",
        "incident_created": "incident",
        "incident_updated": "incident",
        "anomaly_detected": "anomaly",
        "threat_detected": "threat",
        "compliance_violation": "compliance",
        "audit_event": "audit",
    }
    event_type = event_type_map.get(alert_type, "alert")

    return {
        "type": "event",
        "event_id": alert.get("id", str(uuid.uuid4())),
        "event_type": event_type,
        "severity": alert.get("severity", "info"),
        "title": alert.get("title", "Security Event"),
        "message": alert.get("message", ""),
        "payload": {k: v for k, v in alert.items() if k not in ("id", "title", "message", "severity")},
        "org_id": alert.get("tenant_id", "default"),
        "timestamp": alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
    }


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/api/v1/ws/events")
async def ws_security_events(
    websocket: WebSocket,
    api_key: Optional[str] = Query(None, description="API key for authentication"),
    token: Optional[str] = Query(None, description="JWT or API key alias"),
    event_type: Optional[str] = Query(
        None,
        description=(
            "Comma-separated event types to receive: "
            "alert, finding, incident, sla_breach, anomaly, threat, compliance, audit. "
            "Omit to receive all types."
        ),
    ),
    org_id: Optional[str] = Query(None, description="Filter to a specific org/tenant"),
) -> None:
    """WebSocket endpoint for real-time unified security event streaming.

    Streams security events as they occur across all ALDECI engines.
    Clients can filter by event_type and/or org_id.

    Connection lifecycle:
        1. Server authenticates via api_key/token query param before accept().
        2. On success: server sends ``connected`` frame then streams events.
        3. Server sends ``ping`` every 30 s; client should reply ``pong``.
        4. Server closes after 3 consecutive missed pongs.
        5. Client can close at any time — server cleans up gracefully.
    """
    # Auth before accept so we can reject with close code 4403
    if not _authenticate_ws(api_key, token):
        await websocket.close(code=4403, reason="Unauthorized")
        return

    await websocket.accept()

    connection_id = str(uuid.uuid4())
    broadcaster = _get_broadcaster()
    queue = broadcaster.subscribe(connection_id, tenant_id=org_id)
    event_type_filter = _parse_event_type_filter(event_type)

    _logger.info(
        "WS /api/v1/ws/events connected",
        extra={
            "connection_id": connection_id,
            "org_id": org_id,
            "event_type_filter": sorted(event_type_filter) if event_type_filter else None,
        },
    )

    # Send welcome frame
    try:
        await websocket.send_json(
            {
                "type": "connected",
                "connection_id": connection_id,
                "message": "ALDECI event stream active",
                "filters": {
                    "event_type": sorted(event_type_filter) if event_type_filter else "all",
                    "org_id": org_id or "all",
                },
            }
        )
    except Exception:  # noqa: BLE001
        broadcaster.unsubscribe(connection_id)
        return

    missed_pongs = 0

    async def _heartbeat_loop() -> None:
        nonlocal missed_pongs
        while True:
            await asyncio.sleep(_HEARTBEAT_INTERVAL)
            try:
                await websocket.send_json(
                    {"type": "ping", "timestamp": datetime.now(timezone.utc).isoformat()}
                )
                missed_pongs += 1
            except Exception:  # noqa: BLE001
                break

    async def _event_loop() -> None:
        while True:
            try:
                alert = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            security_event = _alert_to_security_event(alert)
            if not _event_matches(security_event, event_type_filter):
                continue
            try:
                await websocket.send_json(security_event)
            except Exception:  # noqa: BLE001
                break

    async def _receive_loop() -> None:
        """Drain incoming frames; reset missed_pongs on pong receipt."""
        nonlocal missed_pongs
        while True:
            try:
                data = await websocket.receive_json()
                if isinstance(data, dict) and data.get("type") == "pong":
                    missed_pongs = 0
            except WebSocketDisconnect:
                break
            except Exception:  # noqa: BLE001
                break

    heartbeat_task = asyncio.create_task(_heartbeat_loop())
    event_task = asyncio.create_task(_event_loop())
    receive_task = asyncio.create_task(_receive_loop())

    try:
        while True:
            await asyncio.sleep(1.0)
            if missed_pongs >= _MAX_MISSED_PONGS:
                _logger.warning(
                    "WS /api/v1/ws/events closing — missed %d pongs",
                    missed_pongs,
                    extra={"connection_id": connection_id},
                )
                break
            if event_task.done() or receive_task.done():
                break
    except asyncio.CancelledError:
        pass
    finally:
        heartbeat_task.cancel()
        event_task.cancel()
        receive_task.cancel()
        broadcaster.unsubscribe(connection_id)
        _logger.info(
            "WS /api/v1/ws/events disconnected",
            extra={"connection_id": connection_id},
        )
        try:
            await websocket.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# REST companion: publish a test event to all subscribers
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/ws/events/test-publish",
    summary="Publish a synthetic security event to all connected WS subscribers",
    dependencies=[Depends(api_key_auth)],
)
async def test_publish_event(
    event_type: str = "alert",
    severity: str = "high",
    title: str = "Test Security Event",
    message: str = "Synthetic event from ALDECI WS event stream",
    org_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Publish a synthetic security event to all connected WebSocket subscribers.

    Useful for smoke-testing the live feed end-to-end.

    Query parameters:
        event_type: One of: alert, finding, incident, sla_breach, anomaly, threat, compliance, audit
        severity:   critical | high | medium | low | info
        title:      Event title
        message:    Event body text
        org_id:     If set, broadcast only to that tenant's subscribers

    Returns:
        {"event_id": str, "delivered": int, "event_type": str, "timestamp": str}
    """
    if event_type not in SECURITY_EVENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid event_type '{event_type}'. Valid: {sorted(SECURITY_EVENT_TYPES)}",
        )

    try:
        from core.alert_broadcaster import build_alert
    except ImportError:
        from suite_core.core.alert_broadcaster import (
            build_alert,  # type: ignore[no-redef]
        )

    # Map event_type back to an alert type the broadcaster understands
    event_type_to_alert = {
        "finding": "finding_created",
        "incident": "incident_created",
        "sla_breach": "sla_breach",
        "anomaly": "anomaly_detected",
        "threat": "threat_detected",
        "compliance": "compliance_violation",
        "audit": "audit_event",
        "alert": "finding_created",
    }
    alert_type = event_type_to_alert.get(event_type, "finding_created")

    try:
        alert = build_alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            tenant_id=org_id,
            metadata={"source": "ws-events-test-publish", "event_type": event_type},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    broadcaster = _get_broadcaster()
    if org_id:
        delivered = await broadcaster.broadcast_to_tenant(org_id, alert)
    else:
        delivered = await broadcaster.broadcast(alert)

    _logger.info(
        "ws-events test-publish sent",
        extra={"event_id": alert["id"], "event_type": event_type, "severity": severity, "delivered": delivered},
    )

    return {
        "event_id": alert["id"],
        "event_type": event_type,
        "delivered": delivered,
        "timestamp": alert["timestamp"],
    }
