"""
websocket_alerts_router.py — Real-time security alerts WebSocket feed.

Endpoints:
    GET /ws/alerts          — WebSocket live alert stream (auth via ?token=)
    POST /api/v1/alerts/test-broadcast  — Send synthetic alert to all subscribers (auth required)

WebSocket protocol:
    On connect:  {"type": "connected", "message": "ALDECI live feed active"}
    Heartbeat:   {"type": "ping"} every 30s; close after 3 missed pongs
    Alert frame: full alert dict from AlertBroadcaster
    Filter:      ?severity=critical,high  and/or  ?type=finding_created,sla_breach

Auth:
    WebSocket — ?token=<api_key_or_jwt>  (query param, checked before accept())
    REST endpoint — standard api_key_auth dependency
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

try:
    from core.alert_broadcaster import (
        ALERT_TYPES,
        SEVERITY_LEVELS,
        build_alert,
        get_alert_broadcaster,
    )
except ImportError:  # graceful degradation if suite-core not on path
    from suite_core.core.alert_broadcaster import (  # type: ignore[no-redef]
        ALERT_TYPES,
        SEVERITY_LEVELS,
        build_alert,
        get_alert_broadcaster,
    )

_logger = logging.getLogger(__name__)

router = APIRouter(tags=["alerts"])

# ---------------------------------------------------------------------------
# Heartbeat config
# ---------------------------------------------------------------------------

_HEARTBEAT_INTERVAL = 30  # seconds
_MAX_MISSED_PONGS = 3


# ---------------------------------------------------------------------------
# WebSocket token auth helper
# ---------------------------------------------------------------------------


def _authenticate_ws_token(token: Optional[str]) -> bool:
    """Validate a token passed via WebSocket ?token= query param.

    Accepts:
    - Any configured API token (FIXOPS_API_TOKEN)
    - A valid JWT (FIXOPS_JWT_SECRET)
    - Everything in dev/demo mode with no auth configured

    Returns:
        True if the token is valid or auth is not required.
    """
    expected_tokens = _load_api_tokens()

    # Dev pass-through
    if _DEV_MODE and not expected_tokens and not _HAS_JWT_AUTH:
        return True

    if not token:
        return False

    # API token check
    if token in expected_tokens:
        return True

    # JWT check
    if _HAS_JWT_AUTH:
        try:
            _decode_jwt(token)
            return True
        except HTTPException:
            pass

    return False


# ---------------------------------------------------------------------------
# Filter helpers
# ---------------------------------------------------------------------------


def _parse_severity_filter(raw: Optional[str]) -> Optional[Set[str]]:
    """Parse comma-separated severity filter, return None if empty/invalid."""
    if not raw:
        return None
    parts = {s.strip().lower() for s in raw.split(",") if s.strip()}
    valid = parts & set(SEVERITY_LEVELS)
    return valid if valid else None


def _parse_type_filter(raw: Optional[str]) -> Optional[Set[str]]:
    """Parse comma-separated alert-type filter, return None if empty/invalid."""
    if not raw:
        return None
    parts = {t.strip() for t in raw.split(",") if t.strip()}
    valid = parts & ALERT_TYPES
    return valid if valid else None


def _alert_matches(
    alert: Dict[str, Any],
    severity_filter: Optional[Set[str]],
    type_filter: Optional[Set[str]],
) -> bool:
    """Return True if alert passes the optional filters."""
    if severity_filter and alert.get("severity") not in severity_filter:
        return False
    if type_filter and alert.get("type") not in type_filter:
        return False
    return True


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws/alerts")
async def websocket_alerts(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="API key or JWT for authentication"),
    severity: Optional[str] = Query(None, description="Comma-separated severity filter, e.g. critical,high"),
    type: Optional[str] = Query(None, description="Comma-separated alert type filter, e.g. finding_created"),
    tenant_id: Optional[str] = Query(None, description="Subscribe to a specific tenant's alerts only"),
) -> None:
    """WebSocket endpoint for real-time security alerts.

    Query parameters:
        token:     API key or JWT (required unless FIXOPS_MODE=dev with no auth configured)
        severity:  Comma-separated severities to receive (e.g. critical,high)
        type:      Comma-separated alert types to receive (e.g. finding_created,sla_breach)
        tenant_id: Subscribe only to alerts for this tenant

    Protocol:
        - On connect:  {"type": "connected", "message": "ALDECI live feed active"}
        - Heartbeat:   {"type": "ping"} every 30 s; reply with {"type": "pong"}
        - Close after 3 consecutive missed pongs
        - Alert frame: full alert dict matching the requested filters
    """
    # --- Auth (before accept so we can reject with 403) ---
    if not _authenticate_ws_token(token):
        await websocket.close(code=4403, reason="Unauthorized")
        return

    await websocket.accept()

    connection_id = str(uuid.uuid4())
    broadcaster = get_alert_broadcaster()
    queue = broadcaster.subscribe(connection_id, tenant_id=tenant_id)

    severity_filter = _parse_severity_filter(severity)
    type_filter = _parse_type_filter(type)

    _logger.info(
        "WS /ws/alerts connected",
        connection_id=connection_id,
        tenant_id=tenant_id,
        severity_filter=severity_filter,
        type_filter=type_filter,
    )

    # Send welcome frame
    try:
        await websocket.send_json(
            {"type": "connected", "message": "ALDECI live feed active", "connection_id": connection_id}
        )
    except Exception:
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
            except Exception:
                break

    async def _alert_loop() -> None:
        while True:
            try:
                alert = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if not _alert_matches(alert, severity_filter, type_filter):
                continue
            try:
                await websocket.send_json(alert)
            except Exception:
                break

    async def _receive_loop() -> None:
        """Drain incoming frames; reset missed_pongs on pong."""
        nonlocal missed_pongs
        while True:
            try:
                data = await websocket.receive_json()
                if isinstance(data, dict) and data.get("type") == "pong":
                    missed_pongs = 0
            except WebSocketDisconnect:
                break
            except Exception:
                break

    heartbeat_task = asyncio.create_task(_heartbeat_loop())
    alert_task = asyncio.create_task(_alert_loop())
    receive_task = asyncio.create_task(_receive_loop())

    try:
        while True:
            await asyncio.sleep(1.0)
            if missed_pongs >= _MAX_MISSED_PONGS:
                _logger.warning("WS /ws/alerts closing — missed %d pongs", missed_pongs, extra={"connection_id": connection_id})
                break
            # Stop if any task finished (disconnect or error)
            if alert_task.done() or receive_task.done():
                break
    except asyncio.CancelledError:
        pass
    finally:
        heartbeat_task.cancel()
        alert_task.cancel()
        receive_task.cancel()
        broadcaster.unsubscribe(connection_id)
        _logger.info("WS /ws/alerts disconnected", connection_id=connection_id)
        try:
            await websocket.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Demo/test broadcast endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/alerts/test-broadcast",
    summary="Send a synthetic test alert to all connected WebSocket subscribers",
    dependencies=[Depends(api_key_auth)],
)
async def test_broadcast(
    alert_type: str = "finding_created",
    severity: str = "high",
    title: str = "Test Alert",
    message: str = "This is a synthetic test alert from ALDECI",
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a synthetic alert to all connected WebSocket subscribers.

    Useful for verifying that the live feed is working end-to-end.

    Query parameters:
        alert_type: One of the supported alert types (default: finding_created)
        severity:   Alert severity (default: high)
        title:      Alert title
        message:    Alert message body
        tenant_id:  If set, broadcast only to that tenant's subscribers

    Returns:
        {"alert_id": str, "delivered": int, "timestamp": str}
    """
    try:
        alert = build_alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            tenant_id=tenant_id,
            metadata={"source": "test-broadcast"},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    broadcaster = get_alert_broadcaster()

    if tenant_id:
        delivered = await broadcaster.broadcast_to_tenant(tenant_id, alert)
    else:
        delivered = await broadcaster.broadcast(alert)

    _logger.info(
        "test-broadcast sent",
        alert_id=alert["id"],
        alert_type=alert_type,
        severity=severity,
        delivered=delivered,
    )

    return {
        "alert_id": alert["id"],
        "delivered": delivered,
        "timestamp": alert["timestamp"],
    }
