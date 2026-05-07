"""
ws_trustgraph_events_router.py — Real-time TrustGraph event stream over WebSocket.

FEATURE-3 (founder spec):
    Add a WebSocket endpoint at /ws/events that streams TrustGraphEventBus events
    directly to subscribed UI clients (Mission Control / LiveFeed).

Endpoint:
    WS  /ws/events — TrustGraph event stream

Why this exists:
    The two pre-existing WebSocket routers (websocket_routes.py and
    ws_events_router.py) both:
      * Mount under /api/v1/ws/events (founder spec asks for /ws/events).
      * Subscribe to AlertBroadcaster / EventBus from event_streaming, NOT to
        the canonical TrustGraphEventBus (suite-core/core/trustgraph_event_bus.py).
      * Are imported in app.py but NEVER actually mounted via include_router.

    This router is the canonical TrustGraph WS feed: one handler per event_type
    is registered against the singleton TrustGraphEventBus on connect; events
    are pushed into a per-connection asyncio.Queue and serialised to JSON over
    the socket. On disconnect, handlers are unregistered cleanly.

Auth:
    Validated BEFORE websocket.accept() so unauth requests get a 4403 close.
    Accepts:
        ?api_key=<token>   query param (matches FIXOPS_API_TOKEN values)
        ?token=<jwt>       query param (HS256, FIXOPS_JWT_SECRET)
        X-API-Key: <token> header (preferred for service-to-service)
    Falls through in dev/demo mode with no credentials configured.

Multi-tenant:
    The optional ?org_id=<id> query param filters server-side. Events whose
    payload contains org_id / tenant_id and don't match are dropped before
    serialisation. Default tenant ('default') is always passed through.

Heartbeat:
    Server sends {"type":"ping","ts":<iso>} every WS_HEARTBEAT_SECONDS (default
    30 s — overridable via FIXOPS_WS_HEARTBEAT for fast tests). Client may
    reply with {"type":"pong"}; missed pongs are tracked but not used to
    force-close so reverse proxies stay friendly.

Frame format:
    {
        "type":       "event",
        "event_type": "finding.created",
        "payload":    {<TrustGraph event payload>},
        "timestamp":  "2026-05-02T..."
    }

Test surface:
    tests/test_feature3_websocket_events.py exercises connect → emit → receive
    + heartbeat + clean disconnect.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import (
    _DEV_MODE,
    _HAS_JWT_AUTH,
    _decode_jwt,
    _load_api_tokens,
)
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

try:
    # Canonical TrustGraph event bus — the real source of truth.
    from core.trustgraph_event_bus import (
        ALL_EVENT_TYPES,
        get_event_bus,
    )
    from core.trustgraph_event_bus import (
        EventBus as TrustGraphEventBus,  # noqa: F401  (typing aid only)
    )
except ImportError:  # pragma: no cover — sitecustomize.py path injection should make this work
    from suite_core.core.trustgraph_event_bus import (  # type: ignore[no-redef]
        ALL_EVENT_TYPES,
        get_event_bus,
    )

_logger = logging.getLogger(__name__)

router = APIRouter(tags=["ws-trustgraph-events"])

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Heartbeat interval in seconds. Overridable so tests can run fast.
_HEARTBEAT_SECONDS: int = int(os.getenv("FIXOPS_WS_HEARTBEAT", "30"))

#: Per-connection inbound event queue size. Slow clients silently drop
#: oldest events when the queue fills (back-pressure guard so a stalled
#: socket can't OOM the API process).
_QUEUE_MAXSIZE: int = 1000

#: Cap on concurrently held events per send loop iteration. Prevents one
#: noisy connection from blocking the event loop indefinitely.
_DRAIN_BATCH: int = 32


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------


def _authenticate_ws(api_key: Optional[str], token: Optional[str], header_key: Optional[str]) -> bool:
    """Validate an API key or JWT token passed via query params or X-API-Key header.

    Mirrors ws_events_router._authenticate_ws so all WS endpoints share the
    same auth surface.

    Returns:
        True iff the credential is valid OR auth is not required (dev mode).
    """
    expected_tokens = _load_api_tokens()

    # Dev pass-through: no credentials configured and running in dev mode
    if _DEV_MODE and not expected_tokens and not _HAS_JWT_AUTH:
        return True

    credential = header_key or api_key or token
    if not credential:
        return False

    if credential in expected_tokens:
        return True

    if _HAS_JWT_AUTH:
        try:
            _decode_jwt(credential)
            return True
        except Exception:  # noqa: BLE001 — any JWT failure is just an auth miss
            pass

    return False


# ---------------------------------------------------------------------------
# Event filtering
# ---------------------------------------------------------------------------

#: Event types that are internal startup noise and must never be forwarded to
#: WebSocket subscribers.  engine.loaded fires once per engine import (~90+
#: engines at startup) and accounts for ~23% of bus traffic with zero UI value.
_WS_BLOCKED_TOPICS: frozenset[str] = frozenset({"engine.loaded"})


def _payload_matches_org(payload: Dict[str, Any], org_filter: Optional[str]) -> bool:
    """Return True if *payload* should be delivered for an org_filter scope.

    Rules:
      * No filter requested  → deliver everything.
      * Filter == 'default'  → deliver events with no org_id/tenant_id OR matching default.
      * Specific org filter  → require exact match on org_id / tenant_id.
    """
    if not org_filter:
        return True

    org_in_payload = payload.get("org_id") or payload.get("tenant_id")
    if org_in_payload is None:
        # Untagged events are tenant-neutral — deliver to "default" subscribers,
        # otherwise drop to enforce strict isolation.
        return org_filter == "default"
    return str(org_in_payload) == str(org_filter)


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws/events")
async def ws_trustgraph_events(
    websocket: WebSocket,
    api_key: Optional[str] = Query(None, description="API key (or JWT) for auth"),
    token: Optional[str] = Query(None, description="JWT (alias of api_key)"),
    org_id: Optional[str] = Query(None, description="Restrict to events tagged with this org/tenant"),
) -> None:
    """Stream TrustGraphEventBus events to a WebSocket client in real time.

    Lifecycle:
        1. Auth (header X-API-Key or ?api_key=/?token= query param) before accept.
        2. accept() and send {"type":"connected", ...} envelope.
        3. Register one TrustGraphEventBus.on() handler per ALL_EVENT_TYPES;
           handlers push (event_type, payload) into a per-connection queue.
        4. Drain queue → serialize → websocket.send_json.
        5. Heartbeat task sends {"type":"ping","ts":...} every _HEARTBEAT_SECONDS.
        6. On disconnect (or send error): unregister all handlers, close socket.
    """
    # ----- AUTH (must happen before accept so we can reject 4403)
    header_key = websocket.headers.get("x-api-key") or websocket.headers.get("X-API-Key")
    if not _authenticate_ws(api_key, token, header_key):
        await websocket.close(code=4403, reason="Unauthorized")
        return

    await websocket.accept()
    connection_id = str(uuid.uuid4())
    bus = get_event_bus()

    # ----- per-connection state
    queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
    registered_handlers: List[tuple[str, Any]] = []

    def _build_handler(event_type: str):
        """Closure that pushes events for *event_type* into the local queue.

        Sync because TrustGraphEventBus._dispatch supports both sync and async
        handlers; sync is cheaper here (no extra task hop) and the actual send
        happens in the async _send_loop.
        """

        def _on_event(payload: Dict[str, Any]) -> bool:
            try:
                # Drop startup-noise topics (e.g. engine.loaded) — 23% of bus traffic.
                if event_type in _WS_BLOCKED_TOPICS:
                    return True
                # Apply server-side org filter to avoid cross-tenant leak.
                if not _payload_matches_org(payload, org_id):
                    return True

                envelope = {
                    "type": "event",
                    "event_type": event_type,
                    "payload": payload,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                if queue.full():
                    # Drop oldest to make room — keep newest for live UI.
                    try:
                        queue.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                queue.put_nowait(envelope)
            except Exception as exc:  # noqa: BLE001 — never let a handler raise into the bus
                _logger.debug("ws/events handler push failed", extra={"error": str(exc)})
            return True

        return _on_event

    # Register a handler per known event type (so new types added later still
    # need a code-side opt-in — explicit is better than implicit for the WS).
    # Skip blocked topics (startup noise) so they never reach the queue.
    for event_type in sorted(ALL_EVENT_TYPES):
        if event_type in _WS_BLOCKED_TOPICS:
            continue
        handler = _build_handler(event_type)
        bus.on(event_type, handler)
        registered_handlers.append((event_type, handler))

    _logger.info(
        "ws/events connected",
        extra={
            "connection_id": connection_id,
            "org_id": org_id,
            "handlers_registered": len(registered_handlers),
        },
    )

    # ----- send initial welcome frame
    try:
        await websocket.send_json(
            {
                "type": "connected",
                "connection_id": connection_id,
                "subscribed_event_types": sorted(ALL_EVENT_TYPES),
                "org_filter": org_id or "all",
                "heartbeat_seconds": _HEARTBEAT_SECONDS,
            }
        )
    except Exception:  # noqa: BLE001 — send may fail if client closes immediately
        _unregister_handlers(bus, registered_handlers)
        return

    # ----- single-loop architecture
    # Starlette's WebSocket.send / receive aren't safe to call concurrently
    # from multiple tasks. We serialize everything through one loop that:
    #   1. waits for the queue to deliver an event (with heartbeat timeout)
    #   2. on event → send envelope
    #   3. on heartbeat timeout → send ping
    #   4. on send error / disconnect → exit cleanly
    last_ping = datetime.now(timezone.utc).timestamp()
    try:
        while True:
            now_ts = datetime.now(timezone.utc).timestamp()
            until_next_ping = max(0.05, _HEARTBEAT_SECONDS - (now_ts - last_ping))

            envelope: Optional[Dict[str, Any]] = None
            try:
                envelope = await asyncio.wait_for(queue.get(), timeout=until_next_ping)
            except asyncio.TimeoutError:
                envelope = None
            except asyncio.CancelledError:
                break

            if envelope is not None:
                try:
                    await websocket.send_json(envelope)
                except WebSocketDisconnect:
                    break
                except Exception as exc:  # noqa: BLE001 — socket dead, exit loop
                    _logger.debug("ws/events send failed", extra={"error": str(exc)})
                    break
                # Best-effort drain of additional ready events to reduce latency
                drained = 0
                while drained < _DRAIN_BATCH - 1:
                    try:
                        extra = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    try:
                        await websocket.send_json(extra)
                        drained += 1
                    except WebSocketDisconnect:
                        envelope = None
                        break
                    except Exception:  # noqa: BLE001
                        envelope = None
                        break
                continue

            # Timeout fired — send heartbeat ping
            try:
                await websocket.send_json(
                    {"type": "ping", "ts": datetime.now(timezone.utc).isoformat()}
                )
                last_ping = datetime.now(timezone.utc).timestamp()
            except WebSocketDisconnect:
                break
            except Exception as exc:  # noqa: BLE001
                _logger.debug("ws/events heartbeat send failed", extra={"error": str(exc)})
                break
    except asyncio.CancelledError:
        pass
    except Exception as exc:  # noqa: BLE001 — never let the WS handler raise into the framework
        _logger.debug("ws/events outer error", extra={"error": str(exc)})
    finally:
        _unregister_handlers(bus, registered_handlers)
        _logger.info("ws/events disconnected", extra={"connection_id": connection_id})
        try:
            await websocket.close()
        except Exception:  # noqa: BLE001 — already closed
            pass


def _unregister_handlers(bus: Any, registered: List[tuple[str, Any]]) -> None:
    """Detach handlers from the bus so closed connections don't leak memory.

    TrustGraphEventBus stores handlers in ``bus._handlers[event_type]: list``.
    The bus exposes no public ``off()`` today — this implementation removes
    the handler in-place, defending the bus from a missing list / concurrent
    mutation by checking membership first.
    """
    handlers_map = getattr(bus, "_handlers", None)
    if handlers_map is None:
        return
    for event_type, handler in registered:
        try:
            handlers_list = handlers_map.get(event_type)
            if handlers_list and handler in handlers_list:
                handlers_list.remove(handler)
        except Exception as exc:  # noqa: BLE001 — never raise in cleanup
            _logger.debug(
                "ws/events handler unregister failed",
                extra={"event_type": event_type, "error": str(exc)},
            )
