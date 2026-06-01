"""Shared safe TrustGraph event-bus emitter.

This module provides a single ``safe_emit`` function that all engines can call
from *synchronous* code without risking:

  - RuntimeWarning: coroutine 'EventBus.emit' was never awaited
    (when bus.emit returns a coroutine but no running event loop exists)
  - Silently dropped events (the original bare-except patterns)

Behaviour:
  - If bus.emit returns a coroutine AND a running loop exists  → schedule via
    loop.create_task() so the coroutine runs in the current event loop.
  - If bus.emit returns a coroutine AND no running loop exists → close the
    coroutine cleanly (no RuntimeWarning) and log a debug note.
  - If bus.emit returns anything else (sync callable)          → result is used
    as-is; no special handling needed.
  - All exceptions from the bus are swallowed — telemetry is always best-effort.

Usage:
    from core._tg_safe_emit import safe_emit
    safe_emit("runtime_protection.event_ingested", {"key": "value"})
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Any, Dict

_logger = logging.getLogger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def safe_emit(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit *event_type* with *payload* to the TrustGraph event bus.

    Safe to call from synchronous code regardless of whether an asyncio event
    loop is currently running.  Never raises; never leaks unawaited coroutines.
    """
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit_fn = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit_fn is None:
            return
        result = emit_fn(event_type, payload)
        if inspect.iscoroutine(result):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(result)
            except RuntimeError:
                # No running loop — close cleanly to suppress RuntimeWarning.
                result.close()
                _logger.debug(
                    "safe_emit: no running loop for event %s — coroutine closed",
                    event_type,
                )
    except Exception:  # noqa: BLE001 — best-effort telemetry, never raise
        pass
