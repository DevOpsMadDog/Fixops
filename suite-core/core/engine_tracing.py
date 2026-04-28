"""Engine call tracing helper for ALDECI.

Provides a lightweight context manager that:
1. Records a span in the in-process ``TracingContext`` (always available).
2. Optionally emits an OpenTelemetry span if the SDK is configured.
3. Attaches standard attributes: org_id, engine_name, method_name, record_count.
4. Propagates trace_id so callers can link log entries to traces.

Usage::

    from core.engine_tracing import trace_engine_call

    with trace_engine_call("risk_engine", "get_risks", org_id="acme") as ctx:
        results = engine.get_risks(org_id)
        ctx.set_record_count(len(results))
    # ctx.trace_id is available after __exit__

Graceful degradation: if OTel is not installed or the collector is down,
this module degrades silently — the in-process TracingContext still records
the span for ``GET /api/v1/system/traces/recent``.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)


class _EngineTraceContext:
    """Mutable context object yielded to the ``with`` block."""

    def __init__(self, trace_id: str, span_id: str) -> None:
        self.trace_id: str = trace_id
        self.span_id: str = span_id
        self._record_count: Optional[int] = None

    def set_record_count(self, count: int) -> None:
        """Record how many rows/items the engine method returned."""
        self._record_count = count


@contextmanager
def trace_engine_call(
    engine_name: str,
    method_name: str,
    org_id: Optional[str] = None,
    parent_trace_id: Optional[str] = None,
    parent_span_id: Optional[str] = None,
) -> Generator[_EngineTraceContext, None, None]:
    """Context manager that wraps an engine method call in a tracing span.

    Args:
        engine_name: Logical name of the engine (e.g. ``"risk_aggregator"``).
        method_name: Method being called (e.g. ``"get_top_risks"``).
        org_id:      Organisation ID for multi-tenant attribute tagging.
        parent_trace_id: Attach this span to an existing trace.
        parent_span_id:  Parent span within the trace.

    Yields:
        ``_EngineTraceContext`` with ``trace_id`` and ``set_record_count()``.

    Raises:
        Re-raises any exception from the body after finishing the span with
        ``status="error"``.
    """
    operation = f"{engine_name}.{method_name}"
    tags: dict[str, Any] = {"engine_name": engine_name, "method_name": method_name}
    if org_id:
        tags["org_id"] = str(org_id)

    # --- In-process TracingContext span ---
    from core.observability import get_tracing_context

    tracer_ctx = get_tracing_context()
    if parent_trace_id:
        trace_id = parent_trace_id
        span_id = tracer_ctx.start_span(
            trace_id,
            operation,
            parent_span_id=parent_span_id,
            service="engine",
            tags=tags,
        )
    else:
        trace_id, span_id = tracer_ctx.start_trace(
            operation, service="engine", tags=tags
        )

    ctx = _EngineTraceContext(trace_id=trace_id, span_id=span_id)

    # --- OTel span (optional) ---
    _otel_span = None
    _otel_token = None
    try:
        from telemetry import get_tracer

        _otel_tracer = get_tracer("fixops.engine")
        _otel_span = _otel_tracer.start_span(operation)
        _otel_span.set_attribute("engine.name", engine_name)
        _otel_span.set_attribute("engine.method", method_name)
        if org_id:
            _otel_span.set_attribute("org_id", str(org_id))
        # Make this the current span so child calls inherit context
        from opentelemetry import context as otel_context

        _otel_token = otel_context.attach(
            otel_context.get_current()
        )
    except Exception:  # noqa: BLE001 — OTel must never break engine calls
        _otel_span = None

    error: Optional[BaseException] = None
    try:
        yield ctx
    except BaseException as exc:
        error = exc
        raise
    finally:
        # Finish in-process span
        record_count = ctx._record_count
        finish_tags: dict[str, Any] = {}
        if record_count is not None:
            finish_tags["record_count"] = record_count
        tracer_ctx.finish_span(
            span_id,
            status="error" if error else "ok",
            error=str(error) if error else None,
            tags=finish_tags if finish_tags else None,
        )
        if not parent_trace_id:
            tracer_ctx.finish_trace(trace_id)

        # Finish OTel span
        if _otel_span is not None:
            try:
                if record_count is not None:
                    _otel_span.set_attribute("record_count", record_count)
                if error:
                    from opentelemetry.trace import StatusCode

                    _otel_span.set_status(StatusCode.ERROR, str(error))
                _otel_span.end()
            except Exception:  # noqa: BLE001
                pass
        if _otel_token is not None:
            try:
                from opentelemetry import context as otel_context

                otel_context.detach(_otel_token)
            except Exception:  # noqa: BLE001
                pass
