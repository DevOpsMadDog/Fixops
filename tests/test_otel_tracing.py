"""Tests for enhanced OpenTelemetry distributed tracing.

Covers:
- trace_engine_call context manager records spans in TracingContext
- LogEntry now carries trace_id field and search filters on it
- GET /api/v1/system/traces/recent returns trace summaries
- trace_id is attached to request.state (verified via TracingContext directly)
"""

from __future__ import annotations

import os

import pytest

# Disable telemetry export so tests never need a collector running
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-that-is-long-enough-32")


# ---------------------------------------------------------------------------
# 1. trace_engine_call records span in TracingContext
# ---------------------------------------------------------------------------


def test_trace_engine_call_records_span():
    """trace_engine_call writes a span + trace into the singleton TracingContext."""
    from core.engine_tracing import trace_engine_call
    from core.observability import get_tracing_context

    ctx_store = get_tracing_context()

    with trace_engine_call("risk_engine", "get_top_risks", org_id="acme-test") as ctx:
        ctx.set_record_count(42)

    trace_id = ctx.trace_id
    assert trace_id, "trace_id must be set"

    spans = ctx_store.get_trace(trace_id)
    assert len(spans) >= 1, "at least one span must be recorded"

    root = spans[0]
    assert root.operation == "risk_engine.get_top_risks"
    assert root.tags.get("engine_name") == "risk_engine"
    assert root.tags.get("method_name") == "get_top_risks"
    assert root.tags.get("org_id") == "acme-test"
    assert root.tags.get("record_count") == 42
    assert root.status == "ok"


def test_trace_engine_call_error_marks_span_error():
    """On exception the span status is 'error' and re-raises."""
    from core.engine_tracing import trace_engine_call
    from core.observability import get_tracing_context

    ctx_store = get_tracing_context()
    trace_id_holder: list[str] = []

    with pytest.raises(ValueError, match="boom"):
        with trace_engine_call("bad_engine", "explode", org_id="org1") as ctx:
            trace_id_holder.append(ctx.trace_id)
            raise ValueError("boom")

    spans = ctx_store.get_trace(trace_id_holder[0])
    assert spans[0].status == "error"
    assert "boom" in (spans[0].error or "")


# ---------------------------------------------------------------------------
# 2. LogEntry trace_id field — store and search
# ---------------------------------------------------------------------------


def test_log_entry_trace_id_stored_and_searchable():
    """Emitting a log with trace_id stores it and search() can filter on it."""
    from core.observability import LogAggregator

    agg = LogAggregator()
    tid = "abc123-trace"

    agg.emit("engine started", level="info", trace_id=tid, correlation_id="cid-1")
    agg.emit("engine finished", level="info", trace_id=tid, correlation_id="cid-1")
    agg.emit("unrelated log", level="info", trace_id="other-trace")

    # Filter by trace_id
    results = agg.search(trace_id=tid)
    assert len(results) == 2
    for entry in results:
        assert entry.trace_id == tid

    # Unrelated trace returns different results
    other = agg.search(trace_id="other-trace")
    assert len(other) == 1
    assert other[0].message == "unrelated log"

    # No trace_id filter returns all
    all_entries = agg.search()
    assert len(all_entries) >= 3


# ---------------------------------------------------------------------------
# 3. GET /api/v1/system/traces/recent endpoint
# ---------------------------------------------------------------------------


def test_system_traces_recent_endpoint():
    """system_traces_recent() handler returns correct structure."""
    import asyncio

    from apps.api.system_router import system_traces_recent
    from core.engine_tracing import trace_engine_call

    # Produce at least one trace before calling the handler
    with trace_engine_call("posture_engine", "get_score", org_id="tenant-42") as ctx:
        ctx.set_record_count(10)

    # Call the async endpoint handler directly (no HTTP layer needed)
    body = asyncio.get_event_loop().run_until_complete(system_traces_recent(limit=50))

    assert "count" in body
    assert "traces" in body
    assert isinstance(body["traces"], list)
    assert body["count"] == len(body["traces"])

    # Verify our trace appears in results
    trace_ids = {t["trace_id"] for t in body["traces"]}
    assert ctx.trace_id in trace_ids, f"Expected {ctx.trace_id} in {trace_ids}"

    # Verify required fields on each entry
    for t in body["traces"]:
        assert "trace_id" in t
        assert "operation" in t
        assert "span_count" in t
        assert "total_duration_ms" in t
        assert "status" in t


# ---------------------------------------------------------------------------
# 4. recent_traces includes org_id and engine_name attributes
# ---------------------------------------------------------------------------


def test_recent_traces_include_span_attributes():
    """recent_traces() surfaces org_id and engine_name from span tags."""
    from core.engine_tracing import trace_engine_call
    from core.observability import get_tracing_context

    ctx_store = get_tracing_context()

    with trace_engine_call("kpi_engine", "compute_mttr", org_id="widget-co") as ctx:
        ctx.set_record_count(5)

    traces = ctx_store.recent_traces(limit=100)
    our_trace = next((t for t in traces if t["trace_id"] == ctx.trace_id), None)
    assert our_trace is not None, "trace must appear in recent_traces()"
    assert our_trace["engine_name"] == "kpi_engine"
    assert our_trace["org_id"] == "widget-co"
    assert our_trace["span_count"] >= 1
    assert our_trace["total_duration_ms"] >= 0.0
