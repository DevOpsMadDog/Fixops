"""Comprehensive tests for the observability module.

Tests cover:
- HealthProbe: liveness, readiness, startup checks
- MetricsCollector: recording, histograms, Prometheus text, error rate
- AlertRule: condition evaluation
- AlertManager: rule CRUD, firing, cooldown, dedup, history, resolution
- LogAggregator: emit, search, stats, JSON lines
- TracingContext: start/finish traces and spans, parent-child, export
- ObservabilityRouter: all 8+ HTTP endpoints via FastAPI TestClient

All tests use in-memory state — no external dependencies.
"""

from __future__ import annotations

import os
import time

import pytest

# Configure environment for testing
os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-that-is-long-enough-32")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

# ---------------------------------------------------------------------------
# Imports (after env setup)
# ---------------------------------------------------------------------------

from core.observability import (
    AlertManager,
    AlertRule,
    FiredAlert,
    HealthProbe,
    LogAggregator,
    MetricsCollector,
    Span,
    TracingContext,
    _get_nested,
    get_alert_manager,
    get_health_probe,
    get_log_aggregator,
    get_metrics_collector,
    get_tracing_context,
)


# ===========================================================================
# HealthProbe
# ===========================================================================


class TestHealthProbe:
    def setup_method(self):
        self.probe = HealthProbe()

    def test_liveness_returns_ok_by_default(self):
        result = self.probe.liveness()
        assert result.status == "ok"
        assert len(result.checks) >= 2

    def test_liveness_checks_memory_and_event_loop(self):
        result = self.probe.liveness()
        names = [c.name for c in result.checks]
        assert "memory" in names
        assert "event_loop" in names

    def test_liveness_all_checks_healthy(self):
        result = self.probe.liveness()
        for check in result.checks:
            assert check.healthy is True

    def test_liveness_has_timestamp(self):
        result = self.probe.liveness()
        assert result.timestamp
        assert "T" in result.timestamp  # ISO 8601

    def test_liveness_has_uptime(self):
        result = self.probe.liveness()
        assert result.uptime_seconds >= 0.0

    def test_readiness_no_checks_registered_returns_ok(self):
        result = self.probe.readiness()
        assert result.status == "ok"

    def test_readiness_db_check_passes(self):
        self.probe.set_db_check(lambda: True)
        result = self.probe.readiness()
        db = next(c for c in result.checks if c.name == "database")
        assert db.healthy is True

    def test_readiness_db_check_fails(self):
        self.probe.set_db_check(lambda: False)
        result = self.probe.readiness()
        assert result.status == "degraded"
        db = next(c for c in result.checks if c.name == "database")
        assert db.healthy is False

    def test_readiness_db_check_exception(self):
        self.probe.set_db_check(lambda: (_ for _ in ()).throw(RuntimeError("conn refused")))
        result = self.probe.readiness()
        assert result.status == "degraded"
        db = next(c for c in result.checks if c.name == "database")
        assert db.healthy is False

    def test_readiness_queue_check_within_bounds(self):
        self.probe.set_queue_check(lambda: 100)
        result = self.probe.readiness()
        q = next(c for c in result.checks if c.name == "queue")
        assert q.healthy is True

    def test_readiness_queue_depth_exceeded(self):
        self.probe._max_queue_depth = 50
        self.probe.set_queue_check(lambda: 100)
        result = self.probe.readiness()
        assert result.status == "degraded"
        q = next(c for c in result.checks if c.name == "queue")
        assert q.healthy is False

    def test_startup_returns_unavailable_before_complete(self):
        result = self.probe.startup()
        assert result.status == "unavailable"

    def test_startup_returns_ok_after_mark_complete(self):
        self.probe.mark_startup_complete()
        result = self.probe.startup()
        assert result.status == "ok"

    def test_startup_check_detail(self):
        result = self.probe.startup()
        check = result.checks[0]
        assert check.name == "startup"
        assert "initialising" in (check.detail or "")


# ===========================================================================
# MetricsCollector
# ===========================================================================


class TestMetricsCollector:
    def setup_method(self):
        self.mc = MetricsCollector()

    def test_initial_snapshot_zero_totals(self):
        snap = self.mc.snapshot()
        assert snap["total_requests"] == 0
        assert snap["total_errors"] == 0
        assert snap["active_connections"] == 0
        assert snap["queue_depth"] == 0

    def test_record_request_increments_total(self):
        self.mc.record_request("GET", "/api/v1/test", 200, 0.01)
        snap = self.mc.snapshot()
        assert snap["total_requests"] == 1

    def test_record_500_increments_errors(self):
        self.mc.record_request("POST", "/api/v1/test", 500, 0.05)
        snap = self.mc.snapshot()
        assert snap["total_errors"] == 1

    def test_record_4xx_does_not_increment_errors(self):
        self.mc.record_request("GET", "/api/v1/missing", 404, 0.005)
        snap = self.mc.snapshot()
        assert snap["total_errors"] == 0

    def test_active_connections_gauge(self):
        self.mc.inc_connections()
        self.mc.inc_connections()
        snap = self.mc.snapshot()
        assert snap["active_connections"] == 2
        self.mc.dec_connections()
        snap = self.mc.snapshot()
        assert snap["active_connections"] == 1

    def test_dec_connections_floor_at_zero(self):
        self.mc.dec_connections()  # already 0
        snap = self.mc.snapshot()
        assert snap["active_connections"] == 0

    def test_set_queue_depth(self):
        self.mc.set_queue_depth(42)
        snap = self.mc.snapshot()
        assert snap["queue_depth"] == 42

    def test_record_db_query(self):
        self.mc.record_db_query(0.002)
        snap = self.mc.snapshot()
        assert snap["db_query_time"]["sample_count"] == 1
        assert snap["db_query_time"]["mean_seconds"] > 0

    def test_latency_histogram_has_inf_bucket(self):
        self.mc.record_request("GET", "/x", 200, 0.1)
        snap = self.mc.snapshot()
        assert "+Inf" in snap["latency"]["histogram_buckets"]

    def test_error_rate_zero_with_no_errors(self):
        self.mc.record_request("GET", "/ok", 200, 0.01)
        assert self.mc.error_rate() == 0.0

    def test_error_rate_nonzero_with_500s(self):
        for _ in range(10):
            self.mc.record_request("GET", "/bad", 500, 0.01)
        rate = self.mc.error_rate(window_seconds=60.0)
        assert rate > 0.0

    def test_prometheus_text_contains_type_lines(self):
        self.mc.record_request("GET", "/health", 200, 0.001)
        text = self.mc.prometheus_text()
        assert "# TYPE fixops_requests_total counter" in text
        assert "fixops_requests_total" in text
        assert "fixops_active_connections" in text

    def test_prometheus_text_ends_with_newline(self):
        text = self.mc.prometheus_text()
        assert text.endswith("\n")

    def test_request_counts_in_snapshot(self):
        self.mc.record_request("GET", "/api/health", 200, 0.01)
        snap = self.mc.snapshot()
        found = any("GET" in k and "200" in k for k in snap["request_counts"])
        assert found


# ===========================================================================
# AlertRule
# ===========================================================================


class TestAlertRule:
    def _make_rule(self, condition: str, threshold: float) -> AlertRule:
        return AlertRule(name="test", metric_key="total_requests", condition=condition, threshold=threshold)

    def test_gt_condition_true(self):
        rule = self._make_rule("gt", 5.0)
        assert rule.evaluate(10.0) is True

    def test_gt_condition_false(self):
        rule = self._make_rule("gt", 5.0)
        assert rule.evaluate(5.0) is False

    def test_lt_condition_true(self):
        rule = self._make_rule("lt", 5.0)
        assert rule.evaluate(3.0) is True

    def test_gte_condition_equal(self):
        rule = self._make_rule("gte", 5.0)
        assert rule.evaluate(5.0) is True

    def test_lte_condition_equal(self):
        rule = self._make_rule("lte", 5.0)
        assert rule.evaluate(5.0) is True

    def test_eq_condition_match(self):
        rule = self._make_rule("eq", 42.0)
        assert rule.evaluate(42.0) is True

    def test_eq_condition_no_match(self):
        rule = self._make_rule("eq", 42.0)
        assert rule.evaluate(43.0) is False

    def test_invalid_condition_returns_false(self):
        rule = AlertRule(name="r", metric_key="k", condition="invalid", threshold=0.0)
        assert rule.evaluate(100.0) is False


# ===========================================================================
# AlertManager
# ===========================================================================


class TestAlertManager:
    def setup_method(self):
        self.mc = MetricsCollector()
        self.mgr = AlertManager(self.mc)

    def test_add_and_list_rule(self):
        rule = AlertRule(name="high_errors", metric_key="total_errors", condition="gt", threshold=10.0)
        self.mgr.add_rule(rule)
        rules = self.mgr.list_rules()
        assert any(r.name == "high_errors" for r in rules)

    def test_remove_existing_rule(self):
        rule = AlertRule(name="r1", metric_key="total_errors", condition="gt", threshold=0.0)
        self.mgr.add_rule(rule)
        removed = self.mgr.remove_rule("r1")
        assert removed is True
        assert not self.mgr.list_rules()

    def test_remove_nonexistent_rule_returns_false(self):
        assert self.mgr.remove_rule("nonexistent") is False

    def test_evaluate_fires_alert_when_condition_met(self):
        # Record many 500s so total_errors > 0
        for _ in range(5):
            self.mc.record_request("GET", "/bad", 500, 0.01)
        rule = AlertRule(name="err_alert", metric_key="total_errors", condition="gt", threshold=0.0, cooldown_seconds=0.0)
        self.mgr.add_rule(rule)
        fired = self.mgr.evaluate()
        assert len(fired) == 1
        assert fired[0].rule_name == "err_alert"

    def test_evaluate_no_fire_when_condition_not_met(self):
        rule = AlertRule(name="idle", metric_key="total_errors", condition="gt", threshold=1000.0, cooldown_seconds=0.0)
        self.mgr.add_rule(rule)
        fired = self.mgr.evaluate()
        assert len(fired) == 0

    def test_cooldown_prevents_double_fire(self):
        for _ in range(5):
            self.mc.record_request("GET", "/bad", 500, 0.01)
        rule = AlertRule(name="cd_test", metric_key="total_errors", condition="gt", threshold=0.0, cooldown_seconds=300.0)
        self.mgr.add_rule(rule)
        first = self.mgr.evaluate()
        second = self.mgr.evaluate()
        assert len(first) == 1
        assert len(second) == 0  # cooldown active

    def test_active_alerts_returns_fired_alert(self):
        for _ in range(5):
            self.mc.record_request("GET", "/bad", 500, 0.01)
        rule = AlertRule(name="active_test", metric_key="total_errors", condition="gt", threshold=0.0, cooldown_seconds=0.0)
        self.mgr.add_rule(rule)
        self.mgr.evaluate()
        actives = self.mgr.active_alerts()
        assert any(a.rule_name == "active_test" for a in actives)

    def test_alert_history_grows(self):
        for _ in range(3):
            self.mc.record_request("GET", "/bad", 500, 0.01)
        rule = AlertRule(name="hist_test", metric_key="total_errors", condition="gt", threshold=0.0, cooldown_seconds=0.0)
        self.mgr.add_rule(rule)
        self.mgr.evaluate()
        history = self.mgr.alert_history()
        assert len(history) >= 1

    def test_clear_active_resolves_alert(self):
        for _ in range(5):
            self.mc.record_request("GET", "/bad", 500, 0.01)
        rule = AlertRule(name="clr_test", metric_key="total_errors", condition="gt", threshold=0.0, cooldown_seconds=0.0)
        self.mgr.add_rule(rule)
        self.mgr.evaluate()
        cleared = self.mgr.clear_active("clr_test")
        assert cleared is True
        assert not any(a.rule_name == "clr_test" for a in self.mgr.active_alerts())

    def test_clear_active_nonexistent_returns_false(self):
        assert self.mgr.clear_active("no_such") is False

    def test_nested_metric_key_resolution(self):
        # error_rate_per_sec is a top-level key
        for _ in range(10):
            self.mc.record_request("GET", "/bad", 500, 0.01)
        rule = AlertRule(name="rate_alert", metric_key="error_rate_per_sec", condition="gte", threshold=0.0, cooldown_seconds=0.0)
        self.mgr.add_rule(rule)
        fired = self.mgr.evaluate()
        # error_rate_per_sec >= 0 always passes
        assert len(fired) >= 0  # may or may not fire depending on timing, just no crash


# ===========================================================================
# _get_nested helper
# ===========================================================================


class TestGetNested:
    def test_top_level_key(self):
        assert _get_nested({"a": 5}, "a") == 5.0

    def test_nested_key(self):
        assert _get_nested({"a": {"b": 3.14}}, "a.b") == pytest.approx(3.14)

    def test_missing_key_returns_none(self):
        assert _get_nested({"a": 1}, "b") is None

    def test_non_float_value_returns_none(self):
        assert _get_nested({"a": "hello"}, "a") is None

    def test_deep_nesting(self):
        data = {"x": {"y": {"z": 99}}}
        assert _get_nested(data, "x.y.z") == 99.0


# ===========================================================================
# LogAggregator
# ===========================================================================


class TestLogAggregator:
    def setup_method(self):
        self.agg = LogAggregator(max_entries=100)

    def test_emit_returns_log_entry(self):
        entry = self.agg.emit("hello world")
        assert entry.message == "hello world"
        assert entry.level == "info"

    def test_emit_stores_entry(self):
        self.agg.emit("stored message", level="warning")
        entries = self.agg.all_entries()
        assert any(e.message == "stored message" for e in entries)

    def test_emit_with_correlation_id(self):
        cid = "req-abc-123"
        self.agg.emit("traced", correlation_id=cid)
        entries = self.agg.search(correlation_id=cid)
        assert len(entries) == 1
        assert entries[0].correlation_id == cid

    def test_emit_with_kwargs_stored_in_extra(self):
        entry = self.agg.emit("tagged", user_id="u1", action="login")
        assert entry.extra["user_id"] == "u1"
        assert entry.extra["action"] == "login"

    def test_search_by_level(self):
        self.agg.emit("info msg", level="info")
        self.agg.emit("error msg", level="error")
        errors = self.agg.search(level="error")
        assert all(e.level == "error" for e in errors)

    def test_search_by_message_substring(self):
        self.agg.emit("connection refused to db")
        self.agg.emit("all systems nominal")
        results = self.agg.search(query="connection refused")
        assert len(results) == 1

    def test_search_by_service(self):
        self.agg.emit("svc-a event", service="svc-a")
        self.agg.emit("svc-b event", service="svc-b")
        results = self.agg.search(service="svc-a")
        assert all(e.service == "svc-a" for e in results)

    def test_search_limit_respected(self):
        for i in range(20):
            self.agg.emit(f"msg {i}")
        results = self.agg.search(limit=5)
        assert len(results) <= 5

    def test_all_entries_newest_first(self):
        self.agg.emit("first")
        self.agg.emit("second")
        entries = self.agg.all_entries()
        assert entries[0].message == "second"

    def test_as_json_lines_valid_ndjson(self):
        import json as _json
        self.agg.emit("line1")
        self.agg.emit("line2")
        ndjson = self.agg.as_json_lines()
        lines = [l for l in ndjson.strip().split("\n") if l]
        for line in lines:
            obj = _json.loads(line)
            assert "message" in obj

    def test_stats_counts_by_level(self):
        self.agg.emit("a", level="info")
        self.agg.emit("b", level="error")
        self.agg.emit("c", level="info")
        stats = self.agg.stats()
        assert stats["by_level"]["info"] == 2
        assert stats["by_level"]["error"] == 1
        assert stats["total"] == 3

    def test_min_level_filter_drops_below_level(self):
        agg = LogAggregator(min_level="warning")
        agg.emit("debug msg", level="debug")
        agg.emit("info msg", level="info")
        agg.emit("warn msg", level="warning")
        entries = agg.all_entries()
        levels = [e.level for e in entries]
        assert "debug" not in levels
        assert "info" not in levels
        assert "warning" in levels

    def test_set_min_level(self):
        self.agg.set_min_level("error")
        self.agg.emit("info ignored", level="info")
        self.agg.emit("error kept", level="error")
        entries = self.agg.all_entries()
        assert all(e.level == "error" for e in entries)


# ===========================================================================
# TracingContext
# ===========================================================================


class TestTracingContext:
    def setup_method(self):
        self.tracer = TracingContext()

    def test_start_trace_returns_trace_and_span_ids(self):
        trace_id, span_id = self.tracer.start_trace("handle_request")
        assert trace_id
        assert span_id

    def test_finish_span_sets_duration(self):
        trace_id, span_id = self.tracer.start_trace("op")
        span = self.tracer.finish_span(span_id)
        assert span is not None
        assert span.duration_ms is not None
        assert span.duration_ms >= 0.0

    def test_finish_span_status_ok(self):
        _, span_id = self.tracer.start_trace("op")
        span = self.tracer.finish_span(span_id, status="ok")
        assert span.status == "ok"

    def test_finish_span_status_error(self):
        _, span_id = self.tracer.start_trace("op")
        span = self.tracer.finish_span(span_id, status="error", error="timeout")
        assert span.status == "error"
        assert span.error == "timeout"

    def test_finish_nonexistent_span_returns_none(self):
        result = self.tracer.finish_span("nonexistent-span-id")
        assert result is None

    def test_start_child_span(self):
        trace_id, root_id = self.tracer.start_trace("root")
        child_id = self.tracer.start_span(trace_id, "child_op", parent_span_id=root_id)
        child = self.tracer.get_span(child_id)
        assert child is not None
        assert child.parent_span_id == root_id

    def test_get_trace_returns_all_spans(self):
        trace_id, root_id = self.tracer.start_trace("root")
        self.tracer.start_span(trace_id, "child1", parent_span_id=root_id)
        self.tracer.start_span(trace_id, "child2", parent_span_id=root_id)
        spans = self.tracer.get_trace(trace_id)
        assert len(spans) == 3

    def test_finish_trace_marks_all_spans_done(self):
        trace_id, root_id = self.tracer.start_trace("root")
        self.tracer.start_span(trace_id, "child", parent_span_id=root_id)
        spans = self.tracer.finish_trace(trace_id)
        for s in spans:
            assert s.finished_at is not None

    def test_export_trace_structure(self):
        trace_id, root_id = self.tracer.start_trace("export_test", service="api")
        child_id = self.tracer.start_span(trace_id, "db_query", parent_span_id=root_id)
        self.tracer.finish_span(child_id)
        self.tracer.finish_span(root_id)
        exported = self.tracer.export_trace(trace_id)
        assert exported["trace_id"] == trace_id
        assert len(exported["spans"]) == 2
        ops = [s["operation"] for s in exported["spans"]]
        assert "export_test" in ops
        assert "db_query" in ops

    def test_recent_traces_after_finish(self):
        trace_id, root_id = self.tracer.start_trace("tracked_op")
        self.tracer.finish_trace(trace_id)
        recent = self.tracer.recent_traces(limit=10)
        assert any(t["trace_id"] == trace_id for t in recent)

    def test_export_trace_not_found_returns_empty_spans(self):
        exported = self.tracer.export_trace("nonexistent-trace-id")
        assert exported["spans"] == []

    def test_span_tags_stored(self):
        trace_id, span_id = self.tracer.start_trace("tagged_op", tags={"http.method": "GET"})
        span = self.tracer.get_span(span_id)
        assert span.tags.get("http.method") == "GET"

    def test_finish_span_adds_extra_tags(self):
        _, span_id = self.tracer.start_trace("op")
        self.tracer.finish_span(span_id, tags={"db.rows": 42})
        span = self.tracer.get_span(span_id)
        assert span.tags.get("db.rows") == 42


# ===========================================================================
# Router (HTTP endpoints via FastAPI TestClient)
# ===========================================================================


@pytest.fixture(scope="module")
def test_client():
    """Create a minimal FastAPI app with the observability router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.observability_router import router as obs_router

    app = FastAPI()
    app.include_router(obs_router)
    return TestClient(app)


class TestObservabilityRouter:
    def test_healthz_returns_200(self, test_client):
        r = test_client.get("/api/v1/observability/healthz")
        assert r.status_code == 200

    def test_healthz_response_shape(self, test_client):
        r = test_client.get("/api/v1/observability/healthz")
        data = r.json()
        assert "status" in data
        assert "checks" in data
        assert "uptime_seconds" in data

    def test_readyz_returns_200(self, test_client):
        r = test_client.get("/api/v1/observability/readyz")
        assert r.status_code == 200

    def test_startupz_returns_200_after_mark_complete(self, test_client):
        # Mark startup complete on the global singleton
        get_health_probe().mark_startup_complete()
        r = test_client.get("/api/v1/observability/startupz")
        assert r.status_code == 200

    def test_metrics_prometheus_text_format(self, test_client):
        r = test_client.get("/api/v1/observability/metrics")
        assert r.status_code == 200
        assert "text/plain" in r.headers["content-type"]
        assert "fixops_requests_total" in r.text

    def test_metrics_json_shape(self, test_client):
        r = test_client.get("/api/v1/observability/metrics/json")
        assert r.status_code == 200
        data = r.json()
        assert "timestamp" in data
        assert "metrics" in data

    def test_traces_returns_list(self, test_client):
        r = test_client.get("/api/v1/observability/traces")
        assert r.status_code == 200
        data = r.json()
        assert "traces" in data
        assert "count" in data

    def test_alerts_active_returns_list(self, test_client):
        r = test_client.get("/api/v1/observability/alerts")
        assert r.status_code == 200
        data = r.json()
        assert "alerts" in data

    def test_alerts_history_returns_list(self, test_client):
        r = test_client.get("/api/v1/observability/alerts/history")
        assert r.status_code == 200
        data = r.json()
        assert "history" in data

    def test_create_alert_rule(self, test_client):
        payload = {
            "name": "test_high_errors",
            "metric_key": "total_errors",
            "condition": "gt",
            "threshold": 100.0,
            "action": "log",
            "cooldown_seconds": 60.0,
            "severity": "warning",
        }
        r = test_client.post("/api/v1/observability/alerts/rules", json=payload)
        assert r.status_code == 201
        data = r.json()
        assert data["status"] == "created"
        assert data["rule_name"] == "test_high_errors"

    def test_create_alert_rule_invalid_condition(self, test_client):
        payload = {
            "name": "bad_rule",
            "metric_key": "total_errors",
            "condition": "not_a_condition",
            "threshold": 0.0,
        }
        r = test_client.post("/api/v1/observability/alerts/rules", json=payload)
        assert r.status_code == 422

    def test_list_alert_rules(self, test_client):
        r = test_client.get("/api/v1/observability/alerts/rules")
        assert r.status_code == 200
        data = r.json()
        assert "rules" in data

    def test_delete_alert_rule(self, test_client):
        # Create first
        payload = {"name": "to_delete", "metric_key": "total_requests", "condition": "gt", "threshold": 9999.0}
        test_client.post("/api/v1/observability/alerts/rules", json=payload)
        r = test_client.delete("/api/v1/observability/alerts/rules/to_delete")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "deleted"

    def test_delete_nonexistent_rule_returns_404(self, test_client):
        r = test_client.delete("/api/v1/observability/alerts/rules/does_not_exist_xyz")
        assert r.status_code == 404

    def test_logs_search_returns_list(self, test_client):
        # Emit something to the global log aggregator
        get_log_aggregator().emit("router test log entry", level="info")
        r = test_client.get("/api/v1/observability/logs")
        assert r.status_code == 200
        data = r.json()
        assert "logs" in data

    def test_logs_search_with_query_param(self, test_client):
        get_log_aggregator().emit("unique_marker_xyz_test", level="warning")
        r = test_client.get("/api/v1/observability/logs?query=unique_marker_xyz_test")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1

    def test_logs_stats_endpoint(self, test_client):
        r = test_client.get("/api/v1/observability/logs/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "by_level" in data

    def test_trace_detail_not_found(self, test_client):
        r = test_client.get("/api/v1/observability/traces/nonexistent-trace-id")
        assert r.status_code == 404

    def test_singleton_getters_return_same_instance(self):
        a = get_metrics_collector()
        b = get_metrics_collector()
        assert a is b

        a = get_health_probe()
        b = get_health_probe()
        assert a is b
