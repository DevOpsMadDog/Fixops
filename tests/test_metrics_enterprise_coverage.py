"""Tests for enterprise Prometheus metrics — FixOpsMetrics facade."""

from core.services.enterprise.metrics import (
    FixOpsMetrics,
    HTTP_REQUESTS,
    HTTP_LATENCY,
    HTTP_ERROR_RATIO,
    HTTP_INFLIGHT,
    HOT_PATH_LATENCY,
    RATE_LIMIT_TRIGGER,
    SIGNING_KEY_AGE,
    SIGNING_KEY_HEALTH,
    ENGINE_DECISIONS,
    UPLOADS_COMPLETED,
    DECISION_LATENCY,
    DECISION_CONFIDENCE,
    DECISION_ERRORS,
    EVIDENCE_REQUESTS,
    EVIDENCE_LATENCY,
    POLICY_EVALUATIONS,
    POLICY_LATENCY,
    POLICY_BLOCK_RATIO,
    _registry,
)


class TestMetricsConstants:
    """Verify all Prometheus metrics are properly defined."""

    def test_http_requests_counter(self):
        assert HTTP_REQUESTS is not None
        assert "fixops_http_requests" in HTTP_REQUESTS._name

    def test_http_latency_histogram(self):
        assert HTTP_LATENCY is not None
        assert HTTP_LATENCY._name == "fixops_http_request_seconds"

    def test_http_error_ratio_gauge(self):
        assert HTTP_ERROR_RATIO is not None

    def test_http_inflight_gauge(self):
        assert HTTP_INFLIGHT is not None

    def test_hot_path_latency_gauge(self):
        assert HOT_PATH_LATENCY is not None

    def test_rate_limit_trigger_counter(self):
        assert RATE_LIMIT_TRIGGER is not None

    def test_signing_key_metrics(self):
        assert SIGNING_KEY_AGE is not None
        assert SIGNING_KEY_HEALTH is not None

    def test_engine_decisions_counter(self):
        assert ENGINE_DECISIONS is not None

    def test_uploads_completed_counter(self):
        assert UPLOADS_COMPLETED is not None

    def test_decision_metrics(self):
        assert DECISION_LATENCY is not None
        assert DECISION_CONFIDENCE is not None
        assert DECISION_ERRORS is not None

    def test_evidence_metrics(self):
        assert EVIDENCE_REQUESTS is not None
        assert EVIDENCE_LATENCY is not None

    def test_policy_metrics(self):
        assert POLICY_EVALUATIONS is not None
        assert POLICY_LATENCY is not None
        assert POLICY_BLOCK_RATIO is not None

    def test_registry_is_not_none(self):
        assert _registry is not None


class TestFixOpsMetrics:
    def test_get_metrics_returns_bytes(self):
        result = FixOpsMetrics.get_metrics()
        assert isinstance(result, bytes)

    def test_record_request(self):
        FixOpsMetrics.record_request(
            endpoint="/api/v1/test",
            method="GET",
            status=200,
            duration=0.05,
        )
        # Should not raise

    def test_record_request_error(self):
        FixOpsMetrics.record_request(
            endpoint="/api/v1/error",
            method="POST",
            status=500,
            duration=1.0,
        )

    def test_request_started(self):
        FixOpsMetrics.request_started("/api/v1/brain")
        # Inflight should increase

    def test_request_finished(self):
        FixOpsMetrics.request_started("/api/v1/brain")
        FixOpsMetrics.request_finished("/api/v1/brain")
        # Inflight should decrease

    def test_request_finished_no_negative(self):
        FixOpsMetrics.request_finished("/api/v1/nonexistent")
        # Should not go negative

    def test_hot_path_endpoint_recorded(self):
        FixOpsMetrics.record_request(
            endpoint="/api/v1/decisions/make-decision",
            method="POST",
            status=200,
            duration=0.001,
        )
        # Hot path latency should be recorded

    def test_hot_path_prefixes_defined(self):
        assert "/api/v1/decisions/make-decision" in FixOpsMetrics._HOT_PATH_PREFIXES
        assert "/api/v1/policy/evaluate" in FixOpsMetrics._HOT_PATH_PREFIXES
        assert "/api/v1/decisions/evidence" in FixOpsMetrics._HOT_PATH_PREFIXES

    def test_metrics_output_contains_fixops(self):
        FixOpsMetrics.record_request("/api/v1/test", "GET", 200, 0.01)
        output = FixOpsMetrics.get_metrics()
        assert b"fixops" in output

    def test_multiple_requests_different_endpoints(self):
        for i in range(5):
            FixOpsMetrics.record_request(
                endpoint=f"/api/v1/endpoint-{i}",
                method="GET",
                status=200,
                duration=0.01 * i,
            )

    def test_mixed_status_codes(self):
        for status in [200, 201, 400, 403, 404, 500, 503]:
            FixOpsMetrics.record_request(
                endpoint="/api/v1/mixed",
                method="GET",
                status=status,
                duration=0.05,
            )
