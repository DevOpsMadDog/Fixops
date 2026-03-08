"""Comprehensive tests for core.api_learning_store — traffic recording, ML, threats."""
import time
import uuid

import pytest

from core.api_learning_store import (
    AnomalyResult,
    APILearningStore,
    ModelInfo,
    ModelStatus,
    PredictionType,
    ThreatAssessment,
    TrafficRecord,
)


@pytest.fixture
def store(tmp_path):
    db_path = tmp_path / "test_api_learning.db"
    return APILearningStore(db_path=db_path)


def _make_record(**overrides) -> TrafficRecord:
    defaults = dict(
        method="GET",
        path="/api/v1/findings",
        status_code=200,
        duration_ms=45.2,
        request_size=128,
        response_size=4096,
        client_ip="10.0.0.1",
        user_agent="TestClient/1.0",
        correlation_id=str(uuid.uuid4()),
        query_params="limit=10",
        error_type="",
        timestamp=time.time(),
    )
    defaults.update(overrides)
    return TrafficRecord(**defaults)


# ─── Data Classes ───────────────────────────────────────────────────────


class TestDataClasses:
    def test_traffic_record_defaults(self):
        r = TrafficRecord(method="POST", path="/api/v1/scan", status_code=201, duration_ms=100.0)
        assert r.request_size == 0
        assert r.response_size == 0
        assert r.client_ip == ""
        assert r.timestamp > 0

    def test_traffic_record_all_fields(self):
        r = _make_record(method="POST", status_code=201)
        assert r.method == "POST"
        assert r.status_code == 201
        assert r.duration_ms == 45.2

    def test_model_info_defaults(self):
        mi = ModelInfo(name="anomaly_detector", type="isolation_forest")
        assert mi.status == ModelStatus.UNTRAINED
        assert mi.samples_trained == 0
        assert mi.accuracy == 0.0

    def test_anomaly_result(self):
        ar = AnomalyResult(is_anomaly=True, score=-0.8, confidence=0.95, reason="unusual pattern")
        assert ar.is_anomaly is True
        assert ar.score == -0.8
        assert ar.confidence == 0.95

    def test_threat_assessment(self):
        ta = ThreatAssessment(
            threat_score=0.85,
            risk_level="high",
            indicators=["rate_burst", "sql_injection"],
            recommended_action="block",
        )
        assert ta.threat_score == 0.85
        assert len(ta.indicators) == 2

    def test_model_status_enum(self):
        assert ModelStatus.UNTRAINED.value == "untrained"
        assert ModelStatus.TRAINING.value == "training"
        assert ModelStatus.READY.value == "ready"
        assert ModelStatus.STALE.value == "stale"

    def test_prediction_type_enum(self):
        assert PredictionType.ANOMALY.value == "anomaly"
        assert PredictionType.RESPONSE_TIME.value == "response_time"
        assert PredictionType.THREAT_SCORE.value == "threat_score"
        assert PredictionType.USAGE_PATTERN.value == "usage_pattern"
        assert PredictionType.ERROR_PROBABILITY.value == "error_probability"


# ─── Store Initialization ──────────────────────────────────────────────


class TestStoreInit:
    def test_store_creates_db(self, tmp_path):
        db_path = tmp_path / "new_store.db"
        APILearningStore(db_path=db_path)
        assert db_path.exists()

    def test_store_creates_parent_dirs(self, tmp_path):
        db_path = tmp_path / "nested" / "dir" / "store.db"
        APILearningStore(db_path=db_path)
        assert db_path.exists()


# ─── Traffic Recording ──────────────────────────────────────────────────


class TestTrafficRecording:
    def test_record_traffic(self, store):
        r = _make_record()
        store.record(r)

    def test_record_multiple(self, store):
        for i in range(10):
            store.record(_make_record(path=f"/api/v1/test/{i}"))
        store.flush()
        stats = store.get_stats()
        assert stats["total_requests"] >= 10

    def test_record_error_traffic(self, store):
        store.record(_make_record(status_code=500, error_type="InternalServerError"))
        store.record(_make_record(status_code=404, error_type="NotFound"))
        store.flush()
        stats = store.get_stats()
        assert stats["total_requests"] >= 2

    def test_record_various_methods(self, store):
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            store.record(_make_record(method=method))

    def test_flush(self, store):
        for _ in range(5):
            store.record(_make_record())
        store.flush()
        stats = store.get_stats()
        assert stats["total_requests"] == 5

    def test_flush_empty(self, store):
        store.flush()  # Should not raise

    def test_get_stats_empty(self, store):
        stats = store.get_stats()
        assert "total_requests" in stats
        assert stats["total_requests"] == 0

    def test_get_stats_with_data(self, store):
        for _ in range(5):
            store.record(_make_record())
        store.flush()
        stats = store.get_stats()
        assert stats["total_requests"] == 5
        assert "avg_duration_ms" in stats
        assert "total_errors" in stats
        assert "total_anomalies" in stats

    def test_get_stats_with_errors(self, store):
        for _ in range(3):
            store.record(_make_record(status_code=200))
        for _ in range(2):
            store.record(_make_record(status_code=500))
        store.flush()
        stats = store.get_stats()
        assert stats["total_errors"] == 2


# ─── Threat Assessment ──────────────────────────────────────────────────


class TestThreatAssessment:
    def test_assess_normal_request(self, store):
        result = store.assess_threat(
            method="GET",
            path="/api/v1/findings",
            status_code=200,
            duration_ms=50.0,
        )
        assert isinstance(result, ThreatAssessment)
        assert result.risk_level == "low"
        assert result.threat_score < 0.2

    def test_assess_auth_failure(self, store):
        result = store.assess_threat(
            method="POST",
            path="/api/v1/auth/login",
            status_code=401,
            client_ip="10.0.0.1",
        )
        assert result.threat_score > 0
        assert len(result.indicators) > 0

    def test_assess_404_enumeration(self, store):
        result = store.assess_threat(
            method="GET",
            path="/api/v1/secrets",
            status_code=404,
        )
        assert "404" in result.indicators[0] or result.threat_score > 0

    def test_assess_suspicious_user_agent(self, store):
        result = store.assess_threat(
            method="GET",
            path="/api/v1/findings",
            user_agent="sqlmap/1.7.2",
        )
        assert result.threat_score >= 0.4
        assert result.risk_level in ("high", "critical")

    def test_assess_sensitive_path_write(self, store):
        result = store.assess_threat(
            method="DELETE",
            path="/api/v1/admin/users",
        )
        assert result.threat_score > 0

    def test_assess_multiple_indicators(self, store):
        result = store.assess_threat(
            method="DELETE",
            path="/api/v1/users/admin",
            status_code=403,
            user_agent="nikto/2.1",
        )
        assert result.threat_score >= 0.4
        assert len(result.indicators) >= 2

    def test_threat_levels(self, store):
        # Low
        low = store.assess_threat(method="GET", path="/api/v1/health")
        assert low.risk_level == "low"

        # Critical
        critical = store.assess_threat(
            method="DELETE",
            path="/api/v1/admin/wipe",
            status_code=403,
            user_agent="burp/2024",
        )
        assert critical.risk_level in ("high", "critical")


# ─── Anomaly Detection ─────────────────────────────────────────────────


class TestAnomalyDetection:
    def test_detect_anomaly_no_model(self, store):
        result = store.detect_anomaly(
            method="GET",
            path="/api/v1/test",
            status_code=200,
            duration_ms=50.0,
        )
        assert isinstance(result, AnomalyResult)

    def test_detect_anomaly_insufficient_data(self, store):
        result = store.detect_anomaly(
            method="GET",
            path="/api/v1/new-endpoint",
            status_code=200,
            duration_ms=50.0,
        )
        assert result.is_anomaly is False
        assert result.confidence <= 0.2

    def test_detect_anomaly_with_stats(self, store):
        # Record enough data to have path stats
        for _ in range(10):
            store.record(_make_record(path="/api/v1/stable", duration_ms=50.0))
        # Now test with normal duration
        result = store.detect_anomaly(
            method="GET",
            path="/api/v1/stable",
            status_code=200,
            duration_ms=55.0,
        )
        assert isinstance(result, AnomalyResult)

    def test_detect_anomaly_extreme_duration(self, store):
        # Record baseline
        for _ in range(10):
            store.record(_make_record(path="/api/v1/stable", duration_ms=50.0))
        # Test with extreme duration
        result = store.detect_anomaly(
            method="GET",
            path="/api/v1/stable",
            status_code=200,
            duration_ms=50000.0,  # 1000x normal
        )
        # Should detect anomaly with statistical method
        assert result.is_anomaly is True


# ─── Response Time Prediction ───────────────────────────────────────────


class TestResponseTimePrediction:
    def test_predict_no_model(self, store):
        result = store.predict_response_time(
            method="GET",
            path="/api/v1/test",
        )
        assert "predicted_ms" in result
        assert result["predicted_ms"] > 0
        assert "method" in result

    def test_predict_with_history(self, store):
        for _ in range(10):
            store.record(_make_record(path="/api/v1/stable", duration_ms=100.0))
        result = store.predict_response_time(
            method="GET",
            path="/api/v1/stable",
        )
        assert result["predicted_ms"] > 0

    def test_predict_with_request_size(self, store):
        result = store.predict_response_time(
            method="POST",
            path="/api/v1/upload",
            request_size=1_000_000,
        )
        assert result["predicted_ms"] > 0


# ─── Model Management ──────────────────────────────────────────────────


class TestModelManagement:
    def test_model_info_initial(self, store):
        # Access internal model info
        assert "anomaly_detector" in store._model_info
        assert "response_predictor" in store._model_info
        assert store._model_info["anomaly_detector"].status == ModelStatus.UNTRAINED

    def test_train_anomaly_insufficient_data(self, store):
        result = store.train_anomaly_detector()
        assert result.status == ModelStatus.UNTRAINED

    def test_train_response_insufficient_data(self, store):
        result = store.train_response_predictor()
        assert result.status == ModelStatus.UNTRAINED

    def test_train_threat_insufficient_data(self, store):
        result = store.train_threat_classifier()
        assert result.status == ModelStatus.UNTRAINED

    def test_train_error_insufficient_data(self, store):
        result = store.train_error_predictor()
        assert result.status == ModelStatus.UNTRAINED

    def test_train_all_insufficient_data(self, store):
        results = store.train_all_models()
        assert len(results) == 4
        for name, info in results.items():
            assert info.status == ModelStatus.UNTRAINED


# ─── Encoding Helpers ───────────────────────────────────────────────────


class TestEncodingHelpers:
    def test_encode_method(self, store):
        assert store._encode_method("GET") == 0
        assert store._encode_method("POST") == 1
        assert store._encode_method("DELETE") == 4
        assert store._encode_method("UNKNOWN") == 7

    def test_encode_path(self, store):
        p1 = store._encode_path("/api/v1/findings")
        p2 = store._encode_path("/api/v1/scan")
        assert isinstance(p1, int)
        assert isinstance(p2, int)
        assert p1 != p2  # Different paths should hash differently

    def test_encode_path_strips_query(self, store):
        p1 = store._encode_path("/api/v1/test?limit=10")
        p2 = store._encode_path("/api/v1/test")
        assert p1 == p2


# ─── Threat Indicators ─────────────────────────────────────────────────


class TestThreatIndicators:
    def test_record_threat(self, store):
        store.record_threat(
            indicator_type="brute_force",
            description="Multiple failed login attempts",
            severity="high",
            source_ip="192.168.1.1",
            target_path="/api/v1/auth/login",
        )
        # Should not raise

    def test_get_threat_indicators_empty(self, store):
        indicators = store.get_threat_indicators()
        assert isinstance(indicators, list)
        assert len(indicators) == 0

    def test_get_threat_indicators_with_data(self, store):
        store.record_threat(
            indicator_type="scanning",
            description="Port scan detected",
            severity="medium",
            source_ip="10.0.0.5",
        )
        indicators = store.get_threat_indicators()
        assert len(indicators) >= 1


# ─── API Health ─────────────────────────────────────────────────────────


class TestAPIHealth:
    def test_get_api_health_empty(self, store):
        health = store.get_api_health()
        assert isinstance(health, dict)

    def test_get_api_health_with_data(self, store):
        for _ in range(10):
            store.record(_make_record(status_code=200, duration_ms=30.0))
        for _ in range(1):
            store.record(_make_record(status_code=500, duration_ms=5000.0))
        store.flush()
        health = store.get_api_health()
        assert isinstance(health, dict)


# ─── Recent Anomalies ──────────────────────────────────────────────────


class TestRecentAnomalies:
    def test_get_recent_anomalies_empty(self, store):
        anomalies = store.get_recent_anomalies()
        assert isinstance(anomalies, list)
        assert len(anomalies) == 0
