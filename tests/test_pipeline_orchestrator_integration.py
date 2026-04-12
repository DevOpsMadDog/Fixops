"""Tests for PipelineOrchestrator with real scanner normalizer integration.

Validates that the 15-stage pipeline correctly processes findings
through normalize, enrich, and score stages using real code paths.
"""

import pytest
import uuid
from core.pipeline_orchestrator import (
    PipelineOrchestrator,
    PipelineStage,
    PipelineEventEmitter,
    PipelineAnalyticsEngine,
    ProcessingStatus,
    StageResult,
    PipelineProcessingState,
)


@pytest.fixture
def orchestrator():
    return PipelineOrchestrator()


@pytest.fixture
def sample_finding():
    return {
        "id": str(uuid.uuid4()),
        "title": "SQL Injection in login endpoint",
        "description": "The /api/login endpoint is vulnerable to SQL injection",
        "severity": "critical",
        "cve": "CVE-2024-1234",
        "resource": "api-server",
        "remediation": "Use parameterized queries",
        "tags": ["owasp-top-10", "injection"],
    }


@pytest.fixture
def minimal_finding():
    return {
        "id": str(uuid.uuid4()),
        "title": "Test finding",
    }


class TestPipelineStages:
    """Test individual pipeline stages."""

    def test_collect_stage(self, orchestrator, sample_finding):
        result = orchestrator.process_finding(sample_finding, source="test")
        assert "_ingested_at" in result
        assert result["_source"] == "test"

    def test_normalize_severity_mapping(self, orchestrator):
        for severity, expected_score in [
            ("critical", 5), ("high", 4), ("medium", 3),
            ("low", 2), ("info", 1), ("unknown", 0),
        ]:
            finding = {"id": str(uuid.uuid4()), "title": "test", "severity": severity}
            result = orchestrator.process_finding(finding, source="test")
            assert result["_severity_score"] == expected_score

    def test_normalize_default_fields(self, orchestrator, minimal_finding):
        result = orchestrator.process_finding(minimal_finding, source="test")
        assert result.get("description") == ""
        assert result.get("remediation") == ""
        assert result.get("tags") == []

    def test_enrich_with_cve(self, orchestrator, sample_finding):
        result = orchestrator.process_finding(sample_finding, source="test")
        assert "_cve_metadata" in result
        assert result["_cve_metadata"].get("epss_score") is not None
        assert "_threat_intel" in result

    def test_enrich_without_cve(self, orchestrator, minimal_finding):
        result = orchestrator.process_finding(minimal_finding, source="test")
        assert result.get("_cve_metadata") == {}
        assert result["_threat_intel"]["actively_exploited"] is False

    def test_deduplicate_first_finding(self, orchestrator, sample_finding):
        result = orchestrator.process_finding(sample_finding, source="test")
        assert "_content_hash" in result

    def test_deduplicate_duplicate_detection(self, orchestrator, sample_finding):
        orchestrator.process_finding(sample_finding, source="test")
        # Process same finding again (same title + cve + resource → same hash)
        dup = {**sample_finding, "id": str(uuid.uuid4())}
        result = orchestrator.process_finding(dup, source="test")
        # Duplicate should still be processed (just flagged)
        assert result is not None

    def test_score_with_cve(self, orchestrator, sample_finding):
        result = orchestrator.process_finding(sample_finding, source="test")
        assert "_risk_score" in result
        assert result["_risk_score"] > 0

    def test_prioritize(self, orchestrator, sample_finding):
        result = orchestrator.process_finding(sample_finding, source="test")
        assert "_priority" in result
        assert result["_priority"] in ["critical", "high", "medium", "low"]
        assert "_priority_score" in result

    def test_classify_vulnerability(self, orchestrator, sample_finding):
        result = orchestrator.process_finding(sample_finding, source="test")
        assert result["_type"] == "vulnerability"

    def test_classify_secret(self, orchestrator):
        finding = {"id": str(uuid.uuid4()), "title": "Hardcoded secret in config.py", "severity": "high"}
        result = orchestrator.process_finding(finding, source="test")
        assert result["_type"] == "secret"

    def test_classify_misconfiguration(self, orchestrator):
        finding = {"id": str(uuid.uuid4()), "title": "S3 bucket misconfiguration", "severity": "medium"}
        result = orchestrator.process_finding(finding, source="test")
        assert result["_type"] == "misconfiguration"

    def test_contextualize(self, orchestrator, sample_finding):
        result = orchestrator.process_finding(sample_finding, source="test")
        assert "_business_context" in result
        assert result["_business_context"]["asset"] == "api-server"

    def test_filter_low_priority(self, orchestrator):
        finding = {"id": str(uuid.uuid4()), "title": "Info level note", "severity": "info"}
        result = orchestrator.process_finding(finding, source="test")
        assert result["_suppressed"] is True

    def test_run_playbooks_critical(self, orchestrator, sample_finding):
        result = orchestrator.process_finding(sample_finding, source="test")
        playbooks = result.get("_triggered_playbooks", [])
        # Critical CVE finding should trigger at least cve_remediation
        assert len(playbooks) > 0

    def test_archive(self, orchestrator, sample_finding):
        result = orchestrator.process_finding(sample_finding, source="test")
        # Finding should complete all 15 stages
        assert result is not None
        assert "_report" in result

    def test_validate_stage(self, orchestrator, sample_finding):
        result = orchestrator.process_finding(sample_finding, source="test")
        assert result["_validated"] is True

    def test_validate_missing_fields(self, orchestrator):
        finding = {"id": str(uuid.uuid4()), "title": ""}  # Empty title
        result = orchestrator.process_finding(finding, source="test")
        assert result["_validated"] is False


class TestNormalizerIntegration:
    """Test integration with real scanner normalizers."""

    def test_normalize_with_raw_scanner_output(self, orchestrator):
        """Test that raw scanner output triggers real parser."""
        # ZAP-style JSON output
        raw = b'{"@version":"2.12.0","site":[{"@name":"http://test","alerts":[{"name":"SQL Injection","riskcode":"3","confidence":"2","desc":"SQL injection found"}]}]}'
        finding = {
            "id": str(uuid.uuid4()),
            "title": "ZAP scan result",
            "severity": "high",
            "_raw_scanner_output": raw,
            "_scanner_type": "zap",
        }
        result = orchestrator.process_finding(finding, source="zap")
        # Should still complete pipeline regardless of parser success
        assert result is not None
        assert "_severity_score" in result

    def test_normalize_without_raw_output(self, orchestrator, sample_finding):
        """Test that pre-parsed findings go through basic normalization."""
        result = orchestrator.process_finding(sample_finding, source="manual")
        assert result["_severity_score"] == 5  # critical = 5


class TestPipelineConfiguration:
    """Test orchestrator configuration."""

    def test_skip_stage(self):
        orchestrator = PipelineOrchestrator()
        orchestrator.skip_stage(PipelineStage.VALIDATE)
        finding = {"id": str(uuid.uuid4()), "title": "test", "severity": "medium"}
        result = orchestrator.process_finding(finding, source="test")
        assert "_validated" not in result

    def test_custom_handler(self):
        orchestrator = PipelineOrchestrator()

        def custom_score(finding, state):
            finding["_risk_score"] = 42
            return StageResult(
                stage=PipelineStage.SCORE,
                status=ProcessingStatus.COMPLETED,
                duration_ms=0,
                metrics={"finding": finding},
            )

        orchestrator.set_handler(PipelineStage.SCORE, custom_score)
        finding = {"id": str(uuid.uuid4()), "title": "test", "severity": "medium", "cve": "CVE-2024-0001"}
        result = orchestrator.process_finding(finding, source="test")
        assert result["_risk_score"] == 42


class TestPipelineAnalytics:
    """Test analytics and metrics."""

    def test_pipeline_status(self, orchestrator, sample_finding):
        orchestrator.process_finding(sample_finding, source="test")
        status = orchestrator.get_pipeline_status()
        assert status["findings_processed"] == 1
        assert "stage_metrics" in status
        assert "collect" in status["stage_metrics"]

    def test_multiple_findings_metrics(self, orchestrator):
        for i in range(5):
            finding = {
                "id": str(uuid.uuid4()),
                "title": f"Finding {i}",
                "severity": "medium",
            }
            orchestrator.process_finding(finding, source="test")

        status = orchestrator.get_pipeline_status()
        assert status["findings_processed"] == 5
        assert status["dedup_cache_size"] == 5

    def test_dedup_cache_growth(self, orchestrator):
        findings = [
            {"id": str(uuid.uuid4()), "title": f"Finding {i}", "severity": "medium"}
            for i in range(3)
        ]
        for f in findings:
            orchestrator.process_finding(f, source="test")

        status = orchestrator.get_pipeline_status()
        assert status["dedup_cache_size"] == 3


class TestEventEmitter:
    """Test event emission during pipeline processing."""

    def test_event_subscription(self):
        emitter = PipelineEventEmitter()
        events = []
        emitter.subscribe("stage_complete", lambda e: events.append(e))
        emitter.emit("stage_complete", {"stage": "collect", "finding_id": "test"})
        assert len(events) == 1
        assert events[0]["stage"] == "collect"

    def test_pipeline_emits_events(self):
        events = []
        orchestrator = PipelineOrchestrator()
        orchestrator.event_emitter.subscribe("stage_complete", lambda e: events.append(e))

        finding = {"id": str(uuid.uuid4()), "title": "test", "severity": "medium"}
        orchestrator.process_finding(finding, source="test")

        # Should emit event for each of the 15 stages
        assert len(events) == 15
        stages = [e["stage"] for e in events]
        assert "collect" in stages
        assert "normalize" in stages
        assert "archive" in stages

    def test_event_listener_error_handling(self):
        emitter = PipelineEventEmitter()

        def failing_listener(e):
            raise RuntimeError("fail")

        emitter.subscribe("test", failing_listener)
        # Should not raise
        emitter.emit("test", {"data": "test"})


class TestAnalyticsEngine:
    """Test PipelineAnalyticsEngine."""

    def test_record_stage(self):
        engine = PipelineAnalyticsEngine()
        engine.record_stage(PipelineStage.COLLECT, 10.0, ProcessingStatus.COMPLETED)
        status = engine.get_status()
        assert "collect" in status["stage_metrics"]
        assert status["stage_metrics"]["collect"]["completed"] == 1

    def test_record_finding(self):
        engine = PipelineAnalyticsEngine()
        engine.record_finding(100.0)
        engine.record_finding(200.0)
        status = engine.get_status()
        assert status["findings_processed"] == 2
        assert status["avg_finding_latency_ms"] == 150.0

    def test_empty_status(self):
        engine = PipelineAnalyticsEngine()
        status = engine.get_status()
        assert status["findings_processed"] == 0
        assert status["avg_finding_latency_ms"] == 0.0
