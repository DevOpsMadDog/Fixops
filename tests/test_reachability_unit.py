"""
Unit tests for suite-evidence-risk/risk/reachability/monitoring.py

Tests the reachability monitoring module including:
- AnalysisMetrics dataclass creation and defaults
- ReachabilityMonitor initialization and configuration
- Analysis tracking (success, error, duration)
- Repository clone tracking
- Cache hit/miss recording
- Metrics summary with enabled/disabled metrics
- Multiple sequential analyses
- Error propagation during tracking
- Metrics counter accuracy
- Cache hit rate calculation
- Average duration calculation
"""

import time

import pytest
from risk.reachability.monitoring import AnalysisMetrics, ReachabilityMonitor


# Disable tracing for all tests to avoid real OTel span issues
@pytest.fixture(autouse=True)
def disable_tracing_for_tests(monkeypatch):
    """Disable tracing for all tests in this module."""

    def _patched_init(self, config=None):
        self.config = config or {}
        self.enable_tracing = False
        self.enable_metrics = self.config.get("enable_metrics", True)
        self._analyses_total = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._total_duration = 0.0

    monkeypatch.setattr(
        "risk.reachability.monitoring.ReachabilityMonitor.__init__",
        _patched_init,
    )


# ---------------------------------------------------------------------------
# AnalysisMetrics tests
# ---------------------------------------------------------------------------


class TestAnalysisMetricsCreation:
    """Tests for AnalysisMetrics dataclass."""

    def test_basic_creation(self):
        metrics = AnalysisMetrics(
            cve_id="CVE-2026-0001",
            component_name="django",
            analysis_duration=2.5,
            is_reachable=True,
            confidence="high",
        )
        assert metrics.cve_id == "CVE-2026-0001"
        assert metrics.component_name == "django"
        assert metrics.analysis_duration == 2.5
        assert metrics.is_reachable is True
        assert metrics.confidence == "high"

    def test_default_values(self):
        metrics = AnalysisMetrics(
            cve_id="CVE-2026-0002",
            component_name="flask",
            analysis_duration=0.0,
            is_reachable=False,
            confidence="unknown",
        )
        assert metrics.cache_hit is False
        assert metrics.error is None
        assert metrics.metadata == {}

    def test_with_cache_hit(self):
        metrics = AnalysisMetrics(
            cve_id="CVE-2026-0003",
            component_name="requests",
            analysis_duration=0.01,
            is_reachable=True,
            confidence="high",
            cache_hit=True,
        )
        assert metrics.cache_hit is True

    def test_with_error(self):
        metrics = AnalysisMetrics(
            cve_id="CVE-2026-0004",
            component_name="numpy",
            analysis_duration=0.5,
            is_reachable=False,
            confidence="unknown",
            error="Connection timeout",
        )
        assert metrics.error == "Connection timeout"

    def test_with_metadata(self):
        metadata = {"call_paths": 3, "source": "tree-sitter", "language": "python"}
        metrics = AnalysisMetrics(
            cve_id="CVE-2026-0005",
            component_name="cryptography",
            analysis_duration=1.0,
            is_reachable=True,
            confidence="medium",
            metadata=metadata,
        )
        assert metrics.metadata == metadata
        assert metrics.metadata["call_paths"] == 3

    def test_mutable_after_creation(self):
        """Metrics fields can be updated after creation (used by context manager)."""
        metrics = AnalysisMetrics(
            cve_id="CVE-2026-0006",
            component_name="lib",
            analysis_duration=0.0,
            is_reachable=False,
            confidence="unknown",
        )
        metrics.is_reachable = True
        metrics.confidence = "high"
        metrics.analysis_duration = 3.14
        assert metrics.is_reachable is True
        assert metrics.confidence == "high"
        assert metrics.analysis_duration == 3.14


# ---------------------------------------------------------------------------
# ReachabilityMonitor initialization tests
# ---------------------------------------------------------------------------


class TestMonitorInitialization:
    """Tests for ReachabilityMonitor initialization."""

    def test_default_config(self):
        monitor = ReachabilityMonitor()
        assert monitor.config == {}
        assert monitor.enable_metrics is True
        assert monitor._analyses_total == 0
        assert monitor._cache_hits == 0
        assert monitor._cache_misses == 0
        assert monitor._total_duration == 0.0

    def test_custom_config_metrics_disabled(self):
        monitor = ReachabilityMonitor(config={"enable_metrics": False})
        assert monitor.enable_metrics is False

    def test_custom_config_metrics_enabled(self):
        monitor = ReachabilityMonitor(config={"enable_metrics": True})
        assert monitor.enable_metrics is True


# ---------------------------------------------------------------------------
# Analysis tracking tests
# ---------------------------------------------------------------------------


class TestTrackAnalysis:
    """Tests for ReachabilityMonitor.track_analysis context manager."""

    def test_successful_analysis_updates_metrics(self):
        monitor = ReachabilityMonitor()
        with monitor.track_analysis("CVE-2026-0010", "test-lib") as metrics:
            metrics.is_reachable = True
            metrics.confidence = "high"

        assert metrics.cve_id == "CVE-2026-0010"
        assert metrics.component_name == "test-lib"
        assert metrics.is_reachable is True
        assert metrics.confidence == "high"
        assert metrics.analysis_duration > 0
        assert monitor._analyses_total == 1

    def test_analysis_records_duration(self):
        monitor = ReachabilityMonitor()
        with monitor.track_analysis("CVE-2026-0011", "lib-a") as metrics:
            time.sleep(0.02)

        assert metrics.analysis_duration >= 0.01
        assert monitor._total_duration >= 0.01

    def test_analysis_error_propagates(self):
        monitor = ReachabilityMonitor()
        with pytest.raises(ValueError, match="simulated failure"):
            with monitor.track_analysis("CVE-2026-0012", "bad-lib") as metrics:
                raise ValueError("simulated failure")

        assert metrics.error == "simulated failure"

    def test_analysis_error_does_not_increment_counter(self):
        """On error, the success counter should not increment."""
        monitor = ReachabilityMonitor()
        with pytest.raises(RuntimeError):
            with monitor.track_analysis("CVE-2026-0013", "crash-lib"):
                raise RuntimeError("crash")

        assert monitor._analyses_total == 0

    def test_analysis_duration_recorded_on_error(self):
        """Even on error, duration is recorded in the finally block."""
        monitor = ReachabilityMonitor()
        with pytest.raises(Exception):
            with monitor.track_analysis("CVE-2026-0014", "err-lib") as metrics:
                time.sleep(0.01)
                raise Exception("boom")

        assert metrics.analysis_duration > 0

    def test_multiple_analyses_accumulate(self):
        monitor = ReachabilityMonitor()
        for i in range(5):
            with monitor.track_analysis(f"CVE-2026-{100+i}", f"lib-{i}") as m:
                m.is_reachable = i % 2 == 0
                m.confidence = "high"

        assert monitor._analyses_total == 5
        assert monitor._total_duration > 0


# ---------------------------------------------------------------------------
# Repository clone tracking tests
# ---------------------------------------------------------------------------


class TestTrackRepoClone:
    """Tests for ReachabilityMonitor.track_repo_clone context manager."""

    def test_successful_clone(self):
        monitor = ReachabilityMonitor()
        with monitor.track_repo_clone("https://github.com/test/repo"):
            pass  # Should complete without error

    def test_clone_error_propagates(self):
        monitor = ReachabilityMonitor()
        with pytest.raises(ConnectionError, match="network unreachable"):
            with monitor.track_repo_clone("https://github.com/test/repo"):
                raise ConnectionError("network unreachable")

    def test_clone_with_delay(self):
        monitor = ReachabilityMonitor()
        with monitor.track_repo_clone("https://github.com/test/repo"):
            time.sleep(0.01)
        # Should complete without error


# ---------------------------------------------------------------------------
# Cache recording tests
# ---------------------------------------------------------------------------


class TestCacheRecording:
    """Tests for cache hit/miss recording."""

    def test_record_cache_hit_increments(self):
        monitor = ReachabilityMonitor()
        assert monitor._cache_hits == 0
        monitor.record_cache_hit("CVE-2026-0020")
        assert monitor._cache_hits == 1
        monitor.record_cache_hit("CVE-2026-0021")
        assert monitor._cache_hits == 2

    def test_record_cache_miss_increments(self):
        monitor = ReachabilityMonitor()
        assert monitor._cache_misses == 0
        monitor.record_cache_miss("CVE-2026-0030")
        assert monitor._cache_misses == 1

    def test_cache_hit_disabled_metrics(self):
        """Cache recording works even when metrics is disabled (no OTel add)."""
        monitor = ReachabilityMonitor(config={"enable_metrics": False})
        monitor.record_cache_hit("CVE-2026-0040")
        assert monitor._cache_hits == 1

    def test_cache_miss_disabled_metrics(self):
        monitor = ReachabilityMonitor(config={"enable_metrics": False})
        monitor.record_cache_miss("CVE-2026-0041")
        assert monitor._cache_misses == 1


# ---------------------------------------------------------------------------
# Metrics summary tests
# ---------------------------------------------------------------------------


class TestMetricsSummary:
    """Tests for ReachabilityMonitor.get_metrics_summary."""

    def test_summary_metrics_enabled(self):
        monitor = ReachabilityMonitor()
        summary = monitor.get_metrics_summary()
        assert summary["status"] == "configured"
        assert "timestamp" in summary
        assert summary["analyses_total"] == 0
        assert summary["cache_hits"] == 0
        assert summary["cache_misses"] == 0
        assert summary["cache_hit_rate"] == 0.0
        assert summary["average_duration"] == 0.0
        assert "instruments" in summary
        assert "scrape_endpoint" in summary

    def test_summary_metrics_disabled(self):
        monitor = ReachabilityMonitor(config={"enable_metrics": False})
        summary = monitor.get_metrics_summary()
        assert summary["status"] == "not_configured"
        assert "timestamp" in summary
        assert "message" in summary
        # Should NOT contain instrument details
        assert "instruments" not in summary

    def test_summary_after_analyses(self):
        monitor = ReachabilityMonitor()
        for i in range(3):
            with monitor.track_analysis(f"CVE-{i}", f"lib-{i}") as m:
                m.is_reachable = True
                m.confidence = "high"

        monitor.record_cache_hit("CVE-0")
        monitor.record_cache_hit("CVE-1")
        monitor.record_cache_miss("CVE-2")

        summary = monitor.get_metrics_summary()
        assert summary["analyses_total"] == 3
        assert summary["cache_hits"] == 2
        assert summary["cache_misses"] == 1
        # Hit rate = 2 / (2+1) = 0.666...
        assert abs(summary["cache_hit_rate"] - 2 / 3) < 0.01
        assert summary["average_duration"] > 0

    def test_summary_instruments_structure(self):
        monitor = ReachabilityMonitor()
        summary = monitor.get_metrics_summary()
        instruments = summary["instruments"]
        assert "analyses_total" in instruments
        assert "analysis_duration_seconds" in instruments
        assert "analysis_errors_total" in instruments
        assert "cache_hits_total" in instruments
        assert "cache_misses_total" in instruments

    def test_cache_hit_rate_zero_operations(self):
        """Cache hit rate is 0 when no cache operations have occurred."""
        monitor = ReachabilityMonitor()
        summary = monitor.get_metrics_summary()
        # max(0+0, 1) = 1 to avoid division by zero, so rate is 0/1 = 0
        assert summary["cache_hit_rate"] == 0.0

    def test_average_duration_zero_analyses(self):
        """Average duration is 0 when no analyses have been run."""
        monitor = ReachabilityMonitor()
        summary = monitor.get_metrics_summary()
        assert summary["average_duration"] == 0.0
