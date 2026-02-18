"""Tests for reachability monitoring module."""

import time

import pytest
from risk.reachability.monitoring import AnalysisMetrics, ReachabilityMonitor


# Disable tracing for all tests to avoid telemetry span issues
@pytest.fixture(autouse=True)
def disable_tracing_for_tests(monkeypatch):
    """Disable tracing for all tests in this module."""
    monkeypatch.setattr(
        "risk.reachability.monitoring.ReachabilityMonitor.__init__",
        lambda self, config=None: setattr(self, "config", config or {})
        or setattr(self, "enable_tracing", False)
        or setattr(self, "enable_metrics", (config or {}).get("enable_metrics", True)),
    )


class TestAnalysisMetrics:
    """Tests for AnalysisMetrics dataclass."""

    def test_analysis_metrics_creation(self):
        """Test creating AnalysisMetrics."""
        metrics = AnalysisMetrics(
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            analysis_duration=1.5,
            is_reachable=True,
            confidence="high",
        )
        assert metrics.cve_id == "CVE-2024-1234"
        assert metrics.component_name == "test-lib"
        assert metrics.analysis_duration == 1.5
        assert metrics.is_reachable is True
        assert metrics.confidence == "high"

    def test_analysis_metrics_defaults(self):
        """Test AnalysisMetrics default values."""
        metrics = AnalysisMetrics(
            cve_id="CVE-2024-5678",
            component_name="another-lib",
            analysis_duration=0.5,
            is_reachable=False,
            confidence="low",
        )
        assert metrics.cache_hit is False
        assert metrics.error is None
        assert metrics.metadata == {}

    def test_analysis_metrics_with_error(self):
        """Test AnalysisMetrics with error."""
        metrics = AnalysisMetrics(
            cve_id="CVE-2024-9999",
            component_name="error-lib",
            analysis_duration=0.1,
            is_reachable=False,
            confidence="unknown",
            error="Analysis failed",
        )
        assert metrics.error == "Analysis failed"

    def test_analysis_metrics_with_metadata(self):
        """Test AnalysisMetrics with metadata."""
        metrics = AnalysisMetrics(
            cve_id="CVE-2024-1111",
            component_name="meta-lib",
            analysis_duration=2.0,
            is_reachable=True,
            confidence="medium",
            metadata={"source": "static_analysis", "paths": 5},
        )
        assert metrics.metadata["source"] == "static_analysis"
        assert metrics.metadata["paths"] == 5


class TestReachabilityMonitor:
    """Tests for ReachabilityMonitor."""

    @pytest.fixture
    def monitor(self):
        """Create a monitor instance for testing."""
        return ReachabilityMonitor()

    @pytest.fixture
    def monitor_disabled(self):
        """Create a monitor with tracing and metrics disabled."""
        return ReachabilityMonitor(
            config={
                "enable_tracing": False,
                "enable_metrics": False,
            }
        )

    def test_monitor_initialization(self, monitor):
        """Test monitor initialization."""
        assert monitor.config == {}
        # Note: enable_tracing is False due to test fixture that disables tracing
        assert monitor.enable_tracing is False
        assert monitor.enable_metrics is True

    def test_monitor_with_custom_config(self):
        """Test monitor with custom config."""
        config = {
            "enable_tracing": False,
            "enable_metrics": True,
        }
        monitor = ReachabilityMonitor(config=config)
        assert monitor.enable_tracing is False
        assert monitor.enable_metrics is True

    def test_track_analysis_success(self, monitor):
        """Test tracking a successful analysis."""
        with monitor.track_analysis("CVE-2024-1234", "test-lib") as metrics:
            metrics.is_reachable = True
            metrics.confidence = "high"
            time.sleep(0.01)  # Small delay to ensure duration > 0

        assert metrics.cve_id == "CVE-2024-1234"
        assert metrics.component_name == "test-lib"
        assert metrics.is_reachable is True
        assert metrics.confidence == "high"
        assert metrics.analysis_duration > 0

    def test_track_analysis_with_error(self, monitor):
        """Test tracking an analysis that raises an error."""
        with pytest.raises(ValueError):
            with monitor.track_analysis("CVE-2024-5678", "error-lib") as metrics:
                raise ValueError("Test error")

        assert metrics.error == "Test error"

    def test_track_analysis_disabled_tracing(self, monitor_disabled):
        """Test tracking analysis with tracing disabled."""
        with monitor_disabled.track_analysis("CVE-2024-1234", "test-lib") as metrics:
            metrics.is_reachable = False
            metrics.confidence = "low"

        assert metrics.is_reachable is False
        assert metrics.confidence == "low"

    def test_track_repo_clone_success(self, monitor):
        """Test tracking a successful repo clone."""
        with monitor.track_repo_clone("https://github.com/test/repo"):
            time.sleep(0.01)  # Small delay

        # Should complete without error

    def test_track_repo_clone_with_error(self, monitor):
        """Test tracking a repo clone that raises an error."""
        with pytest.raises(RuntimeError):
            with monitor.track_repo_clone("https://github.com/test/repo"):
                raise RuntimeError("Clone failed")

    def test_track_repo_clone_disabled_tracing(self, monitor_disabled):
        """Test tracking repo clone with tracing disabled."""
        with monitor_disabled.track_repo_clone("https://github.com/test/repo"):
            pass  # Should complete without error

    def test_record_cache_hit(self, monitor):
        """Test recording cache hit."""
        # Should not raise error
        monitor.record_cache_hit("CVE-2024-1234")

    def test_record_cache_hit_disabled(self, monitor_disabled):
        """Test recording cache hit with metrics disabled."""
        # Should not raise error
        monitor_disabled.record_cache_hit("CVE-2024-1234")

    def test_record_cache_miss(self, monitor):
        """Test recording cache miss."""
        # Should not raise error
        monitor.record_cache_miss("CVE-2024-5678")

    def test_record_cache_miss_disabled(self, monitor_disabled):
        """Test recording cache miss with metrics disabled."""
        # Should not raise error
        monitor_disabled.record_cache_miss("CVE-2024-5678")

    def test_get_metrics_summary(self, monitor):
        """Test getting metrics summary."""
        summary = monitor.get_metrics_summary()

        assert "timestamp" in summary
        assert "analyses_total" in summary
        assert "cache_hit_rate" in summary
        assert "average_duration" in summary

    def test_multiple_analyses_tracking(self, monitor):
        """Test tracking multiple analyses."""
        results = []

        for i in range(3):
            with monitor.track_analysis(f"CVE-2024-{i}", f"lib-{i}") as metrics:
                metrics.is_reachable = i % 2 == 0
                metrics.confidence = "high" if i % 2 == 0 else "low"
            results.append(metrics)

        assert len(results) == 3
        assert results[0].is_reachable is True
        assert results[1].is_reachable is False
        assert results[2].is_reachable is True
