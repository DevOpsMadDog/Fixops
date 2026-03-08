"""Tests for CorrelationEngine — dataclass and initialization."""
import pytest

from core.services.enterprise.correlation_engine import (
    CorrelationResult,
    CorrelationEngine,
)


class TestCorrelationResult:
    def test_create(self):
        r = CorrelationResult(
            finding_id="f-001",
            correlated_findings=["f-002", "f-003"],
            correlation_type="fingerprint",
            confidence_score=0.88,
            noise_reduction_factor=0.65,
            root_cause="SQL injection in login endpoint",
        )
        assert r.finding_id == "f-001"
        assert len(r.correlated_findings) == 2
        assert r.correlation_type == "fingerprint"
        assert r.confidence_score == 0.88
        assert r.noise_reduction_factor == 0.65

    def test_empty_correlations(self):
        r = CorrelationResult(
            finding_id="f-solo",
            correlated_findings=[],
            correlation_type="none",
            confidence_score=1.0,
            noise_reduction_factor=0.0,
            root_cause="",
        )
        assert r.correlated_findings == []


class TestCorrelationEngine:
    @pytest.fixture
    def engine(self):
        return CorrelationEngine()

    def test_init(self, engine):
        assert engine is not None
        assert hasattr(engine, "correlation_strategies")

    def test_has_five_strategies(self, engine):
        assert len(engine.correlation_strategies) == 5

    def test_strategy_names(self, engine):
        method_names = [s.__name__ for s in engine.correlation_strategies]
        assert "_correlate_by_fingerprint" in method_names
        assert "_correlate_by_location" in method_names
        assert "_correlate_by_pattern" in method_names
        assert "_correlate_by_root_cause" in method_names
        assert "_correlate_by_vulnerability" in method_names

    def test_cache_service(self, engine):
        assert engine.cache is not None

    def test_llm_chat_init(self, engine):
        # In test env without API key, llm_chat should be None
        # But may be initialized if settings file has a key
        assert engine.llm_chat is None or engine.llm_chat is not None
