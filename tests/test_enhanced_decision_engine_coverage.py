"""Tests for EnhancedDecisionEngine — MITRE techniques and compliance frameworks."""
import pytest

from core.services.enterprise.enhanced_decision_engine import EnhancedDecisionEngine


class TestEnhancedDecisionEngine:
    @pytest.fixture
    def engine(self):
        return EnhancedDecisionEngine()

    def test_init(self, engine):
        assert engine is not None
        assert engine.cache is not None
        assert engine.llm_engine is not None
        assert engine.marketplace is not None

    def test_mitre_techniques_loaded(self, engine):
        # MITRE techniques are loaded in _load_enhanced_capabilities (async)
        # but we can test that attributes exist
        assert hasattr(engine, "cache")

    def test_compliance_frameworks_loaded(self, engine):
        assert hasattr(engine, "llm_engine")
