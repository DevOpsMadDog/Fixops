"""Tests for core.model_registry — model registry with feature toggles."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.model_registry import (
    ModelMetadata,
    ModelPrediction,
    ModelRegistry,
    ModelType,
    RiskModel,
)


# ── ModelType Enum ──────────────────────────────────────────────────

class TestModelType:
    def test_values(self):
        assert ModelType.WEIGHTED_SCORING.value == "weighted_scoring"
        assert ModelType.BAYESIAN_NETWORK.value == "bayesian_network"
        assert ModelType.BN_LR_HYBRID.value == "bn_lr_hybrid"
        assert ModelType.MARKOV_CHAIN.value == "markov_chain"
        assert ModelType.DYNAMIC_BAYESIAN.value == "dynamic_bayesian"
        assert ModelType.ENSEMBLE.value == "ensemble"

    def test_count(self):
        assert len(ModelType) == 6


# ── ModelMetadata ────────────────────────────────────────────────────

class TestModelMetadata:
    def test_defaults(self):
        meta = ModelMetadata(
            model_id="test-model",
            model_type=ModelType.WEIGHTED_SCORING,
            version="1.0.0",
            description="Test model",
        )
        assert meta.model_id == "test-model"
        assert meta.enabled is True
        assert meta.priority == 0
        assert meta.requires_training is False
        assert meta.training_data_hash is None
        assert meta.performance_metrics == {}
        assert meta.config == {}

    def test_to_dict(self):
        meta = ModelMetadata(
            model_id="bn-model",
            model_type=ModelType.BAYESIAN_NETWORK,
            version="2.0.0",
            description="Bayesian network model",
            enabled=True,
            priority=10,
            performance_metrics={"accuracy": 0.95},
        )
        d = meta.to_dict()
        assert d["model_id"] == "bn-model"
        assert d["model_type"] == "bayesian_network"
        assert d["version"] == "2.0.0"
        assert d["priority"] == 10
        assert d["performance_metrics"]["accuracy"] == 0.95
        assert "created_at" in d


# ── ModelPrediction ─────────────────────────────────────────────────

class TestModelPrediction:
    def test_basic(self):
        pred = ModelPrediction(
            model_id="test",
            model_version="1.0",
            risk_score=0.75,
            verdict="review",
            confidence=0.85,
        )
        assert pred.risk_score == 0.75
        assert pred.verdict == "review"
        assert pred.fallback_used is False

    def test_to_dict(self):
        pred = ModelPrediction(
            model_id="test",
            model_version="1.0",
            risk_score=0.7512,
            verdict="block",
            confidence=0.9123,
            explanation={"key_factor": "KEV listed"},
            features_used=["cvss", "epss", "kev"],
            execution_time_ms=42.567,
            fallback_used=True,
        )
        d = pred.to_dict()
        assert d["risk_score"] == 0.7512
        assert d["verdict"] == "block"
        assert d["confidence"] == 0.9123
        assert d["fallback_used"] is True
        assert len(d["features_used"]) == 3
        assert d["execution_time_ms"] == 42.57  # rounded to 2dp


# ── RiskModel (abstract) ────────────────────────────────────────────

class DummyRiskModel(RiskModel):
    def predict(self, **kwargs):
        return ModelPrediction(
            model_id=self.metadata.model_id,
            model_version=self.metadata.version,
            risk_score=0.5,
            verdict="review",
            confidence=0.8,
        )

    def is_available(self):
        return True


class UnavailableModel(RiskModel):
    def predict(self, **kwargs):
        raise RuntimeError("Not available")

    def is_available(self):
        return False


def _make_model(model_id="test", priority=0, enabled=True):
    return DummyRiskModel(
        ModelMetadata(
            model_id=model_id,
            model_type=ModelType.WEIGHTED_SCORING,
            version="1.0.0",
            description=f"Test model {model_id}",
            priority=priority,
            enabled=enabled,
        )
    )


class TestRiskModel:
    def test_get_metadata(self):
        model = _make_model("my-model")
        meta = model.get_metadata()
        assert meta.model_id == "my-model"

    def test_predict(self):
        model = _make_model()
        pred = model.predict(
            sbom_components=[], sarif_findings=[], cve_records=[]
        )
        assert isinstance(pred, ModelPrediction)
        assert pred.risk_score == 0.5

    def test_is_available(self):
        model = _make_model()
        assert model.is_available() is True


# ── ModelRegistry ────────────────────────────────────────────────────

class TestModelRegistry:
    @pytest.fixture
    def registry(self):
        return ModelRegistry()

    def test_init_empty(self, registry):
        assert registry.list_models() == []
        assert registry._default_model_id is None

    def test_register_model(self, registry):
        model = _make_model("model-1")
        registry.register(model)
        assert registry.get_model("model-1") is model

    def test_register_as_default(self, registry):
        model = _make_model("default-model")
        registry.register(model, set_as_default=True)
        assert registry._default_model_id == "default-model"

    def test_register_multiple(self, registry):
        for i in range(5):
            registry.register(_make_model(f"model-{i}", priority=i))
        models = registry.list_models()
        assert len(models) == 5
        # Should be sorted by priority (highest first)
        assert models[0].priority >= models[-1].priority

    def test_list_enabled_only(self, registry):
        registry.register(_make_model("enabled", enabled=True))
        registry.register(_make_model("disabled", enabled=False))
        enabled = registry.list_models(enabled_only=True)
        assert len(enabled) == 1
        assert enabled[0].model_id == "enabled"

    def test_get_nonexistent_model(self, registry):
        assert registry.get_model("nonexistent") is None

    def test_replace_model(self, registry):
        model_v1 = _make_model("model")
        model_v2 = _make_model("model")
        registry.register(model_v1)
        registry.register(model_v2)
        assert registry.get_model("model") is model_v2

    def test_fallback_chain(self, registry):
        low = _make_model("low", priority=1)
        high = _make_model("high", priority=10)
        registry.register(low)
        registry.register(high)
        # High priority should be first in fallback chain
        assert registry._fallback_chain[0] == "high"

    def test_register_no_fallback(self, registry):
        model = _make_model("no-fallback")
        registry.register(model, add_to_fallback=False)
        assert "no-fallback" not in registry._fallback_chain

    def test_with_config(self):
        config = {"ab_test_enabled": True}
        registry = ModelRegistry(config=config)
        assert registry._config["ab_test_enabled"] is True
