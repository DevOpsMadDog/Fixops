"""Tests for model registry and switchable risk models."""

from typing import Any, Mapping, Optional, Sequence

import pytest

from core.model_factory import create_model_registry_from_config
from core.model_registry import (
    ModelMetadata,
    ModelPrediction,
    ModelRegistry,
    ModelType,
    RiskModel,
    compute_verdict,
)
from core.models import WeightedScoringModel


class MockModel(RiskModel):
    """Mock model for testing."""

    def __init__(self, model_id: str, should_fail: bool = False):
        metadata = ModelMetadata(
            model_id=model_id,
            model_type=ModelType.WEIGHTED_SCORING,
            version="1.0.0",
            description="Mock model for testing",
            enabled=True,
            priority=50,
        )
        super().__init__(metadata)
        self.should_fail = should_fail
        self.call_count = 0

    def predict(
        self,
        *,
        sbom_components: Sequence[Mapping[str, Any]],
        sarif_findings: Sequence[Mapping[str, Any]],
        cve_records: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
        enrichment_map: Optional[Mapping[str, Any]] = None,
    ) -> ModelPrediction:
        self.call_count += 1
        if self.should_fail:
            raise RuntimeError("Mock model failure")

        return ModelPrediction(
            model_id=self.metadata.model_id,
            model_version=self.metadata.version,
            risk_score=0.5,
            verdict="review",
            confidence=0.8,
            explanation={"method": "mock"},
            features_used=["mock_feature"],
            execution_time_ms=1.0,
        )

    def is_available(self) -> bool:
        return not self.should_fail


class TestComputeVerdict:
    """Tests for compute_verdict function."""

    def test_allow_verdict(self):
        assert compute_verdict(0.3) == "allow"
        assert compute_verdict(0.59) == "allow"

    def test_review_verdict(self):
        assert compute_verdict(0.6) == "review"
        assert compute_verdict(0.7) == "review"
        assert compute_verdict(0.84) == "review"

    def test_block_verdict(self):
        assert compute_verdict(0.85) == "block"
        assert compute_verdict(0.95) == "block"
        assert compute_verdict(1.0) == "block"

    def test_custom_thresholds(self):
        assert (
            compute_verdict(0.5, allow_threshold=0.4, block_threshold=0.8) == "review"
        )
        assert compute_verdict(0.3, allow_threshold=0.4, block_threshold=0.8) == "allow"
        assert compute_verdict(0.9, allow_threshold=0.4, block_threshold=0.8) == "block"


class TestModelMetadata:
    """Tests for ModelMetadata."""

    def test_to_dict(self):
        metadata = ModelMetadata(
            model_id="test_model",
            model_type=ModelType.BAYESIAN_NETWORK,
            version="1.0.0",
            description="Test model",
            enabled=True,
            priority=50,
        )
        result = metadata.to_dict()
        assert result["model_id"] == "test_model"
        assert result["model_type"] == "bayesian_network"
        assert result["version"] == "1.0.0"
        assert result["enabled"] is True
        assert result["priority"] == 50


class TestModelPrediction:
    """Tests for ModelPrediction."""

    def test_to_dict(self):
        prediction = ModelPrediction(
            model_id="test_model",
            model_version="1.0.0",
            risk_score=0.75,
            verdict="block",
            confidence=0.9,
            explanation={"method": "test"},
            features_used=["feature1", "feature2"],
            execution_time_ms=10.5,
            fallback_used=False,
        )
        result = prediction.to_dict()
        assert result["model_id"] == "test_model"
        assert result["risk_score"] == 0.75
        assert result["verdict"] == "block"
        assert result["confidence"] == 0.9
        assert result["fallback_used"] is False


class TestModelRegistry:
    """Tests for ModelRegistry."""

    def test_register_model(self):
        registry = ModelRegistry()
        model = MockModel("test_model")
        registry.register(model)

        assert registry.get_model("test_model") is model

    def test_register_sets_default(self):
        registry = ModelRegistry()
        model = MockModel("test_model")
        registry.register(model, set_as_default=True)

        assert registry._default_model_id == "test_model"

    def test_list_models(self):
        registry = ModelRegistry()
        model1 = MockModel("model1")
        model1.metadata.priority = 10
        model2 = MockModel("model2")
        model2.metadata.priority = 50

        registry.register(model1)
        registry.register(model2)

        models = registry.list_models()
        assert len(models) == 2
        assert models[0].model_id == "model2"
        assert models[1].model_id == "model1"

    def test_list_models_enabled_only(self):
        registry = ModelRegistry()
        model1 = MockModel("model1")
        model2 = MockModel("model2")
        model2.metadata.enabled = False

        registry.register(model1)
        registry.register(model2)

        models = registry.list_models(enabled_only=True)
        assert len(models) == 1
        assert models[0].model_id == "model1"

    def test_predict_with_default_model(self):
        registry = ModelRegistry()
        model = MockModel("test_model")
        registry.register(model, set_as_default=True)

        prediction = registry.predict(
            sbom_components=[],
            sarif_findings=[],
            cve_records=[],
        )

        assert prediction.model_id == "test_model"
        assert model.call_count == 1

    def test_predict_with_specific_model(self):
        registry = ModelRegistry()
        model1 = MockModel("model1")
        model2 = MockModel("model2")
        registry.register(model1, set_as_default=True)
        registry.register(model2)

        prediction = registry.predict(
            sbom_components=[],
            sarif_findings=[],
            cve_records=[],
            model_id="model2",
        )

        assert prediction.model_id == "model2"
        assert model1.call_count == 0
        assert model2.call_count == 1

    def test_fallback_chain(self):
        registry = ModelRegistry()
        failing_model = MockModel("failing_model", should_fail=True)
        fallback_model = MockModel("fallback_model")

        registry.register(failing_model, set_as_default=True)
        registry.register(fallback_model)
        registry.set_fallback_chain(["failing_model", "fallback_model"])

        prediction = registry.predict(
            sbom_components=[],
            sarif_findings=[],
            cve_records=[],
            use_fallback=True,
        )

        assert prediction.model_id == "fallback_model"
        assert prediction.fallback_used is True

    def test_no_fallback_raises_error(self):
        registry = ModelRegistry()
        failing_model = MockModel("failing_model", should_fail=True)
        registry.register(failing_model, set_as_default=True)

        with pytest.raises(RuntimeError, match="All models failed"):
            registry.predict(
                sbom_components=[],
                sarif_findings=[],
                cve_records=[],
                use_fallback=False,
            )

    def test_enable_disable_model(self):
        registry = ModelRegistry()
        model = MockModel("test_model")
        registry.register(model)

        assert model.metadata.enabled is True

        registry.disable_model("test_model")
        assert model.metadata.enabled is False

        registry.enable_model("test_model")
        assert model.metadata.enabled is True

    def test_ab_test_configuration(self):
        registry = ModelRegistry()
        control = MockModel("control")
        treatment = MockModel("treatment")
        registry.register(control)
        registry.register(treatment)

        registry.configure_ab_test(
            control_model_id="control",
            treatment_model_id="treatment",
            traffic_split=0.5,
            hash_key="cve_id",
        )

        assert registry._ab_test_config["enabled"] is True
        assert registry._ab_test_config["control_model_id"] == "control"
        assert registry._ab_test_config["treatment_model_id"] == "treatment"
        assert registry._ab_test_config["traffic_split"] == 0.5

    def test_ab_test_assignment(self):
        registry = ModelRegistry()
        control = MockModel("control")
        treatment = MockModel("treatment")
        registry.register(control)
        registry.register(treatment)

        registry.configure_ab_test(
            control_model_id="control",
            treatment_model_id="treatment",
            traffic_split=0.5,
            hash_key="cve_id",
        )

        model_id1, is_treatment1 = registry.get_ab_test_model("CVE-2024-1234")
        model_id2, is_treatment2 = registry.get_ab_test_model("CVE-2024-1234")
        assert model_id1 == model_id2
        assert is_treatment1 == is_treatment2


class TestWeightedScoringModel:
    """Tests for WeightedScoringModel."""

    def test_is_available(self):
        model = WeightedScoringModel()
        assert model.is_available() is True

    def test_predict_no_findings(self):
        model = WeightedScoringModel()
        prediction = model.predict(
            sbom_components=[],
            sarif_findings=[],
            cve_records=[],
        )

        assert prediction.risk_score == 0.0
        assert prediction.verdict == "allow"
        assert prediction.confidence == 0.9

    def test_predict_with_cves(self):
        model = WeightedScoringModel()
        cve_records = [
            {"cve_id": "CVE-2024-0001", "severity": "critical"},
            {"cve_id": "CVE-2024-0002", "severity": "high"},
            {"cve_id": "CVE-2024-0003", "severity": "medium"},
        ]

        prediction = model.predict(
            sbom_components=[],
            sarif_findings=[],
            cve_records=cve_records,
        )

        assert prediction.risk_score == 0.75
        assert prediction.verdict == "review"

    def test_predict_with_kev_boost(self):
        model = WeightedScoringModel()
        cve_records = [
            {"cve_id": "CVE-2024-0001", "severity": "medium"},
        ]
        enrichment_map = {
            "CVE-2024-0001": {"kev_listed": True},
        }

        prediction = model.predict(
            sbom_components=[],
            sarif_findings=[],
            cve_records=cve_records,
            enrichment_map=enrichment_map,
        )

        assert prediction.risk_score == 0.7
        assert prediction.verdict == "review"


class TestModelFactory:
    """Tests for model factory."""

    def test_create_registry_from_config(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": True,
                    "default_model": "weighted_scoring_v1",
                    "fallback_chain": ["weighted_scoring_v1"],
                    "models": {
                        "weighted_scoring_v1": {
                            "enabled": True,
                            "priority": 10,
                            "config": {
                                "allow_threshold": 0.6,
                                "block_threshold": 0.85,
                            },
                        },
                    },
                },
            },
        }

        registry = create_model_registry_from_config(config)
        assert registry is not None
        assert registry._default_model_id == "weighted_scoring_v1"

        models = registry.list_models()
        assert len(models) >= 1
        assert any(m.model_id == "weighted_scoring_v1" for m in models)

    def test_create_registry_disabled(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": False,
                },
            },
        }

        registry = create_model_registry_from_config(config)
        assert registry is None

    def test_create_registry_with_ab_test(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": True,
                    "default_model": "weighted_scoring_v1",
                    "models": {
                        "weighted_scoring_v1": {
                            "enabled": True,
                            "priority": 10,
                            "config": {},
                        },
                        "bayesian_network_v1": {
                            "enabled": True,
                            "priority": 50,
                            "config": {},
                        },
                    },
                    "ab_test": {
                        "enabled": True,
                        "control_model": "weighted_scoring_v1",
                        "treatment_model": "bayesian_network_v1",
                        "traffic_split": 0.5,
                        "hash_key": "cve_id",
                    },
                },
            },
        }

        registry = create_model_registry_from_config(config)
        assert registry is not None
        assert registry._ab_test_config["enabled"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
