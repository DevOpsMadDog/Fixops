"""Model registry for switchable risk assessment models with feature toggles."""

from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


class ModelType(str, Enum):
    """Types of risk assessment models."""

    WEIGHTED_SCORING = "weighted_scoring"
    BAYESIAN_NETWORK = "bayesian_network"
    BN_LR_HYBRID = "bn_lr_hybrid"
    MARKOV_CHAIN = "markov_chain"
    DYNAMIC_BAYESIAN = "dynamic_bayesian"
    ENSEMBLE = "ensemble"


@dataclass
class ModelMetadata:
    """Metadata for a registered risk model."""

    model_id: str
    model_type: ModelType
    version: str
    description: str
    enabled: bool = True
    priority: int = 0  # Higher priority models are tried first
    requires_training: bool = False
    training_data_hash: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "model_id": self.model_id,
            "model_type": self.model_type.value,
            "version": self.version,
            "description": self.description,
            "enabled": self.enabled,
            "priority": self.priority,
            "requires_training": self.requires_training,
            "training_data_hash": self.training_data_hash,
            "created_at": self.created_at,
            "performance_metrics": self.performance_metrics,
            "config": self.config,
        }


@dataclass
class ModelPrediction:
    """Result from a risk model prediction."""

    model_id: str
    model_version: str
    risk_score: float  # 0.0 to 1.0
    verdict: str  # "allow", "review", "block"
    confidence: float  # 0.0 to 1.0
    explanation: Dict[str, Any] = field(default_factory=dict)
    features_used: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    fallback_used: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "model_id": self.model_id,
            "model_version": self.model_version,
            "risk_score": round(self.risk_score, 4),
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "explanation": self.explanation,
            "features_used": self.features_used,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "fallback_used": self.fallback_used,
        }


class RiskModel(ABC):
    """Abstract base class for risk assessment models."""

    def __init__(self, metadata: ModelMetadata):
        self.metadata = metadata

    @abstractmethod
    def predict(
        self,
        *,
        sbom_components: Sequence[Mapping[str, Any]],
        sarif_findings: Sequence[Mapping[str, Any]],
        cve_records: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
        enrichment_map: Optional[Mapping[str, Any]] = None,
    ) -> ModelPrediction:
        """Make a risk prediction.

        Parameters
        ----------
        sbom_components:
            Normalized SBOM components.
        sarif_findings:
            Normalized SARIF findings.
        cve_records:
            Normalized CVE records.
        context:
            Business context (criticality, exposure, etc.).
        enrichment_map:
            Enrichment evidence (KEV, EPSS, CVSS, etc.).

        Returns
        -------
        ModelPrediction
            Risk prediction with score, verdict, and explanation.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if model is available and ready to use.

        Returns
        -------
        bool
            True if model can be used, False otherwise.
        """
        pass

    def get_metadata(self) -> ModelMetadata:
        """Get model metadata."""
        return self.metadata


class ModelRegistry:
    """Registry for managing multiple risk assessment models with feature toggles."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        self._models: Dict[str, RiskModel] = {}
        self._config = dict(config or {})
        self._default_model_id: Optional[str] = None
        self._fallback_chain: List[str] = []
        self._ab_test_config: Dict[str, Any] = {}

    def register(
        self,
        model: RiskModel,
        *,
        set_as_default: bool = False,
        add_to_fallback: bool = True,
    ) -> None:
        """Register a risk model.

        Parameters
        ----------
        model:
            Risk model to register.
        set_as_default:
            If True, set this model as the default.
        add_to_fallback:
            If True, add to fallback chain.
        """
        model_id = model.metadata.model_id
        if model_id in self._models:
            logger.warning(
                "Model %s already registered, replacing with new version", model_id
            )

        self._models[model_id] = model
        logger.info(
            "Registered model: %s (type=%s, version=%s)",
            model_id,
            model.metadata.model_type.value,
            model.metadata.version,
        )

        if set_as_default:
            self._default_model_id = model_id
            logger.info("Set default model to: %s", model_id)

        if add_to_fallback and model_id not in self._fallback_chain:
            inserted = False
            for i, existing_id in enumerate(self._fallback_chain):
                existing_model = self._models.get(existing_id)
                if (
                    existing_model
                    and model.metadata.priority > existing_model.metadata.priority
                ):
                    self._fallback_chain.insert(i, model_id)
                    inserted = True
                    break
            if not inserted:
                self._fallback_chain.append(model_id)

    def get_model(self, model_id: str) -> Optional[RiskModel]:
        """Get a registered model by ID."""
        return self._models.get(model_id)

    def list_models(self, *, enabled_only: bool = False) -> List[ModelMetadata]:
        """List all registered models.

        Parameters
        ----------
        enabled_only:
            If True, only return enabled models.

        Returns
        -------
        List[ModelMetadata]
            List of model metadata.
        """
        models = [model.get_metadata() for model in self._models.values()]
        if enabled_only:
            models = [m for m in models if m.enabled]
        return sorted(models, key=lambda m: m.priority, reverse=True)

    def predict(
        self,
        *,
        sbom_components: Sequence[Mapping[str, Any]],
        sarif_findings: Sequence[Mapping[str, Any]],
        cve_records: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
        enrichment_map: Optional[Mapping[str, Any]] = None,
        model_id: Optional[str] = None,
        use_fallback: bool = True,
    ) -> ModelPrediction:
        """Make a prediction using the specified or default model.

        Parameters
        ----------
        sbom_components:
            Normalized SBOM components.
        sarif_findings:
            Normalized SARIF findings.
        cve_records:
            Normalized CVE records.
        context:
            Business context.
        enrichment_map:
            Enrichment evidence.
        model_id:
            Specific model to use. If None, uses default.
        use_fallback:
            If True, try fallback models on failure.

        Returns
        -------
        ModelPrediction
            Risk prediction.
        """
        target_model_id = model_id or self._default_model_id
        if not target_model_id:
            if not self._models:
                raise ValueError("No models registered")
            enabled = [m for m in self.list_models(enabled_only=True)]
            if not enabled:
                raise ValueError("No enabled models available")
            target_model_id = enabled[0].model_id

        model = self._models.get(target_model_id)
        if model and model.metadata.enabled and model.is_available():
            try:
                prediction = model.predict(
                    sbom_components=sbom_components,
                    sarif_findings=sarif_findings,
                    cve_records=cve_records,
                    context=context,
                    enrichment_map=enrichment_map,
                )
                logger.info(
                    "Prediction from model %s: verdict=%s, score=%.3f, confidence=%.3f",
                    target_model_id,
                    prediction.verdict,
                    prediction.risk_score,
                    prediction.confidence,
                )
                return prediction
            except Exception as exc:
                logger.warning(
                    "Model %s failed: %s. Will try fallback if enabled.",
                    target_model_id,
                    exc,
                    exc_info=True,
                )

        if use_fallback:
            for fallback_id in self._fallback_chain:
                if fallback_id == target_model_id:
                    continue  # Already tried
                fallback_model = self._models.get(fallback_id)
                if (
                    not fallback_model
                    or not fallback_model.metadata.enabled
                    or not fallback_model.is_available()
                ):
                    continue

                try:
                    prediction = fallback_model.predict(
                        sbom_components=sbom_components,
                        sarif_findings=sarif_findings,
                        cve_records=cve_records,
                        context=context,
                        enrichment_map=enrichment_map,
                    )
                    prediction.fallback_used = True
                    logger.info(
                        "Fallback prediction from model %s: verdict=%s, score=%.3f",
                        fallback_id,
                        prediction.verdict,
                        prediction.risk_score,
                    )
                    return prediction
                except Exception as exc:
                    logger.warning(
                        "Fallback model %s also failed: %s", fallback_id, exc
                    )
                    continue

        raise RuntimeError(
            f"All models failed. Primary: {target_model_id}, "
            f"Fallbacks tried: {self._fallback_chain}"
        )

    def set_default_model(self, model_id: str) -> None:
        """Set the default model."""
        if model_id not in self._models:
            raise ValueError(f"Model {model_id} not registered")
        self._default_model_id = model_id
        logger.info("Set default model to: %s", model_id)

    def set_fallback_chain(self, model_ids: List[str]) -> None:
        """Set the fallback chain order."""
        for model_id in model_ids:
            if model_id not in self._models:
                raise ValueError(f"Model {model_id} not registered")
        self._fallback_chain = list(model_ids)
        logger.info("Set fallback chain: %s", " -> ".join(model_ids))

    def enable_model(self, model_id: str) -> None:
        """Enable a model."""
        model = self._models.get(model_id)
        if not model:
            raise ValueError(f"Model {model_id} not registered")
        model.metadata.enabled = True
        logger.info("Enabled model: %s", model_id)

    def disable_model(self, model_id: str) -> None:
        """Disable a model."""
        model = self._models.get(model_id)
        if not model:
            raise ValueError(f"Model {model_id} not registered")
        model.metadata.enabled = False
        logger.info("Disabled model: %s", model_id)

    def configure_ab_test(
        self,
        *,
        control_model_id: str,
        treatment_model_id: str,
        traffic_split: float = 0.5,
        hash_key: str = "cve_id",
    ) -> None:
        """Configure A/B testing between two models.

        Parameters
        ----------
        control_model_id:
            Control (baseline) model ID.
        treatment_model_id:
            Treatment (new) model ID.
        traffic_split:
            Fraction of traffic to send to treatment (0.0 to 1.0).
        hash_key:
            Key to use for consistent hashing (e.g., "cve_id", "component").
        """
        if control_model_id not in self._models:
            raise ValueError(f"Control model {control_model_id} not registered")
        if treatment_model_id not in self._models:
            raise ValueError(f"Treatment model {treatment_model_id} not registered")
        if not 0.0 <= traffic_split <= 1.0:
            raise ValueError("traffic_split must be between 0.0 and 1.0")

        self._ab_test_config = {
            "enabled": True,
            "control_model_id": control_model_id,
            "treatment_model_id": treatment_model_id,
            "traffic_split": traffic_split,
            "hash_key": hash_key,
        }
        logger.info(
            "Configured A/B test: %s (control) vs %s (treatment), split=%.2f",
            control_model_id,
            treatment_model_id,
            traffic_split,
        )

    def get_ab_test_model(self, hash_input: str) -> tuple[str, bool]:
        """Determine which model to use for A/B testing.

        Parameters
        ----------
        hash_input:
            Input to hash for consistent assignment.

        Returns
        -------
        tuple[str, bool]
            (model_id, is_treatment)
        """
        if not self._ab_test_config.get("enabled"):
            return self._default_model_id or "", False

        hash_value = int(hashlib.md5(hash_input.encode()).hexdigest(), 16)
        bucket = (hash_value % 100) / 100.0

        traffic_split = self._ab_test_config["traffic_split"]
        if bucket < traffic_split:
            return self._ab_test_config["treatment_model_id"], True
        else:
            return self._ab_test_config["control_model_id"], False


def compute_verdict(
    risk_score: float,
    *,
    allow_threshold: float = 0.6,
    block_threshold: float = 0.85,
) -> str:
    """Compute verdict from risk score.

    Parameters
    ----------
    risk_score:
        Risk score (0.0 to 1.0).
    allow_threshold:
        Threshold below which to allow.
    block_threshold:
        Threshold above which to block.

    Returns
    -------
    str
        "allow", "review", or "block"
    """
    if risk_score < allow_threshold:
        return "allow"
    elif risk_score >= block_threshold:
        return "block"
    else:
        return "review"


__all__ = [
    "ModelType",
    "ModelMetadata",
    "ModelPrediction",
    "RiskModel",
    "ModelRegistry",
    "compute_verdict",
]
