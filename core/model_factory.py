"""Factory for creating and configuring risk models from overlay configuration."""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

from core.model_registry import ModelRegistry, RiskModel
from core.models import BayesianNetworkModel, BNLRHybridModel, WeightedScoringModel

logger = logging.getLogger(__name__)


def create_model_registry_from_config(
    config: Mapping[str, Any]
) -> Optional[ModelRegistry]:
    """Create and configure ModelRegistry from overlay configuration.

    Parameters
    ----------
    config:
        Overlay configuration dictionary (typically from fixops.overlay.yml).

    Returns
    -------
    Optional[ModelRegistry]
        Configured model registry, or None if risk_models not enabled.

    Example
    -------
    >>> from core.configuration import load_overlay
    >>> overlay = load_overlay("config/fixops.overlay.yml")
    >>> registry = create_model_registry_from_config(overlay)
    >>> prediction = registry.predict(
    ...     sbom_components=components,
    ...     sarif_findings=findings,
    ...     cve_records=cves,
    ...     enrichment_map=enrichment,
    ... )
    """
    probabilistic_config = config.get("probabilistic", {})
    if not isinstance(probabilistic_config, Mapping):
        logger.warning("probabilistic config not found or invalid")
        return None

    risk_models_config = probabilistic_config.get("risk_models", {})
    if not isinstance(risk_models_config, Mapping):
        logger.warning("risk_models config not found or invalid")
        return None

    if not risk_models_config.get("enabled", False):
        logger.info("risk_models not enabled in config")
        return None

    registry = ModelRegistry(config=risk_models_config)

    models_config = risk_models_config.get("models", {})
    if not isinstance(models_config, Mapping):
        logger.warning("models config not found or invalid")
        return None

    weighted_config = models_config.get("weighted_scoring_v1", {})
    if isinstance(weighted_config, Mapping) and weighted_config.get("enabled", True):
        try:
            weighted_model: RiskModel = WeightedScoringModel(
                config=weighted_config.get("config", {})
            )
            weighted_model.metadata.enabled = weighted_config.get("enabled", True)
            weighted_model.metadata.priority = weighted_config.get("priority", 10)
            registry.register(weighted_model, add_to_fallback=True)
            logger.info("Registered weighted_scoring_v1 model")
        except Exception as exc:
            logger.error("Failed to register weighted_scoring_v1: %s", exc)

    bn_config = models_config.get("bayesian_network_v1", {})
    if isinstance(bn_config, Mapping) and bn_config.get("enabled", True):
        try:
            bn_model: RiskModel = BayesianNetworkModel(
                config=bn_config.get("config", {})
            )
            bn_model.metadata.enabled = bn_config.get("enabled", True)
            bn_model.metadata.priority = bn_config.get("priority", 50)
            registry.register(bn_model, add_to_fallback=True)
            logger.info("Registered bayesian_network_v1 model")
        except Exception as exc:
            logger.error("Failed to register bayesian_network_v1: %s", exc)

    bn_lr_config = models_config.get("bn_lr_hybrid_v1", {})
    if isinstance(bn_lr_config, Mapping) and bn_lr_config.get("enabled", True):
        try:
            bn_lr_model: RiskModel = BNLRHybridModel(
                config=bn_lr_config.get("config", {})
            )
            bn_lr_model.metadata.enabled = bn_lr_config.get("enabled", True)
            bn_lr_model.metadata.priority = bn_lr_config.get("priority", 100)
            registry.register(bn_lr_model, add_to_fallback=True)
            logger.info("Registered bn_lr_hybrid_v1 model")
        except Exception as exc:
            logger.error("Failed to register bn_lr_hybrid_v1: %s", exc)

    default_model_id = risk_models_config.get("default_model")
    if default_model_id:
        try:
            registry.set_default_model(default_model_id)
            logger.info("Set default model to: %s", default_model_id)
        except Exception as exc:
            logger.warning("Failed to set default model %s: %s", default_model_id, exc)

    fallback_chain = risk_models_config.get("fallback_chain", [])
    if isinstance(fallback_chain, list) and fallback_chain:
        try:
            registry.set_fallback_chain(fallback_chain)
            logger.info("Set fallback chain: %s", " -> ".join(fallback_chain))
        except Exception as exc:
            logger.warning("Failed to set fallback chain: %s", exc)

    ab_test_config = risk_models_config.get("ab_test", {})
    if isinstance(ab_test_config, Mapping) and ab_test_config.get("enabled", False):
        try:
            registry.configure_ab_test(
                control_model_id=ab_test_config["control_model"],
                treatment_model_id=ab_test_config["treatment_model"],
                traffic_split=ab_test_config.get("traffic_split", 0.5),
                hash_key=ab_test_config.get("hash_key", "cve_id"),
            )
            logger.info(
                "Configured A/B test: %s vs %s",
                ab_test_config["control_model"],
                ab_test_config["treatment_model"],
            )
        except Exception as exc:
            logger.warning("Failed to configure A/B test: %s", exc)

    return registry


__all__ = ["create_model_registry_from_config"]
