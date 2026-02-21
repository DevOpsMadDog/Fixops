"""BN-LR Hybrid model - combines Bayesian Network with Logistic Regression.

This implements the approach from the research paper:
"A hybrid approach combining Bayesian networks and logistic regression for enhancing risk assessment"
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Mapping, Optional, Sequence

from core.model_registry import (
    ModelMetadata,
    ModelPrediction,
    ModelType,
    RiskModel,
    compute_verdict,
)

logger = logging.getLogger(__name__)

try:
    from pgmpy.factors.discrete import TabularCPD
    from pgmpy.inference import VariableElimination
    from pgmpy.models import BayesianNetwork

    PGMPY_AVAILABLE = True
except Exception:
    BayesianNetwork = None  # type: ignore[assignment]
    VariableElimination = None  # type: ignore[assignment]
    TabularCPD = None  # type: ignore[assignment]
    PGMPY_AVAILABLE = False

try:
    import numpy as np
    from sklearn.linear_model import LogisticRegression

    SKLEARN_AVAILABLE = True
except Exception:
    LogisticRegression = None  # type: ignore[assignment]
    np = None  # type: ignore[assignment]
    SKLEARN_AVAILABLE = False


class BNLRHybridModel(RiskModel):
    """BN-LR Hybrid model for risk assessment.

    Combines Bayesian Network (for causal dependencies) with Logistic Regression
    (for calibrated classification). BN posterior probabilities are used as features
    for the LR classifier.

    This is the approach described in the research paper that achieves 97% accuracy.
    """

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        config = config or {}
        metadata = ModelMetadata(
            model_id="bn_lr_hybrid_v1",
            model_type=ModelType.BN_LR_HYBRID,
            version="1.0.0",
            description="BN-LR Hybrid: Bayesian Network posteriors + Logistic Regression classifier (research paper approach)",
            enabled=True,
            priority=100,  # Highest priority - try this first
            requires_training=True,
            config=dict(config),
        )
        super().__init__(metadata)

        self.allow_threshold = config.get("allow_threshold", 0.6)
        self.block_threshold = config.get("block_threshold", 0.85)

        self._build_network()

        self._init_lr_classifier(config)

    def _build_network(self) -> None:
        """Build the Bayesian Network structure and CPDs."""
        if not PGMPY_AVAILABLE:
            logger.warning("pgmpy not available, BN-LR model will not work")
            return

        self.model = BayesianNetwork(
            [
                ("exploitation", "risk"),
                ("exposure", "risk"),
                ("utility", "risk"),
                ("safety_impact", "risk"),
                ("mission_impact", "risk"),
            ]
        )

        exploitation_cpd = TabularCPD(
            variable="exploitation",
            variable_card=3,
            values=[[0.6], [0.3], [0.1]],
            state_names={"exploitation": ["none", "poc", "active"]},
        )

        exposure_cpd = TabularCPD(
            variable="exposure",
            variable_card=3,
            values=[[0.5], [0.3], [0.2]],
            state_names={"exposure": ["controlled", "limited", "open"]},
        )

        utility_cpd = TabularCPD(
            variable="utility",
            variable_card=3,
            values=[[0.4], [0.4], [0.2]],
            state_names={"utility": ["laborious", "efficient", "super_effective"]},
        )

        safety_impact_cpd = TabularCPD(
            variable="safety_impact",
            variable_card=4,
            values=[[0.5], [0.3], [0.15], [0.05]],
            state_names={
                "safety_impact": ["negligible", "marginal", "major", "hazardous"]
            },
        )

        mission_impact_cpd = TabularCPD(
            variable="mission_impact",
            variable_card=3,
            values=[[0.5], [0.35], [0.15]],
            state_names={"mission_impact": ["degraded", "crippled", "mev"]},
        )

        risk_cpd = TabularCPD(
            variable="risk",
            variable_card=4,
            values=[
                [0.7] + [0.5] * 80 + [0.3] * 80 + [0.1] * 163,
                [0.2] + [0.3] * 80 + [0.4] * 80 + [0.3] * 163,
                [0.08] + [0.15] * 80 + [0.2] * 80 + [0.4] * 163,
                [0.02] + [0.05] * 80 + [0.1] * 80 + [0.2] * 163,
            ],
            evidence=[
                "exploitation",
                "exposure",
                "utility",
                "safety_impact",
                "mission_impact",
            ],
            evidence_card=[3, 3, 3, 4, 3],
            state_names={
                "risk": ["low", "medium", "high", "critical"],
                "exploitation": ["none", "poc", "active"],
                "exposure": ["controlled", "limited", "open"],
                "utility": ["laborious", "efficient", "super_effective"],
                "safety_impact": ["negligible", "marginal", "major", "hazardous"],
                "mission_impact": ["degraded", "crippled", "mev"],
            },
        )

        self.model.add_cpds(
            exploitation_cpd,
            exposure_cpd,
            utility_cpd,
            safety_impact_cpd,
            mission_impact_cpd,
            risk_cpd,
        )

        if not self.model.check_model():
            logger.error("BN-LR Hybrid: Bayesian Network model validation failed")

    def _init_lr_classifier(self, config: Mapping[str, Any]) -> None:
        """Initialize Logistic Regression classifier.

        In production, this would be trained on KEV positives vs. negatives.
        For now, we use a simple heuristic-based classifier.
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("sklearn not available, using heuristic LR fallback")
            self.lr_classifier = None
            return

        self.lr_classifier = None  # Would be: joblib.load(model_path)

        self.lr_feature_names = [
            "bn_p_low",
            "bn_p_medium",
            "bn_p_high",
            "bn_p_critical",
            "kev_listed",
            "epss_high",
            "cvss_high",
            "exploit_complexity_low",
        ]

    def _extract_bn_evidence(
        self,
        *,
        cve_records: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
        enrichment_map: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, str]:
        """Extract evidence from inputs for BN inference."""
        evidence: Dict[str, str] = {}

        if enrichment_map:
            has_kev = any(
                isinstance(e, Mapping) and e.get("kev_listed")
                for e in enrichment_map.values()
            )
            has_exploitdb = any(
                isinstance(e, Mapping) and (e.get("exploitdb_refs") or 0) > 0
                for e in enrichment_map.values()
            )

            if has_kev:
                evidence["exploitation"] = "active"
            elif has_exploitdb:
                evidence["exploitation"] = "poc"
            else:
                evidence["exploitation"] = "none"

        if context:
            exposure_val = str(context.get("exposure") or "controlled").lower()
            if exposure_val in ("controlled", "limited", "open"):
                evidence["exposure"] = exposure_val

            utility_val = str(context.get("utility") or "efficient").lower()
            if utility_val in ("laborious", "efficient", "super_effective"):
                evidence["utility"] = utility_val

            safety_val = str(context.get("safety_impact") or "negligible").lower()
            if safety_val in ("negligible", "marginal", "major", "hazardous"):
                evidence["safety_impact"] = safety_val

            mission_val = str(context.get("mission_impact") or "degraded").lower()
            if mission_val in ("degraded", "crippled", "mev"):
                evidence["mission_impact"] = mission_val

        return evidence

    def _extract_raw_features(
        self,
        *,
        cve_records: Sequence[Mapping[str, Any]],
        enrichment_map: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, float]:
        """Extract raw features for LR classifier."""
        features: Dict[str, float] = {}

        features["kev_listed"] = 0.0
        if enrichment_map:
            features["kev_listed"] = float(
                any(
                    isinstance(e, Mapping) and e.get("kev_listed")
                    for e in enrichment_map.values()
                )
            )

        features["epss_high"] = 0.0
        if enrichment_map:
            features["epss_high"] = float(
                any(
                    isinstance(e, Mapping) and (e.get("epss_score") or 0.0) >= 0.7
                    for e in enrichment_map.values()
                )
            )

        features["cvss_high"] = 0.0
        if enrichment_map:
            features["cvss_high"] = float(
                any(
                    isinstance(e, Mapping) and (e.get("cvss_score") or 0.0) >= 7.0
                    for e in enrichment_map.values()
                )
            )

        features["exploit_complexity_low"] = 0.0

        return features

    def predict(
        self,
        *,
        sbom_components: Sequence[Mapping[str, Any]],
        sarif_findings: Sequence[Mapping[str, Any]],
        cve_records: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
        enrichment_map: Optional[Mapping[str, Any]] = None,
    ) -> ModelPrediction:
        """Make prediction using BN-LR hybrid approach."""
        start_time = time.time()

        if not PGMPY_AVAILABLE or not hasattr(self, "model"):
            raise RuntimeError("BN-LR Hybrid model not available (pgmpy missing)")

        evidence = self._extract_bn_evidence(
            cve_records=cve_records,
            context=context,
            enrichment_map=enrichment_map,
        )

        try:
            inference = VariableElimination(self.model)
            result = inference.query(["risk"], evidence=evidence)

            bn_distribution = {
                state: float(prob)
                for state, prob in zip(result.state_names["risk"], result.values)
            }
        except Exception as exc:
            logger.error("BN inference failed in BN-LR hybrid: %s", exc, exc_info=True)
            raise RuntimeError(f"BN inference failed: {exc}") from exc

        raw_features = self._extract_raw_features(
            cve_records=cve_records,
            enrichment_map=enrichment_map,
        )

        lr_features = {
            "bn_p_low": bn_distribution["low"],
            "bn_p_medium": bn_distribution["medium"],
            "bn_p_high": bn_distribution["high"],
            "bn_p_critical": bn_distribution["critical"],
            **raw_features,
        }

        if self.lr_classifier is not None and SKLEARN_AVAILABLE:
            feature_vector = np.array([[lr_features[f] for f in self.lr_feature_names]])
            risk_score = float(self.lr_classifier.predict_proba(feature_vector)[0][1])
            confidence = 0.85  # High confidence with trained model
        else:
            risk_score = (
                0.15 * bn_distribution["low"]
                + 0.45 * bn_distribution["medium"]
                + 0.75 * bn_distribution["high"]
                + 0.95 * bn_distribution["critical"]
                + 0.25 * raw_features["kev_listed"]
                + 0.15 * raw_features["epss_high"]
                + 0.10 * raw_features["cvss_high"]
            )
            risk_score = min(1.0, risk_score)
            confidence = 0.75  # Moderate confidence with heuristic

        verdict = compute_verdict(
            risk_score,
            allow_threshold=self.allow_threshold,
            block_threshold=self.block_threshold,
        )

        execution_time_ms = (time.time() - start_time) * 1000

        return ModelPrediction(
            model_id=self.metadata.model_id,
            model_version=self.metadata.version,
            risk_score=risk_score,
            verdict=verdict,
            confidence=confidence,
            explanation={
                "method": "bn_lr_hybrid",
                "bn_evidence": evidence,
                "bn_posteriors": {k: round(v, 4) for k, v in bn_distribution.items()},
                "raw_features": {k: round(v, 4) for k, v in raw_features.items()},
                "lr_features": {k: round(v, 4) for k, v in lr_features.items()},
                "trained_model_used": self.lr_classifier is not None,
            },
            features_used=list(lr_features.keys()),
            execution_time_ms=execution_time_ms,
        )

    def is_available(self) -> bool:
        """Check if dependencies are available."""
        return PGMPY_AVAILABLE and hasattr(self, "model")
