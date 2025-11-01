"""Bayesian Network model - wraps existing BN logic from processing_layer."""

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


class BayesianNetworkModel(RiskModel):
    """Bayesian Network model for risk assessment.

    Uses pgmpy to model causal dependencies among vulnerability characteristics.
    This is an improved version of the BN in core/processing_layer.py with
    proper CPDs for all nodes.
    """

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        config = config or {}
        metadata = ModelMetadata(
            model_id="bayesian_network_v1",
            model_type=ModelType.BAYESIAN_NETWORK,
            version="1.0.0",
            description="Bayesian Network with causal dependencies (exploitation, exposure, utility, safety_impact, mission_impact → risk)",
            enabled=True,
            priority=50,  # Higher priority than weighted scoring
            requires_training=False,
            config=dict(config),
        )
        super().__init__(metadata)

        self.allow_threshold = config.get("allow_threshold", 0.6)
        self.block_threshold = config.get("block_threshold", 0.85)

        self._build_network()

    def _build_network(self) -> None:
        """Build the Bayesian Network structure and CPDs."""
        if not PGMPY_AVAILABLE:
            logger.warning("pgmpy not available, BN model will not work")
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
                [0.7] + [0.5] * 80 + [0.3] * 80 + [0.1] * 162,  # low
                [0.2] + [0.3] * 80 + [0.4] * 80 + [0.3] * 162,  # medium
                [0.08] + [0.15] * 80 + [0.2] * 80 + [0.4] * 162,  # high
                [0.02] + [0.05] * 80 + [0.1] * 80 + [0.2] * 162,  # critical
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
            logger.error("Bayesian Network model validation failed")

    def _extract_evidence(
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

    def predict(
        self,
        *,
        sbom_components: Sequence[Mapping[str, Any]],
        sarif_findings: Sequence[Mapping[str, Any]],
        cve_records: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
        enrichment_map: Optional[Mapping[str, Any]] = None,
    ) -> ModelPrediction:
        """Make prediction using Bayesian Network inference."""
        start_time = time.time()

        if not PGMPY_AVAILABLE or not hasattr(self, "model"):
            raise RuntimeError("Bayesian Network model not available")

        evidence = self._extract_evidence(
            cve_records=cve_records,
            context=context,
            enrichment_map=enrichment_map,
        )

        try:
            inference = VariableElimination(self.model)
            result = inference.query(["risk"], evidence=evidence)

            distribution = {
                state: float(prob)
                for state, prob in zip(result.state_names["risk"], result.values)
            }

            risk_level_scores = {
                "low": 0.2,
                "medium": 0.5,
                "high": 0.75,
                "critical": 0.95,
            }

            risk_score = sum(
                distribution[level] * risk_level_scores[level] for level in distribution
            )

            most_likely_level = max(distribution, key=distribution.get)  # type: ignore
            confidence = distribution[most_likely_level]

        except Exception as exc:
            logger.error("BN inference failed: %s", exc, exc_info=True)
            raise RuntimeError(f"Bayesian Network inference failed: {exc}") from exc

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
                "method": "bayesian_network",
                "evidence": evidence,
                "risk_distribution": {k: round(v, 4) for k, v in distribution.items()},
                "most_likely_level": most_likely_level,
            },
            features_used=list(evidence.keys()),
            execution_time_ms=execution_time_ms,
        )

    def is_available(self) -> bool:
        """Check if pgmpy is available and model is built."""
        return PGMPY_AVAILABLE and hasattr(self, "model")
