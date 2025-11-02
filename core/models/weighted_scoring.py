"""Weighted scoring model - wraps existing DecisionEngine logic."""

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


class WeightedScoringModel(RiskModel):
    """Traditional weighted severity scoring model.

    This wraps the existing DecisionEngine logic from
    fixops-blended-enterprise/src/services/decision_engine.py
    """

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        config = config or {}
        metadata = ModelMetadata(
            model_id="weighted_scoring_v1",
            model_type=ModelType.WEIGHTED_SCORING,
            version="1.0.0",
            description="Traditional weighted severity scoring (critical=1.0, high=0.75, medium=0.5, low=0.25)",
            enabled=True,
            priority=10,  # Lower priority, used as fallback
            requires_training=False,
            config=dict(config),
        )
        super().__init__(metadata)

        self.severity_weights = config.get(
            "severity_weights",
            {
                "critical": 1.0,
                "high": 0.75,
                "medium": 0.5,
                "low": 0.25,
            },
        )

        self.allow_threshold = config.get("allow_threshold", 0.6)
        self.block_threshold = config.get("block_threshold", 0.85)

    def predict(
        self,
        *,
        sbom_components: Sequence[Mapping[str, Any]],
        sarif_findings: Sequence[Mapping[str, Any]],
        cve_records: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
        enrichment_map: Optional[Mapping[str, Any]] = None,
    ) -> ModelPrediction:
        """Make prediction using weighted severity scoring."""
        start_time = time.time()

        severity_counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for cve in cve_records:
            if not isinstance(cve, Mapping):
                continue
            severity = str(cve.get("severity") or "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        for finding in sarif_findings:
            if not isinstance(finding, Mapping):
                continue
            level = str(finding.get("level") or "").lower()
            if level == "error":
                severity_counts["high"] += 1
            elif level == "warning":
                severity_counts["medium"] += 1
            elif level in ("note", "info"):
                severity_counts["low"] += 1

        kev_boost = 0.0
        if enrichment_map:
            for cve_id, evidence in enrichment_map.items():
                if isinstance(evidence, Mapping) and evidence.get("kev_listed"):
                    kev_boost += 0.2  # Boost for each KEV-listed CVE

        total_findings = sum(severity_counts.values())
        if total_findings == 0:
            risk_score = 0.0
            confidence = 0.9  # High confidence in "no risk"
        else:
            weighted_sum = sum(
                count * self.severity_weights.get(severity, 0.0)
                for severity, count in severity_counts.items()
            )
            risk_score = min(1.0, (weighted_sum / total_findings) + kev_boost)
            confidence = 0.7  # Moderate confidence in weighted scoring

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
                "method": "weighted_severity_scoring",
                "severity_counts": severity_counts,
                "total_findings": total_findings,
                "kev_boost": round(kev_boost, 3),
                "weights": self.severity_weights,
            },
            features_used=["severity", "kev_listed"],
            execution_time_ms=execution_time_ms,
        )

    def is_available(self) -> bool:
        """Weighted scoring is always available."""
        return True
