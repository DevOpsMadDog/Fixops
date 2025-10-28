"""Decision tree orchestrator for CVE exploitation analysis."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from compliance.mapping import (
    ComplianceMappingResult,
    load_control_mappings,
    map_cve_to_controls,
)
from risk.enrichment import EnrichmentEvidence, compute_enrichment
from risk.forecasting import ForecastResult, compute_forecast
from risk.threat_model import ThreatModelResult, compute_threat_model

logger = logging.getLogger(__name__)


@dataclass
class DecisionTreeResult:
    """Complete decision tree result for a CVE."""

    cve_id: str

    enrichment: Optional[EnrichmentEvidence] = None

    forecast: Optional[ForecastResult] = None

    threat_model: Optional[ThreatModelResult] = None

    compliance: Optional[ComplianceMappingResult] = None

    llm_explanation: str = ""
    llm_confidence: float = 0.0
    llm_consensus: Optional[Dict[str, Any]] = None

    verdict: str = "needs_review"  # exploitable, not_exploitable, needs_review
    verdict_confidence: float = 0.0
    verdict_reasoning: List[str] = field(default_factory=list)

    legacy_verdict: str = "defer"  # allow, block, defer

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "enrichment": self.enrichment.to_dict() if self.enrichment else None,
            "forecast": self.forecast.to_dict() if self.forecast else None,
            "threat_model": self.threat_model.to_dict() if self.threat_model else None,
            "compliance": self.compliance.to_dict() if self.compliance else None,
            "llm_explanation": self.llm_explanation,
            "llm_confidence": round(self.llm_confidence, 3),
            "llm_consensus": self.llm_consensus,
            "verdict": self.verdict,
            "verdict_confidence": round(self.verdict_confidence, 3),
            "verdict_reasoning": list(self.verdict_reasoning),
            "legacy_verdict": self.legacy_verdict,
        }


class DecisionTreeOrchestrator:
    """Orchestrates the 6-step decision tree for CVE exploitation analysis."""

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        overlay: Optional[Mapping[str, Any]] = None,
    ):
        """Initialize decision tree orchestrator.

        Parameters
        ----------
        config:
            Optional configuration dictionary.
        overlay:
            Optional overlay configuration.
        """
        self.config = config or {}
        self.overlay = overlay or {}

        dt_config = self.overlay.get("decision_tree", {})
        self.thresholds = dt_config.get("thresholds", {})

        self.not_exploitable_max = self.thresholds.get("not_exploitable_max", 0.15)
        self.exploitable_min = self.thresholds.get("exploitable_min", 0.70)
        self.require_attack_path = self.thresholds.get("require_attack_path", True)
        self.min_confidence = self.thresholds.get("min_confidence", 0.60)

        self.control_mappings = load_control_mappings(self.overlay)

        logger.info(
            "Initialized DecisionTreeOrchestrator with thresholds: "
            "not_exploitable_max=%.2f, exploitable_min=%.2f, require_attack_path=%s",
            self.not_exploitable_max,
            self.exploitable_min,
            self.require_attack_path,
        )

    def analyze(
        self,
        cve_feed: List[Mapping[str, Any]],
        exploit_signals: Optional[Mapping[str, Any]] = None,
        graph: Optional[Mapping[str, Any]] = None,
        cnapp_exposures: Optional[List[Mapping[str, Any]]] = None,
        llm_results: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, DecisionTreeResult]:
        """Run complete 6-step decision tree analysis.

        Parameters
        ----------
        cve_feed:
            List of CVE records from NVD or other sources.
        exploit_signals:
            Optional exploit signals (KEV, EPSS, ExploitDB).
        graph:
            Optional knowledge graph with components and vulnerabilities.
        cnapp_exposures:
            Optional CNAPP exposure findings.
        llm_results:
            Optional LLM analysis results from EnhancedDecisionEngine.

        Returns
        -------
        Dict[str, DecisionTreeResult]
            Mapping of CVE ID to complete decision tree result.
        """
        logger.info("Starting decision tree analysis for %d CVEs", len(cve_feed))

        logger.info("Step 1: Computing enrichment evidence...")
        enrichment_map = compute_enrichment(cve_feed, exploit_signals)

        logger.info("Step 2: Computing exploitation forecasts...")
        forecast_map = compute_forecast(enrichment_map, self.config)

        logger.info("Step 3: Computing threat models...")
        threat_map = compute_threat_model(enrichment_map, graph, cnapp_exposures)

        logger.info("Step 4: Mapping to compliance controls...")
        required_frameworks = self.overlay.get("required_frameworks", [])
        compliance_map = map_cve_to_controls(
            enrichment_map,
            self.control_mappings,
            required_frameworks,
        )

        logger.info("Steps 5 & 6: Computing final verdicts...")
        results: Dict[str, DecisionTreeResult] = {}

        for cve_id in enrichment_map.keys():
            enrichment = enrichment_map.get(cve_id)
            forecast = forecast_map.get(cve_id)
            threat_model = threat_map.get(cve_id)
            compliance = compliance_map.get(cve_id)

            llm_result = llm_results.get(cve_id, {}) if llm_results else {}
            llm_explanation = llm_result.get("explanation", "")
            llm_confidence = llm_result.get("confidence", 0.0)
            llm_consensus = llm_result.get("consensus")

            verdict, verdict_confidence, reasoning = self._compute_verdict(
                enrichment,
                forecast,
                threat_model,
                compliance,
                llm_confidence,
            )

            legacy_verdict = self._map_to_legacy_verdict(verdict)

            result = DecisionTreeResult(
                cve_id=cve_id,
                enrichment=enrichment,
                forecast=forecast,
                threat_model=threat_model,
                compliance=compliance,
                llm_explanation=llm_explanation,
                llm_confidence=llm_confidence,
                llm_consensus=llm_consensus,
                verdict=verdict,
                verdict_confidence=verdict_confidence,
                verdict_reasoning=reasoning,
                legacy_verdict=legacy_verdict,
            )

            results[cve_id] = result

        verdict_counts = {}
        for result in results.values():
            verdict_counts[result.verdict] = verdict_counts.get(result.verdict, 0) + 1

        logger.info(
            "Decision tree analysis complete: %d CVEs analyzed, verdicts: %s",
            len(results),
            verdict_counts,
        )

        return results

    def _compute_verdict(
        self,
        enrichment: Optional[EnrichmentEvidence],
        forecast: Optional[ForecastResult],
        threat_model: Optional[ThreatModelResult],
        compliance: Optional[ComplianceMappingResult],
        llm_confidence: float,
    ) -> tuple[str, float, List[str]]:
        """Compute final verdict based on all evidence.

        Parameters
        ----------
        enrichment:
            Enrichment evidence.
        forecast:
            Forecast result.
        threat_model:
            Threat model result.
        compliance:
            Compliance mapping result.
        llm_confidence:
            LLM confidence score.

        Returns
        -------
        tuple[str, float, List[str]]
            Verdict, confidence, and reasoning.
        """
        reasoning: List[str] = []

        if not enrichment or not forecast or not threat_model:
            return "needs_review", 0.0, ["Insufficient data for verdict"]

        p_exploit = forecast.p_exploit_now

        if enrichment.kev_listed:
            reasoning.append("Listed in CISA KEV catalog (known exploitation)")
            p_exploit = max(p_exploit, 0.85)

        if threat_model.attack_path_found:
            reasoning.append(f"Attack path found: {threat_model.vector_explanation}")
            p_exploit = max(p_exploit, 0.70)
        elif self.require_attack_path and p_exploit > self.exploitable_min:
            reasoning.append("No clear attack path found, reducing confidence")
            p_exploit *= 0.7

        if threat_model.reachability_score > 0.7:
            reasoning.append(
                f"High reachability score ({threat_model.reachability_score:.2f})"
            )
        elif threat_model.reachability_score < 0.3:
            reasoning.append(
                f"Low reachability score ({threat_model.reachability_score:.2f})"
            )
            p_exploit *= 0.5

        if enrichment.has_vendor_advisory:
            reasoning.append("Vendor patch/advisory available")
            p_exploit *= 0.8

        if compliance and compliance.compliance_gaps:
            reasoning.append(
                f"Compliance gaps: {', '.join(compliance.compliance_gaps[:2])}"
            )

        if llm_confidence < self.min_confidence:
            reasoning.append(
                f"Low LLM confidence ({llm_confidence:.2f}), requires expert review"
            )

        verdict_confidence = (forecast.confidence + llm_confidence) / 2.0

        if p_exploit <= self.not_exploitable_max:
            verdict = "not_exploitable"
            reasoning.insert(0, f"Low exploitation probability ({p_exploit:.2f})")
        elif p_exploit >= self.exploitable_min:
            verdict = "exploitable"
            reasoning.insert(0, f"High exploitation probability ({p_exploit:.2f})")
        else:
            verdict = "needs_review"
            reasoning.insert(
                0,
                f"Moderate exploitation probability ({p_exploit:.2f}), requires expert review",
            )

        if verdict_confidence < self.min_confidence:
            verdict = "needs_review"

        return verdict, verdict_confidence, reasoning

    def _map_to_legacy_verdict(self, verdict: str) -> str:
        """Map new verdict to legacy verdict for backward compatibility.

        Parameters
        ----------
        verdict:
            New verdict (exploitable, not_exploitable, needs_review).

        Returns
        -------
        str
            Legacy verdict (allow, block, defer).
        """
        mapping = {
            "exploitable": "block",
            "not_exploitable": "allow",
            "needs_review": "defer",
        }
        return mapping.get(verdict, "defer")


__all__ = ["DecisionTreeResult", "DecisionTreeOrchestrator"]
