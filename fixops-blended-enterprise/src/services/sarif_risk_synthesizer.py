"""SARIF risk synthesis leveraging the SARIF toolkit."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import structlog

from src.integrations.sarif_tooling import SarifToolingAdapter

logger = structlog.get_logger()


@dataclass
class SarifRiskSummary:
    """Container for synthesized SARIF risk information."""

    clusters: List[Dict[str, Any]]
    overall_risk: float
    non_cve_findings: List[Dict[str, Any]]


class SarifRiskSynthesizer:
    """Delegate SARIF clustering and probability estimation to tooling."""

    def __init__(self, tooling: Optional[SarifToolingAdapter] = None) -> None:
        self.tooling = tooling or SarifToolingAdapter()

    async def synthesize(self, sarif_data: Optional[Dict[str, Any]]) -> SarifRiskSummary:
        if not sarif_data:
            return SarifRiskSummary(clusters=[], overall_risk=0.0, non_cve_findings=[])

        results = self._collect_results(sarif_data)
        clusters = self.tooling.cluster_results(results)

        for cluster in clusters:
            cluster_risk = self.tooling.score_cluster(cluster)
            cluster["risk_score"] = cluster_risk
            for finding in cluster.get("findings", []):
                finding["risk_score"] = self.tooling.score_finding(finding)

        non_cve = [finding for finding in results if not finding.get("cve")]
        overall_risk = self._calculate_overall_risk(clusters)

        logger.info(
            "Synthesized SARIF risk profile",
            clusters=len(clusters),
            non_cve_findings=len(non_cve),
            overall_risk=overall_risk,
        )

        return SarifRiskSummary(
            clusters=clusters,
            overall_risk=overall_risk,
            non_cve_findings=non_cve,
        )

    def _collect_results(self, sarif_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        collected: List[Dict[str, Any]] = []
        for run in sarif_data.get("runs", []):
            for result in run.get("results", []):
                collected.append(
                    {
                        "ruleId": result.get("ruleId"),
                        "level": result.get("level"),
                        "severity": result.get("properties", {}).get("securitySeverity", "MEDIUM"),
                        "confidence": result.get("properties", {}).get("confidence", 0.6),
                        "cwe_id": self._extract_tag(result, prefix="CWE-"),
                        "owasp_category": self._extract_tag(result, prefix="OWASP"),
                        "cve": result.get("properties", {}).get("cve"),
                    }
                )
        return collected

    def _calculate_overall_risk(self, clusters: List[Dict[str, Any]]) -> float:
        if not clusters:
            return 0.0
        total = sum(cluster.get("risk_score", 0.0) for cluster in clusters)
        return round(total / len(clusters), 3)

    def _extract_tag(self, result: Dict[str, Any], *, prefix: str) -> Optional[str]:
        tags = result.get("properties", {}).get("tags") or result.get("tags") or []
        for tag in tags:
            if isinstance(tag, str) and tag.startswith(prefix):
                return tag
        return None

