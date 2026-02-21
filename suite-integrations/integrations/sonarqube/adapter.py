"""SonarQube adapter translating issues into FixOps decisions."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping

import structlog
from core.services.enterprise.decision_engine import (
    DecisionContext,
    DecisionEngine,
    DecisionResult,
)

logger = structlog.get_logger()


class SonarQubeAdapter:
    """Normalize SonarQube issues and forward them to the decision engine."""

    def __init__(self, decision_engine: DecisionEngine | None = None) -> None:
        self._engine = decision_engine or DecisionEngine()

    async def ingest(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        findings = list(self._normalize(payload.get("issues") or []))
        context = DecisionContext(
            service_name=payload.get("service_name", "sonarqube-scan"),
            environment=payload.get("environment", "unknown"),
            business_context=payload.get("business_context", {}),
            security_findings=findings,
        )
        result: DecisionResult = await self._engine.make_decision(context)
        logger.info(
            "fixops.sonarqube_adapter.decision",
            verdict=result.decision.value,
            confidence=result.confidence_score,
            findings=len(findings),
        )
        return {
            "verdict": result.decision.value,
            "confidence": result.confidence_score,
            "evidence_id": result.evidence_id,
            "reasoning": result.reasoning,
            "consensus_details": result.consensus_details,
            "mode": getattr(result, "mode", "production"),
        }

    def _normalize(self, issues: Iterable[Mapping[str, Any]]):
        for issue in issues:
            if not isinstance(issue, Mapping):
                continue
            yield {
                "id": issue.get("key"),
                "severity": str(issue.get("severity") or "medium").lower(),
                "type": issue.get("type"),
                "component": issue.get("component"),
                "message": issue.get("message"),
            }
