"""SonarQube adapter translating issues into FixOps decisions."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping

import structlog

from src.services.decision_engine import DecisionEngine

logger = structlog.get_logger()


class SonarQubeAdapter:
    """Normalize SonarQube issues and forward them to the decision engine."""

    def __init__(self, decision_engine: DecisionEngine | None = None) -> None:
        self._engine = decision_engine or DecisionEngine()

    def ingest(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        findings = list(self._normalize(payload.get("issues") or []))
        submission = {"findings": findings, "controls": payload.get("controls") or []}
        outcome = self._engine.evaluate(submission)
        logger.info(
            "fixops.sonarqube_adapter.decision",
            verdict=outcome.verdict,
            confidence=outcome.confidence,
            findings=len(findings),
        )
        return {
            "verdict": outcome.verdict,
            "confidence": outcome.confidence,
            "evidence_id": outcome.evidence.evidence_id,
            "evidence": outcome.evidence.manifest,
            "compliance": outcome.compliance,
            "top_factors": outcome.top_factors,
            "marketplace_recommendations": outcome.marketplace_recommendations,
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

