"""Jenkins push ingest adapter."""

from __future__ import annotations

from typing import Any, Dict, Mapping

import structlog
from core.services.enterprise import signing
from core.services.enterprise.decision_engine import DecisionEngine

logger = structlog.get_logger()


class JenkinsCIAdapter:
    """Accept SARIF/SBOM payloads from Jenkins and return signed verdicts."""

    def __init__(self, decision_engine: DecisionEngine | None = None) -> None:
        self._engine = decision_engine or DecisionEngine()

    def ingest(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        submission = self._normalize(payload)
        outcome = self._engine.evaluate(submission)
        logger.info(
            "fixops.jenkins_adapter.decision",
            verdict=outcome.verdict,
            confidence=outcome.confidence,
            evidence=outcome.evidence.evidence_id,
        )
        decision = {
            "verdict": outcome.verdict,
            "confidence": outcome.confidence,
            "evidence_id": outcome.evidence.evidence_id,
            "evidence": outcome.evidence.manifest,
            "compliance": outcome.compliance,
            "top_factors": outcome.top_factors,
            "marketplace_recommendations": outcome.marketplace_recommendations,
        }
        try:
            signature = signing.sign_manifest(decision)
            decision.update(signature)
        except signing.SigningError:
            decision.update(
                {
                    "signature": None,
                    "kid": None,
                    "alg": signing.ALGORITHM,
                    "digest": None,
                }
            )
        return decision

    def _normalize(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        findings = []
        controls = payload.get("controls") or []
        if isinstance(payload.get("sarif"), Mapping):
            for run in payload["sarif"].get("runs", []):
                if not isinstance(run, Mapping):
                    continue
                for result in run.get("results", []) or []:
                    if not isinstance(result, Mapping):
                        continue
                    findings.append(
                        {
                            "title": (
                                result.get("message", {}).get("text")
                                if isinstance(result.get("message"), Mapping)
                                else result.get("message")
                            ),
                            "severity": str(result.get("level") or "medium").lower(),
                        }
                    )
        if isinstance(payload.get("sbom"), Mapping):
            for component in payload["sbom"].get("components", []) or []:
                if not isinstance(component, Mapping):
                    continue
                findings.append(
                    {
                        "title": component.get("name"),
                        "severity": "medium" if component.get("critical") else "low",
                    }
                )
        return {"findings": findings, "controls": controls}
