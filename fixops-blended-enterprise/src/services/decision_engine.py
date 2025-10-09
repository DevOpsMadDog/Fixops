"""Simplified decision engine used by CI adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping

import structlog

from src.services.compliance import ComplianceEngine
from src.services.evidence import EvidenceRecord, EvidenceStore
from src.services import signing
from src.services.marketplace import get_recommendations


@dataclass
class DecisionOutcome:
    verdict: str
    confidence: float
    evidence: EvidenceRecord
    compliance: Dict[str, Any]
    top_factors: list[Dict[str, Any]]
    marketplace_recommendations: list[Dict[str, Any]]


class DecisionEngine:
    """Derive risk verdicts from normalized findings."""

    SEVERITY_WEIGHTS = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.5,
        "low": 0.25,
    }

    def __init__(self, evidence_store: EvidenceStore | None = None, compliance_engine: ComplianceEngine | None = None) -> None:
        self._evidence_store = evidence_store or EvidenceStore()
        self._compliance = compliance_engine or ComplianceEngine()
        self._logger = structlog.get_logger()

    @property
    def evidence_store(self) -> EvidenceStore:
        return self._evidence_store

    def evaluate(self, submission: Mapping[str, Any]) -> DecisionOutcome:
        findings = submission.get("findings") or []
        controls = submission.get("controls") or []
        verdict, confidence = self._score_findings(findings)
        framework_targets = submission.get("frameworks")
        opa_rules = submission.get("opa_rules")
        opa_input = submission.get("opa_input") or {"findings": findings, "controls": controls}
        compliance = self._compliance.evaluate(
            controls,
            frameworks=framework_targets,
            opa_rules=opa_rules,
            opa_input=opa_input,
        )
        top_factors = self._top_factors(findings, compliance, verdict, confidence)
        failing_controls = [
            roll.get("control_id")
            for roll in compliance.get("controls", [])
            if isinstance(roll, Mapping) and roll.get("status") in {"fail", "failed", "gap", "non_compliant"}
        ]
        marketplace_recommendations = get_recommendations(failing_controls)
        evidence_payload = {
            "findings": findings,
            "verdict": verdict,
            "confidence": confidence,
            "compliance": compliance,
            "top_factors": top_factors,
            "marketplace_recommendations": marketplace_recommendations,
        }
        evidence = self._evidence_store.create(evidence_payload)
        manifest = evidence.manifest
        if isinstance(manifest, dict):
            manifest.setdefault("evidence_url", f"/api/v1/evidence/{evidence.evidence_id}")
        self._apply_signature(evidence)
        return DecisionOutcome(
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            compliance=compliance,
            top_factors=top_factors,
            marketplace_recommendations=marketplace_recommendations,
        )

    def _score_findings(self, findings: Iterable[Mapping[str, Any]]) -> tuple[str, float]:
        if not findings:
            return "allow", 0.6
        scores = [self._weight(finding) for finding in findings]
        aggregate = sum(scores) / max(1, len(scores))
        if aggregate >= 0.85:
            return "block", min(0.99, aggregate)
        if aggregate >= 0.6:
            return "review", aggregate
        return "allow", aggregate

    def _weight(self, finding: Mapping[str, Any]) -> float:
        severity = str(finding.get("severity") or finding.get("level") or "low").lower()
        return self.SEVERITY_WEIGHTS.get(severity, 0.25)

    def _apply_signature(self, evidence: EvidenceRecord) -> None:
        try:
            signature = signing.sign_manifest(evidence.manifest)
        except signing.SigningError:
            self._logger.debug("evidence.signing.disabled")
            return
        kid = signature.get("kid") if isinstance(signature, dict) else signing.get_active_kid()
        alg = signature.get("alg") if isinstance(signature, dict) else signing.ALGORITHM
        self._evidence_store.attach_signature(evidence.evidence_id, signature, kid, alg)
        self._logger.info(
            "evidence.signed",
            evidence_id=evidence.evidence_id,
            kid=kid,
            algorithm=alg,
        )

    def _top_factors(
        self,
        findings: Iterable[Mapping[str, Any]],
        compliance: Mapping[str, Any],
        verdict: str,
        confidence: float,
    ) -> list[Dict[str, Any]]:
        findings_list = list(findings)
        if not findings_list:
            return [
                {
                    "name": "Low finding volume",
                    "weight": round(1 - confidence, 3),
                    "rationale": "No actionable findings supplied; confidence influenced by default baseline.",
                }
            ]

        severities = [str(item.get("severity") or "low").lower() for item in findings_list]
        highest = max(severities, key=lambda value: self.SEVERITY_WEIGHTS.get(value, 0.25))
        highest_weight = self.SEVERITY_WEIGHTS.get(highest, 0.25)
        factors = [
            {
                "name": f"{highest.title()} severity detected",
                "weight": round(highest_weight, 3),
                "rationale": f"Worst finding reported as {highest} which heavily influences the {verdict} verdict.",
            }
        ]

        volume_weight = min(0.35, len(findings_list) * 0.07)
        factors.append(
            {
                "name": "Finding volume",
                "weight": round(volume_weight, 3),
                "rationale": f"{len(findings_list)} normalized findings were evaluated.",
            }
        )

        framework_summary = compliance.get("frameworks", {}) if isinstance(compliance, Mapping) else {}
        failing = [
            name
            for name, stats in framework_summary.items()
            if isinstance(stats, Mapping) and stats.get("fail", 0)
        ]
        if failing:
            weight = min(0.4, 0.2 + 0.1 * len(failing))
            rationale = ", ".join(sorted(failing))
            factors.append(
                {
                    "name": "Compliance gaps",
                    "weight": round(weight, 3),
                    "rationale": f"Frameworks failing controls: {rationale}.",
                }
            )

        factors.sort(key=lambda item: (-item["weight"], item["name"]))
        return factors[:3]


__all__ = ["DecisionEngine", "DecisionOutcome"]

