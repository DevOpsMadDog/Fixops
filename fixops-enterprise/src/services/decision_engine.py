"""Simplified decision engine used by CI adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping

import structlog
from src.services import signing
from src.services.compliance import ComplianceEngine
from src.services.evidence import EvidenceRecord, EvidenceStore
from src.services.marketplace import get_recommendations


@dataclass
class DecisionOutcome:
    verdict: str
    confidence: float
    evidence: EvidenceRecord
    compliance: Dict[str, Any]
    top_factors: list[Dict[str, Any]]
    marketplace_recommendations: list[Dict[str, Any]]
    compliance_rollup: Dict[str, Any]


class DecisionEngine:
    """Derive risk verdicts from normalized findings."""

    SEVERITY_WEIGHTS = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.5,
        "low": 0.25,
    }

    def __init__(
        self,
        evidence_store: EvidenceStore | None = None,
        compliance_engine: ComplianceEngine | None = None,
    ) -> None:
        self._evidence_store = evidence_store or EvidenceStore()
        self._compliance = compliance_engine or ComplianceEngine()
        self._logger = structlog.get_logger()

    @property
    def evidence_store(self) -> EvidenceStore:
        return self._evidence_store

    def evaluate(self, submission: Mapping[str, Any]) -> DecisionOutcome:
        findings = list(submission.get("findings") or [])
        controls = submission.get("controls") or []
        verdict, confidence = self._score_findings(findings)
        framework_targets = submission.get("frameworks")
        opa_rules = submission.get("opa_rules")
        opa_input = submission.get("opa_input") or {
            "findings": findings,
            "controls": controls,
        }
        compliance = self._compliance.evaluate(
            controls,
            frameworks=framework_targets,
            opa_rules=opa_rules,
            opa_input=opa_input,
        )
        build_report = (
            submission.get("build")
            if isinstance(submission.get("build"), Mapping)
            else {}
        )
        test_report = (
            submission.get("test")
            if isinstance(submission.get("test"), Mapping)
            else {}
        )
        deploy_manifest = (
            submission.get("deploy")
            if isinstance(submission.get("deploy"), Mapping)
            else {}
        )
        operate_snapshot = (
            submission.get("operate")
            if isinstance(submission.get("operate"), Mapping)
            else {}
        )
        compliance_rollup = self._compliance_rollup(deploy_manifest)
        top_factors = self._top_factors(
            findings,
            compliance,
            compliance_rollup,
            build_report,
            test_report,
            deploy_manifest,
            operate_snapshot,
            verdict,
        )
        failing_controls = self._failing_controls(compliance, deploy_manifest)
        marketplace_recommendations = get_recommendations(failing_controls)
        evidence_payload = {
            "findings": findings,
            "verdict": verdict,
            "confidence": confidence,
            "compliance": compliance,
            "top_factors": top_factors,
            "marketplace_recommendations": marketplace_recommendations,
            "compliance_rollup": compliance_rollup,
        }
        evidence = self._evidence_store.create(evidence_payload)
        manifest = evidence.manifest
        if isinstance(manifest, dict):
            manifest.setdefault(
                "evidence_url", f"/api/v1/evidence/{evidence.evidence_id}"
            )
        self._apply_signature(evidence)
        return DecisionOutcome(
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            compliance=compliance,
            top_factors=top_factors,
            marketplace_recommendations=marketplace_recommendations,
            compliance_rollup=compliance_rollup,
        )

    def _score_findings(
        self, findings: Iterable[Mapping[str, Any]]
    ) -> tuple[str, float]:
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
        kid = (
            signature.get("kid")
            if isinstance(signature, dict)
            else signing.get_active_kid()
        )
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
        compliance_rollup: Mapping[str, Any],
        build_report: Mapping[str, Any],
        test_report: Mapping[str, Any],
        deploy_manifest: Mapping[str, Any],
        operate_snapshot: Mapping[str, Any],
        verdict: str,
    ) -> list[Dict[str, Any]]:
        factors: list[Dict[str, Any]] = []

        severity_factor = self._severity_factor(
            findings, build_report, test_report, verdict
        )
        if severity_factor:
            factors.append(severity_factor)

        compliance_factor = self._compliance_factor(compliance, compliance_rollup)
        if compliance_factor:
            factors.append(compliance_factor)

        exploit_factor = self._exploit_factor(operate_snapshot)
        if exploit_factor:
            factors.append(exploit_factor)

        if not factors:
            factors.append(
                {
                    "name": "Stable posture",
                    "weight": 0.2,
                    "rationale": "No severe findings, compliance gaps or exploit signals detected.",
                }
            )

        factors.sort(key=lambda item: (-item["weight"], item["name"]))
        return factors

    def _severity_factor(
        self,
        findings: Iterable[Mapping[str, Any]],
        build_report: Mapping[str, Any],
        test_report: Mapping[str, Any],
        verdict: str,
    ) -> Dict[str, Any] | None:
        findings_list = list(findings or [])
        severities = [
            str(item.get("severity") or "low").lower() for item in findings_list
        ]
        test_summary = (
            test_report.get("summary") if isinstance(test_report, Mapping) else {}
        )
        if isinstance(test_summary, Mapping):
            for severity in ("critical", "high", "medium", "low"):
                count = test_summary.get(severity)
                if isinstance(count, int) and count > 0:
                    severities.append(severity)
                    break
        if not severities:
            return None
        highest = max(
            severities, key=lambda value: self.SEVERITY_WEIGHTS.get(value, 0.25)
        )
        weight = round(self.SEVERITY_WEIGHTS.get(highest, 0.25), 3)
        total_findings = len(findings_list)
        return {
            "name": f"{highest.title()} severity detected",
            "weight": weight,
            "rationale": f"{total_findings} findings processed; highest severity {highest} driving {verdict} decision.",
        }

    def _compliance_factor(
        self,
        compliance: Mapping[str, Any],
        compliance_rollup: Mapping[str, Any],
    ) -> Dict[str, Any] | None:
        failing_frameworks: list[str] = []
        framework_summary = (
            compliance.get("frameworks") if isinstance(compliance, Mapping) else {}
        )
        if isinstance(framework_summary, Mapping):
            for name, stats in framework_summary.items():
                if isinstance(stats, Mapping) and stats.get("fail"):
                    failing_frameworks.append(str(name))
        coverage = []
        for item in compliance_rollup.get("frameworks", []) or []:
            if isinstance(item, Mapping) and item.get("coverage", 1) < 1:
                failing_frameworks.append(str(item.get("name")))
                coverage.append(f"{item.get('name')}={item.get('coverage')}")
        if not failing_frameworks:
            return {
                "name": "Controls satisfied",
                "weight": 0.2,
                "rationale": "All mapped controls reported as passing or partially covered.",
            }
        rationale = ", ".join(sorted({entry for entry in failing_frameworks if entry}))
        if coverage:
            rationale += f" (coverage {', '.join(coverage)})"
        return {
            "name": "Compliance gaps",
            "weight": 0.3,
            "rationale": f"Frameworks requiring remediation: {rationale}.",
        }

    def _exploit_factor(
        self, operate_snapshot: Mapping[str, Any]
    ) -> Dict[str, Any] | None:
        kev = (
            operate_snapshot.get("kev_hits")
            if isinstance(operate_snapshot, Mapping)
            else []
        )
        pressure = 0.0
        if isinstance(operate_snapshot, Mapping):
            pressure_entries = operate_snapshot.get("pressure_by_service") or []
            for entry in pressure_entries:
                if isinstance(entry, Mapping) and isinstance(
                    entry.get("pressure"), (int, float)
                ):
                    pressure = max(pressure, float(entry.get("pressure")))
        if not kev and pressure <= 0.2:
            return {
                "name": "Low exploit pressure",
                "weight": 0.15,
                "rationale": "No KEV overlap and service pressure remains minimal.",
            }
        rationale_parts = []
        if kev:
            rationale_parts.append(f"KEV overlap count: {len(kev)}")
        if pressure:
            rationale_parts.append(f"Operational pressure {pressure:.2f}")
        return {
            "name": "Exploit pressure",
            "weight": 0.25 if kev else 0.18,
            "rationale": ", ".join(rationale_parts)
            or "Telemetry indicates elevated activity.",
        }

    def _compliance_rollup(self, deploy_manifest: Mapping[str, Any]) -> Dict[str, Any]:
        controls: dict[str, float] = {}
        frameworks: dict[str, list[float]] = {}
        for evidence in deploy_manifest.get("control_evidence", []) or []:
            if not isinstance(evidence, Mapping):
                continue
            control_id = str(evidence.get("control"))
            result = str(evidence.get("result") or "pass").lower()
            coverage = 1.0 if result == "pass" else 0.5 if result == "partial" else 0.0
            controls[control_id] = coverage
            framework = control_id.split(":")[0] if ":" in control_id else "generic"
            frameworks.setdefault(framework, []).append(coverage)
        framework_rollup = [
            {"name": name, "coverage": round(sum(values) / len(values), 2)}
            for name, values in frameworks.items()
        ]
        controls_list = [
            {"id": control_id, "coverage": round(coverage, 2)}
            for control_id, coverage in sorted(controls.items())
        ]
        return {"controls": controls_list, "frameworks": framework_rollup}

    def _failing_controls(
        self, compliance: Mapping[str, Any], deploy_manifest: Mapping[str, Any]
    ) -> list[str]:
        failing: list[str] = []
        for evidence in deploy_manifest.get("control_evidence", []) or []:
            if (
                isinstance(evidence, Mapping)
                and str(evidence.get("result")).lower() == "fail"
            ):
                failing.append(str(evidence.get("control")))
        controls_section = (
            compliance.get("controls") if isinstance(compliance, Mapping) else []
        )
        for item in controls_section or []:
            if not isinstance(item, Mapping):
                continue
            if str(item.get("status")).lower() in {
                "fail",
                "failed",
                "gap",
                "non_compliant",
            }:
                failing.append(str(item.get("control_id") or item.get("id")))
        return sorted({control for control in failing if control})


__all__ = ["DecisionEngine", "DecisionOutcome"]
