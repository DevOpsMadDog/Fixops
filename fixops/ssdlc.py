"""Lifecycle evaluation across Secure SDLC stages."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING

from fixops.configuration import OverlayConfig

if TYPE_CHECKING:  # pragma: no cover - imported for static type checking only
    from backend.normalizers import NormalizedCVEFeed, NormalizedSARIF, NormalizedSBOM


@dataclass
class RequirementResult:
    key: str
    title: str
    status: str
    details: str


@dataclass
class StageResult:
    identifier: str
    name: str
    description: str
    status: str
    requirements: List[RequirementResult]


class SSDLCEvaluator:
    """Evaluate overlay-defined SSDLC requirements against pipeline artefacts."""

    def __init__(self, settings: Mapping[str, Any]):
        self.settings = dict(settings or {})
        self.stages = self._parse_stages(self.settings.get("stages", []))

    @staticmethod
    def _parse_stages(raw: Any) -> List[Dict[str, Any]]:
        stages: List[Dict[str, Any]] = []
        if isinstance(raw, Iterable):
            for entry in raw:
                if not isinstance(entry, Mapping):
                    continue
                identifier = str(entry.get("id") or entry.get("name") or "").strip()
                if not identifier:
                    continue
                requirements = []
                raw_requirements = entry.get("requirements")
                if isinstance(raw_requirements, Iterable):
                    for req in raw_requirements:
                        if isinstance(req, Mapping):
                            key = str(req.get("key") or req.get("id") or "").strip()
                            title = str(req.get("title") or req.get("name") or key)
                        else:
                            key = str(req).strip()
                            title = key
                        if not key:
                            continue
                        requirements.append({"key": key, "title": title})
                stages.append(
                    {
                        "id": identifier,
                        "name": str(entry.get("name") or identifier),
                        "description": str(entry.get("description") or ""),
                        "requirements": requirements,
                    }
                )
        return stages

    def evaluate(
        self,
        *,
        design_rows: Sequence[Mapping[str, Any]],
        sbom: "NormalizedSBOM",
        sarif: "NormalizedSARIF",
        cve: "NormalizedCVEFeed",
        pipeline_result: Mapping[str, Any],
        context_summary: Optional[Mapping[str, Any]],
        compliance_status: Optional[Mapping[str, Any]],
        policy_summary: Optional[Mapping[str, Any]],
        overlay: OverlayConfig,
    ) -> Dict[str, Any]:
        stage_outputs: List[StageResult] = []
        for stage in self.stages:
            requirements = []
            satisfied = True
            satisfied_any = False
            for requirement in stage.get("requirements", []):
                key = requirement.get("key")
                title = requirement.get("title")
                status, details = self._check_requirement(
                    key,
                    design_rows=design_rows,
                    sbom=sbom,
                    sarif=sarif,
                    cve=cve,
                    pipeline_result=pipeline_result,
                    context_summary=context_summary,
                    compliance_status=compliance_status,
                    policy_summary=policy_summary,
                    overlay=overlay,
                )
                if status == "satisfied":
                    satisfied_any = True
                else:
                    satisfied = False
                requirements.append(RequirementResult(key=key, title=title, status=status, details=details))
            if not requirements:
                stage_status = "informational"
            elif satisfied:
                stage_status = "satisfied"
            elif satisfied_any:
                stage_status = "in_progress"
            else:
                stage_status = "gap"
            stage_outputs.append(
                StageResult(
                    identifier=stage["id"],
                    name=stage["name"],
                    description=stage.get("description", ""),
                    status=stage_status,
                    requirements=requirements,
                )
            )

        summary = self._build_summary(stage_outputs)
        return {
            "summary": summary,
            "stages": [self._serialise_stage(stage) for stage in stage_outputs],
        }

    @staticmethod
    def _serialise_stage(stage: StageResult) -> Dict[str, Any]:
        return {
            "id": stage.identifier,
            "name": stage.name,
            "description": stage.description,
            "status": stage.status,
            "requirements": [
                {
                    "key": requirement.key,
                    "title": requirement.title,
                    "status": requirement.status,
                    "details": requirement.details,
                }
                for requirement in stage.requirements
            ],
        }

    @staticmethod
    def _build_summary(stages: Sequence[StageResult]) -> Dict[str, Any]:
        totals = {
            "total_stages": len(stages),
            "satisfied": 0,
            "in_progress": 0,
            "gaps": 0,
            "informational": 0,
        }
        recommendations: List[str] = []
        for stage in stages:
            if stage.status in totals:
                totals[stage.status] += 1
            if stage.status == "gap":
                recommendations.append(f"Close requirements for {stage.name} stage")
            elif stage.status == "in_progress":
                recommendations.append(f"Complete outstanding items for {stage.name} stage")
        summary = totals
        if recommendations:
            summary["recommendations"] = recommendations
        return summary

    def _check_requirement(
        self,
        key: str,
        *,
        design_rows: Sequence[Mapping[str, Any]],
        sbom: "NormalizedSBOM",
        sarif: "NormalizedSARIF",
        cve: "NormalizedCVEFeed",
        pipeline_result: Mapping[str, Any],
        context_summary: Optional[Mapping[str, Any]],
        compliance_status: Optional[Mapping[str, Any]],
        policy_summary: Optional[Mapping[str, Any]],
        overlay: OverlayConfig,
    ) -> Tuple[str, str]:
        key = str(key or "").lower()
        evaluators = {
            "design": self._check_design,
            "threat_model": self._check_threat_model,
            "ai_register": self._check_ai_register,
            "sbom": self._check_sbom,
            "dependency_pinning": self._check_dependency_pinning,
            "sarif": self._check_sarif,
            "guardrails": self._check_guardrails,
            "cve": self._check_cve,
            "policy_automation": self._check_policy_automation,
            "compliance": self._check_compliance,
            "deploy_approvals": self._check_deploy_approvals,
            "evidence": self._check_evidence,
            "observability": self._check_observability,
            "feedback_loop": self._check_feedback_loop,
        }
        evaluator = evaluators.get(key)
        if evaluator is None:
            return "unknown", "No evaluator registered for requirement"
        return evaluator(
            design_rows=design_rows,
            sbom=sbom,
            sarif=sarif,
            cve=cve,
            pipeline_result=pipeline_result,
            context_summary=context_summary,
            compliance_status=compliance_status,
            policy_summary=policy_summary,
            overlay=overlay,
        )

    @staticmethod
    def _check_design(**kwargs: Any) -> Tuple[str, str]:
        rows: Sequence[Mapping[str, Any]] = kwargs.get("design_rows", [])
        count = sum(1 for row in rows if isinstance(row, Mapping))
        if count:
            return "satisfied", f"{count} design components documented"
        return "gap", "No design context uploaded"

    @staticmethod
    def _check_threat_model(**kwargs: Any) -> Tuple[str, str]:
        rows: Sequence[Mapping[str, Any]] = kwargs.get("design_rows", [])
        documented = 0
        for row in rows:
            for key, value in row.items():
                if "threat" in str(key).lower() or "model" in str(key).lower():
                    if isinstance(value, str) and value.strip():
                        documented += 1
                        break
        if documented:
            return "satisfied", f"Threat modelling captured for {documented} components"
        return "gap", "No threat modelling fields present in design artefacts"

    @staticmethod
    def _check_ai_register(**kwargs: Any) -> Tuple[str, str]:
        analysis = kwargs.get("pipeline_result", {}).get("ai_agent_analysis")
        if analysis and analysis.get("matches"):
            frameworks = analysis.get("summary", {}).get("frameworks_detected", [])
            return "satisfied", f"Agent frameworks registered: {', '.join(frameworks) or 'detected'}"
        return "in_progress", "No agent frameworks detected in current run"

    @staticmethod
    def _check_sbom(**kwargs: Any) -> Tuple[str, str]:
        sbom = kwargs.get("sbom")
        component_count = getattr(sbom, "metadata", {}).get("component_count") if hasattr(sbom, "metadata") else None
        try:
            total = int(component_count)
        except Exception:
            total = len(getattr(sbom, "components", []) or [])
        if total:
            return "satisfied", f"SBOM contains {total} components"
        return "gap", "SBOM missing or empty"

    @staticmethod
    def _check_dependency_pinning(**kwargs: Any) -> Tuple[str, str]:
        sbom = kwargs.get("sbom")
        components = getattr(sbom, "components", []) or []
        if not components:
            return "gap", "No components available to assess dependency pinning"
        pinned = 0
        for component in components:
            version = getattr(component, "version", None)
            purl = getattr(component, "purl", None)
            if version or purl:
                pinned += 1
        coverage = pinned / len(components)
        if pinned and coverage >= 0.6:
            return "satisfied", f"{coverage:.0%} of components pinned"
        if pinned:
            return "in_progress", f"Only {coverage:.0%} of components pinned"
        return "gap", "No components include versions or package URLs"

    @staticmethod
    def _check_sarif(**kwargs: Any) -> Tuple[str, str]:
        sarif = kwargs.get("sarif")
        findings = getattr(sarif, "findings", []) or []
        if findings:
            return "satisfied", f"{len(findings)} static analysis findings processed"
        metadata = getattr(sarif, "metadata", {}) if hasattr(sarif, "metadata") else {}
        count = metadata.get("finding_count")
        if count:
            return "satisfied", f"{count} findings recorded"
        return "gap", "No SARIF scan results provided"

    @staticmethod
    def _check_guardrails(**kwargs: Any) -> Tuple[str, str]:
        evaluation = kwargs.get("pipeline_result", {}).get("guardrail_evaluation")
        if evaluation:
            status = evaluation.get("status")
            if status == "fail":
                return "gap", "Guardrail failure requires remediation"
            return "satisfied", f"Guardrail status: {status}"
        return "gap", "Guardrail evaluation missing"

    @staticmethod
    def _check_cve(**kwargs: Any) -> Tuple[str, str]:
        cve_feed = kwargs.get("cve")
        records = getattr(cve_feed, "records", []) or []
        if records:
            exploited = sum(1 for record in records if getattr(record, "exploited", False))
            return "satisfied", f"{len(records)} CVE records ingested ({exploited} exploited)"
        return "gap", "No CVE feed provided"

    @staticmethod
    def _check_policy_automation(**kwargs: Any) -> Tuple[str, str]:
        policy = kwargs.get("policy_summary") or {}
        if not isinstance(policy, Mapping):
            return "in_progress", "Policy automation not evaluated"
        actions = policy.get("actions") if isinstance(policy.get("actions"), list) else []
        execution = policy.get("execution") if isinstance(policy.get("execution"), Mapping) else {}
        dispatched = execution.get("dispatched_count")
        try:
            dispatched_count = int(dispatched)
        except (TypeError, ValueError):
            dispatched_count = 0
        if dispatched_count > 0:
            return "satisfied", f"{dispatched_count} policy actions dispatched"
        if actions:
            return "in_progress", "Policy actions planned but not dispatched"
        return "in_progress", "No policy automations triggered"

    @staticmethod
    def _check_compliance(**kwargs: Any) -> Tuple[str, str]:
        compliance = kwargs.get("compliance_status") or {}
        frameworks = compliance.get("frameworks") if isinstance(compliance, Mapping) else []
        if not frameworks:
            return "in_progress", "No compliance packs evaluated"
        statuses = [framework.get("status") for framework in frameworks]
        if any(status == "gap" for status in statuses):
            return "gap", "Compliance gaps detected"
        if all(status == "satisfied" for status in statuses):
            return "satisfied", "All compliance controls satisfied"
        return "in_progress", "Compliance remediation in progress"

    @staticmethod
    def _check_deploy_approvals(**kwargs: Any) -> Tuple[str, str]:
        overlay: OverlayConfig = kwargs.get("overlay")
        actions = overlay.policy_settings.get("actions", [])
        approval_actions = [
            action
            for action in actions
            if isinstance(action, Mapping)
            and action.get("type") in {"jira_issue", "confluence_page", "change_request"}
        ]
        if approval_actions:
            channels = {action.get("type") for action in approval_actions}
            return "satisfied", f"Approval hooks configured: {', '.join(sorted(str(channel) for channel in channels))}"
        return "gap", "No deployment approval hooks configured"

    @staticmethod
    def _check_evidence(**kwargs: Any) -> Tuple[str, str]:
        bundle = kwargs.get("pipeline_result", {}).get("evidence_bundle") or {}
        files = bundle.get("files") if isinstance(bundle, Mapping) else {}
        if files and files.get("bundle") and bundle.get("sections"):
            return "satisfied", "Evidence bundle persisted"
        return "gap", "Evidence bundle unavailable"

    @staticmethod
    def _check_observability(**kwargs: Any) -> Tuple[str, str]:
        bundle = kwargs.get("pipeline_result", {}).get("evidence_bundle") or {}
        sections = bundle.get("sections") if isinstance(bundle, Mapping) else []
        guardrail = kwargs.get("pipeline_result", {}).get("guardrail_evaluation") or {}
        if (
            sections
            and {"context_summary", "guardrail_evaluation"}.intersection(set(sections))
            and guardrail.get("status") in {"pass", "warn"}
        ):
            return "satisfied", "Observability artefacts captured in evidence"
        return "in_progress", "No observability artefacts attached"

    @staticmethod
    def _check_feedback_loop(**kwargs: Any) -> Tuple[str, str]:
        overlay: OverlayConfig = kwargs.get("overlay")
        if overlay.toggles.get("capture_feedback"):
            return "satisfied", "Feedback capture enabled for this profile"
        return "in_progress", "Feedback capture disabled"


__all__ = ["SSDLCEvaluator"]
