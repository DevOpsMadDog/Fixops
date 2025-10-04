"""Opinionated compliance pack evaluation."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional


class ComplianceEvaluator:
    """Evaluate compliance packs using pipeline artefacts."""

    def __init__(self, settings: Mapping[str, Any]):
        self.settings = dict(settings or {})
        self.frameworks = [framework for framework in self.settings.get("frameworks", []) if isinstance(framework, Mapping)]

    def _check_requirement(self, requirement: str, pipeline_result: Mapping[str, Any], context_summary: Optional[Mapping[str, Any]]) -> bool:
        requirement = str(requirement)
        if requirement == "design":
            return bool(pipeline_result.get("design_summary", {}).get("row_count"))
        if requirement == "sbom":
            metadata = pipeline_result.get("sbom_summary", {})
            return bool(metadata and metadata.get("component_count", metadata.get("componentCount")))
        if requirement == "sarif":
            metadata = pipeline_result.get("sarif_summary", {})
            return bool(metadata and metadata.get("finding_count", metadata.get("findingCount")))
        if requirement == "cve":
            return bool(pipeline_result.get("cve_summary", {}).get("exploited_count", 0) or pipeline_result.get("cve_summary", {}).get("record_count"))
        if requirement == "context":
            return bool(context_summary and context_summary.get("summary", {}).get("components_evaluated", 0))
        if requirement == "guardrails":
            status = pipeline_result.get("guardrail_evaluation", {})
            return bool(status)
        if requirement == "evidence":
            return bool(pipeline_result.get("evidence_bundle"))
        if requirement == "policy":
            return bool(pipeline_result.get("policy_automation", {}).get("actions"))
        return False

    def evaluate(
        self,
        pipeline_result: Mapping[str, Any],
        context_summary: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        frameworks_output: List[Dict[str, Any]] = []
        gaps: List[str] = []
        for framework in self.frameworks:
            controls_output: List[Dict[str, Any]] = []
            control_results: List[bool] = []
            for control in framework.get("controls", []):
                if not isinstance(control, Mapping):
                    continue
                requires: Iterable[str] = control.get("requires", [])
                satisfied_requirements = []
                missing_requirements = []
                for requirement in requires:
                    if self._check_requirement(requirement, pipeline_result, context_summary):
                        satisfied_requirements.append(requirement)
                    else:
                        missing_requirements.append(requirement)
                status = "satisfied" if not missing_requirements else "gap"
                control_results.append(status == "satisfied")
                if status == "gap":
                    gaps.append(f"{framework.get('name')}: {control.get('id')} missing {', '.join(missing_requirements)}")
                controls_output.append(
                    {
                        "id": control.get("id"),
                        "title": control.get("title"),
                        "status": status,
                        "satisfied": satisfied_requirements,
                        "missing": missing_requirements,
                    }
                )
            overall_status = "satisfied" if all(control_results) and control_results else "in_progress"
            frameworks_output.append(
                {
                    "name": framework.get("name"),
                    "status": overall_status,
                    "controls": controls_output,
                }
            )
        return {"frameworks": frameworks_output, "gaps": gaps}


__all__ = ["ComplianceEvaluator"]
