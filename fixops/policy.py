"""Policy automation planner for FixOps."""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from fixops.configuration import OverlayConfig


class PolicyAutomation:
    """Determine policy-driven follow-up actions."""

    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.settings = overlay.policy_settings
        self.actions_config = [action for action in self.settings.get("actions", []) if isinstance(action, Mapping)]

    def _render_action(self, action: Mapping[str, Any], pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
        rendered = dict(action)
        if action.get("type") == "jira_issue":
            rendered.setdefault("project_key", self.overlay.jira.get("project_key"))
            rendered.setdefault("issue_type", self.overlay.jira.get("default_issue_type", "Task"))
        if action.get("type") == "confluence_page":
            rendered.setdefault("space", self.overlay.confluence.get("space_key"))
        return rendered

    def _should_trigger(self, trigger: str, pipeline_result: Mapping[str, Any], context_summary: Optional[Mapping[str, Any]], compliance_status: Optional[Mapping[str, Any]]) -> bool:
        if trigger == "guardrail:fail":
            return pipeline_result.get("guardrail_evaluation", {}).get("status") == "fail"
        if trigger == "guardrail:warn":
            return pipeline_result.get("guardrail_evaluation", {}).get("status") == "warn"
        if trigger == "context:high":
            if not context_summary:
                return False
            highest = context_summary.get("summary", {}).get("highest_score", 0)
            threshold = int(self.settings.get("context_high_threshold", 7))
            return highest >= threshold
        if trigger == "compliance:gap":
            return bool(compliance_status and compliance_status.get("gaps"))
        return False

    def plan(
        self,
        pipeline_result: Mapping[str, Any],
        context_summary: Optional[Mapping[str, Any]],
        compliance_status: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        actions: List[Dict[str, Any]] = []
        for action in self.actions_config:
            trigger = str(action.get("trigger"))
            if self._should_trigger(trigger, pipeline_result, context_summary, compliance_status):
                actions.append(self._render_action(action, pipeline_result))
        return {"actions": actions}


__all__ = ["PolicyAutomation"]
