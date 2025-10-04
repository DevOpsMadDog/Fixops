"""Policy automation planner for FixOps."""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

from fixops.configuration import OverlayConfig


class _AutomationDispatcher:
    """Persist dispatched actions for auditability and downstream sync."""

    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.settings = overlay.policy_settings
        directories = overlay.data_directories
        base = directories.get("automation_dir")
        if base is None:
            root = overlay.allowed_data_roots[0] if overlay.allowed_data_roots else Path("data").resolve()
            base = (root / "automation" / overlay.mode).resolve()
        self.base_dir = base
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def dispatch(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        identifier = action.get("id") or uuid.uuid4().hex
        filename = f"{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}-{identifier}.json"
        payload = {
            "id": identifier,
            "type": action.get("type"),
            "target": action.get("project_key") or action.get("space") or action.get("endpoint"),
            "payload": dict(action),
            "dispatched_at": datetime.utcnow().isoformat() + "Z",
        }
        path = self.base_dir / filename
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {"status": "dispatched", "id": identifier, "path": str(path)}


class PolicyAutomation:
    """Determine and execute policy-driven follow-up actions."""

    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.settings = overlay.policy_settings
        actions = self.settings.get("actions", [])
        self.actions_config = [action for action in actions if isinstance(action, Mapping)]
        self.dispatcher = _AutomationDispatcher(overlay)

    def _render_action(
        self,
        action: Mapping[str, Any],
        pipeline_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        rendered: Dict[str, Any] = {k: v for k, v in action.items() if k != "trigger"}
        rendered.setdefault("id", uuid.uuid4().hex)
        rendered.setdefault("context", pipeline_result.get("severity_overview"))
        if rendered.get("type") == "jira_issue":
            rendered.setdefault("project_key", self.overlay.jira.get("project_key"))
            rendered.setdefault("issue_type", self.overlay.jira.get("default_issue_type", "Task"))
        if rendered.get("type") == "confluence_page":
            rendered.setdefault("space", self.overlay.confluence.get("space_key"))
        return rendered

    def _should_trigger(
        self,
        trigger: str,
        pipeline_result: Mapping[str, Any],
        context_summary: Optional[Mapping[str, Any]],
        compliance_status: Optional[Mapping[str, Any]],
    ) -> bool:
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
        planned: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        for action in self.actions_config:
            trigger = str(action.get("trigger") or "").strip().lower()
            if self._should_trigger(trigger, pipeline_result, context_summary, compliance_status):
                planned.append(self._render_action(action, pipeline_result))
            else:
                skipped.append({"id": action.get("id"), "reason": f"trigger '{trigger}' not met"})
        status = "ready" if planned else "idle"
        return {"actions": planned, "skipped": skipped, "status": status}

    def execute(
        self,
        planned_actions: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        for action in planned_actions:
            try:
                outcome = self.dispatcher.dispatch(action)
            except Exception as exc:  # pragma: no cover - defensive logging
                outcome = {"status": "failed", "error": str(exc), "id": action.get("id")}
            results.append(outcome)
        dispatched = [result for result in results if result.get("status") == "dispatched"]
        failed = [result for result in results if result.get("status") != "dispatched"]
        summary: MutableMapping[str, Any] = {
            "dispatched_count": len(dispatched),
            "failed_count": len(failed),
            "results": results,
        }
        summary["status"] = "completed" if not failed else "partial"
        return dict(summary)


__all__ = ["PolicyAutomation"]
