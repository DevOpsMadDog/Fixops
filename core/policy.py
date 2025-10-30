"""Policy automation planner for FixOps."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

import requests  # type: ignore[import-untyped]

from core.configuration import OverlayConfig
from core.connectors import AutomationConnectors
from core.paths import ensure_secure_directory


class _OPAClient:
    """Best-effort OPA/Rego client supporting remote and demo evaluation."""

    def __init__(self, settings: Mapping[str, Any] | None) -> None:
        self.settings = dict(settings or {})
        self.url = self.settings.get("url") or self.settings.get("endpoint")
        self.policy_package = self.settings.get("package", "fixops")
        self.token = self.settings.get("token")
        self.timeout = float(self.settings.get("timeout", 5.0))
        self.enabled = bool(self.url)

    def evaluate(
        self, policy: str, payload: Mapping[str, Any]
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        try:
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            response = requests.post(
                f"{self.url}/v1/data/{self.policy_package}/{policy}",
                json={"input": payload},
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            document = response.json()
        except requests.RequestException as exc:  # pragma: no cover - network failure
            return {"policy": policy, "error": str(exc), "status": "failed"}
        result = document.get("result") if isinstance(document, Mapping) else None
        if isinstance(result, Mapping):
            return {"policy": policy, "result": result, "status": "ok"}
        return {"policy": policy, "result": result, "status": "unknown"}


class _AutomationDispatcher:
    """Persist dispatched actions for auditability and downstream sync."""

    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.settings = overlay.policy_settings
        directories = overlay.data_directories
        base = directories.get("automation_dir")
        if base is None:
            root = (
                overlay.allowed_data_roots[0]
                if overlay.allowed_data_roots
                else Path("data").resolve()
            )
            base = (root / "automation" / overlay.mode).resolve()
        self.base_dir = ensure_secure_directory(base)

    def dispatch(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        identifier = action.get("id") or uuid.uuid4().hex
        filename = (
            f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{identifier}.json"
        )
        payload = {
            "id": identifier,
            "type": action.get("type"),
            "target": action.get("project_key")
            or action.get("space")
            or action.get("endpoint"),
            "payload": dict(action),
            "dispatched_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
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
        self.actions_config = [
            action for action in actions if isinstance(action, Mapping)
        ]
        self.dispatcher = _AutomationDispatcher(overlay)
        self.connectors = AutomationConnectors(
            {
                "jira": overlay.jira,
                "confluence": overlay.confluence,
                "policy_automation": self.settings,
            },
            overlay.toggles,
        )
        self.opa_client = _OPAClient(self.settings.get("opa"))

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
            rendered.setdefault(
                "issue_type", self.overlay.jira.get("default_issue_type", "Task")
            )
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
            return (
                pipeline_result.get("guardrail_evaluation", {}).get("status") == "fail"
            )
        if trigger == "guardrail:warn":
            return (
                pipeline_result.get("guardrail_evaluation", {}).get("status") == "warn"
            )
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
            if self._should_trigger(
                trigger, pipeline_result, context_summary, compliance_status
            ):
                planned.append(self._render_action(action, pipeline_result))
            else:
                skipped.append(
                    {"id": action.get("id"), "reason": f"trigger '{trigger}' not met"}
                )
        status = "ready" if planned else "idle"
        plan_summary: Dict[str, Any] = {
            "actions": planned,
            "skipped": skipped,
            "status": status,
        }
        opa_evaluations = self._evaluate_with_opa(pipeline_result)
        if opa_evaluations:
            plan_summary["opa"] = opa_evaluations
        return plan_summary

    def _evaluate_with_opa(
        self, pipeline_result: Mapping[str, Any]
    ) -> Optional[Dict[str, Any]]:
        if not self.opa_client.enabled:
            return None
        vulnerability_input = {
            "vulnerabilities": [
                finding
                for finding in pipeline_result.get("crosswalk", [])
                if finding.get("cves")
            ],
            "severity_overview": pipeline_result.get("severity_overview"),
        }
        sbom_input = {
            "sbom": pipeline_result.get("sbom_summary"),
            "design": pipeline_result.get("design_summary"),
        }
        evaluations = {
            "vulnerability": self.opa_client.evaluate(
                "vulnerability", vulnerability_input
            ),
            "sbom": self.opa_client.evaluate("sbom", sbom_input),
        }
        return {key: value for key, value in evaluations.items() if value is not None}

    def execute(
        self,
        planned_actions: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        remote_results: List[Dict[str, Any]] = []
        for action in planned_actions:
            try:
                outcome = self.dispatcher.dispatch(action)
            except Exception as exc:  # pragma: no cover - defensive logging
                outcome = {
                    "status": "failed",
                    "error": str(exc),
                    "id": action.get("id"),
                }
            delivery = self.connectors.deliver(action)
            delivery_payload = delivery.to_dict()
            remote_results.append(delivery_payload)
            combined = dict(outcome)
            combined["delivery"] = delivery_payload
            results.append(combined)
        dispatched = [
            result for result in results if result.get("status") == "dispatched"
        ]
        failed = [result for result in results if result.get("status") != "dispatched"]
        summary: MutableMapping[str, Any] = {
            "dispatched_count": len(dispatched),
            "failed_count": len(failed),
            "results": results,
            "delivery_results": remote_results,
        }
        summary["status"] = "completed" if not failed else "partial"
        return dict(summary)


__all__ = ["PolicyAutomation"]
