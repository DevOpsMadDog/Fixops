"""Azure DevOps push-model adapter for FixOps decisions."""

from __future__ import annotations

from typing import Any, Dict, Mapping

import structlog
from src.services.decision_engine import DecisionEngine

logger = structlog.get_logger()


class AzureDevOpsAdapter:
    """Handle Azure DevOps webhook events and produce decision responses."""

    def __init__(self, decision_engine: DecisionEngine | None = None) -> None:
        self._engine = decision_engine or DecisionEngine()

    def handle_webhook(self, event: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Process Azure DevOps webhook and return decision."""
        resource = payload.get("resource") or {}
        project = self._extract_project(payload)
        pr_id = self._extract_pr(event, resource)
        decision_payload = self._build_submission(payload)
        outcome = self._engine.evaluate(decision_payload)

        logger.info(
            "fixops.azure_devops_adapter.decision",
            project=project,
            pull_request=pr_id,
            verdict=outcome.verdict,
            confidence=outcome.confidence,
            evidence=outcome.evidence.evidence_id,
        )

        return {
            "project": project,
            "pull_request": pr_id,
            "verdict": outcome.verdict,
            "confidence": outcome.confidence,
            "evidence_id": outcome.evidence.evidence_id,
            "evidence": outcome.evidence.manifest,
            "compliance": outcome.compliance,
            "top_factors": outcome.top_factors,
            "marketplace_recommendations": outcome.marketplace_recommendations,
            "status": {
                "state": "succeeded" if outcome.verdict == "allow" else "failed",
                "description": f"FixOps: {outcome.verdict.upper()} (confidence: {outcome.confidence:.2f})",
            },
        }

    def _extract_project(self, payload: Mapping[str, Any]) -> str:
        """Extract project name from payload."""
        resource_containers = payload.get("resourceContainers") or {}
        project = resource_containers.get("project") or {}
        if isinstance(project, Mapping):
            name = project.get("name") or project.get("id")
            if name:
                return str(name)
        # Fallback to resource
        resource = payload.get("resource") or {}
        repo = resource.get("repository") or {}
        if isinstance(repo, Mapping):
            project_ref = repo.get("project") or {}
            if isinstance(project_ref, Mapping):
                return str(project_ref.get("name", "unknown"))
        return "unknown"

    def _extract_pr(self, event: str, resource: Mapping[str, Any]) -> int:
        """Extract pull request ID from resource."""
        if event in ("git.pullrequest.created", "git.pullrequest.updated"):
            pr_id = resource.get("pullRequestId")
            if pr_id is not None:
                return int(pr_id)
        if event == "build.complete":
            trigger = resource.get("triggerInfo") or {}
            pr_id = trigger.get("pr.number")
            if pr_id is not None:
                return int(pr_id)
        return 0

    def _build_submission(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        """Build decision engine submission from Azure DevOps payload."""
        findings = payload.get("findings") or []
        # Extract from security scan results if present
        resource = payload.get("resource") or {}
        scan_results = resource.get("scanResults") or {}
        if isinstance(scan_results, Mapping):
            sarif_findings = scan_results.get("findings") or []
            if sarif_findings:
                findings = sarif_findings
        controls = payload.get("controls") or []
        return {"findings": list(findings), "controls": list(controls)}

    def ingest(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Ingest Azure DevOps build payload."""
        event_type = payload.get("eventType", "build.complete")
        return self.handle_webhook(event_type, payload)
