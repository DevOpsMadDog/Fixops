"""GitLab push-model adapter for FixOps decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping

import structlog
from src.services.decision_engine import DecisionEngine, DecisionOutcome

logger = structlog.get_logger()


@dataclass
class GitLabComment:
    project_id: int
    merge_request_iid: int
    body: str


class GitLabCIAdapter:
    """Handle GitLab webhook events and produce decision comments."""

    def __init__(self, decision_engine: DecisionEngine | None = None) -> None:
        self._engine = decision_engine or DecisionEngine()

    def handle_webhook(self, event: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Process incoming GitLab webhooks.
        Supports Merge Request events and Pipeline events.
        """
        project_id = self._extract_project_id(payload)
        mr_iid = self._extract_mr_iid(event, payload)
        
        # Build submission from payload (e.g. artifacts, reports)
        decision_payload = self._build_submission(payload)
        
        outcome = self._engine.evaluate(decision_payload)
        comment = self._render_comment(outcome)
        
        logger.info(
            "fixops.gitlab_adapter.decision",
            project_id=project_id,
            merge_request_iid=mr_iid,
            verdict=outcome.verdict,
            confidence=outcome.confidence,
            evidence=outcome.evidence.evidence_id,
        )
        
        return {
            "project_id": project_id,
            "merge_request_iid": mr_iid,
            "comment": comment.body,
            "verdict": outcome.verdict,
            "confidence": outcome.confidence,
            "evidence_id": outcome.evidence.evidence_id,
            "evidence": outcome.evidence.manifest,
            "compliance": outcome.compliance,
            "top_factors": outcome.top_factors,
            "marketplace_recommendations": outcome.marketplace_recommendations,
        }

    def _extract_project_id(self, payload: Mapping[str, Any]) -> int:
        project = payload.get("project") or {}
        if isinstance(project, Mapping):
            pid = project.get("id")
            if pid:
                return int(pid)
        raise ValueError("project details missing from payload")

    def _extract_mr_iid(self, event: str, payload: Mapping[str, Any]) -> int:
        object_attributes = payload.get("object_attributes", {})
        if event == "Merge Request Hook":
             if object_attributes.get("iid"):
                 return int(object_attributes["iid"])
        
        # Fallback or other events logic would go here
        # For stub, we assume MR hook
        return 0

    def _build_submission(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        # In a real implementation, this would parse GitLab Security Reports (SAST/DAST)
        # For the stub, we extract what we can or return empty structure
        return {"findings": [], "controls": []}

    def _render_comment(self, outcome: DecisionOutcome) -> GitLabComment:
        summary = [
            f"### FixOps Verdict: **{outcome.verdict.upper()}**",
            f"- Confidence: {outcome.confidence:.2f}",
            f"- Evidence ID: `{outcome.evidence.evidence_id}`",
        ]
        evidence_url = outcome.evidence.manifest.get(
            "url"
        ) or outcome.evidence.manifest.get("evidence_url")
        if evidence_url:
            summary.append(f"- Evidence: {evidence_url}")
            
        return GitLabComment(project_id=0, merge_request_iid=0, body="\n".join(summary))
