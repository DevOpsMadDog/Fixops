"""GitLab push-model adapter for FixOps decisions."""

from __future__ import annotations

from typing import Any, Dict, Mapping

import structlog
from src.services.decision_engine import DecisionEngine, DecisionOutcome

logger = structlog.get_logger()


class GitLabCIAdapter:
    """Handle GitLab webhook events and produce decision comments."""

    def __init__(self, decision_engine: DecisionEngine | None = None) -> None:
        self._engine = decision_engine or DecisionEngine()

    def handle_webhook(self, event: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Process GitLab webhook and return decision."""
        project = self._extract_project(payload)
        mr_iid = self._extract_mr(event, payload)
        decision_payload = self._build_submission(payload)
        outcome = self._engine.evaluate(decision_payload)
        comment = self._render_comment(outcome)

        logger.info(
            "fixops.gitlab_adapter.decision",
            project=project,
            merge_request=mr_iid,
            verdict=outcome.verdict,
            confidence=outcome.confidence,
            evidence=outcome.evidence.evidence_id,
        )

        return {
            "project": project,
            "merge_request": mr_iid,
            "comment": comment,
            "verdict": outcome.verdict,
            "confidence": outcome.confidence,
            "evidence_id": outcome.evidence.evidence_id,
            "evidence": outcome.evidence.manifest,
            "compliance": outcome.compliance,
            "top_factors": outcome.top_factors,
            "marketplace_recommendations": outcome.marketplace_recommendations,
        }

    def _extract_project(self, payload: Mapping[str, Any]) -> str:
        """Extract project path from payload."""
        project = payload.get("project") or {}
        if isinstance(project, Mapping):
            path = project.get("path_with_namespace") or project.get("path")
            if path:
                return str(path)
        raise ValueError("project details missing from payload")

    def _extract_mr(self, event: str, payload: Mapping[str, Any]) -> int:
        """Extract merge request IID from payload."""
        if event == "merge_request":
            attrs = payload.get("object_attributes") or {}
            if isinstance(attrs, Mapping):
                iid = attrs.get("iid")
                if iid is not None:
                    return int(iid)
        if event == "pipeline":
            mr = payload.get("merge_request") or {}
            if isinstance(mr, Mapping):
                iid = mr.get("iid")
                if iid is not None:
                    return int(iid)
        raise ValueError("merge request IID not present in payload")

    def _build_submission(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        """Build decision engine submission from GitLab payload."""
        findings = (
            payload.get("findings")
            or payload.get("security_reports", {}).get("findings")
            or []
        )
        controls = payload.get("controls") or []
        return {"findings": list(findings), "controls": list(controls)}

    def _render_comment(self, outcome: DecisionOutcome) -> str:
        """Render decision as GitLab comment markdown."""
        lines = [
            f"### FixOps Verdict: **{outcome.verdict.upper()}**",
            f"- Confidence: {outcome.confidence:.2f}",
            f"- Evidence ID: `{outcome.evidence.evidence_id}`",
        ]
        evidence_url = outcome.evidence.manifest.get(
            "url"
        ) or outcome.evidence.manifest.get("evidence_url")
        if evidence_url:
            lines.append(f"- Evidence: {evidence_url}")
        if outcome.top_factors:
            lines.append("\n**Top factors**:")
            for factor in outcome.top_factors:
                lines.append(
                    f"- {factor['name']} ({factor['weight']:.3f}): {factor['rationale']}"
                )
        return "\n".join(lines)

    def ingest(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Ingest GitLab security report payload."""
        return self.handle_webhook("pipeline", payload)
