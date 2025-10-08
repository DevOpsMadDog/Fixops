"""GitHub push-model adapter for FixOps decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping

import structlog

from src.services.decision_engine import DecisionEngine, DecisionOutcome

logger = structlog.get_logger()


@dataclass
class GitHubComment:
    repository: str
    pull_request: int
    body: str


class GitHubCIAdapter:
    """Handle GitHub webhook events and produce decision comments."""

    def __init__(self, decision_engine: DecisionEngine | None = None) -> None:
        self._engine = decision_engine or DecisionEngine()

    def handle_webhook(self, event: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        repo = self._extract_repo(payload)
        pr_number = self._extract_pr(event, payload)
        decision_payload = self._build_submission(payload)
        outcome = self._engine.evaluate(decision_payload)
        comment = self._render_comment(outcome)
        logger.info(
            "fixops.github_adapter.decision",
            repository=repo,
            pull_request=pr_number,
            verdict=outcome.verdict,
            confidence=outcome.confidence,
            evidence=outcome.evidence.evidence_id,
        )
        return {
            "repository": repo,
            "pull_request": pr_number,
            "comment": comment.body,
            "verdict": outcome.verdict,
            "confidence": outcome.confidence,
            "evidence_id": outcome.evidence.evidence_id,
            "evidence": outcome.evidence.manifest,
            "compliance": outcome.compliance,
            "top_factors": outcome.top_factors,
        }

    def _extract_repo(self, payload: Mapping[str, Any]) -> str:
        repo = payload.get("repository") or {}
        if isinstance(repo, Mapping):
            full_name = repo.get("full_name") or repo.get("name")
            if full_name:
                return str(full_name)
        raise ValueError("repository details missing from payload")

    def _extract_pr(self, event: str, payload: Mapping[str, Any]) -> int:
        if event == "pull_request":
            pr = payload.get("number")
            if pr is None and isinstance(payload.get("pull_request"), Mapping):
                pr = payload["pull_request"].get("number")
            if pr is not None:
                return int(pr)
        if event == "check_suite":
            suite = payload.get("check_suite")
            if isinstance(suite, Mapping):
                prs = suite.get("pull_requests")
                if isinstance(prs, list) and prs:
                    pr = prs[0].get("number")
                    if pr is not None:
                        return int(pr)
        raise ValueError("pull request number not present in payload")

    def _build_submission(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        findings = payload.get("findings") or payload.get("analysis", {}).get("findings") or []
        controls = payload.get("controls") or payload.get("analysis", {}).get("controls") or []
        return {"findings": list(findings), "controls": list(controls)}

    def _render_comment(self, outcome: DecisionOutcome) -> GitHubComment:
        summary = [
            f"### FixOps Verdict: **{outcome.verdict.upper()}**",
            f"- Confidence: {outcome.confidence:.2f}",
            f"- Evidence ID: `{outcome.evidence.evidence_id}`",
        ]
        evidence_url = outcome.evidence.manifest.get("url") or outcome.evidence.manifest.get("evidence_url")
        if evidence_url:
            summary.append(f"- Evidence: {evidence_url}")
        if outcome.top_factors:
            summary.append("\n**Top factors**:")
            for factor in outcome.top_factors:
                summary.append(f"- {factor['name']} ({factor['weight']:.3f}): {factor['rationale']}")
        return GitHubComment(repository="", pull_request=0, body="\n".join(summary))

