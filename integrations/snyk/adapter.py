"""Snyk direct integration adapter for FixOps."""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Mapping, Optional

import structlog
from src.services.decision_engine import DecisionEngine

logger = structlog.get_logger()


class SnykAdapter:
    """Direct Snyk integration for importing vulnerabilities."""

    SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "moderate": "medium",
    }

    def __init__(
        self,
        decision_engine: DecisionEngine | None = None,
        api_token: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> None:
        self._engine = decision_engine or DecisionEngine()
        self.api_token = api_token or os.getenv("FIXOPS_SNYK_TOKEN")
        self.org_id = org_id or os.getenv("FIXOPS_SNYK_ORG_ID")
        self.base_url = "https://api.snyk.io/v1"

    def ingest(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Ingest Snyk JSON payload and return decision."""
        findings = list(self._normalize_findings(payload))
        submission = {"findings": findings, "controls": payload.get("controls") or []}
        outcome = self._engine.evaluate(submission)

        logger.info(
            "fixops.snyk_adapter.decision",
            verdict=outcome.verdict,
            confidence=outcome.confidence,
            findings_count=len(findings),
        )

        return {
            "verdict": outcome.verdict,
            "confidence": outcome.confidence,
            "evidence_id": outcome.evidence.evidence_id,
            "evidence": outcome.evidence.manifest,
            "compliance": outcome.compliance,
            "top_factors": outcome.top_factors,
            "marketplace_recommendations": outcome.marketplace_recommendations,
            "findings_processed": len(findings),
        }

    def _normalize_findings(
        self, payload: Mapping[str, Any]
    ) -> Iterable[Dict[str, Any]]:
        """Normalize Snyk vulnerabilities to canonical finding format."""
        # Handle different Snyk payload formats
        vulnerabilities: List[Mapping[str, Any]] = []

        if isinstance(payload.get("vulnerabilities"), list):
            vulnerabilities = payload["vulnerabilities"]
        elif isinstance(payload.get("issues"), Mapping):
            for category, issues in payload["issues"].items():
                if isinstance(issues, list):
                    vulnerabilities.extend(issues)
        elif isinstance(payload.get("issues"), list):
            vulnerabilities = payload["issues"]

        for vuln in vulnerabilities:
            if not isinstance(vuln, Mapping):
                continue

            severity = str(vuln.get("severity", "medium")).lower()
            normalized_severity = self.SEVERITY_MAP.get(severity, "medium")

            # Extract CVE/CWE identifiers
            identifiers = vuln.get("identifiers") or {}
            cve_ids = identifiers.get("CVE") or []
            cwe_ids = identifiers.get("CWE") or []

            finding = {
                "id": vuln.get("id") or vuln.get("issueId"),
                "title": vuln.get("title") or vuln.get("message"),
                "description": vuln.get("description"),
                "severity": normalized_severity,
                "source_tool": "snyk",
                "source_type": "snyk",
                "cve_id": cve_ids[0] if cve_ids else None,
                "cwe_id": cwe_ids[0] if cwe_ids else None,
                "package": vuln.get("packageName") or vuln.get("package"),
                "version": vuln.get("version"),
                "fix_available": bool(
                    vuln.get("isPatchable")
                    or vuln.get("isUpgradable")
                    or vuln.get("fixedIn")
                ),
                "exploitability": vuln.get("exploitMaturity"),
                "cvss_score": vuln.get("cvssScore"),
                "raw": dict(vuln),
            }

            # Add dependency path if available
            from_path = vuln.get("from")
            if isinstance(from_path, list):
                finding["dependency_path"] = from_path
                finding["component"] = from_path[-1] if from_path else None

            yield finding

    async def fetch_project_issues(self, project_id: str) -> Dict[str, Any]:
        """Fetch issues from Snyk API for a specific project."""
        if not self.api_token:
            return {"error": "Snyk API token not configured"}

        import httpx

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/org/{self.org_id}/project/{project_id}/issues",
                headers={
                    "Authorization": f"token {self.api_token}",
                    "Content-Type": "application/json",
                },
                json={"filters": {}},
                timeout=60.0,
            )

            if response.status_code != 200:
                return {"error": f"Snyk API error: {response.status_code}"}

            return response.json()
