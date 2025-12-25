"""DefectDojo integration adapter for FixOps."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional

import structlog
from src.services.decision_engine import DecisionEngine

logger = structlog.get_logger()


class DefectDojoAdapter:
    """Bidirectional DefectDojo integration for findings sync."""

    SEVERITY_MAP = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Info": "info",
        "Informational": "info",
    }

    REVERSE_SEVERITY_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    def __init__(
        self,
        decision_engine: DecisionEngine | None = None,
        api_token: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        self._engine = decision_engine or DecisionEngine()
        self.api_token = api_token or os.getenv("FIXOPS_DEFECTDOJO_TOKEN")
        self.base_url = (base_url or os.getenv("FIXOPS_DEFECTDOJO_URL", "")).rstrip("/")

    def ingest(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Ingest DefectDojo findings and return decision."""
        findings = list(self._normalize_findings(payload))
        submission = {"findings": findings, "controls": payload.get("controls") or []}
        outcome = self._engine.evaluate(submission)

        logger.info(
            "fixops.defectdojo_adapter.decision",
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
        """Normalize DefectDojo findings to canonical format."""
        findings: List[Mapping[str, Any]] = []

        if isinstance(payload.get("results"), list):
            findings = payload["results"]
        elif isinstance(payload.get("findings"), list):
            findings = payload["findings"]
        elif "id" in payload and "title" in payload:
            # Single finding
            findings = [payload]

        for finding in findings:
            if not isinstance(finding, Mapping):
                continue

            severity = str(finding.get("severity", "Medium"))
            normalized_severity = self.SEVERITY_MAP.get(severity, "medium")

            # Extract vulnerability IDs
            vuln_ids = finding.get("vulnerability_ids") or []
            cve_id = None
            cwe_id = None
            for vid in vuln_ids:
                if isinstance(vid, Mapping):
                    vid_value = vid.get("vulnerability_id", "")
                    if vid_value.startswith("CVE-"):
                        cve_id = vid_value
                    elif vid_value.startswith("CWE-"):
                        cwe_id = vid_value

            # Use CWE from finding if not in vulnerability_ids
            if not cwe_id and finding.get("cwe"):
                cwe_id = f"CWE-{finding['cwe']}"

            yield {
                "id": str(finding.get("id")),
                "title": finding.get("title"),
                "description": finding.get("description"),
                "severity": normalized_severity,
                "source_tool": "defectdojo",
                "source_type": "defectdojo",
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "file_path": finding.get("file_path"),
                "line_number": finding.get("line"),
                "component": finding.get("component_name"),
                "status": finding.get("active", True) and "open" or "closed",
                "verified": finding.get("verified", False),
                "false_positive": finding.get("false_p", False),
                "risk_accepted": finding.get("risk_accepted", False),
                "duplicate": finding.get("duplicate", False),
                "raw": dict(finding),
            }

    async def push_findings(
        self,
        findings: List[Dict[str, Any]],
        product_id: int,
        engagement_id: Optional[int] = None,
        test_type: str = "FixOps Scan",
    ) -> Dict[str, Any]:
        """Push findings to DefectDojo."""
        if not self.api_token or not self.base_url:
            return {"error": "DefectDojo not configured"}

        import httpx

        headers = {
            "Authorization": f"Token {self.api_token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient() as client:
            # Create engagement if not provided
            if engagement_id is None:
                engagement_response = await client.post(
                    f"{self.base_url}/api/v2/engagements/",
                    headers=headers,
                    json={
                        "name": f"FixOps Import {datetime.now(timezone.utc).isoformat()}",
                        "product": product_id,
                        "target_start": datetime.now(timezone.utc).date().isoformat(),
                        "target_end": datetime.now(timezone.utc).date().isoformat(),
                        "engagement_type": "CI/CD",
                        "status": "In Progress",
                    },
                    timeout=30.0,
                )
                if engagement_response.status_code == 201:
                    engagement_id = engagement_response.json().get("id")
                else:
                    return {"error": f"Failed to create engagement: {engagement_response.text}"}

            # Create test
            test_response = await client.post(
                f"{self.base_url}/api/v2/tests/",
                headers=headers,
                json={
                    "engagement": engagement_id,
                    "test_type_name": test_type,
                    "target_start": datetime.now(timezone.utc).isoformat(),
                    "target_end": datetime.now(timezone.utc).isoformat(),
                },
                timeout=30.0,
            )

            if test_response.status_code != 201:
                return {"error": f"Failed to create test: {test_response.text}"}

            test_id = test_response.json().get("id")

            # Import findings
            created_count = 0
            errors = []

            for finding in findings:
                severity = self.REVERSE_SEVERITY_MAP.get(
                    finding.get("severity", "medium"), "Medium"
                )

                finding_payload = {
                    "test": test_id,
                    "title": finding.get("title", "Unknown Finding"),
                    "description": finding.get("description", ""),
                    "severity": severity,
                    "active": True,
                    "verified": False,
                    "file_path": finding.get("file_path"),
                    "line": finding.get("line_number"),
                    "cwe": int(finding.get("cwe_id", "CWE-0").replace("CWE-", "")) if finding.get("cwe_id") else None,
                    "numerical_severity": {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(severity, 2),
                }

                # Add vulnerability IDs
                vuln_ids = []
                if finding.get("cve_id"):
                    vuln_ids.append({"vulnerability_id": finding["cve_id"]})
                if vuln_ids:
                    finding_payload["vulnerability_ids"] = vuln_ids

                response = await client.post(
                    f"{self.base_url}/api/v2/findings/",
                    headers=headers,
                    json=finding_payload,
                    timeout=30.0,
                )

                if response.status_code == 201:
                    created_count += 1
                else:
                    errors.append(f"Finding '{finding.get('title')}': {response.text}")

            return {
                "success": True,
                "engagement_id": engagement_id,
                "test_id": test_id,
                "findings_created": created_count,
                "errors": errors,
            }

    async def pull_findings(
        self,
        product_id: Optional[int] = None,
        engagement_id: Optional[int] = None,
        active_only: bool = True,
    ) -> Dict[str, Any]:
        """Pull findings from DefectDojo."""
        if not self.api_token or not self.base_url:
            return {"error": "DefectDojo not configured"}

        import httpx

        params: Dict[str, Any] = {"limit": 1000}
        if product_id:
            params["test__engagement__product"] = product_id
        if engagement_id:
            params["test__engagement"] = engagement_id
        if active_only:
            params["active"] = True

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v2/findings/",
                headers={"Authorization": f"Token {self.api_token}"},
                params=params,
                timeout=60.0,
            )

            if response.status_code != 200:
                return {"error": f"Failed to fetch findings: {response.text}"}

            data = response.json()
            findings = list(self._normalize_findings(data))

            return {
                "success": True,
                "findings": findings,
                "total_count": data.get("count", len(findings)),
            }
