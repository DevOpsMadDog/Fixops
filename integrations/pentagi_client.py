"""Advanced Pentagi client for automated penetration testing integration with FixOps."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)


class PentagiTestType(Enum):
    """Types of penetration tests supported."""

    WEB_APPLICATION = "web_application"
    API_SECURITY = "api_security"
    NETWORK_SCAN = "network_scan"
    CODE_ANALYSIS = "code_analysis"
    INFRASTRUCTURE = "infrastructure"
    CLOUD_SECURITY = "cloud_security"
    CONTAINER_SECURITY = "container_security"
    IOT_DEVICE = "iot_device"
    MOBILE_APP = "mobile_app"
    SOCIAL_ENGINEERING = "social_engineering"


class PentagiSeverity(Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PentagiFinding:
    """Penetration test finding."""

    id: str
    title: str
    description: str
    severity: PentagiSeverity
    vulnerability_type: str
    exploitability: str
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    evidence: str = ""
    steps_to_reproduce: List[str] = field(default_factory=list)
    remediation: str = ""
    affected_components: List[str] = field(default_factory=list)
    attack_vector: str = ""
    impact: str = ""
    confidence: float = 0.0
    false_positive: bool = False
    verified: bool = False
    exploit_successful: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PentagiTestResult:
    """Result of a penetration test."""

    test_id: str
    test_type: PentagiTestType
    target: str
    status: str
    findings: List[PentagiFinding] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    risk_score: float = 0.0
    summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class PentagiClient:
    """Advanced client for Pentagi penetration testing platform."""

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: int = 300,
        max_retries: int = 3,
    ):
        """
        Initialize Pentagi client.

        Args:
            base_url: Base URL of Pentagi instance
            api_key: API key for authentication
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            headers["Content-Type"] = "application/json"
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
                follow_redirects=True,
            )
        return self._client

    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """Make HTTP request with retry logic."""
        client = await self._get_client()
        url = urljoin(self.base_url, endpoint.lstrip("/"))

        for attempt in range(self.max_retries):
            try:
                response = await client.request(method, url, **kwargs)
                response.raise_for_status()
                return response.json() if response.content else {}
            except httpx.HTTPStatusError as e:
                if e.response.status_code < 500 or attempt == self.max_retries - 1:
                    raise
                await asyncio.sleep(2**attempt)
            except Exception:
                if attempt == self.max_retries - 1:
                    raise
                await asyncio.sleep(2**attempt)

        raise Exception("Max retries exceeded")

    async def create_test(
        self,
        target: str,
        test_type: PentagiTestType,
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a new penetration test.

        Args:
            target: Target URL, IP, or identifier
            test_type: Type of test to run
            config: Additional test configuration

        Returns:
            Test ID for tracking
        """
        payload = {
            "target": target,
            "test_type": test_type.value,
            "config": config or {},
        }

        response = await self._request("POST", "/api/v1/flows", json=payload)
        return response.get("id", "")

    async def get_test_status(self, test_id: str) -> Dict[str, Any]:
        """Get status of a penetration test."""
        return await self._request("GET", f"/api/v1/flows/{test_id}")

    async def get_test_results(self, test_id: str) -> PentagiTestResult:
        """Get complete results of a penetration test."""
        flow_data = await self.get_test_status(test_id)
        tasks = await self._request("GET", f"/api/v1/flows/{test_id}/tasks")

        findings = []
        for task in tasks.get("items", []):
            task_id = task.get("id")
            if task_id:
                subtasks = await self._request(
                    "GET", f"/api/v1/tasks/{task_id}/subtasks"
                )
                for subtask in subtasks.get("items", []):
                    findings.extend(await self._extract_findings(subtask))

        return PentagiTestResult(
            test_id=test_id,
            test_type=PentagiTestType(flow_data.get("test_type", "web_application")),
            target=flow_data.get("target", ""),
            status=flow_data.get("status", "unknown"),
            findings=findings,
        )

    async def _extract_findings(self, subtask: Dict[str, Any]) -> List[PentagiFinding]:
        """Extract findings from subtask data."""
        findings = []
        result = subtask.get("result", {})
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except json.JSONDecodeError:
                return findings

        vulnerabilities = result.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            finding = PentagiFinding(
                id=vuln.get("id", ""),
                title=vuln.get("title", "Unknown Vulnerability"),
                description=vuln.get("description", ""),
                severity=PentagiSeverity(vuln.get("severity", "medium").lower()),
                vulnerability_type=vuln.get("type", ""),
                exploitability=vuln.get("exploitability", "unknown"),
                cvss_score=vuln.get("cvss_score"),
                cwe_id=vuln.get("cwe_id"),
                cve_id=vuln.get("cve_id"),
                evidence=vuln.get("evidence", ""),
                steps_to_reproduce=vuln.get("steps", []),
                remediation=vuln.get("remediation", ""),
                affected_components=vuln.get("components", []),
                attack_vector=vuln.get("attack_vector", ""),
                impact=vuln.get("impact", ""),
                confidence=vuln.get("confidence", 0.0),
                verified=vuln.get("verified", False),
                exploit_successful=vuln.get("exploit_successful", False),
                metadata=vuln.get("metadata", {}),
            )
            findings.append(finding)

        return findings

    async def run_automated_scan(
        self,
        target: str,
        scan_types: List[PentagiTestType],
        schedule: Optional[str] = None,
    ) -> List[str]:
        """
        Run automated multi-type security scan.

        Args:
            target: Target to scan
            scan_types: List of test types to run
            schedule: Optional cron schedule for recurring scans

        Returns:
            List of test IDs
        """
        test_ids = []
        for scan_type in scan_types:
            config = {
                "automated": True,
                "schedule": schedule,
                "deep_scan": True,
                "verify_exploits": True,
            }
            test_id = await self.create_test(target, scan_type, config)
            test_ids.append(test_id)

        return test_ids

    async def verify_vulnerability(
        self,
        target: str,
        vulnerability_type: str,
        evidence: str,
    ) -> Dict[str, Any]:
        """
        Verify a specific vulnerability by attempting exploitation.

        Args:
            target: Target to test
            vulnerability_type: Type of vulnerability
            evidence: Evidence of the vulnerability

        Returns:
            Verification result with exploitability assessment
        """
        config = {
            "verify_only": True,
            "vulnerability_type": vulnerability_type,
            "evidence": evidence,
            "exploit_attempt": True,
        }

        test_id = await self.create_test(
            target, PentagiTestType.WEB_APPLICATION, config
        )

        # Wait for test completion
        max_wait = 300  # 5 minutes
        start_time = time.time()
        while time.time() - start_time < max_wait:
            status = await self.get_test_status(test_id)
            if status.get("status") in ["completed", "failed"]:
                break
            await asyncio.sleep(5)

        results = await self.get_test_results(test_id)
        return {
            "verified": any(f.verified for f in results.findings),
            "exploitable": any(f.exploit_successful for f in results.findings),
            "findings": [f.__dict__ for f in results.findings],
        }

    async def continuous_monitoring(
        self,
        targets: List[str],
        interval_minutes: int = 60,
    ) -> Dict[str, str]:
        """
        Set up continuous monitoring for multiple targets.

        Args:
            targets: List of targets to monitor
            interval_minutes: Scan interval in minutes

        Returns:
            Mapping of target to monitoring job ID
        """
        schedule = f"*/{interval_minutes} * * * *"  # Cron format
        job_ids = {}

        for target in targets:
            test_ids = await self.run_automated_scan(
                target,
                [
                    PentagiTestType.WEB_APPLICATION,
                    PentagiTestType.API_SECURITY,
                    PentagiTestType.NETWORK_SCAN,
                ],
                schedule=schedule,
            )
            job_ids[target] = test_ids[0] if test_ids else ""

        return job_ids

    async def get_findings_by_severity(
        self,
        test_id: str,
        severity: Optional[PentagiSeverity] = None,
    ) -> List[PentagiFinding]:
        """Get findings filtered by severity."""
        results = await self.get_test_results(test_id)
        if severity:
            return [f for f in results.findings if f.severity == severity]
        return results.findings

    async def export_report(
        self,
        test_id: str,
        format: str = "json",
    ) -> bytes:
        """
        Export test report in specified format.

        Args:
            test_id: Test ID
            format: Export format (json, pdf, html, sarif)

        Returns:
            Report content as bytes
        """
        endpoint = f"/api/v1/flows/{test_id}/report"
        params = {"format": format}

        client = await self._get_client()
        response = await client.get(endpoint, params=params)
        response.raise_for_status()
        return response.content
