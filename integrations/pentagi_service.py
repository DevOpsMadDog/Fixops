"""Advanced Pentagi service integration with FixOps decision engine."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.pentagi_db import PentagiDB
from core.pentagi_models import (
    ExploitabilityLevel,
    PenTestPriority,
    PenTestRequest,
    PenTestResult,
    PenTestStatus,
)
from integrations.pentagi_client import (
    PentagiClient,
    PentagiFinding,
    PentagiSeverity,
    PentagiTestResult,
    PentagiTestType,
)

logger = logging.getLogger(__name__)


class AdvancedPentagiService:
    """
    Advanced Pentagi service with automated pen testing capabilities.

    Provides features similar to Akido Security and Prism Security:
    - Automated vulnerability verification
    - Continuous security monitoring
    - Exploitability assessment
    - Risk-based prioritization
    - Integration with FixOps decision engine
    """

    def __init__(
        self,
        pentagi_url: str,
        api_key: Optional[str] = None,
        db: Optional[PentagiDB] = None,
    ):
        """
        Initialize advanced Pentagi service.

        Args:
            pentagi_url: URL of Pentagi instance
            api_key: API key for authentication
            db: Database manager instance
        """
        self.client = PentagiClient(pentagi_url, api_key)
        self.db = db or PentagiDB()
        self._monitoring_jobs: Dict[str, str] = {}

    async def close(self):
        """Close service and cleanup resources."""
        await self.client.close()

    async def trigger_pen_test_from_finding(
        self,
        finding_id: str,
        target_url: str,
        vulnerability_type: str,
        test_case: str,
        priority: PenTestPriority = PenTestPriority.MEDIUM,
        auto_verify: bool = True,
    ) -> PenTestRequest:
        """
        Trigger penetration test from a security finding.

        Args:
            finding_id: ID of the finding in FixOps
            target_url: Target URL to test
            vulnerability_type: Type of vulnerability
            test_case: Test case description
            priority: Priority level
            auto_verify: Automatically verify exploitability

        Returns:
            Pen test request object
        """
        # Determine test type from vulnerability type
        test_type = self._map_vulnerability_to_test_type(vulnerability_type)

        # Create pen test request
        request = PenTestRequest(
            id="",
            finding_id=finding_id,
            target_url=target_url,
            vulnerability_type=vulnerability_type,
            test_case=test_case,
            priority=priority,
            status=PenTestStatus.PENDING,
        )
        request = self.db.create_request(request)

        try:
            # Create test in Pentagi
            config = {
                "auto_verify": auto_verify,
                "priority": priority.value,
                "finding_id": finding_id,
            }
            pentagi_test_id = await self.client.create_test(
                target_url, test_type, config
            )

            # Update request with Pentagi job ID
            request.pentagi_job_id = pentagi_test_id
            request.status = PenTestStatus.RUNNING
            request.started_at = datetime.utcnow()
            request = self.db.update_request(request)

            # Start async monitoring
            asyncio.create_task(self._monitor_test(request.id, pentagi_test_id))

        except Exception as e:
            logger.error(f"Failed to create Pentagi test: {e}")
            request.status = PenTestStatus.FAILED
            request = self.db.update_request(request)

        return request

    async def _monitor_test(self, request_id: str, pentagi_test_id: str):
        """Monitor test progress and update status."""
        max_wait = 600  # 10 minutes
        check_interval = 10  # Check every 10 seconds
        start_time = datetime.utcnow()

        while (datetime.utcnow() - start_time).total_seconds() < max_wait:
            try:
                status = await self.client.get_test_status(pentagi_test_id)
                test_status = status.get("status", "").lower()

                request = self.db.get_request(request_id)
                if not request:
                    break

                if test_status in ["completed", "done"]:
                    # Get results and create result record
                    results = await self.client.get_test_results(pentagi_test_id)
                    await self._process_test_results(request, results)
                    break
                elif test_status in ["failed", "error"]:
                    request.status = PenTestStatus.FAILED
                    request.completed_at = datetime.utcnow()
                    self.db.update_request(request)
                    break

                await asyncio.sleep(check_interval)

            except Exception as e:
                logger.error(f"Error monitoring test {pentagi_test_id}: {e}")
                await asyncio.sleep(check_interval)

    async def _process_test_results(
        self,
        request: PenTestRequest,
        results: PentagiTestResult,
    ):
        """Process test results and create result records."""
        if not results.findings:
            # No findings - mark as unexploitable
            result = PenTestResult(
                id="",
                request_id=request.id,
                finding_id=request.finding_id,
                exploitability=ExploitabilityLevel.UNEXPLOITABLE,
                exploit_successful=False,
                evidence="No vulnerabilities found during penetration test",
                confidence_score=0.9,
                execution_time_seconds=results.duration_seconds,
            )
        else:
            # Process findings - use highest severity finding
            highest_finding = max(
                results.findings,
                key=lambda f: self._severity_to_score(f.severity),
            )

            exploitability = self._determine_exploitability(highest_finding)
            exploit_successful = highest_finding.exploit_successful or (
                highest_finding.verified
                and highest_finding.severity
                in [PentagiSeverity.CRITICAL, PentagiSeverity.HIGH]
            )

            evidence = self._format_evidence(highest_finding, results.findings)

            result = PenTestResult(
                id="",
                request_id=request.id,
                finding_id=request.finding_id,
                exploitability=exploitability,
                exploit_successful=exploit_successful,
                evidence=evidence,
                steps_taken=[
                    f"{i+1}. {step}"
                    for i, step in enumerate(highest_finding.steps_to_reproduce)
                ],
                artifacts=self._extract_artifacts(results),
                confidence_score=highest_finding.confidence,
                execution_time_seconds=results.duration_seconds,
                metadata={
                    "cvss_score": highest_finding.cvss_score,
                    "cwe_id": highest_finding.cwe_id,
                    "cve_id": highest_finding.cve_id,
                    "attack_vector": highest_finding.attack_vector,
                    "total_findings": len(results.findings),
                },
            )

        self.db.create_result(result)

        # Update request status
        request.status = PenTestStatus.COMPLETED
        request.completed_at = datetime.utcnow()
        self.db.update_request(request)

    def _map_vulnerability_to_test_type(
        self,
        vulnerability_type: str,
    ) -> PentagiTestType:
        """Map vulnerability type to Pentagi test type."""
        vuln_lower = vulnerability_type.lower()

        if any(x in vuln_lower for x in ["sql", "xss", "csrf", "injection"]):
            return PentagiTestType.WEB_APPLICATION
        elif any(x in vuln_lower for x in ["api", "rest", "graphql"]):
            return PentagiTestType.API_SECURITY
        elif any(x in vuln_lower for x in ["network", "port", "service"]):
            return PentagiTestType.NETWORK_SCAN
        elif any(x in vuln_lower for x in ["code", "sast", "static"]):
            return PentagiTestType.CODE_ANALYSIS
        elif any(x in vuln_lower for x in ["cloud", "aws", "azure", "gcp"]):
            return PentagiTestType.CLOUD_SECURITY
        elif any(x in vuln_lower for x in ["container", "docker", "kubernetes"]):
            return PentagiTestType.CONTAINER_SECURITY
        else:
            return PentagiTestType.WEB_APPLICATION  # Default

    def _severity_to_score(self, severity: PentagiSeverity) -> int:
        """Convert severity to numeric score for comparison."""
        mapping = {
            PentagiSeverity.CRITICAL: 4,
            PentagiSeverity.HIGH: 3,
            PentagiSeverity.MEDIUM: 2,
            PentagiSeverity.LOW: 1,
            PentagiSeverity.INFO: 0,
        }
        return mapping.get(severity, 0)

    def _determine_exploitability(
        self,
        finding: PentagiFinding,
    ) -> ExploitabilityLevel:
        """Determine exploitability level from finding."""
        if finding.exploit_successful:
            return ExploitabilityLevel.CONFIRMED_EXPLOITABLE
        elif finding.verified and finding.severity in [
            PentagiSeverity.CRITICAL,
            PentagiSeverity.HIGH,
        ]:
            return ExploitabilityLevel.LIKELY_EXPLOITABLE
        elif finding.severity == PentagiSeverity.MEDIUM:
            return ExploitabilityLevel.INCONCLUSIVE
        elif finding.false_positive:
            return ExploitabilityLevel.BLOCKED
        else:
            return ExploitabilityLevel.UNEXPLOITABLE

    def _format_evidence(
        self,
        primary_finding: PentagiFinding,
        all_findings: List[PentagiFinding],
    ) -> str:
        """Format evidence from findings."""
        evidence_parts = [
            f"Primary Finding: {primary_finding.title}",
            f"Severity: {primary_finding.severity.value.upper()}",
            f"Type: {primary_finding.vulnerability_type}",
        ]

        if primary_finding.description:
            evidence_parts.append(f"Description: {primary_finding.description}")

        if primary_finding.evidence:
            evidence_parts.append(f"Evidence: {primary_finding.evidence}")

        if primary_finding.cvss_score:
            evidence_parts.append(f"CVSS Score: {primary_finding.cvss_score}")

        if primary_finding.cwe_id:
            evidence_parts.append(f"CWE: {primary_finding.cwe_id}")

        if len(all_findings) > 1:
            evidence_parts.append(
                f"\nAdditional findings: {len(all_findings) - 1} more vulnerabilities detected"
            )

        return "\n".join(evidence_parts)

    def _extract_artifacts(self, results: PentagiTestResult) -> List[str]:
        """Extract artifact references from results."""
        artifacts = []
        for finding in results.findings:
            if finding.metadata.get("screenshot"):
                artifacts.append(finding.metadata["screenshot"])
            if finding.metadata.get("payload"):
                artifacts.append(finding.metadata["payload"])
            if finding.metadata.get("log_file"):
                artifacts.append(finding.metadata["log_file"])
        return artifacts

    async def verify_vulnerability_from_finding(
        self,
        finding_id: str,
        target_url: str,
        vulnerability_type: str,
        evidence: str,
    ) -> Dict[str, Any]:
        """
        Verify a vulnerability by attempting exploitation.

        Similar to Akido Security's automated verification.

        Args:
            finding_id: Finding ID in FixOps
            target_url: Target URL
            vulnerability_type: Type of vulnerability
            evidence: Evidence of the vulnerability

        Returns:
            Verification result
        """
        try:
            result = await self.client.verify_vulnerability(
                target_url, vulnerability_type, evidence
            )

            # Create pen test request and result records
            request = PenTestRequest(
                id="",
                finding_id=finding_id,
                target_url=target_url,
                vulnerability_type=vulnerability_type,
                test_case=f"Verification test for {vulnerability_type}",
                priority=PenTestPriority.HIGH,
                status=PenTestStatus.COMPLETED,
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
            )
            request = self.db.create_request(request)

            exploitability = (
                ExploitabilityLevel.CONFIRMED_EXPLOITABLE
                if result.get("exploitable")
                else ExploitabilityLevel.UNEXPLOITABLE
            )

            pen_result = PenTestResult(
                id="",
                request_id=request.id,
                finding_id=finding_id,
                exploitability=exploitability,
                exploit_successful=result.get("exploitable", False),
                evidence=evidence,
                confidence_score=0.95 if result.get("verified") else 0.5,
                execution_time_seconds=0.0,
            )
            self.db.create_result(pen_result)

            return result

        except Exception as e:
            logger.error(f"Failed to verify vulnerability: {e}")
            raise

    async def setup_continuous_monitoring(
        self,
        targets: List[str],
        interval_minutes: int = 60,
    ) -> Dict[str, str]:
        """
        Set up continuous security monitoring.

        Similar to Prism Security's continuous scanning.

        Args:
            targets: List of targets to monitor
            interval_minutes: Scan interval

        Returns:
            Mapping of target to job ID
        """
        try:
            job_ids = await self.client.continuous_monitoring(targets, interval_minutes)
            self._monitoring_jobs.update(job_ids)
            return job_ids
        except Exception as e:
            logger.error(f"Failed to setup continuous monitoring: {e}")
            raise

    async def run_comprehensive_scan(
        self,
        target: str,
        scan_types: Optional[List[PentagiTestType]] = None,
    ) -> List[PenTestRequest]:
        """
        Run comprehensive multi-vector security scan.

        Args:
            target: Target to scan
            scan_types: Optional list of specific scan types

        Returns:
            List of pen test requests
        """
        if scan_types is None:
            scan_types = [
                PentagiTestType.WEB_APPLICATION,
                PentagiTestType.API_SECURITY,
                PentagiTestType.NETWORK_SCAN,
                PentagiTestType.CODE_ANALYSIS,
            ]

        requests = []
        for scan_type in scan_types:
            try:
                test_id = await self.client.create_test(
                    target,
                    scan_type,
                    {"comprehensive": True, "deep_scan": True},
                )

                request = PenTestRequest(
                    id="",
                    finding_id=f"scan-{scan_type.value}",
                    target_url=target,
                    vulnerability_type=scan_type.value,
                    test_case=f"Comprehensive {scan_type.value} scan",
                    priority=PenTestPriority.HIGH,
                    status=PenTestStatus.RUNNING,
                    pentagi_job_id=test_id,
                    started_at=datetime.utcnow(),
                )
                request = self.db.create_request(request)
                requests.append(request)

                # Start monitoring
                asyncio.create_task(self._monitor_test(request.id, test_id))

            except Exception as e:
                logger.error(f"Failed to create {scan_type.value} scan: {e}")

        return requests

    def get_exploitability_for_finding(
        self,
        finding_id: str,
    ) -> Optional[ExploitabilityLevel]:
        """Get exploitability level for a finding."""
        result = self.db.get_result_by_request(
            self.db.list_requests(finding_id=finding_id)[0].id
            if self.db.list_requests(finding_id=finding_id)
            else None
        )
        return result.exploitability if result else None
