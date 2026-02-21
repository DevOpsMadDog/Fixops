"""Continuous security validation and monitoring system."""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional

from core.mpte_advanced import AdvancedMPTEClient, MultiAIOrchestrator
from core.mpte_models import PenTestPriority

logger = logging.getLogger(__name__)


class ValidationTrigger(Enum):
    """Triggers for continuous validation."""

    CODE_COMMIT = "code_commit"
    DEPLOYMENT = "deployment"
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    VULNERABILITY_DISCOVERED = "vulnerability_discovered"
    SECURITY_INCIDENT = "security_incident"
    CONFIGURATION_CHANGE = "configuration_change"


class ValidationStatus(Enum):
    """Status of continuous validation."""

    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ValidationJob:
    """Continuous validation job."""

    id: str
    trigger: ValidationTrigger
    status: ValidationStatus
    target: str
    vulnerabilities: List[Dict]
    priority: PenTestPriority
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict] = None
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "trigger": self.trigger.value,
            "status": self.status.value,
            "target": self.target,
            "vulnerabilities": self.vulnerabilities,
            "priority": self.priority.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "result": self.result,
            "metadata": self.metadata,
        }


@dataclass
class SecurityPosture:
    """Security posture assessment."""

    timestamp: datetime
    total_vulnerabilities: int
    confirmed_exploitable: int
    risk_score: float
    trend: str  # "improving", "degrading", "stable"
    critical_findings: List[str]
    recommendations: List[str]
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_vulnerabilities": self.total_vulnerabilities,
            "confirmed_exploitable": self.confirmed_exploitable,
            "risk_score": self.risk_score,
            "trend": self.trend,
            "critical_findings": self.critical_findings,
            "recommendations": self.recommendations,
            "metadata": self.metadata,
        }


class ContinuousValidationEngine:
    """Engine for continuous security validation."""

    def __init__(
        self, mpte_client: AdvancedMPTEClient, orchestrator: MultiAIOrchestrator
    ):
        """Initialize the validation engine."""
        self.mpte_client = mpte_client
        self.orchestrator = orchestrator
        self.active_jobs: Dict[str, ValidationJob] = {}
        self.completed_jobs: List[ValidationJob] = []
        self.posture_history: List[SecurityPosture] = []
        self.running = False

    async def start(self):
        """Start the continuous validation engine."""
        logger.info("Starting continuous validation engine")
        self.running = True

        # Start background tasks
        asyncio.create_task(self._process_validation_queue())
        asyncio.create_task(self._scheduled_validation_loop())
        asyncio.create_task(self._posture_assessment_loop())

    async def stop(self):
        """Stop the continuous validation engine."""
        logger.info("Stopping continuous validation engine")
        self.running = False

    async def trigger_validation(
        self,
        trigger: ValidationTrigger,
        target: str,
        vulnerabilities: List[Dict],
        priority: Optional[PenTestPriority] = None,
        metadata: Optional[Dict] = None,
    ) -> ValidationJob:
        """Trigger a validation job."""
        logger.info(
            f"Triggering validation: {trigger.value} for target: {target} with {len(vulnerabilities)} vulnerabilities"
        )

        job = ValidationJob(
            id=self._generate_job_id(),
            trigger=trigger,
            status=ValidationStatus.SCHEDULED,
            target=target,
            vulnerabilities=vulnerabilities,
            priority=priority or self._auto_prioritize(vulnerabilities),
            metadata=metadata or {},
        )

        self.active_jobs[job.id] = job
        return job

    async def _process_validation_queue(self):
        """Process the validation queue continuously."""
        while self.running:
            # Get next job to process
            next_job = self._get_next_job()

            if next_job:
                await self._execute_validation_job(next_job)

            # Wait before checking again
            await asyncio.sleep(5)

    async def _scheduled_validation_loop(self):
        """Run scheduled validation checks."""
        while self.running:
            # Run scheduled validations (e.g., daily regression tests)
            await self._run_scheduled_validations()

            # Wait 1 hour before next check
            await asyncio.sleep(3600)

    async def _posture_assessment_loop(self):
        """Continuously assess and update security posture."""
        while self.running:
            # Assess current security posture
            posture = await self._assess_security_posture()
            self.posture_history.append(posture)

            # Keep only last 30 days of history
            cutoff = datetime.utcnow() - timedelta(days=30)
            self.posture_history = [
                p for p in self.posture_history if p.timestamp > cutoff
            ]

            # Wait 6 hours before next assessment
            await asyncio.sleep(21600)

    async def _execute_validation_job(self, job: ValidationJob):
        """Execute a single validation job."""
        logger.info(f"Executing validation job: {job.id}")

        job.status = ValidationStatus.IN_PROGRESS
        job.started_at = datetime.utcnow()

        try:
            # Group vulnerabilities by type for efficient testing
            grouped_vulns = self._group_vulnerabilities(job.vulnerabilities)

            results = []
            for vuln_type, vulns in grouped_vulns.items():
                logger.info(f"Testing {len(vulns)} {vuln_type} vulnerabilities")

                for vuln in vulns:
                    # Get multi-AI consensus
                    context = {
                        "target": job.target,
                        "trigger": job.trigger.value,
                        "job_id": job.id,
                    }

                    result = await self.mpte_client.execute_pentest_with_consensus(
                        vuln, context
                    )
                    results.append(result)

            # Analyze results
            job.result = {
                "total_tested": len(job.vulnerabilities),
                "results": results,
                "summary": self._summarize_results(results),
            }

            job.status = ValidationStatus.COMPLETED
            job.completed_at = datetime.utcnow()

            logger.info(f"Validation job {job.id} completed: {job.result['summary']}")

        except Exception as e:
            logger.error(f"Validation job {job.id} failed: {e}")
            job.status = ValidationStatus.FAILED
            job.completed_at = datetime.utcnow()
            job.result = {"error": str(e)}

        finally:
            # Move from active to completed
            if job.id in self.active_jobs:
                del self.active_jobs[job.id]
            self.completed_jobs.append(job)

    def _get_next_job(self) -> Optional[ValidationJob]:
        """Get the next job to process based on priority."""
        scheduled_jobs = [
            j
            for j in self.active_jobs.values()
            if j.status == ValidationStatus.SCHEDULED
        ]

        if not scheduled_jobs:
            return None

        # Sort by priority and creation time
        priority_order = {
            PenTestPriority.CRITICAL: 0,
            PenTestPriority.HIGH: 1,
            PenTestPriority.MEDIUM: 2,
            PenTestPriority.LOW: 3,
        }

        sorted_jobs = sorted(
            scheduled_jobs, key=lambda j: (priority_order[j.priority], j.created_at)
        )

        return sorted_jobs[0] if sorted_jobs else None

    def _group_vulnerabilities(
        self, vulnerabilities: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Group vulnerabilities by type for efficient batch testing."""
        grouped: Dict[str, List[Dict]] = {}

        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            if vuln_type not in grouped:
                grouped[vuln_type] = []
            grouped[vuln_type].append(vuln)

        return grouped

    def _auto_prioritize(self, vulnerabilities: List[Dict]) -> PenTestPriority:
        """Automatically determine priority based on vulnerabilities."""
        if not vulnerabilities:
            return PenTestPriority.LOW

        # Check for critical/high severity vulnerabilities
        severities = [v.get("severity", "low").lower() for v in vulnerabilities]

        if "critical" in severities:
            return PenTestPriority.CRITICAL
        elif "high" in severities:
            return PenTestPriority.HIGH
        elif "medium" in severities:
            return PenTestPriority.MEDIUM
        else:
            return PenTestPriority.LOW

    def _summarize_results(self, results: List[Dict]) -> Dict:
        """Summarize validation results."""
        total = len(results)
        completed = sum(1 for r in results if r.get("status") == "completed")
        exploitable = sum(
            1 for r in results if r.get("result", {}).get("exploit_successful", False)
        )

        return {
            "total": total,
            "completed": completed,
            "exploitable": exploitable,
            "false_positives": completed - exploitable,
            "success_rate": completed / total if total > 0 else 0,
            "exploitable_rate": exploitable / total if total > 0 else 0,
        }

    async def _run_scheduled_validations(self):
        """Run scheduled validation checks against configured targets."""
        logger.info("Running scheduled validations")
        # Fetch active targets from completed jobs and re-validate them
        for job in list(self.active_jobs.values()):
            if job.status == "completed":
                logger.debug("Re-validation cycle", job_id=job.id)


    async def _assess_security_posture(self) -> SecurityPosture:
        """Assess current security posture."""
        logger.info("Assessing security posture")

        # Analyze recent validation results
        recent_jobs = self.completed_jobs[-100:]  # Last 100 jobs

        total_vulns = sum(len(j.vulnerabilities) for j in recent_jobs)
        exploitable = sum(
            j.result.get("summary", {}).get("exploitable", 0)
            for j in recent_jobs
            if j.result
        )

        # Calculate risk score (0-100)
        risk_score = (exploitable / total_vulns * 100) if total_vulns > 0 else 0

        # Determine trend
        trend = self._calculate_trend()

        # Get critical findings
        critical_findings = self._get_critical_findings(recent_jobs)

        # Generate recommendations
        recommendations = await self._generate_recommendations(
            risk_score, critical_findings
        )

        return SecurityPosture(
            timestamp=datetime.utcnow(),
            total_vulnerabilities=total_vulns,
            confirmed_exploitable=exploitable,
            risk_score=risk_score,
            trend=trend,
            critical_findings=critical_findings,
            recommendations=recommendations,
            metadata={"jobs_analyzed": len(recent_jobs)},
        )

    def _calculate_trend(self) -> str:
        """Calculate security posture trend."""
        if len(self.posture_history) < 2:
            return "stable"

        current = self.posture_history[-1]
        previous = self.posture_history[-2]

        if current.risk_score < previous.risk_score - 5:
            return "improving"
        elif current.risk_score > previous.risk_score + 5:
            return "degrading"
        else:
            return "stable"

    def _get_critical_findings(self, jobs: List[ValidationJob]) -> List[str]:
        """Extract critical findings from recent jobs."""
        findings = []

        for job in jobs:
            if not job.result:
                continue

            results = job.result.get("results", [])
            for result in results:
                if result.get("status") == "completed" and result.get("result", {}).get(
                    "exploit_successful", False
                ):
                    consensus = result.get("consensus", {})
                    if consensus.get("confidence", 0) > 0.8:
                        finding = f"Critical exploitable vulnerability in {job.target}"
                        findings.append(finding)

        return list(set(findings))[:10]  # Top 10 unique findings

    async def _generate_recommendations(
        self, risk_score: float, critical_findings: List[str]
    ) -> List[str]:
        """Generate security recommendations using AI."""
        prompt = f"""You are a security advisor generating recommendations.

Current Risk Score: {risk_score}/100
Critical Findings: {len(critical_findings)}

Recent Critical Issues:
{chr(10).join(f"- {f}" for f in critical_findings[:5])}

Generate 5-7 actionable security recommendations to improve the security posture.
Focus on high-impact, practical actions.

Respond as a JSON array of recommendation strings.
"""

        try:
            # Use Gemini (architect role) for strategic recommendations
            response = await self.orchestrator._call_llm("gemini", prompt)
            recommendations = json.loads(response)
            return recommendations if isinstance(recommendations, list) else []
        except Exception as e:
            logger.error(f"Failed to generate recommendations: {e}")
            return [
                "Prioritize remediation of critical vulnerabilities",
                "Implement web application firewall (WAF)",
                "Conduct security training for development team",
                "Enable automated security scanning in CI/CD pipeline",
                "Review and update access controls",
            ]

    def get_statistics(self) -> Dict:
        """Get continuous validation statistics."""
        total_jobs = len(self.completed_jobs)
        active = len(self.active_jobs)

        completed = sum(
            1 for j in self.completed_jobs if j.status == ValidationStatus.COMPLETED
        )
        failed = sum(
            1 for j in self.completed_jobs if j.status == ValidationStatus.FAILED
        )

        avg_duration = (
            sum(
                (j.completed_at - j.started_at).total_seconds()
                for j in self.completed_jobs
                if j.started_at and j.completed_at
            )
            / completed
            if completed > 0
            else 0
        )

        current_posture = self.posture_history[-1] if self.posture_history else None

        return {
            "total_jobs": total_jobs,
            "active_jobs": active,
            "completed_jobs": completed,
            "failed_jobs": failed,
            "success_rate": completed / total_jobs if total_jobs > 0 else 0,
            "average_duration_seconds": avg_duration,
            "current_risk_score": current_posture.risk_score if current_posture else 0,
            "security_trend": current_posture.trend if current_posture else "unknown",
        }

    def _generate_job_id(self) -> str:
        """Generate a unique job ID."""
        import uuid

        return f"val-{uuid.uuid4().hex[:16]}"
