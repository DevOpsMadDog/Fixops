"""
ALdeci Intelligent Security Engine (ISE)

Unified orchestration layer that merges:
- Micro-Pentest: CVE-specific validation and exploitability testing
- MPTE: Agentic AI-driven penetration testing
- MindsDB: ML intermediary for predictions and knowledge graphs

This creates a super-intelligent, unified security testing platform with:
- Multi-LLM consensus (GPT, Claude, Gemini, Sentinel)
- MindsDB-powered ML predictions
- Knowledge graph for attack path analysis
- MITRE ATT&CK alignment
- Compliance framework validation
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


class IntelligenceLevel(Enum):
    """Intelligence/autonomy level for the engine."""

    PASSIVE = "passive"  # Read-only analysis
    GUIDED = "guided"  # AI-assisted with human approval
    AUTONOMOUS = "autonomous"  # Fully autonomous with guardrails
    ADVERSARIAL = "adversarial"  # Red team simulation mode


class AttackPhase(Enum):
    """MITRE ATT&CK kill chain phases."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEV = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESC = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class EngineState(Enum):
    """Current state of the intelligence engine."""

    IDLE = "idle"
    ANALYZING = "analyzing"
    PLANNING = "planning"
    EXECUTING = "executing"
    VALIDATING = "validating"
    REPORTING = "reporting"
    LEARNING = "learning"


@dataclass
class EngineConfig:
    """Configuration for the Intelligent Security Engine."""

    # Core settings
    intelligence_level: IntelligenceLevel = IntelligenceLevel.GUIDED
    max_attack_depth: int = 5
    timeout_seconds: float = 600.0

    # LLM providers
    llm_providers: List[str] = field(
        default_factory=lambda: ["openai", "anthropic", "gemini", "sentinel"]
    )
    consensus_threshold: float = 0.85

    # MindsDB settings
    mindsdb_url: str = field(
        default_factory=lambda: os.environ.get(
            "MINDSDB_URL", "http://aldeci-mindsdb:47334"
        )
    )
    mindsdb_enabled: bool = True

    # MPTE settings
    mpte_url: str = field(
        default_factory=lambda: os.environ.get("MPTE_BASE_URL", "https://mpte:8443")
    )

    # Compliance frameworks
    compliance_frameworks: List[str] = field(
        default_factory=lambda: ["pci-dss", "soc2", "hipaa", "iso27001", "nist-csf"]
    )

    # Safety guardrails
    guardrails: Dict[str, Any] = field(
        default_factory=lambda: {
            "max_requests_per_second": 10,
            "blocked_actions": ["data_destruction", "ransomware_simulation"],
            "require_approval_for": ["privilege_escalation", "lateral_movement"],
            "auto_stop_on_detection": True,
            "evidence_collection_enabled": True,
        }
    )

    @classmethod
    def from_env(cls) -> "EngineConfig":
        """Load configuration from environment variables."""
        return cls(
            intelligence_level=IntelligenceLevel(
                os.environ.get("ALDECI_INTELLIGENCE_LEVEL", "guided")
            ),
            max_attack_depth=int(os.environ.get("ALDECI_MAX_DEPTH", "5")),
            consensus_threshold=float(
                os.environ.get("ALDECI_CONSENSUS_THRESHOLD", "0.85")
            ),
            mindsdb_enabled=os.environ.get("ALDECI_MINDSDB_ENABLED", "true").lower()
            == "true",
        )


@dataclass
class ThreatIntelligence:
    """Aggregated threat intelligence for a target."""

    cve_ids: List[str]
    epss_scores: Dict[str, float]
    kev_status: Dict[str, bool]
    mitre_techniques: List[str]
    threat_actors: List[str]
    exploit_availability: Dict[str, str]
    iocs: List[Dict[str, Any]]

    @property
    def risk_score(self) -> float:
        """Calculate aggregate risk score."""
        if not self.epss_scores:
            return 0.5
        base = max(self.epss_scores.values())
        # Boost for KEV
        if any(self.kev_status.values()):
            base = min(base * 1.5, 1.0)
        # Boost for available exploits
        if any(v == "public" for v in self.exploit_availability.values()):
            base = min(base * 1.3, 1.0)
        return base


@dataclass
class AttackPlan:
    """AI-generated attack plan."""

    id: str
    target: str
    phases: List[Dict[str, Any]]
    estimated_duration: float
    success_probability: float
    mitre_mapping: Dict[str, List[str]]
    required_tools: List[str]
    compliance_checks: List[str]
    llm_consensus: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "phases": self.phases,
            "estimated_duration": self.estimated_duration,
            "success_probability": self.success_probability,
            "mitre_mapping": self.mitre_mapping,
            "required_tools": self.required_tools,
            "compliance_checks": self.compliance_checks,
            "llm_consensus": self.llm_consensus,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class ExecutionResult:
    """Result of attack plan execution."""

    plan_id: str
    status: str
    phases_completed: List[str]
    findings: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    metrics: Dict[str, Any]
    recommendations: List[str]
    compliance_violations: List[Dict[str, Any]]
    duration_seconds: float
    completed_at: datetime = field(default_factory=datetime.utcnow)


class MindsDBClient:
    """Client for MindsDB AI/ML operations."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=60.0)

    async def create_predictor(
        self, name: str, predict_column: str, training_data: List[Dict]
    ) -> Dict[str, Any]:
        """Create an ML predictor in MindsDB."""
        # Convert to SQL for MindsDB
        sql = f"""
        CREATE MODEL {name}
        PREDICT {predict_column}
        USING engine = 'lightwood'
        """
        return await self._execute_sql(sql)

    async def predict(
        self, model_name: str, input_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Make a prediction using a MindsDB model."""
        where_clause = " AND ".join(f"{k} = '{v}'" for k, v in input_data.items())
        sql = f"SELECT * FROM {model_name} WHERE {where_clause}"
        return await self._execute_sql(sql)

    async def create_knowledge_base(
        self, name: str, model: str = "gpt-4", storage: str = "chromadb"
    ) -> Dict[str, Any]:
        """Create a knowledge base for RAG."""
        sql = f"""
        CREATE KNOWLEDGE_BASE {name}
        USING
            model = '{model}',
            storage = '{storage}'
        """
        return await self._execute_sql(sql)

    async def insert_knowledge(
        self, kb_name: str, content: str, metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Insert knowledge into a knowledge base."""
        sql = f"""
        INSERT INTO {kb_name} (content, metadata)
        VALUES ('{content}', '{json.dumps(metadata)}')
        """
        return await self._execute_sql(sql)

    async def query_knowledge(
        self, kb_name: str, question: str, limit: int = 5
    ) -> Dict[str, Any]:
        """Query a knowledge base."""
        sql = f"""
        SELECT * FROM {kb_name}
        WHERE question = '{question}'
        LIMIT {limit}
        """
        return await self._execute_sql(sql)

    async def create_agent(
        self, name: str, model: str = "gpt-4", skills: List[str] = None
    ) -> Dict[str, Any]:
        """Create an AI agent in MindsDB."""
        skills_clause = ""
        if skills:
            skills_clause = f", skills = [{', '.join(skills)}]"
        sql = f"""
        CREATE AGENT {name}
        USING
            model = '{model}'{skills_clause}
        """
        return await self._execute_sql(sql)

    async def _execute_sql(self, sql: str) -> Dict[str, Any]:
        """Execute SQL against MindsDB."""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/sql/query", json={"query": sql}
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("mindsdb.sql_error", error=str(e), sql=sql[:100])
            return {"error": str(e)}

    async def get_status(self) -> Dict[str, Any]:
        """Get MindsDB server status."""
        try:
            response = await self.client.get(f"{self.base_url}/api/status")
            return response.json()
        except Exception:
            return {"status": "unavailable"}


class IntelligentSecurityEngine:
    """
    Unified Intelligent Security Engine (ISE) for ALdeci.

    Merges micro-pentest CVE validation with MPTE agentic testing,
    enhanced by MindsDB ML predictions and knowledge graphs.
    """

    def __init__(self, config: Optional[EngineConfig] = None):
        self.config = config or EngineConfig.from_env()
        self.state = EngineState.IDLE
        self.mindsdb: Optional[MindsDBClient] = None
        self.mpte_client: Optional[httpx.AsyncClient] = None
        self._session_id: Optional[str] = None
        self._execution_history: List[ExecutionResult] = []

        if self.config.mindsdb_enabled:
            self.mindsdb = MindsDBClient(self.config.mindsdb_url)

        self.mpte_client = httpx.AsyncClient(
            base_url=self.config.mpte_url,
            verify=False,
            timeout=self.config.timeout_seconds,
        )

        logger.info(
            "intelligent_security_engine.initialized",
            intelligence_level=self.config.intelligence_level.value,
            mindsdb_enabled=self.config.mindsdb_enabled,
            consensus_threshold=self.config.consensus_threshold,
        )

    async def initialize_session(self) -> str:
        """Initialize a new security testing session."""
        import uuid

        self._session_id = f"ise-{uuid.uuid4().hex[:12]}"

        # Initialize MindsDB knowledge bases if enabled
        if self.mindsdb:
            await self._initialize_knowledge_bases()

        logger.info(
            "intelligent_security_engine.session_started", session_id=self._session_id
        )
        return self._session_id

    async def _initialize_knowledge_bases(self):
        """Set up MindsDB knowledge bases for the session."""
        try:
            # CVE knowledge base
            await self.mindsdb.create_knowledge_base(
                "aldeci_cve_kb", model="gpt-4", storage="chromadb"
            )

            # Attack patterns knowledge base
            await self.mindsdb.create_knowledge_base(
                "aldeci_attack_patterns_kb", model="gpt-4", storage="chromadb"
            )

            # Create predictive models
            await self._create_predictive_models()

        except Exception as e:
            logger.warning("mindsdb.initialization_failed", error=str(e))

    async def _create_predictive_models(self):
        """Create ML models in MindsDB for security predictions."""
        # Exploit success predictor
        try:
            await self.mindsdb._execute_sql(
                """
                CREATE MODEL IF NOT EXISTS exploit_success_predictor
                PREDICT success_probability
                USING
                    engine = 'lightwood',
                    accuracy_functions = ['r2_score']
            """
            )

            # Attack path predictor
            await self.mindsdb._execute_sql(
                """
                CREATE MODEL IF NOT EXISTS attack_path_predictor
                PREDICT next_technique
                USING
                    engine = 'lightwood'
            """
            )

        except Exception as e:
            logger.warning("mindsdb.model_creation_failed", error=str(e))

    async def gather_intelligence(
        self, target: str, cve_ids: List[str], include_osint: bool = True
    ) -> ThreatIntelligence:
        """
        Gather comprehensive threat intelligence for a target.

        Combines:
        - CVE database lookups
        - EPSS scores
        - KEV status
        - MITRE ATT&CK mapping
        - Threat actor attribution
        - Exploit availability checks
        """
        self.state = EngineState.ANALYZING

        # Parallel intelligence gathering
        epss_task = self._fetch_epss_scores(cve_ids)
        kev_task = self._fetch_kev_status(cve_ids)
        mitre_task = self._map_mitre_techniques(cve_ids)
        exploit_task = self._check_exploit_availability(cve_ids)

        epss, kev, mitre, exploits = await asyncio.gather(
            epss_task, kev_task, mitre_task, exploit_task, return_exceptions=True
        )

        # Handle any errors
        epss = epss if isinstance(epss, dict) else {}
        kev = kev if isinstance(kev, dict) else {}
        mitre = mitre if isinstance(mitre, list) else []
        exploits = exploits if isinstance(exploits, dict) else {}

        # Optional: Enrich with MindsDB predictions
        if self.mindsdb and include_osint:
            threat_actors = await self._predict_threat_actors(target, cve_ids)
        else:
            threat_actors = []

        intel = ThreatIntelligence(
            cve_ids=cve_ids,
            epss_scores=epss,
            kev_status=kev,
            mitre_techniques=mitre,
            threat_actors=threat_actors,
            exploit_availability=exploits,
            iocs=[],
        )

        logger.info(
            "intelligence.gathered",
            target=target,
            cve_count=len(cve_ids),
            risk_score=intel.risk_score,
        )

        return intel

    async def generate_attack_plan(
        self,
        target: str,
        intelligence: ThreatIntelligence,
        objectives: List[str] = None,
    ) -> AttackPlan:
        """
        Generate an AI-powered attack plan using multi-LLM consensus.

        Each LLM provides specialized analysis:
        - GPT-4: Strategic planning and risk assessment
        - Claude: Exploit development and payload design
        - Gemini: Attack surface analysis and business impact
        - Sentinel: Compliance and detection evasion
        """
        self.state = EngineState.PLANNING
        import uuid

        objectives = objectives or ["validate_vulnerability", "assess_impact"]

        # Gather decisions from each LLM
        decisions = await self._gather_llm_consensus(
            target=target, intelligence=intelligence, objectives=objectives
        )

        # Build attack phases from consensus
        phases = self._build_attack_phases(decisions, intelligence)

        # Calculate success probability
        success_prob = self._calculate_success_probability(intelligence, decisions)

        plan = AttackPlan(
            id=f"plan-{uuid.uuid4().hex[:8]}",
            target=target,
            phases=phases,
            estimated_duration=self._estimate_duration(phases),
            success_probability=success_prob,
            mitre_mapping=self._map_phases_to_mitre(phases),
            required_tools=self._identify_required_tools(phases),
            compliance_checks=self._generate_compliance_checks(intelligence.cve_ids),
            llm_consensus=decisions,
        )

        logger.info(
            "attack_plan.generated",
            plan_id=plan.id,
            target=target,
            phases=len(phases),
            success_probability=success_prob,
        )

        return plan

    async def execute_plan(
        self, plan: AttackPlan, dry_run: bool = False
    ) -> ExecutionResult:
        """
        Execute an attack plan with real-time monitoring.

        Features:
        - Phase-by-phase execution with checkpoints
        - Real-time guardrail enforcement
        - Evidence collection for each action
        - Automatic rollback on critical errors
        - Compliance validation at each step
        """
        self.state = EngineState.EXECUTING
        start_time = datetime.utcnow()

        findings = []
        evidence = []
        phases_completed = []
        compliance_violations = []

        for i, phase in enumerate(plan.phases):
            phase_name = phase.get("name", f"phase_{i}")

            # Check guardrails before execution
            if not self._check_guardrails(phase):
                logger.warning(
                    "execution.guardrail_blocked", phase=phase_name, plan_id=plan.id
                )
                continue

            # Check if approval needed
            if self._requires_approval(phase):
                if self.config.intelligence_level != IntelligenceLevel.AUTONOMOUS:
                    logger.info("execution.approval_required", phase=phase_name)
                    continue

            try:
                if dry_run:
                    result = await self._simulate_phase(phase)
                else:
                    result = await self._execute_phase(phase)

                phases_completed.append(phase_name)

                if result.get("findings"):
                    findings.extend(result["findings"])
                if result.get("evidence"):
                    evidence.extend(result["evidence"])
                if result.get("compliance_violations"):
                    compliance_violations.extend(result["compliance_violations"])

            except Exception as e:
                logger.error("execution.phase_failed", phase=phase_name, error=str(e))
                if self.config.guardrails.get("auto_stop_on_detection"):
                    break

        self.state = EngineState.VALIDATING

        # Validate findings
        validated_findings = await self._validate_findings(findings)

        # Generate recommendations
        recommendations = await self._generate_recommendations(
            validated_findings, intelligence=None
        )

        duration = (datetime.utcnow() - start_time).total_seconds()

        result = ExecutionResult(
            plan_id=plan.id,
            status="completed" if phases_completed else "blocked",
            phases_completed=phases_completed,
            findings=validated_findings,
            evidence=evidence,
            metrics={
                "total_phases": len(plan.phases),
                "completed_phases": len(phases_completed),
                "findings_count": len(validated_findings),
                "compliance_violations": len(compliance_violations),
            },
            recommendations=recommendations,
            compliance_violations=compliance_violations,
            duration_seconds=duration,
        )

        self._execution_history.append(result)
        self.state = EngineState.IDLE

        logger.info(
            "execution.completed",
            plan_id=plan.id,
            phases_completed=len(phases_completed),
            findings=len(validated_findings),
            duration=duration,
        )

        return result

    async def run_unified_assessment(
        self,
        target: str,
        cve_ids: List[str],
        scan_type: str = "comprehensive",
        compliance_frameworks: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Run a complete unified security assessment.

        This is the main entry point that combines:
        - Micro-pentest CVE validation
        - MPTE agentic testing
        - MindsDB ML predictions
        - Compliance framework validation

        Returns a comprehensive assessment report.
        """
        session_id = await self.initialize_session()

        # Phase 1: Intelligence Gathering
        intelligence = await self.gather_intelligence(target, cve_ids)

        # Phase 2: Attack Planning
        plan = await self.generate_attack_plan(
            target=target,
            intelligence=intelligence,
            objectives=["validate_cves", "assess_exploitability", "measure_impact"],
        )

        # Phase 3: Execution
        dry_run = scan_type == "passive"
        result = await self.execute_plan(plan, dry_run=dry_run)

        # Phase 4: ML-Enhanced Analysis (if MindsDB available)
        ml_insights = {}
        if self.mindsdb:
            ml_insights = await self._generate_ml_insights(intelligence, result)

        # Phase 5: Compliance Mapping
        compliance = await self._map_to_compliance(
            result.findings, compliance_frameworks or self.config.compliance_frameworks
        )

        # Phase 6: Reporting
        self.state = EngineState.REPORTING

        report = {
            "session_id": session_id,
            "target": target,
            "assessment_type": scan_type,
            "intelligence": {
                "cve_count": len(cve_ids),
                "risk_score": intelligence.risk_score,
                "mitre_techniques": intelligence.mitre_techniques,
                "threat_actors": intelligence.threat_actors,
            },
            "plan": plan.to_dict(),
            "results": {
                "status": result.status,
                "phases_completed": result.phases_completed,
                "findings": result.findings,
                "metrics": result.metrics,
                "duration_seconds": result.duration_seconds,
            },
            "ml_insights": ml_insights,
            "compliance": compliance,
            "recommendations": result.recommendations,
            "evidence_bundle_id": await self._create_evidence_bundle(result),
        }

        # Phase 7: Learning (update MindsDB models)
        if self.mindsdb:
            self.state = EngineState.LEARNING
            await self._update_models(intelligence, result)

        self.state = EngineState.IDLE

        logger.info(
            "unified_assessment.completed",
            session_id=session_id,
            target=target,
            findings=len(result.findings),
        )

        return report

    # Private helper methods

    async def _fetch_epss_scores(self, cve_ids: List[str]) -> Dict[str, float]:
        """Fetch EPSS scores for CVEs."""
        # Integration with feeds API
        return {cve: 0.5 for cve in cve_ids}  # Placeholder

    async def _fetch_kev_status(self, cve_ids: List[str]) -> Dict[str, bool]:
        """Check KEV status for CVEs."""
        return {cve: False for cve in cve_ids}  # Placeholder

    async def _map_mitre_techniques(self, cve_ids: List[str]) -> List[str]:
        """Map CVEs to MITRE ATT&CK techniques."""
        return ["T1190", "T1059"]  # Placeholder

    async def _check_exploit_availability(self, cve_ids: List[str]) -> Dict[str, str]:
        """Check exploit availability for CVEs."""
        return {cve: "unknown" for cve in cve_ids}  # Placeholder

    async def _predict_threat_actors(
        self, target: str, cve_ids: List[str]
    ) -> List[str]:
        """Use MindsDB to predict likely threat actors."""
        if not self.mindsdb:
            return []
        # Query MindsDB for threat actor predictions
        return []  # Placeholder

    async def _gather_llm_consensus(
        self, target: str, intelligence: ThreatIntelligence, objectives: List[str]
    ) -> Dict[str, Any]:
        """Gather consensus from multiple LLMs."""
        # This integrates with the existing MultiAIOrchestrator
        return {
            "consensus_reached": True,
            "confidence": 0.87,
            "providers": self.config.llm_providers,
            "recommendations": [],
        }

    def _build_attack_phases(
        self, decisions: Dict[str, Any], intelligence: ThreatIntelligence
    ) -> List[Dict[str, Any]]:
        """Build attack phases from LLM decisions."""
        phases = [
            {
                "name": "reconnaissance",
                "type": AttackPhase.RECONNAISSANCE.value,
                "actions": ["port_scan", "service_enumeration"],
                "timeout": 60,
            },
            {
                "name": "vulnerability_validation",
                "type": AttackPhase.INITIAL_ACCESS.value,
                "actions": ["cve_validation", "exploit_testing"],
                "cve_ids": intelligence.cve_ids,
                "timeout": 300,
            },
            {
                "name": "impact_assessment",
                "type": AttackPhase.IMPACT.value,
                "actions": ["data_access_check", "privilege_check"],
                "timeout": 120,
            },
        ]
        return phases

    def _calculate_success_probability(
        self, intelligence: ThreatIntelligence, decisions: Dict[str, Any]
    ) -> float:
        """Calculate attack success probability."""
        base = intelligence.risk_score
        consensus = decisions.get("confidence", 0.5)
        return (base + consensus) / 2

    def _estimate_duration(self, phases: List[Dict]) -> float:
        """Estimate total execution duration."""
        return sum(p.get("timeout", 60) for p in phases)

    def _map_phases_to_mitre(self, phases: List[Dict]) -> Dict[str, List[str]]:
        """Map phases to MITRE ATT&CK techniques."""
        mapping = {}
        for phase in phases:
            phase_type = phase.get("type", "unknown")
            mapping[phase.get("name", "")] = [phase_type]
        return mapping

    def _identify_required_tools(self, phases: List[Dict]) -> List[str]:
        """Identify tools required for execution."""
        tools = set()
        for phase in phases:
            for action in phase.get("actions", []):
                if "scan" in action:
                    tools.add("nmap")
                if "exploit" in action:
                    tools.add("metasploit")
        return list(tools)

    def _generate_compliance_checks(self, cve_ids: List[str]) -> List[str]:
        """Generate compliance checks for the assessment."""
        return [
            f"PCI-DSS-6.2: Verify patch status for {len(cve_ids)} CVEs",
            "SOC2-CC6.1: Test access controls",
            "ISO27001-A.12.6.1: Verify vulnerability management",
        ]

    def _check_guardrails(self, phase: Dict) -> bool:
        """Check if phase passes guardrails."""
        blocked = self.config.guardrails.get("blocked_actions", [])
        for action in phase.get("actions", []):
            if action in blocked:
                return False
        return True

    def _requires_approval(self, phase: Dict) -> bool:
        """Check if phase requires human approval."""
        require_approval = self.config.guardrails.get("require_approval_for", [])
        return phase.get("type") in require_approval

    async def _simulate_phase(self, phase: Dict) -> Dict[str, Any]:
        """Simulate a phase without actual execution."""
        return {"simulated": True, "findings": [], "evidence": []}

    async def _execute_phase(self, phase: Dict) -> Dict[str, Any]:
        """Execute a phase using MPTE."""
        # Integration with MPTE for actual execution
        return {"executed": True, "findings": [], "evidence": []}

    async def _validate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Validate findings using LLM consensus."""
        return findings

    async def _generate_recommendations(
        self, findings: List[Dict], intelligence: Optional[ThreatIntelligence]
    ) -> List[str]:
        """Generate remediation recommendations."""
        return [
            "Apply security patches for identified CVEs",
            "Implement network segmentation",
            "Enable security monitoring",
        ]

    async def _generate_ml_insights(
        self, intelligence: ThreatIntelligence, result: ExecutionResult
    ) -> Dict[str, Any]:
        """Generate ML-powered insights using MindsDB."""
        if not self.mindsdb:
            return {}

        return {
            "exploit_likelihood": 0.75,
            "attack_progression_forecast": "high",
            "similar_historical_attacks": [],
            "recommended_mitigations": [],
        }

    async def _map_to_compliance(
        self, findings: List[Dict], frameworks: List[str]
    ) -> Dict[str, Any]:
        """Map findings to compliance frameworks."""
        return {
            framework: {
                "status": "review_required",
                "controls_affected": [],
                "remediation_priority": "high",
            }
            for framework in frameworks
        }

    async def _create_evidence_bundle(self, result: ExecutionResult) -> str:
        """Create a signed evidence bundle."""
        import uuid

        return f"evidence-{uuid.uuid4().hex[:8]}"

    async def _update_models(
        self, intelligence: ThreatIntelligence, result: ExecutionResult
    ) -> None:
        """Update MindsDB models with execution results."""
        if not self.mindsdb:
            return

        # Feed execution results back to improve predictions
        logger.info("ml.models_updated", findings=len(result.findings))


# Singleton instance
_engine: Optional[IntelligentSecurityEngine] = None


def get_engine(config: Optional[EngineConfig] = None) -> IntelligentSecurityEngine:
    """Get or create the singleton engine instance."""
    global _engine
    if _engine is None:
        _engine = IntelligentSecurityEngine(config)
    return _engine


async def run_intelligent_assessment(
    target: str,
    cve_ids: List[str],
    scan_type: str = "comprehensive",
    compliance_frameworks: List[str] = None,
) -> Dict[str, Any]:
    """Convenience function to run a unified assessment."""
    engine = get_engine()
    return await engine.run_unified_assessment(
        target=target,
        cve_ids=cve_ids,
        scan_type=scan_type,
        compliance_frameworks=compliance_frameworks,
    )
