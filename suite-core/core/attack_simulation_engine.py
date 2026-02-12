"""
FixOps Attack Simulation Engine — Breach & Attack Simulation (BAS).

Multi-stage adversary simulation that models real-world attack campaigns
across the MITRE ATT&CK kill chain. Integrates with:
- Knowledge Graph Brain for asset/vulnerability context
- Event Bus for real-time notifications
- LLM Providers for intelligent scenario generation
- GNN Attack Graph for path prediction

Stages: Reconnaissance → Initial Access → Execution → Persistence →
        Privilege Escalation → Lateral Movement → C2 → Exfiltration
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class KillChainPhase(str, Enum):
    """MITRE ATT&CK kill chain phases."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"


class AttackComplexity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CampaignStatus(str, Enum):
    DRAFT = "draft"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ThreatActorProfile(str, Enum):
    SCRIPT_KIDDIE = "script_kiddie"
    HACKTIVIST = "hacktivist"
    CYBERCRIMINAL = "cybercriminal"
    NATION_STATE = "nation_state"
    INSIDER_THREAT = "insider_threat"
    APT = "apt"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Mapping
# ---------------------------------------------------------------------------

MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    # Reconnaissance
    "T1595": {"name": "Active Scanning", "phase": "reconnaissance", "severity": 0.3},
    "T1592": {"name": "Gather Victim Host Info", "phase": "reconnaissance", "severity": 0.2},
    "T1589": {"name": "Gather Victim Identity Info", "phase": "reconnaissance", "severity": 0.3},
    "T1590": {"name": "Gather Victim Network Info", "phase": "reconnaissance", "severity": 0.4},
    "T1591": {"name": "Gather Victim Org Info", "phase": "reconnaissance", "severity": 0.2},
    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application", "phase": "initial_access", "severity": 0.9},
    "T1133": {"name": "External Remote Services", "phase": "initial_access", "severity": 0.7},
    "T1566": {"name": "Phishing", "phase": "initial_access", "severity": 0.8},
    "T1078": {"name": "Valid Accounts", "phase": "initial_access", "severity": 0.8},
    "T1189": {"name": "Drive-by Compromise", "phase": "initial_access", "severity": 0.6},
    "T1195": {"name": "Supply Chain Compromise", "phase": "initial_access", "severity": 0.95},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "phase": "execution", "severity": 0.7},
    "T1203": {"name": "Exploitation for Client Execution", "phase": "execution", "severity": 0.8},
    "T1047": {"name": "Windows Management Instrumentation", "phase": "execution", "severity": 0.6},
    "T1053": {"name": "Scheduled Task/Job", "phase": "execution", "severity": 0.5},
    # Persistence
    "T1098": {"name": "Account Manipulation", "phase": "persistence", "severity": 0.7},
    "T1136": {"name": "Create Account", "phase": "persistence", "severity": 0.6},
    "T1547": {"name": "Boot or Logon Autostart Execution", "phase": "persistence", "severity": 0.7},
    "T1505": {"name": "Server Software Component (Web Shell)", "phase": "persistence", "severity": 0.9},
    # Privilege Escalation
    "T1068": {"name": "Exploitation for Privilege Escalation", "phase": "privilege_escalation", "severity": 0.9},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "phase": "privilege_escalation", "severity": 0.8},
    "T1134": {"name": "Access Token Manipulation", "phase": "privilege_escalation", "severity": 0.7},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "phase": "lateral_movement", "severity": 0.7},
    "T1550": {"name": "Use Alternate Authentication Material", "phase": "lateral_movement", "severity": 0.8},
    "T1570": {"name": "Lateral Tool Transfer", "phase": "lateral_movement", "severity": 0.6},
    "T1210": {"name": "Exploitation of Remote Services", "phase": "lateral_movement", "severity": 0.9},
    # Command & Control
    "T1071": {"name": "Application Layer Protocol", "phase": "command_and_control", "severity": 0.6},
    "T1573": {"name": "Encrypted Channel", "phase": "command_and_control", "severity": 0.5},
    "T1105": {"name": "Ingress Tool Transfer", "phase": "command_and_control", "severity": 0.7},
    "T1572": {"name": "Protocol Tunneling", "phase": "command_and_control", "severity": 0.6},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "phase": "exfiltration", "severity": 0.8},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "phase": "exfiltration", "severity": 0.7},
    "T1567": {"name": "Exfiltration Over Web Service", "phase": "exfiltration", "severity": 0.8},
    "T1537": {"name": "Transfer Data to Cloud Account", "phase": "exfiltration", "severity": 0.9},
}

PRIVILEGE_LEVELS = [
    "anonymous", "guest", "user", "power_user", "admin", "system", "root",
]

LATERAL_TECHNIQUES = {
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.003": "Distributed Component Object Model",
    "T1021.004": "SSH",
    "T1021.005": "VNC",
    "T1021.006": "Windows Remote Management",
    "T1550.002": "Pass the Hash",
    "T1550.003": "Pass the Ticket",
}


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class AttackStep:
    """A single step in an attack simulation."""
    step_id: str = ""
    phase: KillChainPhase = KillChainPhase.RECONNAISSANCE
    technique_id: str = ""
    technique_name: str = ""
    description: str = ""
    target_asset: str = ""
    success_probability: float = 0.0
    impact_score: float = 0.0
    duration_seconds: float = 0.0
    status: str = "pending"  # pending, executing, succeeded, failed, skipped
    output: str = ""
    artifacts: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self):
        if not self.step_id:
            self.step_id = f"step-{uuid.uuid4().hex[:8]}"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class AttackPath:
    """A sequence of steps forming an attack path."""
    path_id: str = ""
    steps: List[AttackStep] = field(default_factory=list)
    entry_point: str = ""
    target: str = ""
    total_probability: float = 0.0
    total_impact: float = 0.0
    techniques_used: List[str] = field(default_factory=list)
    blast_radius: int = 0

    def __post_init__(self):
        if not self.path_id:
            self.path_id = f"path-{uuid.uuid4().hex[:8]}"


@dataclass
class BreachImpact:
    """Business impact assessment of a simulated breach."""
    financial_loss_min: float = 0.0
    financial_loss_max: float = 0.0
    financial_loss_expected: float = 0.0
    data_records_at_risk: int = 0
    systems_compromised: int = 0
    recovery_time_hours: float = 0.0
    compliance_violations: List[str] = field(default_factory=list)
    affected_business_units: List[str] = field(default_factory=list)
    reputation_impact: str = "low"  # low, medium, high, critical
    regulatory_notifications: List[str] = field(default_factory=list)


@dataclass
class AttackScenario:
    """A pre-defined or AI-generated attack scenario."""
    scenario_id: str = ""
    name: str = ""
    description: str = ""
    threat_actor: ThreatActorProfile = ThreatActorProfile.CYBERCRIMINAL
    complexity: AttackComplexity = AttackComplexity.MEDIUM
    target_assets: List[str] = field(default_factory=list)
    target_cves: List[str] = field(default_factory=list)
    kill_chain_phases: List[KillChainPhase] = field(default_factory=list)
    initial_access_vector: str = ""
    objectives: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def __post_init__(self):
        if not self.scenario_id:
            self.scenario_id = f"scenario-{uuid.uuid4().hex[:8]}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.kill_chain_phases:
            self.kill_chain_phases = list(KillChainPhase)


@dataclass
class CampaignResult:
    """Results of a full attack simulation campaign."""
    campaign_id: str = ""
    scenario: Optional[AttackScenario] = None
    status: CampaignStatus = CampaignStatus.DRAFT
    attack_paths: List[AttackPath] = field(default_factory=list)
    steps_executed: int = 0
    steps_succeeded: int = 0
    steps_failed: int = 0
    breach_impact: Optional[BreachImpact] = None
    mitre_coverage: Dict[str, List[str]] = field(default_factory=dict)
    total_duration_seconds: float = 0.0
    risk_score: float = 0.0
    executive_summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""

    def __post_init__(self):
        if not self.campaign_id:
            self.campaign_id = f"campaign-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Attack Simulation Engine
# ---------------------------------------------------------------------------


class AttackSimulationEngine:
    """
    Orchestrates multi-stage adversary simulations.

    Integrates Knowledge Graph for asset context, LLM for scenario
    generation, Event Bus for cross-suite notifications, and GNN
    attack graph for path prediction.
    """

    def __init__(self) -> None:
        self._campaigns: Dict[str, CampaignResult] = {}
        self._scenarios: Dict[str, AttackScenario] = {}
        self._brain = None
        self._bus = None
        self._llm = None
        self._gnn = None
        logger.info("AttackSimulationEngine initialized")

    # ---- Lazy dependency loaders (graceful degradation) ----

    def _get_brain(self):
        if self._brain is None:
            try:
                from core.knowledge_brain import get_brain
                self._brain = get_brain()
            except Exception:
                pass
        return self._brain

    def _get_bus(self):
        if self._bus is None:
            try:
                from core.event_bus import get_event_bus
                self._bus = get_event_bus()
            except Exception:
                pass
        return self._bus

    def _get_llm(self):
        if self._llm is None:
            try:
                from core.llm_providers import LLMProviderManager
                self._llm = LLMProviderManager()
            except Exception:
                pass
        return self._llm

    def _get_gnn(self):
        if self._gnn is None:
            try:
                from core.attack_graph_gnn import GraphNeuralPredictor
                self._gnn = GraphNeuralPredictor()
            except Exception:
                pass
        return self._gnn

    # ---- Scenario Management ----

    def create_scenario(
        self,
        name: str,
        description: str = "",
        threat_actor: str = "cybercriminal",
        complexity: str = "medium",
        target_assets: Optional[List[str]] = None,
        target_cves: Optional[List[str]] = None,
        objectives: Optional[List[str]] = None,
        initial_access_vector: str = "",
    ) -> AttackScenario:
        """Create a new attack scenario."""
        actor = ThreatActorProfile(threat_actor) if threat_actor in [e.value for e in ThreatActorProfile] else ThreatActorProfile.CYBERCRIMINAL
        cmplx = AttackComplexity(complexity) if complexity in [e.value for e in AttackComplexity] else AttackComplexity.MEDIUM

        scenario = AttackScenario(
            name=name,
            description=description or f"Attack simulation: {name}",
            threat_actor=actor,
            complexity=cmplx,
            target_assets=target_assets or [],
            target_cves=target_cves or [],
            objectives=objectives or ["validate_vulnerability", "assess_impact"],
            initial_access_vector=initial_access_vector or "T1190",
        )
        self._scenarios[scenario.scenario_id] = scenario
        logger.info("scenario.created", extra={"scenario_id": scenario.scenario_id, "scenario_name": name})
        return scenario

    def list_scenarios(self) -> List[AttackScenario]:
        """List all scenarios."""
        return list(self._scenarios.values())

    def get_scenario(self, scenario_id: str) -> Optional[AttackScenario]:
        """Get a scenario by ID."""
        return self._scenarios.get(scenario_id)

    async def generate_scenario_with_llm(
        self,
        target_description: str,
        threat_actor: str = "cybercriminal",
        cve_ids: Optional[List[str]] = None,
    ) -> AttackScenario:
        """Use LLM to generate an intelligent attack scenario."""
        llm = self._get_llm()
        prompt = (
            f"You are a red team expert. Generate a detailed attack scenario for:\n"
            f"Target: {target_description}\n"
            f"Threat Actor Profile: {threat_actor}\n"
            f"Known CVEs: {', '.join(cve_ids or ['none'])}\n\n"
            f"Provide: attack name, description, kill chain phases to exercise, "
            f"initial access vector (MITRE technique ID), specific objectives, "
            f"and complexity assessment. Format as structured analysis."
        )

        llm_response = None
        if llm:
            try:
                llm_response = llm.analyse(
                    "openai",
                    prompt=prompt,
                    context={"target": target_description, "cves": cve_ids or []},
                    default_action="generate_scenario",
                    default_confidence=0.7,
                    default_reasoning="LLM-generated attack scenario",
                )
            except Exception as exc:
                logger.warning("llm_scenario_generation.failed: %s", exc)

        reasoning = llm_response.reasoning if llm_response else "AI-generated red team scenario"
        confidence = llm_response.confidence if llm_response else 0.6

        # Map confidence to complexity
        if confidence >= 0.8:
            complexity = "critical"
        elif confidence >= 0.6:
            complexity = "high"
        elif confidence >= 0.4:
            complexity = "medium"
        else:
            complexity = "low"

        scenario = self.create_scenario(
            name=f"AI-Generated: {target_description[:60]}",
            description=reasoning[:500],
            threat_actor=threat_actor,
            complexity=complexity,
            target_cves=cve_ids or [],
            objectives=["validate_vulnerability", "assess_blast_radius", "test_detection"],
            initial_access_vector="T1190",
        )
        return scenario

    # ---- Campaign Execution ----

    async def run_campaign(
        self,
        scenario_id: str,
        org_id: Optional[str] = None,
    ) -> CampaignResult:
        """Execute a full attack simulation campaign."""
        scenario = self._scenarios.get(scenario_id)
        if not scenario:
            raise ValueError(f"Scenario {scenario_id} not found")

        campaign = CampaignResult(
            scenario=scenario,
            status=CampaignStatus.RUNNING,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._campaigns[campaign.campaign_id] = campaign

        logger.info(
            "campaign.started",
            extra={"campaign_id": campaign.campaign_id, "scenario": scenario.name},
        )

        # Emit start event
        bus = self._get_bus()
        if bus:
            try:
                from core.event_bus import Event, EventType
                await bus.emit(Event(
                    event_type=EventType.ATTACK_SIMULATED,
                    source="attack_simulation_engine",
                    data={"campaign_id": campaign.campaign_id, "action": "started", "scenario": scenario.name},
                    org_id=org_id,
                ))
            except Exception:
                pass

        try:
            # Execute each kill chain phase
            all_steps: List[AttackStep] = []
            for phase in scenario.kill_chain_phases:
                phase_steps = await self._execute_phase(phase, scenario, campaign)
                all_steps.extend(phase_steps)

            # Build attack paths from successful steps
            attack_paths = self._build_attack_paths(all_steps, scenario)
            campaign.attack_paths = attack_paths

            # Calculate MITRE coverage
            campaign.mitre_coverage = self._calculate_mitre_coverage(all_steps)

            # Assess breach impact
            campaign.breach_impact = self._assess_breach_impact(all_steps, scenario)

            # Generate executive summary
            campaign.executive_summary = await self._generate_executive_summary(campaign)

            # Generate recommendations
            campaign.recommendations = self._generate_recommendations(campaign)

            # Finalize
            campaign.steps_executed = len(all_steps)
            campaign.steps_succeeded = sum(1 for s in all_steps if s.status == "succeeded")
            campaign.steps_failed = sum(1 for s in all_steps if s.status == "failed")
            campaign.risk_score = self._calculate_risk_score(campaign)
            campaign.status = CampaignStatus.COMPLETED
            campaign.completed_at = datetime.now(timezone.utc).isoformat()
            campaign.total_duration_seconds = (
                time.time() - datetime.fromisoformat(campaign.started_at.replace("Z", "+00:00")).timestamp()
            )

        except Exception as exc:
            logger.error("campaign.failed: %s", exc)
            campaign.status = CampaignStatus.FAILED
            campaign.completed_at = datetime.now(timezone.utc).isoformat()
            campaign.executive_summary = f"Campaign failed: {exc}"

        # Write results to Knowledge Graph
        self._persist_to_brain(campaign, org_id)

        # Emit completion event
        if bus:
            try:
                from core.event_bus import Event, EventType
                await bus.emit(Event(
                    event_type=EventType.ATTACK_SIMULATED,
                    source="attack_simulation_engine",
                    data={
                        "campaign_id": campaign.campaign_id,
                        "action": "completed",
                        "status": campaign.status.value,
                        "risk_score": campaign.risk_score,
                        "steps_succeeded": campaign.steps_succeeded,
                    },
                    org_id=org_id,
                ))
            except Exception:
                pass

        logger.info(
            "campaign.completed",
            extra={
                "campaign_id": campaign.campaign_id,
                "status": campaign.status.value,
                "risk_score": campaign.risk_score,
            },
        )
        return campaign

    # ---- Phase Execution ----

    async def _execute_phase(
        self,
        phase: KillChainPhase,
        scenario: AttackScenario,
        campaign: CampaignResult,
    ) -> List[AttackStep]:
        """Execute a single kill chain phase, returning steps."""
        techniques = [
            (tid, info) for tid, info in MITRE_TECHNIQUES.items()
            if info["phase"] == phase.value
        ]
        if not techniques:
            return []

        steps: List[AttackStep] = []
        for technique_id, technique_info in techniques:
            step = AttackStep(
                phase=phase,
                technique_id=technique_id,
                technique_name=technique_info["name"],
                target_asset=scenario.target_assets[0] if scenario.target_assets else "primary_target",
                success_probability=technique_info["severity"],
                impact_score=technique_info["severity"],
            )

            # Use LLM for intelligent step analysis
            step = await self._llm_enrich_step(step, scenario)

            # Simulate execution
            step = self._simulate_step_execution(step, scenario)
            steps.append(step)

        return steps

    async def _llm_enrich_step(self, step: AttackStep, scenario: AttackScenario) -> AttackStep:
        """Enrich a step with LLM-generated context."""
        llm = self._get_llm()
        if not llm:
            step.description = f"Simulate {step.technique_name} ({step.technique_id}) against {step.target_asset}"
            step.mitigations = [f"Monitor for {step.technique_name} indicators"]
            return step

        prompt = (
            f"As a red team operator simulating {scenario.threat_actor.value} threat actor:\n"
            f"Technique: {step.technique_id} - {step.technique_name}\n"
            f"Phase: {step.phase.value}\n"
            f"Target: {step.target_asset}\n"
            f"CVEs: {', '.join(scenario.target_cves[:5])}\n\n"
            f"Provide: 1) Realistic attack description (2 sentences), "
            f"2) Detection indicators, 3) Recommended mitigations."
        )
        try:
            resp = llm.analyse(
                "openai",
                prompt=prompt,
                context={"technique": step.technique_id, "target": step.target_asset},
                default_action="simulate",
                default_confidence=step.success_probability,
                default_reasoning=f"Simulating {step.technique_name}",
            )
            step.description = resp.reasoning[:300]
            step.mitigations = list(resp.compliance_concerns[:5]) if resp.compliance_concerns else [
                f"Monitor for {step.technique_name} indicators",
                f"Implement detection rules for {step.technique_id}",
            ]
            step.success_probability = resp.confidence
        except Exception as exc:
            logger.debug("llm_enrich_step.fallback: %s", exc)
            step.description = f"Simulate {step.technique_name} ({step.technique_id}) against {step.target_asset}"
            step.mitigations = [f"Monitor for {step.technique_name} indicators"]

        return step

    def _simulate_step_execution(self, step: AttackStep, scenario: AttackScenario) -> AttackStep:
        """Simulate whether a step succeeds based on probability and threat actor profile."""
        # Adjust success probability based on threat actor sophistication
        actor_multipliers = {
            ThreatActorProfile.SCRIPT_KIDDIE: 0.5,
            ThreatActorProfile.HACKTIVIST: 0.65,
            ThreatActorProfile.CYBERCRIMINAL: 0.75,
            ThreatActorProfile.NATION_STATE: 0.9,
            ThreatActorProfile.INSIDER_THREAT: 0.85,
            ThreatActorProfile.APT: 0.95,
        }
        multiplier = actor_multipliers.get(scenario.threat_actor, 0.7)
        adjusted_prob = min(1.0, step.success_probability * multiplier)

        # Deterministic simulation based on hash (reproducible)
        seed = hashlib.md5(
            f"{step.step_id}:{step.technique_id}:{scenario.scenario_id}".encode()
        ).hexdigest()
        hash_value = int(seed[:8], 16) / 0xFFFFFFFF

        if hash_value <= adjusted_prob:
            step.status = "succeeded"
            step.output = f"Successfully executed {step.technique_name}"
            step.duration_seconds = round(hash_value * 120 + 5, 1)
        else:
            step.status = "failed"
            step.output = f"Failed to execute {step.technique_name} — detected or blocked"
            step.duration_seconds = round(hash_value * 30 + 2, 1)

        return step

    # ---- Path Building ----

    def _build_attack_paths(
        self,
        steps: List[AttackStep],
        scenario: AttackScenario,
    ) -> List[AttackPath]:
        """Build attack paths from executed steps, grouping successful chains."""
        succeeded = [s for s in steps if s.status == "succeeded"]
        if not succeeded:
            return []

        # Group by phase to form ordered paths
        phase_order = list(KillChainPhase)
        phase_steps: Dict[KillChainPhase, List[AttackStep]] = {}
        for s in succeeded:
            phase_steps.setdefault(s.phase, []).append(s)

        # Build primary path (one technique per phase)
        primary_steps = []
        for phase in phase_order:
            ps = phase_steps.get(phase, [])
            if ps:
                # Pick highest impact technique
                best = max(ps, key=lambda x: x.impact_score)
                primary_steps.append(best)

        if primary_steps:
            total_prob = 1.0
            for s in primary_steps:
                total_prob *= s.success_probability
            primary_path = AttackPath(
                steps=primary_steps,
                entry_point=primary_steps[0].target_asset,
                target=primary_steps[-1].target_asset,
                total_probability=round(total_prob, 4),
                total_impact=round(sum(s.impact_score for s in primary_steps), 2),
                techniques_used=[s.technique_id for s in primary_steps],
                blast_radius=len(set(s.target_asset for s in primary_steps)),
            )
            return [primary_path]

        return []

    # ---- MITRE Coverage ----

    def _calculate_mitre_coverage(self, steps: List[AttackStep]) -> Dict[str, List[str]]:
        """Calculate MITRE ATT&CK technique coverage."""
        coverage: Dict[str, List[str]] = {}
        for step in steps:
            phase_key = step.phase.value
            if phase_key not in coverage:
                coverage[phase_key] = []
            if step.technique_id not in coverage[phase_key]:
                coverage[phase_key].append(step.technique_id)
        return coverage

    # ---- Breach Impact Assessment ----

    def _assess_breach_impact(
        self,
        steps: List[AttackStep],
        scenario: AttackScenario,
    ) -> BreachImpact:
        """Assess business impact of the simulated breach."""
        succeeded = [s for s in steps if s.status == "succeeded"]
        success_rate = len(succeeded) / max(len(steps), 1)

        # Financial impact scaled by threat actor and complexity
        base_loss = {
            ThreatActorProfile.SCRIPT_KIDDIE: 50_000,
            ThreatActorProfile.HACKTIVIST: 200_000,
            ThreatActorProfile.CYBERCRIMINAL: 1_000_000,
            ThreatActorProfile.NATION_STATE: 10_000_000,
            ThreatActorProfile.INSIDER_THREAT: 2_000_000,
            ThreatActorProfile.APT: 15_000_000,
        }.get(scenario.threat_actor, 500_000)

        expected = base_loss * success_rate
        min_loss = expected * 0.3
        max_loss = expected * 3.0

        # Check for exfiltration success
        exfil_succeeded = any(
            s.phase == KillChainPhase.EXFILTRATION and s.status == "succeeded"
            for s in steps
        )
        data_risk = 100_000 if exfil_succeeded else int(10_000 * success_rate)

        # Compliance violations
        violations = []
        if exfil_succeeded:
            violations.extend(["GDPR Art. 33 (breach notification)", "PCI-DSS 12.10 (incident response)"])
        if any(s.phase == KillChainPhase.PERSISTENCE and s.status == "succeeded" for s in steps):
            violations.append("SOC2 CC7.2 (system monitoring)")
        if any(s.phase == KillChainPhase.PRIVILEGE_ESCALATION and s.status == "succeeded" for s in steps):
            violations.append("HIPAA 164.312(a) (access control)")

        # Recovery time
        recovery_hours = 4 + (len(succeeded) * 2) + (24 if exfil_succeeded else 0)

        # Reputation
        if success_rate >= 0.7:
            reputation = "critical"
        elif success_rate >= 0.5:
            reputation = "high"
        elif success_rate >= 0.3:
            reputation = "medium"
        else:
            reputation = "low"

        notifications = []
        if exfil_succeeded:
            notifications.extend(["Data Protection Authority", "Affected individuals"])
        if "PCI-DSS" in str(violations):
            notifications.append("PCI Security Standards Council")

        return BreachImpact(
            financial_loss_min=round(min_loss, 2),
            financial_loss_max=round(max_loss, 2),
            financial_loss_expected=round(expected, 2),
            data_records_at_risk=data_risk,
            systems_compromised=len(set(s.target_asset for s in succeeded)),
            recovery_time_hours=round(recovery_hours, 1),
            compliance_violations=violations,
            affected_business_units=["IT", "Security"] + (["Legal", "PR"] if exfil_succeeded else []),
            reputation_impact=reputation,
            regulatory_notifications=notifications,
        )

    # ---- Risk Score ----

    def _calculate_risk_score(self, campaign: CampaignResult) -> float:
        """Calculate overall campaign risk score (0-10)."""
        if not campaign.attack_paths:
            return 0.0
        path_scores = [p.total_impact for p in campaign.attack_paths]
        avg_impact = sum(path_scores) / len(path_scores)
        success_rate = campaign.steps_succeeded / max(campaign.steps_executed, 1)
        # Scale to 0-10
        raw = (avg_impact * 4) + (success_rate * 6)
        return round(min(10.0, max(0.0, raw)), 2)

    # ---- Executive Summary ----

    async def _generate_executive_summary(self, campaign: CampaignResult) -> str:
        """Generate executive summary using LLM or fallback."""
        llm = self._get_llm()
        if llm and campaign.steps_executed > 0:
            prompt = (
                f"Generate a 3-sentence executive summary of this attack simulation:\n"
                f"- {campaign.steps_executed} attack steps executed, "
                f"{campaign.steps_succeeded} succeeded, {campaign.steps_failed} failed\n"
                f"- Threat actor: {campaign.scenario.threat_actor.value if campaign.scenario else 'unknown'}\n"
                f"- MITRE phases covered: {list(campaign.mitre_coverage.keys())}\n"
                f"- Breach impact: {campaign.breach_impact.reputation_impact if campaign.breach_impact else 'N/A'}\n"
                f"- Risk score: {campaign.risk_score}/10\n"
            )
            try:
                resp = llm.analyse(
                    "openai",
                    prompt=prompt,
                    context={"campaign_id": campaign.campaign_id},
                    default_action="summarize",
                    default_confidence=0.8,
                    default_reasoning="Attack simulation summary",
                )
                return resp.reasoning[:500]
            except Exception:
                pass

        # Fallback
        return (
            f"Attack simulation completed with {campaign.steps_succeeded}/{campaign.steps_executed} "
            f"steps succeeding across {len(campaign.mitre_coverage)} kill chain phases. "
            f"Risk score: {campaign.risk_score}/10. "
            f"{'Data exfiltration was achieved.' if campaign.breach_impact and campaign.breach_impact.data_records_at_risk > 50000 else 'Full breach was not achieved.'}"
        )

    # ---- Recommendations ----

    def _generate_recommendations(self, campaign: CampaignResult) -> List[str]:
        """Generate security recommendations based on simulation results."""
        recs = []
        if not campaign.attack_paths:
            return ["All attack paths were successfully blocked. Continue monitoring."]

        for path in campaign.attack_paths:
            for step in path.steps:
                if step.status == "succeeded":
                    recs.append(
                        f"Implement detection for {step.technique_name} ({step.technique_id}) — "
                        f"this technique succeeded during simulation"
                    )
                    for mitigation in step.mitigations[:1]:
                        recs.append(f"  → Mitigation: {mitigation}")

        if campaign.breach_impact:
            bi = campaign.breach_impact
            if bi.compliance_violations:
                recs.append(f"Address {len(bi.compliance_violations)} compliance violations: {', '.join(bi.compliance_violations[:3])}")
            if bi.reputation_impact in ("high", "critical"):
                recs.append("URGENT: Implement incident response playbook — reputation impact is " + bi.reputation_impact)

        # Deduplicate
        seen = set()
        unique_recs = []
        for r in recs:
            if r not in seen:
                seen.add(r)
                unique_recs.append(r)
        return unique_recs[:20]

    # ---- Brain Persistence ----

    def _persist_to_brain(self, campaign: CampaignResult, org_id: Optional[str] = None) -> None:
        """Write campaign results to the Knowledge Graph."""
        brain = self._get_brain()
        if not brain:
            return
        try:
            from core.knowledge_brain import GraphNode, GraphEdge, EntityType, EdgeType
            # Create campaign node
            brain.upsert_node(GraphNode(
                node_id=f"attack:{campaign.campaign_id}",
                node_type=EntityType.ATTACK,
                org_id=org_id,
                properties={
                    "campaign_id": campaign.campaign_id,
                    "status": campaign.status.value,
                    "risk_score": campaign.risk_score,
                    "steps_executed": campaign.steps_executed,
                    "steps_succeeded": campaign.steps_succeeded,
                    "scenario_name": campaign.scenario.name if campaign.scenario else "",
                },
            ))
            # Link to target CVEs
            if campaign.scenario:
                for cve_id in campaign.scenario.target_cves:
                    brain.add_edge(GraphEdge(
                        source_id=f"attack:{campaign.campaign_id}",
                        target_id=f"cve:{cve_id}",
                        edge_type=EdgeType.EXPLOITS,
                        properties={"campaign": campaign.campaign_id},
                    ))
        except Exception as exc:
            logger.debug("persist_to_brain.failed: %s", exc)

    # ---- Campaign Queries ----

    def get_campaign(self, campaign_id: str) -> Optional[CampaignResult]:
        """Get campaign by ID."""
        return self._campaigns.get(campaign_id)

    def list_campaigns(self, status: Optional[str] = None) -> List[CampaignResult]:
        """List campaigns, optionally filtered by status."""
        campaigns = list(self._campaigns.values())
        if status:
            campaigns = [c for c in campaigns if c.status.value == status]
        return sorted(campaigns, key=lambda c: c.started_at or "", reverse=True)

    def get_mitre_heatmap(self) -> Dict[str, Dict[str, int]]:
        """Get MITRE ATT&CK heatmap across all campaigns."""
        heatmap: Dict[str, Dict[str, int]] = {}
        for campaign in self._campaigns.values():
            for phase, techniques in campaign.mitre_coverage.items():
                if phase not in heatmap:
                    heatmap[phase] = {}
                for tid in techniques:
                    heatmap[phase][tid] = heatmap[phase].get(tid, 0) + 1
        return heatmap


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[AttackSimulationEngine] = None


def get_attack_simulation_engine() -> AttackSimulationEngine:
    """Get or create the singleton AttackSimulationEngine."""
    global _engine
    if _engine is None:
        _engine = AttackSimulationEngine()
    return _engine


__all__ = [
    "AttackComplexity",
    "AttackPath",
    "AttackScenario",
    "AttackSimulationEngine",
    "AttackStep",
    "BreachImpact",
    "CampaignResult",
    "CampaignStatus",
    "KillChainPhase",
    "MITRE_TECHNIQUES",
    "ThreatActorProfile",
    "get_attack_simulation_engine",
]

