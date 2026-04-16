"""
FixOps Breach Simulation Engine.

Simulates attack scenarios against current defenses to identify gaps,
validate detection capabilities, and track posture improvement over time.

Scenarios: RANSOMWARE, DATA_EXFILTRATION, CREDENTIAL_THEFT, LATERAL_MOVEMENT,
           PRIVILEGE_ESCALATION, SUPPLY_CHAIN, INSIDER_THREAT, APT_CAMPAIGN

Each scenario has 5-10 attack steps. The simulator evaluates defenses for each
step, computes detection/containment timing, and produces a scored gap analysis.
"""

from __future__ import annotations

import json
import random
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

_logger = structlog.get_logger(__name__)

_DEFAULT_DB_PATH = "data/breach_simulation.db"

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AttackScenario(str, Enum):
    """Supported breach simulation scenarios."""

    RANSOMWARE = "ransomware"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"
    INSIDER_THREAT = "insider_threat"
    APT_CAMPAIGN = "apt_campaign"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SimulationResult(BaseModel):
    """Result of a single breach simulation run."""

    id: str = Field(default_factory=lambda: f"sim-{uuid.uuid4().hex[:12]}")
    scenario: AttackScenario
    steps_executed: int = Field(..., ge=0)
    steps_blocked: int = Field(..., ge=0)
    detection_time_seconds: float = Field(..., ge=0.0)
    containment_time_seconds: float = Field(..., ge=0.0)
    data_at_risk: str = Field(..., description="Description of data exposed if breach succeeded")
    defenses_tested: List[str] = Field(default_factory=list)
    gaps_found: List[str] = Field(default_factory=list)
    score: float = Field(..., ge=0.0, le=100.0, description="Defense effectiveness 0-100")
    org_id: str = Field(..., description="Organisation identifier")
    simulated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class AttackStep(BaseModel):
    """A single step in an attack scenario."""

    step_id: str
    name: str
    technique: str  # MITRE technique ID or description
    phase: str
    severity: str  # low / medium / high / critical
    defense_control: str  # control that should block this
    blocked: bool = False
    detection_triggered: bool = False


class DefenseCoverage(BaseModel):
    """Defense coverage summary for an org."""

    org_id: str
    total_simulations: int
    scenarios_tested: List[str]
    scenarios_not_tested: List[str]
    average_score: float
    weakest_scenario: Optional[str]
    strongest_scenario: Optional[str]
    coverage_percent: float


class GapAnalysis(BaseModel):
    """Gap analysis across all simulations for an org."""

    org_id: str
    total_simulations: int
    recurring_gaps: List[str]
    gap_frequency: Dict[str, int]
    critical_gaps: List[str]
    recommended_priorities: List[str]


# ---------------------------------------------------------------------------
# Scenario definitions — 8 scenarios with 5-10 steps each
# ---------------------------------------------------------------------------

_SCENARIO_STEPS: Dict[str, List[Dict[str, Any]]] = {
    AttackScenario.RANSOMWARE: [
        {"step_id": "rw-1", "name": "Phishing email delivery", "technique": "T1566.001", "phase": "initial_access", "severity": "high", "defense_control": "Email filtering / anti-phishing"},
        {"step_id": "rw-2", "name": "Malicious macro execution", "technique": "T1204.002", "phase": "execution", "severity": "high", "defense_control": "Macro policy / application whitelisting"},
        {"step_id": "rw-3", "name": "Disable antivirus via registry", "technique": "T1562.001", "phase": "defense_evasion", "severity": "critical", "defense_control": "Tamper protection / EDR"},
        {"step_id": "rw-4", "name": "Credential harvesting from LSASS", "technique": "T1003.001", "phase": "credential_access", "severity": "critical", "defense_control": "Credential Guard / EDR memory protection"},
        {"step_id": "rw-5", "name": "SMB lateral spread to file servers", "technique": "T1021.002", "phase": "lateral_movement", "severity": "high", "defense_control": "Network segmentation / SMB signing"},
        {"step_id": "rw-6", "name": "Shadow copy deletion", "technique": "T1490", "phase": "impact", "severity": "critical", "defense_control": "VSS protection / backup monitoring"},
        {"step_id": "rw-7", "name": "Encrypt files with AES-256", "technique": "T1486", "phase": "impact", "severity": "critical", "defense_control": "File integrity monitoring / honeypots"},
        {"step_id": "rw-8", "name": "Ransom note deployment", "technique": "T1491", "phase": "impact", "severity": "high", "defense_control": "Process monitoring / anomaly detection"},
    ],
    AttackScenario.DATA_EXFILTRATION: [
        {"step_id": "de-1", "name": "Spear-phishing for VPN credentials", "technique": "T1566.002", "phase": "initial_access", "severity": "high", "defense_control": "MFA / phishing-resistant auth"},
        {"step_id": "de-2", "name": "VPN login with stolen credentials", "technique": "T1078", "phase": "initial_access", "severity": "high", "defense_control": "Conditional access / anomalous login detection"},
        {"step_id": "de-3", "name": "Internal network reconnaissance", "technique": "T1046", "phase": "discovery", "severity": "medium", "defense_control": "NDR / internal scan detection"},
        {"step_id": "de-4", "name": "Database enumeration", "technique": "T1213", "phase": "collection", "severity": "high", "defense_control": "Database activity monitoring / UEBA"},
        {"step_id": "de-5", "name": "Bulk data staging to temp directory", "technique": "T1074.001", "phase": "collection", "severity": "high", "defense_control": "DLP / file access monitoring"},
        {"step_id": "de-6", "name": "Data compression and encryption", "technique": "T1560.001", "phase": "collection", "severity": "medium", "defense_control": "Process behavior monitoring"},
        {"step_id": "de-7", "name": "Exfiltration over HTTPS to cloud storage", "technique": "T1567.002", "phase": "exfiltration", "severity": "critical", "defense_control": "CASB / egress filtering / DLP"},
        {"step_id": "de-8", "name": "Cover tracks — log deletion", "technique": "T1070.001", "phase": "defense_evasion", "severity": "high", "defense_control": "Immutable logging / SIEM alerting"},
    ],
    AttackScenario.CREDENTIAL_THEFT: [
        {"step_id": "ct-1", "name": "Password spray against Entra ID", "technique": "T1110.003", "phase": "credential_access", "severity": "high", "defense_control": "Account lockout / Smart Lockout / MFA"},
        {"step_id": "ct-2", "name": "Kerberoasting service accounts", "technique": "T1558.003", "phase": "credential_access", "severity": "high", "defense_control": "Service account password policy / ATA"},
        {"step_id": "ct-3", "name": "NTLM relay attack", "technique": "T1557.001", "phase": "credential_access", "severity": "critical", "defense_control": "SMB signing / LDAP signing / EPA"},
        {"step_id": "ct-4", "name": "Pass-the-Hash to admin share", "technique": "T1550.002", "phase": "lateral_movement", "severity": "critical", "defense_control": "Credential Guard / restricted admin mode"},
        {"step_id": "ct-5", "name": "DCSync to dump domain credentials", "technique": "T1003.006", "phase": "credential_access", "severity": "critical", "defense_control": "Privileged access workstations / tier model"},
        {"step_id": "ct-6", "name": "Golden ticket creation", "technique": "T1558.001", "phase": "privilege_escalation", "severity": "critical", "defense_control": "krbtgt rotation / PAM"},
    ],
    AttackScenario.LATERAL_MOVEMENT: [
        {"step_id": "lm-1", "name": "Initial foothold via RCE vulnerability", "technique": "T1190", "phase": "initial_access", "severity": "critical", "defense_control": "Patch management / WAF"},
        {"step_id": "lm-2", "name": "Local privilege escalation", "technique": "T1068", "phase": "privilege_escalation", "severity": "high", "defense_control": "Endpoint patching / hardening"},
        {"step_id": "lm-3", "name": "Internal network scan (nmap)", "technique": "T1046", "phase": "discovery", "severity": "medium", "defense_control": "NDR / IDS scan signatures"},
        {"step_id": "lm-4", "name": "WMI remote execution", "technique": "T1047", "phase": "lateral_movement", "severity": "high", "defense_control": "WMI monitoring / network segmentation"},
        {"step_id": "lm-5", "name": "RDP pivot to jump host", "technique": "T1021.001", "phase": "lateral_movement", "severity": "high", "defense_control": "Network access control / MFA for RDP"},
        {"step_id": "lm-6", "name": "SSH key theft and reuse", "technique": "T1552.004", "phase": "lateral_movement", "severity": "high", "defense_control": "SSH key management / PAM"},
        {"step_id": "lm-7", "name": "Reach domain controller", "technique": "T1018", "phase": "lateral_movement", "severity": "critical", "defense_control": "Micro-segmentation / DC firewall rules"},
    ],
    AttackScenario.PRIVILEGE_ESCALATION: [
        {"step_id": "pe-1", "name": "Weak service permissions abuse", "technique": "T1574.010", "phase": "privilege_escalation", "severity": "high", "defense_control": "Service ACL auditing / least privilege"},
        {"step_id": "pe-2", "name": "Scheduled task hijacking", "technique": "T1053.005", "phase": "privilege_escalation", "severity": "high", "defense_control": "Scheduled task auditing / AppLocker"},
        {"step_id": "pe-3", "name": "UAC bypass via fodhelper", "technique": "T1548.002", "phase": "privilege_escalation", "severity": "high", "defense_control": "UAC always-on-secure-desktop / EDR"},
        {"step_id": "pe-4", "name": "Token impersonation", "technique": "T1134.001", "phase": "privilege_escalation", "severity": "critical", "defense_control": "Privileged access management"},
        {"step_id": "pe-5", "name": "Sudo misconfiguration abuse", "technique": "T1548.003", "phase": "privilege_escalation", "severity": "high", "defense_control": "Sudo policy review / CIS benchmarks"},
        {"step_id": "pe-6", "name": "SUID binary exploitation", "technique": "T1548.001", "phase": "privilege_escalation", "severity": "high", "defense_control": "SUID auditing / integrity monitoring"},
        {"step_id": "pe-7", "name": "Domain admin group membership abuse", "technique": "T1098", "phase": "privilege_escalation", "severity": "critical", "defense_control": "AD group change monitoring / PASM"},
    ],
    AttackScenario.SUPPLY_CHAIN: [
        {"step_id": "sc-1", "name": "Compromise upstream dependency", "technique": "T1195.001", "phase": "initial_access", "severity": "critical", "defense_control": "SCA / dependency pinning / SBOM"},
        {"step_id": "sc-2", "name": "Malicious package in build pipeline", "technique": "T1195.002", "phase": "initial_access", "severity": "critical", "defense_control": "Build integrity / artifact signing"},
        {"step_id": "sc-3", "name": "Backdoor injected into released artifact", "technique": "T1554", "phase": "persistence", "severity": "critical", "defense_control": "Binary signing / provenance verification"},
        {"step_id": "sc-4", "name": "CI/CD secret exfiltration", "technique": "T1552.001", "phase": "credential_access", "severity": "high", "defense_control": "Secret scanning / CI/CD secrets management"},
        {"step_id": "sc-5", "name": "Lateral move via deployment pipeline", "technique": "T1072", "phase": "lateral_movement", "severity": "high", "defense_control": "Pipeline RBAC / network isolation"},
        {"step_id": "sc-6", "name": "Production data access via compromised deploy", "technique": "T1213", "phase": "collection", "severity": "critical", "defense_control": "Prod access controls / least-privilege deploy"},
        {"step_id": "sc-7", "name": "Persistent backdoor in production", "technique": "T1546", "phase": "persistence", "severity": "critical", "defense_control": "Runtime security / file integrity monitoring"},
        {"step_id": "sc-8", "name": "Exfiltration via outbound container", "technique": "T1567", "phase": "exfiltration", "severity": "high", "defense_control": "Container network policy / egress controls"},
        {"step_id": "sc-9", "name": "Cover tracks in build logs", "technique": "T1070", "phase": "defense_evasion", "severity": "medium", "defense_control": "Immutable audit logs / log integrity"},
    ],
    AttackScenario.INSIDER_THREAT: [
        {"step_id": "it-1", "name": "Abuse privileged access to bulk download", "technique": "T1530", "phase": "collection", "severity": "high", "defense_control": "UEBA / abnormal access detection"},
        {"step_id": "it-2", "name": "Data staging on personal cloud drive", "technique": "T1074.002", "phase": "collection", "severity": "high", "defense_control": "CASB / DLP / shadow IT detection"},
        {"step_id": "it-3", "name": "USB exfiltration of sensitive files", "technique": "T1052.001", "phase": "exfiltration", "severity": "critical", "defense_control": "USB policy / endpoint DLP"},
        {"step_id": "it-4", "name": "Email sensitive data externally", "technique": "T1048.003", "phase": "exfiltration", "severity": "high", "defense_control": "Email DLP / attachment scanning"},
        {"step_id": "it-5", "name": "Disable user monitoring agents", "technique": "T1562", "phase": "defense_evasion", "severity": "high", "defense_control": "Tamper protection / admin alerting"},
        {"step_id": "it-6", "name": "Access after notice period began", "technique": "T1078.002", "phase": "initial_access", "severity": "high", "defense_control": "Offboarding process / access revocation SLA"},
        {"step_id": "it-7", "name": "Intellectual property theft", "technique": "T1213.003", "phase": "collection", "severity": "critical", "defense_control": "Data classification / rights management"},
    ],
    AttackScenario.APT_CAMPAIGN: [
        {"step_id": "apt-1", "name": "Watering hole attack on industry site", "technique": "T1189", "phase": "initial_access", "severity": "high", "defense_control": "Web filtering / browser isolation"},
        {"step_id": "apt-2", "name": "Zero-day browser exploit delivery", "technique": "T1203", "phase": "execution", "severity": "critical", "defense_control": "Patch management / sandboxing"},
        {"step_id": "apt-3", "name": "Custom implant installation", "technique": "T1027", "phase": "defense_evasion", "severity": "critical", "defense_control": "EDR / memory scanning"},
        {"step_id": "apt-4", "name": "Encrypted C2 over DNS", "technique": "T1071.004", "phase": "command_and_control", "severity": "high", "defense_control": "DNS monitoring / RPZ / NDR"},
        {"step_id": "apt-5", "name": "Living-off-the-land with LOLBins", "technique": "T1218", "phase": "execution", "severity": "high", "defense_control": "Application control / LOLBIN detection"},
        {"step_id": "apt-6", "name": "AD reconnaissance (BloodHound)", "technique": "T1482", "phase": "discovery", "severity": "high", "defense_control": "Defender for Identity / LDAP monitoring"},
        {"step_id": "apt-7", "name": "Kerberos delegation abuse", "technique": "T1558.004", "phase": "lateral_movement", "severity": "critical", "defense_control": "Constrained delegation enforcement"},
        {"step_id": "apt-8", "name": "Long-term persistence via UEFI implant", "technique": "T1542.001", "phase": "persistence", "severity": "critical", "defense_control": "Secure Boot / UEFI integrity"},
        {"step_id": "apt-9", "name": "Selective targeted exfiltration", "technique": "T1029", "phase": "exfiltration", "severity": "high", "defense_control": "Scheduled transfer detection / DLP"},
        {"step_id": "apt-10", "name": "Multi-year dwell time with minimal noise", "technique": "T1083", "phase": "discovery", "severity": "high", "defense_control": "UEBA / threat hunting program"},
    ],
}

_DATA_AT_RISK: Dict[str, str] = {
    AttackScenario.RANSOMWARE: "All on-premises file shares, databases, and backup media within blast radius",
    AttackScenario.DATA_EXFILTRATION: "Customer PII, financial records, IP in accessible databases and file stores",
    AttackScenario.CREDENTIAL_THEFT: "Domain credentials, service account secrets, privileged session tokens",
    AttackScenario.LATERAL_MOVEMENT: "All assets reachable from initial foothold via network pivot",
    AttackScenario.PRIVILEGE_ESCALATION: "Full domain — all resources accessible to SYSTEM/root/Domain Admin",
    AttackScenario.SUPPLY_CHAIN: "Production environment, all customer data, downstream software consumers",
    AttackScenario.INSIDER_THREAT: "Intellectual property, customer PII, confidential business data in scope of role",
    AttackScenario.APT_CAMPAIGN: "Strategic assets, long-term IP, nation-state-grade data exposure across entire estate",
}


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------


class _SimulationDB:
    """Thin SQLite wrapper for simulation history."""

    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS simulations (
                        id                       TEXT PRIMARY KEY,
                        org_id                   TEXT NOT NULL,
                        scenario                 TEXT NOT NULL,
                        steps_executed           INTEGER NOT NULL,
                        steps_blocked            INTEGER NOT NULL,
                        detection_time_seconds   REAL NOT NULL,
                        containment_time_seconds REAL NOT NULL,
                        data_at_risk             TEXT NOT NULL,
                        defenses_tested          TEXT NOT NULL DEFAULT '[]',
                        gaps_found               TEXT NOT NULL DEFAULT '[]',
                        score                    REAL NOT NULL,
                        simulated_at             TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_sim_org_ts
                        ON simulations (org_id, simulated_at);

                    CREATE INDEX IF NOT EXISTS idx_sim_scenario
                        ON simulations (scenario);
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def save(self, result: SimulationResult) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO simulations
                        (id, org_id, scenario, steps_executed, steps_blocked,
                         detection_time_seconds, containment_time_seconds,
                         data_at_risk, defenses_tested, gaps_found, score, simulated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.id,
                        result.org_id,
                        result.scenario.value,
                        result.steps_executed,
                        result.steps_blocked,
                        result.detection_time_seconds,
                        result.containment_time_seconds,
                        result.data_at_risk,
                        json.dumps(result.defenses_tested),
                        json.dumps(result.gaps_found),
                        result.score,
                        result.simulated_at,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def get_by_id(self, sim_id: str) -> Optional[SimulationResult]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM simulations WHERE id = ?", (sim_id,)
                ).fetchone()
            finally:
                conn.close()
        return self._row_to_result(row) if row else None

    def get_history(self, org_id: str, limit: int = 100) -> List[SimulationResult]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM simulations
                    WHERE org_id = ?
                    ORDER BY simulated_at DESC
                    LIMIT ?
                    """,
                    (org_id, limit),
                ).fetchall()
            finally:
                conn.close()
        return [self._row_to_result(r) for r in rows]

    def get_by_scenario(
        self, org_id: str, scenario: str
    ) -> List[SimulationResult]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM simulations
                    WHERE org_id = ? AND scenario = ?
                    ORDER BY simulated_at DESC
                    """,
                    (org_id, scenario),
                ).fetchall()
            finally:
                conn.close()
        return [self._row_to_result(r) for r in rows]

    def get_by_ids(self, sim_ids: List[str]) -> List[SimulationResult]:
        if not sim_ids:
            return []
        placeholders = ",".join("?" * len(sim_ids))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    f"SELECT * FROM simulations WHERE id IN ({placeholders})",  # nosec B608
                    sim_ids,
                ).fetchall()
            finally:
                conn.close()
        return [self._row_to_result(r) for r in rows]

    @staticmethod
    def _row_to_result(row: sqlite3.Row) -> SimulationResult:
        return SimulationResult(
            id=row["id"],
            org_id=row["org_id"],
            scenario=AttackScenario(row["scenario"]),
            steps_executed=row["steps_executed"],
            steps_blocked=row["steps_blocked"],
            detection_time_seconds=row["detection_time_seconds"],
            containment_time_seconds=row["containment_time_seconds"],
            data_at_risk=row["data_at_risk"],
            defenses_tested=json.loads(row["defenses_tested"]),
            gaps_found=json.loads(row["gaps_found"]),
            score=row["score"],
            simulated_at=row["simulated_at"],
        )


# ---------------------------------------------------------------------------
# Core simulator
# ---------------------------------------------------------------------------

# Severity weights used in scoring
_SEVERITY_WEIGHT: Dict[str, float] = {
    "low": 1.0,
    "medium": 2.0,
    "high": 3.0,
    "critical": 5.0,
}


class BreachSimulator:
    """
    Simulates attack scenarios against configured defenses.

    Each scenario has a fixed set of attack steps. The simulator
    deterministically (but with slight jitter) evaluates each step
    against a defense control and computes detection/containment times,
    gaps, and a 0-100 defense effectiveness score.

    Args:
        db_path: Path to the SQLite database file.
        defense_effectiveness: 0.0-1.0 base probability that a defense
            blocks a given step. Used when no org-specific overrides exist.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB_PATH,
        defense_effectiveness: float = 0.65,
    ) -> None:
        self._db = _SimulationDB(db_path)
        self._base_effectiveness = max(0.0, min(1.0, defense_effectiveness))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_scenario_steps(self, scenario: AttackScenario) -> List[AttackStep]:
        """Return the attack steps defined for a scenario."""
        raw = _SCENARIO_STEPS.get(scenario.value, [])
        return [AttackStep(**s) for s in raw]

    def evaluate_defenses(
        self, scenario: AttackScenario, org_id: str
    ) -> List[AttackStep]:
        """
        Evaluate which defenses would trigger for each step.

        Returns the list of steps with `blocked` and `detection_triggered`
        fields populated. This is a deterministic evaluation — the same
        scenario/org_id combination always produces the same result within
        a session (seeded from org_id hash).
        """
        steps = self.get_scenario_steps(scenario)
        rng = random.Random(hash(f"{org_id}:{scenario.value}"))
        evaluated: List[AttackStep] = []
        for step in steps:
            p_block = self._base_effectiveness
            # Critical steps are harder to block
            if step.severity == "critical":
                p_block *= 0.8
            blocked = rng.random() < p_block
            # Detection can happen even if not fully blocked
            detected = blocked or rng.random() < (p_block * 0.6)
            evaluated.append(
                step.model_copy(update={"blocked": blocked, "detection_triggered": detected})
            )
        return evaluated

    def run_simulation(
        self, scenario: AttackScenario, org_id: str
    ) -> SimulationResult:
        """
        Execute a breach simulation and persist the result.

        Evaluates all scenario steps against defenses, computes timing
        and gaps, scores the defense posture, and stores to SQLite.
        """
        evaluated = self.evaluate_defenses(scenario, org_id)

        steps_executed = len(evaluated)
        steps_blocked = sum(1 for s in evaluated if s.blocked)

        # Detection time: time until first detection trigger
        detection_time = self._compute_detection_time(evaluated)
        containment_time = self._compute_containment_time(evaluated, detection_time)

        defenses_tested = [s.defense_control for s in evaluated]
        gaps_found = [
            f"{s.name} — missing: {s.defense_control}"
            for s in evaluated
            if not s.blocked
        ]

        score = self._compute_score(evaluated)

        result = SimulationResult(
            scenario=scenario,
            steps_executed=steps_executed,
            steps_blocked=steps_blocked,
            detection_time_seconds=detection_time,
            containment_time_seconds=containment_time,
            data_at_risk=_DATA_AT_RISK.get(scenario.value, "Unknown data exposure"),
            defenses_tested=defenses_tested,
            gaps_found=gaps_found,
            score=score,
            org_id=org_id,
        )
        self._db.save(result)
        _logger.info(
            "breach_simulation.completed",
            sim_id=result.id,
            org_id=org_id,
            scenario=scenario.value,
            score=score,
            gaps=len(gaps_found),
        )
        return result

    def get_simulation_history(
        self, org_id: str, limit: int = 100
    ) -> List[SimulationResult]:
        """Return past simulations for an org, newest first."""
        return self._db.get_history(org_id, limit=limit)

    def get_defense_coverage(self, org_id: str) -> DefenseCoverage:
        """Summarise which attack types have been tested for an org."""
        history = self._db.get_history(org_id, limit=500)
        tested = list({r.scenario.value for r in history})
        all_scenarios = [s.value for s in AttackScenario]
        not_tested = [s for s in all_scenarios if s not in tested]

        scores_by_scenario: Dict[str, List[float]] = {}
        for r in history:
            scores_by_scenario.setdefault(r.scenario.value, []).append(r.score)

        avg_score = (
            sum(r.score for r in history) / len(history) if history else 0.0
        )

        weakest: Optional[str] = None
        strongest: Optional[str] = None
        if scores_by_scenario:
            avgs = {k: sum(v) / len(v) for k, v in scores_by_scenario.items()}
            weakest = min(avgs, key=lambda k: avgs[k])
            strongest = max(avgs, key=lambda k: avgs[k])

        return DefenseCoverage(
            org_id=org_id,
            total_simulations=len(history),
            scenarios_tested=tested,
            scenarios_not_tested=not_tested,
            average_score=round(avg_score, 2),
            weakest_scenario=weakest,
            strongest_scenario=strongest,
            coverage_percent=round(100.0 * len(tested) / max(len(all_scenarios), 1), 2),
        )

    def get_gap_analysis(self, org_id: str) -> GapAnalysis:
        """Identify the most frequent and critical defense gaps across simulations."""
        history = self._db.get_history(org_id, limit=500)

        gap_freq: Dict[str, int] = {}
        for result in history:
            for gap in result.gaps_found:
                gap_freq[gap] = gap_freq.get(gap, 0) + 1

        # Sort by frequency
        sorted_gaps = sorted(gap_freq.items(), key=lambda x: x[1], reverse=True)
        recurring_gaps = [g for g, _ in sorted_gaps[:10]]

        # Critical gaps: those with "critical" severity in scenario steps
        critical_controls: set[str] = set()
        for scenario in AttackScenario:
            for step_data in _SCENARIO_STEPS.get(scenario.value, []):
                if step_data["severity"] == "critical":
                    critical_controls.add(step_data["defense_control"])

        critical_gaps = [
            g for g in recurring_gaps
            if any(ctrl in g for ctrl in critical_controls)
        ]

        # Recommended priorities: top recurring gaps not yet critical
        priorities = [
            f"Remediate: {g.split(' — missing: ')[-1]}"
            for g in recurring_gaps[:5]
            if g
        ]

        return GapAnalysis(
            org_id=org_id,
            total_simulations=len(history),
            recurring_gaps=recurring_gaps,
            gap_frequency=gap_freq,
            critical_gaps=critical_gaps,
            recommended_priorities=priorities,
        )

    def compare_simulations(self, sim_ids: List[str]) -> Dict[str, Any]:
        """
        Compare multiple simulations to track improvement over time.

        Returns a dict with each simulation's key metrics and a delta
        analysis showing score change and gap reduction.
        """
        results = self._db.get_by_ids(sim_ids)
        if not results:
            return {"simulations": [], "comparison": {}}

        # Sort by simulated_at chronologically
        results.sort(key=lambda r: r.simulated_at)

        summaries = [
            {
                "id": r.id,
                "scenario": r.scenario.value,
                "score": r.score,
                "steps_blocked": r.steps_blocked,
                "steps_executed": r.steps_executed,
                "gaps_found": len(r.gaps_found),
                "detection_time_seconds": r.detection_time_seconds,
                "simulated_at": r.simulated_at,
            }
            for r in results
        ]

        comparison: Dict[str, Any] = {}
        if len(results) >= 2:
            first = results[0]
            last = results[-1]
            comparison = {
                "score_delta": round(last.score - first.score, 2),
                "gaps_delta": len(last.gaps_found) - len(first.gaps_found),
                "detection_time_delta_seconds": round(
                    last.detection_time_seconds - first.detection_time_seconds, 2
                ),
                "trend": "improving" if last.score > first.score else (
                    "stable" if last.score == first.score else "declining"
                ),
                "earliest": first.simulated_at,
                "latest": last.simulated_at,
            }

        return {"simulations": summaries, "comparison": comparison}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_detection_time(steps: List[AttackStep]) -> float:
        """
        Compute time-to-detect in seconds.

        Steps that triggered detection reduce the detection window.
        If nothing was detected, return a large dwell time.
        """
        detected_indices = [i for i, s in enumerate(steps) if s.detection_triggered]
        if not detected_indices:
            return 86400.0  # 24 hours — not detected
        # Detection happens at the first triggered step; earlier detection = fewer steps
        first_detected = detected_indices[0]
        # Base: 5 min per step before first detection trigger
        base = first_detected * 300.0
        return max(60.0, base)

    @staticmethod
    def _compute_containment_time(
        steps: List[AttackStep], detection_time: float
    ) -> float:
        """
        Compute time-to-contain in seconds.

        Containment follows detection. Fewer unblocked steps = faster containment.
        """
        unblocked = sum(1 for s in steps if not s.blocked)
        # Each unblocked step adds 10 minutes to containment
        additional = unblocked * 600.0
        return detection_time + additional

    def _compute_score(self, steps: List[AttackStep]) -> float:
        """
        Compute 0-100 defense effectiveness score.

        Weighted by severity — blocking critical steps earns more points.
        """
        if not steps:
            return 0.0
        total_weight = sum(_SEVERITY_WEIGHT.get(s.severity, 1.0) for s in steps)
        blocked_weight = sum(
            _SEVERITY_WEIGHT.get(s.severity, 1.0) for s in steps if s.blocked
        )
        if total_weight == 0.0:
            return 0.0
        raw = (blocked_weight / total_weight) * 100.0
        return round(min(100.0, max(0.0, raw)), 2)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_simulator_instance: Optional[BreachSimulator] = None
_simulator_lock = threading.Lock()


def get_breach_simulator(db_path: str = _DEFAULT_DB_PATH) -> BreachSimulator:
    """Return the module-level singleton BreachSimulator."""
    global _simulator_instance
    if _simulator_instance is None:
        with _simulator_lock:
            if _simulator_instance is None:
                _simulator_instance = BreachSimulator(db_path=db_path)
    return _simulator_instance
