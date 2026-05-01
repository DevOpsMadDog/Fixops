"""
IR Playbook Engine — Incident Response for ALDECI.

Structured incident response following NIST 800-61r2:
  Preparation → Detection & Analysis → Containment → Eradication → Recovery → Lessons Learned

Features:
- 15 built-in playbooks: malware, ransomware, data breach, credential compromise,
  insider threat, DDoS, supply chain attack, API abuse, cloud misconfiguration,
  phishing, unauthorized access, data exfiltration, website defacement,
  zero-day exploit, compliance violation
- Automated actions: block IP, disable user, isolate host, revoke tokens, snapshot disk
- Manual actions: call legal, notify customers, file with regulators
- Evidence chain with SHA-256 hashing (FIPS-compliant)
- Timeline reconstruction from events, logs, alerts, and containment actions
- IR metrics: MTTD, MTTC, MTTR, incidents by type/severity
- Regulatory notification tracker: GDPR (72h), HIPAA (60d), PCI-DSS (immediate),
  state breach laws
- Multi-tenant (per org_id), SQLite-backed, thread-safe

Compliance: NIST 800-61r2, GDPR Art.33, HIPAA §164.412, PCI-DSS 12.10
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field, field_validator

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


def _emit_event(event_type: str, payload) -> None:  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

_logger = structlog.get_logger(__name__)

# Default DB path alongside running process
_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "ir_playbook.db")


# ============================================================================
# ENUMS
# ============================================================================


class IRPhase(str, Enum):
    """NIST 800-61r2 incident response phases (ordered)."""

    PREPARATION = "preparation"
    DETECTION_ANALYSIS = "detection_analysis"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"
    CLOSED = "closed"


# Ordered phase sequence for advancement logic
_PHASE_ORDER: List[IRPhase] = [
    IRPhase.PREPARATION,
    IRPhase.DETECTION_ANALYSIS,
    IRPhase.CONTAINMENT,
    IRPhase.ERADICATION,
    IRPhase.RECOVERY,
    IRPhase.LESSONS_LEARNED,
    IRPhase.CLOSED,
]


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IncidentType(str, Enum):
    MALWARE_INFECTION = "malware_infection"
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    INSIDER_THREAT = "insider_threat"
    DDOS = "ddos"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    API_ABUSE = "api_abuse"
    CLOUD_MISCONFIGURATION = "cloud_misconfiguration"
    PHISHING_CAMPAIGN = "phishing_campaign"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    WEBSITE_DEFACEMENT = "website_defacement"
    ZERO_DAY_EXPLOIT = "zero_day_exploit"
    COMPLIANCE_VIOLATION = "compliance_violation"


class ActionType(str, Enum):
    # Automated
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    ISOLATE_HOST = "isolate_host"
    REVOKE_TOKENS = "revoke_tokens"
    SNAPSHOT_DISK = "snapshot_disk"
    RESET_PASSWORD = "reset_password"
    QUARANTINE_EMAIL = "quarantine_email"
    ENABLE_MFA = "enable_mfa"
    UPDATE_FIREWALL = "update_firewall"
    KILL_SESSION = "kill_session"
    # Manual
    CALL_LEGAL = "call_legal"
    NOTIFY_CUSTOMERS = "notify_customers"
    FILE_REGULATORY = "file_regulatory"
    NOTIFY_MANAGEMENT = "notify_management"
    ENGAGE_IR_RETAINER = "engage_ir_retainer"
    NOTIFY_LAW_ENFORCEMENT = "notify_law_enforcement"
    # Decision points
    ESCALATE = "escalate"
    CONTAIN_ONLY = "contain_only"
    APPROVE_RECOVERY = "approve_recovery"


class ActionMode(str, Enum):
    AUTOMATED = "automated"
    MANUAL = "manual"
    DECISION = "decision"


class IncidentStatus(str, Enum):
    ACTIVE = "active"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERING = "recovering"
    CLOSED = "closed"


class RegulationFramework(str, Enum):
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    CCPA = "ccpa"
    SOC2 = "soc2"
    NIST = "nist"


# Regulatory notification deadlines (hours from incident detection)
_NOTIFICATION_DEADLINES: Dict[RegulationFramework, Optional[int]] = {
    RegulationFramework.GDPR: 72,        # 72 hours — GDPR Art. 33
    RegulationFramework.HIPAA: 1440,     # 60 days = 1440 hours — HIPAA §164.412
    RegulationFramework.PCI_DSS: 1,      # Immediate (1 hour) — PCI-DSS 12.10
    RegulationFramework.CCPA: 720,       # 30 days — California Civil Code §1798.82
    RegulationFramework.SOC2: None,      # No prescribed deadline (contract-dependent)
    RegulationFramework.NIST: None,      # Guidance, not mandate
}

_NOTIFICATION_TEMPLATES: Dict[RegulationFramework, str] = {
    RegulationFramework.GDPR: (
        "GDPR Data Breach Notification\n"
        "To: [Supervisory Authority]\n"
        "Re: Personal Data Breach — Article 33 Notification\n\n"
        "Nature of the breach: {incident_type}\n"
        "Categories of data: {data_categories}\n"
        "Approximate number of individuals: {affected_count}\n"
        "Likely consequences: {consequences}\n"
        "Measures taken: {measures}\n"
        "DPO Contact: {dpo_contact}\n"
    ),
    RegulationFramework.HIPAA: (
        "HIPAA Breach Notification — HHS Office for Civil Rights\n"
        "Covered Entity: {org_name}\n"
        "Nature of Breach: {incident_type}\n"
        "PHI Elements Involved: {phi_elements}\n"
        "Affected Individuals: {affected_count}\n"
        "Discovery Date: {detection_date}\n"
        "Safeguards in Place: {safeguards}\n"
    ),
    RegulationFramework.PCI_DSS: (
        "PCI-DSS Breach Notification — Card Brand and Acquirer\n"
        "Merchant/Service Provider: {org_name}\n"
        "Incident Type: {incident_type}\n"
        "Cardholder Data Compromised: {chd_scope}\n"
        "Date Discovered: {detection_date}\n"
        "Immediate Containment Actions: {measures}\n"
        "Forensic Investigator Engaged: {forensic_firm}\n"
    ),
    RegulationFramework.CCPA: (
        "CCPA Data Breach Notification\n"
        "Business: {org_name}\n"
        "Breach Date: {detection_date}\n"
        "Personal Information Affected: {data_categories}\n"
        "Affected California Residents: {affected_count}\n"
        "Actions Taken: {measures}\n"
    ),
    RegulationFramework.SOC2: (
        "SOC2 Security Incident Notification\n"
        "Customer: [Customer Name]\n"
        "Incident: {incident_type}\n"
        "Discovery: {detection_date}\n"
        "Impact Assessment: {consequences}\n"
        "Remediation: {measures}\n"
    ),
    RegulationFramework.NIST: (
        "NIST IR Notification\n"
        "Incident Type: {incident_type}\n"
        "NIST 800-61 Phase: {current_phase}\n"
        "Detection Date: {detection_date}\n"
        "Actions Taken: {measures}\n"
    ),
}


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class PlaybookStep(BaseModel):
    """A single step within an IR phase."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    action_type: ActionType
    action_mode: ActionMode
    phase: IRPhase
    order: int = 0
    requires_approval: bool = False
    evidence_required: List[str] = Field(default_factory=list)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout_minutes: int = 60


class IRPlaybook(BaseModel):
    """A structured incident response playbook."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    incident_type: IncidentType
    description: str
    severity_threshold: IncidentSeverity = IncidentSeverity.HIGH
    phases: Dict[str, List[PlaybookStep]] = Field(default_factory=dict)
    applicable_regulations: List[RegulationFramework] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvidenceItem(BaseModel):
    """A single piece of evidence with cryptographic chain-of-custody."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    collector_id: str
    evidence_type: str
    description: str
    raw_content: str
    sha256_hash: str = ""
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    previous_hash: str = ""  # Links to prior evidence — cryptographic chain
    chain_sequence: int = 0

    @field_validator("sha256_hash", mode="before")
    @classmethod
    def compute_hash(cls, v: str, info: Any) -> str:
        """Compute SHA-256 of raw_content if hash not provided."""
        if v:
            return v
        raw = ""
        if hasattr(info, "data") and "raw_content" in info.data:
            raw = info.data["raw_content"]
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class TimelineEvent(BaseModel):
    """A single event in the incident timeline."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    event_type: str  # alert, log, action, communication, detection, containment
    source: str
    description: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PhaseRecord(BaseModel):
    """Record of work done in a single IR phase."""

    phase: IRPhase
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    steps_completed: List[str] = Field(default_factory=list)
    approval_granted_by: Optional[str] = None
    notes: str = ""


class RegulatoryNotification(BaseModel):
    """Tracks regulatory notification deadline and status."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    framework: RegulationFramework
    deadline_hours: Optional[int] = None
    detection_time: datetime
    deadline_at: Optional[datetime] = None
    notified_at: Optional[datetime] = None
    is_overdue: bool = False
    template: str = ""
    status: str = "pending"  # pending, sent, overdue, not_applicable


class IRIncident(BaseModel):
    """A live incident under response."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_id: str
    title: str
    incident_type: IncidentType
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.ACTIVE
    current_phase: IRPhase = IRPhase.DETECTION_ANALYSIS
    org_id: str = "default"
    assigned_to: Optional[str] = None
    affected_systems: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    phase_history: List[PhaseRecord] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detected_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IRMetrics(BaseModel):
    """Aggregate IR metrics for an org."""

    org_id: str
    total_incidents: int
    active_incidents: int
    closed_incidents: int
    mean_time_to_detect_hours: float  # MTTD
    mean_time_to_contain_hours: float  # MTTC
    mean_time_to_resolve_hours: float  # MTTR
    incidents_by_type: Dict[str, int]
    incidents_by_severity: Dict[str, int]
    playbook_effectiveness: Dict[str, float]  # playbook_id -> avg resolve hours


# ============================================================================
# BUILT-IN PLAYBOOK LIBRARY
# ============================================================================


def _make_steps(phase_steps: Dict[IRPhase, List[Tuple]]) -> Dict[str, List[PlaybookStep]]:
    """Build phase dict from (name, description, action_type, mode, requires_approval) tuples."""
    result: Dict[str, List[PlaybookStep]] = {}
    for phase, steps in phase_steps.items():
        result[phase.value] = [
            PlaybookStep(
                name=s[0],
                description=s[1],
                action_type=s[2],
                action_mode=s[3],
                phase=phase,
                order=i,
                requires_approval=s[4] if len(s) > 4 else False,
                evidence_required=s[5] if len(s) > 5 else [],
            )
            for i, s in enumerate(steps)
        ]
    return result


def _build_library() -> Dict[IncidentType, IRPlaybook]:
    """Build the 15 built-in IR playbooks."""
    library: Dict[IncidentType, IRPlaybook] = {}

    # ------------------------------------------------------------------
    # 1. Malware Infection
    # ------------------------------------------------------------------
    library[IncidentType.MALWARE_INFECTION] = IRPlaybook(
        id="ir-malware-infection",
        name="Malware Infection Response",
        incident_type=IncidentType.MALWARE_INFECTION,
        description="Response playbook for malware infections including trojans, viruses, worms.",
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.SOC2],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Identify Infected Host", "Confirm host identity and scope of infection.", ActionType.ISOLATE_HOST, ActionMode.AUTOMATED, False, ["host_logs", "av_alerts"]),
                ("Collect Malware Sample", "Extract malware binary for analysis.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["disk_snapshot"]),
                ("Determine Malware Family", "Classify malware type and C2 infrastructure.", ActionType.ESCALATE, ActionMode.MANUAL, False),
            ],
            IRPhase.CONTAINMENT: [
                ("Isolate Infected Host", "Network-isolate the infected system.", ActionType.ISOLATE_HOST, ActionMode.AUTOMATED, True, ["network_logs"]),
                ("Block C2 IPs", "Block known command-and-control IP addresses.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
                ("Revoke Host Credentials", "Revoke any credentials exposed on infected host.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, False),
            ],
            IRPhase.ERADICATION: [
                ("Remove Malware", "Delete malware artifacts and persistence mechanisms.", ActionType.KILL_SESSION, ActionMode.MANUAL, True),
                ("Patch Vulnerability", "Apply patches for the exploited vulnerability.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, False),
                ("Reset Compromised Credentials", "Reset all credentials touched by malware.", ActionType.RESET_PASSWORD, ActionMode.AUTOMATED, False),
            ],
            IRPhase.RECOVERY: [
                ("Restore from Clean Backup", "Restore system from pre-infection backup.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Verify System Integrity", "Run integrity checks post-restoration.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False),
                ("Re-enable Host", "Return host to production after clean bill of health.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("Post-Incident Review", "Conduct review with SOC and IT teams.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Update AV Signatures", "Push updated signatures based on collected sample.", ActionType.UPDATE_FIREWALL, ActionMode.AUTOMATED, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 2. Ransomware
    # ------------------------------------------------------------------
    library[IncidentType.RANSOMWARE] = IRPlaybook(
        id="ir-ransomware",
        name="Ransomware Response",
        incident_type=IncidentType.RANSOMWARE,
        description="Response playbook for ransomware events. Includes legal and law enforcement coordination.",
        severity_threshold=IncidentSeverity.CRITICAL,
        applicable_regulations=[RegulationFramework.GDPR, RegulationFramework.HIPAA, RegulationFramework.PCI_DSS, RegulationFramework.NIST],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Identify Encrypted Systems", "Enumerate all encrypted hosts and shares.", ActionType.ISOLATE_HOST, ActionMode.AUTOMATED, False, ["file_system_logs"]),
                ("Engage Legal Counsel", "Notify legal team immediately.", ActionType.CALL_LEGAL, ActionMode.MANUAL, True),
                ("Assess Ransom Note", "Capture and analyze ransom note for threat actor attribution.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["disk_snapshot"]),
                ("Notify Law Enforcement", "File report with FBI IC3 / local law enforcement.", ActionType.NOTIFY_LAW_ENFORCEMENT, ActionMode.MANUAL, True),
            ],
            IRPhase.CONTAINMENT: [
                ("Isolate All Affected Segments", "Quarantine infected network segments.", ActionType.ISOLATE_HOST, ActionMode.AUTOMATED, True),
                ("Disable Shared Drives", "Unmount all network shares to stop lateral encryption.", ActionType.KILL_SESSION, ActionMode.AUTOMATED, False),
                ("Block Threat Actor IPs", "Block known ransomware C2 infrastructure.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
                ("Engage IR Retainer", "Activate external incident response retainer.", ActionType.ENGAGE_IR_RETAINER, ActionMode.MANUAL, True),
            ],
            IRPhase.ERADICATION: [
                ("Identify Patient Zero", "Trace initial infection vector.", ActionType.ESCALATE, ActionMode.MANUAL, True),
                ("Remove Ransomware Artifacts", "Clean ransomware files and registry keys.", ActionType.KILL_SESSION, ActionMode.MANUAL, True),
                ("Patch Initial Access Vector", "Close the vulnerability used for initial access.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, False),
            ],
            IRPhase.RECOVERY: [
                ("Assess Backup Integrity", "Verify backups are clean and pre-date encryption.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, True),
                ("Executive Approval for Recovery", "Get C-suite sign-off before restoration.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Staged Recovery", "Restore systems in priority order.", ActionType.APPROVE_RECOVERY, ActionMode.MANUAL, True),
                ("Notify Affected Parties", "Notify customers/regulators per legal guidance.", ActionType.NOTIFY_CUSTOMERS, ActionMode.MANUAL, True),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("Ransomware Post-Mortem", "Full debrief with all stakeholders.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Backup Strategy Review", "Improve backup procedures and immutability.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Tabletop Exercise Update", "Update tabletop scenarios based on this incident.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 3. Data Breach
    # ------------------------------------------------------------------
    library[IncidentType.DATA_BREACH] = IRPlaybook(
        id="ir-data-breach",
        name="Data Breach Response",
        incident_type=IncidentType.DATA_BREACH,
        description="Response for confirmed or suspected personal data exfiltration.",
        severity_threshold=IncidentSeverity.HIGH,
        applicable_regulations=[RegulationFramework.GDPR, RegulationFramework.HIPAA, RegulationFramework.CCPA, RegulationFramework.PCI_DSS],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Confirm Data Exfiltration", "Confirm data left environment via DLP or SIEM.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["dlp_alerts", "network_logs"]),
                ("Classify Breached Data", "Identify PII, PHI, PCI, IP in scope.", ActionType.ESCALATE, ActionMode.MANUAL, True),
                ("Estimate Affected Records", "Count affected individuals and records.", ActionType.ESCALATE, ActionMode.MANUAL, False),
                ("Notify Legal and Privacy Officer", "Loop in legal and DPO immediately.", ActionType.CALL_LEGAL, ActionMode.MANUAL, True),
            ],
            IRPhase.CONTAINMENT: [
                ("Block Exfiltration Channel", "Block egress path used for exfiltration.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
                ("Revoke Attacker Access", "Revoke all compromised credentials.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, True),
                ("Preserve Evidence", "Capture logs and forensic images.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["forensic_image"]),
            ],
            IRPhase.ERADICATION: [
                ("Close Access Vector", "Patch or remediate the entry point.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, True),
                ("Audit All Privileged Access", "Review and reset all privileged credentials.", ActionType.RESET_PASSWORD, ActionMode.AUTOMATED, False),
            ],
            IRPhase.RECOVERY: [
                ("Assess Data Availability", "Verify remaining data integrity.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("File Regulatory Notifications", "Submit breach notifications per applicable laws.", ActionType.FILE_REGULATORY, ActionMode.MANUAL, True),
                ("Notify Affected Individuals", "Send breach notices to impacted customers.", ActionType.NOTIFY_CUSTOMERS, ActionMode.MANUAL, True),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("Root Cause Analysis", "Determine and document root cause.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("DLP Policy Update", "Strengthen data loss prevention rules.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 4. Credential Compromise
    # ------------------------------------------------------------------
    library[IncidentType.CREDENTIAL_COMPROMISE] = IRPlaybook(
        id="ir-credential-compromise",
        name="Credential Compromise Response",
        incident_type=IncidentType.CREDENTIAL_COMPROMISE,
        description="Response for compromised credentials: password spray, credential stuffing, phished creds.",
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.SOC2],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Identify Compromised Accounts", "Enumerate accounts showing anomalous access.", ActionType.DISABLE_USER, ActionMode.AUTOMATED, False, ["auth_logs"]),
                ("Determine Breach Vector", "Was it phishing, spray, stuffing, or dark web?", ActionType.ESCALATE, ActionMode.MANUAL, False),
            ],
            IRPhase.CONTAINMENT: [
                ("Disable Compromised Accounts", "Immediately disable all affected user accounts.", ActionType.DISABLE_USER, ActionMode.AUTOMATED, True),
                ("Revoke All Sessions", "Invalidate all active sessions for affected users.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, False),
                ("Block Attacker IPs", "Block IPs showing attack patterns.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
            ],
            IRPhase.ERADICATION: [
                ("Force Password Reset", "Reset passwords for all affected accounts.", ActionType.RESET_PASSWORD, ActionMode.AUTOMATED, False),
                ("Enable MFA", "Enforce MFA on all affected accounts.", ActionType.ENABLE_MFA, ActionMode.AUTOMATED, False),
                ("Audit OAuth Grants", "Revoke suspicious OAuth application permissions.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, False),
            ],
            IRPhase.RECOVERY: [
                ("Re-enable Accounts", "Re-enable accounts after credential reset.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Monitor for Reuse", "Watch for continued credential reuse attempts.", ActionType.ESCALATE, ActionMode.AUTOMATED, False),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("MFA Coverage Review", "Audit MFA enrollment across all users.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Password Policy Audit", "Review and update password policies.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 5. Insider Threat
    # ------------------------------------------------------------------
    library[IncidentType.INSIDER_THREAT] = IRPlaybook(
        id="ir-insider-threat",
        name="Insider Threat Response",
        incident_type=IncidentType.INSIDER_THREAT,
        description="Response for malicious or negligent insider activity. Requires HR and Legal coordination.",
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.SOC2, RegulationFramework.GDPR],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Collect User Activity Evidence", "Pull UEBA alerts, access logs, DLP events.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["ueba_logs", "dlp_alerts"]),
                ("Notify HR and Legal", "Confidentially loop in HR and Legal.", ActionType.CALL_LEGAL, ActionMode.MANUAL, True),
                ("Preserve Chain of Custody", "Cryptographically seal all evidence.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["forensic_image"]),
            ],
            IRPhase.CONTAINMENT: [
                ("Restrict Account Access", "Limit to read-only or suspend access.", ActionType.DISABLE_USER, ActionMode.AUTOMATED, True),
                ("Revoke Privileged Access", "Remove admin/elevated rights immediately.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, True),
                ("Monitor Remaining Access", "Watch for continued suspicious activity.", ActionType.ESCALATE, ActionMode.AUTOMATED, False),
            ],
            IRPhase.ERADICATION: [
                ("Disable Account Fully", "Terminate account per HR decision.", ActionType.DISABLE_USER, ActionMode.MANUAL, True),
                ("Recover Exfiltrated Data", "Assess and recover if possible.", ActionType.ESCALATE, ActionMode.MANUAL, False),
                ("Notify Law Enforcement if Criminal", "File criminal referral if warranted.", ActionType.NOTIFY_LAW_ENFORCEMENT, ActionMode.MANUAL, True),
            ],
            IRPhase.RECOVERY: [
                ("Restore Affected Data", "Recover any impacted data or systems.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Notify Affected Parties", "Notify customers/regulators if data was exposed.", ActionType.NOTIFY_CUSTOMERS, ActionMode.MANUAL, True),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("UEBA Tuning", "Improve behavioral analytics detection rules.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Access Review", "Conduct access recertification across the org.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 6. DDoS
    # ------------------------------------------------------------------
    library[IncidentType.DDOS] = IRPlaybook(
        id="ir-ddos",
        name="DDoS Response",
        incident_type=IncidentType.DDOS,
        description="Response for volumetric, protocol, and application-layer DDoS attacks.",
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.SOC2],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Confirm DDoS Attack", "Verify anomalous traffic volume with ISP/CDN.", ActionType.ESCALATE, ActionMode.AUTOMATED, False, ["netflow_logs"]),
                ("Classify Attack Vector", "Layer 3/4 volumetric vs Layer 7 application.", ActionType.ESCALATE, ActionMode.MANUAL, False),
            ],
            IRPhase.CONTAINMENT: [
                ("Enable DDoS Scrubbing", "Route traffic through DDoS mitigation service.", ActionType.UPDATE_FIREWALL, ActionMode.AUTOMATED, True),
                ("Block Attack Source IPs", "Null-route or firewall top attack IPs.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
                ("Rate Limit Endpoints", "Apply rate limiting at CDN/WAF layer.", ActionType.UPDATE_FIREWALL, ActionMode.AUTOMATED, False),
                ("Notify ISP/Upstream", "Coordinate with upstream provider for BGP blackhole.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
            IRPhase.ERADICATION: [
                ("Tune Mitigation Rules", "Refine block rules based on traffic patterns.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, False),
                ("Identify Attack Infrastructure", "Attribution and takedown requests.", ActionType.NOTIFY_LAW_ENFORCEMENT, ActionMode.MANUAL, False),
            ],
            IRPhase.RECOVERY: [
                ("Remove Scrubbing", "Gradually remove scrubbing as traffic normalizes.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Restore Rate Limits", "Return to normal rate limit thresholds.", ActionType.UPDATE_FIREWALL, ActionMode.AUTOMATED, False),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("DDoS Runbook Update", "Update runbook with lessons from this attack.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Capacity Planning", "Review capacity and DDoS protection tiers.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 7. Supply Chain Attack
    # ------------------------------------------------------------------
    library[IncidentType.SUPPLY_CHAIN_ATTACK] = IRPlaybook(
        id="ir-supply-chain",
        name="Supply Chain Attack Response",
        incident_type=IncidentType.SUPPLY_CHAIN_ATTACK,
        description="Response for compromised third-party software, libraries, or vendors.",
        severity_threshold=IncidentSeverity.CRITICAL,
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.SOC2, RegulationFramework.GDPR],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Identify Compromised Component", "Pinpoint the malicious package/vendor.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["sbom_data", "package_logs"]),
                ("Determine Blast Radius", "Enumerate all systems using the component.", ActionType.ESCALATE, ActionMode.MANUAL, True),
                ("Notify Vendor", "Contact the compromised vendor/supplier.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
            IRPhase.CONTAINMENT: [
                ("Isolate Affected Systems", "Quarantine systems using compromised component.", ActionType.ISOLATE_HOST, ActionMode.AUTOMATED, True),
                ("Block Malicious Endpoints", "Block C2/exfil endpoints from the supply chain attack.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
                ("Freeze Deployments", "Halt all deployments pending investigation.", ActionType.CONTAIN_ONLY, ActionMode.DECISION, True),
            ],
            IRPhase.ERADICATION: [
                ("Remove Compromised Package", "Purge malicious version from all systems.", ActionType.KILL_SESSION, ActionMode.MANUAL, True),
                ("Rebuild from Trusted Source", "Rebuild affected containers/VMs from clean base.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, True),
                ("Rotate All Secrets", "Rotate all secrets that may have been exposed.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, True),
            ],
            IRPhase.RECOVERY: [
                ("Deploy Clean Version", "Deploy vetted replacement for compromised component.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Resume Deployments", "Resume CI/CD with enhanced scanning.", ActionType.APPROVE_RECOVERY, ActionMode.MANUAL, True),
                ("Notify Regulators if Required", "File regulatory notifications for data exposure.", ActionType.FILE_REGULATORY, ActionMode.MANUAL, True),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("SBOM Program Review", "Improve software bill of materials practices.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Vendor Risk Assessment", "Update third-party risk management program.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 8. API Abuse
    # ------------------------------------------------------------------
    library[IncidentType.API_ABUSE] = IRPlaybook(
        id="ir-api-abuse",
        name="API Abuse Response",
        incident_type=IncidentType.API_ABUSE,
        description="Response for API scraping, enumeration, credential stuffing, or abuse of API endpoints.",
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.SOC2, RegulationFramework.PCI_DSS],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Identify Abusive Patterns", "Confirm API abuse via rate/anomaly alerts.", ActionType.ESCALATE, ActionMode.AUTOMATED, False, ["api_logs"]),
                ("Classify Abuse Type", "Scraping, enumeration, credential stuffing, biz logic.", ActionType.ESCALATE, ActionMode.MANUAL, False),
            ],
            IRPhase.CONTAINMENT: [
                ("Block Abusive IPs", "Block IP ranges showing abusive patterns.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
                ("Revoke Abusive Tokens", "Revoke API keys/tokens being abused.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, False),
                ("Rate Limit Aggressively", "Apply strict rate limits on affected endpoints.", ActionType.UPDATE_FIREWALL, ActionMode.AUTOMATED, False),
            ],
            IRPhase.ERADICATION: [
                ("Patch Vulnerable Logic", "Fix business logic flaws exploited.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, True),
                ("Implement CAPTCHA", "Add bot detection to targeted endpoints.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, False),
            ],
            IRPhase.RECOVERY: [
                ("Re-enable Affected APIs", "Restore endpoints with enhanced protection.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Monitor for Recurrence", "Watch for re-emergence of abuse patterns.", ActionType.ESCALATE, ActionMode.AUTOMATED, False),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("API Security Review", "Review API design for security anti-patterns.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("WAF Rule Update", "Add WAF rules based on observed attack signatures.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 9. Cloud Misconfiguration
    # ------------------------------------------------------------------
    library[IncidentType.CLOUD_MISCONFIGURATION] = IRPlaybook(
        id="ir-cloud-misconfig",
        name="Cloud Misconfiguration Response",
        incident_type=IncidentType.CLOUD_MISCONFIGURATION,
        description="Response for exposed S3 buckets, open security groups, public databases, overprivileged roles.",
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.GDPR, RegulationFramework.SOC2],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Identify Misconfigured Resource", "Confirm resource type and exposure level.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["cloud_config_logs"]),
                ("Assess Data Exposure", "Determine if data was accessed by unauthorized parties.", ActionType.ESCALATE, ActionMode.MANUAL, True),
            ],
            IRPhase.CONTAINMENT: [
                ("Restrict Public Access", "Apply restrictive ACLs/security groups immediately.", ActionType.UPDATE_FIREWALL, ActionMode.AUTOMATED, True),
                ("Rotate Exposed Credentials", "Rotate any keys/secrets accessible via misconfiguration.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, False),
                ("Enable Access Logging", "Enable CloudTrail/audit logs on affected resources.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False),
            ],
            IRPhase.ERADICATION: [
                ("Apply Correct Configuration", "Implement least-privilege resource configuration.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, True),
                ("Scan for Similar Issues", "Run CSPM scan across all cloud accounts.", ActionType.ESCALATE, ActionMode.AUTOMATED, False),
            ],
            IRPhase.RECOVERY: [
                ("Re-enable Service Access", "Restore authorized access to the resource.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Notify Affected Parties", "If data was accessed, initiate breach notification.", ActionType.NOTIFY_CUSTOMERS, ActionMode.MANUAL, True),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("CSPM Policy Update", "Improve cloud security posture management policies.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("IaC Security Checks", "Add security checks to infrastructure-as-code pipelines.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 10. Phishing Campaign
    # ------------------------------------------------------------------
    library[IncidentType.PHISHING_CAMPAIGN] = IRPlaybook(
        id="ir-phishing",
        name="Phishing Campaign Response",
        incident_type=IncidentType.PHISHING_CAMPAIGN,
        description="Response for phishing emails targeting employees. Includes credential and malware follow-ons.",
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.SOC2],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Identify Phishing Email", "Obtain full email headers and body for analysis.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["email_headers"]),
                ("Assess Click/Compromise Rate", "Determine who clicked links or submitted credentials.", ActionType.ESCALATE, ActionMode.MANUAL, False),
            ],
            IRPhase.CONTAINMENT: [
                ("Quarantine Phishing Email", "Pull phishing email from all mailboxes.", ActionType.QUARANTINE_EMAIL, ActionMode.AUTOMATED, False),
                ("Block Phishing Domain/IP", "Block the phishing site at DNS and IP level.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
                ("Reset Compromised Credentials", "Force password reset for users who were phished.", ActionType.RESET_PASSWORD, ActionMode.AUTOMATED, True),
            ],
            IRPhase.ERADICATION: [
                ("Enable MFA for Phished Users", "Require MFA immediately for affected accounts.", ActionType.ENABLE_MFA, ActionMode.AUTOMATED, False),
                ("Scan for Malware Payload", "Check endpoints of users who clicked links.", ActionType.ISOLATE_HOST, ActionMode.AUTOMATED, False),
                ("Report Phishing Domain", "Submit domain for takedown via registrar and ISACs.", ActionType.NOTIFY_LAW_ENFORCEMENT, ActionMode.MANUAL, False),
            ],
            IRPhase.RECOVERY: [
                ("Restore User Access", "Re-enable access after credential remediation.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, False),
                ("Send User Notification", "Notify affected users of the phishing attempt.", ActionType.NOTIFY_CUSTOMERS, ActionMode.MANUAL, False),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("Phishing Simulation Update", "Add new template to phishing training platform.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Email Filter Tuning", "Update email gateway rules to catch similar campaigns.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 11. Unauthorized Access
    # ------------------------------------------------------------------
    library[IncidentType.UNAUTHORIZED_ACCESS] = IRPlaybook(
        id="ir-unauthorized-access",
        name="Unauthorized Access Response",
        incident_type=IncidentType.UNAUTHORIZED_ACCESS,
        description="Response for unauthorized login or access to systems, data, or applications.",
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.SOC2, RegulationFramework.GDPR],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Confirm Unauthorized Access", "Verify access was not authorized via ticketing/change.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["auth_logs", "access_logs"]),
                ("Identify Accessed Resources", "Enumerate all data/systems accessed.", ActionType.ESCALATE, ActionMode.MANUAL, False),
            ],
            IRPhase.CONTAINMENT: [
                ("Terminate Active Session", "Kill active unauthorized sessions.", ActionType.KILL_SESSION, ActionMode.AUTOMATED, True),
                ("Block Attacker IP", "Block the source IP of unauthorized access.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
                ("Revoke Access Tokens", "Revoke all tokens used in unauthorized access.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, False),
            ],
            IRPhase.ERADICATION: [
                ("Reset Compromised Account", "Reset credentials and re-enroll MFA.", ActionType.RESET_PASSWORD, ActionMode.AUTOMATED, False),
                ("Patch Access Vector", "Fix the vulnerability or misconfiguration exploited.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, True),
            ],
            IRPhase.RECOVERY: [
                ("Verify Access Controls", "Confirm proper access controls are restored.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Notify if Data Accessed", "If data was accessed, assess breach notification need.", ActionType.NOTIFY_CUSTOMERS, ActionMode.MANUAL, True),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("Access Control Review", "Audit access controls across all critical systems.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("MFA Enforcement", "Expand MFA to all access pathways.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 12. Data Exfiltration
    # ------------------------------------------------------------------
    library[IncidentType.DATA_EXFILTRATION] = IRPlaybook(
        id="ir-data-exfiltration",
        name="Data Exfiltration Response",
        incident_type=IncidentType.DATA_EXFILTRATION,
        description="Response for confirmed data exfiltration via network, cloud, USB, or email.",
        severity_threshold=IncidentSeverity.CRITICAL,
        applicable_regulations=[RegulationFramework.GDPR, RegulationFramework.HIPAA, RegulationFramework.CCPA, RegulationFramework.PCI_DSS],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Confirm Exfiltration Channel", "Identify how data left: HTTP/DNS/cloud/USB/email.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["netflow_logs", "dlp_alerts"]),
                ("Quantify Exfiltrated Data", "Estimate volume and classification of data exfiltrated.", ActionType.ESCALATE, ActionMode.MANUAL, True),
                ("Notify Legal", "Alert legal counsel for regulatory assessment.", ActionType.CALL_LEGAL, ActionMode.MANUAL, True),
            ],
            IRPhase.CONTAINMENT: [
                ("Block Exfiltration Channel", "Block the specific channel used for exfiltration.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, True),
                ("Isolate Source System", "Isolate the system that initiated exfiltration.", ActionType.ISOLATE_HOST, ActionMode.AUTOMATED, True),
                ("Revoke Attacker Credentials", "Revoke all credentials used by the attacker.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, True),
            ],
            IRPhase.ERADICATION: [
                ("Remove Attacker Persistence", "Eliminate backdoors and persistence mechanisms.", ActionType.KILL_SESSION, ActionMode.MANUAL, True),
                ("Close Exfiltration Vector", "Patch or reconfigure to prevent recurrence.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, True),
            ],
            IRPhase.RECOVERY: [
                ("File Regulatory Notifications", "Submit breach notifications per applicable regulations.", ActionType.FILE_REGULATORY, ActionMode.MANUAL, True),
                ("Notify Affected Individuals", "Send breach notices to impacted data subjects.", ActionType.NOTIFY_CUSTOMERS, ActionMode.MANUAL, True),
                ("Engage Data Recovery Services", "Attempt data recovery where possible.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("DLP Enhancement", "Strengthen data loss prevention policies.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Egress Monitoring", "Improve outbound traffic monitoring.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 13. Website Defacement
    # ------------------------------------------------------------------
    library[IncidentType.WEBSITE_DEFACEMENT] = IRPlaybook(
        id="ir-website-defacement",
        name="Website Defacement Response",
        incident_type=IncidentType.WEBSITE_DEFACEMENT,
        description="Response for unauthorized modification of web content by external attackers.",
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.SOC2],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Confirm Defacement", "Screenshot and document the defaced content.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["web_screenshot", "server_logs"]),
                ("Identify Entry Point", "Review web server logs for initial access vector.", ActionType.ESCALATE, ActionMode.MANUAL, False),
            ],
            IRPhase.CONTAINMENT: [
                ("Take Site Offline", "Redirect traffic to maintenance page.", ActionType.ISOLATE_HOST, ActionMode.AUTOMATED, True),
                ("Revoke Web Admin Access", "Suspend all CMS/admin credentials.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, False),
                ("Block Attacker IP", "Block source IPs of the attacker.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
            ],
            IRPhase.ERADICATION: [
                ("Remove Malicious Content", "Clean or restore web files from backup.", ActionType.KILL_SESSION, ActionMode.MANUAL, True),
                ("Patch Web Application", "Apply patches for exploited CMS/web vulnerabilities.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, True),
                ("Harden Web Server", "Remove unnecessary services and tighten permissions.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, False),
            ],
            IRPhase.RECOVERY: [
                ("Restore Website", "Restore site from clean backup after patching.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Notify Stakeholders", "Inform management and customers of incident.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("WAF Deployment", "Deploy or enhance web application firewall.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("File Integrity Monitoring", "Implement FIM on web server files.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 14. Zero-Day Exploit
    # ------------------------------------------------------------------
    library[IncidentType.ZERO_DAY_EXPLOIT] = IRPlaybook(
        id="ir-zero-day",
        name="Zero-Day Exploit Response",
        incident_type=IncidentType.ZERO_DAY_EXPLOIT,
        description="Response for exploitation of previously unknown vulnerabilities. Requires vendor coordination.",
        severity_threshold=IncidentSeverity.CRITICAL,
        applicable_regulations=[RegulationFramework.NIST, RegulationFramework.SOC2, RegulationFramework.GDPR],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Confirm Zero-Day Activity", "Verify anomalous behavior consistent with zero-day exploitation.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["edr_alerts", "server_logs"]),
                ("Engage IR Retainer", "Activate external IR retainer for zero-day expertise.", ActionType.ENGAGE_IR_RETAINER, ActionMode.MANUAL, True),
                ("Notify Vendor", "Contact software vendor with proof-of-concept details.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, True),
            ],
            IRPhase.CONTAINMENT: [
                ("Isolate Affected Systems", "Immediately quarantine all systems showing exploitation.", ActionType.ISOLATE_HOST, ActionMode.AUTOMATED, True),
                ("Apply Virtual Patch", "Deploy WAF/IPS rules to block exploit pattern.", ActionType.UPDATE_FIREWALL, ActionMode.AUTOMATED, True),
                ("Block Exploit Infrastructure", "Block known exploit delivery infrastructure.", ActionType.BLOCK_IP, ActionMode.AUTOMATED, False),
                ("Revoke Post-Exploitation Credentials", "Revoke credentials obtained post-exploitation.", ActionType.REVOKE_TOKENS, ActionMode.AUTOMATED, True),
            ],
            IRPhase.ERADICATION: [
                ("Apply Vendor Patch", "Apply official patch when released by vendor.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, True),
                ("Rebuild Compromised Systems", "Rebuild from clean image rather than remediate.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, True),
            ],
            IRPhase.RECOVERY: [
                ("Staged Return to Production", "Carefully restore systems with enhanced monitoring.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
                ("Executive Briefing", "Brief C-suite on zero-day impact and resolution.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Notify Regulators if Data Impacted", "File regulatory notifications if data was accessed.", ActionType.FILE_REGULATORY, ActionMode.MANUAL, True),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("Threat Intelligence Sharing", "Share IOCs with ISACs and threat intel communities.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Detection Engineering", "Write detection rules for this zero-day pattern.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, False),
            ],
        }),
    )

    # ------------------------------------------------------------------
    # 15. Compliance Violation
    # ------------------------------------------------------------------
    library[IncidentType.COMPLIANCE_VIOLATION] = IRPlaybook(
        id="ir-compliance-violation",
        name="Compliance Violation Response",
        incident_type=IncidentType.COMPLIANCE_VIOLATION,
        description="Response for confirmed compliance violations: GDPR, HIPAA, PCI-DSS, SOC2, etc.",
        applicable_regulations=[RegulationFramework.GDPR, RegulationFramework.HIPAA, RegulationFramework.PCI_DSS, RegulationFramework.SOC2, RegulationFramework.CCPA],
        phases=_make_steps({
            IRPhase.DETECTION_ANALYSIS: [
                ("Confirm Violation Scope", "Determine which framework(s) are violated and scope.", ActionType.ESCALATE, ActionMode.MANUAL, True),
                ("Notify Legal and Compliance", "Alert legal and compliance officers.", ActionType.CALL_LEGAL, ActionMode.MANUAL, True),
                ("Document Evidence", "Collect and preserve all relevant evidence.", ActionType.SNAPSHOT_DISK, ActionMode.AUTOMATED, False, ["compliance_evidence"]),
            ],
            IRPhase.CONTAINMENT: [
                ("Stop Violating Activity", "Immediately halt the non-compliant process.", ActionType.CONTAIN_ONLY, ActionMode.DECISION, True),
                ("Isolate Non-Compliant System", "Restrict access to the violating system.", ActionType.ISOLATE_HOST, ActionMode.AUTOMATED, False),
            ],
            IRPhase.ERADICATION: [
                ("Remediate Root Cause", "Fix the process or technical control that failed.", ActionType.UPDATE_FIREWALL, ActionMode.MANUAL, True),
                ("Update Policies", "Revise policies to prevent recurrence.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
            IRPhase.RECOVERY: [
                ("File Self-Disclosure", "Submit self-disclosure to relevant regulator.", ActionType.FILE_REGULATORY, ActionMode.MANUAL, True),
                ("Resume Compliant Operations", "Restore operations after remediation verified.", ActionType.APPROVE_RECOVERY, ActionMode.DECISION, True),
            ],
            IRPhase.LESSONS_LEARNED: [
                ("Compliance Training", "Mandatory training for affected teams.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
                ("Control Enhancement", "Strengthen detective and preventive controls.", ActionType.NOTIFY_MANAGEMENT, ActionMode.MANUAL, False),
            ],
        }),
    )

    return library


# Module-level playbook library (built once at import)
_PLAYBOOK_LIBRARY: Dict[IncidentType, IRPlaybook] = _build_library()


# ============================================================================
# EVIDENCE CHAIN HELPERS
# ============================================================================


def _compute_evidence_hash(raw_content: str) -> str:
    """Compute FIPS-compliant SHA-256 hash of evidence content."""
    return hashlib.sha256(raw_content.encode("utf-8")).hexdigest()


def _compute_chain_hash(evidence_id: str, content_hash: str, previous_hash: str, timestamp: str) -> str:
    """Chain-link hash: SHA-256 of (evidence_id + content_hash + previous_hash + timestamp)."""
    chain_input = f"{evidence_id}:{content_hash}:{previous_hash}:{timestamp}"
    return hashlib.sha256(chain_input.encode("utf-8")).hexdigest()


# ============================================================================
# IR PLAYBOOK ENGINE
# ============================================================================


class IRPlaybookEngine:
    """
    SQLite-backed Incident Response Playbook Engine.

    Thread-safe via per-instance lock. Multi-tenant via org_id.
    NIST 800-61r2 compliant with cryptographic evidence chain.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # FEATURE-5: route through DBAdapter so DATABASE_URL switches to postgres.
        from core.db_adapter import get_adapter
        self._db = get_adapter(db_path)
        self._init_db()

    # -----------------------------------------------------------------------
    # DB INIT
    # -----------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS ir_incidents (
                    id              TEXT PRIMARY KEY,
                    playbook_id     TEXT NOT NULL,
                    title           TEXT NOT NULL,
                    incident_type   TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'active',
                    current_phase   TEXT NOT NULL DEFAULT 'detection_analysis',
                    org_id          TEXT NOT NULL DEFAULT 'default',
                    assigned_to     TEXT,
                    affected_systems TEXT NOT NULL DEFAULT '[]',
                    affected_users  TEXT NOT NULL DEFAULT '[]',
                    tags            TEXT NOT NULL DEFAULT '[]',
                    phase_history   TEXT NOT NULL DEFAULT '[]',
                    context         TEXT NOT NULL DEFAULT '{}',
                    created_at      TEXT NOT NULL,
                    detected_at     TEXT,
                    contained_at    TEXT,
                    resolved_at     TEXT,
                    updated_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ir_evidence (
                    id              TEXT PRIMARY KEY,
                    incident_id     TEXT NOT NULL,
                    collector_id    TEXT NOT NULL,
                    evidence_type   TEXT NOT NULL,
                    description     TEXT NOT NULL,
                    raw_content     TEXT NOT NULL,
                    sha256_hash     TEXT NOT NULL,
                    collected_at    TEXT NOT NULL,
                    previous_hash   TEXT NOT NULL DEFAULT '',
                    chain_sequence  INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (incident_id) REFERENCES ir_incidents(id)
                );

                CREATE TABLE IF NOT EXISTS ir_timeline (
                    id              TEXT PRIMARY KEY,
                    incident_id     TEXT NOT NULL,
                    event_type      TEXT NOT NULL,
                    source          TEXT NOT NULL,
                    description     TEXT NOT NULL,
                    timestamp       TEXT NOT NULL,
                    metadata        TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (incident_id) REFERENCES ir_incidents(id)
                );

                CREATE TABLE IF NOT EXISTS ir_notifications (
                    id              TEXT PRIMARY KEY,
                    incident_id     TEXT NOT NULL,
                    framework       TEXT NOT NULL,
                    deadline_hours  INTEGER,
                    detection_time  TEXT NOT NULL,
                    deadline_at     TEXT,
                    notified_at     TEXT,
                    is_overdue      INTEGER NOT NULL DEFAULT 0,
                    template        TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    FOREIGN KEY (incident_id) REFERENCES ir_incidents(id)
                );

                CREATE INDEX IF NOT EXISTS idx_ir_incidents_org
                    ON ir_incidents(org_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_ir_incidents_type
                    ON ir_incidents(org_id, incident_type);
                CREATE INDEX IF NOT EXISTS idx_ir_evidence_incident
                    ON ir_evidence(incident_id, chain_sequence);
                CREATE INDEX IF NOT EXISTS idx_ir_timeline_incident
                    ON ir_timeline(incident_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_ir_notifications_incident
                    ON ir_notifications(incident_id);
            """)

    def _connect(self):  # type: ignore[no-untyped-def]
        """Return a fresh per-call connection.

        FEATURE-5: when DATABASE_URL is set the adapter returns a psycopg2.connection
        instead of sqlite3.Connection. Both support the context-manager protocol so
        existing `with self._connect() as conn:` callers work unchanged.
        """
        if self._db.is_postgres:
            return self._db._psycopg2.connect(self._db.dsn)  # type: ignore[union-attr]
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # -----------------------------------------------------------------------
    # SERIALIZATION HELPERS
    # -----------------------------------------------------------------------

    def _row_to_incident(self, row: sqlite3.Row) -> IRIncident:
        phase_history_raw = json.loads(row["phase_history"])
        phase_history = [PhaseRecord(**p) for p in phase_history_raw]
        return IRIncident(
            id=row["id"],
            playbook_id=row["playbook_id"],
            title=row["title"],
            incident_type=IncidentType(row["incident_type"]),
            severity=IncidentSeverity(row["severity"]),
            status=IncidentStatus(row["status"]),
            current_phase=IRPhase(row["current_phase"]),
            org_id=row["org_id"],
            assigned_to=row["assigned_to"],
            affected_systems=json.loads(row["affected_systems"]),
            affected_users=json.loads(row["affected_users"]),
            tags=json.loads(row["tags"]),
            phase_history=phase_history,
            context=json.loads(row["context"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            detected_at=datetime.fromisoformat(row["detected_at"]) if row["detected_at"] else None,
            contained_at=datetime.fromisoformat(row["contained_at"]) if row["contained_at"] else None,
            resolved_at=datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def _row_to_evidence(self, row: sqlite3.Row) -> EvidenceItem:
        return EvidenceItem(
            id=row["id"],
            incident_id=row["incident_id"],
            collector_id=row["collector_id"],
            evidence_type=row["evidence_type"],
            description=row["description"],
            raw_content=row["raw_content"],
            sha256_hash=row["sha256_hash"],
            collected_at=datetime.fromisoformat(row["collected_at"]),
            previous_hash=row["previous_hash"],
            chain_sequence=row["chain_sequence"],
        )

    def _row_to_timeline_event(self, row: sqlite3.Row) -> TimelineEvent:
        return TimelineEvent(
            id=row["id"],
            incident_id=row["incident_id"],
            event_type=row["event_type"],
            source=row["source"],
            description=row["description"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            metadata=json.loads(row["metadata"]),
        )

    def _row_to_notification(self, row: sqlite3.Row) -> RegulatoryNotification:
        return RegulatoryNotification(
            id=row["id"],
            incident_id=row["incident_id"],
            framework=RegulationFramework(row["framework"]),
            deadline_hours=row["deadline_hours"],
            detection_time=datetime.fromisoformat(row["detection_time"]),
            deadline_at=datetime.fromisoformat(row["deadline_at"]) if row["deadline_at"] else None,
            notified_at=datetime.fromisoformat(row["notified_at"]) if row["notified_at"] else None,
            is_overdue=bool(row["is_overdue"]),
            template=row["template"],
            status=row["status"],
        )

    # -----------------------------------------------------------------------
    # PLAYBOOK LIBRARY
    # -----------------------------------------------------------------------

    def list_playbooks(self) -> List[IRPlaybook]:
        """Return all built-in IR playbooks."""
        return list(_PLAYBOOK_LIBRARY.values())

    def get_playbook(self, playbook_id: str) -> Optional[IRPlaybook]:
        """Return a playbook by ID."""
        for pb in _PLAYBOOK_LIBRARY.values():
            if pb.id == playbook_id:
                return pb
        return None

    def get_playbook_for_type(self, incident_type: IncidentType) -> Optional[IRPlaybook]:
        """Return the playbook for a given incident type."""
        return _PLAYBOOK_LIBRARY.get(incident_type)

    # -----------------------------------------------------------------------
    # INCIDENT MANAGEMENT
    # -----------------------------------------------------------------------

    def create_incident(
        self,
        title: str,
        incident_type: IncidentType,
        severity: IncidentSeverity,
        org_id: str = "default",
        assigned_to: Optional[str] = None,
        affected_systems: Optional[List[str]] = None,
        affected_users: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        detected_at: Optional[datetime] = None,
    ) -> IRIncident:
        """
        Create a new incident. Auto-selects playbook based on incident_type.
        Creates regulatory notifications based on the playbook's applicable_regulations.
        """
        playbook = self.get_playbook_for_type(incident_type)
        if playbook is None:
            raise ValueError(f"No playbook found for incident type: {incident_type}")

        now = datetime.now(timezone.utc)
        detection_time = detected_at or now

        incident = IRIncident(
            playbook_id=playbook.id,
            title=title,
            incident_type=incident_type,
            severity=severity,
            org_id=org_id,
            assigned_to=assigned_to,
            affected_systems=affected_systems or [],
            affected_users=affected_users or [],
            tags=tags or [],
            context=context or {},
            created_at=now,
            detected_at=detection_time,
            updated_at=now,
            phase_history=[
                PhaseRecord(
                    phase=IRPhase.DETECTION_ANALYSIS,
                    started_at=now,
                )
            ],
        )

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO ir_incidents
                        (id, playbook_id, title, incident_type, severity, status,
                         current_phase, org_id, assigned_to, affected_systems, affected_users,
                         tags, phase_history, context, created_at, detected_at, contained_at,
                         resolved_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
                    """,
                    (
                        incident.id, incident.playbook_id, incident.title,
                        incident.incident_type.value, incident.severity.value,
                        incident.status.value, incident.current_phase.value,
                        incident.org_id, incident.assigned_to,
                        json.dumps(incident.affected_systems),
                        json.dumps(incident.affected_users),
                        json.dumps(incident.tags),
                        json.dumps([p.model_dump(mode="json") for p in incident.phase_history]),
                        json.dumps(incident.context),
                        incident.created_at.isoformat(),
                        detection_time.isoformat(),
                        now.isoformat(),
                    ),
                )

        # Create timeline entry for incident creation
        self.add_timeline_event(
            incident_id=incident.id,
            event_type="detection",
            source="ir_engine",
            description=f"Incident created: {title} — Type: {incident_type.value} Severity: {severity.value}",
            metadata={"playbook_id": playbook.id, "org_id": org_id},
        )

        # Create regulatory notifications
        self._create_regulatory_notifications(incident, playbook, detection_time)

        _logger.info(
            "IR incident created",
            incident_id=incident.id,
            incident_type=incident_type.value,
            severity=severity.value,
            playbook_id=playbook.id,
        )
        _emit_event("ir.incident.created", {
            "incident_id": incident.id,
            "incident_type": incident_type.value,
            "severity": severity.value,
            "playbook_id": playbook.id,
            "org_id": org_id,
        })
        return incident

    def get_incident(self, incident_id: str, org_id: str = "default") -> Optional[IRIncident]:
        """Retrieve an incident by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM ir_incidents WHERE id = ? AND org_id = ?",
                (incident_id, org_id),
            ).fetchone()
        return self._row_to_incident(row) if row else None

    def list_incidents(
        self,
        org_id: str = "default",
        status: Optional[IncidentStatus] = None,
        incident_type: Optional[IncidentType] = None,
        limit: int = 100,
    ) -> List[IRIncident]:
        """List incidents for an org with optional filters."""
        query = "SELECT * FROM ir_incidents WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status = ?"
            params.append(status.value)
        if incident_type:
            query += " AND incident_type = ?"
            params.append(incident_type.value)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_incident(r) for r in rows]

    def advance_phase(
        self,
        incident_id: str,
        org_id: str = "default",
        approved_by: Optional[str] = None,
        notes: str = "",
    ) -> IRIncident:
        """
        Advance incident to the next NIST 800-61 phase.
        Updates status, timestamps, and phase_history.
        """
        incident = self.get_incident(incident_id, org_id=org_id)
        if incident is None:
            raise ValueError(f"Incident '{incident_id}' not found")
        if incident.current_phase == IRPhase.CLOSED:
            raise ValueError("Incident is already closed")

        current_idx = _PHASE_ORDER.index(incident.current_phase)
        next_phase = _PHASE_ORDER[current_idx + 1]
        now = datetime.now(timezone.utc)

        # Complete current phase record
        phase_history = incident.phase_history
        if phase_history and phase_history[-1].phase == incident.current_phase:
            phase_history[-1].completed_at = now
            phase_history[-1].approval_granted_by = approved_by
            phase_history[-1].notes = notes

        # Start new phase record
        if next_phase != IRPhase.CLOSED:
            phase_history.append(PhaseRecord(phase=next_phase, started_at=now))

        # Update status and timestamps
        new_status = incident.status
        contained_at = incident.contained_at
        resolved_at = incident.resolved_at

        if next_phase == IRPhase.ERADICATION:
            new_status = IncidentStatus.CONTAINED
            contained_at = now
        elif next_phase == IRPhase.RECOVERY:
            new_status = IncidentStatus.ERADICATED
        elif next_phase == IRPhase.LESSONS_LEARNED:
            new_status = IncidentStatus.RECOVERING
        elif next_phase == IRPhase.CLOSED:
            new_status = IncidentStatus.CLOSED
            resolved_at = now

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE ir_incidents
                       SET current_phase = ?,
                           status = ?,
                           phase_history = ?,
                           contained_at = ?,
                           resolved_at = ?,
                           updated_at = ?
                     WHERE id = ? AND org_id = ?
                    """,
                    (
                        next_phase.value,
                        new_status.value,
                        json.dumps([p.model_dump(mode="json") for p in phase_history]),
                        contained_at.isoformat() if contained_at else None,
                        resolved_at.isoformat() if resolved_at else None,
                        now.isoformat(),
                        incident_id,
                        org_id,
                    ),
                )

        # Add timeline event for phase transition
        self.add_timeline_event(
            incident_id=incident_id,
            event_type="phase_transition",
            source="ir_engine",
            description=f"Phase advanced: {incident.current_phase.value} → {next_phase.value}",
            metadata={"approved_by": approved_by, "notes": notes},
        )

        _logger.info(
            "IR phase advanced",
            incident_id=incident_id,
            from_phase=incident.current_phase.value,
            to_phase=next_phase.value,
        )
        _emit_event("ir.incident.phase_advanced", {
            "incident_id": incident_id,
            "from_phase": incident.current_phase.value,
            "to_phase": next_phase.value,
            "org_id": org_id,
        })

        updated = self.get_incident(incident_id, org_id=org_id)
        return updated  # type: ignore[return-value]

    # -----------------------------------------------------------------------
    # EVIDENCE CHAIN
    # -----------------------------------------------------------------------

    def add_evidence(
        self,
        incident_id: str,
        collector_id: str,
        evidence_type: str,
        description: str,
        raw_content: str,
        org_id: str = "default",
    ) -> EvidenceItem:
        """
        Add evidence to the incident with cryptographic chain-of-custody.
        Each piece of evidence is linked to the previous via chain hash.
        """
        # Verify incident exists
        if not self.get_incident(incident_id, org_id=org_id):
            raise ValueError(f"Incident '{incident_id}' not found")

        content_hash = _compute_evidence_hash(raw_content)
        now = datetime.now(timezone.utc)

        # Get previous evidence for chain linking
        with self._connect() as conn:
            prev_row = conn.execute(
                """
                SELECT sha256_hash, chain_sequence FROM ir_evidence
                 WHERE incident_id = ?
                 ORDER BY chain_sequence DESC LIMIT 1
                """,
                (incident_id,),
            ).fetchone()

        previous_hash = prev_row["sha256_hash"] if prev_row else ""
        chain_sequence = (prev_row["chain_sequence"] + 1) if prev_row else 0

        evidence = EvidenceItem(
            incident_id=incident_id,
            collector_id=collector_id,
            evidence_type=evidence_type,
            description=description,
            raw_content=raw_content,
            sha256_hash=content_hash,
            collected_at=now,
            previous_hash=previous_hash,
            chain_sequence=chain_sequence,
        )

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO ir_evidence
                        (id, incident_id, collector_id, evidence_type, description,
                         raw_content, sha256_hash, collected_at, previous_hash, chain_sequence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence.id, evidence.incident_id, evidence.collector_id,
                        evidence.evidence_type, evidence.description, evidence.raw_content,
                        evidence.sha256_hash, evidence.collected_at.isoformat(),
                        evidence.previous_hash, evidence.chain_sequence,
                    ),
                )

        # Add timeline event for evidence collection
        self.add_timeline_event(
            incident_id=incident_id,
            event_type="evidence",
            source=collector_id,
            description=f"Evidence collected: {evidence_type} — {description}",
            metadata={"evidence_id": evidence.id, "sha256": content_hash},
        )

        return evidence

    def get_evidence_chain(self, incident_id: str, org_id: str = "default") -> List[EvidenceItem]:
        """Return the full evidence chain for an incident, in collection order."""
        if not self.get_incident(incident_id, org_id=org_id):
            raise ValueError(f"Incident '{incident_id}' not found")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ir_evidence WHERE incident_id = ? ORDER BY chain_sequence ASC",
                (incident_id,),
            ).fetchall()
        return [self._row_to_evidence(r) for r in rows]

    def verify_evidence_chain(self, incident_id: str, org_id: str = "default") -> bool:
        """
        Verify cryptographic integrity of the evidence chain.
        Returns True if all chain links are valid.
        """
        chain = self.get_evidence_chain(incident_id, org_id=org_id)
        if not chain:
            return True
        expected_previous = ""
        for item in chain:
            if item.previous_hash != expected_previous:
                return False
            computed = _compute_evidence_hash(item.raw_content)
            if computed != item.sha256_hash:
                return False
            expected_previous = item.sha256_hash
        return True

    # -----------------------------------------------------------------------
    # TIMELINE
    # -----------------------------------------------------------------------

    def add_timeline_event(
        self,
        incident_id: str,
        event_type: str,
        source: str,
        description: str,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TimelineEvent:
        """Add an event to the incident timeline."""
        event = TimelineEvent(
            incident_id=incident_id,
            event_type=event_type,
            source=source,
            description=description,
            timestamp=timestamp or datetime.now(timezone.utc),
            metadata=metadata or {},
        )
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO ir_timeline
                        (id, incident_id, event_type, source, description, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.id, event.incident_id, event.event_type,
                        event.source, event.description,
                        event.timestamp.isoformat(), json.dumps(event.metadata),
                    ),
                )
        return event

    def get_timeline(self, incident_id: str, org_id: str = "default") -> List[TimelineEvent]:
        """Return incident timeline in chronological order."""
        if not self.get_incident(incident_id, org_id=org_id):
            raise ValueError(f"Incident '{incident_id}' not found")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ir_timeline WHERE incident_id = ? ORDER BY timestamp ASC",
                (incident_id,),
            ).fetchall()
        return [self._row_to_timeline_event(r) for r in rows]

    # -----------------------------------------------------------------------
    # REGULATORY NOTIFICATIONS
    # -----------------------------------------------------------------------

    def _create_regulatory_notifications(
        self,
        incident: IRIncident,
        playbook: IRPlaybook,
        detection_time: datetime,
    ) -> None:
        """Create regulatory notification records for applicable regulations."""
        context = incident.context
        for framework in playbook.applicable_regulations:
            deadline_hours = _NOTIFICATION_DEADLINES.get(framework)
            deadline_at: Optional[datetime] = None
            if deadline_hours is not None:
                deadline_at = detection_time + timedelta(hours=deadline_hours)

            template_str = _NOTIFICATION_TEMPLATES.get(framework, "")
            # Fill template with available context
            try:
                template_rendered = template_str.format(
                    incident_type=incident.incident_type.value,
                    detection_date=detection_time.isoformat(),
                    org_name=context.get("org_name", "[Org Name]"),
                    data_categories=context.get("data_categories", "[Data Categories]"),
                    affected_count=context.get("affected_count", "[Count]"),
                    consequences=context.get("consequences", "[Consequences]"),
                    measures=context.get("measures", "[Measures Taken]"),
                    dpo_contact=context.get("dpo_contact", "[DPO Contact]"),
                    phi_elements=context.get("phi_elements", "[PHI Elements]"),
                    safeguards=context.get("safeguards", "[Safeguards]"),
                    chd_scope=context.get("chd_scope", "[Cardholder Data Scope]"),
                    forensic_firm=context.get("forensic_firm", "[Forensic Firm]"),
                    current_phase=incident.current_phase.value,
                )
            except (KeyError, ValueError):
                template_rendered = template_str

            notification_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            is_overdue = deadline_at is not None and now > deadline_at

            with self._lock:
                with self._connect() as conn:
                    conn.execute(
                        """
                        INSERT INTO ir_notifications
                            (id, incident_id, framework, deadline_hours, detection_time,
                             deadline_at, notified_at, is_overdue, template, status)
                        VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                        """,
                        (
                            notification_id, incident.id, framework.value, deadline_hours,
                            detection_time.isoformat(),
                            deadline_at.isoformat() if deadline_at else None,
                            int(is_overdue), template_rendered,
                            "pending",
                        ),
                    )

    def get_notifications(
        self,
        org_id: str = "default",
        incident_id: Optional[str] = None,
    ) -> List[RegulatoryNotification]:
        """Return regulatory notifications, refreshing overdue status."""
        now = datetime.now(timezone.utc)
        query = """
            SELECT n.* FROM ir_notifications n
            JOIN ir_incidents i ON i.id = n.incident_id
            WHERE i.org_id = ?
        """
        params: List[Any] = [org_id]
        if incident_id:
            query += " AND n.incident_id = ?"
            params.append(incident_id)
        query += " ORDER BY n.deadline_at ASC NULLS LAST"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        notifications = [self._row_to_notification(r) for r in rows]

        # Refresh overdue status
        for n in notifications:
            if n.deadline_at and now > n.deadline_at and n.status == "pending":
                n.is_overdue = True
                n.status = "overdue"
                with self._lock:
                    with self._connect() as conn:
                        conn.execute(
                            "UPDATE ir_notifications SET is_overdue = 1, status = 'overdue' WHERE id = ?",
                            (n.id,),
                        )

        return notifications

    def mark_notification_sent(
        self, notification_id: str, org_id: str = "default"
    ) -> Optional[RegulatoryNotification]:
        """Mark a regulatory notification as sent."""
        now = datetime.now(timezone.utc)
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE ir_notifications
                       SET notified_at = ?, status = 'sent'
                     WHERE id = ? AND incident_id IN (
                         SELECT id FROM ir_incidents WHERE org_id = ?
                     )
                    """,
                    (now.isoformat(), notification_id, org_id),
                )

        # Return updated notification
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM ir_notifications WHERE id = ?", (notification_id,)
            ).fetchone()
        return self._row_to_notification(row) if row else None

    # -----------------------------------------------------------------------
    # METRICS
    # -----------------------------------------------------------------------

    def get_metrics(self, org_id: str = "default") -> IRMetrics:
        """
        Compute MTTD, MTTC, MTTR and aggregate incident metrics for an org.
        All times in hours.
        """
        with self._connect() as conn:
            # Counts
            count_row = conn.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN status != 'closed' THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) as closed
                FROM ir_incidents WHERE org_id = ?
                """,
                (org_id,),
            ).fetchone()

            # MTTD: created_at → detected_at (hours)
            mttd_row = conn.execute(
                """
                SELECT AVG(
                    (julianday(detected_at) - julianday(created_at)) * 24.0
                ) as mttd
                FROM ir_incidents
                WHERE org_id = ? AND detected_at IS NOT NULL
                """,
                (org_id,),
            ).fetchone()

            # MTTC: detected_at → contained_at (hours)
            mttc_row = conn.execute(
                """
                SELECT AVG(
                    (julianday(contained_at) - julianday(detected_at)) * 24.0
                ) as mttc
                FROM ir_incidents
                WHERE org_id = ? AND contained_at IS NOT NULL AND detected_at IS NOT NULL
                """,
                (org_id,),
            ).fetchone()

            # MTTR: detected_at → resolved_at (hours)
            mttr_row = conn.execute(
                """
                SELECT AVG(
                    (julianday(resolved_at) - julianday(detected_at)) * 24.0
                ) as mttr
                FROM ir_incidents
                WHERE org_id = ? AND resolved_at IS NOT NULL AND detected_at IS NOT NULL
                """,
                (org_id,),
            ).fetchone()

            # By type
            type_rows = conn.execute(
                "SELECT incident_type, COUNT(*) as cnt FROM ir_incidents WHERE org_id = ? GROUP BY incident_type",
                (org_id,),
            ).fetchall()

            # By severity
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM ir_incidents WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()

            # Playbook effectiveness (avg hours to resolve per playbook)
            pb_rows = conn.execute(
                """
                SELECT playbook_id,
                       AVG((julianday(resolved_at) - julianday(detected_at)) * 24.0) as avg_hours
                FROM ir_incidents
                WHERE org_id = ? AND resolved_at IS NOT NULL AND detected_at IS NOT NULL
                GROUP BY playbook_id
                """,
                (org_id,),
            ).fetchall()

        return IRMetrics(
            org_id=org_id,
            total_incidents=count_row["total"] or 0,
            active_incidents=count_row["active"] or 0,
            closed_incidents=count_row["closed"] or 0,
            mean_time_to_detect_hours=mttd_row["mttd"] or 0.0,
            mean_time_to_contain_hours=mttc_row["mttc"] or 0.0,
            mean_time_to_resolve_hours=mttr_row["mttr"] or 0.0,
            incidents_by_type={r["incident_type"]: r["cnt"] for r in type_rows},
            incidents_by_severity={r["severity"]: r["cnt"] for r in sev_rows},
            playbook_effectiveness={
                r["playbook_id"]: (r["avg_hours"] or 0.0) for r in pb_rows
            },
        )
