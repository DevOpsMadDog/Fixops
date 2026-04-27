"""
Threat Hunting Engine — ALDECI.

Proactive threat detection beyond automated scanning:
- Hunt Hypothesis Library (30+ MITRE ATT&CK-based hypotheses)
- IOC Management (IPs, domains, hashes, URLs, emails, registry keys)
- Sigma Rule Engine (parse/execute YAML detection rules)
- Hunt Workflows (hypothesis → data collection → analysis → findings → report)
- Threat Actor Profiles (aliases, motivation, TTPs, targeted industries)
- Kill Chain Visualization (7-phase Cyber Kill Chain coverage)
- Automated Hunt Triggers (CVE, IOC match, network pattern, compliance)

SQLite-backed, thread-safe.
Compliance: MITRE ATT&CK, Cyber Kill Chain, STIX 2.1
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises.

    Hub-level emit so this engine module participates in second-brain coverage.
    Downstream callers are AQUA via blast-radius (depth ≤ 2).
    """
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


# Module-load heartbeat — fires once per process so this file is observable
# in the TrustGraph second-brain, even if no public method is called yet.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "threat_hunter.db")


# ============================================================================
# ENUMS
# ============================================================================


class MitreTactic(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


class KillChainPhase(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class HuntStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    ANALYSIS = "analysis"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    URL = "url"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"


class ThreatActorMotivation(str, Enum):
    FINANCIAL = "financial"
    ESPIONAGE = "espionage"
    HACKTIVISM = "hacktivism"
    SABOTAGE = "sabotage"
    UNKNOWN = "unknown"


class HuntTriggerType(str, Enum):
    NEW_CVE = "new_cve"
    IOC_MATCH = "ioc_match"
    NETWORK_ANOMALY = "network_anomaly"
    COMPLIANCE_FAILURE = "compliance_failure"
    MANUAL = "manual"


class HuntSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class HuntHypothesis(BaseModel):
    """A pre-built or custom hunt hypothesis."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    mitre_tactic: MitreTactic
    mitre_technique_id: str  # e.g. T1566
    mitre_technique_name: str
    kill_chain_phase: KillChainPhase
    severity: HuntSeverity
    data_sources: List[str] = Field(default_factory=list)
    search_query: str = ""
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IOC(BaseModel):
    """An Indicator of Compromise."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: IOCType
    value: str
    description: str = ""
    confidence: int = Field(default=50, ge=0, le=100)
    severity: HuntSeverity = HuntSeverity.MEDIUM
    source: str = "manual"
    tags: List[str] = Field(default_factory=list)
    stix_id: Optional[str] = None
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    active: bool = True


class SigmaRule(BaseModel):
    """A Sigma detection rule."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    author: str = ""
    status: str = "experimental"
    logsource_category: str = ""
    logsource_product: str = ""
    detection_keywords: List[str] = Field(default_factory=list)
    detection_condition: str = ""
    false_positives: List[str] = Field(default_factory=list)
    level: HuntSeverity = HuntSeverity.MEDIUM
    tags: List[str] = Field(default_factory=list)
    raw_yaml: str = ""
    search_query: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    enabled: bool = True


class HuntFinding(BaseModel):
    """A finding discovered during a hunt."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hunt_id: str
    title: str
    description: str = ""
    severity: HuntSeverity
    mitre_technique_id: str = ""
    evidence: List[str] = Field(default_factory=list)
    ioc_matches: List[str] = Field(default_factory=list)
    kill_chain_phase: Optional[KillChainPhase] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HuntWorkflow(BaseModel):
    """A structured threat hunt workflow."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hypothesis_id: str
    hypothesis_name: str
    org_id: str
    status: HuntStatus = HuntStatus.PENDING
    trigger_type: HuntTriggerType = HuntTriggerType.MANUAL
    trigger_context: Dict[str, Any] = Field(default_factory=dict)
    analyst: str = "system"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    data_sources_queried: List[str] = Field(default_factory=list)
    notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatActorProfile(BaseModel):
    """A known threat actor profile."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    aliases: List[str] = Field(default_factory=list)
    motivation: ThreatActorMotivation = ThreatActorMotivation.UNKNOWN
    description: str = ""
    targeted_industries: List[str] = Field(default_factory=list)
    targeted_regions: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    associated_ioc_ids: List[str] = Field(default_factory=list)
    first_observed: Optional[datetime] = None
    last_active: Optional[datetime] = None
    sophistication: str = "unknown"  # low, medium, high, nation-state
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class KillChainCoverage(BaseModel):
    """Kill chain phase coverage summary."""

    phase: KillChainPhase
    hypothesis_count: int
    sigma_rule_count: int
    active_hunt_count: int
    covered: bool


class HuntTrigger(BaseModel):
    """An automated trigger that initiates a hunt."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    trigger_type: HuntTriggerType
    context: Dict[str, Any] = Field(default_factory=dict)
    hypothesis_id: Optional[str] = None
    hunt_id: Optional[str] = None
    fired_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# BUILT-IN HUNT HYPOTHESES (30+ MITRE ATT&CK based)
# ============================================================================

_BUILTIN_HYPOTHESES: List[Dict[str, Any]] = [
    # --- Initial Access ---
    {
        "name": "Phishing Email with Malicious Attachment",
        "description": "Hunt for phishing emails delivering malicious attachments via T1566.001",
        "mitre_tactic": MitreTactic.INITIAL_ACCESS,
        "mitre_technique_id": "T1566.001",
        "mitre_technique_name": "Spearphishing Attachment",
        "kill_chain_phase": KillChainPhase.DELIVERY,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["email_logs", "endpoint_telemetry"],
        "search_query": "email.attachment.type:(exe OR vbs OR js OR docm OR xlsm) AND email.spam_score:>0.7",
        "tags": ["phishing", "initial-access", "T1566"],
    },
    {
        "name": "Exploit Public-Facing Application",
        "description": "Hunt for exploitation attempts against public-facing applications (T1190)",
        "mitre_tactic": MitreTactic.INITIAL_ACCESS,
        "mitre_technique_id": "T1190",
        "mitre_technique_name": "Exploit Public-Facing Application",
        "kill_chain_phase": KillChainPhase.EXPLOITATION,
        "severity": HuntSeverity.CRITICAL,
        "data_sources": ["web_logs", "waf_logs", "ids_logs"],
        "search_query": "http.status:500 AND (http.uri:*../..* OR http.uri:*union+select* OR http.uri:*<script>*)",
        "tags": ["exploitation", "initial-access", "T1190"],
    },
    {
        "name": "Phishing Link in Email Body",
        "description": "Hunt for phishing emails with malicious links (T1566.002)",
        "mitre_tactic": MitreTactic.INITIAL_ACCESS,
        "mitre_technique_id": "T1566.002",
        "mitre_technique_name": "Spearphishing Link",
        "kill_chain_phase": KillChainPhase.DELIVERY,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["email_logs", "proxy_logs"],
        "search_query": "email.link.domain NOT IN known_domains AND email.link.tld:(xyz OR tk OR ml OR ga)",
        "tags": ["phishing", "initial-access", "T1566"],
    },
    # --- Execution ---
    {
        "name": "Suspicious Command and Scripting Interpreter",
        "description": "Hunt for abuse of scripting interpreters (PowerShell, cmd, bash) T1059",
        "mitre_tactic": MitreTactic.EXECUTION,
        "mitre_technique_id": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "kill_chain_phase": KillChainPhase.INSTALLATION,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["endpoint_telemetry", "process_logs"],
        "search_query": "process.name:(powershell.exe OR cmd.exe OR wscript.exe) AND process.args:(*-EncodedCommand* OR *-enc* OR *DownloadString* OR *IEX*)",
        "tags": ["execution", "scripting", "T1059"],
    },
    {
        "name": "Scheduled Task Creation for Persistence",
        "description": "Hunt for scheduled task creation as execution mechanism (T1053)",
        "mitre_tactic": MitreTactic.EXECUTION,
        "mitre_technique_id": "T1053",
        "mitre_technique_name": "Scheduled Task/Job",
        "kill_chain_phase": KillChainPhase.INSTALLATION,
        "severity": HuntSeverity.MEDIUM,
        "data_sources": ["endpoint_telemetry", "windows_event_logs"],
        "search_query": "event.id:4698 OR (process.name:schtasks.exe AND process.args:*/create*)",
        "tags": ["execution", "scheduled-task", "T1053"],
    },
    {
        "name": "WMI Event Subscription Abuse",
        "description": "Hunt for WMI event subscriptions used for execution (T1047)",
        "mitre_tactic": MitreTactic.EXECUTION,
        "mitre_technique_id": "T1047",
        "mitre_technique_name": "Windows Management Instrumentation",
        "kill_chain_phase": KillChainPhase.INSTALLATION,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["endpoint_telemetry", "wmi_logs"],
        "search_query": "process.name:wmic.exe AND process.args:(*process+call+create* OR *os+get*)",
        "tags": ["execution", "wmi", "T1047"],
    },
    # --- Persistence ---
    {
        "name": "Valid Account Abuse for Persistence",
        "description": "Hunt for legitimate account usage outside normal patterns (T1078)",
        "mitre_tactic": MitreTactic.PERSISTENCE,
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["auth_logs", "vpn_logs"],
        "search_query": "auth.success:true AND (auth.time:OUTSIDE_BUSINESS_HOURS OR auth.geo_distance:>500km)",
        "tags": ["persistence", "valid-accounts", "T1078"],
    },
    {
        "name": "New Account Creation",
        "description": "Hunt for unauthorized account creation events (T1136)",
        "mitre_tactic": MitreTactic.PERSISTENCE,
        "mitre_technique_id": "T1136",
        "mitre_technique_name": "Create Account",
        "kill_chain_phase": KillChainPhase.INSTALLATION,
        "severity": HuntSeverity.MEDIUM,
        "data_sources": ["auth_logs", "windows_event_logs"],
        "search_query": "event.id:(4720 OR 4722 OR 4723 OR 4724) AND NOT actor.name:known_admins",
        "tags": ["persistence", "account-creation", "T1136"],
    },
    {
        "name": "Registry Run Keys Persistence",
        "description": "Hunt for registry run key modifications for persistence (T1547.001)",
        "mitre_tactic": MitreTactic.PERSISTENCE,
        "mitre_technique_id": "T1547.001",
        "mitre_technique_name": "Registry Run Keys / Startup Folder",
        "kill_chain_phase": KillChainPhase.INSTALLATION,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["endpoint_telemetry", "registry_logs"],
        "search_query": "registry.path:(HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run OR HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) AND registry.action:write",
        "tags": ["persistence", "registry", "T1547"],
    },
    {
        "name": "Boot or Logon Autostart via Services",
        "description": "Hunt for new or modified Windows services for persistence (T1543.003)",
        "mitre_tactic": MitreTactic.PERSISTENCE,
        "mitre_technique_id": "T1543.003",
        "mitre_technique_name": "Windows Service",
        "kill_chain_phase": KillChainPhase.INSTALLATION,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["windows_event_logs", "endpoint_telemetry"],
        "search_query": "event.id:(7045 OR 4697) AND service.path NOT IN known_service_paths",
        "tags": ["persistence", "services", "T1543"],
    },
    # --- Privilege Escalation ---
    {
        "name": "Exploitation for Privilege Escalation",
        "description": "Hunt for local privilege escalation exploit attempts (T1068)",
        "mitre_tactic": MitreTactic.PRIVILEGE_ESCALATION,
        "mitre_technique_id": "T1068",
        "mitre_technique_name": "Exploitation for Privilege Escalation",
        "kill_chain_phase": KillChainPhase.EXPLOITATION,
        "severity": HuntSeverity.CRITICAL,
        "data_sources": ["endpoint_telemetry", "ids_logs"],
        "search_query": "process.integrity_level:high AND process.parent.integrity_level:medium AND process.name NOT IN known_elevated",
        "tags": ["privilege-escalation", "exploit", "T1068"],
    },
    {
        "name": "Abuse Elevation Control Mechanism",
        "description": "Hunt for UAC bypass and sudo abuse (T1548)",
        "mitre_tactic": MitreTactic.PRIVILEGE_ESCALATION,
        "mitre_technique_id": "T1548",
        "mitre_technique_name": "Abuse Elevation Control Mechanism",
        "kill_chain_phase": KillChainPhase.EXPLOITATION,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["endpoint_telemetry", "windows_event_logs"],
        "search_query": "event.id:4688 AND process.integrity_level:high AND process.parent.name:(fodhelper.exe OR eventvwr.exe OR sdclt.exe)",
        "tags": ["privilege-escalation", "uac-bypass", "T1548"],
    },
    {
        "name": "Token Impersonation / Theft",
        "description": "Hunt for access token manipulation for privilege escalation (T1134)",
        "mitre_tactic": MitreTactic.PRIVILEGE_ESCALATION,
        "mitre_technique_id": "T1134",
        "mitre_technique_name": "Access Token Manipulation",
        "kill_chain_phase": KillChainPhase.EXPLOITATION,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["endpoint_telemetry", "windows_event_logs"],
        "search_query": "api.call:(SeImpersonatePrivilege OR SeAssignPrimaryTokenPrivilege) AND process.name NOT IN system_processes",
        "tags": ["privilege-escalation", "token", "T1134"],
    },
    # --- Defense Evasion ---
    {
        "name": "Indicator Removal on Host",
        "description": "Hunt for log clearing and artifact deletion (T1070)",
        "mitre_tactic": MitreTactic.DEFENSE_EVASION,
        "mitre_technique_id": "T1070",
        "mitre_technique_name": "Indicator Removal on Host",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["windows_event_logs", "endpoint_telemetry"],
        "search_query": "event.id:(1102 OR 104) OR (process.name:wevtutil.exe AND process.args:*cl*)",
        "tags": ["defense-evasion", "log-clearing", "T1070"],
    },
    {
        "name": "Masquerading as Legitimate Process",
        "description": "Hunt for processes impersonating legitimate system binaries (T1036)",
        "mitre_tactic": MitreTactic.DEFENSE_EVASION,
        "mitre_technique_id": "T1036",
        "mitre_technique_name": "Masquerading",
        "kill_chain_phase": KillChainPhase.INSTALLATION,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["endpoint_telemetry"],
        "search_query": "process.name:(svchost.exe OR lsass.exe OR csrss.exe) AND process.path NOT IN (C:\\Windows\\System32\\* OR C:\\Windows\\SysWOW64\\*)",
        "tags": ["defense-evasion", "masquerading", "T1036"],
    },
    {
        "name": "Obfuscated Files or Information",
        "description": "Hunt for encoded/obfuscated payloads in commands (T1027)",
        "mitre_tactic": MitreTactic.DEFENSE_EVASION,
        "mitre_technique_id": "T1027",
        "mitre_technique_name": "Obfuscated Files or Information",
        "kill_chain_phase": KillChainPhase.DELIVERY,
        "severity": HuntSeverity.MEDIUM,
        "data_sources": ["endpoint_telemetry", "process_logs"],
        "search_query": "process.args:(*base64* OR *[System.Convert]::FromBase64* OR *FromBase64String*) AND process.name:(powershell.exe OR cmd.exe)",
        "tags": ["defense-evasion", "obfuscation", "T1027"],
    },
    {
        "name": "Disable or Modify Security Tools",
        "description": "Hunt for attempts to disable AV/EDR (T1562)",
        "mitre_tactic": MitreTactic.DEFENSE_EVASION,
        "mitre_technique_id": "T1562",
        "mitre_technique_name": "Impair Defenses",
        "kill_chain_phase": KillChainPhase.INSTALLATION,
        "severity": HuntSeverity.CRITICAL,
        "data_sources": ["endpoint_telemetry", "windows_event_logs"],
        "search_query": "process.args:(*DisableRealtimeMonitoring* OR *Set-MpPreference* OR *sc+stop+windefend*)",
        "tags": ["defense-evasion", "disable-security", "T1562"],
    },
    # --- Credential Access ---
    {
        "name": "OS Credential Dumping via LSASS",
        "description": "Hunt for LSASS memory access for credential extraction (T1003.001)",
        "mitre_tactic": MitreTactic.CREDENTIAL_ACCESS,
        "mitre_technique_id": "T1003.001",
        "mitre_technique_name": "LSASS Memory",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.CRITICAL,
        "data_sources": ["endpoint_telemetry", "windows_event_logs"],
        "search_query": "process.target:lsass.exe AND process.access_rights:(0x1F1FFF OR 0x1010) AND process.name NOT IN (antivirus, edr_processes)",
        "tags": ["credential-access", "lsass", "T1003"],
    },
    {
        "name": "Credential Dumping via Registry SAM",
        "description": "Hunt for SAM/SYSTEM/SECURITY hive dumping (T1003.002)",
        "mitre_tactic": MitreTactic.CREDENTIAL_ACCESS,
        "mitre_technique_id": "T1003.002",
        "mitre_technique_name": "Security Account Manager",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.CRITICAL,
        "data_sources": ["registry_logs", "endpoint_telemetry"],
        "search_query": "process.args:(*reg+save* OR *reg+export*) AND (registry.path:*SAM* OR registry.path:*SYSTEM* OR registry.path:*SECURITY*)",
        "tags": ["credential-access", "sam-dump", "T1003"],
    },
    {
        "name": "Kerberoasting Attack",
        "description": "Hunt for service ticket requests indicating Kerberoasting (T1558.003)",
        "mitre_tactic": MitreTactic.CREDENTIAL_ACCESS,
        "mitre_technique_id": "T1558.003",
        "mitre_technique_name": "Kerberoasting",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["windows_event_logs", "kerberos_logs"],
        "search_query": "event.id:4769 AND ticket.encryption_type:0x17 AND ticket.count:>10 AND timespan:5m",
        "tags": ["credential-access", "kerberoasting", "T1558"],
    },
    {
        "name": "Password Spraying Attack",
        "description": "Hunt for horizontal brute force across many accounts (T1110.003)",
        "mitre_tactic": MitreTactic.CREDENTIAL_ACCESS,
        "mitre_technique_id": "T1110.003",
        "mitre_technique_name": "Password Spraying",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["auth_logs", "windows_event_logs"],
        "search_query": "event.id:4625 AND auth.failure_count:>10 AND auth.unique_accounts:>5 AND timespan:10m",
        "tags": ["credential-access", "password-spraying", "T1110"],
    },
    # --- Lateral Movement ---
    {
        "name": "Remote Services — SMB/Windows Admin Shares",
        "description": "Hunt for lateral movement via SMB admin shares (T1021.002)",
        "mitre_tactic": MitreTactic.LATERAL_MOVEMENT,
        "mitre_technique_id": "T1021.002",
        "mitre_technique_name": "SMB/Windows Admin Shares",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["network_logs", "windows_event_logs"],
        "search_query": "event.id:5140 AND share.name:(ADMIN$ OR C$ OR IPC$) AND NOT source.ip IN known_admin_hosts",
        "tags": ["lateral-movement", "smb", "T1021"],
    },
    {
        "name": "Remote Desktop Protocol Lateral Movement",
        "description": "Hunt for unusual RDP connections indicating lateral movement (T1021.001)",
        "mitre_tactic": MitreTactic.LATERAL_MOVEMENT,
        "mitre_technique_id": "T1021.001",
        "mitre_technique_name": "Remote Desktop Protocol",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["network_logs", "windows_event_logs"],
        "search_query": "event.id:(4624 OR 4625) AND logon.type:10 AND NOT source.ip IN known_rdp_sources",
        "tags": ["lateral-movement", "rdp", "T1021"],
    },
    {
        "name": "Pass-the-Hash Attack",
        "description": "Hunt for NTLM hash reuse for lateral movement (T1550.002)",
        "mitre_tactic": MitreTactic.LATERAL_MOVEMENT,
        "mitre_technique_id": "T1550.002",
        "mitre_technique_name": "Pass the Hash",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.CRITICAL,
        "data_sources": ["windows_event_logs", "network_logs"],
        "search_query": "event.id:4624 AND logon.type:3 AND logon.auth_package:NTLM AND account.name NOT IN machine_accounts",
        "tags": ["lateral-movement", "pass-the-hash", "T1550"],
    },
    # --- Exfiltration ---
    {
        "name": "Exfiltration Over Alternative Protocol",
        "description": "Hunt for data exfiltration via DNS, ICMP, or non-standard ports (T1048)",
        "mitre_tactic": MitreTactic.EXFILTRATION,
        "mitre_technique_id": "T1048",
        "mitre_technique_name": "Exfiltration Over Alternative Protocol",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.CRITICAL,
        "data_sources": ["network_logs", "dns_logs"],
        "search_query": "dns.query.length:>100 OR (icmp.data_size:>100 AND icmp.direction:outbound) OR network.bytes_out:>100MB AND NOT dest.port IN (80, 443, 22)",
        "tags": ["exfiltration", "alt-protocol", "T1048"],
    },
    {
        "name": "Data Staged for Exfiltration",
        "description": "Hunt for large data staging before exfiltration (T1074)",
        "mitre_tactic": MitreTactic.COLLECTION,
        "mitre_technique_id": "T1074",
        "mitre_technique_name": "Data Staged",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["endpoint_telemetry", "file_logs"],
        "search_query": "file.operation:create AND file.size:>500MB AND file.path:(*/temp/* OR */tmp/* OR */appdata/*) AND file.extension:(zip OR rar OR 7z OR tar.gz)",
        "tags": ["collection", "staging", "T1074"],
    },
    {
        "name": "Web Service Exfiltration",
        "description": "Hunt for data exfiltration via legitimate web services (T1567)",
        "mitre_tactic": MitreTactic.EXFILTRATION,
        "mitre_technique_id": "T1567",
        "mitre_technique_name": "Exfiltration Over Web Service",
        "kill_chain_phase": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["proxy_logs", "network_logs"],
        "search_query": "http.upload_bytes:>50MB AND http.dest:(pastebin.com OR dropbox.com OR mega.nz OR transfer.sh OR anonfiles.com)",
        "tags": ["exfiltration", "web-service", "T1567"],
    },
    # --- Command and Control ---
    {
        "name": "Beaconing to C2 Infrastructure",
        "description": "Hunt for regular periodic outbound connections indicating C2 beaconing (T1071)",
        "mitre_tactic": MitreTactic.COMMAND_AND_CONTROL,
        "mitre_technique_id": "T1071",
        "mitre_technique_name": "Application Layer Protocol",
        "kill_chain_phase": KillChainPhase.COMMAND_AND_CONTROL,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["network_logs", "proxy_logs"],
        "search_query": "network.connection.regularity:>0.9 AND network.connection.interval:BETWEEN(30s,300s) AND NOT dest.ip IN known_cloud_services",
        "tags": ["c2", "beaconing", "T1071"],
    },
    {
        "name": "DNS Tunneling for C2",
        "description": "Hunt for DNS tunneling used as covert C2 channel (T1071.004)",
        "mitre_tactic": MitreTactic.COMMAND_AND_CONTROL,
        "mitre_technique_id": "T1071.004",
        "mitre_technique_name": "DNS",
        "kill_chain_phase": KillChainPhase.COMMAND_AND_CONTROL,
        "severity": HuntSeverity.HIGH,
        "data_sources": ["dns_logs", "network_logs"],
        "search_query": "dns.query.length:>60 AND dns.query.entropy:>3.5 AND dns.query.type:(TXT OR NULL OR CNAME)",
        "tags": ["c2", "dns-tunneling", "T1071"],
    },
    {
        "name": "Proxy Use for C2 Communication",
        "description": "Hunt for use of multi-hop proxies to hide C2 (T1090)",
        "mitre_tactic": MitreTactic.COMMAND_AND_CONTROL,
        "mitre_technique_id": "T1090",
        "mitre_technique_name": "Proxy",
        "kill_chain_phase": KillChainPhase.COMMAND_AND_CONTROL,
        "severity": HuntSeverity.MEDIUM,
        "data_sources": ["network_logs", "proxy_logs"],
        "search_query": "network.proxy_chain_length:>2 OR (http.via_header:* AND http.x_forwarded_for.count:>3)",
        "tags": ["c2", "proxy", "T1090"],
    },
    # --- Discovery ---
    {
        "name": "Network Reconnaissance and Scanning",
        "description": "Hunt for internal network scanning indicating discovery phase (T1046)",
        "mitre_tactic": MitreTactic.DISCOVERY,
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "kill_chain_phase": KillChainPhase.RECONNAISSANCE,
        "severity": HuntSeverity.MEDIUM,
        "data_sources": ["network_logs", "ids_logs"],
        "search_query": "network.unique_dest_ports:>50 AND timespan:5m AND NOT source.ip IN known_scanners",
        "tags": ["discovery", "scanning", "T1046"],
    },
    {
        "name": "Domain Enumeration via LDAP",
        "description": "Hunt for excessive LDAP queries indicating AD reconnaissance (T1018)",
        "mitre_tactic": MitreTactic.DISCOVERY,
        "mitre_technique_id": "T1018",
        "mitre_technique_name": "Remote System Discovery",
        "kill_chain_phase": KillChainPhase.RECONNAISSANCE,
        "severity": HuntSeverity.MEDIUM,
        "data_sources": ["network_logs", "windows_event_logs"],
        "search_query": "network.dest.port:389 AND network.query.count:>100 AND timespan:60s AND NOT source.ip IN domain_controllers",
        "tags": ["discovery", "ldap", "T1018"],
    },
]


# ============================================================================
# BUILT-IN THREAT ACTOR PROFILES
# ============================================================================

_BUILTIN_ACTORS: List[Dict[str, Any]] = [
    {
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "STRONTIUM"],
        "motivation": ThreatActorMotivation.ESPIONAGE,
        "description": "Russian state-sponsored group attributed to GRU, known for targeting government, military, and political entities.",
        "targeted_industries": ["government", "defense", "energy", "media"],
        "targeted_regions": ["NATO countries", "Eastern Europe", "United States"],
        "mitre_techniques": ["T1566", "T1059", "T1078", "T1003", "T1048", "T1071"],
        "sophistication": "nation-state",
        "tags": ["russia", "apt", "espionage"],
    },
    {
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM", "Midnight Blizzard"],
        "motivation": ThreatActorMotivation.ESPIONAGE,
        "description": "Russian SVR-attributed group known for SolarWinds supply chain attack and targeting diplomatic entities.",
        "targeted_industries": ["government", "think-tanks", "healthcare", "energy"],
        "targeted_regions": ["United States", "Europe", "NATO allies"],
        "mitre_techniques": ["T1195", "T1078", "T1021", "T1027", "T1070", "T1566"],
        "sophistication": "nation-state",
        "tags": ["russia", "apt", "supply-chain"],
    },
    {
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "ZINC", "Guardians of Peace"],
        "motivation": ThreatActorMotivation.FINANCIAL,
        "description": "North Korean state-sponsored group primarily motivated by financial gain through cryptocurrency theft and ransomware.",
        "targeted_industries": ["financial", "cryptocurrency", "defense", "media"],
        "targeted_regions": ["Global", "South Korea", "United States", "Europe"],
        "mitre_techniques": ["T1566", "T1059", "T1190", "T1003", "T1048", "T1486"],
        "sophistication": "nation-state",
        "tags": ["north-korea", "apt", "financial"],
    },
    {
        "name": "FIN7",
        "aliases": ["Carbanak", "Navigator Group", "ITG14"],
        "motivation": ThreatActorMotivation.FINANCIAL,
        "description": "Financially motivated criminal group targeting retail, hospitality, and restaurant sectors for payment card data.",
        "targeted_industries": ["retail", "hospitality", "restaurant", "financial"],
        "targeted_regions": ["United States", "Europe", "Australia"],
        "mitre_techniques": ["T1566", "T1059", "T1078", "T1053", "T1003", "T1048"],
        "sophistication": "high",
        "tags": ["criminal", "fin7", "pos-attacks"],
    },
    {
        "name": "Volt Typhoon",
        "aliases": ["BRONZE SILHOUETTE", "Vanguard Panda"],
        "motivation": ThreatActorMotivation.ESPIONAGE,
        "description": "Chinese state-sponsored group targeting critical infrastructure using living-off-the-land techniques.",
        "targeted_industries": ["critical-infrastructure", "utilities", "communications", "government"],
        "targeted_regions": ["United States", "Guam", "Pacific region"],
        "mitre_techniques": ["T1190", "T1078", "T1036", "T1070", "T1021", "T1083"],
        "sophistication": "nation-state",
        "tags": ["china", "apt", "critical-infrastructure", "lolbas"],
    },
]


# ============================================================================
# SIGMA RULE PARSER
# ============================================================================


def parse_sigma_rule(yaml_content: str) -> SigmaRule:
    """
    Parse a Sigma YAML rule into a SigmaRule model.

    Extracts title, description, author, logsource, detection, and level.
    Converts detection conditions into a simplified search query string.
    """
    try:
        data = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid Sigma YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Sigma rule must be a YAML mapping")

    title = data.get("title", "Unnamed Rule")
    description = data.get("description", "")
    author = data.get("author", "")
    status = data.get("status", "experimental")
    level_raw = data.get("level", "medium")
    false_positives = data.get("falsepositives", [])
    tags = data.get("tags", [])

    logsource = data.get("logsource", {})
    category = logsource.get("category", "")
    product = logsource.get("product", "")

    detection = data.get("detection", {})
    keywords: List[str] = []
    condition = detection.get("condition", "")

    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    keywords.append(item)
        elif isinstance(val, dict):
            for field_val in val.values():
                if isinstance(field_val, list):
                    keywords.extend(str(v) for v in field_val)
                elif isinstance(field_val, str):
                    keywords.append(field_val)
        elif isinstance(val, str):
            keywords.append(val)

    # Build simplified search query from detection keywords
    search_query = " AND ".join(f'"{kw}"' for kw in keywords[:10]) if keywords else condition

    severity_map = {
        "informational": HuntSeverity.LOW,
        "low": HuntSeverity.LOW,
        "medium": HuntSeverity.MEDIUM,
        "high": HuntSeverity.HIGH,
        "critical": HuntSeverity.CRITICAL,
    }
    severity = severity_map.get(level_raw.lower(), HuntSeverity.MEDIUM)

    return SigmaRule(
        name=title,
        description=description,
        author=author,
        status=status,
        logsource_category=category,
        logsource_product=product,
        detection_keywords=keywords,
        detection_condition=condition,
        false_positives=false_positives if isinstance(false_positives, list) else [str(false_positives)],
        level=severity,
        tags=tags,
        raw_yaml=yaml_content,
        search_query=search_query,
    )


# ============================================================================
# THREAT HUNTING ENGINE
# ============================================================================


class ThreatHunter:
    """
    SQLite-backed threat hunting engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to data/threat_hunter.db.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()
        self._seed_builtin_data()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create SQLite schema if it doesn't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id                   TEXT PRIMARY KEY,
                    name                 TEXT NOT NULL,
                    description          TEXT NOT NULL,
                    mitre_tactic         TEXT NOT NULL,
                    mitre_technique_id   TEXT NOT NULL,
                    mitre_technique_name TEXT NOT NULL,
                    kill_chain_phase     TEXT NOT NULL,
                    severity             TEXT NOT NULL,
                    data_sources         TEXT NOT NULL DEFAULT '[]',
                    search_query         TEXT NOT NULL DEFAULT '',
                    tags                 TEXT NOT NULL DEFAULT '[]',
                    created_at           DATETIME NOT NULL,
                    builtin              INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS iocs (
                    id          TEXT PRIMARY KEY,
                    type        TEXT NOT NULL,
                    value       TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    confidence  INTEGER NOT NULL DEFAULT 50,
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    source      TEXT NOT NULL DEFAULT 'manual',
                    tags        TEXT NOT NULL DEFAULT '[]',
                    stix_id     TEXT,
                    first_seen  DATETIME NOT NULL,
                    last_seen   DATETIME NOT NULL,
                    active      INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON iocs (type, value);
                CREATE INDEX IF NOT EXISTS idx_ioc_active ON iocs (active);

                CREATE TABLE IF NOT EXISTS sigma_rules (
                    id                   TEXT PRIMARY KEY,
                    name                 TEXT NOT NULL,
                    description          TEXT NOT NULL DEFAULT '',
                    author               TEXT NOT NULL DEFAULT '',
                    status               TEXT NOT NULL DEFAULT 'experimental',
                    logsource_category   TEXT NOT NULL DEFAULT '',
                    logsource_product    TEXT NOT NULL DEFAULT '',
                    detection_keywords   TEXT NOT NULL DEFAULT '[]',
                    detection_condition  TEXT NOT NULL DEFAULT '',
                    false_positives      TEXT NOT NULL DEFAULT '[]',
                    level                TEXT NOT NULL DEFAULT 'medium',
                    tags                 TEXT NOT NULL DEFAULT '[]',
                    raw_yaml             TEXT NOT NULL DEFAULT '',
                    search_query         TEXT NOT NULL DEFAULT '',
                    created_at           DATETIME NOT NULL,
                    enabled              INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS hunt_workflows (
                    id                      TEXT PRIMARY KEY,
                    hypothesis_id           TEXT NOT NULL,
                    hypothesis_name         TEXT NOT NULL,
                    org_id                  TEXT NOT NULL DEFAULT 'default',
                    status                  TEXT NOT NULL DEFAULT 'pending',
                    trigger_type            TEXT NOT NULL DEFAULT 'manual',
                    trigger_context         TEXT NOT NULL DEFAULT '{}',
                    analyst                 TEXT NOT NULL DEFAULT 'system',
                    started_at              DATETIME,
                    completed_at            DATETIME,
                    findings_count          INTEGER NOT NULL DEFAULT 0,
                    data_sources_queried    TEXT NOT NULL DEFAULT '[]',
                    notes                   TEXT NOT NULL DEFAULT '',
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_hunt_status ON hunt_workflows (status);
                CREATE INDEX IF NOT EXISTS idx_hunt_org ON hunt_workflows (org_id);

                CREATE TABLE IF NOT EXISTS hunt_findings (
                    id                   TEXT PRIMARY KEY,
                    hunt_id              TEXT NOT NULL,
                    title                TEXT NOT NULL,
                    description          TEXT NOT NULL DEFAULT '',
                    severity             TEXT NOT NULL DEFAULT 'medium',
                    mitre_technique_id   TEXT NOT NULL DEFAULT '',
                    evidence             TEXT NOT NULL DEFAULT '[]',
                    ioc_matches          TEXT NOT NULL DEFAULT '[]',
                    kill_chain_phase     TEXT,
                    created_at           DATETIME NOT NULL,
                    FOREIGN KEY (hunt_id) REFERENCES hunt_workflows(id)
                );

                CREATE TABLE IF NOT EXISTS threat_actors (
                    id                   TEXT PRIMARY KEY,
                    name                 TEXT NOT NULL,
                    aliases              TEXT NOT NULL DEFAULT '[]',
                    motivation           TEXT NOT NULL DEFAULT 'unknown',
                    description          TEXT NOT NULL DEFAULT '',
                    targeted_industries  TEXT NOT NULL DEFAULT '[]',
                    targeted_regions     TEXT NOT NULL DEFAULT '[]',
                    mitre_techniques     TEXT NOT NULL DEFAULT '[]',
                    associated_ioc_ids   TEXT NOT NULL DEFAULT '[]',
                    first_observed       DATETIME,
                    last_active          DATETIME,
                    sophistication       TEXT NOT NULL DEFAULT 'unknown',
                    tags                 TEXT NOT NULL DEFAULT '[]',
                    created_at           DATETIME NOT NULL,
                    builtin              INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS hunt_triggers (
                    id              TEXT PRIMARY KEY,
                    trigger_type    TEXT NOT NULL,
                    context         TEXT NOT NULL DEFAULT '{}',
                    hypothesis_id   TEXT,
                    hunt_id         TEXT,
                    fired_at        DATETIME NOT NULL
                );
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Seed built-in data (idempotent)
    # ------------------------------------------------------------------

    def _seed_builtin_data(self) -> None:
        """Insert built-in hypotheses and threat actors if not already present."""
        with self._lock:
            with self._get_conn() as conn:
                existing_count = conn.execute(
                    "SELECT COUNT(*) FROM hypotheses WHERE builtin=1"
                ).fetchone()[0]
                if existing_count == 0:
                    now = datetime.now(timezone.utc).isoformat()
                    for hyp in _BUILTIN_HYPOTHESES:
                        conn.execute(
                            """INSERT OR IGNORE INTO hypotheses
                               (id, name, description, mitre_tactic, mitre_technique_id,
                                mitre_technique_name, kill_chain_phase, severity,
                                data_sources, search_query, tags, created_at, builtin)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                            (
                                str(uuid.uuid4()),
                                hyp["name"],
                                hyp["description"],
                                hyp["mitre_tactic"].value,
                                hyp["mitre_technique_id"],
                                hyp["mitre_technique_name"],
                                hyp["kill_chain_phase"].value,
                                hyp["severity"].value,
                                json.dumps(hyp.get("data_sources", [])),
                                hyp.get("search_query", ""),
                                json.dumps(hyp.get("tags", [])),
                                now,
                            ),
                        )

                actor_count = conn.execute(
                    "SELECT COUNT(*) FROM threat_actors WHERE builtin=1"
                ).fetchone()[0]
                if actor_count == 0:
                    now = datetime.now(timezone.utc).isoformat()
                    for actor in _BUILTIN_ACTORS:
                        conn.execute(
                            """INSERT OR IGNORE INTO threat_actors
                               (id, name, aliases, motivation, description,
                                targeted_industries, targeted_regions, mitre_techniques,
                                associated_ioc_ids, first_observed, last_active,
                                sophistication, tags, created_at, builtin)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                            (
                                str(uuid.uuid4()),
                                actor["name"],
                                json.dumps(actor.get("aliases", [])),
                                actor["motivation"].value,
                                actor.get("description", ""),
                                json.dumps(actor.get("targeted_industries", [])),
                                json.dumps(actor.get("targeted_regions", [])),
                                json.dumps(actor.get("mitre_techniques", [])),
                                json.dumps([]),
                                None,
                                None,
                                actor.get("sophistication", "unknown"),
                                json.dumps(actor.get("tags", [])),
                                now,
                            ),
                        )

    # ------------------------------------------------------------------
    # Hypothesis Library
    # ------------------------------------------------------------------

    def list_hypotheses(
        self,
        tactic: Optional[MitreTactic] = None,
        severity: Optional[HuntSeverity] = None,
        kill_chain_phase: Optional[KillChainPhase] = None,
    ) -> List[HuntHypothesis]:
        """Return hunt hypotheses, optionally filtered."""
        with self._lock:
            with self._get_conn() as conn:
                query = "SELECT * FROM hypotheses WHERE 1=1"
                params: List[Any] = []
                if tactic:
                    query += " AND mitre_tactic=?"
                    params.append(tactic.value)
                if severity:
                    query += " AND severity=?"
                    params.append(severity.value)
                if kill_chain_phase:
                    query += " AND kill_chain_phase=?"
                    params.append(kill_chain_phase.value)
                query += " ORDER BY severity DESC, name ASC"
                rows = conn.execute(query, params).fetchall()
                return [self._row_to_hypothesis(r) for r in rows]

    def add_hypothesis(self, hyp: HuntHypothesis) -> HuntHypothesis:
        """Persist a new custom hypothesis."""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO hypotheses
                       (id, name, description, mitre_tactic, mitre_technique_id,
                        mitre_technique_name, kill_chain_phase, severity,
                        data_sources, search_query, tags, created_at, builtin)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                    (
                        hyp.id,
                        hyp.name,
                        hyp.description,
                        hyp.mitre_tactic.value,
                        hyp.mitre_technique_id,
                        hyp.mitre_technique_name,
                        hyp.kill_chain_phase.value,
                        hyp.severity.value,
                        json.dumps(hyp.data_sources),
                        hyp.search_query,
                        json.dumps(hyp.tags),
                        hyp.created_at.isoformat(),
                    ),
                )
        _logger.info("hypothesis.added id=%s name=%s", hyp.id, hyp.name)
        return hyp

    def _row_to_hypothesis(self, row: sqlite3.Row) -> HuntHypothesis:
        return HuntHypothesis(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            mitre_tactic=MitreTactic(row["mitre_tactic"]),
            mitre_technique_id=row["mitre_technique_id"],
            mitre_technique_name=row["mitre_technique_name"],
            kill_chain_phase=KillChainPhase(row["kill_chain_phase"]),
            severity=HuntSeverity(row["severity"]),
            data_sources=json.loads(row["data_sources"]),
            search_query=row["search_query"],
            tags=json.loads(row["tags"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    # ------------------------------------------------------------------
    # IOC Management
    # ------------------------------------------------------------------

    def add_ioc(self, ioc: IOC) -> IOC:
        """Persist a single IOC."""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO iocs
                       (id, type, value, description, confidence, severity,
                        source, tags, stix_id, first_seen, last_seen, active)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        ioc.id,
                        ioc.type.value,
                        ioc.value,
                        ioc.description,
                        ioc.confidence,
                        ioc.severity.value,
                        ioc.source,
                        json.dumps(ioc.tags),
                        ioc.stix_id,
                        ioc.first_seen.isoformat(),
                        ioc.last_seen.isoformat(),
                        int(ioc.active),
                    ),
                )
        _logger.info("ioc.added type=%s value=%s", ioc.type.value, ioc.value)
        return ioc

    def bulk_import_iocs(self, iocs: List[IOC]) -> int:
        """Bulk import IOCs, return count inserted/updated."""
        with self._lock:
            with self._get_conn() as conn:
                count = 0
                for ioc in iocs:
                    conn.execute(
                        """INSERT OR REPLACE INTO iocs
                           (id, type, value, description, confidence, severity,
                            source, tags, stix_id, first_seen, last_seen, active)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            ioc.id,
                            ioc.type.value,
                            ioc.value,
                            ioc.description,
                            ioc.confidence,
                            ioc.severity.value,
                            ioc.source,
                            json.dumps(ioc.tags),
                            ioc.stix_id,
                            ioc.first_seen.isoformat(),
                            ioc.last_seen.isoformat(),
                            int(ioc.active),
                        ),
                    )
                    count += 1
        _logger.info("ioc.bulk_import count=%d", count)
        return count

    def import_stix_bundle(self, bundle: Dict[str, Any]) -> int:
        """
        Import IOCs from a STIX 2.1 bundle.

        Handles indicator objects with pattern field.
        Returns count of imported IOCs.
        """
        objects = bundle.get("objects", [])
        iocs: List[IOC] = []
        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            stix_id = obj.get("id", "")
            pattern = obj.get("pattern", "")
            name = obj.get("name", "")
            description = obj.get("description", "")
            labels = obj.get("labels", [])

            ioc_type, ioc_value = _parse_stix_pattern(pattern)
            if ioc_type is None or ioc_value is None:
                continue

            iocs.append(
                IOC(
                    type=ioc_type,
                    value=ioc_value,
                    description=description or name,
                    source="stix2.1",
                    stix_id=stix_id,
                    tags=labels,
                )
            )

        return self.bulk_import_iocs(iocs)

    def list_iocs(
        self,
        ioc_type: Optional[IOCType] = None,
        active_only: bool = True,
        limit: int = 500,
    ) -> List[IOC]:
        """List IOCs with optional type filter."""
        with self._lock:
            with self._get_conn() as conn:
                query = "SELECT * FROM iocs WHERE 1=1"
                params: List[Any] = []
                if active_only:
                    query += " AND active=1"
                if ioc_type:
                    query += " AND type=?"
                    params.append(ioc_type.value)
                query += " ORDER BY last_seen DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(query, params).fetchall()
                return [self._row_to_ioc(r) for r in rows]

    def check_ioc_match(self, value: str) -> Optional[IOC]:
        """Check if a value matches any active IOC. Returns first match."""
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM iocs WHERE value=? AND active=1 LIMIT 1",
                    (value,),
                ).fetchone()
                return self._row_to_ioc(row) if row else None

    def _row_to_ioc(self, row: sqlite3.Row) -> IOC:
        return IOC(
            id=row["id"],
            type=IOCType(row["type"]),
            value=row["value"],
            description=row["description"],
            confidence=row["confidence"],
            severity=HuntSeverity(row["severity"]),
            source=row["source"],
            tags=json.loads(row["tags"]),
            stix_id=row["stix_id"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            active=bool(row["active"]),
        )

    # ------------------------------------------------------------------
    # Sigma Rule Engine
    # ------------------------------------------------------------------

    def add_sigma_rule(self, rule: SigmaRule) -> SigmaRule:
        """Persist a Sigma detection rule."""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO sigma_rules
                       (id, name, description, author, status, logsource_category,
                        logsource_product, detection_keywords, detection_condition,
                        false_positives, level, tags, raw_yaml, search_query,
                        created_at, enabled)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        rule.id,
                        rule.name,
                        rule.description,
                        rule.author,
                        rule.status,
                        rule.logsource_category,
                        rule.logsource_product,
                        json.dumps(rule.detection_keywords),
                        rule.detection_condition,
                        json.dumps(rule.false_positives),
                        rule.level.value,
                        json.dumps(rule.tags),
                        rule.raw_yaml,
                        rule.search_query,
                        rule.created_at.isoformat(),
                        int(rule.enabled),
                    ),
                )
        _logger.info("sigma_rule.added id=%s name=%s", rule.id, rule.name)
        return rule

    def import_sigma_yaml(self, yaml_content: str) -> SigmaRule:
        """Parse and persist a Sigma rule from YAML string."""
        rule = parse_sigma_rule(yaml_content)
        return self.add_sigma_rule(rule)

    def list_sigma_rules(self, enabled_only: bool = True) -> List[SigmaRule]:
        """List Sigma rules."""
        with self._lock:
            with self._get_conn() as conn:
                query = "SELECT * FROM sigma_rules"
                if enabled_only:
                    query += " WHERE enabled=1"
                query += " ORDER BY level DESC, name ASC"
                rows = conn.execute(query).fetchall()
                return [self._row_to_sigma(r) for r in rows]

    def _row_to_sigma(self, row: sqlite3.Row) -> SigmaRule:
        return SigmaRule(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            author=row["author"],
            status=row["status"],
            logsource_category=row["logsource_category"],
            logsource_product=row["logsource_product"],
            detection_keywords=json.loads(row["detection_keywords"]),
            detection_condition=row["detection_condition"],
            false_positives=json.loads(row["false_positives"]),
            level=HuntSeverity(row["level"]),
            tags=json.loads(row["tags"]),
            raw_yaml=row["raw_yaml"],
            search_query=row["search_query"],
            created_at=datetime.fromisoformat(row["created_at"]),
            enabled=bool(row["enabled"]),
        )

    # ------------------------------------------------------------------
    # Hunt Workflows
    # ------------------------------------------------------------------

    def start_hunt(
        self,
        hypothesis_id: str,
        org_id: str = "default",
        analyst: str = "system",
        trigger_type: HuntTriggerType = HuntTriggerType.MANUAL,
        trigger_context: Optional[Dict[str, Any]] = None,
    ) -> HuntWorkflow:
        """Start a new hunt workflow for the given hypothesis."""
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT name FROM hypotheses WHERE id=?", (hypothesis_id,)
                ).fetchone()
                if not row:
                    raise ValueError(f"Hypothesis not found: {hypothesis_id}")
                hypothesis_name = row["name"]

        now = datetime.now(timezone.utc)
        workflow = HuntWorkflow(
            hypothesis_id=hypothesis_id,
            hypothesis_name=hypothesis_name,
            org_id=org_id,
            status=HuntStatus.ACTIVE,
            trigger_type=trigger_type,
            trigger_context=trigger_context or {},
            analyst=analyst,
            started_at=now,
        )

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO hunt_workflows
                       (id, hypothesis_id, hypothesis_name, org_id, status,
                        trigger_type, trigger_context, analyst, started_at,
                        completed_at, findings_count, data_sources_queried, notes, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        workflow.id,
                        workflow.hypothesis_id,
                        workflow.hypothesis_name,
                        workflow.org_id,
                        workflow.status.value,
                        workflow.trigger_type.value,
                        json.dumps(workflow.trigger_context),
                        workflow.analyst,
                        workflow.started_at.isoformat() if workflow.started_at else None,
                        None,
                        0,
                        json.dumps([]),
                        "",
                        workflow.created_at.isoformat(),
                    ),
                )

        _logger.info(
            "hunt.started id=%s hypothesis=%s org=%s",
            workflow.id,
            hypothesis_name,
            org_id,
        )
        return workflow

    def complete_hunt(self, hunt_id: str, notes: str = "") -> HuntWorkflow:
        """Mark a hunt as completed."""
        now = datetime.now(timezone.utc)
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "UPDATE hunt_workflows SET status=?, completed_at=?, notes=? WHERE id=?",
                    (HuntStatus.COMPLETED.value, now.isoformat(), notes, hunt_id),
                )
        return self.get_hunt(hunt_id)

    def get_hunt(self, hunt_id: str) -> HuntWorkflow:
        """Retrieve a hunt workflow by ID."""
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM hunt_workflows WHERE id=?", (hunt_id,)
                ).fetchone()
                if not row:
                    raise ValueError(f"Hunt not found: {hunt_id}")
                return self._row_to_workflow(row)

    def list_active_hunts(self, org_id: Optional[str] = None) -> List[HuntWorkflow]:
        """List hunts with active or pending status."""
        with self._lock:
            with self._get_conn() as conn:
                query = "SELECT * FROM hunt_workflows WHERE status IN ('active','pending','analysis')"
                params: List[Any] = []
                if org_id:
                    query += " AND org_id=?"
                    params.append(org_id)
                query += " ORDER BY created_at DESC"
                rows = conn.execute(query, params).fetchall()
                return [self._row_to_workflow(r) for r in rows]

    def list_hunts(self, org_id: Optional[str] = None, limit: int = 100) -> List[HuntWorkflow]:
        """List all hunts."""
        with self._lock:
            with self._get_conn() as conn:
                query = "SELECT * FROM hunt_workflows WHERE 1=1"
                params: List[Any] = []
                if org_id:
                    query += " AND org_id=?"
                    params.append(org_id)
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(query, params).fetchall()
                return [self._row_to_workflow(r) for r in rows]

    def add_finding(self, finding: HuntFinding) -> HuntFinding:
        """Add a finding to a hunt and increment findings_count."""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO hunt_findings
                       (id, hunt_id, title, description, severity, mitre_technique_id,
                        evidence, ioc_matches, kill_chain_phase, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        finding.id,
                        finding.hunt_id,
                        finding.title,
                        finding.description,
                        finding.severity.value,
                        finding.mitre_technique_id,
                        json.dumps(finding.evidence),
                        json.dumps(finding.ioc_matches),
                        finding.kill_chain_phase.value if finding.kill_chain_phase else None,
                        finding.created_at.isoformat(),
                    ),
                )
                conn.execute(
                    "UPDATE hunt_workflows SET findings_count = findings_count + 1 WHERE id=?",
                    (finding.hunt_id,),
                )
        _logger.info(
            "hunt.finding_added hunt_id=%s finding_id=%s severity=%s",
            finding.hunt_id,
            finding.id,
            finding.severity.value,
        )
        return finding

    def list_findings(self, hunt_id: str) -> List[HuntFinding]:
        """List all findings for a hunt."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM hunt_findings WHERE hunt_id=? ORDER BY created_at DESC",
                    (hunt_id,),
                ).fetchall()
                return [self._row_to_finding(r) for r in rows]

    def _row_to_workflow(self, row: sqlite3.Row) -> HuntWorkflow:
        return HuntWorkflow(
            id=row["id"],
            hypothesis_id=row["hypothesis_id"],
            hypothesis_name=row["hypothesis_name"],
            org_id=row["org_id"],
            status=HuntStatus(row["status"]),
            trigger_type=HuntTriggerType(row["trigger_type"]),
            trigger_context=json.loads(row["trigger_context"]),
            analyst=row["analyst"],
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            findings_count=row["findings_count"],
            data_sources_queried=json.loads(row["data_sources_queried"]),
            notes=row["notes"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def _row_to_finding(self, row: sqlite3.Row) -> HuntFinding:
        return HuntFinding(
            id=row["id"],
            hunt_id=row["hunt_id"],
            title=row["title"],
            description=row["description"],
            severity=HuntSeverity(row["severity"]),
            mitre_technique_id=row["mitre_technique_id"],
            evidence=json.loads(row["evidence"]),
            ioc_matches=json.loads(row["ioc_matches"]),
            kill_chain_phase=KillChainPhase(row["kill_chain_phase"]) if row["kill_chain_phase"] else None,
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    # ------------------------------------------------------------------
    # Threat Actor Profiles
    # ------------------------------------------------------------------

    def list_actors(self, motivation: Optional[ThreatActorMotivation] = None) -> List[ThreatActorProfile]:
        """List threat actor profiles."""
        with self._lock:
            with self._get_conn() as conn:
                query = "SELECT * FROM threat_actors WHERE 1=1"
                params: List[Any] = []
                if motivation:
                    query += " AND motivation=?"
                    params.append(motivation.value)
                query += " ORDER BY name ASC"
                rows = conn.execute(query, params).fetchall()
                return [self._row_to_actor(r) for r in rows]

    def add_actor(self, actor: ThreatActorProfile) -> ThreatActorProfile:
        """Persist a threat actor profile."""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO threat_actors
                       (id, name, aliases, motivation, description,
                        targeted_industries, targeted_regions, mitre_techniques,
                        associated_ioc_ids, first_observed, last_active,
                        sophistication, tags, created_at, builtin)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                    (
                        actor.id,
                        actor.name,
                        json.dumps(actor.aliases),
                        actor.motivation.value,
                        actor.description,
                        json.dumps(actor.targeted_industries),
                        json.dumps(actor.targeted_regions),
                        json.dumps(actor.mitre_techniques),
                        json.dumps(actor.associated_ioc_ids),
                        actor.first_observed.isoformat() if actor.first_observed else None,
                        actor.last_active.isoformat() if actor.last_active else None,
                        actor.sophistication,
                        json.dumps(actor.tags),
                        actor.created_at.isoformat(),
                    ),
                )
        _logger.info("actor.added id=%s name=%s", actor.id, actor.name)
        return actor

    def _row_to_actor(self, row: sqlite3.Row) -> ThreatActorProfile:
        return ThreatActorProfile(
            id=row["id"],
            name=row["name"],
            aliases=json.loads(row["aliases"]),
            motivation=ThreatActorMotivation(row["motivation"]),
            description=row["description"],
            targeted_industries=json.loads(row["targeted_industries"]),
            targeted_regions=json.loads(row["targeted_regions"]),
            mitre_techniques=json.loads(row["mitre_techniques"]),
            associated_ioc_ids=json.loads(row["associated_ioc_ids"]),
            first_observed=datetime.fromisoformat(row["first_observed"]) if row["first_observed"] else None,
            last_active=datetime.fromisoformat(row["last_active"]) if row["last_active"] else None,
            sophistication=row["sophistication"],
            tags=json.loads(row["tags"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    # ------------------------------------------------------------------
    # Kill Chain Coverage
    # ------------------------------------------------------------------

    def get_kill_chain_coverage(self) -> List[KillChainCoverage]:
        """
        Compute kill chain coverage across all phases.

        Returns coverage stats per phase showing hypothesis and sigma rule counts.
        """
        with self._lock:
            with self._get_conn() as conn:
                coverage: List[KillChainCoverage] = []
                for phase in KillChainPhase:
                    hyp_count = conn.execute(
                        "SELECT COUNT(*) FROM hypotheses WHERE kill_chain_phase=?",
                        (phase.value,),
                    ).fetchone()[0]

                    active_hunt_count = conn.execute(
                        """SELECT COUNT(*) FROM hunt_workflows hw
                           JOIN hypotheses h ON hw.hypothesis_id = h.id
                           WHERE h.kill_chain_phase=? AND hw.status IN ('active','pending','analysis')""",
                        (phase.value,),
                    ).fetchone()[0]

                    # Sigma rules don't map directly to kill chain — count enabled rules
                    # proportionally (all rules shown for covered phases)
                    sigma_count = conn.execute(
                        "SELECT COUNT(*) FROM sigma_rules WHERE enabled=1"
                    ).fetchone()[0] if hyp_count > 0 else 0

                    coverage.append(
                        KillChainCoverage(
                            phase=phase,
                            hypothesis_count=hyp_count,
                            sigma_rule_count=sigma_count,
                            active_hunt_count=active_hunt_count,
                            covered=hyp_count > 0,
                        )
                    )
                return coverage

    # ------------------------------------------------------------------
    # Automated Hunt Triggers
    # ------------------------------------------------------------------

    def fire_trigger(
        self,
        trigger_type: HuntTriggerType,
        context: Dict[str, Any],
        org_id: str = "default",
    ) -> Optional[HuntWorkflow]:
        """
        Evaluate a trigger and auto-initiate a hunt if a matching hypothesis exists.

        Maps trigger types to relevant MITRE tactics and picks the best hypothesis.
        Records the trigger regardless of whether a hunt was started.
        """
        trigger = HuntTrigger(
            trigger_type=trigger_type,
            context=context,
        )

        # Select tactic based on trigger type
        tactic_map: Dict[HuntTriggerType, MitreTactic] = {
            HuntTriggerType.NEW_CVE: MitreTactic.INITIAL_ACCESS,
            HuntTriggerType.IOC_MATCH: MitreTactic.COMMAND_AND_CONTROL,
            HuntTriggerType.NETWORK_ANOMALY: MitreTactic.LATERAL_MOVEMENT,
            HuntTriggerType.COMPLIANCE_FAILURE: MitreTactic.DEFENSE_EVASION,
        }

        tactic = tactic_map.get(trigger_type)
        workflow: Optional[HuntWorkflow] = None

        if tactic:
            hypotheses = self.list_hypotheses(tactic=tactic, severity=HuntSeverity.HIGH)
            if not hypotheses:
                hypotheses = self.list_hypotheses(tactic=tactic)
            if hypotheses:
                best = hypotheses[0]
                try:
                    workflow = self.start_hunt(
                        hypothesis_id=best.id,
                        org_id=org_id,
                        analyst="system",
                        trigger_type=trigger_type,
                        trigger_context=context,
                    )
                    trigger.hypothesis_id = best.id
                    trigger.hunt_id = workflow.id
                except Exception:
                    _logger.exception("trigger.hunt_start_failed trigger_type=%s", trigger_type.value)

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO hunt_triggers
                       (id, trigger_type, context, hypothesis_id, hunt_id, fired_at)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        trigger.id,
                        trigger.trigger_type.value,
                        json.dumps(trigger.context),
                        trigger.hypothesis_id,
                        trigger.hunt_id,
                        trigger.fired_at.isoformat(),
                    ),
                )

        _logger.info(
            "trigger.fired type=%s hunt_started=%s",
            trigger_type.value,
            workflow is not None,
        )
        return workflow

    def list_triggers(self, limit: int = 100) -> List[HuntTrigger]:
        """List recent automated triggers."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM hunt_triggers ORDER BY fired_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [
                    HuntTrigger(
                        id=r["id"],
                        trigger_type=HuntTriggerType(r["trigger_type"]),
                        context=json.loads(r["context"]),
                        hypothesis_id=r["hypothesis_id"],
                        hunt_id=r["hunt_id"],
                        fired_at=datetime.fromisoformat(r["fired_at"]),
                    )
                    for r in rows
                ]


# ============================================================================
# STIX 2.1 HELPERS
# ============================================================================


def _parse_stix_pattern(pattern: str) -> tuple[Optional[IOCType], Optional[str]]:
    """
    Extract IOC type and value from a STIX 2.1 pattern string.

    Handles common patterns:
      [ipv4-addr:value = '1.2.3.4']
      [domain-name:value = 'evil.com']
      [file:hashes.MD5 = 'abc123']
      [file:hashes.'SHA-256' = 'abc...']
      [url:value = 'http://evil.com/path']
      [email-addr:value = 'spam@evil.com']
    """
    import re

    pattern = pattern.strip("[]").strip()

    matchers = [
        (r"ipv4-addr:value\s*=\s*'([^']+)'", IOCType.IP),
        (r"ipv6-addr:value\s*=\s*'([^']+)'", IOCType.IP),
        (r"domain-name:value\s*=\s*'([^']+)'", IOCType.DOMAIN),
        (r"url:value\s*=\s*'([^']+)'", IOCType.URL),
        (r"email-addr:value\s*=\s*'([^']+)'", IOCType.EMAIL),
        (r"file:hashes\.MD5\s*=\s*'([^']+)'", IOCType.MD5),
        (r"file:hashes\.'SHA-1'\s*=\s*'([^']+)'", IOCType.SHA1),
        (r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'", IOCType.SHA256),
        (r"windows-registry-key:key\s*=\s*'([^']+)'", IOCType.REGISTRY_KEY),
    ]

    for regex, ioc_type in matchers:
        m = re.search(regex, pattern, re.IGNORECASE)
        if m:
            return ioc_type, m.group(1)

    return None, None


def export_iocs_to_stix(iocs: List[IOC], bundle_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Export a list of IOCs as a STIX 2.1 bundle.

    Each IOC becomes an indicator object with a pattern field.
    """
    pattern_map: Dict[IOCType, str] = {
        IOCType.IP: "ipv4-addr:value = '{value}'",
        IOCType.DOMAIN: "domain-name:value = '{value}'",
        IOCType.URL: "url:value = '{value}'",
        IOCType.EMAIL: "email-addr:value = '{value}'",
        IOCType.MD5: "file:hashes.MD5 = '{value}'",
        IOCType.SHA1: "file:hashes.'SHA-1' = '{value}'",
        IOCType.SHA256: "file:hashes.'SHA-256' = '{value}'",
        IOCType.REGISTRY_KEY: "windows-registry-key:key = '{value}'",
    }

    objects = []
    for ioc in iocs:
        pattern_template = pattern_map.get(ioc.type, "domain-name:value = '{value}'")
        pattern = f"[{pattern_template.format(value=ioc.value)}]"

        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ioc.stix_id or f"indicator--{ioc.id}",
                "name": f"{ioc.type.value}: {ioc.value}",
                "description": ioc.description,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ioc.first_seen.isoformat(),
                "labels": ioc.tags,
                "confidence": ioc.confidence,
            }
        )

    return {
        "type": "bundle",
        "id": bundle_id or f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }
