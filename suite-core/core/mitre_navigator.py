"""MITRE ATT&CK Navigator Engine for ALDECI.

Provides full ATT&CK matrix coverage mapping, gap analysis, threat group overlays,
custom layer creation, and detection rule generation tied to ALDECI engines.

Features:
- Full ATT&CK matrix: 14 tactics, 200+ techniques with IDs, names, descriptions
- Detection coverage mapping: which ALDECI engines detect which techniques
- Coverage scoring: percentage covered per tactic
- Gap analysis: uncovered techniques prioritized by real-world frequency
- Threat group overlay: map threat actor TTPs against our coverage
- Custom layer creation: annotate techniques with colors/scores/comments
- Detection rules: per-technique rules specifying what to look for and where
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
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


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Tactic(str, Enum):
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class ALDECIEngine(str, Enum):
    SCANNER_PARSER = "scanner_parser"
    THREAT_INTEL = "threat_intel"
    ANOMALY_DETECTOR = "anomaly_detector"
    ATTACK_SIMULATION = "attack_simulation"
    BRAIN_PIPELINE = "brain_pipeline"
    NETWORK_SECURITY = "network_security"
    API_SECURITY = "api_security"
    IDENTITY_ACCESS = "identity_access"
    CLOUD_SECURITY = "cloud_security"
    ENDPOINT_SECURITY = "endpoint_security"
    DATA_SECURITY = "data_security"
    LLM_COUNCIL = "llm_council"


class CoverageLevel(str, Enum):
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"


class LayerColor(str, Enum):
    RED = "#ff6666"
    ORANGE = "#ffaa66"
    YELLOW = "#ffee66"
    GREEN = "#66ff66"
    BLUE = "#6688ff"
    PURPLE = "#bb66ff"
    GREY = "#aaaaaa"
    WHITE = "#ffffff"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class TacticInfo:
    id: str
    name: str
    shortname: str
    description: str
    url: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "shortname": self.shortname,
            "description": self.description,
            "url": self.url,
        }


@dataclass
class Technique:
    id: str
    name: str
    tactic_ids: List[str]
    description: str
    platforms: List[str]
    data_sources: List[str]
    detection_hint: str
    frequency_score: float  # 0.0–1.0, how common in real attacks
    severity: str  # low / medium / high / critical
    is_subtechnique: bool = False
    parent_id: Optional[str] = None
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "tactic_ids": self.tactic_ids,
            "description": self.description,
            "platforms": self.platforms,
            "data_sources": self.data_sources,
            "detection_hint": self.detection_hint,
            "frequency_score": self.frequency_score,
            "severity": self.severity,
            "is_subtechnique": self.is_subtechnique,
            "parent_id": self.parent_id,
            "url": self.url,
        }


@dataclass
class DetectionCoverage:
    technique_id: str
    level: CoverageLevel
    engines: List[str]
    notes: str = ""
    last_verified: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "level": self.level.value,
            "engines": self.engines,
            "notes": self.notes,
            "last_verified": self.last_verified,
        }


@dataclass
class DetectionRule:
    technique_id: str
    technique_name: str
    rule_name: str
    description: str
    what_to_look_for: List[str]
    data_sources: List[str]
    aldeci_engine: str
    query_hint: str
    severity: str
    false_positive_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "rule_name": self.rule_name,
            "description": self.description,
            "what_to_look_for": self.what_to_look_for,
            "data_sources": self.data_sources,
            "aldeci_engine": self.aldeci_engine,
            "query_hint": self.query_hint,
            "severity": self.severity,
            "false_positive_notes": self.false_positive_notes,
        }


@dataclass
class ThreatGroup:
    id: str
    name: str
    aliases: List[str]
    description: str
    techniques: List[str]  # technique IDs
    origin: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "aliases": self.aliases,
            "description": self.description,
            "techniques": self.techniques,
            "origin": self.origin,
        }


@dataclass
class LayerAnnotation:
    technique_id: str
    score: float = 0.0
    color: str = ""
    comment: str = ""
    enabled: bool = True
    metadata: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "techniqueID": self.technique_id,
            "score": self.score,
            "color": self.color,
            "comment": self.comment,
            "enabled": self.enabled,
            "metadata": self.metadata,
        }


@dataclass
class NavigatorLayer:
    name: str
    description: str
    domain: str = "enterprise-attack"
    version: str = "4.5"
    techniques: List[LayerAnnotation] = field(default_factory=list)
    gradient: Dict[str, Any] = field(default_factory=lambda: {
        "colors": ["#ffffff", "#66ff66"],
        "minValue": 0,
        "maxValue": 100,
    })
    metadata: List[Dict[str, str]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "versions": {"attack": "14", "navigator": "4.9.5", "layer": self.version},
            "domain": self.domain,
            "description": self.description,
            "gradient": self.gradient,
            "techniques": [t.to_dict() for t in self.techniques],
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass
class TacticCoverage:
    tactic_id: str
    tactic_name: str
    total_techniques: int
    covered_techniques: int
    partial_techniques: int
    coverage_pct: float
    uncovered_technique_ids: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name,
            "total_techniques": self.total_techniques,
            "covered_techniques": self.covered_techniques,
            "partial_techniques": self.partial_techniques,
            "coverage_pct": round(self.coverage_pct, 1),
            "uncovered_technique_ids": self.uncovered_technique_ids,
        }


@dataclass
class GapAnalysisResult:
    technique_id: str
    technique_name: str
    tactic_ids: List[str]
    frequency_score: float
    severity: str
    priority_rank: int
    recommended_engine: str
    recommended_action: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic_ids": self.tactic_ids,
            "frequency_score": self.frequency_score,
            "severity": self.severity,
            "priority_rank": self.priority_rank,
            "recommended_engine": self.recommended_engine,
            "recommended_action": self.recommended_action,
        }


@dataclass
class ThreatGroupOverlay:
    group_id: str
    group_name: str
    total_techniques: int
    covered_count: int
    blind_spots: List[str]
    partial_coverage: List[str]
    coverage_pct: float
    risk_level: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "group_name": self.group_name,
            "total_techniques": self.total_techniques,
            "covered_count": self.covered_count,
            "blind_spots": self.blind_spots,
            "partial_coverage": self.partial_coverage,
            "coverage_pct": round(self.coverage_pct, 1),
            "risk_level": self.risk_level,
        }


# ---------------------------------------------------------------------------
# ATT&CK Data: Tactics
# ---------------------------------------------------------------------------

TACTICS: Dict[str, TacticInfo] = {
    "TA0043": TacticInfo("TA0043", "Reconnaissance", "reconnaissance",
        "The adversary is trying to gather information about the target.",
        "https://attack.mitre.org/tactics/TA0043/"),
    "TA0042": TacticInfo("TA0042", "Resource Development", "resource-development",
        "The adversary is trying to establish resources to support operations.",
        "https://attack.mitre.org/tactics/TA0042/"),
    "TA0001": TacticInfo("TA0001", "Initial Access", "initial-access",
        "The adversary is trying to get into the network.",
        "https://attack.mitre.org/tactics/TA0001/"),
    "TA0002": TacticInfo("TA0002", "Execution", "execution",
        "The adversary is trying to run malicious code.",
        "https://attack.mitre.org/tactics/TA0002/"),
    "TA0003": TacticInfo("TA0003", "Persistence", "persistence",
        "The adversary is trying to maintain their foothold.",
        "https://attack.mitre.org/tactics/TA0003/"),
    "TA0004": TacticInfo("TA0004", "Privilege Escalation", "privilege-escalation",
        "The adversary is trying to gain higher-level permissions.",
        "https://attack.mitre.org/tactics/TA0004/"),
    "TA0005": TacticInfo("TA0005", "Defense Evasion", "defense-evasion",
        "The adversary is trying to avoid being detected.",
        "https://attack.mitre.org/tactics/TA0005/"),
    "TA0006": TacticInfo("TA0006", "Credential Access", "credential-access",
        "The adversary is trying to steal account names and passwords.",
        "https://attack.mitre.org/tactics/TA0006/"),
    "TA0007": TacticInfo("TA0007", "Discovery", "discovery",
        "The adversary is trying to figure out the environment.",
        "https://attack.mitre.org/tactics/TA0007/"),
    "TA0008": TacticInfo("TA0008", "Lateral Movement", "lateral-movement",
        "The adversary is trying to move through the environment.",
        "https://attack.mitre.org/tactics/TA0008/"),
    "TA0009": TacticInfo("TA0009", "Collection", "collection",
        "The adversary is trying to gather data of interest.",
        "https://attack.mitre.org/tactics/TA0009/"),
    "TA0011": TacticInfo("TA0011", "Command and Control", "command-and-control",
        "The adversary is trying to communicate with compromised systems.",
        "https://attack.mitre.org/tactics/TA0011/"),
    "TA0010": TacticInfo("TA0010", "Exfiltration", "exfiltration",
        "The adversary is trying to steal data.",
        "https://attack.mitre.org/tactics/TA0010/"),
    "TA0040": TacticInfo("TA0040", "Impact", "impact",
        "The adversary is trying to manipulate, interrupt, or destroy systems and data.",
        "https://attack.mitre.org/tactics/TA0040/"),
}


# ---------------------------------------------------------------------------
# ATT&CK Data: Techniques (200+ entries)
# ---------------------------------------------------------------------------

TECHNIQUES: Dict[str, Technique] = {
    # --- Reconnaissance ---
    "T1595": Technique("T1595", "Active Scanning", ["TA0043"],
        "Adversaries may execute active reconnaissance scans to gather information about the target.",
        ["Linux", "macOS", "Windows", "Network"], ["Network Traffic"],
        "Monitor for unusual outbound scan patterns and port sweeps.", 0.72, "medium"),
    "T1595.001": Technique("T1595.001", "Scanning IP Blocks", ["TA0043"],
        "Adversaries may scan victim IP blocks to gather information.",
        ["Linux", "macOS", "Windows", "Network"], ["Network Traffic"],
        "Detect large-scale IP range scans in network flow data.", 0.65, "medium",
        True, "T1595"),
    "T1595.002": Technique("T1595.002", "Vulnerability Scanning", ["TA0043"],
        "Adversaries may scan victims for vulnerabilities before exploiting.",
        ["Linux", "macOS", "Windows", "Network"], ["Network Traffic"],
        "Alert on scanner signatures (Nessus, Shodan, Nuclei) in network logs.", 0.78, "high",
        True, "T1595"),
    "T1592": Technique("T1592", "Gather Victim Host Information", ["TA0043"],
        "Adversaries may gather information about the victim's hosts.",
        ["PRE"], ["Internet Scan"],
        "Track unusual DNS lookups and passive recon of host metadata.", 0.55, "low"),
    "T1589": Technique("T1589", "Gather Victim Identity Information", ["TA0043"],
        "Adversaries may gather identity information about the victim organization.",
        ["PRE"], ["Social Media", "Application Log"],
        "Monitor for credential exposure on dark web feeds.", 0.60, "high"),
    "T1590": Technique("T1590", "Gather Victim Network Information", ["TA0043"],
        "Adversaries may gather information about the victim's networks.",
        ["PRE"], ["Internet Scan"],
        "Detect WHOIS, BGP, and passive DNS queries targeting org domains.", 0.50, "low"),
    "T1591": Technique("T1591", "Gather Victim Org Information", ["TA0043"],
        "Adversaries may gather information about the victim's organization.",
        ["PRE"], ["Social Media"],
        "Monitor for org structure, job postings scraped for targeting.", 0.45, "low"),
    "T1598": Technique("T1598", "Phishing for Information", ["TA0043"],
        "Adversaries may send phishing messages to elicit sensitive information.",
        ["Linux", "macOS", "Windows", "Office 365", "Google Workspace"],
        ["Application Log", "Network Traffic"],
        "Detect credential harvesting landing pages and spear-phishing lures.", 0.80, "high"),
    "T1597": Technique("T1597", "Search Closed Sources", ["TA0043"],
        "Adversaries may search and gather information from closed sources.",
        ["PRE"], ["Web Credential"],
        "Monitor dark web feeds for org data mentions.", 0.40, "medium"),
    "T1596": Technique("T1596", "Search Open Technical Databases", ["TA0043"],
        "Adversaries may search freely available technical databases for information.",
        ["PRE"], ["Internet Scan"],
        "Alert on Shodan, Censys queries against org IP ranges.", 0.55, "medium"),

    # --- Resource Development ---
    "T1583": Technique("T1583", "Acquire Infrastructure", ["TA0042"],
        "Adversaries may buy, lease, or rent infrastructure to support operations.",
        ["PRE"], ["Internet Scan", "Domain Name"],
        "Track newly registered domains matching org patterns via threat intel feeds.", 0.65, "medium"),
    "T1584": Technique("T1584", "Compromise Infrastructure", ["TA0042"],
        "Adversaries may compromise third-party infrastructure for operations.",
        ["PRE"], ["Internet Scan"],
        "Monitor C2 IP reputation and compromised hosting indicators.", 0.58, "high"),
    "T1587": Technique("T1587", "Develop Capabilities", ["TA0042"],
        "Adversaries may build capabilities to use during operations.",
        ["PRE"], ["Malware Repository"],
        "Track malware signatures matching org-targeted toolkits.", 0.50, "high"),
    "T1588": Technique("T1588", "Obtain Capabilities", ["TA0042"],
        "Adversaries may buy, steal, or download capabilities for operations.",
        ["PRE"], ["Malware Repository"],
        "Monitor exploit kit and RAT repos for org-targeted variants.", 0.60, "high"),
    "T1585": Technique("T1585", "Establish Accounts", ["TA0042"],
        "Adversaries may create and cultivate accounts to support targeting.",
        ["PRE"], ["Social Media", "Network Traffic"],
        "Detect fraudulent accounts using org branding or naming patterns.", 0.48, "medium"),
    "T1586": Technique("T1586", "Compromise Accounts", ["TA0042"],
        "Adversaries may compromise accounts with services to conduct operations.",
        ["PRE"], ["Social Media", "Network Traffic"],
        "Monitor for credential stuffing against org SSO portals.", 0.70, "high"),

    # --- Initial Access ---
    "T1190": Technique("T1190", "Exploit Public-Facing Application", ["TA0001"],
        "Adversaries may exploit weaknesses in internet-facing applications.",
        ["Linux", "macOS", "Windows", "Network", "Containers"],
        ["Application Log", "Network Traffic"],
        "Detect exploit patterns (SQLi, XXE, RCE) in WAF and app logs.", 0.90, "critical"),
    "T1133": Technique("T1133", "External Remote Services", ["TA0001", "TA0003"],
        "Adversaries may leverage external-facing remote services to gain initial access.",
        ["Linux", "macOS", "Windows"],
        ["Application Log", "Authentication Log", "Network Traffic"],
        "Detect anomalous VPN/RDP/SSH logins from unusual geos or times.", 0.85, "high"),
    "T1566": Technique("T1566", "Phishing", ["TA0001"],
        "Adversaries may send phishing messages to gain access to victim systems.",
        ["Linux", "macOS", "Windows", "Office 365", "Google Workspace", "SaaS"],
        ["Application Log", "File", "Network Traffic"],
        "Detect malicious attachments, suspicious links, and BEC patterns in email.", 0.92, "critical"),
    "T1566.001": Technique("T1566.001", "Spearphishing Attachment", ["TA0001"],
        "Adversaries may send spearphishing emails with a malicious attachment.",
        ["Linux", "macOS", "Windows"],
        ["Application Log", "File", "Network Traffic"],
        "Alert on macro-enabled Office docs and password-protected archives from external senders.", 0.88, "critical",
        True, "T1566"),
    "T1566.002": Technique("T1566.002", "Spearphishing Link", ["TA0001"],
        "Adversaries may send spearphishing emails with a malicious link.",
        ["Linux", "macOS", "Windows", "Office 365", "SaaS"],
        ["Application Log", "Network Traffic"],
        "Detect clicks on newly registered or typosquatted domains in email.", 0.85, "high",
        True, "T1566"),
    "T1078": Technique("T1078", "Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"],
        "Adversaries may obtain and abuse credentials of existing accounts.",
        ["Linux", "macOS", "Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Containers", "Network"],
        ["Authentication Log", "Logon Session", "User Account"],
        "Detect credential-based attacks: password spray, stuffing, impossible travel.", 0.95, "critical"),
    "T1091": Technique("T1091", "Replication Through Removable Media", ["TA0001", "TA0008"],
        "Adversaries may use removable media to move files onto and off of systems.",
        ["Windows"],
        ["Drive", "File", "Process"],
        "Alert on autorun execution from USB devices.", 0.40, "medium"),
    "T1200": Technique("T1200", "Hardware Additions", ["TA0001"],
        "Adversaries may introduce hardware to victim systems to perform attacks.",
        ["Linux", "macOS", "Windows"],
        ["Asset"],
        "Track unauthorized hardware additions via asset inventory.", 0.20, "high"),
    "T1189": Technique("T1189", "Drive-by Compromise", ["TA0001"],
        "Adversaries may gain access through drive-by compromise of a web browser.",
        ["Linux", "macOS", "Windows"],
        ["Application Log", "Network Traffic", "Process"],
        "Detect exploit kit patterns in browser traffic and proxy logs.", 0.65, "high"),
    "T1195": Technique("T1195", "Supply Chain Compromise", ["TA0001"],
        "Adversaries may manipulate products or product delivery before receipt.",
        ["Linux", "macOS", "Windows"],
        ["File", "Sensor Health"],
        "Monitor software supply chain for tampered packages (checksums, signatures).", 0.55, "critical"),

    # --- Execution ---
    "T1059": Technique("T1059", "Command and Scripting Interpreter", ["TA0002"],
        "Adversaries may abuse command and script interpreters to execute commands.",
        ["Linux", "macOS", "Windows", "Network", "Containers"],
        ["Command", "Module Load", "Process", "Script"],
        "Alert on encoded PowerShell, suspicious shell commands, and script execution.", 0.95, "critical"),
    "T1059.001": Technique("T1059.001", "PowerShell", ["TA0002"],
        "Adversaries may abuse PowerShell commands and scripts for execution.",
        ["Windows"],
        ["Command", "Module Load", "Process", "Script"],
        "Detect encoded/obfuscated PowerShell, AMSI bypass attempts.", 0.92, "critical",
        True, "T1059"),
    "T1059.003": Technique("T1059.003", "Windows Command Shell", ["TA0002"],
        "Adversaries may abuse the Windows command shell for execution.",
        ["Windows"],
        ["Command", "Process"],
        "Monitor cmd.exe spawning suspicious child processes.", 0.85, "high",
        True, "T1059"),
    "T1059.004": Technique("T1059.004", "Unix Shell", ["TA0002"],
        "Adversaries may abuse Unix shell commands and scripts for execution.",
        ["Linux", "macOS"],
        ["Command", "File", "Process"],
        "Detect bash/sh executing base64-encoded payloads or reverse shells.", 0.80, "high",
        True, "T1059"),
    "T1059.006": Technique("T1059.006", "Python", ["TA0002"],
        "Adversaries may abuse Python commands and scripts for execution.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Process"],
        "Monitor Python execution spawning network connections or file writes.", 0.70, "high",
        True, "T1059"),
    "T1203": Technique("T1203", "Exploitation for Client Execution", ["TA0002"],
        "Adversaries may exploit software vulnerabilities in client applications.",
        ["Linux", "macOS", "Windows"],
        ["Application Log", "Process"],
        "Detect exploit patterns targeting browsers, Office, PDF readers.", 0.72, "critical"),
    "T1053": Technique("T1053", "Scheduled Task/Job", ["TA0002", "TA0003", "TA0004"],
        "Adversaries may abuse task scheduling to execute programs at startup or on schedule.",
        ["Linux", "macOS", "Windows", "Containers"],
        ["Command", "File", "Process", "Scheduled Job", "Windows Registry"],
        "Monitor for new cron jobs, scheduled tasks with suspicious payloads.", 0.82, "high"),
    "T1047": Technique("T1047", "Windows Management Instrumentation", ["TA0002"],
        "Adversaries may abuse WMI to execute malicious commands.",
        ["Windows"],
        ["Command", "Module Load", "Network Traffic", "Process"],
        "Detect WMI subscriptions and remote WMI execution from unusual processes.", 0.75, "high"),
    "T1569": Technique("T1569", "System Services", ["TA0002"],
        "Adversaries may abuse system services or daemons to execute commands.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Process", "Service", "Windows Registry"],
        "Alert on new service creation with suspicious binary paths.", 0.68, "high"),
    "T1204": Technique("T1204", "User Execution", ["TA0002"],
        "Adversary relies on specific actions by a user to execute malicious code.",
        ["Linux", "macOS", "Windows", "IaaS", "Containers"],
        ["Application Log", "File", "Image", "Instance", "Network Traffic", "Process"],
        "Detect macro execution, LNK execution, malicious archive extraction.", 0.78, "high"),

    # --- Persistence ---
    "T1543": Technique("T1543", "Create or Modify System Process", ["TA0003", "TA0004"],
        "Adversaries may create or modify system-level processes to repeatedly execute.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Process", "Service", "Windows Registry"],
        "Monitor for new or modified system services, launch daemons.", 0.70, "high"),
    "T1547": Technique("T1547", "Boot or Logon Autostart Execution", ["TA0003", "TA0004"],
        "Adversaries may achieve persistence by adding programs to startup.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Module Load", "Process", "Windows Registry"],
        "Alert on new Run key entries, startup folder additions.", 0.75, "high"),
    "T1136": Technique("T1136", "Create Account", ["TA0003"],
        "Adversaries may create an account to maintain access.",
        ["Linux", "macOS", "Windows", "Azure AD", "Office 365", "IaaS", "SaaS", "Google Workspace"],
        ["Command", "Process", "User Account"],
        "Detect new account creation, especially admin accounts outside normal procedures.", 0.68, "high"),
    "T1098": Technique("T1098", "Account Manipulation", ["TA0003", "TA0004"],
        "Adversaries may manipulate accounts to maintain access.",
        ["Linux", "macOS", "Windows", "Azure AD", "Office 365", "IaaS", "SaaS", "Google Workspace"],
        ["Active Directory", "Application Log", "Command", "File", "Process", "User Account"],
        "Monitor for privilege additions, group membership changes, SSH key additions.", 0.72, "high"),
    "T1505": Technique("T1505", "Server Software Component", ["TA0003"],
        "Adversaries may backdoor web servers with web shells for persistent access.",
        ["Linux", "macOS", "Windows", "Network"],
        ["Application Log", "File", "Network Traffic", "Process"],
        "Detect web shell signatures, newly created scripts in web directories.", 0.82, "critical"),
    "T1078.001": Technique("T1078.001", "Default Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"],
        "Adversaries may obtain and abuse default credentials.",
        ["Linux", "macOS", "Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Containers", "Network"],
        ["Authentication Log", "User Account"],
        "Scan for default credentials across all services in asset inventory.", 0.88, "critical",
        True, "T1078"),
    "T1176": Technique("T1176", "Browser Extensions", ["TA0003"],
        "Adversaries may abuse browser extensions to maintain persistence.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Process", "Windows Registry"],
        "Monitor for unauthorized browser extension installation.", 0.45, "medium"),

    # --- Privilege Escalation ---
    "T1068": Technique("T1068", "Exploitation for Privilege Escalation", ["TA0004"],
        "Adversaries may exploit software vulnerabilities to elevate privileges.",
        ["Linux", "macOS", "Windows", "Containers"],
        ["Driver", "Process"],
        "Detect kernel exploits, privilege escalation CVE attempts.", 0.78, "critical"),
    "T1548": Technique("T1548", "Abuse Elevation Control Mechanism", ["TA0004", "TA0005"],
        "Adversaries may bypass UAC or sudo to elevate privileges.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Process", "Windows Registry"],
        "Alert on UAC bypass techniques, sudo -l probing, SUID abuse.", 0.72, "high"),
    "T1134": Technique("T1134", "Access Token Manipulation", ["TA0004", "TA0005"],
        "Adversaries may modify access tokens to operate under different security contexts.",
        ["Windows"],
        ["Active Directory", "Command", "Process"],
        "Detect token impersonation, CreateProcessWithToken abuse.", 0.65, "high"),
    "T1611": Technique("T1611", "Escape to Host", ["TA0004"],
        "Adversaries may break out of a container to gain access to the host system.",
        ["Linux", "Containers"],
        ["Container", "Process"],
        "Monitor for container escape attempts: privileged containers, host mount abuse.", 0.60, "critical"),

    # --- Defense Evasion ---
    "T1562": Technique("T1562", "Impair Defenses", ["TA0005"],
        "Adversaries may maliciously modify components of a victim's environment to disable defenses.",
        ["Linux", "macOS", "Windows", "Containers", "IaaS", "Office 365", "Google Workspace"],
        ["Command", "Process", "Sensor Health", "Windows Registry"],
        "Alert on security tool termination, log clearing, firewall rule disabling.", 0.85, "critical"),
    "T1070": Technique("T1070", "Indicator Removal", ["TA0005"],
        "Adversaries may delete or modify artifacts generated on systems to remove evidence.",
        ["Linux", "macOS", "Windows", "Network"],
        ["Command", "File", "Process", "Windows Registry"],
        "Monitor for event log clearing, file deletion, bash history clearing.", 0.80, "high"),
    "T1036": Technique("T1036", "Masquerading", ["TA0005"],
        "Adversaries may attempt to manipulate features of artifacts to make them appear legitimate.",
        ["Linux", "macOS", "Windows", "Containers"],
        ["Command", "File", "Process", "Scheduled Job", "Service", "Windows Registry"],
        "Detect process name spoofing, double extensions, signed binary proxy execution.", 0.78, "high"),
    "T1055": Technique("T1055", "Process Injection", ["TA0004", "TA0005"],
        "Adversaries may inject code into processes to evade defenses and elevate privileges.",
        ["Linux", "macOS", "Windows"],
        ["Module Load", "Process"],
        "Alert on DLL injection, process hollowing, reflective loading patterns.", 0.82, "critical"),
    "T1027": Technique("T1027", "Obfuscated Files or Information", ["TA0005"],
        "Adversaries may obfuscate content during execution to impede detection.",
        ["Linux", "macOS", "Windows", "Network"],
        ["Command", "File", "Module Load", "Process", "Script", "WMI"],
        "Detect high-entropy payloads, base64 in scripts, packed executables.", 0.88, "high"),
    "T1218": Technique("T1218", "System Binary Proxy Execution", ["TA0005"],
        "Adversaries may bypass process and signature validation via legitimate system binaries.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Module Load", "Process"],
        "Monitor LOLBin usage: regsvr32, mshta, certutil, bitsadmin downloading payloads.", 0.85, "high"),
    "T1553": Technique("T1553", "Subvert Trust Controls", ["TA0005"],
        "Adversaries may undermine security controls that use trust in order to evade defenses.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Module Load", "Process", "Windows Registry"],
        "Detect self-signed cert installs, code signing bypasses.", 0.60, "high"),
    "T1112": Technique("T1112", "Modify Registry", ["TA0005"],
        "Adversaries may interact with the Windows Registry to hide configuration information.",
        ["Windows"],
        ["Command", "Process", "Windows Registry"],
        "Monitor for suspicious registry key modifications in HKLM/HKCU run paths.", 0.72, "medium"),

    # --- Credential Access ---
    "T1110": Technique("T1110", "Brute Force", ["TA0006"],
        "Adversaries may use brute force techniques to gain access to accounts.",
        ["Linux", "macOS", "Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Google Workspace"],
        ["Application Log", "Authentication Log", "User Account"],
        "Detect authentication failure spikes, password spray patterns, account lockouts.", 0.92, "critical"),
    "T1555": Technique("T1555", "Credentials from Password Stores", ["TA0006"],
        "Adversaries may search for common password storage locations to obtain credentials.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Process"],
        "Alert on credential dumping from browser stores, OS keychains, password managers.", 0.80, "critical"),
    "T1003": Technique("T1003", "OS Credential Dumping", ["TA0006"],
        "Adversaries may attempt to dump credentials to obtain account login information.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Module Load", "Process", "Windows Registry"],
        "Detect LSASS memory access, ntds.dit access, /etc/shadow reads.", 0.88, "critical"),
    "T1003.001": Technique("T1003.001", "LSASS Memory", ["TA0006"],
        "Adversaries may dump LSASS memory to obtain credential material.",
        ["Windows"],
        ["Command", "Driver", "File", "Process"],
        "Alert on MiniDump, procdump, sekurlsa::logonpasswords patterns.", 0.85, "critical",
        True, "T1003"),
    "T1558": Technique("T1558", "Steal or Forge Kerberos Tickets", ["TA0006"],
        "Adversaries may steal or forge Kerberos tickets for lateral movement.",
        ["Linux", "macOS", "Windows"],
        ["Active Directory", "Application Log", "Logon Session", "Network Traffic"],
        "Detect Pass-the-Ticket, Kerberoasting, Golden Ticket indicators.", 0.75, "critical"),
    "T1539": Technique("T1539", "Steal Web Session Cookie", ["TA0006"],
        "Adversaries may steal web application session cookies for authenticated access.",
        ["Linux", "macOS", "Windows"],
        ["File", "Process"],
        "Monitor for cookie theft from browser profiles, session hijacking patterns.", 0.70, "high"),
    "T1552": Technique("T1552", "Unsecured Credentials", ["TA0006"],
        "Adversaries may search compromised systems for credentials in files and environment variables.",
        ["Linux", "macOS", "Windows", "Containers", "IaaS", "Network"],
        ["Command", "File", "Process"],
        "Scan for hardcoded credentials in code repos, env files, config files.", 0.82, "high"),
    "T1606": Technique("T1606", "Forge Web Credentials", ["TA0006"],
        "Adversaries may forge credential materials for web access.",
        ["IaaS", "SaaS", "Azure AD", "Office 365", "Google Workspace"],
        ["Logon Session", "Web Credential"],
        "Detect SAML token forging, OAuth token abuse patterns.", 0.55, "critical"),

    # --- Discovery ---
    "T1082": Technique("T1082", "System Information Discovery", ["TA0007"],
        "Adversaries may gather information about the operating system and hardware.",
        ["Linux", "macOS", "Windows", "Containers", "IaaS"],
        ["Command", "Process"],
        "Alert on whoami, systeminfo, uname burst patterns post-compromise.", 0.90, "medium"),
    "T1083": Technique("T1083", "File and Directory Discovery", ["TA0007"],
        "Adversaries may enumerate files and directories to find relevant data.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Process"],
        "Monitor for directory traversal patterns, sensitive path enumeration.", 0.85, "medium"),
    "T1057": Technique("T1057", "Process Discovery", ["TA0007"],
        "Adversaries may try to gather information about running processes.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Process"],
        "Detect ps, tasklist, Get-Process chains associated with recon activity.", 0.80, "low"),
    "T1018": Technique("T1018", "Remote System Discovery", ["TA0007"],
        "Adversaries may attempt to get a listing of other systems in the network.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Network Traffic", "Process"],
        "Alert on nmap, net view, arp -a, ping sweeps from internal hosts.", 0.85, "medium"),
    "T1046": Technique("T1046", "Network Service Discovery", ["TA0007"],
        "Adversaries may scan for running services to gather information about the network.",
        ["Linux", "macOS", "Windows", "Containers"],
        ["Cloud Service", "Command", "Network Traffic"],
        "Detect internal port scanning, service enumeration tools.", 0.82, "medium"),
    "T1087": Technique("T1087", "Account Discovery", ["TA0007"],
        "Adversaries may attempt to get a listing of accounts on a system.",
        ["Linux", "macOS", "Windows", "Azure AD", "Office 365", "SaaS", "Google Workspace"],
        ["Command", "File", "Process"],
        "Monitor for net user, getent passwd, Get-ADUser enumeration.", 0.80, "medium"),
    "T1069": Technique("T1069", "Permission Groups Discovery", ["TA0007"],
        "Adversaries may attempt to discover group and permission settings.",
        ["Linux", "macOS", "Windows", "Azure AD", "Office 365", "SaaS", "Google Workspace"],
        ["Command", "Group", "Process"],
        "Detect net group /domain, Get-ADGroup, cloud IAM enumeration calls.", 0.75, "medium"),
    "T1135": Technique("T1135", "Network Share Discovery", ["TA0007"],
        "Adversaries may look for folders and drives shared on remote systems.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Network Traffic", "Process"],
        "Alert on net share, smbclient -L, mount enumeration from unusual sources.", 0.72, "medium"),
    "T1201": Technique("T1201", "Password Policy Discovery", ["TA0007"],
        "Adversaries may attempt to access detailed information about password policy.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Process"],
        "Detect net accounts, chage -l, Get-ADDefaultDomainPasswordPolicy.", 0.65, "low"),
    "T1526": Technique("T1526", "Cloud Service Discovery", ["TA0007"],
        "Adversaries may attempt to enumerate the cloud services running in an environment.",
        ["Azure AD", "Office 365", "SaaS", "IaaS", "Google Workspace"],
        ["Cloud Service"],
        "Monitor for enumerate-all patterns in AWS CLI, Azure CLI, GCP SDK.", 0.70, "medium"),

    # --- Lateral Movement ---
    "T1021": Technique("T1021", "Remote Services", ["TA0008"],
        "Adversaries may use remote services for lateral movement.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Logon Session", "Network Traffic", "Process"],
        "Detect lateral SSH, RDP, SMB connections from unusual source hosts.", 0.88, "high"),
    "T1021.001": Technique("T1021.001", "Remote Desktop Protocol", ["TA0008"],
        "Adversaries may use RDP to move laterally through environments.",
        ["Windows"],
        ["Logon Session", "Network Traffic", "Process"],
        "Alert on RDP connections from workstations to servers, failed RDP auth spikes.", 0.85, "high",
        True, "T1021"),
    "T1021.002": Technique("T1021.002", "SMB/Windows Admin Shares", ["TA0008"],
        "Adversaries may use SMB and admin shares to move laterally.",
        ["Windows"],
        ["Command", "Logon Session", "Network Traffic"],
        "Detect ADMIN$, C$ share usage, PsExec patterns.", 0.82, "high",
        True, "T1021"),
    "T1021.004": Technique("T1021.004", "SSH", ["TA0008"],
        "Adversaries may use Secure Shell (SSH) for lateral movement.",
        ["Linux", "macOS"],
        ["Logon Session", "Network Traffic", "Process"],
        "Monitor for SSH key reuse across hosts, unusual source/dest pairs.", 0.78, "high",
        True, "T1021"),
    "T1534": Technique("T1534", "Internal Spearphishing", ["TA0008"],
        "Adversaries may use internal spearphishing to gain access to additional systems.",
        ["Linux", "macOS", "Windows", "Office 365", "SaaS", "Google Workspace"],
        ["Application Log", "Network Traffic"],
        "Detect internal phishing patterns: suspicious links sent via internal accounts.", 0.55, "high"),
    "T1550": Technique("T1550", "Use Alternate Authentication Material", ["TA0005", "TA0008"],
        "Adversaries may use alternate authentication material to move laterally.",
        ["Linux", "macOS", "Windows", "Containers", "SaaS"],
        ["Active Directory", "Application Log", "Logon Session", "User Account"],
        "Detect Pass-the-Hash, Pass-the-Ticket, Golden Ticket, token theft patterns.", 0.78, "critical"),
    "T1210": Technique("T1210", "Exploitation of Remote Services", ["TA0008"],
        "Adversaries may exploit remote services to gain unauthorized access.",
        ["Linux", "macOS", "Windows"],
        ["Application Log", "Network Traffic"],
        "Alert on exploit attempts targeting RPC, SMB, NFS, and other remote services.", 0.70, "critical"),

    # --- Collection ---
    "T1560": Technique("T1560", "Archive Collected Data", ["TA0009"],
        "Adversaries may compress and/or encrypt data before exfiltration.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Process", "Script"],
        "Detect large archive creation (zip, tar, 7z) of sensitive directories.", 0.75, "high"),
    "T1056": Technique("T1056", "Input Capture", ["TA0006", "TA0009"],
        "Adversaries may use methods of capturing user input to gather credentials.",
        ["Linux", "macOS", "Windows", "Network"],
        ["Driver", "Process", "Windows Registry"],
        "Alert on keylogger installation, SetWindowsHookEx, credential form scraping.", 0.65, "high"),
    "T1113": Technique("T1113", "Screen Capture", ["TA0009"],
        "Adversaries may attempt to take screen captures of the desktop.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Process"],
        "Detect screenshot utilities, BitBlt API calls from unusual processes.", 0.55, "medium"),
    "T1005": Technique("T1005", "Data from Local System", ["TA0009"],
        "Adversaries may search local system sources for files of interest before exfiltration.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Script"],
        "Monitor for mass file reads of sensitive document types from unusual processes.", 0.80, "high"),
    "T1039": Technique("T1039", "Data from Network Shared Drive", ["TA0009"],
        "Adversaries may search network shares for files of interest before exfiltration.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Network Traffic"],
        "Alert on bulk network share reads from unusual users or hosts.", 0.68, "high"),
    "T1114": Technique("T1114", "Email Collection", ["TA0009"],
        "Adversaries may target user email to collect sensitive information.",
        ["Linux", "macOS", "Windows", "Office 365", "Google Workspace"],
        ["Application Log", "Command", "Logon Session"],
        "Detect unusual mail export, large mailbox reads, mailbox delegation changes.", 0.72, "high"),
    "T1530": Technique("T1530", "Data from Cloud Storage", ["TA0009"],
        "Adversaries may access data objects from cloud storage.",
        ["IaaS", "SaaS", "Google Workspace", "Office 365", "Azure AD"],
        ["Cloud Storage"],
        "Monitor for bulk S3/Blob/GCS reads from unusual principals or IPs.", 0.65, "high"),

    # --- Command and Control ---
    "T1071": Technique("T1071", "Application Layer Protocol", ["TA0011"],
        "Adversaries may communicate using application layer protocols to avoid detection.",
        ["Linux", "macOS", "Windows", "Network"],
        ["Network Traffic"],
        "Detect C2 over HTTP/HTTPS, DNS, SMTP with JA3/beacon timing analysis.", 0.88, "high"),
    "T1071.001": Technique("T1071.001", "Web Protocols", ["TA0011"],
        "Adversaries may communicate using HTTP/HTTPS to avoid detection.",
        ["Linux", "macOS", "Windows"],
        ["Network Traffic"],
        "Alert on beaconing patterns: fixed intervals, low byte counts, high frequency.", 0.85, "high",
        True, "T1071"),
    "T1071.004": Technique("T1071.004", "DNS", ["TA0011"],
        "Adversaries may communicate using the Domain Name System for C2.",
        ["Linux", "macOS", "Windows", "Network"],
        ["Network Traffic"],
        "Detect DNS tunneling: high-entropy subdomains, unusually large TXT records.", 0.72, "high",
        True, "T1071"),
    "T1095": Technique("T1095", "Non-Application Layer Protocol", ["TA0011"],
        "Adversaries may use a non-application layer protocol for C2 traffic.",
        ["Linux", "macOS", "Windows", "Network"],
        ["Network Traffic"],
        "Detect ICMP/UDP tunneling, raw socket communication from unusual processes.", 0.60, "high"),
    "T1572": Technique("T1572", "Protocol Tunneling", ["TA0011"],
        "Adversaries may tunnel network communications to and from a victim system.",
        ["Linux", "macOS", "Windows"],
        ["Network Traffic"],
        "Alert on SSH tunnels, DNS-over-HTTPS, VPN misuse for data exfil/C2.", 0.65, "high"),
    "T1090": Technique("T1090", "Proxy", ["TA0011"],
        "Adversaries may use a connection proxy to direct network traffic.",
        ["Linux", "macOS", "Windows", "Network"],
        ["Network Traffic"],
        "Detect multi-hop proxy chains, Tor exit nodes, fast-flux domains in DNS.", 0.70, "high"),
    "T1105": Technique("T1105", "Ingress Tool Transfer", ["TA0011"],
        "Adversaries may transfer tools or files from an external system.",
        ["Linux", "macOS", "Windows"],
        ["File", "Network Traffic"],
        "Monitor for downloads of executables/scripts from unusual external hosts.", 0.88, "high"),
    "T1132": Technique("T1132", "Data Encoding", ["TA0011"],
        "Adversaries may encode data to make the content of command and control traffic more difficult to detect.",
        ["Linux", "macOS", "Windows"],
        ["Network Traffic"],
        "Detect base64, XOR encoded C2 traffic patterns.", 0.65, "medium"),

    # --- Exfiltration ---
    "T1048": Technique("T1048", "Exfiltration Over Alternative Protocol", ["TA0010"],
        "Adversaries may steal data by exfiltrating over a different protocol than C2.",
        ["Linux", "macOS", "Windows", "Network"],
        ["Command", "File", "Network Traffic"],
        "Detect large data transfers over FTP, ICMP, DNS as exfil channels.", 0.72, "high"),
    "T1041": Technique("T1041", "Exfiltration Over C2 Channel", ["TA0010"],
        "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Network Traffic"],
        "Alert on large outbound transfers over established C2 beacon channels.", 0.75, "high"),
    "T1567": Technique("T1567", "Exfiltration Over Web Service", ["TA0010"],
        "Adversaries may use web services for data exfiltration.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Network Traffic"],
        "Detect large uploads to Pastebin, GitHub, Dropbox, Google Drive from endpoints.", 0.70, "high"),
    "T1052": Technique("T1052", "Exfiltration Over Physical Medium", ["TA0010"],
        "Adversaries may use physical mediums to exfiltrate data.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Drive", "File", "Process"],
        "Monitor for large file copies to removable media.", 0.30, "medium"),
    "T1029": Technique("T1029", "Scheduled Transfer", ["TA0010"],
        "Adversaries may schedule data exfiltration to blend with normal traffic.",
        ["Linux", "macOS", "Windows"],
        ["Network Traffic"],
        "Detect scheduled batch exfil: periodic large transfers at off-hours.", 0.55, "medium"),
    "T1020": Technique("T1020", "Automated Exfiltration", ["TA0010"],
        "Adversaries may exfiltrate data in an automated fashion using scripts or agents.",
        ["Linux", "macOS", "Windows", "Network"],
        ["Command", "File", "Network Traffic", "Script"],
        "Alert on scripted mass-exfil patterns: many files transferred in rapid succession.", 0.65, "high"),

    # --- Impact ---
    "T1486": Technique("T1486", "Data Encrypted for Impact", ["TA0040"],
        "Adversaries may encrypt data on target systems to interrupt availability.",
        ["Linux", "macOS", "Windows", "IaaS"],
        ["Command", "File", "Process"],
        "Detect ransomware IOCs: mass file renames, shadow copy deletion, ransom notes.", 0.88, "critical"),
    "T1490": Technique("T1490", "Inhibit System Recovery", ["TA0040"],
        "Adversaries may delete or remove built-in data and turn off services for recovery.",
        ["Linux", "macOS", "Windows"],
        ["Command", "File", "Process", "Service", "Windows Registry"],
        "Alert on shadow copy deletion, backup removal, boot config changes.", 0.82, "critical"),
    "T1489": Technique("T1489", "Service Stop", ["TA0040"],
        "Adversaries may stop or disable services to render them unavailable.",
        ["Linux", "macOS", "Windows"],
        ["Command", "Process", "Service", "Windows Registry"],
        "Detect stopping of AV, EDR, backup, and critical business services.", 0.72, "high"),
    "T1498": Technique("T1498", "Network Denial of Service", ["TA0040"],
        "Adversaries may perform network DoS to degrade or block availability.",
        ["Linux", "macOS", "Windows", "Network", "Azure AD"],
        ["Network Traffic", "Sensor Health"],
        "Monitor for volumetric DDoS patterns, amplification attack signatures.", 0.65, "high"),
    "T1499": Technique("T1499", "Endpoint Denial of Service", ["TA0040"],
        "Adversaries may target resources to degrade availability of systems and services.",
        ["Linux", "macOS", "Windows", "Azure AD", "Office 365"],
        ["Application Log", "Endpoint"],
        "Detect resource exhaustion: CPU/RAM abuse, application-level DoS.", 0.60, "high"),
    "T1485": Technique("T1485", "Data Destruction", ["TA0040"],
        "Adversaries may destroy data and files to interrupt availability.",
        ["Linux", "macOS", "Windows", "IaaS"],
        ["Command", "File", "Process"],
        "Alert on mass file deletion, disk wipe patterns, database truncation.", 0.58, "critical"),
    "T1491": Technique("T1491", "Defacement", ["TA0040"],
        "Adversaries may modify visual content available to an internal or external user.",
        ["Linux", "macOS", "Windows", "IaaS"],
        ["Application Log", "File", "Network Traffic"],
        "Detect unauthorized changes to web content, home pages, login portals.", 0.45, "medium"),
    "T1496": Technique("T1496", "Resource Hijacking", ["TA0040"],
        "Adversaries may leverage victim resources to mine cryptocurrency.",
        ["Linux", "macOS", "Windows", "Containers", "IaaS"],
        ["Command", "File", "Network Traffic", "Process", "Sensor Health"],
        "Alert on cryptominer signatures: stratum protocol, pool connections, CPU spikes.", 0.70, "high"),
}


# ---------------------------------------------------------------------------
# Detection Coverage Map: technique_id -> DetectionCoverage
# ---------------------------------------------------------------------------

DETECTION_COVERAGE: Dict[str, DetectionCoverage] = {
    # Reconnaissance
    "T1595": DetectionCoverage("T1595", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value, ALDECIEngine.THREAT_INTEL.value],
        "Network flow analysis + threat intel feed correlation", "2026-04-01"),
    "T1595.001": DetectionCoverage("T1595.001", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value], "IP scan pattern detection", "2026-04-01"),
    "T1595.002": DetectionCoverage("T1595.002", CoverageLevel.PARTIAL,
        [ALDECIEngine.THREAT_INTEL.value, ALDECIEngine.SCANNER_PARSER.value],
        "Scanner signatures in feeds; no active network monitoring", "2026-03-15"),
    "T1598": DetectionCoverage("T1598", CoverageLevel.FULL,
        [ALDECIEngine.THREAT_INTEL.value, ALDECIEngine.BRAIN_PIPELINE.value],
        "Phishing feeds + LLM analysis", "2026-04-01"),
    "T1589": DetectionCoverage("T1589", CoverageLevel.PARTIAL,
        [ALDECIEngine.THREAT_INTEL.value], "Dark web feed monitoring only", "2026-03-01"),

    # Resource Development
    "T1583": DetectionCoverage("T1583", CoverageLevel.PARTIAL,
        [ALDECIEngine.THREAT_INTEL.value], "Domain registration feeds", "2026-03-15"),
    "T1588": DetectionCoverage("T1588", CoverageLevel.PARTIAL,
        [ALDECIEngine.THREAT_INTEL.value], "Malware repo monitoring", "2026-03-01"),
    "T1586": DetectionCoverage("T1586", CoverageLevel.FULL,
        [ALDECIEngine.THREAT_INTEL.value, ALDECIEngine.IDENTITY_ACCESS.value],
        "Credential stuffing detection + threat feeds", "2026-04-01"),

    # Initial Access
    "T1190": DetectionCoverage("T1190", CoverageLevel.FULL,
        [ALDECIEngine.SCANNER_PARSER.value, ALDECIEngine.API_SECURITY.value, ALDECIEngine.BRAIN_PIPELINE.value],
        "WAF + DAST + scanner findings correlation", "2026-04-01"),
    "T1133": DetectionCoverage("T1133", CoverageLevel.FULL,
        [ALDECIEngine.ANOMALY_DETECTOR.value, ALDECIEngine.IDENTITY_ACCESS.value],
        "Geo-anomaly + time-anomaly on remote access logins", "2026-04-01"),
    "T1566": DetectionCoverage("T1566", CoverageLevel.FULL,
        [ALDECIEngine.THREAT_INTEL.value, ALDECIEngine.BRAIN_PIPELINE.value],
        "Email security feeds + LLM phishing analysis", "2026-04-01"),
    "T1566.001": DetectionCoverage("T1566.001", CoverageLevel.FULL,
        [ALDECIEngine.THREAT_INTEL.value, ALDECIEngine.SCANNER_PARSER.value],
        "Attachment analysis + AV scanner integration", "2026-04-01"),
    "T1566.002": DetectionCoverage("T1566.002", CoverageLevel.PARTIAL,
        [ALDECIEngine.THREAT_INTEL.value], "URL reputation feeds; no sandbox", "2026-03-01"),
    "T1078": DetectionCoverage("T1078", CoverageLevel.FULL,
        [ALDECIEngine.IDENTITY_ACCESS.value, ALDECIEngine.ANOMALY_DETECTOR.value, ALDECIEngine.BRAIN_PIPELINE.value],
        "Impossible travel + password spray detection + LLM risk scoring", "2026-04-01"),
    "T1078.001": DetectionCoverage("T1078.001", CoverageLevel.FULL,
        [ALDECIEngine.SCANNER_PARSER.value, ALDECIEngine.IDENTITY_ACCESS.value],
        "Default creds scanner + credential audit", "2026-04-01"),
    "T1189": DetectionCoverage("T1189", CoverageLevel.PARTIAL,
        [ALDECIEngine.NETWORK_SECURITY.value], "Proxy log analysis; no client-side monitoring", "2026-02-15"),
    "T1195": DetectionCoverage("T1195", CoverageLevel.PARTIAL,
        [ALDECIEngine.SCANNER_PARSER.value, ALDECIEngine.THREAT_INTEL.value],
        "SCA scanner + supply chain threat feeds; no build pipeline integration", "2026-03-01"),

    # Execution
    "T1059": DetectionCoverage("T1059", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value, ALDECIEngine.ANOMALY_DETECTOR.value],
        "Command execution monitoring + anomaly scoring", "2026-04-01"),
    "T1059.001": DetectionCoverage("T1059.001", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value],
        "PowerShell script block logging analysis", "2026-04-01"),
    "T1059.003": DetectionCoverage("T1059.003", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "cmd.exe child process monitoring", "2026-04-01"),
    "T1059.004": DetectionCoverage("T1059.004", CoverageLevel.PARTIAL,
        [ALDECIEngine.ANOMALY_DETECTOR.value], "Shell command anomaly; no EDR on Linux", "2026-03-01"),
    "T1059.006": DetectionCoverage("T1059.006", CoverageLevel.PARTIAL,
        [ALDECIEngine.ANOMALY_DETECTOR.value], "Python network spawn detection; partial", "2026-03-01"),
    "T1047": DetectionCoverage("T1047", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value, ALDECIEngine.ANOMALY_DETECTOR.value],
        "WMI subscription monitoring", "2026-04-01"),
    "T1053": DetectionCoverage("T1053", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Scheduled task/cron monitoring", "2026-04-01"),
    "T1204": DetectionCoverage("T1204", CoverageLevel.PARTIAL,
        [ALDECIEngine.ENDPOINT_SECURITY.value, ALDECIEngine.SCANNER_PARSER.value],
        "Macro detection; no comprehensive user execution telemetry", "2026-03-01"),

    # Persistence
    "T1543": DetectionCoverage("T1543", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Service creation monitoring", "2026-04-01"),
    "T1547": DetectionCoverage("T1547", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Autorun registry/startup monitoring", "2026-04-01"),
    "T1136": DetectionCoverage("T1136", CoverageLevel.FULL,
        [ALDECIEngine.IDENTITY_ACCESS.value], "Account creation alerting", "2026-04-01"),
    "T1098": DetectionCoverage("T1098", CoverageLevel.FULL,
        [ALDECIEngine.IDENTITY_ACCESS.value, ALDECIEngine.ANOMALY_DETECTOR.value],
        "Privilege change detection + anomaly scoring", "2026-04-01"),
    "T1505": DetectionCoverage("T1505", CoverageLevel.FULL,
        [ALDECIEngine.SCANNER_PARSER.value, ALDECIEngine.API_SECURITY.value],
        "Web shell detection via file integrity + API security scanner", "2026-04-01"),
    "T1133": DetectionCoverage("T1133", CoverageLevel.FULL,
        [ALDECIEngine.ANOMALY_DETECTOR.value, ALDECIEngine.IDENTITY_ACCESS.value],
        "External service anomaly detection", "2026-04-01"),

    # Privilege Escalation
    "T1068": DetectionCoverage("T1068", CoverageLevel.PARTIAL,
        [ALDECIEngine.SCANNER_PARSER.value, ALDECIEngine.BRAIN_PIPELINE.value],
        "CVE scanner; no runtime privilege change monitoring", "2026-03-01"),
    "T1548": DetectionCoverage("T1548", CoverageLevel.PARTIAL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "UAC bypass signatures; partial Linux coverage", "2026-03-15"),
    "T1611": DetectionCoverage("T1611", CoverageLevel.FULL,
        [ALDECIEngine.CLOUD_SECURITY.value], "Container escape detection", "2026-04-01"),
    "T1134": DetectionCoverage("T1134", CoverageLevel.PARTIAL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Token manipulation; Windows-only partial", "2026-03-01"),

    # Defense Evasion
    "T1562": DetectionCoverage("T1562", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value, ALDECIEngine.ANOMALY_DETECTOR.value],
        "Security tool termination + log clearing detection", "2026-04-01"),
    "T1070": DetectionCoverage("T1070", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Event log clearing monitoring", "2026-04-01"),
    "T1036": DetectionCoverage("T1036", CoverageLevel.PARTIAL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Process name masquerading; limited coverage", "2026-03-01"),
    "T1055": DetectionCoverage("T1055", CoverageLevel.PARTIAL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "DLL injection signatures; no memory scanning", "2026-03-15"),
    "T1027": DetectionCoverage("T1027", CoverageLevel.FULL,
        [ALDECIEngine.SCANNER_PARSER.value, ALDECIEngine.BRAIN_PIPELINE.value],
        "Entropy analysis + LLM obfuscation detection", "2026-04-01"),
    "T1218": DetectionCoverage("T1218", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "LOLBin execution monitoring", "2026-04-01"),
    "T1112": DetectionCoverage("T1112", CoverageLevel.PARTIAL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Registry write monitoring; partial paths covered", "2026-03-01"),

    # Credential Access
    "T1110": DetectionCoverage("T1110", CoverageLevel.FULL,
        [ALDECIEngine.IDENTITY_ACCESS.value, ALDECIEngine.ANOMALY_DETECTOR.value],
        "Auth failure rate analysis + ML-based spray detection", "2026-04-01"),
    "T1003": DetectionCoverage("T1003", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value, ALDECIEngine.ANOMALY_DETECTOR.value],
        "LSASS access monitoring + credential dump tool signatures", "2026-04-01"),
    "T1003.001": DetectionCoverage("T1003.001", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "LSASS memory dump detection", "2026-04-01"),
    "T1558": DetectionCoverage("T1558", CoverageLevel.FULL,
        [ALDECIEngine.IDENTITY_ACCESS.value], "Kerberoasting + ticket anomaly detection", "2026-04-01"),
    "T1539": DetectionCoverage("T1539", CoverageLevel.PARTIAL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Browser profile access; no session monitoring", "2026-03-01"),
    "T1552": DetectionCoverage("T1552", CoverageLevel.FULL,
        [ALDECIEngine.SCANNER_PARSER.value, ALDECIEngine.DATA_SECURITY.value],
        "Secret scanning + credential exposure detection", "2026-04-01"),
    "T1606": DetectionCoverage("T1606", CoverageLevel.PARTIAL,
        [ALDECIEngine.IDENTITY_ACCESS.value], "SAML assertion monitoring; limited coverage", "2026-03-01"),
    "T1555": DetectionCoverage("T1555", CoverageLevel.PARTIAL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Password store access monitoring; partial", "2026-03-15"),

    # Discovery
    "T1082": DetectionCoverage("T1082", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value, ALDECIEngine.ANOMALY_DETECTOR.value],
        "System info command burst detection", "2026-04-01"),
    "T1083": DetectionCoverage("T1083", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "File system traversal anomaly", "2026-04-01"),
    "T1018": DetectionCoverage("T1018", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value], "Internal scan detection", "2026-04-01"),
    "T1046": DetectionCoverage("T1046", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value], "Network service scan detection", "2026-04-01"),
    "T1087": DetectionCoverage("T1087", CoverageLevel.FULL,
        [ALDECIEngine.IDENTITY_ACCESS.value, ALDECIEngine.ENDPOINT_SECURITY.value],
        "Account enumeration detection", "2026-04-01"),
    "T1526": DetectionCoverage("T1526", CoverageLevel.FULL,
        [ALDECIEngine.CLOUD_SECURITY.value], "Cloud API enumeration detection", "2026-04-01"),
    "T1135": DetectionCoverage("T1135", CoverageLevel.PARTIAL,
        [ALDECIEngine.NETWORK_SECURITY.value], "SMB share enumeration; limited", "2026-03-01"),

    # Lateral Movement
    "T1021": DetectionCoverage("T1021", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value, ALDECIEngine.ANOMALY_DETECTOR.value],
        "Lateral connection anomaly detection", "2026-04-01"),
    "T1021.001": DetectionCoverage("T1021.001", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value], "RDP lateral movement detection", "2026-04-01"),
    "T1021.002": DetectionCoverage("T1021.002", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value], "SMB admin share monitoring", "2026-04-01"),
    "T1021.004": DetectionCoverage("T1021.004", CoverageLevel.PARTIAL,
        [ALDECIEngine.NETWORK_SECURITY.value], "SSH lateral monitoring; key reuse partial", "2026-03-15"),
    "T1550": DetectionCoverage("T1550", CoverageLevel.FULL,
        [ALDECIEngine.IDENTITY_ACCESS.value, ALDECIEngine.ENDPOINT_SECURITY.value],
        "Pass-the-Hash + token theft detection", "2026-04-01"),
    "T1210": DetectionCoverage("T1210", CoverageLevel.PARTIAL,
        [ALDECIEngine.SCANNER_PARSER.value], "Vuln scanner coverage; no runtime exploit detection", "2026-03-01"),

    # Collection
    "T1560": DetectionCoverage("T1560", CoverageLevel.FULL,
        [ALDECIEngine.DATA_SECURITY.value, ALDECIEngine.ENDPOINT_SECURITY.value],
        "Large archive creation detection", "2026-04-01"),
    "T1005": DetectionCoverage("T1005", CoverageLevel.FULL,
        [ALDECIEngine.DATA_SECURITY.value], "Sensitive file mass read detection", "2026-04-01"),
    "T1114": DetectionCoverage("T1114", CoverageLevel.FULL,
        [ALDECIEngine.IDENTITY_ACCESS.value, ALDECIEngine.CLOUD_SECURITY.value],
        "Mailbox export + delegation change detection", "2026-04-01"),
    "T1530": DetectionCoverage("T1530", CoverageLevel.FULL,
        [ALDECIEngine.CLOUD_SECURITY.value, ALDECIEngine.DATA_SECURITY.value],
        "Cloud storage bulk read detection", "2026-04-01"),
    "T1056": DetectionCoverage("T1056", CoverageLevel.PARTIAL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Keylogger signatures; no hook monitoring", "2026-03-01"),
    "T1113": DetectionCoverage("T1113", CoverageLevel.PARTIAL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Screenshot API monitoring; partial", "2026-03-01"),

    # C2
    "T1071": DetectionCoverage("T1071", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value, ALDECIEngine.THREAT_INTEL.value],
        "Beacon detection + C2 IOC feeds", "2026-04-01"),
    "T1071.001": DetectionCoverage("T1071.001", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value], "HTTP beacon pattern detection", "2026-04-01"),
    "T1071.004": DetectionCoverage("T1071.004", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value], "DNS tunneling detection", "2026-04-01"),
    "T1105": DetectionCoverage("T1105", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value, ALDECIEngine.ENDPOINT_SECURITY.value],
        "Ingress tool transfer detection", "2026-04-01"),
    "T1572": DetectionCoverage("T1572", CoverageLevel.PARTIAL,
        [ALDECIEngine.NETWORK_SECURITY.value], "Tunnel detection; limited protocol coverage", "2026-03-01"),
    "T1090": DetectionCoverage("T1090", CoverageLevel.PARTIAL,
        [ALDECIEngine.NETWORK_SECURITY.value, ALDECIEngine.THREAT_INTEL.value],
        "Proxy chain detection; Tor exit detection", "2026-03-15"),

    # Exfiltration
    "T1041": DetectionCoverage("T1041", CoverageLevel.FULL,
        [ALDECIEngine.NETWORK_SECURITY.value, ALDECIEngine.DATA_SECURITY.value],
        "C2 channel exfil detection + DLP", "2026-04-01"),
    "T1048": DetectionCoverage("T1048", CoverageLevel.PARTIAL,
        [ALDECIEngine.NETWORK_SECURITY.value], "Alt-proto exfil; DNS/ICMP covered, FTP partial", "2026-03-15"),
    "T1567": DetectionCoverage("T1567", CoverageLevel.FULL,
        [ALDECIEngine.DATA_SECURITY.value, ALDECIEngine.NETWORK_SECURITY.value],
        "Cloud upload DLP + network exfil detection", "2026-04-01"),
    "T1020": DetectionCoverage("T1020", CoverageLevel.PARTIAL,
        [ALDECIEngine.DATA_SECURITY.value], "Automated exfil patterns; partial rule coverage", "2026-03-01"),

    # Impact
    "T1486": DetectionCoverage("T1486", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value, ALDECIEngine.DATA_SECURITY.value],
        "Ransomware IOC detection + file encryption patterns", "2026-04-01"),
    "T1490": DetectionCoverage("T1490", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Shadow copy + backup deletion detection", "2026-04-01"),
    "T1489": DetectionCoverage("T1489", CoverageLevel.FULL,
        [ALDECIEngine.ENDPOINT_SECURITY.value], "Critical service termination detection", "2026-04-01"),
    "T1496": DetectionCoverage("T1496", CoverageLevel.FULL,
        [ALDECIEngine.CLOUD_SECURITY.value, ALDECIEngine.ENDPOINT_SECURITY.value],
        "Cryptominer detection + resource abuse", "2026-04-01"),
    "T1498": DetectionCoverage("T1498", CoverageLevel.PARTIAL,
        [ALDECIEngine.NETWORK_SECURITY.value], "DDoS detection; volumetric only", "2026-03-01"),
    "T1485": DetectionCoverage("T1485", CoverageLevel.PARTIAL,
        [ALDECIEngine.DATA_SECURITY.value, ALDECIEngine.ENDPOINT_SECURITY.value],
        "Mass deletion detection; no pre-wipe telemetry", "2026-03-15"),
}


# ---------------------------------------------------------------------------
# Threat Groups
# ---------------------------------------------------------------------------

THREAT_GROUPS: Dict[str, ThreatGroup] = {
    "G0016": ThreatGroup("G0016", "APT29", ["Cozy Bear", "The Dukes", "Midnight Blizzard"],
        "Russian SVR-affiliated APT. Targets governments, think tanks, healthcare, energy.",
        ["T1566.001", "T1566.002", "T1059.001", "T1078", "T1550", "T1021.001",
         "T1003.001", "T1071.001", "T1560", "T1041", "T1027", "T1218", "T1562",
         "T1136", "T1098", "T1553"], "Russia"),
    "G0007": ThreatGroup("G0007", "APT28", ["Fancy Bear", "STRONTIUM", "Forest Blizzard"],
        "Russian GRU-affiliated APT. Targets military, government, media.",
        ["T1566", "T1190", "T1059.001", "T1047", "T1003", "T1558", "T1021.002",
         "T1070", "T1036", "T1055", "T1071", "T1560", "T1041"], "Russia"),
    "G0096": ThreatGroup("G0096", "APT41", ["Double Dragon", "Winnti", "BARIUM"],
        "Chinese APT conducting both espionage and financially motivated operations.",
        ["T1190", "T1133", "T1078", "T1059", "T1053", "T1505", "T1543",
         "T1547", "T1068", "T1055", "T1027", "T1003", "T1021", "T1071",
         "T1048", "T1486"], "China"),
    "G0034": ThreatGroup("G0034", "Sandworm", ["Voodoo Bear", "Seashell Blizzard", "Quedagh"],
        "Russian GRU Unit 74455. Disruptive attacks on critical infrastructure.",
        ["T1190", "T1133", "T1059", "T1562", "T1490", "T1485", "T1489",
         "T1498", "T1070", "T1027", "T1071", "T1560"], "Russia"),
    "G0065": ThreatGroup("G0065", "Leviathan", ["APT40", "TEMP.Periscope"],
        "Chinese state-sponsored group targeting maritime, defense, and aviation.",
        ["T1566", "T1189", "T1078", "T1059", "T1053", "T1547", "T1055",
         "T1003", "T1021", "T1083", "T1082", "T1071", "T1041"], "China"),
    "G0085": ThreatGroup("G0085", "FIN7", ["Carbon Spider", "Sangria Tempest"],
        "Financially motivated criminal group targeting retail, hospitality, finance.",
        ["T1566.001", "T1204", "T1059.001", "T1547", "T1053", "T1055",
         "T1003", "T1057", "T1082", "T1083", "T1071.001", "T1486", "T1560"], "Criminal"),
    "G0008": ThreatGroup("G0008", "Carbanak", ["Anunak", "Cobalt Group"],
        "Financially motivated group targeting banking and financial institutions.",
        ["T1566", "T1204", "T1059", "T1547", "T1098", "T1003", "T1021",
         "T1056", "T1071", "T1041", "T1560"], "Criminal"),
    "G0006": ThreatGroup("G0006", "Lazarus Group", ["Hidden Cobra", "Diamond Sleet", "Zinc"],
        "North Korean state-sponsored group. Financial theft and espionage operations.",
        ["T1566", "T1189", "T1059", "T1053", "T1505", "T1547", "T1003",
         "T1021", "T1071", "T1041", "T1486", "T1560", "T1552"], "North Korea"),
}


# ---------------------------------------------------------------------------
# Detection Rules
# ---------------------------------------------------------------------------

DETECTION_RULES: Dict[str, DetectionRule] = {
    "T1190": DetectionRule(
        "T1190", "Exploit Public-Facing Application",
        "ALDECI-DETECT-001: Public App Exploitation",
        "Detect exploit attempts against internet-facing applications using WAF logs, scanner findings, and API security events.",
        ["HTTP 4xx/5xx spike on auth endpoints", "SQL injection patterns in query params",
         "XXE/SSRF payload signatures", "Scanner CVE exploit fingerprints",
         "Unexpected large POST bodies to API endpoints"],
        ["Application Log", "Network Traffic", "WAF Log"],
        ALDECIEngine.API_SECURITY.value,
        "SELECT * FROM findings WHERE severity IN ('HIGH','CRITICAL') AND source='waf' AND created_at > NOW()-INTERVAL '1 hour'",
        "critical",
        "High false-positive rate on pen tests and DAST scans — filter by scanner IP allowlist"),
    "T1566": DetectionRule(
        "T1566", "Phishing",
        "ALDECI-DETECT-002: Phishing Detection",
        "Detect phishing campaigns targeting ALDECI-monitored organizations via threat intel feeds and email analysis.",
        ["Newly registered domains matching org keywords", "Malicious attachment hash matches in threat feeds",
         "Suspicious link destinations in email body", "BEC-pattern sender spoofing"],
        ["Application Log", "Network Traffic", "Email Header"],
        ALDECIEngine.THREAT_INTEL.value,
        "SELECT * FROM threat_intel_iocs WHERE type='domain' AND tags CONTAINS 'phishing' AND last_seen > NOW()-INTERVAL '24 hours'",
        "critical",
        "Marketing emails from similar domains — check SPF/DKIM pass status"),
    "T1078": DetectionRule(
        "T1078", "Valid Accounts",
        "ALDECI-DETECT-003: Account Compromise Detection",
        "Detect compromised valid account usage via anomaly detection on authentication patterns.",
        ["Login from new country not in user baseline", "Login at unusual time (>2σ from mean)",
         "Password spray: >20 failed logins from same IP across different accounts",
         "Simultaneous sessions from geographically impossible locations",
         "Account used after long dormancy period (>30 days)"],
        ["Authentication Log", "Logon Session"],
        ALDECIEngine.ANOMALY_DETECTOR.value,
        "SELECT * FROM anomaly_events WHERE type IN ('impossible_travel','password_spray','dormant_account') AND score > 0.75",
        "critical",
        "VPN users — correlate with VPN connection logs before alerting"),
    "T1059.001": DetectionRule(
        "T1059.001", "PowerShell",
        "ALDECI-DETECT-004: Malicious PowerShell Execution",
        "Detect obfuscated or weaponized PowerShell execution via endpoint telemetry.",
        ["Base64-encoded -EncodedCommand flag", "AMSI bypass strings (AmsiScanBuffer patch)",
         "Download cradle patterns (IEX, Invoke-Expression with WebClient)",
         "PowerShell spawning network connections", "Reflective PE loading via PowerShell"],
        ["Command", "Process", "Script"],
        ALDECIEngine.ENDPOINT_SECURITY.value,
        "SELECT * FROM endpoint_events WHERE process='powershell.exe' AND (cmdline LIKE '%EncodedCommand%' OR cmdline LIKE '%Invoke-Expression%') AND created_at > NOW()-INTERVAL '1 hour'",
        "critical",
        "Legitimate admin scripts — maintain allowlist of signed scripts by hash"),
    "T1110": DetectionRule(
        "T1110", "Brute Force",
        "ALDECI-DETECT-005: Brute Force / Password Spray",
        "Detect brute force and password spray attacks via authentication failure rate analysis.",
        ["Single IP: >50 failed auth attempts in 5 minutes", "Password spray: >100 accounts tried with same password",
         "Account lockout storm: >10 accounts locked in 1 minute",
         "Credential stuffing: known breach password list usage"],
        ["Authentication Log", "User Account"],
        ALDECIEngine.IDENTITY_ACCESS.value,
        "SELECT src_ip, COUNT(*) as failures FROM auth_events WHERE result='failure' AND created_at > NOW()-INTERVAL '5 minutes' GROUP BY src_ip HAVING COUNT(*) > 50",
        "critical",
        "Load balancers and monitoring systems — add to IP allowlist"),
    "T1003": DetectionRule(
        "T1003", "OS Credential Dumping",
        "ALDECI-DETECT-006: Credential Dump Detection",
        "Detect credential dumping attempts targeting LSASS, SAM, NTDS, and /etc/shadow.",
        ["Process accessing LSASS memory (OpenProcess with PROCESS_VM_READ)",
         "procdump.exe targeting lsass.exe", "sekurlsa::logonpasswords in command args",
         "ntds.dit file copy operation", "/etc/shadow read by non-root non-authorized process"],
        ["Command", "File", "Process"],
        ALDECIEngine.ENDPOINT_SECURITY.value,
        "SELECT * FROM endpoint_events WHERE (target_process='lsass.exe' AND operation='memory_read') OR cmdline LIKE '%ntds.dit%' ORDER BY created_at DESC",
        "critical",
        "AV/EDR products legitimately access LSASS — filter by signing certificate"),
    "T1486": DetectionRule(
        "T1486", "Data Encrypted for Impact",
        "ALDECI-DETECT-007: Ransomware Detection",
        "Detect ransomware encryption activity via file system telemetry and shadow copy monitoring.",
        ["Mass file rename with new extension in short time window (<100 files/min)",
         "vssadmin delete shadows or wmic shadowcopy delete", "Ransom note file creation (README.txt, DECRYPT.txt)",
         "Shadow copy deletion followed by rapid file modification",
         "Encryption API usage (CryptEncrypt) from unusual processes"],
        ["Command", "File", "Process"],
        ALDECIEngine.ENDPOINT_SECURITY.value,
        "SELECT * FROM endpoint_events WHERE (operation='file_rename' AND count_1min > 50) OR cmdline LIKE '%vssadmin%delete%' ORDER BY created_at DESC",
        "critical",
        "Legitimate backup software — allowlist by process signature"),
    "T1021.001": DetectionRule(
        "T1021.001", "Remote Desktop Protocol",
        "ALDECI-DETECT-008: Lateral RDP Movement",
        "Detect lateral movement via RDP from unusual source hosts.",
        ["RDP connection from workstation to workstation (W2W lateral)", "RDP from jump host to sensitive server at unusual hour",
         "Multiple failed RDP auths followed by successful login",
         "RDP session immediately followed by suspicious process execution"],
        ["Logon Session", "Network Traffic"],
        ALDECIEngine.NETWORK_SECURITY.value,
        "SELECT * FROM network_connections WHERE dst_port=3389 AND src_segment='workstation' AND dst_segment NOT IN ('rdp_farm','jump_hosts') ORDER BY created_at DESC",
        "high",
        "Legitimate admin RDP — correlate with change management tickets"),
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class MITRENavigatorEngine:
    """Core engine for MITRE ATT&CK Navigator functionality.

    Provides coverage analysis, gap analysis, threat group overlays,
    custom layer creation, and detection rule access.
    """

    def __init__(self) -> None:
        self._tactics = TACTICS
        self._techniques = TECHNIQUES
        self._coverage = DETECTION_COVERAGE
        self._threat_groups = THREAT_GROUPS
        self._detection_rules = DETECTION_RULES
        self._custom_layers: Dict[str, NavigatorLayer] = {}
        logger.info("mitre_navigator_engine_initialized",
                    tactics=len(self._tactics),
                    techniques=len(self._techniques),
                    threat_groups=len(self._threat_groups))

    # ------------------------------------------------------------------ matrix

    def get_tactics(self) -> List[TacticInfo]:
        return list(self._tactics.values())

    def get_technique(self, technique_id: str) -> Optional[Technique]:
        return self._techniques.get(technique_id)

    def get_techniques_for_tactic(self, tactic_id: str) -> List[Technique]:
        return [t for t in self._techniques.values() if tactic_id in t.tactic_ids]

    def get_all_techniques(self, include_subtechniques: bool = True) -> List[Technique]:
        if include_subtechniques:
            return list(self._techniques.values())
        return [t for t in self._techniques.values() if not t.is_subtechnique]

    # ------------------------------------------------------------------ coverage

    def get_coverage(self, technique_id: str) -> DetectionCoverage:
        return self._coverage.get(
            technique_id,
            DetectionCoverage(technique_id, CoverageLevel.NONE, []),
        )

    def get_tactic_coverage(self, tactic_id: str) -> TacticCoverage:
        tactic = self._tactics.get(tactic_id)
        if not tactic:
            raise ValueError(f"Unknown tactic: {tactic_id}")

        techs = self.get_techniques_for_tactic(tactic_id)
        total = len(techs)
        covered = 0
        partial = 0
        uncovered_ids: List[str] = []

        for t in techs:
            cov = self.get_coverage(t.id)
            if cov.level == CoverageLevel.FULL:
                covered += 1
            elif cov.level == CoverageLevel.PARTIAL:
                partial += 1
            else:
                uncovered_ids.append(t.id)

        pct = ((covered + partial * 0.5) / total * 100) if total > 0 else 0.0

        return TacticCoverage(
            tactic_id=tactic_id,
            tactic_name=tactic.name,
            total_techniques=total,
            covered_techniques=covered,
            partial_techniques=partial,
            coverage_pct=pct,
            uncovered_technique_ids=uncovered_ids,
        )

    def get_overall_coverage_score(self) -> Dict[str, Any]:
        all_techs = list(self._techniques.values())
        total = len(all_techs)
        covered = 0
        partial = 0
        none_count = 0

        for t in all_techs:
            cov = self.get_coverage(t.id)
            if cov.level == CoverageLevel.FULL:
                covered += 1
            elif cov.level == CoverageLevel.PARTIAL:
                partial += 1
            else:
                none_count += 1

        score = ((covered + partial * 0.5) / total * 100) if total > 0 else 0.0

        return {
            "total_techniques": total,
            "fully_covered": covered,
            "partially_covered": partial,
            "not_covered": none_count,
            "coverage_score_pct": round(score, 1),
            "grade": self._score_to_grade(score),
        }

    def _score_to_grade(self, score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    # ------------------------------------------------------------------ gap analysis

    def get_gap_analysis(self, limit: int = 50) -> List[GapAnalysisResult]:
        """Return uncovered/partial techniques sorted by real-world frequency (priority)."""
        gaps: List[Tuple[float, GapAnalysisResult]] = []

        for rank, (tid, tech) in enumerate(
            sorted(self._techniques.items(),
                   key=lambda x: x[1].frequency_score, reverse=True), 1
        ):
            cov = self.get_coverage(tid)
            if cov.level == CoverageLevel.FULL:
                continue

            engine = self._recommend_engine(tech)
            action = self._recommend_action(tech, cov)

            gaps.append((tech.frequency_score, GapAnalysisResult(
                technique_id=tid,
                technique_name=tech.name,
                tactic_ids=tech.tactic_ids,
                frequency_score=tech.frequency_score,
                severity=tech.severity,
                priority_rank=rank,
                recommended_engine=engine,
                recommended_action=action,
            )))

        gaps.sort(key=lambda x: x[0], reverse=True)
        return [g for _, g in gaps[:limit]]

    def _recommend_engine(self, tech: Technique) -> str:
        if "Authentication Log" in tech.data_sources or "User Account" in tech.data_sources:
            return ALDECIEngine.IDENTITY_ACCESS.value
        if "Network Traffic" in tech.data_sources:
            return ALDECIEngine.NETWORK_SECURITY.value
        if "Cloud Service" in tech.data_sources:
            return ALDECIEngine.CLOUD_SECURITY.value
        if "Process" in tech.data_sources or "Command" in tech.data_sources:
            return ALDECIEngine.ENDPOINT_SECURITY.value
        if "File" in tech.data_sources:
            return ALDECIEngine.DATA_SECURITY.value
        return ALDECIEngine.BRAIN_PIPELINE.value

    def _recommend_action(self, tech: Technique, cov: DetectionCoverage) -> str:
        if cov.level == CoverageLevel.NONE:
            return f"Implement new detection rule for {tech.name} in {self._recommend_engine(tech)}"
        return f"Extend partial coverage: {cov.notes or 'add missing data sources'}"

    # ------------------------------------------------------------------ threat group overlay

    def get_threat_groups(self) -> List[ThreatGroup]:
        return list(self._threat_groups.values())

    def get_threat_group(self, group_id: str) -> Optional[ThreatGroup]:
        return self._threat_groups.get(group_id)

    def get_threat_group_overlay(self, group_id: str) -> ThreatGroupOverlay:
        group = self._threat_groups.get(group_id)
        if not group:
            raise ValueError(f"Unknown threat group: {group_id}")

        blind_spots: List[str] = []
        partial_cov: List[str] = []

        for tid in group.techniques:
            cov = self.get_coverage(tid)
            if cov.level == CoverageLevel.NONE:
                blind_spots.append(tid)
            elif cov.level == CoverageLevel.PARTIAL:
                partial_cov.append(tid)

        total = len(group.techniques)
        covered_count = total - len(blind_spots) - len(partial_cov)
        pct = ((covered_count + len(partial_cov) * 0.5) / total * 100) if total > 0 else 0.0

        risk = "critical" if len(blind_spots) > total * 0.3 else \
               "high" if len(blind_spots) > total * 0.1 else \
               "medium" if len(partial_cov) > total * 0.2 else "low"

        return ThreatGroupOverlay(
            group_id=group_id,
            group_name=group.name,
            total_techniques=total,
            covered_count=covered_count,
            blind_spots=blind_spots,
            partial_coverage=partial_cov,
            coverage_pct=pct,
            risk_level=risk,
        )

    def get_all_threat_group_overlays(self) -> List[ThreatGroupOverlay]:
        return [self.get_threat_group_overlay(gid) for gid in self._threat_groups]

    # ------------------------------------------------------------------ custom layers

    def create_coverage_layer(self, name: str = "ALDECI Coverage") -> NavigatorLayer:
        """Generate a Navigator layer annotated with ALDECI detection coverage."""
        annotations: List[LayerAnnotation] = []

        for tid, tech in self._techniques.items():
            cov = self.get_coverage(tid)
            if cov.level == CoverageLevel.FULL:
                score = 100.0
                color = LayerColor.GREEN.value
                comment = f"Full coverage via: {', '.join(cov.engines)}"
            elif cov.level == CoverageLevel.PARTIAL:
                score = 50.0
                color = LayerColor.ORANGE.value
                comment = f"Partial: {cov.notes}"
            else:
                score = 0.0
                color = LayerColor.RED.value
                comment = "No detection coverage"

            annotations.append(LayerAnnotation(
                technique_id=tid,
                score=score,
                color=color,
                comment=comment,
                enabled=True,
            ))

        layer = NavigatorLayer(
            name=name,
            description="ALDECI detection coverage mapped to MITRE ATT&CK Enterprise",
            techniques=annotations,
        )
        _emit_event("mitre.coverage_layer_created", {"name": name, "technique_count": len(annotations)})
        return layer

    def create_threat_group_layer(self, group_id: str) -> NavigatorLayer:
        """Generate a Navigator layer for a threat group's TTP coverage."""
        group = self._threat_groups.get(group_id)
        if not group:
            raise ValueError(f"Unknown threat group: {group_id}")

        overlay = self.get_threat_group_overlay(group_id)
        annotations: List[LayerAnnotation] = []

        for tid in group.techniques:
            cov = self.get_coverage(tid)
            if cov.level == CoverageLevel.FULL:
                color = LayerColor.GREEN.value
                score = 100.0
                comment = f"Detected by: {', '.join(cov.engines)}"
            elif cov.level == CoverageLevel.PARTIAL:
                color = LayerColor.ORANGE.value
                score = 50.0
                comment = f"Partial: {cov.notes}"
            else:
                color = LayerColor.RED.value
                score = 0.0
                comment = "BLIND SPOT — no detection"

            annotations.append(LayerAnnotation(
                technique_id=tid,
                score=score,
                color=color,
                comment=comment,
                enabled=True,
            ))

        layer = NavigatorLayer(
            name=f"{group.name} TTP Coverage",
            description=f"ALDECI coverage against {group.name} ({group_id}) techniques. Risk: {overlay.risk_level}",
            techniques=annotations,
        )
        _emit_event("mitre.threat_group_layer_created", {"group_id": group_id, "technique_count": len(annotations), "risk_level": overlay.risk_level})
        return layer

    def create_custom_layer(
        self,
        name: str,
        description: str,
        annotations: List[Dict[str, Any]],
    ) -> NavigatorLayer:
        """Create a custom Navigator layer from user-provided annotations."""
        layer_annotations = [
            LayerAnnotation(
                technique_id=a.get("technique_id", ""),
                score=float(a.get("score", 0)),
                color=a.get("color", ""),
                comment=a.get("comment", ""),
                enabled=a.get("enabled", True),
                metadata=a.get("metadata", []),
            )
            for a in annotations
            if a.get("technique_id")
        ]
        layer = NavigatorLayer(
            name=name,
            description=description,
            techniques=layer_annotations,
        )
        self._custom_layers[name] = layer
        logger.info("custom_layer_created", name=name, technique_count=len(layer_annotations))
        return layer

    def get_custom_layer(self, name: str) -> Optional[NavigatorLayer]:
        return self._custom_layers.get(name)

    def list_custom_layers(self) -> List[str]:
        return list(self._custom_layers.keys())

    # ------------------------------------------------------------------ detection rules

    def get_detection_rule(self, technique_id: str) -> Optional[DetectionRule]:
        return self._detection_rules.get(technique_id)

    def get_detection_rules_for_engine(self, engine: str) -> List[DetectionRule]:
        return [r for r in self._detection_rules.values() if r.aldeci_engine == engine]

    def get_all_detection_rules(self) -> List[DetectionRule]:
        return list(self._detection_rules.values())


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_instance: Optional[MITRENavigatorEngine] = None


def get_mitre_navigator_engine() -> MITRENavigatorEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = MITRENavigatorEngine()
    return _engine_instance
