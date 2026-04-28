"""
ALDECI Purple Team Exercise Engine.

Collaborative red + blue team exercises with MITRE ATT&CK mapping.
Covers exercise lifecycle, 30+ pre-built attack scenarios, detection
validation, blue team response tracking, gap identification, scoring,
and after-action report generation.

Pure Python — Pydantic v2, structlog, no external API calls required.
"""

from __future__ import annotations

import statistics
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

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


class ExerciseStatus(str, Enum):
    DRAFT = "draft"
    PLANNED = "planned"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class ScenarioCategory(str, Enum):
    PHISHING_TO_EXFIL = "phishing_to_exfil"
    SUPPLY_CHAIN = "supply_chain"
    RANSOMWARE = "ransomware"
    INSIDER_THREAT = "insider_threat"
    CLOUD_BREACH = "cloud_breach"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_ATTACK = "credential_attack"
    WEB_APP_ATTACK = "web_app_attack"
    PHYSICAL_CYBER = "physical_cyber"
    ZERO_DAY = "zero_day"


class StepOutcome(str, Enum):
    NOT_STARTED = "not_started"
    EXECUTED = "executed"
    DETECTED = "detected"
    BLOCKED = "blocked"
    MISSED = "missed"


class DetectionEngine(str, Enum):
    SIEM = "siem"
    EDR = "edr"
    NDR = "ndr"
    SOAR = "soar"
    THREAT_INTEL = "threat_intel"
    ANOMALY = "anomaly"
    MANUAL = "manual"
    NONE = "none"


class ContainmentAction(str, Enum):
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    REVOKE_TOKEN = "revoke_token"
    QUARANTINE_FILE = "quarantine_file"
    FIREWALL_RULE = "firewall_rule"
    PATCH_APPLIED = "patch_applied"
    ESCALATE = "escalate"
    MONITOR = "monitor"


class ExerciseScope(str, Enum):
    FULL = "full"          # All ALDECI detection surfaces
    EDR_ONLY = "edr_only"
    NETWORK = "network"
    CLOUD = "cloud"
    IDENTITY = "identity"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Registry
# ---------------------------------------------------------------------------

MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1566":   {"name": "Phishing",                              "tactic": "initial_access",        "severity": 0.80},
    "T1566.001": {"name": "Spearphishing Attachment",            "tactic": "initial_access",        "severity": 0.82},
    "T1566.002": {"name": "Spearphishing Link",                  "tactic": "initial_access",        "severity": 0.78},
    "T1059":   {"name": "Command and Scripting Interpreter",     "tactic": "execution",             "severity": 0.70},
    "T1059.001": {"name": "PowerShell",                          "tactic": "execution",             "severity": 0.75},
    "T1059.003": {"name": "Windows Command Shell",               "tactic": "execution",             "severity": 0.65},
    "T1047":   {"name": "Windows Management Instrumentation",    "tactic": "execution",             "severity": 0.60},
    "T1053":   {"name": "Scheduled Task/Job",                    "tactic": "persistence",           "severity": 0.55},
    "T1136":   {"name": "Create Account",                        "tactic": "persistence",           "severity": 0.65},
    "T1547":   {"name": "Boot or Logon Autostart Execution",     "tactic": "persistence",           "severity": 0.70},
    "T1098":   {"name": "Account Manipulation",                  "tactic": "persistence",           "severity": 0.70},
    "T1068":   {"name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation",  "severity": 0.90},
    "T1548":   {"name": "Abuse Elevation Control Mechanism",     "tactic": "privilege_escalation",  "severity": 0.80},
    "T1134":   {"name": "Access Token Manipulation",             "tactic": "privilege_escalation",  "severity": 0.75},
    "T1021":   {"name": "Remote Services",                       "tactic": "lateral_movement",      "severity": 0.70},
    "T1021.001": {"name": "Remote Desktop Protocol",             "tactic": "lateral_movement",      "severity": 0.72},
    "T1550":   {"name": "Use Alternate Authentication Material", "tactic": "lateral_movement",      "severity": 0.80},
    "T1550.002": {"name": "Pass the Hash",                       "tactic": "lateral_movement",      "severity": 0.82},
    "T1210":   {"name": "Exploitation of Remote Services",       "tactic": "lateral_movement",      "severity": 0.88},
    "T1041":   {"name": "Exfiltration Over C2 Channel",         "tactic": "exfiltration",          "severity": 0.80},
    "T1048":   {"name": "Exfiltration Over Alt Protocol",       "tactic": "exfiltration",          "severity": 0.70},
    "T1567":   {"name": "Exfiltration Over Web Service",        "tactic": "exfiltration",          "severity": 0.75},
    "T1537":   {"name": "Transfer Data to Cloud Account",        "tactic": "exfiltration",          "severity": 0.85},
    "T1195":   {"name": "Supply Chain Compromise",               "tactic": "initial_access",        "severity": 0.95},
    "T1195.002": {"name": "Compromise Software Supply Chain",    "tactic": "initial_access",        "severity": 0.95},
    "T1486":   {"name": "Data Encrypted for Impact",             "tactic": "impact",                "severity": 0.95},
    "T1490":   {"name": "Inhibit System Recovery",               "tactic": "impact",                "severity": 0.90},
    "T1078":   {"name": "Valid Accounts",                        "tactic": "initial_access",        "severity": 0.80},
    "T1078.002": {"name": "Domain Accounts",                     "tactic": "initial_access",        "severity": 0.82},
    "T1110":   {"name": "Brute Force",                           "tactic": "credential_access",     "severity": 0.60},
    "T1110.003": {"name": "Password Spraying",                   "tactic": "credential_access",     "severity": 0.65},
    "T1555":   {"name": "Credentials from Password Stores",      "tactic": "credential_access",     "severity": 0.75},
    "T1552":   {"name": "Unsecured Credentials",                 "tactic": "credential_access",     "severity": 0.70},
    "T1190":   {"name": "Exploit Public-Facing Application",     "tactic": "initial_access",        "severity": 0.88},
    "T1133":   {"name": "External Remote Services",              "tactic": "initial_access",        "severity": 0.72},
    "T1071":   {"name": "Application Layer Protocol",            "tactic": "command_and_control",   "severity": 0.60},
    "T1573":   {"name": "Encrypted Channel",                     "tactic": "command_and_control",   "severity": 0.55},
    "T1105":   {"name": "Ingress Tool Transfer",                 "tactic": "command_and_control",   "severity": 0.65},
    "T1530":   {"name": "Data from Cloud Storage",               "tactic": "collection",            "severity": 0.72},
    "T1619":   {"name": "Cloud Storage Object Discovery",        "tactic": "discovery",             "severity": 0.50},
    "T1552.005": {"name": "Cloud Instance Metadata API",         "tactic": "credential_access",     "severity": 0.80},
    "T1525":   {"name": "Implant Internal Image",                "tactic": "persistence",           "severity": 0.85},
}


# ---------------------------------------------------------------------------
# Pre-built Scenario Library
# ---------------------------------------------------------------------------

SCENARIO_LIBRARY: List[Dict[str, Any]] = [
    # ---- Phishing → Lateral Movement → Exfil ----
    {
        "scenario_id": "sc-001",
        "name": "Spearphishing to Data Exfiltration",
        "category": ScenarioCategory.PHISHING_TO_EXFIL,
        "description": "Targeted spearphishing email delivers macro payload; attacker pivots to domain controller and exfils sensitive data.",
        "threat_actor": "cybercriminal",
        "difficulty": "medium",
        "estimated_duration_minutes": 90,
        "steps": [
            {"technique_id": "T1566.001", "description": "Send spearphishing attachment with malicious macro", "target": "end_user_workstation"},
            {"technique_id": "T1059.001", "description": "Macro executes PowerShell downloader", "target": "end_user_workstation"},
            {"technique_id": "T1105",     "description": "Download C2 implant via HTTPS", "target": "end_user_workstation"},
            {"technique_id": "T1547",     "description": "Establish persistence via registry run key", "target": "end_user_workstation"},
            {"technique_id": "T1110.003", "description": "Password spray against AD", "target": "active_directory"},
            {"technique_id": "T1550.002", "description": "Pass-the-Hash to pivot to file server", "target": "file_server"},
            {"technique_id": "T1041",     "description": "Exfiltrate data over C2 channel", "target": "file_server"},
        ],
    },
    {
        "scenario_id": "sc-002",
        "name": "Business Email Compromise (BEC)",
        "category": ScenarioCategory.PHISHING_TO_EXFIL,
        "description": "Attacker compromises executive email via OAuth token theft and manipulates finance workflows.",
        "threat_actor": "cybercriminal",
        "difficulty": "medium",
        "estimated_duration_minutes": 60,
        "steps": [
            {"technique_id": "T1566.002", "description": "Phishing link to fake OAuth consent page", "target": "executive_workstation"},
            {"technique_id": "T1078",     "description": "Use stolen OAuth token to access email", "target": "email_service"},
            {"technique_id": "T1552",     "description": "Search email for credentials and financial data", "target": "email_service"},
            {"technique_id": "T1567",     "description": "Exfiltrate emails via web service", "target": "email_service"},
        ],
    },
    # ---- Supply Chain ----
    {
        "scenario_id": "sc-003",
        "name": "SolarWinds-Style Supply Chain",
        "category": ScenarioCategory.SUPPLY_CHAIN,
        "description": "Trojanised software update distributed to all customers; attacker leverages trusted software signing.",
        "threat_actor": "nation_state",
        "difficulty": "critical",
        "estimated_duration_minutes": 240,
        "steps": [
            {"technique_id": "T1195.002", "description": "Compromise build pipeline; inject backdoor into update", "target": "build_server"},
            {"technique_id": "T1525",     "description": "Deploy malicious container image to registry", "target": "container_registry"},
            {"technique_id": "T1078.002", "description": "Use domain account from environment variable leak", "target": "internal_network"},
            {"technique_id": "T1071",     "description": "Beacon to C2 over HTTPS", "target": "corporate_workstations"},
            {"technique_id": "T1537",     "description": "Transfer sensitive data to cloud account", "target": "cloud_storage"},
        ],
    },
    {
        "scenario_id": "sc-004",
        "name": "Open Source Dependency Poisoning",
        "category": ScenarioCategory.SUPPLY_CHAIN,
        "description": "Malicious npm/PyPI package with typosquatting compromises CI/CD pipeline.",
        "threat_actor": "cybercriminal",
        "difficulty": "high",
        "estimated_duration_minutes": 120,
        "steps": [
            {"technique_id": "T1195",     "description": "Publish malicious lookalike package to public registry", "target": "ci_cd_pipeline"},
            {"technique_id": "T1059",     "description": "Malicious package runs shell command on install", "target": "build_server"},
            {"technique_id": "T1552.005", "description": "Steal cloud credentials from CI environment variables", "target": "ci_cd_pipeline"},
            {"technique_id": "T1530",     "description": "Access cloud storage with stolen credentials", "target": "cloud_storage"},
        ],
    },
    # ---- Ransomware ----
    {
        "scenario_id": "sc-005",
        "name": "Ransomware: Initial Access to Encryption",
        "category": ScenarioCategory.RANSOMWARE,
        "description": "Full ransomware kill chain from phishing to mass encryption with backup deletion.",
        "threat_actor": "ransomware_group",
        "difficulty": "critical",
        "estimated_duration_minutes": 180,
        "steps": [
            {"technique_id": "T1566.001", "description": "Spearphishing with LNK dropper", "target": "end_user_workstation"},
            {"technique_id": "T1059.003", "description": "CMD executes encoded payload", "target": "end_user_workstation"},
            {"technique_id": "T1548",     "description": "UAC bypass for elevated execution", "target": "end_user_workstation"},
            {"technique_id": "T1021.001", "description": "RDP lateral movement to servers", "target": "file_servers"},
            {"technique_id": "T1490",     "description": "Delete shadow copies and backups", "target": "file_servers"},
            {"technique_id": "T1486",     "description": "Encrypt all files with AES-256", "target": "file_servers"},
        ],
    },
    {
        "scenario_id": "sc-006",
        "name": "Double Extortion Ransomware",
        "category": ScenarioCategory.RANSOMWARE,
        "description": "Attacker exfiltrates data before encrypting, enabling two-pronged extortion.",
        "threat_actor": "ransomware_group",
        "difficulty": "critical",
        "estimated_duration_minutes": 240,
        "steps": [
            {"technique_id": "T1190",     "description": "Exploit VPN vulnerability for initial access", "target": "vpn_gateway"},
            {"technique_id": "T1078",     "description": "Use valid VPN credentials to access network", "target": "internal_network"},
            {"technique_id": "T1210",     "description": "Exploit SMB vulnerability for lateral movement", "target": "internal_servers"},
            {"technique_id": "T1041",     "description": "Exfiltrate sensitive files to C2", "target": "file_servers"},
            {"technique_id": "T1490",     "description": "Disable backup services and VSS", "target": "file_servers"},
            {"technique_id": "T1486",     "description": "Deploy ransomware encryptor across network", "target": "enterprise_wide"},
        ],
    },
    # ---- Insider Threat ----
    {
        "scenario_id": "sc-007",
        "name": "Malicious Insider — Data Theft",
        "category": ScenarioCategory.INSIDER_THREAT,
        "description": "Disgruntled employee exfiltrates intellectual property before resignation.",
        "threat_actor": "insider",
        "difficulty": "medium",
        "estimated_duration_minutes": 120,
        "steps": [
            {"technique_id": "T1078",     "description": "Log in with legitimate credentials after hours", "target": "file_server"},
            {"technique_id": "T1530",     "description": "Access cloud storage buckets outside normal scope", "target": "cloud_storage"},
            {"technique_id": "T1567",     "description": "Upload files to personal cloud drive", "target": "cloud_storage"},
            {"technique_id": "T1048",     "description": "Exfiltrate via personal email SMTP", "target": "email_gateway"},
        ],
    },
    {
        "scenario_id": "sc-008",
        "name": "Insider Privilege Abuse — Sabotage",
        "category": ScenarioCategory.INSIDER_THREAT,
        "description": "Privileged admin abuses access to corrupt databases before departing.",
        "threat_actor": "insider",
        "difficulty": "high",
        "estimated_duration_minutes": 90,
        "steps": [
            {"technique_id": "T1078.002", "description": "Use admin account to access production systems", "target": "database_server"},
            {"technique_id": "T1136",     "description": "Create hidden backdoor admin account", "target": "active_directory"},
            {"technique_id": "T1098",     "description": "Add attacker account to privileged groups", "target": "active_directory"},
            {"technique_id": "T1486",     "description": "Corrupt critical database records", "target": "database_server"},
        ],
    },
    # ---- Cloud Breach ----
    {
        "scenario_id": "sc-009",
        "name": "AWS IAM Privilege Escalation",
        "category": ScenarioCategory.CLOUD_BREACH,
        "description": "Attacker gains initial foothold via exposed access key and escalates to admin via IAM misconfiguration.",
        "threat_actor": "cybercriminal",
        "difficulty": "high",
        "estimated_duration_minutes": 90,
        "steps": [
            {"technique_id": "T1552.005", "description": "Steal AWS credentials from instance metadata", "target": "ec2_instance"},
            {"technique_id": "T1619",     "description": "Enumerate S3 buckets and IAM policies", "target": "aws_environment"},
            {"technique_id": "T1068",     "description": "Exploit IAM policy misconfiguration for admin access", "target": "aws_iam"},
            {"technique_id": "T1530",     "description": "Access sensitive data from all S3 buckets", "target": "s3_storage"},
            {"technique_id": "T1537",     "description": "Transfer data to attacker-controlled cloud account", "target": "cloud_egress"},
        ],
    },
    {
        "scenario_id": "sc-010",
        "name": "Kubernetes Cluster Compromise",
        "category": ScenarioCategory.CLOUD_BREACH,
        "description": "Unauthenticated Kubelet API leads to full cluster takeover and crypto-mining deployment.",
        "threat_actor": "cybercriminal",
        "difficulty": "high",
        "estimated_duration_minutes": 120,
        "steps": [
            {"technique_id": "T1190",     "description": "Access exposed Kubernetes API server", "target": "k8s_api"},
            {"technique_id": "T1552.005", "description": "Steal service account tokens from pods", "target": "k8s_pods"},
            {"technique_id": "T1525",     "description": "Deploy malicious container image", "target": "k8s_cluster"},
            {"technique_id": "T1105",     "description": "Download crypto-miner to compromised nodes", "target": "k8s_nodes"},
        ],
    },
    {
        "scenario_id": "sc-011",
        "name": "Azure AD Consent Grant Attack",
        "category": ScenarioCategory.CLOUD_BREACH,
        "description": "Attacker registers malicious OAuth app and tricks users into granting broad permissions.",
        "threat_actor": "nation_state",
        "difficulty": "high",
        "estimated_duration_minutes": 60,
        "steps": [
            {"technique_id": "T1566.002", "description": "Phishing link to malicious OAuth app consent page", "target": "end_users"},
            {"technique_id": "T1078",     "description": "Access M365 tenant with delegated permissions", "target": "m365_tenant"},
            {"technique_id": "T1552",     "description": "Read emails and SharePoint files", "target": "m365_tenant"},
            {"technique_id": "T1567",     "description": "Exfiltrate via Graph API to attacker server", "target": "cloud_egress"},
        ],
    },
    {
        "scenario_id": "sc-012",
        "name": "GCP Service Account Key Abuse",
        "category": ScenarioCategory.CLOUD_BREACH,
        "description": "Exposed GCP service account key leads to BigQuery data breach.",
        "threat_actor": "cybercriminal",
        "difficulty": "medium",
        "estimated_duration_minutes": 60,
        "steps": [
            {"technique_id": "T1552",     "description": "Find GCP service account key in public GitHub repo", "target": "public_repo"},
            {"technique_id": "T1619",     "description": "Enumerate GCP resources with stolen key", "target": "gcp_environment"},
            {"technique_id": "T1530",     "description": "Export BigQuery datasets", "target": "bigquery"},
        ],
    },
    # ---- Lateral Movement Focus ----
    {
        "scenario_id": "sc-013",
        "name": "Active Directory Golden Ticket",
        "category": ScenarioCategory.LATERAL_MOVEMENT,
        "description": "Attacker obtains KRBTGT hash and forges Kerberos tickets for persistent domain dominance.",
        "threat_actor": "apt",
        "difficulty": "critical",
        "estimated_duration_minutes": 180,
        "steps": [
            {"technique_id": "T1566.001", "description": "Initial access via phishing", "target": "workstation"},
            {"technique_id": "T1068",     "description": "Local privilege escalation to SYSTEM", "target": "workstation"},
            {"technique_id": "T1210",     "description": "Lateral movement to domain controller", "target": "domain_controller"},
            {"technique_id": "T1550",     "description": "Dump KRBTGT hash from NTDS.dit", "target": "domain_controller"},
            {"technique_id": "T1550.002", "description": "Forge golden ticket for any domain account", "target": "active_directory"},
            {"technique_id": "T1021.001", "description": "RDP to all hosts using golden ticket", "target": "enterprise_wide"},
        ],
    },
    {
        "scenario_id": "sc-014",
        "name": "Pass-the-Hash Lateral Sweep",
        "category": ScenarioCategory.LATERAL_MOVEMENT,
        "description": "NTLM hash harvested from one workstation enables lateral movement across the environment.",
        "threat_actor": "cybercriminal",
        "difficulty": "medium",
        "estimated_duration_minutes": 90,
        "steps": [
            {"technique_id": "T1110",     "description": "Brute-force local admin account", "target": "workstation"},
            {"technique_id": "T1555",     "description": "Dump cached credentials from LSASS", "target": "workstation"},
            {"technique_id": "T1550.002", "description": "Pass-the-Hash to file server", "target": "file_server"},
            {"technique_id": "T1021.001", "description": "RDP pivot to jump server", "target": "jump_server"},
            {"technique_id": "T1041",     "description": "Exfiltrate sensitive documents", "target": "file_server"},
        ],
    },
    # ---- Credential Attack ----
    {
        "scenario_id": "sc-015",
        "name": "Password Spray → MFA Fatigue",
        "category": ScenarioCategory.CREDENTIAL_ATTACK,
        "description": "Password spray against external login page followed by MFA push fatigue attack.",
        "threat_actor": "cybercriminal",
        "difficulty": "medium",
        "estimated_duration_minutes": 60,
        "steps": [
            {"technique_id": "T1110.003", "description": "Password spray against Azure AD login", "target": "azure_ad"},
            {"technique_id": "T1078",     "description": "Authenticate with valid credentials after spray", "target": "cloud_tenant"},
            {"technique_id": "T1133",     "description": "Access VPN using compromised credentials", "target": "vpn_gateway"},
            {"technique_id": "T1552",     "description": "Access internal resources and harvest more credentials", "target": "internal_network"},
        ],
    },
    {
        "scenario_id": "sc-016",
        "name": "Kerberoasting",
        "category": ScenarioCategory.CREDENTIAL_ATTACK,
        "description": "Domain user requests service tickets for SPNs and cracks offline to obtain service account passwords.",
        "threat_actor": "cybercriminal",
        "difficulty": "medium",
        "estimated_duration_minutes": 60,
        "steps": [
            {"technique_id": "T1078",     "description": "Access domain with any valid user account", "target": "active_directory"},
            {"technique_id": "T1558.003", "description": "Request Kerberos service tickets for high-value SPNs", "target": "active_directory"},
            {"technique_id": "T1110",     "description": "Offline crack of service ticket hashes", "target": "attacker_machine"},
            {"technique_id": "T1078.002", "description": "Authenticate as service account", "target": "internal_services"},
            {"technique_id": "T1068",     "description": "Exploit service account privileges for escalation", "target": "servers"},
        ],
    },
    # ---- Web App Attack ----
    {
        "scenario_id": "sc-017",
        "name": "SQL Injection to Server Takeover",
        "category": ScenarioCategory.WEB_APP_ATTACK,
        "description": "SQLi vulnerability in web app exploited to read database, then OS command injection for full server control.",
        "threat_actor": "cybercriminal",
        "difficulty": "medium",
        "estimated_duration_minutes": 90,
        "steps": [
            {"technique_id": "T1190",     "description": "Identify and exploit SQL injection in login form", "target": "web_application"},
            {"technique_id": "T1552",     "description": "Dump credentials and PII from database", "target": "database_server"},
            {"technique_id": "T1059",     "description": "OS command injection via xp_cmdshell", "target": "database_server"},
            {"technique_id": "T1105",     "description": "Download reverse shell to database server", "target": "database_server"},
            {"technique_id": "T1041",     "description": "Exfiltrate customer data", "target": "database_server"},
        ],
    },
    {
        "scenario_id": "sc-018",
        "name": "SSRF to Cloud Metadata Exfiltration",
        "category": ScenarioCategory.WEB_APP_ATTACK,
        "description": "Server-Side Request Forgery used to access cloud metadata API and steal IAM credentials.",
        "threat_actor": "cybercriminal",
        "difficulty": "medium",
        "estimated_duration_minutes": 60,
        "steps": [
            {"technique_id": "T1190",     "description": "Exploit SSRF in image processing endpoint", "target": "web_application"},
            {"technique_id": "T1552.005", "description": "Access EC2 metadata API via SSRF", "target": "cloud_metadata"},
            {"technique_id": "T1619",     "description": "Enumerate AWS resources with stolen role credentials", "target": "aws_environment"},
            {"technique_id": "T1530",     "description": "Download sensitive data from S3 buckets", "target": "s3_storage"},
        ],
    },
    # ---- APT / Nation State ----
    {
        "scenario_id": "sc-019",
        "name": "APT29-Style Cozy Bear Campaign",
        "category": ScenarioCategory.PHISHING_TO_EXFIL,
        "description": "Nation-state spearphishing with NOBELIUM-style techniques targeting government supply chain.",
        "threat_actor": "nation_state",
        "difficulty": "critical",
        "estimated_duration_minutes": 360,
        "steps": [
            {"technique_id": "T1566.001", "description": "HTML smuggling spearphish to government target", "target": "target_workstation"},
            {"technique_id": "T1059.001", "description": "PowerShell execution with AMSI bypass", "target": "target_workstation"},
            {"technique_id": "T1573",     "description": "Encrypted C2 over HTTPS with domain fronting", "target": "target_workstation"},
            {"technique_id": "T1547",     "description": "COM object hijacking for persistence", "target": "target_workstation"},
            {"technique_id": "T1210",     "description": "Zero-day exploitation for lateral movement", "target": "internal_network"},
            {"technique_id": "T1041",     "description": "Long-duration stealth exfiltration", "target": "data_stores"},
        ],
    },
    {
        "scenario_id": "sc-020",
        "name": "Lazarus Group Financial Attack",
        "category": ScenarioCategory.PHISHING_TO_EXFIL,
        "description": "North Korean TTPs targeting financial institutions via SWIFT network compromise.",
        "threat_actor": "nation_state",
        "difficulty": "critical",
        "estimated_duration_minutes": 480,
        "steps": [
            {"technique_id": "T1566.001", "description": "Watering hole attack via finance industry website", "target": "finance_workstation"},
            {"technique_id": "T1203",     "description": "Browser exploit for initial code execution", "target": "finance_workstation"},
            {"technique_id": "T1105",     "description": "Download FALLCHILL/HARDRAIN implant", "target": "finance_workstation"},
            {"technique_id": "T1021",     "description": "Lateral movement to SWIFT operator workstation", "target": "swift_workstation"},
            {"technique_id": "T1041",     "description": "Fraudulent SWIFT transaction initiation", "target": "swift_network"},
        ],
    },
    # ---- Zero Day / Advanced ----
    {
        "scenario_id": "sc-021",
        "name": "Zero-Day Browser RCE",
        "category": ScenarioCategory.ZERO_DAY,
        "description": "Watering hole with browser zero-day achieves RCE without user interaction.",
        "threat_actor": "nation_state",
        "difficulty": "critical",
        "estimated_duration_minutes": 120,
        "steps": [
            {"technique_id": "T1189",     "description": "Drive-by compromise via compromised industry website", "target": "browser"},
            {"technique_id": "T1203",     "description": "Zero-day browser exploit for sandbox escape", "target": "workstation"},
            {"technique_id": "T1055",     "description": "Process injection into svchost.exe", "target": "workstation"},
            {"technique_id": "T1071",     "description": "C2 beacon over DNS-over-HTTPS", "target": "workstation"},
        ],
    },
    {
        "scenario_id": "sc-022",
        "name": "Log4Shell Mass Exploitation",
        "category": ScenarioCategory.WEB_APP_ATTACK,
        "description": "Log4j JNDI injection exploited across all internet-facing Java applications.",
        "threat_actor": "cybercriminal",
        "difficulty": "high",
        "estimated_duration_minutes": 120,
        "steps": [
            {"technique_id": "T1190",     "description": "Log4Shell JNDI injection via User-Agent header", "target": "java_application"},
            {"technique_id": "T1059",     "description": "Remote code execution via LDAP callback", "target": "java_application"},
            {"technique_id": "T1136",     "description": "Create backdoor user account on server", "target": "application_server"},
            {"technique_id": "T1021",     "description": "SSH lateral movement using harvested keys", "target": "internal_servers"},
        ],
    },
    # ---- Physical-Cyber ----
    {
        "scenario_id": "sc-023",
        "name": "USB Drop Attack",
        "category": ScenarioCategory.PHYSICAL_CYBER,
        "description": "Malicious USB dropped in parking lot with HID attack payload.",
        "threat_actor": "cybercriminal",
        "difficulty": "medium",
        "estimated_duration_minutes": 90,
        "steps": [
            {"technique_id": "T1052",     "description": "Employee plugs in attacker USB device", "target": "workstation"},
            {"technique_id": "T1059.001", "description": "HID emulation runs PowerShell payload", "target": "workstation"},
            {"technique_id": "T1547",     "description": "Persistence via startup folder", "target": "workstation"},
            {"technique_id": "T1071",     "description": "Reverse shell over corporate network", "target": "workstation"},
        ],
    },
    # ---- Additional Scenarios ----
    {
        "scenario_id": "sc-024",
        "name": "Ransomware-as-a-Service (RaaS) Affiliate",
        "category": ScenarioCategory.RANSOMWARE,
        "description": "RaaS affiliate using commodity tools and living-off-the-land techniques.",
        "threat_actor": "ransomware_group",
        "difficulty": "high",
        "estimated_duration_minutes": 180,
        "steps": [
            {"technique_id": "T1133",     "description": "Initial access via compromised RDP credentials", "target": "rdp_endpoint"},
            {"technique_id": "T1047",     "description": "WMI for reconnaissance and lateral movement", "target": "internal_network"},
            {"technique_id": "T1053",     "description": "Scheduled tasks for ransomware execution", "target": "all_endpoints"},
            {"technique_id": "T1490",     "description": "Disable Windows Defender and backup services", "target": "all_endpoints"},
            {"technique_id": "T1486",     "description": "Deploy ransomware via scheduled task", "target": "enterprise_wide"},
        ],
    },
    {
        "scenario_id": "sc-025",
        "name": "CI/CD Pipeline Compromise",
        "category": ScenarioCategory.SUPPLY_CHAIN,
        "description": "Attacker compromises GitHub Actions workflow to inject malicious code into production.",
        "threat_actor": "cybercriminal",
        "difficulty": "high",
        "estimated_duration_minutes": 120,
        "steps": [
            {"technique_id": "T1552",     "description": "Extract GitHub PAT from leaked .env file", "target": "github_repo"},
            {"technique_id": "T1195.002", "description": "Modify GitHub Actions workflow to inject malicious steps", "target": "ci_cd_pipeline"},
            {"technique_id": "T1552",     "description": "Steal production secrets from CI environment", "target": "ci_cd_pipeline"},
            {"technique_id": "T1537",     "description": "Exfiltrate secrets to attacker-controlled endpoint", "target": "cloud_egress"},
        ],
    },
    {
        "scenario_id": "sc-026",
        "name": "Multi-Cloud Pivot Attack",
        "category": ScenarioCategory.CLOUD_BREACH,
        "description": "Attacker compromises one cloud account and pivots across AWS, Azure, and GCP.",
        "threat_actor": "apt",
        "difficulty": "critical",
        "estimated_duration_minutes": 300,
        "steps": [
            {"technique_id": "T1552",     "description": "Find cross-cloud credentials in Terraform state file", "target": "terraform_backend"},
            {"technique_id": "T1619",     "description": "Enumerate all cloud environments", "target": "multi_cloud"},
            {"technique_id": "T1530",     "description": "Access sensitive data across all cloud providers", "target": "cloud_storage"},
            {"technique_id": "T1537",     "description": "Exfiltrate data to attacker infrastructure", "target": "cloud_egress"},
        ],
    },
    {
        "scenario_id": "sc-027",
        "name": "Fileless Malware via LOLBins",
        "category": ScenarioCategory.LATERAL_MOVEMENT,
        "description": "Entirely fileless attack using Windows built-in tools, evading AV/EDR.",
        "threat_actor": "apt",
        "difficulty": "high",
        "estimated_duration_minutes": 120,
        "steps": [
            {"technique_id": "T1566.002", "description": "Phishing link triggers mshta.exe payload", "target": "workstation"},
            {"technique_id": "T1059.001", "description": "PowerShell in-memory implant via Invoke-Expression", "target": "workstation"},
            {"technique_id": "T1047",     "description": "WMI subscription for persistence without files", "target": "workstation"},
            {"technique_id": "T1550.002", "description": "Pass-the-Hash using built-in net commands", "target": "servers"},
        ],
    },
    {
        "scenario_id": "sc-028",
        "name": "DNS Tunneling C2",
        "category": ScenarioCategory.LATERAL_MOVEMENT,
        "description": "Attacker uses DNS queries for C2 communication, bypassing HTTP inspection.",
        "threat_actor": "apt",
        "difficulty": "high",
        "estimated_duration_minutes": 90,
        "steps": [
            {"technique_id": "T1190",     "description": "Initial access via vulnerable web application", "target": "web_server"},
            {"technique_id": "T1071",     "description": "Deploy DNS tunnel C2 client", "target": "web_server"},
            {"technique_id": "T1021",     "description": "Pivot through DNS tunnel to internal systems", "target": "internal_network"},
            {"technique_id": "T1041",     "description": "Exfiltrate data encoded in DNS queries", "target": "data_stores"},
        ],
    },
    {
        "scenario_id": "sc-029",
        "name": "Email Server Compromise",
        "category": ScenarioCategory.WEB_APP_ATTACK,
        "description": "ProxyLogon/ProxyShell-style Exchange exploitation for persistent email access.",
        "threat_actor": "nation_state",
        "difficulty": "critical",
        "estimated_duration_minutes": 180,
        "steps": [
            {"technique_id": "T1190",     "description": "Exploit Exchange ProxyShell RCE", "target": "exchange_server"},
            {"technique_id": "T1505",     "description": "Deploy web shell for persistent access", "target": "exchange_server"},
            {"technique_id": "T1078",     "description": "Harvest email credentials from Exchange", "target": "active_directory"},
            {"technique_id": "T1552",     "description": "Access all mailboxes via admin account", "target": "exchange_server"},
            {"technique_id": "T1041",     "description": "Exfiltrate sensitive communications", "target": "exchange_server"},
        ],
    },
    {
        "scenario_id": "sc-030",
        "name": "Vendor / Third-Party Access Abuse",
        "category": ScenarioCategory.INSIDER_THREAT,
        "description": "Compromised managed service provider uses their remote access to pivot into client environment.",
        "threat_actor": "cybercriminal",
        "difficulty": "high",
        "estimated_duration_minutes": 150,
        "steps": [
            {"technique_id": "T1078",     "description": "Compromise MSP technician credentials", "target": "msp_portal"},
            {"technique_id": "T1133",     "description": "Use MSP VPN credentials to access client network", "target": "client_network"},
            {"technique_id": "T1021.001", "description": "RDP to client servers via MSP jump host", "target": "client_servers"},
            {"technique_id": "T1552",     "description": "Harvest credentials from client AD", "target": "client_ad"},
            {"technique_id": "T1537",     "description": "Exfiltrate client data via MSP infrastructure", "target": "cloud_egress"},
        ],
    },
]

# Patch missing technique IDs gracefully
_UNKNOWN_TECHNIQUE = {"name": "Unknown Technique", "tactic": "unknown", "severity": 0.5}


def _get_technique(technique_id: str) -> Dict[str, Any]:
    return MITRE_TECHNIQUES.get(technique_id, {**_UNKNOWN_TECHNIQUE, "id": technique_id})


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

try:
    from pydantic import BaseModel, Field
    _PYDANTIC_V2 = True
except ImportError:
    raise ImportError("pydantic v2 is required")


class AttackStepResult(BaseModel):
    """Result of executing a single attack step during a purple team exercise."""

    step_index: int = Field(..., description="Zero-based step index")
    technique_id: str
    technique_name: str
    tactic: str
    target: str
    description: str
    severity: float = Field(ge=0.0, le=1.0)
    outcome: StepOutcome = StepOutcome.NOT_STARTED
    detected: bool = False
    detection_engine: DetectionEngine = DetectionEngine.NONE
    alert_fired: bool = False
    time_to_detect_seconds: Optional[float] = None
    detection_notes: str = ""
    executed_at: Optional[str] = None
    detected_at: Optional[str] = None


class BlueTeamAction(BaseModel):
    """A containment or response action taken by the blue team."""

    action_id: str = Field(default_factory=lambda: f"act-{uuid.uuid4().hex[:8]}")
    exercise_id: str
    step_index: int
    action: ContainmentAction
    actor: str = "blue_team"
    description: str = ""
    effective: bool = True
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ExerciseStep(BaseModel):
    """One step within an exercise — combines scenario definition with runtime results."""

    step_index: int
    technique_id: str
    technique_name: str
    tactic: str
    target: str
    description: str
    severity: float = Field(ge=0.0, le=1.0)
    # runtime
    outcome: StepOutcome = StepOutcome.NOT_STARTED
    detected: bool = False
    detection_engine: DetectionEngine = DetectionEngine.NONE
    alert_fired: bool = False
    time_to_detect_seconds: Optional[float] = None
    detection_notes: str = ""
    executed_at: Optional[str] = None
    detected_at: Optional[str] = None
    blue_team_actions: List[BlueTeamAction] = Field(default_factory=list)


class DetectionGap(BaseModel):
    """An attack step that went undetected — represents a detection engineering backlog item."""

    gap_id: str = Field(default_factory=lambda: f"gap-{uuid.uuid4().hex[:8]}")
    exercise_id: str
    step_index: int
    technique_id: str
    technique_name: str
    tactic: str
    severity: float
    priority: str  # critical / high / medium / low
    recommended_detection: str
    affected_engine: str = "siem"


class ExerciseScores(BaseModel):
    """Computed scores for a completed exercise."""

    red_team_success_rate: float = Field(ge=0.0, le=1.0, description="Fraction of steps that succeeded undetected")
    blue_team_detection_rate: float = Field(ge=0.0, le=1.0, description="Fraction of executed steps detected")
    blue_team_block_rate: float = Field(ge=0.0, le=1.0, description="Fraction of executed steps blocked")
    mean_time_to_detect_seconds: Optional[float] = None
    coverage_score: float = Field(ge=0.0, le=1.0, description="Weighted detection coverage across tactics")
    steps_total: int
    steps_executed: int
    steps_detected: int
    steps_blocked: int
    steps_missed: int
    technique_coverage: Dict[str, bool] = Field(default_factory=dict)


class AfterActionReport(BaseModel):
    """Full after-action report for a completed exercise."""

    report_id: str = Field(default_factory=lambda: f"aar-{uuid.uuid4().hex[:8]}")
    exercise_id: str
    exercise_name: str
    scenario_name: str
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    executive_summary: str
    scores: ExerciseScores
    step_results: List[ExerciseStep]
    detection_gaps: List[DetectionGap]
    blue_team_actions: List[BlueTeamAction]
    technique_results: List[Dict[str, Any]]
    recommended_improvements: List[str]
    tactic_coverage: Dict[str, Dict[str, Any]]


class Exercise(BaseModel):
    """A purple team exercise instance."""

    exercise_id: str = Field(default_factory=lambda: f"ex-{uuid.uuid4().hex[:8]}")
    name: str
    description: str = ""
    scenario_id: str
    scenario_name: str
    category: str
    scope: ExerciseScope = ExerciseScope.FULL
    status: ExerciseStatus = ExerciseStatus.DRAFT
    red_team_lead: str = "red_team"
    blue_team_lead: str = "blue_team"
    scheduled_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    steps: List[ExerciseStep] = Field(default_factory=list)
    blue_team_actions: List[BlueTeamAction] = Field(default_factory=list)
    scores: Optional[ExerciseScores] = None
    detection_gaps: List[DetectionGap] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    notes: str = ""


# ---------------------------------------------------------------------------
# Purple Team Engine
# ---------------------------------------------------------------------------

_GAP_PRIORITY_MAP = {
    (0.9, 1.01): "critical",
    (0.7, 0.9):  "high",
    (0.4, 0.7):  "medium",
    (0.0, 0.4):  "low",
}

_DETECTION_RECOMMENDATION: Dict[str, str] = {
    "initial_access":       "Add SIEM rule for failed + successful auth from unusual geo/IP; enable phishing simulation alerts",
    "execution":            "Enable PowerShell script block logging and Sysmon process creation events in SIEM",
    "persistence":          "Alert on registry run-key modifications, scheduled task creation, and new service installs",
    "privilege_escalation": "Monitor for token manipulation, UAC bypass patterns, and local admin group changes",
    "lateral_movement":     "Detect anomalous SMB/RDP auth patterns; alert on NTLM relay and pass-the-hash indicators",
    "credential_access":    "Enable Credential Guard; alert on LSASS access by non-system processes",
    "discovery":            "Baseline and alert on excessive AD/LDAP enumeration and network scanning",
    "collection":           "DLP rules on cloud storage access outside normal scope; alert on bulk download activity",
    "command_and_control":  "DNS RPZ rules and threat-intel feed integration; alert on domain-fronting patterns",
    "exfiltration":         "Egress DLP; alert on large outbound transfers to unknown destinations",
    "impact":               "Alert on VSS/shadow copy deletion, rapid file rename activity (ransomware indicators)",
    "unknown":              "Review logs manually; create SIEM detection for this technique",
}


def _gap_priority(severity: float) -> str:
    for (lo, hi), label in _GAP_PRIORITY_MAP.items():
        if lo <= severity < hi:
            return label
    return "low"


class PurpleTeamEngine:
    """Core engine for managing purple team exercises."""

    def __init__(self) -> None:
        # In-memory stores — keyed by ID
        self._exercises: Dict[str, Exercise] = {}
        self._reports: Dict[str, AfterActionReport] = {}
        self._log = logger.bind(component="purple_team_engine")

    # ------------------------------------------------------------------
    # Exercise Management
    # ------------------------------------------------------------------

    def list_exercises(self) -> List[Exercise]:
        return list(self._exercises.values())

    def get_exercise(self, exercise_id: str) -> Optional[Exercise]:
        return self._exercises.get(exercise_id)

    def create_exercise(
        self,
        *,
        name: str,
        scenario_id: str,
        description: str = "",
        scope: ExerciseScope = ExerciseScope.FULL,
        red_team_lead: str = "red_team",
        blue_team_lead: str = "blue_team",
        scheduled_at: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Exercise:
        scenario = self.get_scenario(scenario_id)
        if scenario is None:
            raise ValueError(f"Scenario not found: {scenario_id}")

        steps: List[ExerciseStep] = []
        for i, raw_step in enumerate(scenario["steps"]):
            tid = raw_step["technique_id"]
            tech = _get_technique(tid)
            steps.append(
                ExerciseStep(
                    step_index=i,
                    technique_id=tid,
                    technique_name=tech["name"],
                    tactic=tech["tactic"],
                    target=raw_step.get("target", ""),
                    description=raw_step.get("description", ""),
                    severity=tech["severity"],
                )
            )

        ex = Exercise(
            name=name,
            description=description or scenario["description"],
            scenario_id=scenario_id,
            scenario_name=scenario["name"],
            category=scenario["category"].value
            if hasattr(scenario["category"], "value")
            else str(scenario["category"]),
            scope=scope,
            red_team_lead=red_team_lead,
            blue_team_lead=blue_team_lead,
            scheduled_at=scheduled_at,
            steps=steps,
            tags=tags or [],
        )
        self._exercises[ex.exercise_id] = ex
        self._log.info("exercise_created", exercise_id=ex.exercise_id, scenario=scenario_id)
        return ex

    def start_exercise(self, exercise_id: str) -> Exercise:
        ex = self._require_exercise(exercise_id)
        if ex.status not in (ExerciseStatus.DRAFT, ExerciseStatus.PLANNED):
            raise ValueError(f"Cannot start exercise in status {ex.status}")
        ex.status = ExerciseStatus.ACTIVE
        ex.started_at = datetime.now(timezone.utc).isoformat()
        self._log.info("exercise_started", exercise_id=exercise_id)
        return ex

    def pause_exercise(self, exercise_id: str) -> Exercise:
        ex = self._require_exercise(exercise_id)
        if ex.status != ExerciseStatus.ACTIVE:
            raise ValueError("Only active exercises can be paused")
        ex.status = ExerciseStatus.PAUSED
        return ex

    def cancel_exercise(self, exercise_id: str) -> Exercise:
        ex = self._require_exercise(exercise_id)
        if ex.status == ExerciseStatus.COMPLETED:
            raise ValueError("Cannot cancel a completed exercise")
        ex.status = ExerciseStatus.CANCELLED
        ex.completed_at = datetime.now(timezone.utc).isoformat()
        return ex

    # ------------------------------------------------------------------
    # Detection Validation
    # ------------------------------------------------------------------

    def record_step_result(
        self,
        exercise_id: str,
        step_index: int,
        *,
        outcome: StepOutcome,
        detected: bool,
        detection_engine: DetectionEngine = DetectionEngine.NONE,
        alert_fired: bool = False,
        time_to_detect_seconds: Optional[float] = None,
        detection_notes: str = "",
    ) -> ExerciseStep:
        """Record whether an attack step was detected (or missed) by ALDECI."""
        ex = self._require_exercise(exercise_id)
        if ex.status != ExerciseStatus.ACTIVE:
            raise ValueError("Exercise must be active to record step results")
        step = self._require_step(ex, step_index)

        now = datetime.now(timezone.utc).isoformat()
        step.outcome = outcome
        step.detected = detected
        step.detection_engine = detection_engine
        step.alert_fired = alert_fired
        step.time_to_detect_seconds = time_to_detect_seconds
        step.detection_notes = detection_notes
        step.executed_at = now
        if detected:
            step.detected_at = now

        self._log.info(
            "step_result_recorded",
            exercise_id=exercise_id,
            step_index=step_index,
            outcome=outcome.value,
            detected=detected,
        )
        return step

    # ------------------------------------------------------------------
    # Blue Team Response Tracking
    # ------------------------------------------------------------------

    def add_blue_team_action(
        self,
        exercise_id: str,
        step_index: int,
        *,
        action: ContainmentAction,
        actor: str = "blue_team",
        description: str = "",
        effective: bool = True,
    ) -> BlueTeamAction:
        ex = self._require_exercise(exercise_id)
        step = self._require_step(ex, step_index)

        bta = BlueTeamAction(
            exercise_id=exercise_id,
            step_index=step_index,
            action=action,
            actor=actor,
            description=description,
            effective=effective,
        )
        step.blue_team_actions.append(bta)
        ex.blue_team_actions.append(bta)
        self._log.info(
            "blue_team_action_added",
            exercise_id=exercise_id,
            step_index=step_index,
            action=action.value,
        )
        return bta

    # ------------------------------------------------------------------
    # Gap Identification
    # ------------------------------------------------------------------

    def identify_gaps(self, exercise_id: str) -> List[DetectionGap]:
        """Identify attack steps that were executed but not detected."""
        ex = self._require_exercise(exercise_id)
        gaps: List[DetectionGap] = []
        for step in ex.steps:
            if step.outcome == StepOutcome.EXECUTED and not step.detected:
                tech = _get_technique(step.technique_id)
                gap = DetectionGap(
                    exercise_id=exercise_id,
                    step_index=step.step_index,
                    technique_id=step.technique_id,
                    technique_name=step.technique_name,
                    tactic=step.tactic,
                    severity=step.severity,
                    priority=_gap_priority(step.severity),
                    recommended_detection=_DETECTION_RECOMMENDATION.get(
                        tech["tactic"], _DETECTION_RECOMMENDATION["unknown"]
                    ),
                    affected_engine=_suggest_detection_engine(step.tactic),
                )
                gaps.append(gap)

        ex.detection_gaps = gaps
        self._log.info(
            "gaps_identified",
            exercise_id=exercise_id,
            gap_count=len(gaps),
        )
        return gaps

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def compute_scores(self, exercise_id: str) -> ExerciseScores:
        """Compute red/blue team scores for a completed exercise."""
        ex = self._require_exercise(exercise_id)

        executed = [s for s in ex.steps if s.outcome != StepOutcome.NOT_STARTED]
        detected = [s for s in executed if s.detected]
        blocked = [s for s in executed if s.outcome == StepOutcome.BLOCKED]
        missed = [s for s in executed if s.outcome == StepOutcome.EXECUTED and not s.detected]

        n_exec = len(executed)
        n_det = len(detected)
        n_blk = len(blocked)
        n_miss = len(missed)

        detect_rate = n_det / n_exec if n_exec else 0.0
        block_rate = n_blk / n_exec if n_exec else 0.0
        red_success = n_miss / n_exec if n_exec else 0.0

        detect_times = [
            s.time_to_detect_seconds
            for s in detected
            if s.time_to_detect_seconds is not None
        ]
        mttd = statistics.mean(detect_times) if detect_times else None

        # Weighted coverage: severity-weighted detection rate per tactic
        tactic_severities: Dict[str, List[float]] = {}
        tactic_detected: Dict[str, int] = {}
        for s in executed:
            tactic_severities.setdefault(s.tactic, []).append(s.severity)
            if s.detected:
                tactic_detected[s.tactic] = tactic_detected.get(s.tactic, 0) + 1

        coverage_scores: List[float] = []
        for tactic, sevs in tactic_severities.items():
            n_tactic = len(sevs)
            n_tactic_det = tactic_detected.get(tactic, 0)
            tactic_rate = n_tactic_det / n_tactic if n_tactic else 0.0
            weight = statistics.mean(sevs)
            coverage_scores.append(tactic_rate * weight)
        coverage_score = statistics.mean(coverage_scores) if coverage_scores else 0.0

        technique_coverage = {s.technique_id: s.detected for s in executed}

        scores = ExerciseScores(
            red_team_success_rate=round(red_success, 4),
            blue_team_detection_rate=round(detect_rate, 4),
            blue_team_block_rate=round(block_rate, 4),
            mean_time_to_detect_seconds=round(mttd, 2) if mttd is not None else None,
            coverage_score=round(coverage_score, 4),
            steps_total=len(ex.steps),
            steps_executed=n_exec,
            steps_detected=n_det,
            steps_blocked=n_blk,
            steps_missed=n_miss,
            technique_coverage=technique_coverage,
        )
        ex.scores = scores
        return scores

    def complete_exercise(self, exercise_id: str) -> Exercise:
        """Mark an exercise complete, computing scores and gaps automatically."""
        ex = self._require_exercise(exercise_id)
        if ex.status not in (ExerciseStatus.ACTIVE, ExerciseStatus.PAUSED):
            raise ValueError(f"Cannot complete exercise in status {ex.status}")

        ex.status = ExerciseStatus.COMPLETED
        ex.completed_at = datetime.now(timezone.utc).isoformat()

        # Auto-compute
        self.compute_scores(exercise_id)
        self.identify_gaps(exercise_id)

        self._log.info("exercise_completed", exercise_id=exercise_id)
        _emit_event("purple_team.exercise_completed", {"exercise_id": exercise_id, "status": ex.status.value})
        return ex

    # ------------------------------------------------------------------
    # After-Action Report
    # ------------------------------------------------------------------

    def generate_report(self, exercise_id: str) -> AfterActionReport:
        """Generate a comprehensive after-action report."""
        ex = self._require_exercise(exercise_id)
        if ex.status != ExerciseStatus.COMPLETED:
            raise ValueError("Exercise must be completed before generating a report")

        scores = ex.scores or self.compute_scores(exercise_id)
        gaps = ex.detection_gaps or self.identify_gaps(exercise_id)

        # Technique-by-technique results
        technique_results = []
        for step in ex.steps:
            technique_results.append(
                {
                    "step_index": step.step_index,
                    "technique_id": step.technique_id,
                    "technique_name": step.technique_name,
                    "tactic": step.tactic,
                    "target": step.target,
                    "outcome": step.outcome.value,
                    "detected": step.detected,
                    "detection_engine": step.detection_engine.value,
                    "alert_fired": step.alert_fired,
                    "time_to_detect_seconds": step.time_to_detect_seconds,
                    "blue_team_actions_count": len(step.blue_team_actions),
                }
            )

        # Tactic coverage breakdown
        tactic_coverage: Dict[str, Dict[str, Any]] = {}
        for step in ex.steps:
            tc = tactic_coverage.setdefault(
                step.tactic, {"total": 0, "detected": 0, "missed": 0, "techniques": []}
            )
            if step.outcome != StepOutcome.NOT_STARTED:
                tc["total"] += 1
                if step.detected:
                    tc["detected"] += 1
                elif step.outcome == StepOutcome.EXECUTED:
                    tc["missed"] += 1
            if step.technique_id not in tc["techniques"]:
                tc["techniques"].append(step.technique_id)

        for tactic, tc in tactic_coverage.items():
            tc["detection_rate"] = (
                round(tc["detected"] / tc["total"], 4) if tc["total"] else 0.0
            )

        # Recommended improvements — top 5 by severity gap
        sorted_gaps = sorted(gaps, key=lambda g: g.severity, reverse=True)
        recommendations: List[str] = []
        seen: set = set()
        for g in sorted_gaps[:10]:
            rec = g.recommended_detection
            if rec not in seen:
                recommendations.append(
                    f"[{g.tactic.upper()} / {g.technique_id}] {rec}"
                )
                seen.add(rec)
            if len(recommendations) >= 5:
                break

        # Always add score-based recommendations
        if scores.blue_team_detection_rate < 0.5:
            recommendations.append(
                "Detection rate below 50% — prioritise SIEM rule tuning and threat hunt cadence"
            )
        if scores.mean_time_to_detect_seconds and scores.mean_time_to_detect_seconds > 3600:
            recommendations.append(
                "MTTD exceeds 1 hour — consider automating initial triage with SOAR playbooks"
            )
        if scores.blue_team_block_rate == 0.0:
            recommendations.append(
                "Zero steps blocked — review EDR prevention mode settings and firewall rule coverage"
            )

        # Executive summary
        det_pct = round(scores.blue_team_detection_rate * 100, 1)
        red_pct = round(scores.red_team_success_rate * 100, 1)
        mttd_str = (
            f"{round(scores.mean_time_to_detect_seconds / 60, 1)} minutes"
            if scores.mean_time_to_detect_seconds is not None
            else "N/A (no detections)"
        )
        executive_summary = (
            f"Purple team exercise '{ex.name}' ({ex.scenario_name}) completed on "
            f"{ex.completed_at[:10]}. "
            f"Blue team detected {scores.steps_detected} of {scores.steps_executed} attack steps "
            f"({det_pct}% detection rate). "
            f"Red team succeeded on {scores.steps_missed} steps ({red_pct}% success rate). "
            f"Mean time to detect: {mttd_str}. "
            f"Coverage score: {round(scores.coverage_score * 100, 1)}%. "
            f"Identified {len(gaps)} detection gap(s) requiring immediate attention."
        )

        report = AfterActionReport(
            exercise_id=exercise_id,
            exercise_name=ex.name,
            scenario_name=ex.scenario_name,
            executive_summary=executive_summary,
            scores=scores,
            step_results=ex.steps,
            detection_gaps=gaps,
            blue_team_actions=ex.blue_team_actions,
            technique_results=technique_results,
            recommended_improvements=recommendations,
            tactic_coverage=tactic_coverage,
        )
        self._reports[report.report_id] = report
        self._log.info(
            "report_generated",
            report_id=report.report_id,
            exercise_id=exercise_id,
            gap_count=len(gaps),
        )
        _emit_event("purple_team.report_generated", {"report_id": report.report_id, "exercise_id": exercise_id, "gap_count": len(gaps)})
        return report

    def get_report(self, report_id: str) -> Optional[AfterActionReport]:
        return self._reports.get(report_id)

    def list_reports(self) -> List[AfterActionReport]:
        return list(self._reports.values())

    # ------------------------------------------------------------------
    # Scenario Library
    # ------------------------------------------------------------------

    def list_scenarios(
        self, category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        scenarios = SCENARIO_LIBRARY
        if category:
            scenarios = [
                s
                for s in scenarios
                if (
                    s["category"].value
                    if hasattr(s["category"], "value")
                    else str(s["category"])
                )
                == category
            ]
        return [_scenario_summary(s) for s in scenarios]

    def get_scenario(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        for s in SCENARIO_LIBRARY:
            if s["scenario_id"] == scenario_id:
                return s
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _require_exercise(self, exercise_id: str) -> Exercise:
        ex = self._exercises.get(exercise_id)
        if ex is None:
            raise KeyError(f"Exercise not found: {exercise_id}")
        return ex

    def _require_step(self, ex: Exercise, step_index: int) -> ExerciseStep:
        for step in ex.steps:
            if step.step_index == step_index:
                return step
        raise KeyError(f"Step {step_index} not found in exercise {ex.exercise_id}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _suggest_detection_engine(tactic: str) -> str:
    mapping = {
        "initial_access": "siem",
        "execution": "edr",
        "persistence": "edr",
        "privilege_escalation": "edr",
        "lateral_movement": "ndr",
        "credential_access": "edr",
        "discovery": "siem",
        "collection": "siem",
        "command_and_control": "ndr",
        "exfiltration": "ndr",
        "impact": "edr",
    }
    return mapping.get(tactic, "siem")


def _scenario_summary(s: Dict[str, Any]) -> Dict[str, Any]:
    cat = s["category"]
    return {
        "scenario_id": s["scenario_id"],
        "name": s["name"],
        "category": cat.value if hasattr(cat, "value") else str(cat),
        "description": s["description"],
        "threat_actor": s["threat_actor"],
        "difficulty": s["difficulty"],
        "estimated_duration_minutes": s["estimated_duration_minutes"],
        "step_count": len(s["steps"]),
        "techniques": [step["technique_id"] for step in s["steps"]],
    }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine: Optional[PurpleTeamEngine] = None


def get_purple_team_engine() -> PurpleTeamEngine:
    global _engine
    if _engine is None:
        _engine = PurpleTeamEngine()
    return _engine
