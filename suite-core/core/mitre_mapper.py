"""
FixOps MITRE ATT&CK v14 Application-Layer Mapping Engine.

Maps application vulnerabilities (CWE IDs, CVEs, scanner findings) to
MITRE ATT&CK techniques and tactics. Supports:

- 100+ CWE → ATT&CK technique mappings (OWASP Top 10, SANS Top 25, etc.)
- Text-based title/description matching for unstructured scanner findings
- CVE → ATT&CK technique mappings for well-known CVEs
- Kill chain phase coverage analysis
- MITRE ATT&CK Navigator layer JSON export

All mappings are built-in (no external API calls) — safe for air-gapped
environments. Based on MITRE ATT&CK v14 (Enterprise).

References:
    https://attack.mitre.org/
    https://cwe.mitre.org/
    https://github.com/mitre/cti
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
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


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


# ---------------------------------------------------------------------------
# MITRE ATT&CK v14 — All 14 Tactics
# ---------------------------------------------------------------------------

TACTICS: Dict[str, Dict[str, str]] = {
    "TA0043": {
        "name": "Reconnaissance",
        "shortname": "reconnaissance",
        "description": "The adversary is trying to gather information they can use to plan future operations.",
        "url": "https://attack.mitre.org/tactics/TA0043/",
    },
    "TA0042": {
        "name": "Resource Development",
        "shortname": "resource-development",
        "description": "The adversary is trying to establish resources they can use to support operations.",
        "url": "https://attack.mitre.org/tactics/TA0042/",
    },
    "TA0001": {
        "name": "Initial Access",
        "shortname": "initial-access",
        "description": "The adversary is trying to get into your network.",
        "url": "https://attack.mitre.org/tactics/TA0001/",
    },
    "TA0002": {
        "name": "Execution",
        "shortname": "execution",
        "description": "The adversary is trying to run malicious code.",
        "url": "https://attack.mitre.org/tactics/TA0002/",
    },
    "TA0003": {
        "name": "Persistence",
        "shortname": "persistence",
        "description": "The adversary is trying to maintain their foothold.",
        "url": "https://attack.mitre.org/tactics/TA0003/",
    },
    "TA0004": {
        "name": "Privilege Escalation",
        "shortname": "privilege-escalation",
        "description": "The adversary is trying to gain higher-level permissions.",
        "url": "https://attack.mitre.org/tactics/TA0004/",
    },
    "TA0005": {
        "name": "Defense Evasion",
        "shortname": "defense-evasion",
        "description": "The adversary is trying to avoid being detected.",
        "url": "https://attack.mitre.org/tactics/TA0005/",
    },
    "TA0006": {
        "name": "Credential Access",
        "shortname": "credential-access",
        "description": "The adversary is trying to steal account names and passwords.",
        "url": "https://attack.mitre.org/tactics/TA0006/",
    },
    "TA0007": {
        "name": "Discovery",
        "shortname": "discovery",
        "description": "The adversary is trying to figure out your environment.",
        "url": "https://attack.mitre.org/tactics/TA0007/",
    },
    "TA0008": {
        "name": "Lateral Movement",
        "shortname": "lateral-movement",
        "description": "The adversary is trying to move through your environment.",
        "url": "https://attack.mitre.org/tactics/TA0008/",
    },
    "TA0009": {
        "name": "Collection",
        "shortname": "collection",
        "description": "The adversary is trying to gather data of interest to their goal.",
        "url": "https://attack.mitre.org/tactics/TA0009/",
    },
    "TA0011": {
        "name": "Command and Control",
        "shortname": "command-and-control",
        "description": "The adversary is trying to communicate with compromised systems to control them.",
        "url": "https://attack.mitre.org/tactics/TA0011/",
    },
    "TA0010": {
        "name": "Exfiltration",
        "shortname": "exfiltration",
        "description": "The adversary is trying to steal data.",
        "url": "https://attack.mitre.org/tactics/TA0010/",
    },
    "TA0040": {
        "name": "Impact",
        "shortname": "impact",
        "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
        "url": "https://attack.mitre.org/tactics/TA0040/",
    },
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK v14 — Technique Catalog
# Each technique: id, name, tactic_ids, description, url, is_subtechnique
# ---------------------------------------------------------------------------

TECHNIQUES: Dict[str, Dict[str, Any]] = {
    # --- Initial Access ---
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic_ids": ["TA0001"],
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "is_subtechnique": False,
        "platforms": ["Linux", "Windows", "macOS", "Network", "IaaS", "Containers"],
    },
    "T1189": {
        "name": "Drive-by Compromise",
        "tactic_ids": ["TA0001"],
        "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.",
        "url": "https://attack.mitre.org/techniques/T1189/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Linux", "macOS", "SaaS"],
    },
    "T1566": {
        "name": "Phishing",
        "tactic_ids": ["TA0001"],
        "description": "Adversaries may send phishing messages to gain access to victim systems.",
        "url": "https://attack.mitre.org/techniques/T1566/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "SaaS", "Office 365", "Google Workspace"],
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic_ids": ["TA0001"],
        "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access.",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
        "is_subtechnique": True,
        "parent_id": "T1566",
        "platforms": ["macOS", "Windows", "Linux"],
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic_ids": ["TA0001"],
        "description": "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access.",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
        "is_subtechnique": True,
        "parent_id": "T1566",
        "platforms": ["Linux", "macOS", "Windows", "Office 365", "SaaS", "Google Workspace"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic_ids": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Linux", "macOS", "Google Workspace", "Containers", "Network"],
    },
    "T1078.001": {
        "name": "Valid Accounts: Default Accounts",
        "tactic_ids": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "description": "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access.",
        "url": "https://attack.mitre.org/techniques/T1078/001/",
        "is_subtechnique": True,
        "parent_id": "T1078",
        "platforms": ["Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Linux", "macOS"],
    },
    "T1078.003": {
        "name": "Valid Accounts: Local Accounts",
        "tactic_ids": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "description": "Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access.",
        "url": "https://attack.mitre.org/techniques/T1078/003/",
        "is_subtechnique": True,
        "parent_id": "T1078",
        "platforms": ["Linux", "macOS", "Windows", "Containers"],
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic_ids": ["TA0001", "TA0003"],
        "description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network.",
        "url": "https://attack.mitre.org/techniques/T1133/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Linux", "Containers", "macOS"],
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactic_ids": ["TA0001"],
        "description": "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer.",
        "url": "https://attack.mitre.org/techniques/T1195/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1195.002": {
        "name": "Supply Chain Compromise: Compromise Software Supply Chain",
        "tactic_ids": ["TA0001"],
        "description": "Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.",
        "url": "https://attack.mitre.org/techniques/T1195/002/",
        "is_subtechnique": True,
        "parent_id": "T1195",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    # --- Execution ---
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic_ids": ["TA0002"],
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "Network", "IaaS", "Office 365", "Azure AD", "Google Workspace", "Containers"],
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic_ids": ["TA0002"],
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
        "is_subtechnique": True,
        "parent_id": "T1059",
        "platforms": ["Windows"],
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic_ids": ["TA0002"],
        "description": "Adversaries may abuse the Windows command shell for execution.",
        "url": "https://attack.mitre.org/techniques/T1059/003/",
        "is_subtechnique": True,
        "parent_id": "T1059",
        "platforms": ["Windows"],
    },
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic_ids": ["TA0002"],
        "description": "Adversaries may abuse Unix shell commands and scripts for execution.",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
        "is_subtechnique": True,
        "parent_id": "T1059",
        "platforms": ["macOS", "Linux", "Network"],
    },
    "T1059.007": {
        "name": "Command and Scripting Interpreter: JavaScript",
        "tactic_ids": ["TA0002"],
        "description": "Adversaries may abuse various implementations of JavaScript for execution.",
        "url": "https://attack.mitre.org/techniques/T1059/007/",
        "is_subtechnique": True,
        "parent_id": "T1059",
        "platforms": ["Windows", "macOS", "Linux"],
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic_ids": ["TA0002"],
        "description": "Adversaries may exploit software vulnerabilities in client applications to execute code.",
        "url": "https://attack.mitre.org/techniques/T1203/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1204": {
        "name": "User Execution",
        "tactic_ids": ["TA0002"],
        "description": "An adversary may rely upon specific actions by a user in order to gain execution.",
        "url": "https://attack.mitre.org/techniques/T1204/",
        "is_subtechnique": False,
        "platforms": ["Linux", "Windows", "macOS", "IaaS", "Containers"],
    },
    "T1106": {
        "name": "Native API",
        "tactic_ids": ["TA0002"],
        "description": "Adversaries may interact with the native OS application programming interface (API) to execute behaviors.",
        "url": "https://attack.mitre.org/techniques/T1106/",
        "is_subtechnique": False,
        "platforms": ["Windows", "macOS", "Linux"],
    },
    # --- Persistence ---
    "T1505": {
        "name": "Server Software Component",
        "tactic_ids": ["TA0003"],
        "description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access.",
        "url": "https://attack.mitre.org/techniques/T1505/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Linux", "macOS", "Network"],
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic_ids": ["TA0003"],
        "description": "Adversaries may backdoor web servers with web shells to establish persistent access to systems.",
        "url": "https://attack.mitre.org/techniques/T1505/003/",
        "is_subtechnique": True,
        "parent_id": "T1505",
        "platforms": ["Windows", "Linux", "macOS", "Network"],
    },
    "T1176": {
        "name": "Browser Extensions",
        "tactic_ids": ["TA0003"],
        "description": "Adversaries may abuse Internet browser extensions to establish persistent access to victim systems.",
        "url": "https://attack.mitre.org/techniques/T1176/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic_ids": ["TA0003", "TA0004"],
        "description": "Adversaries may manipulate accounts to maintain access to victim systems.",
        "url": "https://attack.mitre.org/techniques/T1098/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Azure AD", "Office 365", "IaaS", "Linux", "macOS", "Google Workspace", "Containers", "SaaS", "Network"],
    },
    "T1136": {
        "name": "Create Account",
        "tactic_ids": ["TA0003"],
        "description": "Adversaries may create an account to maintain access to victim systems.",
        "url": "https://attack.mitre.org/techniques/T1136/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Azure AD", "Office 365", "IaaS", "Linux", "macOS", "Google Workspace", "Containers", "Network"],
    },
    "T1525": {
        "name": "Implant Internal Image",
        "tactic_ids": ["TA0003"],
        "description": "Adversaries may implant cloud or container images with malicious code to establish persistence.",
        "url": "https://attack.mitre.org/techniques/T1525/",
        "is_subtechnique": False,
        "platforms": ["IaaS", "Containers"],
    },
    # --- Privilege Escalation ---
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic_ids": ["TA0004"],
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
        "url": "https://attack.mitre.org/techniques/T1068/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "Containers"],
    },
    "T1055": {
        "name": "Process Injection",
        "tactic_ids": ["TA0004", "TA0005"],
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
        "url": "https://attack.mitre.org/techniques/T1055/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1611": {
        "name": "Escape to Host",
        "tactic_ids": ["TA0004"],
        "description": "Adversaries may break out of a container to gain access to the underlying host.",
        "url": "https://attack.mitre.org/techniques/T1611/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Linux", "Containers"],
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic_ids": ["TA0004", "TA0005"],
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions.",
        "url": "https://attack.mitre.org/techniques/T1548/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "IaaS"],
    },
    # --- Defense Evasion ---
    "T1070": {
        "name": "Indicator Removal",
        "tactic_ids": ["TA0005"],
        "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence.",
        "url": "https://attack.mitre.org/techniques/T1070/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "Containers", "Network"],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic_ids": ["TA0005"],
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.",
        "url": "https://attack.mitre.org/techniques/T1027/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic_ids": ["TA0005"],
        "description": "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms.",
        "url": "https://attack.mitre.org/techniques/T1562/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Azure AD", "Office 365", "IaaS", "Linux", "macOS", "Containers", "Network"],
    },
    "T1036": {
        "name": "Masquerading",
        "tactic_ids": ["TA0005"],
        "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.",
        "url": "https://attack.mitre.org/techniques/T1036/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "Containers"],
    },
    # --- Credential Access ---
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic_ids": ["TA0006"],
        "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials.",
        "url": "https://attack.mitre.org/techniques/T1552/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Azure AD", "Office 365", "IaaS", "Linux", "macOS", "Containers", "Network"],
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic_ids": ["TA0006"],
        "description": "Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
        "is_subtechnique": True,
        "parent_id": "T1552",
        "platforms": ["Windows", "IaaS", "Linux", "macOS"],
    },
    "T1552.004": {
        "name": "Unsecured Credentials: Private Keys",
        "tactic_ids": ["TA0006"],
        "description": "Adversaries may search for private key certificate files on compromised systems.",
        "url": "https://attack.mitre.org/techniques/T1552/004/",
        "is_subtechnique": True,
        "parent_id": "T1552",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic_ids": ["TA0006"],
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Linux", "macOS", "Containers", "Network", "Google Workspace"],
    },
    "T1110.003": {
        "name": "Brute Force: Password Spraying",
        "tactic_ids": ["TA0006"],
        "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
        "is_subtechnique": True,
        "parent_id": "T1110",
        "platforms": ["Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Linux", "macOS", "Containers", "Network"],
    },
    "T1212": {
        "name": "Exploitation for Credential Access",
        "tactic_ids": ["TA0006"],
        "description": "Adversaries may exploit software vulnerabilities in an attempt to collect credentials.",
        "url": "https://attack.mitre.org/techniques/T1212/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1528": {
        "name": "Steal Application Access Token",
        "tactic_ids": ["TA0006"],
        "description": "Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.",
        "url": "https://attack.mitre.org/techniques/T1528/",
        "is_subtechnique": False,
        "platforms": ["Android", "iOS", "SaaS", "Office 365", "Azure AD", "Google Workspace"],
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic_ids": ["TA0006"],
        "description": "An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services.",
        "url": "https://attack.mitre.org/techniques/T1539/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "SaaS", "Office 365", "Google Workspace"],
    },
    "T1111": {
        "name": "Multi-Factor Authentication Interception",
        "tactic_ids": ["TA0006"],
        "description": "Adversaries may target multi-factor authentication (MFA) mechanisms to gain access to credentials.",
        "url": "https://attack.mitre.org/techniques/T1111/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1621": {
        "name": "Multi-Factor Authentication Request Generation",
        "tactic_ids": ["TA0006"],
        "description": "Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.",
        "url": "https://attack.mitre.org/techniques/T1621/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Office 365", "SaaS", "IaaS", "Azure AD", "Google Workspace"],
    },
    # --- Discovery ---
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic_ids": ["TA0007"],
        "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information.",
        "url": "https://attack.mitre.org/techniques/T1083/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic_ids": ["TA0007"],
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "is_subtechnique": False,
        "platforms": ["Windows", "IaaS", "Linux", "macOS", "Containers", "Network"],
    },
    "T1518": {
        "name": "Software Discovery",
        "tactic_ids": ["TA0007"],
        "description": "Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment.",
        "url": "https://attack.mitre.org/techniques/T1518/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Linux", "macOS", "Google Workspace"],
    },
    "T1580": {
        "name": "Cloud Infrastructure Discovery",
        "tactic_ids": ["TA0007"],
        "description": "An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment.",
        "url": "https://attack.mitre.org/techniques/T1580/",
        "is_subtechnique": False,
        "platforms": ["IaaS"],
    },
    # --- Lateral Movement ---
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactic_ids": ["TA0008"],
        "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.",
        "url": "https://attack.mitre.org/techniques/T1210/",
        "is_subtechnique": False,
        "platforms": ["Linux", "Windows", "macOS"],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic_ids": ["TA0008"],
        "description": "Adversaries may use valid accounts to log into a service that accepts remote connections.",
        "url": "https://attack.mitre.org/techniques/T1021/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1534": {
        "name": "Internal Spearphishing",
        "tactic_ids": ["TA0008"],
        "description": "Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization after they already have access to accounts or systems within the environment.",
        "url": "https://attack.mitre.org/techniques/T1534/",
        "is_subtechnique": False,
        "platforms": ["Windows", "macOS", "Linux", "Office 365", "SaaS", "Google Workspace"],
    },
    # --- Collection ---
    "T1005": {
        "name": "Data from Local System",
        "tactic_ids": ["TA0009"],
        "description": "Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data.",
        "url": "https://attack.mitre.org/techniques/T1005/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "Network"],
    },
    "T1213": {
        "name": "Data from Information Repositories",
        "tactic_ids": ["TA0009"],
        "description": "Adversaries may leverage information repositories to mine valuable information.",
        "url": "https://attack.mitre.org/techniques/T1213/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "Office 365", "SaaS", "Google Workspace"],
    },
    "T1114": {
        "name": "Email Collection",
        "tactic_ids": ["TA0009"],
        "description": "Adversaries may target user email to collect sensitive information.",
        "url": "https://attack.mitre.org/techniques/T1114/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Office 365", "Google Workspace"],
    },
    "T1560": {
        "name": "Archive Collected Data",
        "tactic_ids": ["TA0009"],
        "description": "An adversary may compress and/or encrypt data that is collected prior to exfiltration.",
        "url": "https://attack.mitre.org/techniques/T1560/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    # --- Command and Control ---
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic_ids": ["TA0011"],
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "Network"],
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic_ids": ["TA0011"],
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "is_subtechnique": True,
        "parent_id": "T1071",
        "platforms": ["Linux", "macOS", "Windows", "Network"],
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic_ids": ["TA0011"],
        "description": "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1572/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic_ids": ["TA0011"],
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
        "url": "https://attack.mitre.org/techniques/T1105/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "Network"],
    },
    "T1102": {
        "name": "Web Service",
        "tactic_ids": ["TA0011"],
        "description": "Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system.",
        "url": "https://attack.mitre.org/techniques/T1102/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    # --- Exfiltration ---
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic_ids": ["TA0010"],
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic_ids": ["TA0010"],
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.",
        "url": "https://attack.mitre.org/techniques/T1048/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "Network"],
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic_ids": ["TA0010"],
        "description": "Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel.",
        "url": "https://attack.mitre.org/techniques/T1567/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    # --- Impact ---
    "T1485": {
        "name": "Data Destruction",
        "tactic_ids": ["TA0040"],
        "description": "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability.",
        "url": "https://attack.mitre.org/techniques/T1485/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Linux", "macOS", "Containers", "Network", "Google Workspace"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic_ids": ["TA0040"],
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
        "url": "https://attack.mitre.org/techniques/T1486/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "IaaS"],
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic_ids": ["TA0040"],
        "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users.",
        "url": "https://attack.mitre.org/techniques/T1499/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Google Workspace"],
    },
    "T1499.004": {
        "name": "Endpoint Denial of Service: Application or System Exploitation",
        "tactic_ids": ["TA0040"],
        "description": "Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users.",
        "url": "https://attack.mitre.org/techniques/T1499/004/",
        "is_subtechnique": True,
        "parent_id": "T1499",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1489": {
        "name": "Service Stop",
        "tactic_ids": ["TA0040"],
        "description": "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users.",
        "url": "https://attack.mitre.org/techniques/T1489/",
        "is_subtechnique": False,
        "platforms": ["Windows", "Linux", "macOS", "Network"],
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactic_ids": ["TA0040"],
        "description": "Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks.",
        "url": "https://attack.mitre.org/techniques/T1496/",
        "is_subtechnique": False,
        "platforms": ["Windows", "IaaS", "Linux", "macOS", "Containers"],
    },
    "T1565": {
        "name": "Data Manipulation",
        "tactic_ids": ["TA0040"],
        "description": "Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity.",
        "url": "https://attack.mitre.org/techniques/T1565/",
        "is_subtechnique": False,
        "platforms": ["Linux", "macOS", "Windows"],
    },
    # --- Reconnaissance ---
    "T1595": {
        "name": "Active Scanning",
        "tactic_ids": ["TA0043"],
        "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
        "url": "https://attack.mitre.org/techniques/T1595/",
        "is_subtechnique": False,
        "platforms": ["PRE"],
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactic_ids": ["TA0043"],
        "description": "Adversaries may gather information about the victim's hosts that can be used during targeting.",
        "url": "https://attack.mitre.org/techniques/T1592/",
        "is_subtechnique": False,
        "platforms": ["PRE"],
    },
    "T1589": {
        "name": "Gather Victim Identity Information",
        "tactic_ids": ["TA0043"],
        "description": "Adversaries may gather information about the victim's identity that can be used during targeting.",
        "url": "https://attack.mitre.org/techniques/T1589/",
        "is_subtechnique": False,
        "platforms": ["PRE"],
    },
    "T1596": {
        "name": "Search Open Technical Databases",
        "tactic_ids": ["TA0043"],
        "description": "Adversaries may search freely available technical databases for information about victims that can be used during targeting.",
        "url": "https://attack.mitre.org/techniques/T1596/",
        "is_subtechnique": False,
        "platforms": ["PRE"],
    },
    # --- Resource Development ---
    "T1588": {
        "name": "Obtain Capabilities",
        "tactic_ids": ["TA0042"],
        "description": "Adversaries may buy and/or steal capabilities that can be used during targeting.",
        "url": "https://attack.mitre.org/techniques/T1588/",
        "is_subtechnique": False,
        "platforms": ["PRE"],
    },
    "T1588.006": {
        "name": "Obtain Capabilities: Vulnerabilities",
        "tactic_ids": ["TA0042"],
        "description": "Adversaries may acquire information about vulnerabilities that can be used during targeting.",
        "url": "https://attack.mitre.org/techniques/T1588/006/",
        "is_subtechnique": True,
        "parent_id": "T1588",
        "platforms": ["PRE"],
    },
}

# ---------------------------------------------------------------------------
# CWE → MITRE ATT&CK Technique Mappings
# 100+ mappings covering OWASP Top 10, SANS Top 25, and common app vulns.
# Format: { cwe_id: [{"technique_id": str, "confidence": float, "rationale": str}] }
# ---------------------------------------------------------------------------

CWE_TO_TECHNIQUES: Dict[str, List[Dict[str, Any]]] = {
    # ---- Injection ----
    # CWE-89: SQL Injection
    "89": [
        {"technique_id": "T1190", "confidence": 0.95, "rationale": "SQL Injection directly exploits a public-facing application vulnerability"},
        {"technique_id": "T1005", "confidence": 0.80, "rationale": "SQLi enables extraction of data from local/backend databases"},
    ],
    # CWE-564: SQL Injection: Hibernate
    "564": [
        {"technique_id": "T1190", "confidence": 0.93, "rationale": "Hibernate SQLi exploits application layer"},
        {"technique_id": "T1005", "confidence": 0.75, "rationale": "Enables database data extraction"},
    ],
    # CWE-943: ORM Injection
    "943": [
        {"technique_id": "T1190", "confidence": 0.90, "rationale": "ORM injection exploits application data access layer"},
    ],
    # CWE-77: Command Injection
    "77": [
        {"technique_id": "T1059", "confidence": 0.95, "rationale": "Command injection leads to arbitrary command execution"},
        {"technique_id": "T1059.004", "confidence": 0.85, "rationale": "Unix shell commands commonly executed via injection"},
        {"technique_id": "T1190", "confidence": 0.90, "rationale": "Exploits public-facing application"},
    ],
    # CWE-78: OS Command Injection
    "78": [
        {"technique_id": "T1059", "confidence": 0.98, "rationale": "OS command injection is direct command execution"},
        {"technique_id": "T1059.003", "confidence": 0.80, "rationale": "Windows command shell execution via injection"},
        {"technique_id": "T1059.004", "confidence": 0.85, "rationale": "Unix shell execution via injection"},
        {"technique_id": "T1190", "confidence": 0.90, "rationale": "Exploits public-facing application"},
    ],
    # CWE-88: Argument Injection or Modification
    "88": [
        {"technique_id": "T1059", "confidence": 0.85, "rationale": "Argument injection can lead to command execution"},
        {"technique_id": "T1190", "confidence": 0.80, "rationale": "Exploits application input handling"},
    ],
    # CWE-91: XML Injection (Blind XPath Injection)
    "91": [
        {"technique_id": "T1190", "confidence": 0.88, "rationale": "XML/XPath injection exploits application parsing"},
        {"technique_id": "T1005", "confidence": 0.70, "rationale": "May enable data extraction from XML stores"},
    ],
    # CWE-93: Improper Neutralization of CRLF Sequences (HTTP Response Splitting)
    "93": [
        {"technique_id": "T1189", "confidence": 0.80, "rationale": "HTTP response splitting can lead to drive-by compromise"},
        {"technique_id": "T1539", "confidence": 0.75, "rationale": "Can facilitate session cookie theft"},
    ],
    # CWE-94: Code Injection
    "94": [
        {"technique_id": "T1059", "confidence": 0.95, "rationale": "Code injection leads directly to code execution"},
        {"technique_id": "T1190", "confidence": 0.90, "rationale": "Exploits public-facing application"},
    ],
    # CWE-95: Eval Injection (Server-Side Code Execution)
    "95": [
        {"technique_id": "T1059", "confidence": 0.95, "rationale": "Eval injection is direct server-side code execution"},
        {"technique_id": "T1059.007", "confidence": 0.85, "rationale": "JavaScript eval injection"},
        {"technique_id": "T1505.003", "confidence": 0.70, "rationale": "Persistent web shell can be established via eval injection"},
    ],
    # CWE-96: Improper Neutralization of Directives in Statically Saved Code (Static Code Injection)
    "96": [
        {"technique_id": "T1505", "confidence": 0.88, "rationale": "Static code injection enables persistent server-side code"},
        {"technique_id": "T1059", "confidence": 0.85, "rationale": "Injected code can be executed"},
    ],
    # CWE-98: Improper Control of Filename for Include/Require (PHP Remote File Inclusion)
    "98": [
        {"technique_id": "T1059", "confidence": 0.90, "rationale": "RFI leads to execution of attacker-controlled code"},
        {"technique_id": "T1105", "confidence": 0.85, "rationale": "Remote file inclusion transfers attacker tools"},
        {"technique_id": "T1190", "confidence": 0.88, "rationale": "Exploits public-facing web application"},
    ],
    # CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
    "113": [
        {"technique_id": "T1189", "confidence": 0.78, "rationale": "HTTP header injection can enable drive-by attacks"},
        {"technique_id": "T1539", "confidence": 0.72, "rationale": "Can enable session hijacking"},
    ],
    # CWE-116: Improper Encoding or Escaping of Output
    "116": [
        {"technique_id": "T1059.007", "confidence": 0.80, "rationale": "Improper encoding can enable JavaScript injection (XSS)"},
        {"technique_id": "T1189", "confidence": 0.75, "rationale": "Can facilitate drive-by compromise via XSS"},
    ],
    # CWE-134: Use of Externally-Controlled Format String
    "134": [
        {"technique_id": "T1068", "confidence": 0.85, "rationale": "Format string vulnerabilities can enable privilege escalation"},
        {"technique_id": "T1059", "confidence": 0.80, "rationale": "Can lead to arbitrary code execution"},
    ],

    # ---- Cross-Site Scripting (XSS) ----
    # CWE-79: Cross-site Scripting
    "79": [
        {"technique_id": "T1189", "confidence": 0.92, "rationale": "XSS is a primary mechanism for drive-by compromise"},
        {"technique_id": "T1539", "confidence": 0.90, "rationale": "XSS is used to steal web session cookies"},
        {"technique_id": "T1059.007", "confidence": 0.88, "rationale": "XSS executes JavaScript in victim's browser"},
    ],
    # CWE-80: Improper Neutralization of Script-Related HTML Tags (Basic XSS)
    "80": [
        {"technique_id": "T1189", "confidence": 0.90, "rationale": "Basic XSS enables drive-by compromise"},
        {"technique_id": "T1539", "confidence": 0.85, "rationale": "Script injection can steal session cookies"},
    ],
    # CWE-83: Improper Neutralization of Script in Attributes in a Web Page
    "83": [
        {"technique_id": "T1189", "confidence": 0.88, "rationale": "Attribute-based XSS enables drive-by attacks"},
        {"technique_id": "T1059.007", "confidence": 0.82, "rationale": "Event handler script execution"},
    ],
    # CWE-84: Improper Neutralization of Encoded URI Schemes in a Web Page
    "84": [
        {"technique_id": "T1189", "confidence": 0.85, "rationale": "URI scheme injection enables drive-by actions"},
    ],

    # ---- Authentication and Authorization ----
    # CWE-287: Improper Authentication
    "287": [
        {"technique_id": "T1078", "confidence": 0.90, "rationale": "Broken authentication enables use of valid accounts without proper credentials"},
        {"technique_id": "T1110", "confidence": 0.80, "rationale": "Weak authentication facilitates brute force attacks"},
    ],
    # CWE-306: Missing Authentication for Critical Function
    "306": [
        {"technique_id": "T1078", "confidence": 0.95, "rationale": "Missing authentication allows direct access with no credentials"},
        {"technique_id": "T1190", "confidence": 0.88, "rationale": "Unauthenticated access to public-facing application"},
    ],
    # CWE-307: Improper Restriction of Excessive Authentication Attempts
    "307": [
        {"technique_id": "T1110", "confidence": 0.95, "rationale": "Missing lockout directly enables brute force attacks"},
        {"technique_id": "T1110.003", "confidence": 0.88, "rationale": "Enables password spraying attacks"},
    ],
    # CWE-308: Use of Single-factor Authentication
    "308": [
        {"technique_id": "T1078", "confidence": 0.85, "rationale": "Single-factor auth is more vulnerable to account takeover"},
        {"technique_id": "T1110", "confidence": 0.80, "rationale": "Single factor makes brute force more viable"},
    ],
    # CWE-521: Weak Password Requirements
    "521": [
        {"technique_id": "T1110", "confidence": 0.92, "rationale": "Weak password requirements facilitate brute force attacks"},
        {"technique_id": "T1078", "confidence": 0.80, "rationale": "Weak passwords increase risk of credential compromise"},
    ],
    # CWE-522: Insufficiently Protected Credentials
    "522": [
        {"technique_id": "T1552", "confidence": 0.92, "rationale": "Insufficiently protected credentials are unsecured credentials"},
        {"technique_id": "T1552.001", "confidence": 0.85, "rationale": "Credentials stored insecurely in files"},
    ],
    # CWE-523: Unprotected Transport of Credentials
    "523": [
        {"technique_id": "T1552", "confidence": 0.90, "rationale": "Credentials transmitted in cleartext can be intercepted"},
        {"technique_id": "T1539", "confidence": 0.75, "rationale": "Session tokens transmitted insecurely can be stolen"},
    ],
    # CWE-620: Unverified Password Change
    "620": [
        {"technique_id": "T1098", "confidence": 0.88, "rationale": "Unverified password change enables account manipulation"},
        {"technique_id": "T1078", "confidence": 0.80, "rationale": "Allows attacker to obtain valid account access"},
    ],
    # CWE-640: Weak Password Recovery Mechanism
    "640": [
        {"technique_id": "T1078", "confidence": 0.85, "rationale": "Weak recovery enables account takeover"},
        {"technique_id": "T1110", "confidence": 0.78, "rationale": "Weak recovery questions can be brute forced"},
    ],
    # CWE-798: Use of Hard-coded Credentials
    "798": [
        {"technique_id": "T1078.001", "confidence": 0.98, "rationale": "Hard-coded credentials are default account credentials"},
        {"technique_id": "T1552.001", "confidence": 0.90, "rationale": "Hard-coded credentials are insecure credentials in files"},
    ],
    # CWE-259: Use of Hard-coded Password
    "259": [
        {"technique_id": "T1078.001", "confidence": 0.98, "rationale": "Hard-coded passwords are default/static credentials"},
        {"technique_id": "T1552", "confidence": 0.90, "rationale": "Hard-coded passwords are unsecured credentials"},
    ],

    # ---- Access Control ----
    # CWE-22: Path Traversal
    "22": [
        {"technique_id": "T1083", "confidence": 0.92, "rationale": "Path traversal enables file and directory discovery/access"},
        {"technique_id": "T1005", "confidence": 0.85, "rationale": "Path traversal reads data from local system"},
        {"technique_id": "T1552.001", "confidence": 0.75, "rationale": "May expose credential files"},
    ],
    # CWE-23: Relative Path Traversal
    "23": [
        {"technique_id": "T1083", "confidence": 0.90, "rationale": "Relative path traversal enables directory traversal"},
        {"technique_id": "T1005", "confidence": 0.82, "rationale": "Enables reading of local system files"},
    ],
    # CWE-36: Absolute Path Traversal
    "36": [
        {"technique_id": "T1083", "confidence": 0.92, "rationale": "Absolute path traversal enables access to any file"},
        {"technique_id": "T1005", "confidence": 0.85, "rationale": "Reads data from local filesystem"},
    ],
    # CWE-284: Improper Access Control
    "284": [
        {"technique_id": "T1078", "confidence": 0.88, "rationale": "Improper access control allows unauthorized account usage"},
        {"technique_id": "T1068", "confidence": 0.80, "rationale": "May enable privilege escalation"},
    ],
    # CWE-285: Improper Authorization
    "285": [
        {"technique_id": "T1078", "confidence": 0.90, "rationale": "Improper authorization allows unauthorized actions"},
        {"technique_id": "T1068", "confidence": 0.78, "rationale": "Horizontal/vertical privilege escalation"},
    ],
    # CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
    "639": [
        {"technique_id": "T1078", "confidence": 0.88, "rationale": "IDOR enables access to other users' resources"},
        {"technique_id": "T1005", "confidence": 0.82, "rationale": "Enables access to data of other users"},
    ],
    # CWE-862: Missing Authorization
    "862": [
        {"technique_id": "T1078", "confidence": 0.92, "rationale": "Missing authorization checks allow unauthorized access"},
        {"technique_id": "T1190", "confidence": 0.82, "rationale": "Exposes functionality of public-facing application"},
    ],
    # CWE-863: Incorrect Authorization
    "863": [
        {"technique_id": "T1078", "confidence": 0.90, "rationale": "Incorrect authorization leads to unauthorized access"},
        {"technique_id": "T1068", "confidence": 0.78, "rationale": "Can enable privilege escalation"},
    ],
    # CWE-269: Improper Privilege Management
    "269": [
        {"technique_id": "T1068", "confidence": 0.90, "rationale": "Improper privilege management directly enables privilege escalation"},
        {"technique_id": "T1078", "confidence": 0.80, "rationale": "Overprivileged accounts are valid accounts with excessive rights"},
    ],

    # ---- Sensitive Data Exposure ----
    # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
    "200": [
        {"technique_id": "T1005", "confidence": 0.88, "rationale": "Sensitive data exposure leaks local system data"},
        {"technique_id": "T1552", "confidence": 0.75, "rationale": "May expose credential or key material"},
    ],
    # CWE-201: Insertion of Sensitive Information Into Sent Data
    "201": [
        {"technique_id": "T1041", "confidence": 0.80, "rationale": "Sensitive data sent over communication channel"},
        {"technique_id": "T1005", "confidence": 0.75, "rationale": "Sensitive data collected and transmitted"},
    ],
    # CWE-202: Exposure of Sensitive Information Through Data Queries
    "202": [
        {"technique_id": "T1005", "confidence": 0.85, "rationale": "Query-based data exposure leaks system data"},
        {"technique_id": "T1213", "confidence": 0.78, "rationale": "Data exposed from information repositories"},
    ],
    # CWE-203: Observable Discrepancy (Information Exposure)
    "203": [
        {"technique_id": "T1592", "confidence": 0.82, "rationale": "Observable discrepancies reveal host information to attacker"},
        {"technique_id": "T1518", "confidence": 0.75, "rationale": "Reveals software version and configuration"},
    ],
    # CWE-209: Generation of Error Message Containing Sensitive Information
    "209": [
        {"technique_id": "T1592", "confidence": 0.85, "rationale": "Detailed errors reveal stack traces and host information"},
        {"technique_id": "T1518", "confidence": 0.80, "rationale": "Reveals software versions and libraries"},
    ],
    # CWE-312: Cleartext Storage of Sensitive Information
    "312": [
        {"technique_id": "T1552.001", "confidence": 0.92, "rationale": "Cleartext storage of credentials enables credential theft"},
        {"technique_id": "T1005", "confidence": 0.85, "rationale": "Sensitive data accessible from local system"},
    ],
    # CWE-313: Cleartext Storage in a File or on Disk
    "313": [
        {"technique_id": "T1552.001", "confidence": 0.92, "rationale": "Credentials stored in cleartext files"},
        {"technique_id": "T1005", "confidence": 0.85, "rationale": "Sensitive data on disk can be read"},
    ],
    # CWE-319: Cleartext Transmission of Sensitive Information
    "319": [
        {"technique_id": "T1552", "confidence": 0.88, "rationale": "Cleartext transmission exposes credentials to interception"},
        {"technique_id": "T1041", "confidence": 0.75, "rationale": "Data transmitted in cleartext over channel"},
    ],
    # CWE-326: Inadequate Encryption Strength
    "326": [
        {"technique_id": "T1552", "confidence": 0.80, "rationale": "Weak encryption makes credentials recoverable"},
        {"technique_id": "T1485", "confidence": 0.60, "rationale": "Weak encryption may not protect data from destruction/manipulation"},
    ],
    # CWE-327: Use of a Broken or Risky Cryptographic Algorithm
    "327": [
        {"technique_id": "T1552", "confidence": 0.82, "rationale": "Broken crypto allows credential recovery"},
        {"technique_id": "T1212", "confidence": 0.70, "rationale": "Exploitable crypto for credential access"},
    ],
    # CWE-328: Use of Weak Hash
    "328": [
        {"technique_id": "T1110", "confidence": 0.88, "rationale": "Weak hashes (MD5, SHA1) are susceptible to brute force/rainbow tables"},
        {"technique_id": "T1552", "confidence": 0.82, "rationale": "Weak hashed credentials can be cracked"},
    ],
    # CWE-330: Use of Insufficiently Random Values
    "330": [
        {"technique_id": "T1212", "confidence": 0.80, "rationale": "Predictable values enable cryptographic attacks"},
        {"technique_id": "T1539", "confidence": 0.75, "rationale": "Predictable session tokens can be forged"},
    ],

    # ---- XML and SSRF ----
    # CWE-611: Improper Restriction of XML External Entity Reference (XXE)
    "611": [
        {"technique_id": "T1190", "confidence": 0.95, "rationale": "XXE exploits a public-facing application's XML parsing"},
        {"technique_id": "T1005", "confidence": 0.88, "rationale": "XXE reads arbitrary files from local system"},
        {"technique_id": "T1046", "confidence": 0.75, "rationale": "XXE can be used for internal network discovery via SSRF-like behavior"},
    ],
    # CWE-776: Improper Restriction of Recursive Entity References in DTDs (XML Bomb)
    "776": [
        {"technique_id": "T1499", "confidence": 0.90, "rationale": "XML bomb causes denial of service"},
        {"technique_id": "T1499.004", "confidence": 0.85, "rationale": "Exploits XML parser to crash application"},
    ],
    # CWE-918: Server-Side Request Forgery (SSRF)
    "918": [
        {"technique_id": "T1190", "confidence": 0.90, "rationale": "SSRF exploits public-facing application to reach internal systems"},
        {"technique_id": "T1046", "confidence": 0.88, "rationale": "SSRF enables internal network service discovery"},
        {"technique_id": "T1580", "confidence": 0.80, "rationale": "SSRF can enumerate cloud infrastructure (IMDS, etc.)"},
    ],

    # ---- Deserialization ----
    # CWE-502: Deserialization of Untrusted Data
    "502": [
        {"technique_id": "T1059", "confidence": 0.93, "rationale": "Insecure deserialization leads to remote code execution"},
        {"technique_id": "T1190", "confidence": 0.90, "rationale": "Exploits deserialization in public-facing application"},
        {"technique_id": "T1068", "confidence": 0.78, "rationale": "Can lead to privilege escalation via code execution"},
    ],

    # ---- File Upload ----
    # CWE-434: Unrestricted Upload of File with Dangerous Type
    "434": [
        {"technique_id": "T1505.003", "confidence": 0.95, "rationale": "Unrestricted file upload is the primary way to plant a web shell"},
        {"technique_id": "T1059", "confidence": 0.88, "rationale": "Uploaded files can contain executable code"},
        {"technique_id": "T1190", "confidence": 0.85, "rationale": "Exploits file handling in public-facing application"},
    ],
    # CWE-73: External Control of File Name or Path
    "73": [
        {"technique_id": "T1083", "confidence": 0.85, "rationale": "Controlled file paths enable directory traversal"},
        {"technique_id": "T1005", "confidence": 0.80, "rationale": "Can access arbitrary files on local system"},
    ],

    # ---- Cross-Site Request Forgery ----
    # CWE-352: Cross-Site Request Forgery (CSRF)
    "352": [
        {"technique_id": "T1098", "confidence": 0.88, "rationale": "CSRF can force authenticated users to modify accounts"},
        {"technique_id": "T1204", "confidence": 0.80, "rationale": "CSRF relies on user execution of forged requests"},
    ],

    # ---- Open Redirect ----
    # CWE-601: URL Redirection to Untrusted Site (Open Redirect)
    "601": [
        {"technique_id": "T1566.002", "confidence": 0.85, "rationale": "Open redirects used in phishing spearphishing link attacks"},
        {"technique_id": "T1189", "confidence": 0.78, "rationale": "Can redirect users to malicious sites for drive-by compromise"},
    ],

    # ---- Memory Corruption ----
    # CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
    "119": [
        {"technique_id": "T1068", "confidence": 0.88, "rationale": "Buffer overflow vulnerabilities enable privilege escalation"},
        {"technique_id": "T1203", "confidence": 0.85, "rationale": "Client-side buffer overflows exploited for code execution"},
        {"technique_id": "T1190", "confidence": 0.80, "rationale": "Remote buffer overflows in public-facing services"},
    ],
    # CWE-120: Buffer Copy without Checking Size of Input (Classic Buffer Overflow)
    "120": [
        {"technique_id": "T1068", "confidence": 0.90, "rationale": "Classic buffer overflow commonly exploited for privilege escalation"},
        {"technique_id": "T1203", "confidence": 0.82, "rationale": "Client-side exploitation via buffer overflow"},
    ],
    # CWE-121: Stack-based Buffer Overflow
    "121": [
        {"technique_id": "T1068", "confidence": 0.92, "rationale": "Stack overflow enables privilege escalation via RIP/EIP control"},
        {"technique_id": "T1059", "confidence": 0.85, "rationale": "Stack overflow leads to arbitrary code execution"},
    ],
    # CWE-122: Heap-based Buffer Overflow
    "122": [
        {"technique_id": "T1068", "confidence": 0.90, "rationale": "Heap overflow enables privilege escalation"},
        {"technique_id": "T1059", "confidence": 0.82, "rationale": "Heap overflow leads to code execution"},
    ],
    # CWE-123: Write-what-where Condition
    "123": [
        {"technique_id": "T1068", "confidence": 0.92, "rationale": "Write-what-where directly enables privilege escalation"},
    ],
    # CWE-125: Out-of-bounds Read
    "125": [
        {"technique_id": "T1005", "confidence": 0.80, "rationale": "Out-of-bounds read leaks memory/data"},
        {"technique_id": "T1592", "confidence": 0.70, "rationale": "Memory leaks reveal host information"},
    ],
    # CWE-190: Integer Overflow or Wraparound
    "190": [
        {"technique_id": "T1068", "confidence": 0.82, "rationale": "Integer overflow can lead to buffer overflow and privilege escalation"},
        {"technique_id": "T1499.004", "confidence": 0.75, "rationale": "Integer overflow can cause application crashes"},
    ],
    # CWE-416: Use After Free
    "416": [
        {"technique_id": "T1068", "confidence": 0.88, "rationale": "Use-after-free is commonly exploited for privilege escalation"},
        {"technique_id": "T1203", "confidence": 0.82, "rationale": "Client-side exploitation via use-after-free"},
    ],
    # CWE-476: NULL Pointer Dereference
    "476": [
        {"technique_id": "T1499.004", "confidence": 0.88, "rationale": "NULL dereference typically causes application/system crash"},
        {"technique_id": "T1499", "confidence": 0.82, "rationale": "Leads to denial of service condition"},
    ],

    # ---- Race Conditions ----
    # CWE-362: Race Condition (Concurrent Execution Using Shared Resource with Improper Synchronization)
    "362": [
        {"technique_id": "T1068", "confidence": 0.80, "rationale": "TOCTOU race conditions can be exploited for privilege escalation"},
    ],
    # CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
    "367": [
        {"technique_id": "T1068", "confidence": 0.85, "rationale": "TOCTOU is a classic privilege escalation vector"},
    ],

    # ---- Cryptographic Issues ----
    # CWE-295: Improper Certificate Validation
    "295": [
        {"technique_id": "T1552", "confidence": 0.82, "rationale": "Invalid cert validation exposes credentials to MitM"},
        {"technique_id": "T1539", "confidence": 0.78, "rationale": "TLS bypass exposes session tokens"},
    ],
    # CWE-297: Improper Validation of Certificate with Host Mismatch
    "297": [
        {"technique_id": "T1552", "confidence": 0.80, "rationale": "Host mismatch allows credential interception via MitM"},
    ],
    # CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    "338": [
        {"technique_id": "T1212", "confidence": 0.80, "rationale": "Weak PRNG enables prediction of cryptographic values"},
        {"technique_id": "T1539", "confidence": 0.75, "rationale": "Predictable session tokens enable session hijacking"},
    ],

    # ---- Configuration and Logging ----
    # CWE-16: Configuration
    "16": [
        {"technique_id": "T1562", "confidence": 0.78, "rationale": "Misconfiguration can impair security controls"},
        {"technique_id": "T1078", "confidence": 0.70, "rationale": "Misconfigured access controls allow unauthorized access"},
    ],
    # CWE-778: Insufficient Logging
    "778": [
        {"technique_id": "T1070", "confidence": 0.80, "rationale": "Insufficient logging reduces indicator detection; attackers rely on this for evasion"},
        {"technique_id": "T1562", "confidence": 0.75, "rationale": "Missing logs impair defensive monitoring"},
    ],
    # CWE-779: Logging of Excessive Data
    "779": [
        {"technique_id": "T1005", "confidence": 0.72, "rationale": "Excessive logging may capture sensitive data"},
    ],

    # ---- Template Injection ----
    # CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine (SSTI)
    "1336": [
        {"technique_id": "T1059", "confidence": 0.95, "rationale": "Server-side template injection leads to code execution"},
        {"technique_id": "T1190", "confidence": 0.90, "rationale": "SSTI exploits public-facing web application"},
        {"technique_id": "T1505.003", "confidence": 0.75, "rationale": "SSTI can be used to plant web shells"},
    ],

    # ---- Prototype Pollution ----
    # CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
    "1321": [
        {"technique_id": "T1059.007", "confidence": 0.88, "rationale": "Prototype pollution affects JavaScript execution context"},
        {"technique_id": "T1190", "confidence": 0.82, "rationale": "Exploits application-layer JavaScript processing"},
    ],

    # ---- LDAP Injection ----
    # CWE-90: Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)
    "90": [
        {"technique_id": "T1190", "confidence": 0.88, "rationale": "LDAP injection exploits application's directory service queries"},
        {"technique_id": "T1078", "confidence": 0.80, "rationale": "Can bypass authentication or retrieve user credentials"},
    ],

    # ---- Clickjacking / UI Redress ----
    # CWE-1021: Improper Restriction of Rendered UI Layers or Frames (Clickjacking)
    "1021": [
        {"technique_id": "T1204", "confidence": 0.85, "rationale": "Clickjacking tricks users into executing actions"},
        {"technique_id": "T1189", "confidence": 0.75, "rationale": "UI redress attack component of drive-by compromise"},
    ],

    # ---- Dependency / Supply Chain ----
    # CWE-1104: Use of Unmaintained Third Party Components
    "1104": [
        {"technique_id": "T1195.002", "confidence": 0.88, "rationale": "Unmaintained components may contain supply chain vulnerabilities"},
        {"technique_id": "T1190", "confidence": 0.80, "rationale": "Vulnerable components exploitable in public-facing applications"},
    ],
    # CWE-1395: Dependency on Vulnerable Third-Party Component
    "1395": [
        {"technique_id": "T1195.002", "confidence": 0.92, "rationale": "Directly represents software supply chain compromise risk"},
        {"technique_id": "T1190", "confidence": 0.82, "rationale": "Vulnerable dependency exploitable in public apps"},
    ],

    # ---- Mass Assignment ----
    # CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
    "915": [
        {"technique_id": "T1078", "confidence": 0.85, "rationale": "Mass assignment may allow privilege escalation via role modification"},
        {"technique_id": "T1068", "confidence": 0.80, "rationale": "Enables privilege modification through over-posting"},
    ],

    # ---- HTTP Smuggling ----
    # CWE-444: Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)
    "444": [
        {"technique_id": "T1190", "confidence": 0.88, "rationale": "HTTP smuggling exploits inconsistencies in application-layer parsing"},
        {"technique_id": "T1539", "confidence": 0.80, "rationale": "Request smuggling can capture session cookies from other users"},
    ],

    # ---- Timing Attacks ----
    # CWE-208: Observable Timing Discrepancy
    "208": [
        {"technique_id": "T1212", "confidence": 0.80, "rationale": "Timing side-channels enable credential/key extraction"},
        {"technique_id": "T1110", "confidence": 0.72, "rationale": "Timing information aids password brute force"},
    ],

    # ---- JWT / Token Issues ----
    # CWE-347: Improper Verification of Cryptographic Signature
    "347": [
        {"technique_id": "T1528", "confidence": 0.88, "rationale": "Unverified JWT/token signatures enable token forgery"},
        {"technique_id": "T1078", "confidence": 0.82, "rationale": "Forged tokens enable unauthorized account access"},
    ],

    # ---- Log Injection ----
    # CWE-117: Improper Output Neutralization for Logs
    "117": [
        {"technique_id": "T1070", "confidence": 0.85, "rationale": "Log injection can falsify audit trails to evade detection"},
        {"technique_id": "T1562", "confidence": 0.75, "rationale": "Injected log entries impair defensive monitoring"},
    ],
}

# ---------------------------------------------------------------------------
# CVE → MITRE ATT&CK Technique Mappings
# Well-known CVEs with documented ATT&CK technique associations
# ---------------------------------------------------------------------------

CVE_TO_TECHNIQUES: Dict[str, List[Dict[str, Any]]] = {
    # Log4Shell
    "CVE-2021-44228": [
        {"technique_id": "T1190", "confidence": 0.98, "rationale": "Log4Shell is a remote code execution exploit in public-facing applications using Log4j"},
        {"technique_id": "T1059", "confidence": 0.95, "rationale": "Log4Shell achieves arbitrary code execution via JNDI injection"},
        {"technique_id": "T1105", "confidence": 0.85, "rationale": "Commonly used to download second-stage payloads"},
    ],
    # ProxyLogon (Exchange)
    "CVE-2021-26855": [
        {"technique_id": "T1190", "confidence": 0.98, "rationale": "ProxyLogon is a server-side request forgery in Microsoft Exchange (public-facing)"},
        {"technique_id": "T1505.003", "confidence": 0.90, "rationale": "ProxyLogon chained with ProxyShell to deploy web shells"},
    ],
    # PrintNightmare
    "CVE-2021-34527": [
        {"technique_id": "T1068", "confidence": 0.95, "rationale": "PrintNightmare is a local privilege escalation / remote code execution vulnerability"},
        {"technique_id": "T1059", "confidence": 0.88, "rationale": "Enables arbitrary DLL loading and code execution"},
    ],
    # EternalBlue (SMB)
    "CVE-2017-0144": [
        {"technique_id": "T1210", "confidence": 0.98, "rationale": "EternalBlue exploits remote SMB service for lateral movement"},
        {"technique_id": "T1059", "confidence": 0.90, "rationale": "Achieves remote code execution on target systems"},
    ],
    # Heartbleed
    "CVE-2014-0160": [
        {"technique_id": "T1552", "confidence": 0.95, "rationale": "Heartbleed reads server memory exposing private keys and credentials"},
        {"technique_id": "T1552.004", "confidence": 0.92, "rationale": "Heartbleed specifically targets private TLS keys"},
        {"technique_id": "T1005", "confidence": 0.85, "rationale": "Out-of-bounds memory read leaks local system data"},
    ],
    # Shellshock
    "CVE-2014-6271": [
        {"technique_id": "T1059.004", "confidence": 0.98, "rationale": "Shellshock directly executes Unix shell commands via Bash vulnerability"},
        {"technique_id": "T1190", "confidence": 0.92, "rationale": "Exploitable via web servers and CGI (public-facing)"},
    ],
    # Apache Struts (Equifax breach)
    "CVE-2017-5638": [
        {"technique_id": "T1190", "confidence": 0.98, "rationale": "Struts2 RCE directly exploits a public-facing Java application"},
        {"technique_id": "T1059", "confidence": 0.95, "rationale": "Remote code execution via OGNL injection"},
    ],
    # Spring4Shell
    "CVE-2022-22965": [
        {"technique_id": "T1190", "confidence": 0.97, "rationale": "Spring4Shell is RCE in Spring Framework public-facing applications"},
        {"technique_id": "T1059", "confidence": 0.92, "rationale": "Achieves remote code execution via class loader manipulation"},
    ],
    # SolarWinds SUNBURST
    "CVE-2020-10148": [
        {"technique_id": "T1195.002", "confidence": 0.98, "rationale": "SolarWinds was a software supply chain compromise"},
        {"technique_id": "T1071.001", "confidence": 0.90, "rationale": "SUNBURST used web protocols for C2 communication"},
    ],
    # BlueKeep (RDP)
    "CVE-2019-0708": [
        {"technique_id": "T1210", "confidence": 0.95, "rationale": "BlueKeep is a wormable RDP exploit for lateral movement"},
        {"technique_id": "T1190", "confidence": 0.85, "rationale": "Exploits external-facing RDP service"},
    ],
    # ZeroLogon
    "CVE-2020-1472": [
        {"technique_id": "T1068", "confidence": 0.95, "rationale": "ZeroLogon enables privilege escalation to domain admin"},
        {"technique_id": "T1078", "confidence": 0.90, "rationale": "Allows takeover of domain controller account"},
    ],
    # Citrix ADC (Shitrix)
    "CVE-2019-19781": [
        {"technique_id": "T1190", "confidence": 0.97, "rationale": "Path traversal RCE in Citrix ADC (public-facing)"},
        {"technique_id": "T1059", "confidence": 0.92, "rationale": "Achieves unauthenticated remote code execution"},
    ],
    # MOVEit Transfer
    "CVE-2023-34362": [
        {"technique_id": "T1190", "confidence": 0.98, "rationale": "MOVEit SQLi leads to RCE in public-facing file transfer application"},
        {"technique_id": "T1505.003", "confidence": 0.90, "rationale": "Exploited to deploy web shells on MOVEit servers"},
    ],
    # Confluence OGNL injection
    "CVE-2022-26134": [
        {"technique_id": "T1190", "confidence": 0.97, "rationale": "Confluence OGNL injection is unauthenticated RCE in public-facing wiki"},
        {"technique_id": "T1059", "confidence": 0.93, "rationale": "OGNL injection achieves server-side code execution"},
    ],
    # GitLab RCE
    "CVE-2021-22205": [
        {"technique_id": "T1190", "confidence": 0.96, "rationale": "GitLab RCE via ExifTool image parsing in public-facing DevOps platform"},
        {"technique_id": "T1059", "confidence": 0.90, "rationale": "Achieves remote code execution on GitLab server"},
    ],
}

# ---------------------------------------------------------------------------
# Text-based matching rules
# Maps vulnerability title/description keywords → ATT&CK techniques
# ---------------------------------------------------------------------------

TEXT_MATCH_RULES: List[Dict[str, Any]] = [
    # SQL Injection patterns
    {
        "patterns": [r"sql\s+inject", r"sqli", r"sql\s+injection"],
        "technique_id": "T1190",
        "confidence": 0.90,
        "rationale": "SQL injection matches public-facing application exploitation",
    },
    {
        "patterns": [r"sql\s+inject", r"sqli"],
        "technique_id": "T1005",
        "confidence": 0.78,
        "rationale": "SQL injection enables database data extraction",
    },
    # XSS patterns
    {
        "patterns": [r"cross.?site\s+script", r"\bxss\b", r"script\s+inject"],
        "technique_id": "T1189",
        "confidence": 0.88,
        "rationale": "XSS is a primary drive-by compromise technique",
    },
    {
        "patterns": [r"cross.?site\s+script", r"\bxss\b"],
        "technique_id": "T1539",
        "confidence": 0.85,
        "rationale": "XSS commonly used to steal session cookies",
    },
    # Command injection patterns
    {
        "patterns": [r"command\s+inject", r"os\s+inject", r"shell\s+inject", r"rce\b", r"remote\s+code\s+exec"],
        "technique_id": "T1059",
        "confidence": 0.93,
        "rationale": "Command/code injection leads to command execution",
    },
    {
        "patterns": [r"command\s+inject", r"os\s+inject", r"rce\b", r"remote\s+code\s+exec"],
        "technique_id": "T1190",
        "confidence": 0.90,
        "rationale": "Remote code execution exploits public-facing application",
    },
    # Path traversal
    {
        "patterns": [r"path\s+travers", r"directory\s+travers", r"dot.?dot.?slash", r"\.\./"],
        "technique_id": "T1083",
        "confidence": 0.90,
        "rationale": "Path traversal enables file system access",
    },
    # SSRF
    {
        "patterns": [r"\bssrf\b", r"server.?side\s+request\s+forg"],
        "technique_id": "T1190",
        "confidence": 0.88,
        "rationale": "SSRF exploits public-facing application to reach internal services",
    },
    {
        "patterns": [r"\bssrf\b", r"server.?side\s+request\s+forg"],
        "technique_id": "T1046",
        "confidence": 0.85,
        "rationale": "SSRF enables internal network service discovery",
    },
    # XXE
    {
        "patterns": [r"\bxxe\b", r"xml\s+external\s+entit", r"xml\s+inject"],
        "technique_id": "T1190",
        "confidence": 0.92,
        "rationale": "XXE exploits XML parsing in public-facing applications",
    },
    {
        "patterns": [r"\bxxe\b", r"xml\s+external\s+entit"],
        "technique_id": "T1005",
        "confidence": 0.85,
        "rationale": "XXE reads local files from server",
    },
    # Deserialization
    {
        "patterns": [r"deserializ", r"insecure\s+deserializ", r"java\s+deserializ"],
        "technique_id": "T1059",
        "confidence": 0.90,
        "rationale": "Insecure deserialization enables code execution",
    },
    {
        "patterns": [r"deserializ", r"insecure\s+deserializ"],
        "technique_id": "T1190",
        "confidence": 0.85,
        "rationale": "Deserialization exploit in public-facing application",
    },
    # CSRF
    {
        "patterns": [r"\bcsrf\b", r"cross.?site\s+request\s+forg"],
        "technique_id": "T1098",
        "confidence": 0.85,
        "rationale": "CSRF forces account manipulation actions",
    },
    # Authentication bypass
    {
        "patterns": [r"auth(entication)?\s+bypass", r"broken\s+auth", r"missing\s+auth"],
        "technique_id": "T1078",
        "confidence": 0.90,
        "rationale": "Authentication bypass enables use of accounts without credentials",
    },
    {
        "patterns": [r"auth(entication)?\s+bypass", r"broken\s+auth"],
        "technique_id": "T1110",
        "confidence": 0.78,
        "rationale": "Broken authentication facilitates brute force",
    },
    # Brute force / weak passwords
    {
        "patterns": [r"brute\s+force", r"weak\s+pass", r"password\s+spray", r"no\s+lockout", r"account\s+lockout"],
        "technique_id": "T1110",
        "confidence": 0.92,
        "rationale": "Weak authentication directly enables brute force",
    },
    # Hardcoded credentials
    {
        "patterns": [r"hard.?coded\s+(cred|pass|secret|key|token)", r"default\s+(cred|pass)"],
        "technique_id": "T1078.001",
        "confidence": 0.95,
        "rationale": "Hard-coded / default credentials enable default account access",
    },
    {
        "patterns": [r"hard.?coded\s+(cred|pass|secret|key|token)", r"default\s+(cred|pass)"],
        "technique_id": "T1552",
        "confidence": 0.88,
        "rationale": "Hard-coded credentials are unsecured credentials",
    },
    # Sensitive data / info disclosure
    {
        "patterns": [r"sensitive\s+data", r"info(rmation)?\s+disclos", r"data\s+exposure", r"info\s+leak"],
        "technique_id": "T1005",
        "confidence": 0.82,
        "rationale": "Information disclosure exposes local system data",
    },
    # Error messages / stack traces
    {
        "patterns": [r"stack\s+trace", r"verbose\s+error", r"debug\s+info", r"error\s+message.*sensitiv"],
        "technique_id": "T1592",
        "confidence": 0.82,
        "rationale": "Error messages reveal host and software information",
    },
    # Open redirect
    {
        "patterns": [r"open\s+redirect", r"unvalidated\s+redirect"],
        "technique_id": "T1566.002",
        "confidence": 0.85,
        "rationale": "Open redirects used as phishing link components",
    },
    # File upload
    {
        "patterns": [r"unrestricted\s+file\s+upload", r"dangerous\s+file\s+type", r"file\s+upload.*bypass"],
        "technique_id": "T1505.003",
        "confidence": 0.92,
        "rationale": "Unrestricted file upload enables web shell deployment",
    },
    # Privilege escalation
    {
        "patterns": [r"privilege\s+escal", r"privesc", r"sudo\s+misconfigur", r"suid\s+misconfig"],
        "technique_id": "T1068",
        "confidence": 0.90,
        "rationale": "Privilege escalation vulnerability enables elevation of privileges",
    },
    # Buffer overflow
    {
        "patterns": [r"buffer\s+overflow", r"heap\s+overflow", r"stack\s+overflow", r"memory\s+corrup"],
        "technique_id": "T1068",
        "confidence": 0.88,
        "rationale": "Memory corruption vulnerabilities enable privilege escalation",
    },
    # Cleartext / unencrypted
    {
        "patterns": [r"cleartext", r"plain.?text.*pass", r"unencrypted.*pass", r"http\s+not\s+https"],
        "technique_id": "T1552",
        "confidence": 0.85,
        "rationale": "Cleartext credentials are unsecured credentials",
    },
    # JWT issues
    {
        "patterns": [r"jwt.*none\s+algorithm", r"jwt.*alg.*none", r"jwt\s+bypass", r"token\s+forg"],
        "technique_id": "T1528",
        "confidence": 0.88,
        "rationale": "JWT algorithm confusion allows application access token theft/forgery",
    },
    # SSTI
    {
        "patterns": [r"server.?side\s+template\s+inject", r"\bssti\b"],
        "technique_id": "T1059",
        "confidence": 0.93,
        "rationale": "SSTI executes arbitrary code via template engine",
    },
    {
        "patterns": [r"server.?side\s+template\s+inject", r"\bssti\b"],
        "technique_id": "T1190",
        "confidence": 0.88,
        "rationale": "SSTI exploits public-facing application",
    },
    # Prototype pollution
    {
        "patterns": [r"prototype\s+pollution"],
        "technique_id": "T1059.007",
        "confidence": 0.85,
        "rationale": "Prototype pollution affects JavaScript execution",
    },
    # Cryptographic weakness
    {
        "patterns": [r"weak\s+crypt", r"md5\s+hash", r"sha1\s+hash", r"broken\s+crypt"],
        "technique_id": "T1110",
        "confidence": 0.82,
        "rationale": "Weak hashes enable offline password cracking",
    },
    # Supply chain / dependency
    {
        "patterns": [r"supply\s+chain", r"dependency.*vulnerab", r"vulnerable.*dependency", r"outdated.*component"],
        "technique_id": "T1195.002",
        "confidence": 0.88,
        "rationale": "Vulnerable dependencies represent software supply chain risk",
    },
    # DoS / resource exhaustion
    {
        "patterns": [r"denial.?of.?service", r"\bdos\b", r"resource\s+exhaust", r"xml\s+bomb", r"regex\s+dos", r"\bredos\b"],
        "technique_id": "T1499",
        "confidence": 0.88,
        "rationale": "DoS vulnerabilities lead to endpoint denial of service",
    },
    # Mass assignment
    {
        "patterns": [r"mass\s+assign", r"over.?post", r"parameter\s+pollution"],
        "technique_id": "T1078",
        "confidence": 0.82,
        "rationale": "Mass assignment may allow privilege escalation via role modification",
    },
    # Insecure direct object reference (IDOR)
    {
        "patterns": [r"\bidor\b", r"insecure\s+direct\s+object", r"broken\s+access\s+control"],
        "technique_id": "T1078",
        "confidence": 0.85,
        "rationale": "IDOR allows unauthorized access to other users' objects",
    },
    # Web shell
    {
        "patterns": [r"web\s+shell", r"webshell", r"backdoor.*upload"],
        "technique_id": "T1505.003",
        "confidence": 0.98,
        "rationale": "Web shell is a direct persistence mechanism",
    },
    # Request smuggling
    {
        "patterns": [r"http\s+request\s+smuggl", r"request\s+smuggl"],
        "technique_id": "T1190",
        "confidence": 0.88,
        "rationale": "HTTP request smuggling exploits application-layer inconsistencies",
    },
    # Clickjacking
    {
        "patterns": [r"clickjack", r"ui\s+redress", r"x-?frame-?options"],
        "technique_id": "T1204",
        "confidence": 0.82,
        "rationale": "Clickjacking tricks users into executing unintended actions",
    },
    # Security misconfiguration
    {
        "patterns": [r"security\s+misconfigur", r"cors\s+misconfigur", r"misconfigur.*header", r"missing\s+security.*header"],
        "technique_id": "T1562",
        "confidence": 0.80,
        "rationale": "Security misconfigurations impair defensive capabilities",
    },
    # Certificate / TLS issues
    {
        "patterns": [r"invalid\s+cert", r"cert.*not\s+valid", r"ssl.*vulnerab", r"tls.*vulnerab", r"weak\s+tls", r"sslv[23]"],
        "technique_id": "T1552",
        "confidence": 0.80,
        "rationale": "TLS/cert issues expose credentials to interception",
    },
    # Insecure cookies
    {
        "patterns": [r"insecure\s+cookie", r"cookie.*missing.*httponly", r"cookie.*missing.*secure", r"session.*fixat"],
        "technique_id": "T1539",
        "confidence": 0.85,
        "rationale": "Insecure cookies facilitate session cookie theft",
    },
    # Log injection
    {
        "patterns": [r"log\s+inject", r"log\s+forg"],
        "technique_id": "T1070",
        "confidence": 0.82,
        "rationale": "Log injection can falsify audit trails",
    },
    # Scanning / enumeration
    {
        "patterns": [r"user\s+enum", r"username\s+enum", r"account\s+enum"],
        "technique_id": "T1589",
        "confidence": 0.82,
        "rationale": "Username enumeration is reconnaissance for victim identities",
    },
    # Race condition
    {
        "patterns": [r"race\s+condition", r"toctou", r"time.?of.?check"],
        "technique_id": "T1068",
        "confidence": 0.80,
        "rationale": "Race conditions can enable privilege escalation",
    },
    # Cryptomining / resource hijacking
    {
        "patterns": [r"crypto\s*min", r"resource\s+hijack", r"coin\s*min"],
        "technique_id": "T1496",
        "confidence": 0.88,
        "rationale": "Cryptomining malware hijacks system resources",
    },
    # Ransomware / encryption for impact
    {
        "patterns": [r"ransom", r"encrypt.*impact", r"data.*encrypt.*for.*impact"],
        "technique_id": "T1486",
        "confidence": 0.90,
        "rationale": "Ransomware encrypts data for impact",
    },
]

# Compile text match patterns for performance
_COMPILED_TEXT_RULES: List[Dict[str, Any]] = []
for rule in TEXT_MATCH_RULES:
    compiled = [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]
    _COMPILED_TEXT_RULES.append({**rule, "_compiled": compiled})


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TechniqueMapping:
    """A single technique mapping result."""
    technique_id: str
    technique_name: str
    tactic_ids: List[str]
    tactic_names: List[str]
    confidence: float
    source: str          # "cwe", "cve", "text_match"
    source_ref: str      # CWE-89, CVE-2021-44228, or matched text
    rationale: str
    technique_url: str


@dataclass
class FindingMappingResult:
    """Result of mapping a single finding."""
    finding_id: str
    finding_title: str
    cwe_id: Optional[str]
    cve_ids: List[str]
    techniques: List[TechniqueMapping]
    primary_tactic: Optional[str]
    risk_score: float    # 0.0 – 10.0


@dataclass
class KillChainCoverage:
    """Kill chain phase coverage analysis."""
    tactic_id: str
    tactic_name: str
    covered: bool
    technique_count: int
    techniques: List[str]
    highest_confidence: float


@dataclass
class MappingEngineResult:
    """Full mapping result for a set of findings."""
    session_id: str
    mapped_at: str
    total_findings: int
    total_techniques: int
    total_tactics_covered: int
    kill_chain_coverage: List[KillChainCoverage]
    finding_results: List[FindingMappingResult]
    all_techniques: List[str]
    technique_frequency: Dict[str, int]
    coverage_percentage: float


# ---------------------------------------------------------------------------
# Core Mapping Engine
# ---------------------------------------------------------------------------

class MITREMapper:
    """
    MITRE ATT&CK v14 Application-Layer Mapping Engine.

    Maps CWE IDs, CVE IDs, and vulnerability text to ATT&CK techniques.
    All mapping data is embedded — no external API calls required.
    """

    def __init__(self):
        self._techniques = TECHNIQUES
        self._tactics = TACTICS
        self._cwe_map = CWE_TO_TECHNIQUES
        self._cve_map = CVE_TO_TECHNIQUES
        self._text_rules = _COMPILED_TEXT_RULES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def map_finding(self, finding: Dict[str, Any]) -> FindingMappingResult:
        """
        Map a single security finding to MITRE ATT&CK techniques.

        Args:
            finding: Dict with keys: id, title, description (optional),
                     cwe_id (optional), cve_ids (optional list)

        Returns:
            FindingMappingResult with all matched techniques
        """
        _emit_event("finding.created", {"module": __name__, "action": "map_finding"})
        finding_id = str(finding.get("id", str(uuid.uuid4())))
        title = str(finding.get("title", ""))
        description = str(finding.get("description", ""))
        cwe_id = self._normalize_cwe(finding.get("cwe_id"))
        cve_ids = [str(c).upper() for c in (finding.get("cve_ids") or [])]
        if finding.get("cve_id"):
            cve_ids.append(str(finding["cve_id"]).upper())

        # Deduplicate CVE IDs
        cve_ids = list(dict.fromkeys(cve_ids))

        # Collect mappings from all sources
        raw_mappings: List[Tuple[str, float, str, str]] = []  # (technique_id, confidence, source, ref)

        # 1. CWE → techniques
        if cwe_id and cwe_id in self._cwe_map:
            for m in self._cwe_map[cwe_id]:
                raw_mappings.append((m["technique_id"], m["confidence"], "cwe", f"CWE-{cwe_id}", m["rationale"]))

        # 2. CVE → techniques
        for cve in cve_ids:
            if cve in self._cve_map:
                for m in self._cve_map[cve]:
                    raw_mappings.append((m["technique_id"], m["confidence"], "cve", cve, m["rationale"]))

        # 3. Text matching on title + description
        combined_text = f"{title} {description}"
        for rule in self._text_rules:
            for compiled_re in rule["_compiled"]:
                if compiled_re.search(combined_text):
                    raw_mappings.append((
                        rule["technique_id"],
                        rule["confidence"] * 0.85,  # Slight confidence discount for text-only
                        "text_match",
                        title[:80],
                        rule["rationale"],
                    ))
                    break  # Only match each rule once per finding

        # Deduplicate: keep highest confidence per technique_id
        best: Dict[str, Tuple[float, str, str, str]] = {}
        for tid, conf, source, ref, rationale in raw_mappings:
            if tid not in best or conf > best[tid][0]:
                best[tid] = (conf, source, ref, rationale)

        # Build TechniqueMapping objects
        techniques: List[TechniqueMapping] = []
        for tid, (conf, source, ref, rationale) in best.items():
            if tid not in self._techniques:
                continue
            t = self._techniques[tid]
            tactic_names = [self._tactics[ta]["name"] for ta in t["tactic_ids"] if ta in self._tactics]
            techniques.append(TechniqueMapping(
                technique_id=tid,
                technique_name=t["name"],
                tactic_ids=t["tactic_ids"],
                tactic_names=tactic_names,
                confidence=round(conf, 3),
                source=source,
                source_ref=ref,
                rationale=rationale,
                technique_url=t["url"],
            ))

        # Sort by confidence descending
        techniques.sort(key=lambda x: x.confidence, reverse=True)

        # Determine primary tactic (tactic of highest-confidence technique, preferring Initial Access)
        primary_tactic = self._infer_primary_tactic(techniques)

        # Compute risk score: weighted by severity and coverage
        risk_score = self._compute_risk_score(finding, techniques)

        return FindingMappingResult(
            finding_id=finding_id,
            finding_title=title,
            cwe_id=cwe_id,
            cve_ids=cve_ids,
            techniques=techniques,
            primary_tactic=primary_tactic,
            risk_score=risk_score,
        )

    def map_findings(self, findings: List[Dict[str, Any]]) -> MappingEngineResult:
        """
        Map a collection of findings and produce a complete kill chain analysis.

        Args:
            findings: List of finding dicts

        Returns:
            MappingEngineResult with full analysis
        """
        _emit_event("finding.updated", {"module": __name__, "action": "map_findings"})
        session_id = str(uuid.uuid4())
        mapped_at = datetime.now(timezone.utc).isoformat()

        finding_results = [self.map_finding(f) for f in findings]

        # Aggregate technique frequency
        tech_freq: Dict[str, int] = {}
        all_tids: Set[str] = set()
        for fr in finding_results:
            for tm in fr.techniques:
                tech_freq[tm.technique_id] = tech_freq.get(tm.technique_id, 0) + 1
                all_tids.add(tm.technique_id)

        # Kill chain coverage
        kc_coverage = self._build_kill_chain_coverage(finding_results)

        covered_tactics = sum(1 for kc in kc_coverage if kc.covered)
        coverage_pct = round(covered_tactics / len(TACTICS) * 100, 1)

        return MappingEngineResult(
            session_id=session_id,
            mapped_at=mapped_at,
            total_findings=len(findings),
            total_techniques=len(all_tids),
            total_tactics_covered=covered_tactics,
            kill_chain_coverage=kc_coverage,
            finding_results=finding_results,
            all_techniques=sorted(all_tids),
            technique_frequency=tech_freq,
            coverage_percentage=coverage_pct,
        )

    def get_cwe_mapping(self, cwe_id: str) -> Optional[List[Dict[str, Any]]]:
        """Return all technique mappings for a CWE ID."""
        normalized = self._normalize_cwe(cwe_id)
        if not normalized or normalized not in self._cwe_map:
            return None
        results = []
        for m in self._cwe_map[normalized]:
            tid = m["technique_id"]
            if tid in self._techniques:
                t = self._techniques[tid]
                results.append({
                    "technique_id": tid,
                    "technique_name": t["name"],
                    "tactic_ids": t["tactic_ids"],
                    "tactic_names": [self._tactics.get(ta, {}).get("name", ta) for ta in t["tactic_ids"]],
                    "confidence": m["confidence"],
                    "rationale": m["rationale"],
                    "technique_url": t["url"],
                })
        return results

    def generate_navigator_layer(
        self,
        findings: List[Dict[str, Any]],
        layer_name: str = "FixOps Application Vulnerability Coverage",
        description: str = "Auto-generated by FixOps MITRE ATT&CK Mapper",
    ) -> Dict[str, Any]:
        """
        Generate a MITRE ATT&CK Navigator layer JSON.

        The output conforms to Navigator layer schema v4.5 and can be
        imported directly at https://mitre-attack.github.io/attack-navigator/

        Args:
            findings: List of finding dicts
            layer_name: Display name for the layer
            description: Layer description

        Returns:
            Navigator layer JSON dict
        """
        result = self.map_findings(findings)

        # Build technique scores for Navigator
        techniques_list = []
        seen_tids: Set[str] = set()

        for fr in result.finding_results:
            for tm in fr.techniques:
                if tm.technique_id in seen_tids:
                    continue
                seen_tids.add(tm.technique_id)

                # Color based on highest confidence
                score = int(tm.confidence * 100)
                color = self._confidence_to_color(tm.confidence)

                entry: Dict[str, Any] = {
                    "techniqueID": tm.technique_id,
                    "score": score,
                    "color": color,
                    "comment": f"Mapped from: {tm.source_ref} | {tm.rationale}",
                    "enabled": True,
                    "metadata": [
                        {"name": "source", "value": tm.source},
                        {"name": "source_ref", "value": tm.source_ref},
                        {"name": "confidence", "value": str(tm.confidence)},
                    ],
                    "links": [{"label": "ATT&CK", "url": tm.technique_url}],
                    "showSubtechniques": tm.technique_id.endswith(".001") is False,
                }
                techniques_list.append(entry)

        return {
            "name": layer_name,
            "versions": {
                "attack": "14",
                "navigator": "4.9",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": description,
            "filters": {
                "platforms": [
                    "Linux", "macOS", "Windows", "Network", "PRE",
                    "Containers", "IaaS", "SaaS", "Azure AD", "Office 365", "Google Workspace",
                ],
            },
            "sorting": 3,  # descending by score
            "layout": {
                "layout": "side",
                "aggregateFunction": "max",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False,
                "expandedSubtechniques": "annotated",
            },
            "hideDisabled": False,
            "techniques": techniques_list,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "High confidence (≥80%)", "color": "#d32f2f"},
                {"label": "Medium confidence (60–79%)", "color": "#f57c00"},
                {"label": "Low confidence (<60%)", "color": "#fbc02d"},
            ],
            "metadata": [
                {"name": "generated_by", "value": "FixOps MITRE ATT&CK Mapper v1.0"},
                {"name": "generated_at", "value": datetime.now(timezone.utc).isoformat()},
                {"name": "total_findings", "value": str(result.total_findings)},
                {"name": "total_techniques", "value": str(result.total_techniques)},
                {"name": "attack_version", "value": "14"},
            ],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
        }

    def list_techniques(self) -> List[Dict[str, Any]]:
        """List all techniques with metadata."""
        result = []
        for tid, t in self._techniques.items():
            result.append({
                "technique_id": tid,
                "name": t["name"],
                "tactic_ids": t["tactic_ids"],
                "tactic_names": [self._tactics.get(ta, {}).get("name", ta) for ta in t["tactic_ids"]],
                "is_subtechnique": t.get("is_subtechnique", False),
                "parent_id": t.get("parent_id"),
                "platforms": t.get("platforms", []),
                "url": t["url"],
                "description": t["description"],
            })
        result.sort(key=lambda x: x["technique_id"])
        return result

    def list_tactics(self) -> List[Dict[str, Any]]:
        """List all 14 MITRE ATT&CK tactics."""
        result = []
        for tid, t in self._tactics.items():
            result.append({
                "tactic_id": tid,
                "name": t["name"],
                "shortname": t["shortname"],
                "description": t["description"],
                "url": t["url"],
            })
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _normalize_cwe(self, cwe_id: Any) -> Optional[str]:
        """Normalize CWE ID to bare numeric string (e.g., 'CWE-89' → '89')."""
        if cwe_id is None:
            return None
        s = str(cwe_id).strip()
        # Handle 'CWE-89', 'cwe-89', '89'
        s = re.sub(r"(?i)^cwe[-_]?", "", s).strip()
        return s if s.isdigit() else None

    def _infer_primary_tactic(self, techniques: List[TechniqueMapping]) -> Optional[str]:
        """Infer the primary tactic from mapped techniques."""
        if not techniques:
            return None

        # Prefer Initial Access or Execution as primary tactic for app vulnerabilities
        preferred_order = ["TA0001", "TA0002", "TA0006", "TA0004", "TA0003"]
        tactic_confidence: Dict[str, float] = {}
        for tm in techniques:
            for ta in tm.tactic_ids:
                if ta not in tactic_confidence or tm.confidence > tactic_confidence[ta]:
                    tactic_confidence[ta] = tm.confidence

        for preferred_ta in preferred_order:
            if preferred_ta in tactic_confidence:
                return self._tactics.get(preferred_ta, {}).get("name", preferred_ta)

        # Fall back to highest confidence tactic
        if tactic_confidence:
            best_ta = max(tactic_confidence, key=lambda ta: tactic_confidence[ta])
            return self._tactics.get(best_ta, {}).get("name", best_ta)
        return None

    def _compute_risk_score(self, finding: Dict[str, Any], techniques: List[TechniqueMapping]) -> float:
        """Compute a 0–10 risk score for a finding based on severity and technique coverage."""
        severity = str(finding.get("severity", "medium")).lower()
        severity_base = {
            "critical": 10.0, "high": 8.0, "medium": 5.0, "low": 2.0, "info": 0.5
        }.get(severity, 5.0)

        if not techniques:
            return round(severity_base * 0.5, 1)

        max_conf = max(t.confidence for t in techniques)
        tech_multiplier = 0.5 + (max_conf * 0.5)
        score = severity_base * tech_multiplier
        return round(min(score, 10.0), 1)

    def _build_kill_chain_coverage(self, finding_results: List[FindingMappingResult]) -> List[KillChainCoverage]:
        """Build kill chain phase coverage from a set of finding results."""
        tactic_techniques: Dict[str, List[Tuple[str, float]]] = {ta: [] for ta in self._tactics}

        for fr in finding_results:
            for tm in fr.techniques:
                for ta in tm.tactic_ids:
                    if ta in tactic_techniques:
                        tactic_techniques[ta].append((tm.technique_id, tm.confidence))

        coverage = []
        for ta_id, ta_info in self._tactics.items():
            mapped_techs = tactic_techniques.get(ta_id, [])
            if mapped_techs:
                list(dict.fromkeys(t[0] for t in mapped_techs))
                highest_conf = max(t[1] for t in mapped_techs)
            else:
                highest_conf = 0.0

            coverage.append(KillChainCoverage(
                tactic_id=ta_id,
                tactic_name=ta_info["name"],
                covered=bool(mapped_techs),
                technique_count=len(set(t[0] for t in mapped_techs)),
                techniques=list(dict.fromkeys(t[0] for t in mapped_techs)),
                highest_confidence=round(highest_conf, 3),
            ))

        return coverage

    def _confidence_to_color(self, confidence: float) -> str:
        """Map confidence score to ATT&CK Navigator hex color."""
        if confidence >= 0.80:
            return "#d32f2f"  # Red — high confidence
        elif confidence >= 0.60:
            return "#f57c00"  # Orange — medium confidence
        else:
            return "#fbc02d"  # Yellow — lower confidence


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_mapper_instance: Optional[MITREMapper] = None


def get_mitre_mapper() -> MITREMapper:
    """Return the singleton MITREMapper instance."""
    global _mapper_instance
    if _mapper_instance is None:
        _mapper_instance = MITREMapper()
    return _mapper_instance
