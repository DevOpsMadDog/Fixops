"""ALDECI SentinelOne Singularity XDR Connector.

Real parser for SentinelOne Singularity Threat objects per the official API
docs (Singularity Cloud / Singularity XDR Public API):

    GET /web/api/v2.1/threats?limit=N
    GET /web/api/v2.1/threats/{threat_id}/threat-events
    GET /web/api/v2.1/threats/{threat_id}/iocs

Schema reference:
    https://usea1-XXX.sentinelone.net/api-doc/openapi.json
    Response: {"data": [Threat, ...], "pagination": {...}}

Each Threat object exposes:
    id                       - SentinelOne internal threat id (UUID-style)
    threatInfo:              - canonical container for the alert envelope
        threatName           - filename or rule
        classification       - "Malware" / "Generic.Suspicious" / "PUA" / etc.
        confidenceLevel      - "malicious" / "suspicious"
        mitigationStatus     - "mitigated" / "not_mitigated" / "marked_as_benign"
        analystVerdict       - "true_positive" / "false_positive" / "undefined"
        threatId             - Public-facing threat reference id
        sha1, sha256, md5    - File hashes (when applicable)
        filePath             - Disk location of the offending file
        fileSize             - Size in bytes
        engines              - Detection engines that fired (list)
        detectionType        - "static" / "dynamic"
        initiatedBy          - "agent_policy" / "deep_visibility" / etc.
        publisher            - Cert publisher
        signatureVerification- Signature trust state
        createdAt            - Threat creation ISO-8601
    agentDetectionInfo:      - Endpoint that produced the alert
        agentUuid            - Agent UUID
        agentComputerName    - Hostname
        agentDomain          - AD/LDAP domain
        agentIpV4            - Endpoint IP
        agentOsName          - OS family
        agentOsRevision      - Build number
        agentVersion         - SentinelOne agent version
    indicators:              - List of MITRE indicators
        [{"category": "...", "tactics": [{"name": "Execution",
                                          "techniques": [{"name": "T1059", ...}]}]}]
    mitigationStatusDescription
    network/processes/etc.   - Optional sub-objects on enriched alerts

The connector:
  1. Accepts either a list of Threat dicts OR the wrapping object
     {"data": [...], "pagination": {...}}.
  2. Maps SentinelOne severity (Critical/High/Medium/Low) → ALDECI severity.
  3. Records each threat as a SecurityFindingsEngine row with
     ``source_tool="sentinelone"``.
  4. Embeds 10 realistic SentinelOne Threat samples for offline demos and
     contract tests so the connector is exercisable without API access.

Multi-tenant: every ingest call is scoped by an explicit ``org_id``.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity / classification mappings
# ---------------------------------------------------------------------------
# SentinelOne does not use a single "severity" field on every Threat. The
# canonical signal is (confidenceLevel + classification + analystVerdict +
# detectionType). The following table is derived from the SentinelOne XDR
# Severity Calculation guide and matches what the SentinelOne console shows in
# its Threat Severity column.
_S1_CONFIDENCE_TO_SEVERITY = {
    "malicious":  "high",      # Default: malicious confidence
    "suspicious": "medium",    # Default: suspicious confidence
}

_S1_CLASSIFICATION_BUMP_TO_CRITICAL = {
    "Ransomware",
    "Trojan",
    "Backdoor",
    "RootKit",
    "Worm",
    "Exploit",
}

_S1_CLASSIFICATION_DOWN_TO_LOW = {
    "PUA",
    "Adware",
    "Generic.Heuristic",
}

# Public severity field if SentinelOne returned one explicitly (some
# event-stream payloads include `threatInfo.severity`).
_S1_EXPLICIT_SEVERITY = {
    "Critical": "critical",
    "critical": "critical",
    "High":     "high",
    "high":     "high",
    "Medium":   "medium",
    "medium":   "medium",
    "Low":      "low",
    "low":      "low",
    "Info":     "informational",
    "info":     "informational",
}

# Confidence/classification → CVSS mapping (used for SecurityFindingsEngine)
_SEVERITY_TO_CVSS = {
    "critical":      9.5,
    "high":          7.5,
    "medium":        5.0,
    "low":           3.0,
    "informational": 1.0,
}

_VALID_ALDECI_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


# ---------------------------------------------------------------------------
# Embedded SentinelOne Threat samples — REAL Singularity XDR API format.
#
# These ten samples follow the exact field naming and nesting documented at
# https://www.sentinelone.com/blog/sentinelone-rest-api/ and the public
# OpenAPI schema. Content is plausible but synthetic, so they can be safely
# committed and used for tests + offline demo runs.
# ---------------------------------------------------------------------------
_S1_FALLBACK_THREATS: List[Dict[str, Any]] = [
    {
        "id": "1234567890123456789",
        "threatInfo": {
            "threatId": "1234567890123456789",
            "threatName": "WannaCry.exe",
            "classification": "Ransomware",
            "classificationSource": "Engine",
            "confidenceLevel": "malicious",
            "mitigationStatus": "mitigated",
            "mitigationStatusDescription": "Mitigated by Behavioral AI",
            "analystVerdict": "true_positive",
            "sha1":   "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467",
            "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "md5":    "84c82835a5d21bbcf75a61706d8ab549",
            "filePath": "C:\\Users\\victim\\AppData\\Local\\Temp\\WannaCry.exe",
            "fileSize": 3514368,
            "engines": ["DFI - Static", "Behavioral AI"],
            "detectionType": "dynamic",
            "initiatedBy": "agent_policy",
            "publisher": "",
            "signatureVerification": "NotSigned",
            "createdAt": "2026-04-25T12:01:14.123456Z",
        },
        "agentDetectionInfo": {
            "agentUuid": "f1b8d2e0-4f3c-11ee-be56-0242ac120002",
            "agentComputerName": "DESKTOP-WIN10-01",
            "agentDomain": "CORP",
            "agentIpV4": "10.20.30.41",
            "agentOsName": "Windows 10 Pro",
            "agentOsRevision": "19044",
            "agentVersion": "23.4.2.13",
        },
        "indicators": [
            {
                "category": "Ransomware",
                "tactics": [
                    {"name": "Impact",
                     "techniques": [{"name": "T1486", "link": "https://attack.mitre.org/techniques/T1486/"}]},
                ],
            },
        ],
    },
    {
        "id": "2345678901234567890",
        "threatInfo": {
            "threatId": "2345678901234567890",
            "threatName": "mimikatz.exe",
            "classification": "Trojan",
            "confidenceLevel": "malicious",
            "mitigationStatus": "not_mitigated",
            "analystVerdict": "true_positive",
            "sha1":   "917c92e8662faf96fffb8ffe7b7c80fb6b4e7c0c",
            "sha256": "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1",
            "filePath": "C:\\Tools\\mimikatz.exe",
            "fileSize": 1042440,
            "engines": ["DFI - Static"],
            "detectionType": "static",
            "initiatedBy": "agent_policy",
            "publisher": "",
            "signatureVerification": "NotSigned",
            "createdAt": "2026-04-25T12:09:55.000Z",
        },
        "agentDetectionInfo": {
            "agentUuid": "a2b8d2e0-4f3c-11ee-be56-0242ac120002",
            "agentComputerName": "WS-DEV-021",
            "agentDomain": "CORP",
            "agentIpV4": "10.20.30.55",
            "agentOsName": "Windows 11 Enterprise",
            "agentOsRevision": "22621",
            "agentVersion": "23.4.2.13",
        },
        "indicators": [
            {
                "category": "Credential Access",
                "tactics": [
                    {"name": "Credential Access",
                     "techniques": [{"name": "T1003.001"}]},
                ],
            },
        ],
    },
    {
        "id": "3456789012345678901",
        "threatInfo": {
            "threatId": "3456789012345678901",
            "threatName": "powershell_obfuscated.ps1",
            "classification": "Malware",
            "confidenceLevel": "suspicious",
            "mitigationStatus": "mitigated",
            "analystVerdict": "undefined",
            "sha1":   "b7f884c1d51d1d8d29a6ec6c7c8b1f1f3a4426467",
            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "filePath": "C:\\Users\\analyst\\Downloads\\update.ps1",
            "fileSize": 14852,
            "engines": ["Behavioral AI", "Anti-Exploit"],
            "detectionType": "dynamic",
            "initiatedBy": "deep_visibility",
            "createdAt": "2026-04-25T13:14:21.500Z",
        },
        "agentDetectionInfo": {
            "agentUuid": "c2b8d2e0-4f3c-11ee-be56-0242ac120002",
            "agentComputerName": "WS-FIN-007",
            "agentDomain": "CORP",
            "agentIpV4": "10.20.40.7",
            "agentOsName": "Windows 10 Pro",
            "agentOsRevision": "19044",
            "agentVersion": "23.4.2.13",
        },
        "indicators": [
            {
                "category": "Execution",
                "tactics": [
                    {"name": "Execution",
                     "techniques": [{"name": "T1059.001"}]},
                ],
            },
            {
                "category": "Defense Evasion",
                "tactics": [
                    {"name": "Defense Evasion",
                     "techniques": [{"name": "T1027"}]},
                ],
            },
        ],
    },
    {
        "id": "4567890123456789012",
        "threatInfo": {
            "threatId": "4567890123456789012",
            "threatName": "Emotet.dll",
            "classification": "Trojan",
            "confidenceLevel": "malicious",
            "mitigationStatus": "mitigated",
            "analystVerdict": "true_positive",
            "sha256": "7b3b1c5a4e8d9f0a1b2c3d4e5f607182930465876a8b9c0d1e2f3041526374859",
            "filePath": "C:\\ProgramData\\Microsoft\\WinUpdate\\loader.dll",
            "fileSize": 528384,
            "engines": ["DFI - Static"],
            "detectionType": "static",
            "createdAt": "2026-04-25T13:42:08.000Z",
        },
        "agentDetectionInfo": {
            "agentUuid": "d2b8d2e0-4f3c-11ee-be56-0242ac120002",
            "agentComputerName": "SRV-FILE-01",
            "agentDomain": "CORP",
            "agentIpV4": "10.20.50.10",
            "agentOsName": "Windows Server 2019",
            "agentOsRevision": "17763",
            "agentVersion": "23.4.2.13",
        },
        "indicators": [
            {
                "category": "Command and Control",
                "tactics": [
                    {"name": "Command and Control",
                     "techniques": [{"name": "T1071.001"}]},
                ],
            },
        ],
    },
    {
        "id": "5678901234567890123",
        "threatInfo": {
            "threatId": "5678901234567890123",
            "threatName": "Suspicious script execution from temp",
            "classification": "Generic.Suspicious",
            "confidenceLevel": "suspicious",
            "mitigationStatus": "mitigated",
            "analystVerdict": "undefined",
            "filePath": "/tmp/.x/setup.sh",
            "fileSize": 8421,
            "engines": ["Behavioral AI"],
            "detectionType": "dynamic",
            "createdAt": "2026-04-25T14:01:03.000Z",
        },
        "agentDetectionInfo": {
            "agentUuid": "e2b8d2e0-4f3c-11ee-be56-0242ac120002",
            "agentComputerName": "linux-build-09",
            "agentDomain": "",
            "agentIpV4": "10.30.10.9",
            "agentOsName": "Ubuntu 22.04",
            "agentOsRevision": "22.04.4",
            "agentVersion": "23.4.2.13",
        },
        "indicators": [
            {
                "category": "Execution",
                "tactics": [
                    {"name": "Execution",
                     "techniques": [{"name": "T1059.004"}]},
                ],
            },
        ],
    },
    {
        "id": "6789012345678901234",
        "threatInfo": {
            "threatId": "6789012345678901234",
            "threatName": "Coinminer.xmrig",
            "classification": "Malware",
            "confidenceLevel": "malicious",
            "mitigationStatus": "mitigated",
            "analystVerdict": "true_positive",
            "sha256": "a4d7c9e1b2f3041526374859768798a8b9c0d1e2f3041526374859aabbccddeefff",
            "filePath": "/var/tmp/.cache/xmrig",
            "fileSize": 4517888,
            "engines": ["DFI - Static"],
            "detectionType": "static",
            "createdAt": "2026-04-25T14:22:18.000Z",
        },
        "agentDetectionInfo": {
            "agentUuid": "f2b8d2e0-4f3c-11ee-be56-0242ac120002",
            "agentComputerName": "k8s-worker-03",
            "agentIpV4": "10.30.20.13",
            "agentOsName": "Amazon Linux 2",
            "agentOsRevision": "5.10.205",
            "agentVersion": "23.4.2.13",
        },
        "indicators": [
            {
                "category": "Impact",
                "tactics": [
                    {"name": "Impact",
                     "techniques": [{"name": "T1496"}]},
                ],
            },
        ],
    },
    {
        "id": "7890123456789012345",
        "threatInfo": {
            "threatId": "7890123456789012345",
            "threatName": "OpenSSH-Backdoor",
            "classification": "Backdoor",
            "confidenceLevel": "malicious",
            "mitigationStatus": "not_mitigated",
            "analystVerdict": "true_positive",
            "sha256": "b1d7c9e1b2f3041526374859768798a8b9c0d1e2f3041526374859ddeefff00112",
            "filePath": "/usr/sbin/sshd-real",
            "fileSize": 832416,
            "engines": ["DFI - Static", "Behavioral AI"],
            "detectionType": "dynamic",
            "createdAt": "2026-04-25T14:55:42.000Z",
        },
        "agentDetectionInfo": {
            "agentUuid": "ababcdef-4f3c-11ee-be56-0242ac120002",
            "agentComputerName": "ubuntu-edge-04",
            "agentIpV4": "10.30.30.4",
            "agentOsName": "Ubuntu 22.04",
            "agentOsRevision": "22.04.4",
            "agentVersion": "23.4.2.13",
        },
        "indicators": [
            {
                "category": "Persistence",
                "tactics": [
                    {"name": "Persistence",
                     "techniques": [{"name": "T1554"}]},
                ],
            },
            {
                "category": "Lateral Movement",
                "tactics": [
                    {"name": "Lateral Movement",
                     "techniques": [{"name": "T1021.004"}]},
                ],
            },
        ],
    },
    {
        "id": "8901234567890123456",
        "threatInfo": {
            "threatId": "8901234567890123456",
            "threatName": "AdwareToolbar",
            "classification": "PUA",
            "confidenceLevel": "suspicious",
            "mitigationStatus": "marked_as_benign",
            "analystVerdict": "false_positive",
            "sha256": "ccd7c9e1b2f3041526374859768798a8b9c0d1e2f30415263748590112233445566",
            "filePath": "C:\\Program Files\\Toolbar\\helper.exe",
            "fileSize": 224256,
            "engines": ["DFI - Static"],
            "detectionType": "static",
            "createdAt": "2026-04-25T15:01:11.000Z",
        },
        "agentDetectionInfo": {
            "agentUuid": "1234abcd-4f3c-11ee-be56-0242ac120002",
            "agentComputerName": "DESKTOP-MKT-12",
            "agentDomain": "CORP",
            "agentIpV4": "10.40.10.12",
            "agentOsName": "Windows 10 Pro",
            "agentOsRevision": "19044",
            "agentVersion": "23.4.2.13",
        },
        "indicators": [],
    },
    {
        "id": "9012345678901234567",
        "threatInfo": {
            "threatId": "9012345678901234567",
            "threatName": "RogueProcess.injection",
            "classification": "Exploit",
            "confidenceLevel": "malicious",
            "mitigationStatus": "mitigated",
            "analystVerdict": "true_positive",
            "filePath": "C:\\Windows\\System32\\rundll32.exe",
            "fileSize": 71680,
            "engines": ["Anti-Exploit", "Behavioral AI"],
            "detectionType": "dynamic",
            "createdAt": "2026-04-25T15:33:48.000Z",
        },
        "agentDetectionInfo": {
            "agentUuid": "5678abcd-4f3c-11ee-be56-0242ac120002",
            "agentComputerName": "DESKTOP-WIN10-25",
            "agentDomain": "CORP",
            "agentIpV4": "10.40.20.25",
            "agentOsName": "Windows 10 Enterprise",
            "agentOsRevision": "19045",
            "agentVersion": "23.4.2.13",
        },
        "indicators": [
            {
                "category": "Defense Evasion",
                "tactics": [
                    {"name": "Defense Evasion",
                     "techniques": [{"name": "T1055"}]},
                ],
            },
        ],
    },
    {
        "id": "0123456789012345678",
        "threatInfo": {
            "threatId": "0123456789012345678",
            "threatName": "TrickBot.loader",
            "classification": "Trojan",
            "confidenceLevel": "malicious",
            "mitigationStatus": "mitigated",
            "analystVerdict": "true_positive",
            "severity": "Critical",   # explicit severity field present
            "sha256": "deadc0ffeeb2f3041526374859768798a8b9c0d1e2f3041526374859aabbccddee",
            "filePath": "C:\\Users\\guest\\AppData\\Roaming\\trick.exe",
            "fileSize": 982016,
            "engines": ["DFI - Static", "Behavioral AI"],
            "detectionType": "dynamic",
            "createdAt": "2026-04-25T16:08:55.000Z",
        },
        "agentDetectionInfo": {
            "agentUuid": "9999abcd-4f3c-11ee-be56-0242ac120002",
            "agentComputerName": "WS-HR-002",
            "agentDomain": "CORP",
            "agentIpV4": "10.40.30.2",
            "agentOsName": "Windows 11 Pro",
            "agentOsRevision": "22621",
            "agentVersion": "23.4.2.13",
        },
        "indicators": [
            {
                "category": "Execution",
                "tactics": [
                    {"name": "Execution",
                     "techniques": [{"name": "T1059.003"}]},
                ],
            },
            {
                "category": "Command and Control",
                "tactics": [
                    {"name": "Command and Control",
                     "techniques": [{"name": "T1071.001"}]},
                ],
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_str(value: Any, max_len: int = 1024) -> str:
    """Coerce to str and bound length (defensive — raw API input)."""
    if value is None:
        return ""
    s = str(value)
    return s[:max_len]


def _map_severity(threat_info: Mapping[str, Any]) -> str:
    """Map SentinelOne threat envelope to ALDECI severity.

    Order of precedence:
      1. Explicit ``threatInfo.severity`` (Critical/High/Medium/Low/Info).
      2. ``confidenceLevel`` baseline (malicious=high, suspicious=medium).
      3. ``classification`` bumps:
         - Ransomware/Trojan/Backdoor/RootKit/Worm/Exploit → critical
         - PUA/Adware/Generic.Heuristic → low
      4. ``analystVerdict == 'false_positive'`` clamps result to low.
    """
    explicit = threat_info.get("severity")
    if explicit and explicit in _S1_EXPLICIT_SEVERITY:
        sev = _S1_EXPLICIT_SEVERITY[explicit]
        # analyst verdict overrides only towards low for false_positive
        if threat_info.get("analystVerdict") == "false_positive" and sev != "informational":
            return "low"
        return sev

    confidence = (threat_info.get("confidenceLevel") or "").lower()
    sev = _S1_CONFIDENCE_TO_SEVERITY.get(confidence, "medium")

    classification = threat_info.get("classification") or ""
    if classification in _S1_CLASSIFICATION_BUMP_TO_CRITICAL:
        sev = "critical"
    elif classification in _S1_CLASSIFICATION_DOWN_TO_LOW:
        sev = "low"

    if threat_info.get("analystVerdict") == "false_positive":
        sev = "low"

    if sev not in _VALID_ALDECI_SEVERITIES:
        sev = "medium"
    return sev


def _extract_mitre(indicators: Sequence[Mapping[str, Any]]) -> List[str]:
    """Return all MITRE technique IDs surfaced by an S1 Threat object."""
    out: List[str] = []
    for ind in indicators or []:
        for tac in ind.get("tactics") or []:
            for tech in tac.get("techniques") or []:
                name = tech.get("name") or ""
                if name and name not in out:
                    out.append(name)
    return out


def _correlation_key(threat_id: str, hostname: str, file_hash: str) -> str:
    """Stable lifecycle key for SecurityFindingsEngine dedup."""
    base = threat_id or file_hash or hostname or "s1-unknown"
    return f"sentinelone|{base}|{hostname or 'no-host'}"


def _normalize_threat(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Convert a raw SentinelOne Threat object into ALDECI's intermediate dict.

    Pure function — no DB writes, no side effects. Used for both ingest and
    direct unit-testing. Defensive against missing keys.
    """
    if not isinstance(raw, Mapping):
        raise ValueError("SentinelOne Threat must be a dict-like object")

    threat_info = raw.get("threatInfo") or {}
    if not isinstance(threat_info, Mapping):
        threat_info = {}
    agent = raw.get("agentDetectionInfo") or {}
    if not isinstance(agent, Mapping):
        agent = {}
    indicators = raw.get("indicators") or []
    if not isinstance(indicators, list):
        indicators = []

    threat_id = _safe_str(
        raw.get("id") or threat_info.get("threatId") or "",
        max_len=128,
    )
    threat_name = _safe_str(threat_info.get("threatName") or "Unnamed S1 Threat", max_len=255)
    classification = _safe_str(threat_info.get("classification") or "Unknown", max_len=128)
    severity = _map_severity(threat_info)
    cvss = _SEVERITY_TO_CVSS.get(severity, 5.0)
    mitigation_status = _safe_str(threat_info.get("mitigationStatus") or "unknown", max_len=64)
    analyst_verdict = _safe_str(threat_info.get("analystVerdict") or "undefined", max_len=64)

    sha256 = _safe_str(threat_info.get("sha256") or "", max_len=128)
    sha1 = _safe_str(threat_info.get("sha1") or "", max_len=64)
    md5 = _safe_str(threat_info.get("md5") or "", max_len=64)
    file_hash = sha256 or sha1 or md5
    file_path = _safe_str(threat_info.get("filePath") or "", max_len=1024)

    hostname = _safe_str(agent.get("agentComputerName") or "", max_len=255)
    agent_uuid = _safe_str(agent.get("agentUuid") or "", max_len=128)
    agent_ip = _safe_str(agent.get("agentIpV4") or "", max_len=64)
    os_name = _safe_str(agent.get("agentOsName") or "", max_len=128)

    mitre_techniques = _extract_mitre(indicators)

    asset_id = hostname or agent_uuid or agent_ip or "unknown-endpoint"
    title = f"SentinelOne {classification}: {threat_name}"[:255]
    description = (
        f"SentinelOne {classification} ({analyst_verdict}, {mitigation_status}). "
        f"Endpoint={hostname or 'unknown'} ({os_name}, {agent_ip}). "
        f"File={file_path or 'n/a'}. "
        f"Hash(sha256)={sha256 or 'n/a'}. "
        f"MITRE={','.join(mitre_techniques) or 'n/a'}."
    )[:2000]
    remediation = (
        "Confirm SentinelOne mitigation completed; if mitigationStatus != 'mitigated', "
        "trigger isolation via the SentinelOne console. Investigate parent process and "
        "lateral-movement signals; rotate credentials if Credential Access TTP fired."
    )

    return {
        "threat_id":          threat_id,
        "title":              title,
        "classification":     classification,
        "severity":           severity,
        "cvss_score":         cvss,
        "mitigation_status":  mitigation_status,
        "analyst_verdict":    analyst_verdict,
        "asset_id":           asset_id,
        "asset_type":         "endpoint",
        "hostname":           hostname,
        "agent_uuid":         agent_uuid,
        "agent_ip":           agent_ip,
        "os_name":            os_name,
        "file_hash":          file_hash,
        "file_path":          file_path,
        "mitre_techniques":   mitre_techniques,
        "description":        description,
        "remediation":        remediation,
        "correlation_key":    _correlation_key(threat_id, hostname, file_hash),
        "raw_created_at":     _safe_str(threat_info.get("createdAt") or "", max_len=64),
    }


def _coerce_dump(payload: Union[str, bytes, Mapping[str, Any], Sequence[Any]]) -> List[Dict[str, Any]]:
    """Accept any of: JSON string, bytes, list, {data:[...]}, single Threat dict.

    Returns a flat list of Threat dicts. Raises ValueError on hopelessly
    malformed input so callers can return a 400 to clients.
    """
    if isinstance(payload, (str, bytes)):
        text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"sentinelone_connector: invalid JSON dump: {exc}") from exc

    if isinstance(payload, Mapping):
        # SentinelOne API canonical wrapper: {"data": [...], "pagination": {...}}
        data = payload.get("data")
        if isinstance(data, list):
            return [t for t in data if isinstance(t, Mapping)]
        # Single Threat as a top-level dict: be permissive
        if "threatInfo" in payload or "id" in payload:
            return [dict(payload)]
        raise ValueError("sentinelone_connector: dump dict missing 'data' list")
    if isinstance(payload, list):
        return [t for t in payload if isinstance(t, Mapping)]
    raise ValueError("sentinelone_connector: unsupported dump type")


# ---------------------------------------------------------------------------
# SentinelOneConnector
# ---------------------------------------------------------------------------
class SentinelOneConnector:
    """Real SentinelOne Singularity XDR ingest connector.

    Args:
        findings_engine: instance of ``core.security_findings_engine.SecurityFindingsEngine``
        correlation_engine: optional ``SecurityEventCorrelationEngine`` for cross-domain rules

    The connector is dependency-injected (no implicit singletons inside
    methods) which makes it trivially testable with isolated SQLite DBs.
    """

    def __init__(
        self,
        findings_engine: Any,
        correlation_engine: Any = None,
    ) -> None:
        if findings_engine is None:
            raise ValueError("findings_engine is required")
        self._findings = findings_engine
        self._correlation = correlation_engine
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public ingest API
    # ------------------------------------------------------------------
    def ingest_s1_dump(
        self,
        json_dump: Union[str, bytes, Mapping[str, Any], Sequence[Any]],
        org_id: str,
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ingest a SentinelOne API ``/threats`` dump.

        Args:
            json_dump:  raw JSON dump (str/bytes), API wrapper dict
                        ``{"data": [...]}``, list of Threat dicts, or single
                        Threat dict.
            org_id:     ALDECI tenant id — required.
            scan_id:    optional scan id for ``SecurityFindingsEngine`` lifecycle
                        reconciliation. If omitted, a uuid4 is generated.

        Returns:
            ``{org_id, scan_id, threats_seen, findings_recorded, severity_breakdown,
               mitigation_breakdown, recorded_finding_ids, errors: [{...}]}``
        """
        if not org_id or not isinstance(org_id, str):
            raise ValueError("org_id is required (non-empty str)")
        org_id = org_id.strip()
        if not org_id:
            raise ValueError("org_id cannot be blank")

        threats = _coerce_dump(json_dump)
        scan_id = scan_id or f"s1-scan-{uuid.uuid4().hex[:12]}-{int(datetime.now(timezone.utc).timestamp())}"

        recorded_ids: List[str] = []
        severity_counts: Dict[str, int] = {s: 0 for s in _VALID_ALDECI_SEVERITIES}
        mitigation_counts: Dict[str, int] = {}
        errors: List[Dict[str, Any]] = []

        with self._lock:
            for idx, raw in enumerate(threats):
                try:
                    norm = _normalize_threat(raw)
                except (ValueError, TypeError) as exc:
                    errors.append({"index": idx, "error": str(exc)})
                    _logger.warning("sentinelone normalize failed at idx %d: %s", idx, exc)
                    continue

                try:
                    finding = self._findings.record_finding(
                        org_id=org_id,
                        title=norm["title"],
                        finding_type="malware",
                        source_tool="sentinelone",
                        severity=norm["severity"],
                        cvss_score=norm["cvss_score"],
                        asset_id=norm["asset_id"],
                        asset_type=norm["asset_type"],
                        description=norm["description"],
                        remediation=norm["remediation"],
                        correlation_key=norm["correlation_key"],
                        scan_id=scan_id,
                    )
                except (ValueError, TypeError) as exc:
                    errors.append({"index": idx, "error": f"record_finding: {exc}"})
                    _logger.warning("sentinelone record_finding failed at idx %d: %s", idx, exc)
                    continue

                fid = finding.get("id") if isinstance(finding, Mapping) else None
                if fid:
                    recorded_ids.append(fid)
                    # Attach evidence — raw S1 Threat for full audit
                    try:
                        self._findings.add_evidence(
                            finding_id=fid,
                            org_id=org_id,
                            evidence_type="report",
                            content=json.dumps(raw, default=str)[:65536],
                        )
                    except (ValueError, TypeError, AttributeError) as exc:
                        _logger.debug("sentinelone add_evidence skipped: %s", exc)

                severity_counts[norm["severity"]] = severity_counts.get(norm["severity"], 0) + 1
                mitigation_counts[norm["mitigation_status"]] = (
                    mitigation_counts.get(norm["mitigation_status"], 0) + 1
                )
                self._mirror_correlation(org_id=org_id, norm=norm)

        emit_connector_event(
            connector="SentinelOneConnector",
            org_id=org_id,
            source_kind="edr",
            finding_count=len(recorded_ids),
            extra={"scan_id": scan_id, "threats_seen": len(threats), "errors": len(errors)},
        )
        return {
            "org_id":               org_id,
            "scan_id":              scan_id,
            "source_tool":          "sentinelone",
            "threats_seen":         len(threats),
            "findings_recorded":    len(recorded_ids),
            "severity_breakdown":   severity_counts,
            "mitigation_breakdown": mitigation_counts,
            "recorded_finding_ids": recorded_ids,
            "errors":               errors,
            "ingested_at":          _now_iso(),
        }

    def ingest_fallback(self, org_id: str, max_events: int = 10) -> Dict[str, Any]:
        """Ingest the embedded SentinelOne sample dump (offline demo).

        Convenience for `/ingest/sample` route and integration tests.
        """
        max_events = max(1, min(int(max_events), len(_S1_FALLBACK_THREATS)))
        sample = list(_S1_FALLBACK_THREATS[:max_events])
        result = self.ingest_s1_dump({"data": sample}, org_id=org_id)
        result["mode"] = "fallback"
        return result

    # ------------------------------------------------------------------
    # Internal: cross-engine correlation mirror
    # ------------------------------------------------------------------
    def _mirror_correlation(self, *, org_id: str, norm: Mapping[str, Any]) -> None:
        if not self._correlation:
            return
        # Correlation engine valid severities: critical/high/medium/low/info
        sev = norm["severity"] if norm["severity"] != "informational" else "info"
        try:
            self._correlation.ingest_event(
                org_id,
                {
                    "source_system": "sentinelone",
                    "event_type":    "edr_threat",
                    "severity":      sev,
                    "entity_id":     norm["asset_id"],
                    "entity_type":   norm["asset_type"],
                    "raw_data": {
                        "threat_id":         norm["threat_id"],
                        "classification":    norm["classification"],
                        "mitigation_status": norm["mitigation_status"],
                        "analyst_verdict":   norm["analyst_verdict"],
                        "file_hash":         norm["file_hash"],
                        "file_path":         norm["file_path"],
                        "mitre_techniques":  norm["mitre_techniques"],
                    },
                },
            )
        except (ValueError, TypeError, AttributeError) as exc:
            _logger.debug("sentinelone correlation mirror skipped: %s", exc)


# ---------------------------------------------------------------------------
# Module-level singleton accessor
# ---------------------------------------------------------------------------
_singleton_lock = threading.Lock()
_singleton: Optional[SentinelOneConnector] = None


def get_sentinelone_connector() -> SentinelOneConnector:
    """Lazy singleton — wires SecurityFindingsEngine + correlation on first use."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            from core.security_findings_engine import SecurityFindingsEngine
            try:
                from core.security_event_correlation_engine import (
                    SecurityEventCorrelationEngine,
                )
                corr: Any = SecurityEventCorrelationEngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("sentinelone: correlation engine unavailable: %s", exc)
                corr = None
            _singleton = SentinelOneConnector(
                findings_engine=SecurityFindingsEngine(),
                correlation_engine=corr,
            )
        return _singleton


__all__ = [
    "SentinelOneConnector",
    "get_sentinelone_connector",
    "_S1_FALLBACK_THREATS",
    "_normalize_threat",
    "_map_severity",
    "_extract_mitre",
    "_coerce_dump",
    "_correlation_key",
]
