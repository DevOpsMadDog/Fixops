"""ALDECI Microsoft Defender XDR (Sentinel-XDR) Connector.

Real parser for Microsoft Graph Security API alert format (Defender XDR /
Microsoft Sentinel-XDR unified alerts schema).

Today, Defender XDR alerts are exported via:
  - Microsoft Graph Security API (https://graph.microsoft.com/v1.0/security/alerts_v2)
  - Defender XDR streaming API (m365 Defender custom-detection KQL output)
  - Defender XDR JSON dump (alerts page export → bulk JSON)

Their proprietary KQL output is NOT directly ingestable by ALDECI: severity strings
("informational"|"low"|"medium"|"high"), category labels (lateral_movement,
discovery, etc.), evidence array (deviceEvidence, fileEvidence, ipEvidence,
processEvidence, userEvidence), entities array, and MITRE technique IDs in
mitreTechniques[] need normalization to ALDECI's SecurityFindingsEngine schema.

This connector:
  1. Parses real Defender XDR alert JSON (alertId, severity, category,
     mitreTechniques[], evidence[], entities[]).
  2. Maps Defender severity → ALDECI severity (1:1 with normalization).
  3. Maps Defender category → ALDECI finding_type with MITRE attribution.
  4. Extracts asset identity from evidence array (deviceEvidence > processEvidence
     > fileEvidence > ipEvidence > userEvidence in priority order).
  5. Embeds 10 sample Defender alerts based on Microsoft Graph Security API
     public docs (REAL schema, plausible content) as a fallback when no
     dump file is provided.
  6. Calls SecurityFindingsEngine.record_finding(source_tool="defender_xdr").

Multi-tenant: all events are attributed to an explicit ``org_id``.

Reference: https://learn.microsoft.com/en-us/graph/api/resources/security-alert
           https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-overview
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defender XDR severity → ALDECI severity (1:1, normalized lowercase)
# ---------------------------------------------------------------------------
_DEFENDER_SEVERITY_MAP: Dict[str, str] = {
    "informational": "informational",
    "low":           "low",
    "medium":        "medium",
    "high":          "high",
    # Sentinel sometimes uses these; map defensively
    "critical":      "critical",
    "unknown":       "low",
}

# CVSS proxy per ALDECI severity bucket (Defender doesn't carry CVSS natively)
_SEVERITY_TO_CVSS: Dict[str, float] = {
    "informational": 1.0,
    "low":           3.0,
    "medium":        5.5,
    "high":          7.8,
    "critical":      9.5,
}

# Defender category → ALDECI finding_type
# Real categories from Microsoft Graph Security API spec.
_DEFENDER_CATEGORY_MAP: Dict[str, str] = {
    "initialaccess":          "anomaly",
    "execution":              "anomaly",
    "persistence":            "anomaly",
    "privilegeescalation":    "anomaly",
    "defenseevasion":         "anomaly",
    "credentialaccess":       "secret-exposure",
    "discovery":              "anomaly",
    "lateralmovement":        "anomaly",
    "collection":             "data-leak",
    "commandandcontrol":      "anomaly",
    "exfiltration":           "data-leak",
    "impact":                 "anomaly",
    "malware":                "malware",
    "ransomware":             "malware",
    "suspiciousactivity":     "anomaly",
    "unwantedsoftware":       "malware",
    "exploit":                "vulnerability",
    "phishing":               "anomaly",
    "policyviolation":        "policy-violation",
    "compromisedaccount":     "anomaly",
    "informationgathering":   "anomaly",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Embedded fallback Defender XDR alerts.
# Schema sourced verbatim from Microsoft Graph Security API public docs:
#   https://learn.microsoft.com/en-us/graph/api/resources/security-alert
# Content is plausible/synthetic; format is REAL Defender XDR format.
# ---------------------------------------------------------------------------
_DEFENDER_FALLBACK_ALERTS: List[Dict[str, Any]] = [
    {
        "alertId":             "da637621289512345678_-1283456789",
        "incidentId":          "12345",
        "title":               "Suspicious PowerShell command line",
        "description":         (
            "An unusual PowerShell invocation was observed using encoded command "
            "(EncodedCommand), known evasion behavior consistent with Cobalt Strike."
        ),
        "category":            "Execution",
        "severity":            "high",
        "status":              "new",
        "createdDateTime":     "2026-04-25T14:32:11Z",
        "lastUpdateDateTime":  "2026-04-25T14:32:15Z",
        "detectionSource":     "MicrosoftDefenderForEndpoint",
        "serviceSource":       "microsoftDefenderForEndpoint",
        "mitreTechniques":     ["T1059.001", "T1027"],
        "evidence": [
            {
                "@odata.type":      "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName":    "WIN-SRV-01.contoso.local",
                "azureAdDeviceId":  "11111111-1111-1111-1111-111111111111",
                "osPlatform":       "Windows10",
                "version":          "10.0.19045",
                "loggedOnUsers":    [{"accountName": "alice", "domainName": "contoso"}],
            },
            {
                "@odata.type":      "#microsoft.graph.security.processEvidence",
                "processId":        4892,
                "processCommandLine": "powershell.exe -EncodedCommand SQBFAFgAIAAo...",
                "imageFile":        {"fileName": "powershell.exe", "filePath": "C:\\Windows\\System32"},
                "parentProcessImageFile": {"fileName": "winword.exe"},
            },
        ],
        "entities":             [],
    },
    {
        "alertId":             "da637621289512345679_-1283456790",
        "incidentId":          "12345",
        "title":               "Possible lateral movement using SMB",
        "description":         "Account performed SMB enumeration across multiple hosts.",
        "category":            "LateralMovement",
        "severity":            "high",
        "status":              "new",
        "createdDateTime":     "2026-04-25T14:35:01Z",
        "detectionSource":     "MicrosoftDefenderForIdentity",
        "serviceSource":       "microsoftDefenderForIdentity",
        "mitreTechniques":     ["T1021.002"],
        "evidence": [
            {
                "@odata.type":      "#microsoft.graph.security.userEvidence",
                "userAccount":      {
                    "accountName":  "svc-backup",
                    "domainName":   "contoso.local",
                    "userSid":      "S-1-5-21-1004336348-1177238915-682003330-512",
                },
            },
            {
                "@odata.type":      "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName":    "WIN-FILE-01.contoso.local",
                "osPlatform":       "WindowsServer2019",
            },
        ],
    },
    {
        "alertId":             "da637621289512345680_-1283456791",
        "incidentId":          "12346",
        "title":               "Ransomware behavior detected (file encryption pattern)",
        "description":         "Process is rapidly modifying files with high entropy — consistent with ransomware encryption.",
        "category":            "Ransomware",
        "severity":            "high",
        "status":              "new",
        "createdDateTime":     "2026-04-25T15:00:23Z",
        "detectionSource":     "MicrosoftDefenderForEndpoint",
        "mitreTechniques":     ["T1486"],
        "evidence": [
            {
                "@odata.type":      "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName":    "WIN-WS-23.contoso.local",
                "osPlatform":       "Windows11",
            },
            {
                "@odata.type":      "#microsoft.graph.security.fileEvidence",
                "fileName":         "wannacry.exe",
                "filePath":         "C:\\Users\\bob\\Downloads",
                "sha256":           "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
                "fileSize":         3514368,
            },
        ],
    },
    {
        "alertId":             "da637621289512345681_-1283456792",
        "incidentId":          "12347",
        "title":               "Credential dumping via LSASS access",
        "description":         "Process accessed LSASS memory; behavior consistent with Mimikatz / credential theft.",
        "category":            "CredentialAccess",
        "severity":            "high",
        "status":              "new",
        "createdDateTime":     "2026-04-25T15:12:08Z",
        "detectionSource":     "MicrosoftDefenderForEndpoint",
        "mitreTechniques":     ["T1003.001"],
        "evidence": [
            {
                "@odata.type":      "#microsoft.graph.security.processEvidence",
                "processId":        7384,
                "processCommandLine": "procdump.exe -ma lsass.exe lsass.dmp",
                "imageFile":        {"fileName": "procdump.exe"},
            },
            {
                "@odata.type":      "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName":    "WIN-DC-01.contoso.local",
            },
        ],
    },
    {
        "alertId":             "da637621289512345682_-1283456793",
        "incidentId":          "12348",
        "title":               "Suspicious sign-in from anonymous IP",
        "description":         "User signed in from a Tor exit node.",
        "category":            "InitialAccess",
        "severity":            "medium",
        "status":              "new",
        "createdDateTime":     "2026-04-25T15:25:14Z",
        "detectionSource":     "MicrosoftDefenderForCloudApps",
        "serviceSource":       "microsoftDefenderForCloudApps",
        "mitreTechniques":     ["T1078.004"],
        "evidence": [
            {
                "@odata.type":      "#microsoft.graph.security.userEvidence",
                "userAccount":      {
                    "accountName":  "carol",
                    "userPrincipalName": "carol@contoso.com",
                },
            },
            {
                "@odata.type":      "#microsoft.graph.security.ipEvidence",
                "ipAddress":        "185.220.101.42",
                "countryLetterCode": "DE",
            },
        ],
    },
    {
        "alertId":             "da637621289512345683_-1283456794",
        "incidentId":          "12349",
        "title":               "Outbound C2 traffic to known TI domain",
        "description":         "Endpoint contacted a domain on Microsoft Threat Intelligence command-and-control list.",
        "category":            "CommandAndControl",
        "severity":            "high",
        "status":              "new",
        "createdDateTime":     "2026-04-25T15:38:51Z",
        "detectionSource":     "MicrosoftDefenderForEndpoint",
        "mitreTechniques":     ["T1071.001"],
        "evidence": [
            {
                "@odata.type":      "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName":    "WIN-WS-04.contoso.local",
            },
            {
                "@odata.type":      "#microsoft.graph.security.urlEvidence",
                "url":              "http://malicious-c2.example.net/beacon",
            },
            {
                "@odata.type":      "#microsoft.graph.security.ipEvidence",
                "ipAddress":        "203.0.113.45",
            },
        ],
    },
    {
        "alertId":             "da637621289512345684_-1283456795",
        "incidentId":          "12350",
        "title":               "User added to highly privileged group",
        "description":         "Account was added to Domain Admins; configuration drift outside change-control window.",
        "category":            "PrivilegeEscalation",
        "severity":            "medium",
        "status":              "new",
        "createdDateTime":     "2026-04-25T15:51:09Z",
        "detectionSource":     "MicrosoftDefenderForIdentity",
        "mitreTechniques":     ["T1098"],
        "evidence": [
            {
                "@odata.type":      "#microsoft.graph.security.userEvidence",
                "userAccount":      {
                    "accountName":  "dave",
                    "domainName":   "contoso.local",
                },
            },
        ],
    },
    {
        "alertId":             "da637621289512345685_-1283456796",
        "incidentId":          "12351",
        "title":               "Phishing email delivered, opened by user",
        "description":         "Email containing a known malicious URL was delivered and opened.",
        "category":            "Phishing",
        "severity":            "medium",
        "status":              "new",
        "createdDateTime":     "2026-04-25T16:02:14Z",
        "detectionSource":     "MicrosoftDefenderForOffice365",
        "serviceSource":       "microsoftDefenderForOffice365",
        "mitreTechniques":     ["T1566.002"],
        "evidence": [
            {
                "@odata.type":      "#microsoft.graph.security.mailboxEvidence",
                "userAccount":      {"accountName": "eve", "userPrincipalName": "eve@contoso.com"},
            },
            {
                "@odata.type":      "#microsoft.graph.security.urlEvidence",
                "url":              "http://phish.example.net/login",
            },
        ],
    },
    {
        "alertId":             "da637621289512345686_-1283456797",
        "incidentId":          "12352",
        "title":               "Exfiltration over web service",
        "description":         "Large data transfer to external SaaS (mega.nz) during off-hours.",
        "category":            "Exfiltration",
        "severity":            "medium",
        "status":              "new",
        "createdDateTime":     "2026-04-25T16:18:33Z",
        "detectionSource":     "MicrosoftDefenderForCloudApps",
        "mitreTechniques":     ["T1567.002"],
        "evidence": [
            {
                "@odata.type":      "#microsoft.graph.security.userEvidence",
                "userAccount":      {"accountName": "frank"},
            },
            {
                "@odata.type":      "#microsoft.graph.security.urlEvidence",
                "url":              "https://mega.nz/transfer/abcdef",
            },
        ],
    },
    {
        "alertId":             "da637621289512345687_-1283456798",
        "incidentId":          "12353",
        "title":               "Detected file-less malware (in-memory injection)",
        "description":         "Process injected code into another running process; consistent with reflective DLL injection.",
        "category":            "DefenseEvasion",
        "severity":            "high",
        "status":              "new",
        "createdDateTime":     "2026-04-25T16:32:11Z",
        "detectionSource":     "MicrosoftDefenderForEndpoint",
        "mitreTechniques":     ["T1055.001"],
        "evidence": [
            {
                "@odata.type":      "#microsoft.graph.security.processEvidence",
                "processId":        9091,
                "processCommandLine": "rundll32.exe inject.dll,Run",
                "imageFile":        {"fileName": "rundll32.exe"},
            },
            {
                "@odata.type":      "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName":    "WIN-WS-12.contoso.local",
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Pure normalization helpers (no DB)
# ---------------------------------------------------------------------------
def _normalize_severity(defender_severity: Any) -> str:
    """Map Defender severity → ALDECI severity (defaults to 'medium')."""
    if not isinstance(defender_severity, str):
        return "medium"
    key = defender_severity.strip().lower()
    return _DEFENDER_SEVERITY_MAP.get(key, "medium")


def _normalize_category(defender_category: Any) -> str:
    """Map Defender category → ALDECI finding_type."""
    if not isinstance(defender_category, str):
        return "anomaly"
    key = defender_category.strip().lower().replace(" ", "").replace("_", "").replace("-", "")
    return _DEFENDER_CATEGORY_MAP.get(key, "anomaly")


def _evidence_type(item: Dict[str, Any]) -> str:
    """Infer the evidence sub-type from @odata.type or duck-typed keys."""
    odata = (item.get("@odata.type") or "").lower()
    if "deviceevidence" in odata:
        return "device"
    if "processevidence" in odata:
        return "process"
    if "fileevidence" in odata:
        return "file"
    if "userevidence" in odata or "mailboxevidence" in odata:
        return "user"
    if "ipevidence" in odata:
        return "ip"
    if "urlevidence" in odata:
        return "url"
    # Duck-typed fallback
    if "deviceDnsName" in item:
        return "device"
    if "processId" in item or "processCommandLine" in item:
        return "process"
    if "fileName" in item or "sha256" in item:
        return "file"
    if "userAccount" in item:
        return "user"
    if "ipAddress" in item:
        return "ip"
    if "url" in item:
        return "url"
    return "unknown"


def _extract_primary_asset(evidence: List[Dict[str, Any]]) -> Dict[str, str]:
    """Walk evidence array in priority order to find a primary asset.

    Priority: device > process > file > user > ip > url.
    Returns {asset_id, asset_type}. Empty strings if nothing extractable.
    """
    if not isinstance(evidence, list):
        return {"asset_id": "", "asset_type": ""}

    by_type: Dict[str, Dict[str, Any]] = {}
    for item in evidence:
        if not isinstance(item, dict):
            continue
        et = _evidence_type(item)
        if et not in by_type:
            by_type[et] = item

    # device wins
    if "device" in by_type:
        d = by_type["device"]
        return {
            "asset_id":   d.get("deviceDnsName") or d.get("azureAdDeviceId") or "unknown-device",
            "asset_type": "host",
        }
    if "process" in by_type:
        p = by_type["process"]
        img = p.get("imageFile") or {}
        return {
            "asset_id":   img.get("fileName") or f"pid:{p.get('processId', '?')}",
            "asset_type": "process",
        }
    if "file" in by_type:
        f = by_type["file"]
        return {
            "asset_id":   f.get("sha256") or f.get("fileName") or "unknown-file",
            "asset_type": "file",
        }
    if "user" in by_type:
        u = by_type["user"].get("userAccount") or {}
        return {
            "asset_id":   u.get("userPrincipalName") or u.get("accountName") or "unknown-user",
            "asset_type": "user",
        }
    if "ip" in by_type:
        return {"asset_id": by_type["ip"].get("ipAddress") or "unknown-ip", "asset_type": "ip"}
    if "url" in by_type:
        return {"asset_id": by_type["url"].get("url") or "unknown-url", "asset_type": "url"}

    return {"asset_id": "", "asset_type": ""}


def _normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a single Defender XDR alert dict → ALDECI finding payload.

    Returns a dict ready to pass as kwargs to
    ``SecurityFindingsEngine.record_finding``.
    """
    if not isinstance(alert, dict):
        raise ValueError("alert must be a dict")

    severity = _normalize_severity(alert.get("severity"))
    finding_type = _normalize_category(alert.get("category"))
    evidence = alert.get("evidence") or []
    primary = _extract_primary_asset(evidence)
    mitre_list = alert.get("mitreTechniques") or []
    mitre_str = ",".join(t for t in mitre_list if isinstance(t, str))
    alert_id = str(alert.get("alertId") or "").strip() or "unknown-alert-id"
    incident_id = str(alert.get("incidentId") or "").strip()
    detection_source = alert.get("detectionSource") or alert.get("serviceSource") or "Defender"

    title = (alert.get("title") or "Defender XDR alert").strip()
    description_parts: List[str] = []
    if alert.get("description"):
        description_parts.append(str(alert["description"]).strip())
    if mitre_str:
        description_parts.append(f"MITRE ATT&CK: {mitre_str}")
    if detection_source:
        description_parts.append(f"DetectionSource: {detection_source}")
    if incident_id:
        description_parts.append(f"DefenderIncidentId: {incident_id}")
    description_parts.append(f"DefenderAlertId: {alert_id}")
    description = " | ".join(description_parts)[:2000]

    cvss = _SEVERITY_TO_CVSS.get(severity, 5.0)

    return {
        "title":            title[:255],
        "finding_type":     finding_type,
        "source_tool":      "defender_xdr",
        "severity":         severity,
        "cvss_score":       cvss,
        "asset_id":         primary["asset_id"][:255] if primary["asset_id"] else "unknown",
        "asset_type":       primary["asset_type"] or "unknown",
        "description":      description,
        "remediation":      _suggest_remediation(finding_type, severity),
        "correlation_key":  f"defender_xdr|{alert_id}",
        # Carried for caller use, NOT passed to record_finding:
        "_alert_id":        alert_id,
        "_incident_id":     incident_id,
        "_mitre":           mitre_str,
        "_detection_source": detection_source,
        "_evidence_count":  len(evidence) if isinstance(evidence, list) else 0,
    }


def _suggest_remediation(finding_type: str, severity: str) -> str:
    """Heuristic remediation guidance based on Defender category mapping."""
    base = {
        "malware":         "Isolate device, run full antimalware scan, restore from clean backup.",
        "secret-exposure": "Rotate impacted credentials immediately and revoke active sessions.",
        "data-leak":       "Quarantine affected data path; review DLP policies; involve legal.",
        "policy-violation": "Reconcile against change-control; revert if unauthorized.",
        "vulnerability":   "Apply vendor patch and rescan with vulnerability scanner.",
        "anomaly":         "Investigate via SOC console; correlate with EDR/SIEM telemetry.",
    }.get(finding_type, "Investigate via SOC console; correlate with EDR/SIEM telemetry.")
    if severity in {"high", "critical"}:
        base = "URGENT: " + base
    return base


# ---------------------------------------------------------------------------
# DefenderXDRConnector
# ---------------------------------------------------------------------------
class DefenderXDRConnector:
    """Microsoft Defender XDR / Sentinel-XDR alert ingestion connector.

    Args:
        findings_engine:    instance of core.security_findings_engine.SecurityFindingsEngine
        correlation_engine: optional core.security_event_correlation_engine.SecurityEventCorrelationEngine
                            for cross-domain correlation mirror.
    """

    SOURCE_TOOL = "defender_xdr"

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
    # Mirror to security_event_correlation_engine (cross-domain rules)
    # ------------------------------------------------------------------
    def _mirror_correlation(
        self,
        org_id: str,
        alert_id: str,
        severity: str,
        finding_type: str,
        asset_id: str,
        asset_type: str,
        raw: Dict[str, Any],
    ) -> None:
        if not self._correlation:
            return
        sev = severity if severity in {"critical", "high", "medium", "low", "info"} else "low"
        if sev == "informational":
            sev = "low"
        try:
            self._correlation.ingest_event(
                org_id,
                {
                    "source_system": "defender_xdr",
                    "event_type": finding_type,
                    "severity": sev,
                    "entity_id": asset_id or "unknown",
                    "entity_type": asset_type or "unknown",
                    "raw_data": {
                        "alert_id": alert_id,
                        "title": raw.get("title"),
                        "category": raw.get("category"),
                        "mitre": raw.get("mitreTechniques"),
                    },
                },
            )
        except (ValueError, TypeError, AttributeError) as exc:
            _logger.warning("defender_xdr correlation mirror failed for %s: %s", alert_id, exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def parse_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a single raw Defender XDR alert and return the normalized payload.

        Pure function: does NOT touch the DB.
        """
        return _normalize_alert(alert)

    def parse_alerts(self, alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse a batch of Defender XDR alerts.

        Malformed entries are skipped and logged; the call never raises.
        """
        out: List[Dict[str, Any]] = []
        for raw in alerts:
            try:
                out.append(_normalize_alert(raw))
            except (ValueError, TypeError, KeyError) as exc:
                _logger.warning("skip malformed defender alert: %s", exc)
        return out

    def ingest_defender_dump(
        self,
        org_id: str,
        dump_file: Optional[str] = None,
        max_alerts: int = 100,
        force_fallback: bool = False,
    ) -> Dict[str, Any]:
        """Ingest a Defender XDR alert dump (JSON) into SecurityFindingsEngine.

        Args:
            org_id:         Tenant identifier (multi-tenant isolation).
            dump_file:      Path to a JSON dump. Accepts either a JSON list of
                            alerts OR an object containing ``{"value": [...]}``
                            (the Microsoft Graph response wrapper).
            max_alerts:     Cap how many alerts to ingest.
            force_fallback: If True (or the dump file is missing/invalid),
                            ingest the embedded fallback samples.

        Returns:
            {source, mode, alerts_processed, findings_recorded, skipped,
             severity_counts, source_tool}
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")
        if max_alerts < 1:
            raise ValueError("max_alerts must be >= 1")
        max_alerts = min(max_alerts, 1000)

        alerts: List[Dict[str, Any]] = []
        mode = "fallback"

        if dump_file and not force_fallback:
            path = Path(dump_file)
            if path.is_file():
                try:
                    with path.open("r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    if isinstance(data, dict) and isinstance(data.get("value"), list):
                        alerts = list(data["value"])
                    elif isinstance(data, list):
                        alerts = list(data)
                    else:
                        _logger.warning(
                            "defender dump %s is not a list or {value:[...]} — falling back",
                            dump_file,
                        )
                        alerts = []
                    if alerts:
                        mode = "live"
                except (OSError, json.JSONDecodeError, ValueError) as exc:
                    _logger.warning("defender dump read failed: %s — using fallback", exc)
                    alerts = []
            else:
                _logger.warning("defender dump %s not found — using fallback", dump_file)

        if not alerts:
            alerts = list(_DEFENDER_FALLBACK_ALERTS)
            mode = "fallback"

        alerts = alerts[:max_alerts]

        recorded = 0
        skipped = 0
        severity_counts: Dict[str, int] = {}
        recorded_ids: List[str] = []

        with self._lock:
            for raw in alerts:
                try:
                    norm = _normalize_alert(raw)
                except (ValueError, TypeError, KeyError) as exc:
                    _logger.warning("skip malformed defender alert: %s", exc)
                    skipped += 1
                    continue

                # Pop carry-over keys not accepted by record_finding
                alert_id = norm.pop("_alert_id", "")
                norm.pop("_incident_id", "")
                norm.pop("_mitre", None)
                norm.pop("_detection_source", None)
                norm.pop("_evidence_count", None)

                try:
                    rec = self._findings.record_finding(
                        org_id=org_id,
                        title=norm["title"],
                        finding_type=norm["finding_type"],
                        source_tool=self.SOURCE_TOOL,
                        severity=norm["severity"],
                        cvss_score=norm["cvss_score"],
                        asset_id=norm["asset_id"],
                        asset_type=norm["asset_type"],
                        description=norm["description"],
                        remediation=norm["remediation"],
                        correlation_key=norm["correlation_key"],
                    )
                    if rec and rec.get("id"):
                        recorded += 1
                        recorded_ids.append(rec["id"])
                        severity_counts[norm["severity"]] = severity_counts.get(norm["severity"], 0) + 1
                except (ValueError, TypeError) as exc:
                    _logger.warning("defender finding record failed for %s: %s", alert_id, exc)
                    skipped += 1
                    continue

                # Mirror to correlation engine (best-effort)
                self._mirror_correlation(
                    org_id=org_id,
                    alert_id=alert_id,
                    severity=norm["severity"],
                    finding_type=norm["finding_type"],
                    asset_id=norm["asset_id"],
                    asset_type=norm["asset_type"],
                    raw=raw,
                )

        emit_connector_event(
            connector="DefenderXDRConnector",
            org_id=org_id,
            source_kind="edr",
            finding_count=recorded,
            extra={"mode": mode, "alerts_processed": len(alerts), "skipped": skipped},
        )
        return {
            "source":            "defender_xdr",
            "source_tool":       self.SOURCE_TOOL,
            "mode":              mode,
            "alerts_processed":  len(alerts),
            "findings_recorded": recorded,
            "skipped":           skipped,
            "severity_counts":   severity_counts,
            "recorded_finding_ids": recorded_ids,
            "ingested_at":       _now_iso(),
        }

    def ingest_alert(self, org_id: str, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a single Defender XDR alert. Returns the recorded finding row."""
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")
        norm = _normalize_alert(alert)
        alert_id = norm.pop("_alert_id", "")
        norm.pop("_incident_id", None)
        norm.pop("_mitre", None)
        norm.pop("_detection_source", None)
        norm.pop("_evidence_count", None)
        with self._lock:
            rec = self._findings.record_finding(
                org_id=org_id,
                title=norm["title"],
                finding_type=norm["finding_type"],
                source_tool=self.SOURCE_TOOL,
                severity=norm["severity"],
                cvss_score=norm["cvss_score"],
                asset_id=norm["asset_id"],
                asset_type=norm["asset_type"],
                description=norm["description"],
                remediation=norm["remediation"],
                correlation_key=norm["correlation_key"],
            )
            self._mirror_correlation(
                org_id=org_id,
                alert_id=alert_id,
                severity=norm["severity"],
                finding_type=norm["finding_type"],
                asset_id=norm["asset_id"],
                asset_type=norm["asset_type"],
                raw=alert,
            )
        emit_connector_event(
            connector="DefenderXDRConnector",
            org_id=org_id,
            source_kind="edr",
            finding_count=1 if rec else 0,
            extra={"alert_id": alert_id, "mode": "single"},
        )
        return rec or {}


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_singleton_lock = threading.Lock()
_singleton: Optional[DefenderXDRConnector] = None


def get_defender_xdr_connector() -> DefenderXDRConnector:
    """Lazy singleton — wires SecurityFindingsEngine + correlation on first use."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            from core.security_findings_engine import SecurityFindingsEngine
            try:
                from core.security_event_correlation_engine import (
                    SecurityEventCorrelationEngine,
                )
                corr = SecurityEventCorrelationEngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("correlation engine unavailable: %s", exc)
                corr = None
            _singleton = DefenderXDRConnector(
                findings_engine=SecurityFindingsEngine(),
                correlation_engine=corr,
            )
        return _singleton


__all__ = [
    "DefenderXDRConnector",
    "get_defender_xdr_connector",
    "_DEFENDER_FALLBACK_ALERTS",
    "_DEFENDER_SEVERITY_MAP",
    "_DEFENDER_CATEGORY_MAP",
    "_normalize_severity",
    "_normalize_category",
    "_normalize_alert",
    "_extract_primary_asset",
    "_evidence_type",
    "_suggest_remediation",
]
