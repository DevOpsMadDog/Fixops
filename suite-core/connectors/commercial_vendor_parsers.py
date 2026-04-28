"""Commercial Vendor Parsers — ALDECI substitution closer.

Implements **real** format parsers for four commercial security vendors that
ALDECI previously only had stubbed/substitute integrations for:

  * Lacework             — Compliance event JSON dump
  * Sysdig Secure        — Runtime alert JSON dump
  * Recorded Future      — Entity export JSON
  * Mandiant Threat Intel— Indicator export JSON

For each vendor we:
  1. Parse the vendor's native JSON schema (keys + value shapes match the
     real product export formats — see field comments below).
  2. Normalize each record into ALDECI's internal canonical shape.
  3. Mirror appropriate records into the public engines:
       * SecurityFindingsEngine        — for findings/violations/alerts
       * ThreatIntelFusionEngine       — for IOCs/indicators
     via the same code path the REST API uses (no direct DB writes).
  4. Embed 5+ realistic sample records per vendor so air-gapped/demo
     environments still have a deterministic dataset.

Vision pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence),
V9 (Air-gapped fallback), V10 (Universal Connector Mesh).

Closes 4 of 11 substitute-only-integration gaps tracked in board.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from connectors._emit import emit_connector_event

logger = logging.getLogger(__name__)


# =============================================================================
# Severity normalization
# =============================================================================

_SEV_MAP: Dict[str, Tuple[str, float]] = {
    "CRITICAL":      ("critical",      9.5),
    "HIGH":          ("high",          7.5),
    "MEDIUM":        ("medium",        5.0),
    "MODERATE":      ("medium",        5.0),
    "LOW":           ("low",           3.0),
    "INFO":          ("informational", 0.0),
    "INFORMATIONAL": ("informational", 0.0),
    "UNKNOWN":       ("informational", 0.0),
    # Numeric Sysdig 1-7 mapped to severity bands
    "1": ("critical", 9.5),
    "2": ("critical", 9.0),
    "3": ("high",     7.5),
    "4": ("medium",   5.5),
    "5": ("medium",   4.5),
    "6": ("low",      3.0),
    "7": ("informational", 1.0),
}


def _normalize_severity(raw: Any) -> Tuple[str, float]:
    if raw is None:
        return ("informational", 0.0)
    key = str(raw).strip().upper()
    return _SEV_MAP.get(key, ("informational", 0.0))


def _risk_score_to_severity(score: Any) -> Tuple[str, float]:
    """Recorded Future / Mandiant 0-100 risk score → (severity, cvss)."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ("informational", 0.0)
    s = max(0.0, min(100.0, s))
    if s >= 80:
        return ("critical", round(min(10.0, s / 10.0), 1))
    if s >= 60:
        return ("high",     round(s / 10.0, 1))
    if s >= 40:
        return ("medium",   round(s / 10.0, 1))
    if s >= 20:
        return ("low",      round(s / 10.0, 1))
    return ("informational", round(s / 10.0, 1))


# =============================================================================
# Embedded sample dumps — 5+ records per vendor (real shape; safe for tests)
# =============================================================================

LACEWORK_SAMPLE: Dict[str, Any] = {
    "data": [
        {
            "host":       "ip-10-0-1-12.ec2.internal",
            "account":    "aws-prod-987654321098",
            "event_type": "ComplianceFailure",
            "severity":   "Critical",
            "rule_id":    "LW_AWS_S3_1",
            "title":      "S3 bucket allows public READ",
            "description":"Bucket 'corp-finance-2023' grants public READ via ACL.",
            "first_seen": "2026-04-22T11:30:11Z",
        },
        {
            "host":       "ip-10-0-2-44.ec2.internal",
            "account":    "aws-prod-987654321098",
            "event_type": "Vulnerability",
            "severity":   "High",
            "rule_id":    "LW_HOST_VULN_OPENSSL",
            "title":      "OpenSSL 1.1.1n CVE-2023-0286 (X.400 type confusion)",
            "description":"openssl 1.1.1n vulnerable; fixed in 1.1.1t.",
            "first_seen": "2026-04-22T12:01:02Z",
        },
        {
            "host":       "k8s-worker-3.cluster.local",
            "account":    "gcp-prod-883",
            "event_type": "RuntimeAnomaly",
            "severity":   "Medium",
            "rule_id":    "LW_K8S_RUNTIME_07",
            "title":      "Container spawned interactive shell",
            "description":"`/bin/sh -i` launched in pod nginx-7d9b.",
            "first_seen": "2026-04-22T13:14:55Z",
        },
        {
            "host":       "azure-vm-jumphost-01",
            "account":    "az-corp-prod",
            "event_type": "PolicyViolation",
            "severity":   "High",
            "rule_id":    "LW_AZ_NSG_01",
            "title":      "NSG allows 0.0.0.0/0 inbound 22",
            "description":"jumphost-nsg permits world-open SSH.",
            "first_seen": "2026-04-22T14:00:00Z",
        },
        {
            "host":       "ip-10-0-9-123.ec2.internal",
            "account":    "aws-prod-987654321098",
            "event_type": "ConfigDrift",
            "severity":   "Low",
            "rule_id":    "LW_AWS_IAM_8",
            "title":      "Root account access keys present",
            "description":"Root user has active access keys (CIS 1.4).",
            "first_seen": "2026-04-22T15:22:09Z",
        },
        {
            "host":       "rds-pg-prod.aws.local",
            "account":    "aws-prod-987654321098",
            "event_type": "ComplianceFailure",
            "severity":   "Medium",
            "rule_id":    "LW_AWS_RDS_4",
            "title":      "RDS instance not encrypted at rest",
            "description":"prod-postgres has StorageEncrypted=false.",
            "first_seen": "2026-04-22T15:45:30Z",
        },
    ]
}


SYSDIG_SAMPLE: Dict[str, Any] = {
    "alerts": [
        {
            "id":             "sysdig-evt-90011",
            "rule":           "Terminal shell in container",
            "severity":       3,
            "container_name": "checkout-service-7b9d-xx",
            "container_id":   "1f9ab23ce7",
            "host_id":        "node-prod-01",
            "policy":         "Container drift detection",
            "description":    "A shell was spawned in checkout-service container.",
            "timestamp":      "2026-04-22T11:00:00Z",
        },
        {
            "id":             "sysdig-evt-90012",
            "rule":           "Write below /etc",
            "severity":       2,
            "container_name": "redis-cache-1",
            "container_id":   "98ab23bb01",
            "host_id":        "node-prod-02",
            "policy":         "Critical filesystem writes",
            "description":    "Process wrote to /etc/passwd inside container.",
            "timestamp":      "2026-04-22T11:14:52Z",
        },
        {
            "id":             "sysdig-evt-90013",
            "rule":           "Outbound connection to suspicious IP",
            "severity":       3,
            "container_name": "billing-worker-3",
            "container_id":   "a01ce98213",
            "host_id":        "node-prod-03",
            "policy":         "Network anomaly",
            "description":    "Outbound to 185.220.101.45 (Tor exit).",
            "timestamp":      "2026-04-22T12:01:09Z",
        },
        {
            "id":             "sysdig-evt-90014",
            "rule":           "Privileged container started",
            "severity":       2,
            "container_name": "infra-debug-shell",
            "container_id":   "ff019a23bc",
            "host_id":        "node-prod-04",
            "policy":         "Privileged workloads",
            "description":    "Container started with --privileged=true.",
            "timestamp":      "2026-04-22T12:30:00Z",
        },
        {
            "id":             "sysdig-evt-90015",
            "rule":           "Sudoers file edited",
            "severity":       4,
            "container_name": "user-auth-1",
            "container_id":   "9912ab44ee",
            "host_id":        "node-prod-05",
            "policy":         "Privilege escalation",
            "description":    "/etc/sudoers modified inside container.",
            "timestamp":      "2026-04-22T13:00:00Z",
        },
        {
            "id":             "sysdig-evt-90016",
            "rule":           "Crypto miner process detected",
            "severity":       1,
            "container_name": "marketing-cms-worker",
            "container_id":   "55ee99aa11",
            "host_id":        "node-prod-06",
            "policy":         "Cryptomining detection",
            "description":    "xmrig process spawned with 92% CPU.",
            "timestamp":      "2026-04-22T13:30:00Z",
        },
    ]
}


RECORDED_FUTURE_SAMPLE: Dict[str, Any] = {
    "data": {
        "results": [
            {
                "entity": {"type": "IpAddress", "name": "185.220.101.45"},
                "risk":   {"score": 92, "level": "Very Malicious", "criticalityLabel": "Critical"},
                "evidenceDetails": [
                    {"rule": "Recent C&C Server", "evidenceString":
                        "185.220.101.45 reported as Cobalt Strike C2 on 2026-04-20."},
                    {"rule": "Tor Exit Node", "evidenceString":
                        "Confirmed Tor exit node since 2025-11-01."},
                ],
            },
            {
                "entity": {"type": "Hash", "name":
                    "44d88612fea8a8f36de82e1278abb02f"},
                "risk":   {"score": 88, "level": "Very Malicious"},
                "evidenceDetails": [
                    {"rule": "Linked to Malware",
                     "evidenceString": "MD5 linked to Emotet payload sample."},
                ],
            },
            {
                "entity": {"type": "Domain", "name": "secure-update-microsft.com"},
                "risk":   {"score": 76, "level": "Malicious"},
                "evidenceDetails": [
                    {"rule": "Typosquat",
                     "evidenceString": "Typosquat of microsoft.com registered 2026-04-15."},
                ],
            },
            {
                "entity": {"type": "URL", "name":
                    "http://malware-drop.example/payload.exe"},
                "risk":   {"score": 71, "level": "Malicious"},
                "evidenceDetails": [
                    {"rule": "Recent Malware Hosting",
                     "evidenceString": "Hosted Cobalt Strike beacon on 2026-04-19."},
                ],
            },
            {
                "entity": {"type": "IpAddress", "name": "104.21.45.12"},
                "risk":   {"score": 45, "level": "Suspicious"},
                "evidenceDetails": [
                    {"rule": "Recent SSH Brute Force",
                     "evidenceString": "Reported by 5+ honeypots in past 7d."},
                ],
            },
            {
                "entity": {"type": "Vulnerability", "name": "CVE-2024-21762"},
                "risk":   {"score": 95, "level": "Very Malicious",
                           "criticalityLabel": "Critical"},
                "evidenceDetails": [
                    {"rule": "Cyber Exploit",
                     "evidenceString": "Fortinet FortiOS RCE actively exploited."},
                ],
            },
        ]
    }
}


MANDIANT_SAMPLE: Dict[str, Any] = {
    "indicators": [
        {
            "id":               "indicator--mand-0001",
            "indicator_value":  "evil-c2.example.net",
            "type":             "fqdn",
            "severity":         "Critical",
            "confidence":       95,
            "attribution":      {"actor": "APT41",
                                 "motivations": ["espionage", "financial"]},
            "first_seen":       "2026-04-19T09:11:22Z",
            "last_seen":        "2026-04-22T10:11:22Z",
            "description":      "APT41 C2 infrastructure for ShadowPad.",
        },
        {
            "id":               "indicator--mand-0002",
            "indicator_value":  "104.244.74.211",
            "type":             "ipv4",
            "severity":         "High",
            "confidence":       85,
            "attribution":      {"actor": "Sandworm Team",
                                 "motivations": ["disruption"]},
            "first_seen":       "2026-04-15T00:00:00Z",
            "last_seen":        "2026-04-22T03:00:00Z",
            "description":      "Sandworm wiper staging server.",
        },
        {
            "id":               "indicator--mand-0003",
            "indicator_value":
                "5d41402abc4b2a76b9719d911017c592df4587f9b9f8a8c1c0fe2e9f0a8d9b1e",
            "type":             "sha256",
            "severity":         "Critical",
            "confidence":       99,
            "attribution":      {"actor": "Lazarus Group",
                                 "motivations": ["financial"]},
            "first_seen":       "2026-04-10T12:00:00Z",
            "last_seen":        "2026-04-22T12:00:00Z",
            "description":      "Lazarus AppleJeus backdoor sample.",
        },
        {
            "id":               "indicator--mand-0004",
            "indicator_value":  "phisher@bad-corp-update.org",
            "type":             "email",
            "severity":         "Medium",
            "confidence":       70,
            "attribution":      {"actor": "FIN7",
                                 "motivations": ["financial"]},
            "first_seen":       "2026-04-21T08:00:00Z",
            "last_seen":        "2026-04-22T08:00:00Z",
            "description":      "FIN7 spear-phishing sender.",
        },
        {
            "id":               "indicator--mand-0005",
            "indicator_value":  "https://evil-cdn.example/loader.js",
            "type":             "url",
            "severity":         "High",
            "confidence":       80,
            "attribution":      {"actor": "Magecart",
                                 "motivations": ["financial"]},
            "first_seen":       "2026-04-22T01:00:00Z",
            "last_seen":        "2026-04-22T13:00:00Z",
            "description":      "Magecart skimmer loader.",
        },
        {
            "id":               "indicator--mand-0006",
            "indicator_value":  "198.51.100.77",
            "type":             "ipv4",
            "severity":         "Low",
            "confidence":       55,
            "attribution":      {"actor": "Unattributed",
                                 "motivations": []},
            "first_seen":       "2026-04-22T11:00:00Z",
            "last_seen":        "2026-04-22T11:30:00Z",
            "description":      "Low-confidence scanning host.",
        },
    ]
}


_MANDIANT_TYPE_MAP = {
    "ipv4": "ip", "ipv6": "ip", "ip-addr": "ip",
    "fqdn": "domain", "domain": "domain",
    "url": "url",
    "sha256": "hash", "md5": "hash", "sha1": "hash", "hash": "hash",
    "email": "email",
}

_RF_TYPE_MAP = {
    "IpAddress": "ip", "Ip": "ip",
    "Domain": "domain", "InternetDomainName": "domain",
    "URL": "url", "Url": "url",
    "Hash": "hash", "FileHash": "hash",
    "EmailAddress": "email",
    "Vulnerability": "url",  # CVE — not strictly an IOC; downgraded to URL bucket
}


# =============================================================================
# Result wrappers
# =============================================================================

@dataclass
class IngestResult:
    vendor: str
    org_id: str
    findings_recorded: int = 0
    indicators_recorded: int = 0
    skipped: int = 0
    errors: List[str] = field(default_factory=list)
    used_fallback: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor":              self.vendor,
            "org_id":              self.org_id,
            "findings_recorded":   self.findings_recorded,
            "indicators_recorded": self.indicators_recorded,
            "skipped":             self.skipped,
            "errors":              self.errors,
            "used_fallback":       self.used_fallback,
            "total":               self.findings_recorded + self.indicators_recorded,
        }


# =============================================================================
# Connector
# =============================================================================

class CommercialVendorConnector:
    """Universal commercial-vendor parser & ingester.

    Mirrors records into:
      * SecurityFindingsEngine.record_finding   — for events / alerts / vulns
      * ThreatIntelFusionEngine.ingest_indicator — for IOCs / indicators

    All ingestion uses the **public API surface** of those engines so dedup,
    correlation_key, lifecycle and TrustGraph emission stay authoritative.
    """

    def __init__(self,
                 findings_engine: Any = None,
                 ti_engine: Any = None) -> None:
        self._findings_engine = findings_engine
        self._ti_engine = ti_engine

    # ---- engines (lazy) -----------------------------------------------------

    def _findings(self):
        if self._findings_engine is None:
            from core.security_findings_engine import SecurityFindingsEngine
            self._findings_engine = SecurityFindingsEngine()
        return self._findings_engine

    def _ti(self):
        if self._ti_engine is None:
            from core.threat_intel_fusion_engine import ThreatIntelFusionEngine
            self._ti_engine = ThreatIntelFusionEngine()
        return self._ti_engine

    # ---- safe ingestion helpers --------------------------------------------

    def _record_finding(self,
                        org_id: str,
                        title: str,
                        finding_type: str,
                        source_tool: str,
                        severity: str,
                        cvss: float,
                        asset_id: str,
                        asset_type: str,
                        description: str,
                        remediation: str,
                        correlation_key: str,
                        scan_id: str,
                        result: IngestResult) -> bool:
        try:
            self._findings().record_finding(
                org_id=org_id,
                title=str(title)[:240],
                finding_type=finding_type,
                source_tool=source_tool,
                severity=severity,
                cvss_score=float(cvss),
                asset_id=str(asset_id)[:240],
                asset_type=asset_type,
                description=str(description)[:4000],
                remediation=str(remediation)[:4000],
                correlation_key=correlation_key,
                scan_id=scan_id,
            )
            return True
        except (ValueError, TypeError, sqlite3.Error, KeyError) as exc:
            result.errors.append(f"finding ingest failed: {exc}")
            return False
        except Exception as exc:  # noqa: BLE001  — never let a single bad row kill the batch
            result.errors.append(f"finding ingest unexpected: {exc}")
            return False

    def _record_indicator(self,
                          org_id: str,
                          indicator_type: str,
                          value: str,
                          confidence: int,
                          tags: List[str],
                          source_id: str,
                          result: IngestResult) -> bool:
        if indicator_type not in {"ip", "domain", "hash", "url", "email"}:
            indicator_type = "ip"
        try:
            self._ti().ingest_indicator(
                org_id,
                {
                    "indicator_type": indicator_type,
                    "value":          str(value),
                    "confidence":     int(max(0, min(100, confidence))),
                    "tags":           tags if isinstance(tags, list) else [],
                    "source_id":      source_id,
                    "expiry_days":    30,
                },
            )
            return True
        except (ValueError, TypeError, sqlite3.Error, KeyError) as exc:
            result.errors.append(f"indicator ingest failed: {exc}")
            return False
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"indicator ingest unexpected: {exc}")
            return False

    # =========================================================================
    # LACEWORK
    # =========================================================================

    def ingest_lacework_dump(self,
                             org_id: str = "default",
                             dump: Optional[Dict[str, Any]] = None) -> IngestResult:
        """Parse Lacework Compliance Event JSON; mirror to SecurityFindings."""
        result = IngestResult(vendor="lacework", org_id=org_id)
        if dump is None:
            dump = LACEWORK_SAMPLE
            result.used_fallback = True
        records = (dump.get("data") or []) if isinstance(dump, dict) else []
        if not isinstance(records, list):
            result.errors.append("lacework: 'data' must be a list")
            return result
        for row in records:
            if not isinstance(row, dict):
                result.skipped += 1
                continue
            host       = str(row.get("host") or "").strip()
            account    = str(row.get("account") or "").strip()
            event_type = str(row.get("event_type") or "ComplianceFailure").strip()
            severity   = row.get("severity") or "Medium"
            rule_id    = str(row.get("rule_id") or "").strip()
            title      = str(row.get("title") or rule_id or "Lacework event").strip()
            desc       = str(row.get("description") or "").strip()
            first_seen = str(row.get("first_seen") or "").strip()

            if not (host or account):
                result.skipped += 1
                continue

            sev_label, cvss = _normalize_severity(severity)
            asset_id = f"{account}:{host}".strip(":") or "unknown-asset"
            corr     = f"lacework|{account}|{host}|{rule_id}|{event_type}"

            ftype = "compliance-gap"
            if event_type.lower().startswith("vuln"):
                ftype = "vulnerability"
            elif "anomaly" in event_type.lower():
                ftype = "anomaly"
            elif "policy" in event_type.lower() or "drift" in event_type.lower():
                ftype = "policy-violation"

            ok = self._record_finding(
                org_id=org_id,
                title=f"[Lacework] {title}",
                finding_type=ftype,
                source_tool="custom",  # vendor name carried in correlation_key + tags
                severity=sev_label,
                cvss=cvss,
                asset_id=asset_id,
                asset_type="cloud_resource",
                description=f"{desc}\n\nVendor: Lacework | Rule: {rule_id} "
                            f"| First seen: {first_seen}",
                remediation=f"Address Lacework rule {rule_id} on {asset_id}",
                correlation_key=corr,
                scan_id=f"lacework:{account or 'global'}",
                result=result,
            )
            if ok:
                result.findings_recorded += 1
            else:
                result.skipped += 1
        emit_connector_event(
            connector="CommercialVendorConnector",
            org_id=org_id,
            source_kind="cspm",
            finding_count=result.findings_recorded,
            extra={"vendor": "lacework", "skipped": result.skipped, "used_fallback": result.used_fallback},
        )
        return result

    # =========================================================================
    # SYSDIG SECURE
    # =========================================================================

    def ingest_sysdig_dump(self,
                           org_id: str = "default",
                           dump: Optional[Dict[str, Any]] = None) -> IngestResult:
        """Parse Sysdig Secure runtime alert JSON; mirror to SecurityFindings."""
        result = IngestResult(vendor="sysdig", org_id=org_id)
        if dump is None:
            dump = SYSDIG_SAMPLE
            result.used_fallback = True
        alerts = (dump.get("alerts") or []) if isinstance(dump, dict) else []
        if not isinstance(alerts, list):
            result.errors.append("sysdig: 'alerts' must be a list")
            return result
        for a in alerts:
            if not isinstance(a, dict):
                result.skipped += 1
                continue
            alert_id  = str(a.get("id") or "").strip()
            rule      = str(a.get("rule") or "").strip()
            sev_raw   = a.get("severity")
            container = str(a.get("container_name") or "").strip()
            cid       = str(a.get("container_id") or "").strip()
            host_id   = str(a.get("host_id") or "").strip()
            policy    = str(a.get("policy") or "").strip()
            desc      = str(a.get("description") or "").strip()
            ts        = str(a.get("timestamp") or "").strip()

            if not (rule and (container or host_id)):
                result.skipped += 1
                continue
            sev_label, cvss = _normalize_severity(sev_raw)
            asset_id = f"{host_id}:{container}".strip(":") or alert_id or "sysdig-asset"
            corr     = f"sysdig|{host_id}|{container}|{rule}|{policy}"

            ftype = "anomaly"
            low = rule.lower()
            if "shell" in low or "privileg" in low or "sudo" in low:
                ftype = "policy-violation"
            elif "miner" in low or "malware" in low:
                ftype = "malware"

            ok = self._record_finding(
                org_id=org_id,
                title=f"[Sysdig] {rule}",
                finding_type=ftype,
                source_tool="custom",
                severity=sev_label,
                cvss=cvss,
                asset_id=asset_id,
                asset_type="container",
                description=f"{desc}\n\nVendor: Sysdig Secure | Policy: {policy} "
                            f"| Container: {container} ({cid}) "
                            f"| Host: {host_id} | At: {ts}",
                remediation=f"Investigate Sysdig alert {alert_id} on {asset_id}; "
                            f"review policy '{policy}'",
                correlation_key=corr,
                scan_id=f"sysdig:{host_id or 'global'}",
                result=result,
            )
            if ok:
                result.findings_recorded += 1
            else:
                result.skipped += 1
        emit_connector_event(
            connector="CommercialVendorConnector",
            org_id=org_id,
            source_kind="container",
            finding_count=result.findings_recorded,
            extra={"vendor": "sysdig", "skipped": result.skipped, "used_fallback": result.used_fallback},
        )
        return result

    # =========================================================================
    # RECORDED FUTURE
    # =========================================================================

    def ingest_recorded_future_dump(self,
                                    org_id: str = "default",
                                    dump: Optional[Dict[str, Any]] = None) -> IngestResult:
        """Parse Recorded Future entity export; mirror IOCs to TI Fusion +
        emit a finding for each high/critical risk score so risk surface
        reflects exposure.
        """
        result = IngestResult(vendor="recorded_future", org_id=org_id)
        if dump is None:
            dump = RECORDED_FUTURE_SAMPLE
            result.used_fallback = True
        # Real RF API: dump["data"]["results"] OR dump["results"] depending on endpoint
        data = dump.get("data") if isinstance(dump, dict) else None
        results = []
        if isinstance(data, dict):
            results = data.get("results") or []
        elif isinstance(dump, dict):
            results = dump.get("results") or []
        if not isinstance(results, list):
            result.errors.append("recorded_future: missing/invalid 'results' list")
            return result

        for r in results:
            if not isinstance(r, dict):
                result.skipped += 1
                continue
            entity = r.get("entity") or {}
            risk   = r.get("risk") or {}
            ev     = r.get("evidenceDetails") or []
            if not isinstance(entity, dict):
                result.skipped += 1
                continue
            ent_type = str(entity.get("type") or "").strip()
            ent_name = str(entity.get("name") or "").strip()
            score    = risk.get("score", 0)
            level    = str(risk.get("level") or "").strip()
            crit_lbl = str(risk.get("criticalityLabel") or "").strip()
            if not ent_name:
                result.skipped += 1
                continue

            sev_label, cvss = _risk_score_to_severity(score)
            mapped = _RF_TYPE_MAP.get(ent_type, "ip")
            evidence_str = " | ".join(
                f"{(e or {}).get('rule', '?')}: "
                f"{(e or {}).get('evidenceString', '')[:160]}"
                for e in ev if isinstance(e, dict)
            )[:1200]

            # ---- Mirror to TI Fusion (IOC pivot path) -----------------------
            if ent_type != "Vulnerability":
                tags = [t for t in (level.lower().replace(" ", "_"),
                                    crit_lbl.lower(),
                                    "recorded_future") if t]
                if self._record_indicator(
                    org_id=org_id,
                    indicator_type=mapped,
                    value=ent_name,
                    confidence=int(max(0, min(100, float(score or 0)))),
                    tags=tags,
                    source_id="recorded_future",
                    result=result,
                ):
                    result.indicators_recorded += 1

            # ---- Mirror to SecurityFindings when meaningfully risky --------
            try:
                num_score = float(score)
            except (TypeError, ValueError):
                num_score = 0.0
            if num_score >= 60:
                corr = f"recorded_future|{ent_type}|{ent_name}"
                ok = self._record_finding(
                    org_id=org_id,
                    title=f"[Recorded Future] {ent_type} {ent_name} ({level})",
                    finding_type=("vulnerability"
                                  if ent_type == "Vulnerability"
                                  else "anomaly"),
                    source_tool="custom",
                    severity=sev_label,
                    cvss=cvss,
                    asset_id=ent_name,
                    asset_type="threat_intel_entity",
                    description=f"Recorded Future risk score {num_score} ({level}). "
                                f"Evidence: {evidence_str or 'n/a'}",
                    remediation="Block at perimeter / hunt across logs for matches "
                                "to this entity.",
                    correlation_key=corr,
                    scan_id="recorded_future:export",
                    result=result,
                )
                if ok:
                    result.findings_recorded += 1
        emit_connector_event(
            connector="CommercialVendorConnector",
            org_id=org_id,
            source_kind="threat_intel",
            finding_count=result.findings_recorded + result.indicators_recorded,
            extra={
                "vendor": "recorded_future",
                "indicators_recorded": result.indicators_recorded,
                "findings_recorded": result.findings_recorded,
                "used_fallback": result.used_fallback,
            },
        )
        return result

    # =========================================================================
    # MANDIANT THREAT INTEL
    # =========================================================================

    def ingest_mandiant_dump(self,
                             org_id: str = "default",
                             dump: Optional[Dict[str, Any]] = None) -> IngestResult:
        """Parse Mandiant Threat Intel indicator export; mirror IOCs to TI
        Fusion + emit findings for High/Critical attributions.
        """
        result = IngestResult(vendor="mandiant", org_id=org_id)
        if dump is None:
            dump = MANDIANT_SAMPLE
            result.used_fallback = True
        indicators = (dump.get("indicators") or []) if isinstance(dump, dict) else []
        if not isinstance(indicators, list):
            result.errors.append("mandiant: 'indicators' must be a list")
            return result

        for ind in indicators:
            if not isinstance(ind, dict):
                result.skipped += 1
                continue
            ind_id = str(ind.get("id") or "").strip()
            value  = str(ind.get("indicator_value") or ind.get("value") or "").strip()
            raw_t  = str(ind.get("type") or "ip").strip().lower()
            sev    = ind.get("severity") or "Medium"
            conf   = ind.get("confidence", 50)
            attr   = ind.get("attribution") or {}
            actor  = str((attr or {}).get("actor") or "Unknown").strip()
            motiv  = list((attr or {}).get("motivations") or [])
            desc   = str(ind.get("description") or "").strip()
            first_seen = str(ind.get("first_seen") or "").strip()
            last_seen  = str(ind.get("last_seen") or "").strip()
            if not value:
                result.skipped += 1
                continue

            sev_label, cvss = _normalize_severity(sev)
            mapped_type = _MANDIANT_TYPE_MAP.get(raw_t, "ip")
            try:
                conf_int = int(conf)
            except (TypeError, ValueError):
                conf_int = 50
            conf_int = max(0, min(100, conf_int))

            tags = ["mandiant", actor.lower().replace(" ", "_")] + \
                   [m.lower() for m in motiv if isinstance(m, str)]

            if self._record_indicator(
                org_id=org_id,
                indicator_type=mapped_type,
                value=value,
                confidence=conf_int,
                tags=[t for t in tags if t],
                source_id=f"mandiant:{actor}",
                result=result,
            ):
                result.indicators_recorded += 1

            # Always emit a finding — Mandiant attribution is high-fidelity.
            corr = f"mandiant|{actor}|{value}|{ind_id}"
            ok = self._record_finding(
                org_id=org_id,
                title=f"[Mandiant] {actor} indicator: {value}",
                finding_type="anomaly",
                source_tool="custom",
                severity=sev_label,
                cvss=cvss,
                asset_id=value,
                asset_type="threat_intel_entity",
                description=(
                    f"{desc}\n\nVendor: Mandiant TI | Actor: {actor} "
                    f"| Motivations: {', '.join(motiv) or 'n/a'} "
                    f"| Confidence: {conf_int} "
                    f"| First seen: {first_seen} | Last seen: {last_seen}"
                ),
                remediation=(
                    f"Search SIEM/EDR for {value}; if seen, treat as confirmed "
                    f"compromise consistent with {actor} TTPs."
                ),
                correlation_key=corr,
                scan_id="mandiant:export",
                result=result,
            )
            if ok:
                result.findings_recorded += 1
        emit_connector_event(
            connector="CommercialVendorConnector",
            org_id=org_id,
            source_kind="threat_intel",
            finding_count=result.findings_recorded + result.indicators_recorded,
            extra={
                "vendor": "mandiant",
                "indicators_recorded": result.indicators_recorded,
                "findings_recorded": result.findings_recorded,
                "used_fallback": result.used_fallback,
            },
        )
        return result

    # =========================================================================
    # Convenience
    # =========================================================================

    def ingest_all_samples(self, org_id: str = "default") -> Dict[str, Any]:
        """Run every embedded sample through every parser. Useful for demos."""
        return {
            "lacework":         self.ingest_lacework_dump(org_id).to_dict(),
            "sysdig":           self.ingest_sysdig_dump(org_id).to_dict(),
            "recorded_future":  self.ingest_recorded_future_dump(org_id).to_dict(),
            "mandiant":         self.ingest_mandiant_dump(org_id).to_dict(),
            "completed_at":     time.time(),
        }


# =============================================================================
# Singleton accessor
# =============================================================================

_default_connector: Optional[CommercialVendorConnector] = None


def get_default_connector() -> CommercialVendorConnector:
    global _default_connector
    if _default_connector is None:
        _default_connector = CommercialVendorConnector()
    return _default_connector


__all__ = [
    "CommercialVendorConnector",
    "IngestResult",
    "get_default_connector",
    "LACEWORK_SAMPLE",
    "SYSDIG_SAMPLE",
    "RECORDED_FUTURE_SAMPLE",
    "MANDIANT_SAMPLE",
]
