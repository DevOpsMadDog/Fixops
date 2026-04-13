"""
Playbook Marketplace — shareable, importable remediation playbooks.

Provides a SQLite-backed marketplace where teams can publish, browse, install,
rate, export and import security playbook templates covering incident response,
remediation, compliance and hardening scenarios.

15 built-in templates ship with the platform. Organisations can publish their
own and import templates from external sources.

Compliance: SOC2 CC7.2, NIST IR-4, ISO27001 A.16
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

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_DB_DEFAULT = str(Path(__file__).parent.parent / "data" / "playbook_marketplace.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PlaybookCategory(str, Enum):
    INCIDENT_RESPONSE = "incident_response"
    REMEDIATION = "remediation"
    COMPLIANCE = "compliance"
    HARDENING = "hardening"


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class PlaybookTemplate(BaseModel):
    """A shareable playbook template in the marketplace."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    category: PlaybookCategory
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    author: str = "community"
    version: str = "1.0.0"
    downloads: int = 0
    rating: float = 0.0
    rating_count: int = 0
    tags: List[str] = Field(default_factory=list)
    org_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Built-in templates
# ---------------------------------------------------------------------------


def _builtin_templates() -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "id": "pb-ransomware-response-001",
            "name": "Ransomware Incident Response",
            "description": "End-to-end ransomware response: isolation, forensics, recovery, and communication",
            "category": "incident_response",
            "author": "ALDECI Security Team",
            "version": "2.0.0",
            "tags": ["ransomware", "incident-response", "critical"],
            "steps": [
                {"order": 1, "name": "Isolate affected systems", "action": "network_isolation", "automated": True},
                {"order": 2, "name": "Notify incident response team", "action": "notify_team", "automated": True},
                {"order": 3, "name": "Capture forensic images", "action": "forensic_capture", "automated": False},
                {"order": 4, "name": "Identify patient zero", "action": "threat_hunt", "automated": False},
                {"order": 5, "name": "Assess backup integrity", "action": "backup_check", "automated": True},
                {"order": 6, "name": "Eradicate malware", "action": "malware_removal", "automated": False},
                {"order": 7, "name": "Restore from clean backup", "action": "restore_backup", "automated": False},
                {"order": 8, "name": "Post-incident review", "action": "pir_report", "automated": False},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-data-breach-001",
            "name": "Data Breach Response",
            "description": "GDPR/CCPA-aligned data breach response: containment, notification, regulatory reporting",
            "category": "incident_response",
            "author": "ALDECI Security Team",
            "version": "1.5.0",
            "tags": ["data-breach", "gdpr", "ccpa", "regulatory"],
            "steps": [
                {"order": 1, "name": "Confirm breach scope", "action": "scope_assessment", "automated": False},
                {"order": 2, "name": "Contain data exfiltration", "action": "block_exfil", "automated": True},
                {"order": 3, "name": "Preserve evidence", "action": "evidence_collection", "automated": True},
                {"order": 4, "name": "Notify DPO / legal counsel", "action": "notify_legal", "automated": True},
                {"order": 5, "name": "72-hour regulatory notification", "action": "regulator_notice", "automated": False},
                {"order": 6, "name": "Notify affected individuals", "action": "user_notification", "automated": False},
                {"order": 7, "name": "Remediate root cause", "action": "root_cause_fix", "automated": False},
                {"order": 8, "name": "Update data inventory", "action": "data_inventory_update", "automated": False},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-patch-management-001",
            "name": "Critical Patch Management",
            "description": "Automated patch assessment, testing, and deployment pipeline for critical CVEs",
            "category": "remediation",
            "author": "ALDECI Security Team",
            "version": "1.2.0",
            "tags": ["patching", "cve", "vulnerability-management"],
            "steps": [
                {"order": 1, "name": "Identify affected assets", "action": "asset_scan", "automated": True},
                {"order": 2, "name": "Assess exploitability (CVSS/EPSS)", "action": "risk_score", "automated": True},
                {"order": 3, "name": "Download and verify patches", "action": "patch_download", "automated": True},
                {"order": 4, "name": "Deploy to staging environment", "action": "staging_deploy", "automated": True},
                {"order": 5, "name": "Run regression tests", "action": "regression_test", "automated": True},
                {"order": 6, "name": "Schedule production deployment", "action": "prod_schedule", "automated": False},
                {"order": 7, "name": "Deploy to production", "action": "prod_deploy", "automated": True},
                {"order": 8, "name": "Verify patch success", "action": "patch_verify", "automated": True},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-server-hardening-001",
            "name": "Linux Server Hardening",
            "description": "CIS Benchmark Level 2 server hardening: SSH, firewall, audit, kernel parameters",
            "category": "hardening",
            "author": "ALDECI Security Team",
            "version": "3.0.0",
            "tags": ["cis-benchmark", "linux", "hardening", "ssh"],
            "steps": [
                {"order": 1, "name": "Disable unused services", "action": "disable_services", "automated": True},
                {"order": 2, "name": "Configure SSH hardening", "action": "ssh_harden", "automated": True},
                {"order": 3, "name": "Enable auditd logging", "action": "enable_auditd", "automated": True},
                {"order": 4, "name": "Apply kernel security params", "action": "sysctl_harden", "automated": True},
                {"order": 5, "name": "Configure firewall rules", "action": "firewall_configure", "automated": True},
                {"order": 6, "name": "Enable AIDE file integrity", "action": "aide_configure", "automated": True},
                {"order": 7, "name": "Configure PAM password policy", "action": "pam_harden", "automated": True},
                {"order": 8, "name": "Validate CIS score", "action": "cis_validate", "automated": True},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-soc2-readiness-001",
            "name": "SOC 2 Type II Readiness",
            "description": "Step-by-step SOC 2 Type II preparation: controls gap analysis, evidence collection, audit preparation",
            "category": "compliance",
            "author": "ALDECI Security Team",
            "version": "1.0.0",
            "tags": ["soc2", "compliance", "audit", "trust-services"],
            "steps": [
                {"order": 1, "name": "Map trust service criteria", "action": "tsc_mapping", "automated": True},
                {"order": 2, "name": "Run controls gap analysis", "action": "gap_analysis", "automated": True},
                {"order": 3, "name": "Remediate critical gaps", "action": "gap_remediation", "automated": False},
                {"order": 4, "name": "Collect continuous evidence", "action": "evidence_collect", "automated": True},
                {"order": 5, "name": "Conduct internal audit", "action": "internal_audit", "automated": False},
                {"order": 6, "name": "Engage external auditor", "action": "auditor_engage", "automated": False},
                {"order": 7, "name": "Address auditor findings", "action": "finding_remediate", "automated": False},
                {"order": 8, "name": "Obtain SOC 2 report", "action": "report_obtain", "automated": False},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-phishing-response-001",
            "name": "Phishing Incident Response",
            "description": "Rapid phishing email response: user triage, credential reset, mailbox cleanup, awareness",
            "category": "incident_response",
            "author": "ALDECI Security Team",
            "version": "1.1.0",
            "tags": ["phishing", "email", "social-engineering"],
            "steps": [
                {"order": 1, "name": "Quarantine phishing email", "action": "email_quarantine", "automated": True},
                {"order": 2, "name": "Identify all recipients", "action": "recipient_identify", "automated": True},
                {"order": 3, "name": "Check for credential compromise", "action": "cred_check", "automated": True},
                {"order": 4, "name": "Force password reset", "action": "password_reset", "automated": True},
                {"order": 5, "name": "Revoke active sessions", "action": "session_revoke", "automated": True},
                {"order": 6, "name": "Block sender domain", "action": "domain_block", "automated": True},
                {"order": 7, "name": "User awareness notification", "action": "user_notify", "automated": True},
                {"order": 8, "name": "Submit IOCs to threat intel", "action": "ioc_submit", "automated": True},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-cloud-misconfig-001",
            "name": "Cloud Misconfiguration Remediation",
            "description": "Auto-remediate common AWS/Azure/GCP misconfigurations: public S3 buckets, open security groups, exposed secrets",
            "category": "remediation",
            "author": "ALDECI Security Team",
            "version": "2.1.0",
            "tags": ["cloud", "aws", "azure", "gcp", "misconfiguration", "cspm"],
            "steps": [
                {"order": 1, "name": "Scan for misconfigurations", "action": "cloud_scan", "automated": True},
                {"order": 2, "name": "Prioritize by risk score", "action": "risk_prioritize", "automated": True},
                {"order": 3, "name": "Block public S3 access", "action": "s3_block_public", "automated": True},
                {"order": 4, "name": "Restrict security groups", "action": "sg_restrict", "automated": True},
                {"order": 5, "name": "Rotate exposed secrets", "action": "secret_rotate", "automated": True},
                {"order": 6, "name": "Enable CloudTrail/Activity logs", "action": "audit_enable", "automated": True},
                {"order": 7, "name": "Enforce encryption at rest", "action": "encrypt_enforce", "automated": True},
                {"order": 8, "name": "Validate posture score", "action": "posture_validate", "automated": True},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-iso27001-001",
            "name": "ISO 27001 Certification Readiness",
            "description": "ISO 27001:2022 certification preparation: ISMS scope, risk assessment, controls implementation",
            "category": "compliance",
            "author": "ALDECI Security Team",
            "version": "1.0.0",
            "tags": ["iso27001", "isms", "compliance", "certification"],
            "steps": [
                {"order": 1, "name": "Define ISMS scope", "action": "isms_scope", "automated": False},
                {"order": 2, "name": "Information security risk assessment", "action": "risk_assessment", "automated": True},
                {"order": 3, "name": "Select Annex A controls", "action": "control_select", "automated": True},
                {"order": 4, "name": "Implement selected controls", "action": "control_implement", "automated": False},
                {"order": 5, "name": "Internal audit", "action": "internal_audit", "automated": False},
                {"order": 6, "name": "Management review", "action": "mgmt_review", "automated": False},
                {"order": 7, "name": "Stage 1 certification audit", "action": "cert_audit_1", "automated": False},
                {"order": 8, "name": "Stage 2 certification audit", "action": "cert_audit_2", "automated": False},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-insider-threat-001",
            "name": "Insider Threat Response",
            "description": "Structured insider threat investigation: evidence preservation, access revocation, HR coordination",
            "category": "incident_response",
            "author": "ALDECI Security Team",
            "version": "1.0.0",
            "tags": ["insider-threat", "ueba", "investigation"],
            "steps": [
                {"order": 1, "name": "Flag suspicious behaviour", "action": "ueba_alert", "automated": True},
                {"order": 2, "name": "Preserve digital evidence", "action": "evidence_preserve", "automated": True},
                {"order": 3, "name": "Notify HR and legal", "action": "hr_legal_notify", "automated": False},
                {"order": 4, "name": "Restrict access silently", "action": "access_restrict", "automated": True},
                {"order": 5, "name": "Monitor exfiltration channels", "action": "exfil_monitor", "automated": True},
                {"order": 6, "name": "Conduct investigation interview", "action": "interview", "automated": False},
                {"order": 7, "name": "Revoke all access", "action": "access_revoke", "automated": True},
                {"order": 8, "name": "File incident report", "action": "incident_report", "automated": False},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-vuln-remediation-001",
            "name": "CVSS Critical Vulnerability Remediation",
            "description": "Structured remediation workflow for CVSS 9.0+ vulnerabilities with SLA tracking",
            "category": "remediation",
            "author": "ALDECI Security Team",
            "version": "1.3.0",
            "tags": ["vulnerability", "cvss", "cve", "sla"],
            "steps": [
                {"order": 1, "name": "Triage vulnerability report", "action": "vuln_triage", "automated": True},
                {"order": 2, "name": "Identify affected assets", "action": "asset_identify", "automated": True},
                {"order": 3, "name": "Apply compensating controls", "action": "compensating_controls", "automated": True},
                {"order": 4, "name": "Develop remediation plan", "action": "remediation_plan", "automated": False},
                {"order": 5, "name": "Test fix in staging", "action": "staging_test", "automated": True},
                {"order": 6, "name": "Deploy fix to production", "action": "prod_deploy", "automated": True},
                {"order": 7, "name": "Verify remediation", "action": "verify_fix", "automated": True},
                {"order": 8, "name": "Close vulnerability ticket", "action": "ticket_close", "automated": True},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-kubernetes-hardening-001",
            "name": "Kubernetes Cluster Hardening",
            "description": "NSA/CISA Kubernetes hardening guide: RBAC, network policies, pod security, secrets management",
            "category": "hardening",
            "author": "ALDECI Security Team",
            "version": "1.0.0",
            "tags": ["kubernetes", "k8s", "container", "hardening", "nsa-cisa"],
            "steps": [
                {"order": 1, "name": "Audit RBAC permissions", "action": "rbac_audit", "automated": True},
                {"order": 2, "name": "Apply pod security standards", "action": "pod_security", "automated": True},
                {"order": 3, "name": "Configure network policies", "action": "network_policy", "automated": True},
                {"order": 4, "name": "Enable secrets encryption", "action": "secret_encrypt", "automated": True},
                {"order": 5, "name": "Disable privileged containers", "action": "priv_disable", "automated": True},
                {"order": 6, "name": "Enable audit logging", "action": "audit_log", "automated": True},
                {"order": 7, "name": "Configure admission controllers", "action": "admission_ctrl", "automated": True},
                {"order": 8, "name": "Run kube-bench validation", "action": "kube_bench", "automated": True},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-pci-dss-001",
            "name": "PCI DSS v4.0 Compliance",
            "description": "PCI DSS 4.0 compliance workflow: cardholder data environment scoping, controls, QSA assessment",
            "category": "compliance",
            "author": "ALDECI Security Team",
            "version": "1.0.0",
            "tags": ["pci-dss", "compliance", "payment", "cardholder-data"],
            "steps": [
                {"order": 1, "name": "Define CDE scope", "action": "cde_scope", "automated": False},
                {"order": 2, "name": "Network segmentation validation", "action": "network_segment", "automated": True},
                {"order": 3, "name": "Vulnerability scans (ASV)", "action": "asv_scan", "automated": True},
                {"order": 4, "name": "Penetration testing", "action": "pentest", "automated": False},
                {"order": 5, "name": "Implement required controls", "action": "controls_implement", "automated": False},
                {"order": 6, "name": "Self-assessment questionnaire", "action": "saq_complete", "automated": False},
                {"order": 7, "name": "QSA on-site assessment", "action": "qsa_assess", "automated": False},
                {"order": 8, "name": "Remediate QSA findings", "action": "qsa_remediate", "automated": False},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-ddos-response-001",
            "name": "DDoS Attack Response",
            "description": "DDoS mitigation: traffic analysis, upstream filtering, CDN failover, and post-attack hardening",
            "category": "incident_response",
            "author": "ALDECI Security Team",
            "version": "1.0.0",
            "tags": ["ddos", "availability", "cdn", "traffic"],
            "steps": [
                {"order": 1, "name": "Detect and classify DDoS", "action": "ddos_detect", "automated": True},
                {"order": 2, "name": "Activate CDN DDoS protection", "action": "cdn_activate", "automated": True},
                {"order": 3, "name": "Enable upstream rate limiting", "action": "rate_limit", "automated": True},
                {"order": 4, "name": "Engage upstream ISP filtering", "action": "isp_filter", "automated": False},
                {"order": 5, "name": "Null-route attack source IPs", "action": "null_route", "automated": True},
                {"order": 6, "name": "Notify stakeholders", "action": "stakeholder_notify", "automated": True},
                {"order": 7, "name": "Monitor recovery", "action": "recovery_monitor", "automated": True},
                {"order": 8, "name": "Post-attack hardening review", "action": "hardening_review", "automated": False},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-zero-trust-001",
            "name": "Zero Trust Architecture Hardening",
            "description": "NIST SP 800-207 Zero Trust implementation: identity verification, micro-segmentation, continuous validation",
            "category": "hardening",
            "author": "ALDECI Security Team",
            "version": "1.0.0",
            "tags": ["zero-trust", "nist", "micro-segmentation", "identity"],
            "steps": [
                {"order": 1, "name": "Inventory all assets and identities", "action": "asset_inventory", "automated": True},
                {"order": 2, "name": "Implement strong MFA", "action": "mfa_enforce", "automated": True},
                {"order": 3, "name": "Apply least-privilege access", "action": "least_priv", "automated": True},
                {"order": 4, "name": "Deploy micro-segmentation", "action": "micro_segment", "automated": False},
                {"order": 5, "name": "Enforce device health checks", "action": "device_health", "automated": True},
                {"order": 6, "name": "Enable continuous session validation", "action": "session_validate", "automated": True},
                {"order": 7, "name": "Centralise log and telemetry", "action": "log_centralise", "automated": True},
                {"order": 8, "name": "Run zero-trust maturity assessment", "action": "maturity_assess", "automated": True},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": "pb-supply-chain-001",
            "name": "Software Supply Chain Security",
            "description": "SLSA Level 3 supply chain hardening: SBOM generation, dependency audit, provenance verification",
            "category": "remediation",
            "author": "ALDECI Security Team",
            "version": "1.0.0",
            "tags": ["supply-chain", "sbom", "slsa", "dependencies"],
            "steps": [
                {"order": 1, "name": "Generate SBOM for all projects", "action": "sbom_generate", "automated": True},
                {"order": 2, "name": "Audit third-party dependencies", "action": "dep_audit", "automated": True},
                {"order": 3, "name": "Scan for known CVEs in deps", "action": "dep_cve_scan", "automated": True},
                {"order": 4, "name": "Enforce dependency pinning", "action": "dep_pin", "automated": True},
                {"order": 5, "name": "Sign all build artifacts", "action": "artifact_sign", "automated": True},
                {"order": 6, "name": "Verify build provenance (SLSA)", "action": "slsa_verify", "automated": True},
                {"order": 7, "name": "Configure private package mirror", "action": "pkg_mirror", "automated": False},
                {"order": 8, "name": "Monitor for new CVEs continuously", "action": "cve_monitor", "automated": True},
            ],
            "downloads": 0,
            "rating": 0.0,
            "rating_count": 0,
            "org_id": None,
            "created_at": now,
            "updated_at": now,
        },
    ]


# ---------------------------------------------------------------------------
# Marketplace class
# ---------------------------------------------------------------------------


class PlaybookMarketplace:
    """
    SQLite-backed playbook marketplace.

    Supports publishing, browsing, installing, rating, exporting and importing
    playbook templates. Thread-safe via a reentrant lock.
    """

    def __init__(self, db_path: str = _DB_DEFAULT) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_builtins()

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS playbook_templates (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category    TEXT NOT NULL,
                    steps       TEXT NOT NULL,
                    author      TEXT NOT NULL DEFAULT 'community',
                    version     TEXT NOT NULL DEFAULT '1.0.0',
                    downloads   INTEGER NOT NULL DEFAULT 0,
                    rating      REAL NOT NULL DEFAULT 0.0,
                    rating_count INTEGER NOT NULL DEFAULT 0,
                    tags        TEXT NOT NULL DEFAULT '[]',
                    org_id      TEXT,
                    builtin     INTEGER NOT NULL DEFAULT 0,
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS installed_playbooks (
                    id            TEXT NOT NULL,
                    org_id        TEXT NOT NULL,
                    installed_at  TEXT NOT NULL,
                    PRIMARY KEY (id, org_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS playbook_ratings (
                    playbook_id TEXT NOT NULL,
                    rater_id    TEXT NOT NULL,
                    rating      REAL NOT NULL,
                    rated_at    TEXT NOT NULL,
                    PRIMARY KEY (playbook_id, rater_id)
                )
            """)
            conn.commit()

    def _seed_builtins(self) -> None:
        """Insert built-in templates only if they don't already exist."""
        with self._lock, self._connect() as conn:
            for tpl in _builtin_templates():
                existing = conn.execute(
                    "SELECT id FROM playbook_templates WHERE id = ?", (tpl["id"],)
                ).fetchone()
                if not existing:
                    conn.execute(
                        """
                        INSERT INTO playbook_templates
                            (id, name, description, category, steps, author, version,
                             downloads, rating, rating_count, tags, org_id,
                             builtin, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                        """,
                        (
                            tpl["id"], tpl["name"], tpl["description"],
                            tpl["category"], json.dumps(tpl["steps"]),
                            tpl["author"], tpl["version"],
                            tpl["downloads"], tpl["rating"], tpl["rating_count"],
                            json.dumps(tpl["tags"]), tpl.get("org_id"),
                            tpl["created_at"], tpl["updated_at"],
                        ),
                    )
            conn.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["steps"] = json.loads(d["steps"])
        d["tags"] = json.loads(d["tags"])
        d.pop("builtin", None)
        return d

    def _get_row(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM playbook_templates WHERE id = ?", (playbook_id,)
            ).fetchone()
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish_playbook(self, template: PlaybookTemplate) -> Dict[str, Any]:
        """Share a playbook template in the marketplace."""
        now = datetime.now(timezone.utc).isoformat()
        if not template.id:
            template.id = str(uuid.uuid4())
        template.created_at = template.created_at or now
        template.updated_at = now

        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM playbook_templates WHERE id = ?", (template.id,)
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE playbook_templates
                       SET name=?, description=?, category=?, steps=?,
                           author=?, version=?, tags=?, org_id=?, updated_at=?
                     WHERE id=?
                    """,
                    (
                        template.name, template.description,
                        template.category, json.dumps(template.steps),
                        template.author, template.version,
                        json.dumps(template.tags), template.org_id, now,
                        template.id,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO playbook_templates
                        (id, name, description, category, steps, author, version,
                         downloads, rating, rating_count, tags, org_id,
                         builtin, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0.0, 0, ?, ?, 0, ?, ?)
                    """,
                    (
                        template.id, template.name, template.description,
                        template.category, json.dumps(template.steps),
                        template.author, template.version,
                        json.dumps(template.tags), template.org_id,
                        template.created_at, now,
                    ),
                )
            conn.commit()

        return self._get_row(template.id)  # type: ignore[return-value]

    def list_playbooks(
        self,
        category: Optional[str] = None,
        search: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Browse marketplace playbooks with optional filtering."""
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM playbook_templates ORDER BY downloads DESC, name ASC").fetchall()

        results = [self._row_to_dict(r) for r in rows]

        if category:
            results = [r for r in results if r["category"] == category]

        if search:
            q = search.lower()
            results = [
                r for r in results
                if q in r["name"].lower() or q in r["description"].lower()
            ]

        if tags:
            results = [
                r for r in results
                if any(t in r["tags"] for t in tags)
            ]

        return results

    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Get full details of a playbook template."""
        return self._get_row(playbook_id)

    def install_playbook(self, playbook_id: str, org_id: str) -> Dict[str, Any]:
        """Install a playbook template into an organisation."""
        tpl = self._get_row(playbook_id)
        if not tpl:
            raise ValueError(f"Playbook not found: {playbook_id}")

        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO installed_playbooks (id, org_id, installed_at)
                VALUES (?, ?, ?)
                """,
                (playbook_id, org_id, now),
            )
            conn.execute(
                "UPDATE playbook_templates SET downloads = downloads + 1 WHERE id = ?",
                (playbook_id,),
            )
            conn.commit()

        return {"playbook_id": playbook_id, "org_id": org_id, "installed_at": now}

    def rate_playbook(self, playbook_id: str, rating: float, rater_id: str = "anonymous") -> Dict[str, Any]:
        """Submit or update a rating (1.0–5.0) for a playbook."""
        if not 1.0 <= rating <= 5.0:
            raise ValueError(f"Rating must be between 1.0 and 5.0, got {rating}")
        tpl = self._get_row(playbook_id)
        if not tpl:
            raise ValueError(f"Playbook not found: {playbook_id}")

        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO playbook_ratings (playbook_id, rater_id, rating, rated_at)
                VALUES (?, ?, ?, ?)
                """,
                (playbook_id, rater_id, rating, now),
            )
            # Recalculate average
            row = conn.execute(
                "SELECT AVG(rating) as avg_r, COUNT(*) as cnt FROM playbook_ratings WHERE playbook_id = ?",
                (playbook_id,),
            ).fetchone()
            avg_r = round(row["avg_r"], 2) if row["avg_r"] else rating
            cnt = row["cnt"]
            conn.execute(
                "UPDATE playbook_templates SET rating=?, rating_count=? WHERE id=?",
                (avg_r, cnt, playbook_id),
            )
            conn.commit()

        return {"playbook_id": playbook_id, "rating": avg_r, "rating_count": cnt}

    def get_installed(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all playbooks installed by an organisation."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT pt.*, ip.installed_at AS install_date
                  FROM playbook_templates pt
                  JOIN installed_playbooks ip ON pt.id = ip.id
                 WHERE ip.org_id = ?
                 ORDER BY ip.installed_at DESC
                """,
                (org_id,),
            ).fetchall()

        results = []
        for row in rows:
            d = dict(row)
            d["steps"] = json.loads(d["steps"])
            d["tags"] = json.loads(d["tags"])
            d.pop("builtin", None)
            results.append(d)
        return results

    def export_playbook(self, playbook_id: str) -> str:
        """Export a playbook template as a JSON string."""
        tpl = self._get_row(playbook_id)
        if not tpl:
            raise ValueError(f"Playbook not found: {playbook_id}")
        return json.dumps(tpl, indent=2)

    def import_playbook(self, json_data: str, org_id: Optional[str] = None) -> Dict[str, Any]:
        """Import a playbook template from a JSON string."""
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

        # Assign a new ID to avoid collision with existing templates
        data["id"] = str(uuid.uuid4())
        data["org_id"] = org_id
        data["downloads"] = 0
        data["rating"] = 0.0
        data["rating_count"] = 0

        try:
            template = PlaybookTemplate(**data)
        except Exception as exc:
            raise ValueError(f"Invalid playbook data: {exc}") from exc

        return self.publish_playbook(template)

    def get_popular(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the most-downloaded playbooks."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM playbook_templates ORDER BY downloads DESC, rating DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_marketplace_stats(self) -> Dict[str, Any]:
        """Return aggregate marketplace statistics."""
        with self._lock, self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM playbook_templates").fetchone()[0]
            total_installs = conn.execute("SELECT COUNT(*) FROM installed_playbooks").fetchone()[0]
            total_downloads = conn.execute(
                "SELECT COALESCE(SUM(downloads), 0) FROM playbook_templates"
            ).fetchone()[0]
            by_category_rows = conn.execute(
                "SELECT category, COUNT(*) as cnt FROM playbook_templates GROUP BY category"
            ).fetchall()
            top_rated_rows = conn.execute(
                """
                SELECT id, name, rating, downloads
                  FROM playbook_templates
                 WHERE rating_count > 0
                 ORDER BY rating DESC
                 LIMIT 5
                """
            ).fetchall()
            avg_rating_row = conn.execute(
                "SELECT AVG(rating) FROM playbook_templates WHERE rating > 0"
            ).fetchone()

        by_category = {row["category"]: row["cnt"] for row in by_category_rows}
        top_rated = [dict(r) for r in top_rated_rows]
        avg_rating = round(avg_rating_row[0], 2) if avg_rating_row[0] else 0.0

        return {
            "total_playbooks": total,
            "total_installs": total_installs,
            "total_downloads": total_downloads,
            "average_rating": avg_rating,
            "by_category": by_category,
            "top_rated": top_rated,
        }


__all__ = ["PlaybookCategory", "PlaybookTemplate", "PlaybookMarketplace"]
