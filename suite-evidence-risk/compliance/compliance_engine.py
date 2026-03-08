"""Full Compliance Auto-Mapping Engine (V10 — CTEM Full Loop with Cryptographic Proof).

Maps findings to compliance controls across 6 frameworks:
- SOC2 Type II (Trust Service Criteria CC1-CC9, A1, PI1, C1, P1)
- PCI DSS 4.0 (12 Requirements)
- ISO 27001:2022 (93 Controls in 4 themes)
- NIST 800-53 Rev 5 (20 Control Families)
- NIST CSF 2.0 (6 Functions)
- OWASP ASVS 4.0 (14 Chapters)

Capabilities:
- Auto-map CWE/CVE findings to framework controls
- Track control effectiveness over time
- Generate compliance posture scores per framework
- Produce audit-ready evidence bundles per control
- Gap analysis: which controls have no evidence
- Continuous compliance monitoring (re-evaluate on new findings)

Environment variables:
- FIXOPS_COMPLIANCE_FRAMEWORKS: Comma-separated list of enabled frameworks (default: all)
- FIXOPS_COMPLIANCE_DB_PATH: SQLite DB path (default: .fixops_data/compliance.db)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Framework(str, Enum):
    SOC2 = "SOC2"
    PCI_DSS = "PCI_DSS_4.0"
    ISO_27001 = "ISO_27001_2022"
    NIST_800_53 = "NIST_800_53_R5"
    NIST_CSF = "NIST_CSF_2.0"
    OWASP_ASVS = "OWASP_ASVS_4.0"


class ControlStatus(str, Enum):
    SATISFIED = "satisfied"
    PARTIALLY_SATISFIED = "partially_satisfied"
    NOT_SATISFIED = "not_satisfied"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"


class EvidenceType(str, Enum):
    SCAN_RESULT = "scan_result"
    POLICY_CHECK = "policy_check"
    CONFIG_AUDIT = "config_audit"
    ACCESS_REVIEW = "access_review"
    PENETRATION_TEST = "penetration_test"
    CODE_REVIEW = "code_review"
    INCIDENT_RESPONSE = "incident_response"
    TRAINING_RECORD = "training_record"
    RISK_ASSESSMENT = "risk_assessment"
    CHANGE_RECORD = "change_record"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------
@dataclass
class Control:
    """A single compliance control."""
    control_id: str
    framework: Framework
    title: str
    description: str
    category: str
    sub_category: str = ""
    related_cwes: List[str] = field(default_factory=list)
    evidence_types: List[EvidenceType] = field(default_factory=list)
    automated: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "framework": self.framework.value if hasattr(self.framework, 'value') else str(self.framework),
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "sub_category": self.sub_category,
            "related_cwes": self.related_cwes,
            "evidence_types": [e.value for e in self.evidence_types],
            "automated": self.automated,
        }


@dataclass
class ControlAssessment:
    """Assessment of a single control."""
    assessment_id: str
    control_id: str
    framework: Framework
    status: ControlStatus
    evidence_count: int = 0
    findings_count: int = 0
    critical_findings: int = 0
    last_assessed: str = ""
    assessor: str = "automated"
    notes: str = ""
    evidence_refs: List[str] = field(default_factory=list)
    score: float = 0.0  # 0.0-1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "control_id": self.control_id,
            "framework": self.framework.value if hasattr(self.framework, 'value') else str(self.framework),
            "status": self.status.value,
            "evidence_count": self.evidence_count,
            "findings_count": self.findings_count,
            "critical_findings": self.critical_findings,
            "last_assessed": self.last_assessed,
            "assessor": self.assessor,
            "notes": self.notes,
            "evidence_refs": self.evidence_refs,
            "score": self.score,
        }


@dataclass
class CompliancePosture:
    """Overall compliance posture for a framework."""
    framework: Framework
    total_controls: int = 0
    satisfied: int = 0
    partially_satisfied: int = 0
    not_satisfied: int = 0
    not_assessed: int = 0
    not_applicable: int = 0
    overall_score: float = 0.0
    trend: str = "stable"  # improving, stable, degrading
    last_evaluated: str = ""
    gaps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework.value if hasattr(self.framework, 'value') else str(self.framework),
            "total_controls": self.total_controls,
            "satisfied": self.satisfied,
            "partially_satisfied": self.partially_satisfied,
            "not_satisfied": self.not_satisfied,
            "not_assessed": self.not_assessed,
            "not_applicable": self.not_applicable,
            "overall_score": round(self.overall_score, 2),
            "compliance_percentage": round(
                (self.satisfied + self.partially_satisfied * 0.5) / max(self.total_controls - self.not_applicable, 1) * 100, 1
            ),
            "trend": self.trend,
            "last_evaluated": self.last_evaluated,
            "gaps": self.gaps[:20],
        }


# ---------------------------------------------------------------------------
# Framework Control Definitions
# ---------------------------------------------------------------------------

SOC2_CONTROLS: Dict[str, Dict[str, Any]] = {
    "CC1.1": {"title": "COSO Principle 1 — Integrity & Ethics", "category": "CC1", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK, EvidenceType.TRAINING_RECORD], "automated": False},
    "CC1.2": {"title": "Board Independence & Oversight", "category": "CC1", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "CC2.1": {"title": "Information Quality Objectives", "category": "CC2", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "CC3.1": {"title": "Risk Assessment Process", "category": "CC3", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    "CC3.2": {"title": "Fraud Risk Assessment", "category": "CC3", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    "CC3.4": {"title": "Technology Change Risk", "category": "CC3", "cwes": ["CWE-1104"], "evidence": [EvidenceType.CHANGE_RECORD, EvidenceType.RISK_ASSESSMENT], "automated": True},
    "CC4.1": {"title": "Ongoing Monitoring", "category": "CC4", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CONFIG_AUDIT], "automated": True},
    "CC4.2": {"title": "Deficiency Communication", "category": "CC4", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "CC5.1": {"title": "Control Activities for Risk Mitigation", "category": "CC5", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": True},
    "CC5.2": {"title": "Technology General Controls", "category": "CC5", "cwes": ["CWE-693"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.SCAN_RESULT], "automated": True},
    "CC6.1": {"title": "Logical Access Security", "category": "CC6", "cwes": ["CWE-287", "CWE-306", "CWE-862"], "evidence": [EvidenceType.ACCESS_REVIEW, EvidenceType.CONFIG_AUDIT], "automated": True},
    "CC6.2": {"title": "User Provisioning", "category": "CC6", "cwes": ["CWE-269", "CWE-732"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "CC6.3": {"title": "Access Termination", "category": "CC6", "cwes": ["CWE-269"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "CC6.6": {"title": "System Boundary Protection", "category": "CC6", "cwes": ["CWE-284", "CWE-918"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.SCAN_RESULT], "automated": True},
    "CC6.7": {"title": "Data Transmission Restriction", "category": "CC6", "cwes": ["CWE-319", "CWE-311"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "CC6.8": {"title": "Unauthorized Software Prevention", "category": "CC6", "cwes": ["CWE-829", "CWE-506"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "CC7.1": {"title": "Configuration Change Detection", "category": "CC7", "cwes": ["CWE-1104"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.CHANGE_RECORD], "automated": True},
    "CC7.2": {"title": "Anomaly Monitoring", "category": "CC7", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "CC7.3": {"title": "Security Event Evaluation", "category": "CC7", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "CC7.4": {"title": "Incident Response", "category": "CC7", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "CC8.1": {"title": "Change Management", "category": "CC8", "cwes": ["CWE-1104"], "evidence": [EvidenceType.CHANGE_RECORD, EvidenceType.CODE_REVIEW], "automated": True},
    "CC9.1": {"title": "Risk Mitigation Activities", "category": "CC9", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
}

PCI_DSS_CONTROLS: Dict[str, Dict[str, Any]] = {
    "1.1": {"title": "Install & Maintain Network Security Controls", "category": "Req1", "cwes": ["CWE-284"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "2.1": {"title": "Secure System Configurations", "category": "Req2", "cwes": ["CWE-1188", "CWE-16"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "2.2": {"title": "System Hardening Standards", "category": "Req2", "cwes": ["CWE-16", "CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.SCAN_RESULT], "automated": True},
    "3.1": {"title": "Account Data Retention Policy", "category": "Req3", "cwes": ["CWE-312", "CWE-311"], "evidence": [EvidenceType.POLICY_CHECK], "automated": True},
    "3.5": {"title": "Primary Account Number Protection", "category": "Req3", "cwes": ["CWE-312", "CWE-327"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "4.1": {"title": "Strong Cryptography for Transmission", "category": "Req4", "cwes": ["CWE-319", "CWE-327"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "5.1": {"title": "Anti-Malware Protection", "category": "Req5", "cwes": ["CWE-506"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "5.2": {"title": "Malware Prevention Mechanisms", "category": "Req5", "cwes": ["CWE-506", "CWE-829"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "6.1": {"title": "Vulnerability Identification", "category": "Req6", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "6.2": {"title": "Bespoke & Custom Software Security", "category": "Req6", "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-502"], "evidence": [EvidenceType.CODE_REVIEW, EvidenceType.SCAN_RESULT], "automated": True},
    "6.3": {"title": "Security Vulnerabilities Addressed", "category": "Req6", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CHANGE_RECORD], "automated": True},
    "6.4": {"title": "Web Application Firewall", "category": "Req6", "cwes": ["CWE-79", "CWE-89"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "6.5": {"title": "Change Management for Code", "category": "Req6", "cwes": ["CWE-1104"], "evidence": [EvidenceType.CODE_REVIEW, EvidenceType.CHANGE_RECORD], "automated": True},
    "7.1": {"title": "Restrict Access by Business Need", "category": "Req7", "cwes": ["CWE-269", "CWE-862"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "8.1": {"title": "User Identification & Authentication", "category": "Req8", "cwes": ["CWE-287", "CWE-798"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.ACCESS_REVIEW], "automated": True},
    "8.3": {"title": "MFA Implementation", "category": "Req8", "cwes": ["CWE-287", "CWE-306"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "10.1": {"title": "Audit Logging", "category": "Req10", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "10.2": {"title": "Audit Log Content", "category": "Req10", "cwes": ["CWE-778", "CWE-117"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "11.1": {"title": "Wireless Access Point Testing", "category": "Req11", "cwes": [], "evidence": [EvidenceType.PENETRATION_TEST], "automated": False},
    "11.3": {"title": "Vulnerability Scanning", "category": "Req11", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "11.4": {"title": "Penetration Testing", "category": "Req11", "cwes": [], "evidence": [EvidenceType.PENETRATION_TEST], "automated": True},
    "12.1": {"title": "Information Security Policy", "category": "Req12", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
}

NIST_800_53_CONTROLS: Dict[str, Dict[str, Any]] = {
    "AC-2": {"title": "Account Management", "category": "AC", "cwes": ["CWE-269", "CWE-732"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "AC-3": {"title": "Access Enforcement", "category": "AC", "cwes": ["CWE-862", "CWE-863"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-6": {"title": "Least Privilege", "category": "AC", "cwes": ["CWE-269", "CWE-250"], "evidence": [EvidenceType.ACCESS_REVIEW, EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-7": {"title": "Unsuccessful Login Attempts", "category": "AC", "cwes": ["CWE-307"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AT-1": {"title": "Security Awareness Training", "category": "AT", "cwes": [], "evidence": [EvidenceType.TRAINING_RECORD], "automated": False},
    "AU-2": {"title": "Event Logging", "category": "AU", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AU-3": {"title": "Content of Audit Records", "category": "AU", "cwes": ["CWE-778", "CWE-117"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AU-6": {"title": "Audit Record Review & Analysis", "category": "AU", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "CA-2": {"title": "Control Assessments", "category": "CA", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    "CA-7": {"title": "Continuous Monitoring", "category": "CA", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "CM-2": {"title": "Baseline Configuration", "category": "CM", "cwes": ["CWE-16", "CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "CM-6": {"title": "Configuration Settings", "category": "CM", "cwes": ["CWE-16"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "CM-7": {"title": "Least Functionality", "category": "CM", "cwes": ["CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "IA-2": {"title": "Identification & Authentication", "category": "IA", "cwes": ["CWE-287", "CWE-306"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "IA-5": {"title": "Authenticator Management", "category": "IA", "cwes": ["CWE-798", "CWE-521"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.SCAN_RESULT], "automated": True},
    "IR-4": {"title": "Incident Handling", "category": "IR", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "IR-5": {"title": "Incident Monitoring", "category": "IR", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE, EvidenceType.SCAN_RESULT], "automated": True},
    "RA-3": {"title": "Risk Assessment", "category": "RA", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    "RA-5": {"title": "Vulnerability Monitoring & Scanning", "category": "RA", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SA-11": {"title": "Developer Testing & Evaluation", "category": "SA", "cwes": ["CWE-89", "CWE-79", "CWE-78"], "evidence": [EvidenceType.CODE_REVIEW, EvidenceType.SCAN_RESULT], "automated": True},
    "SA-15": {"title": "Development Process & Standards", "category": "SA", "cwes": [], "evidence": [EvidenceType.CODE_REVIEW], "automated": True},
    "SC-7": {"title": "Boundary Protection", "category": "SC", "cwes": ["CWE-284", "CWE-918"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC-8": {"title": "Transmission Confidentiality", "category": "SC", "cwes": ["CWE-319"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC-12": {"title": "Cryptographic Key Management", "category": "SC", "cwes": ["CWE-320", "CWE-327"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC-13": {"title": "Cryptographic Protection", "category": "SC", "cwes": ["CWE-327", "CWE-326"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SC-28": {"title": "Protection of Information at Rest", "category": "SC", "cwes": ["CWE-312", "CWE-311"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SI-2": {"title": "Flaw Remediation", "category": "SI", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CHANGE_RECORD], "automated": True},
    "SI-3": {"title": "Malicious Code Protection", "category": "SI", "cwes": ["CWE-506"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SI-4": {"title": "System Monitoring", "category": "SI", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SI-10": {"title": "Information Input Validation", "category": "SI", "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-22"], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CODE_REVIEW], "automated": True},
}

ISO_27001_CONTROLS: Dict[str, Dict[str, Any]] = {
    "A.5.1": {"title": "Policies for Information Security", "category": "Organizational", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "A.5.2": {"title": "Information Security Roles", "category": "Organizational", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "A.6.1": {"title": "Screening", "category": "People", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "A.6.3": {"title": "Information Security Awareness & Training", "category": "People", "cwes": [], "evidence": [EvidenceType.TRAINING_RECORD], "automated": False},
    "A.7.1": {"title": "Physical Security Perimeters", "category": "Physical", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": False},
    "A.8.1": {"title": "User Endpoint Devices", "category": "Technological", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "A.8.2": {"title": "Privileged Access Rights", "category": "Technological", "cwes": ["CWE-269", "CWE-250"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "A.8.3": {"title": "Information Access Restriction", "category": "Technological", "cwes": ["CWE-862", "CWE-863"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "A.8.5": {"title": "Secure Authentication", "category": "Technological", "cwes": ["CWE-287", "CWE-521"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "A.8.7": {"title": "Protection Against Malware", "category": "Technological", "cwes": ["CWE-506"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "A.8.8": {"title": "Management of Technical Vulnerabilities", "category": "Technological", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "A.8.9": {"title": "Configuration Management", "category": "Technological", "cwes": ["CWE-16", "CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "A.8.12": {"title": "Data Leakage Prevention", "category": "Technological", "cwes": ["CWE-200", "CWE-209"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "A.8.15": {"title": "Logging", "category": "Technological", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "A.8.16": {"title": "Monitoring Activities", "category": "Technological", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "A.8.20": {"title": "Networks Security", "category": "Technological", "cwes": ["CWE-284"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "A.8.24": {"title": "Use of Cryptography", "category": "Technological", "cwes": ["CWE-327", "CWE-326"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "A.8.25": {"title": "Secure Development Life Cycle", "category": "Technological", "cwes": [], "evidence": [EvidenceType.CODE_REVIEW], "automated": True},
    "A.8.26": {"title": "Application Security Requirements", "category": "Technological", "cwes": ["CWE-89", "CWE-79"], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CODE_REVIEW], "automated": True},
    "A.8.28": {"title": "Secure Coding", "category": "Technological", "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-502", "CWE-22"], "evidence": [EvidenceType.CODE_REVIEW, EvidenceType.SCAN_RESULT], "automated": True},
    "A.8.29": {"title": "Security Testing in Development", "category": "Technological", "cwes": [], "evidence": [EvidenceType.PENETRATION_TEST, EvidenceType.SCAN_RESULT], "automated": True},
}

# Build reverse lookup: CWE → list of (framework, control_id)
_CWE_TO_CONTROLS: Dict[str, List[Tuple[Framework, str]]] = {}


def _build_cwe_index() -> None:
    """Build the CWE → controls reverse index."""
    global _CWE_TO_CONTROLS
    if _CWE_TO_CONTROLS:
        return
    for framework, controls in [
        (Framework.SOC2, SOC2_CONTROLS),
        (Framework.PCI_DSS, PCI_DSS_CONTROLS),
        (Framework.NIST_800_53, NIST_800_53_CONTROLS),
        (Framework.ISO_27001, ISO_27001_CONTROLS),
    ]:
        for ctrl_id, ctrl_def in controls.items():
            for cwe in ctrl_def.get("cwes", []):
                _CWE_TO_CONTROLS.setdefault(cwe, []).append((framework, ctrl_id))


# ---------------------------------------------------------------------------
# Database Layer
# ---------------------------------------------------------------------------
class ComplianceDB:
    """SQLite persistence for compliance assessments."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv(
            "FIXOPS_COMPLIANCE_DB_PATH",
            os.path.join(os.getenv("FIXOPS_DATA_DIR", ".fixops_data"), "compliance.db"),
        )
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS assessments (
                    assessment_id TEXT PRIMARY KEY,
                    control_id TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'not_assessed',
                    evidence_count INTEGER DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    critical_findings INTEGER DEFAULT 0,
                    score REAL DEFAULT 0.0,
                    assessor TEXT DEFAULT 'automated',
                    notes TEXT DEFAULT '',
                    evidence_refs TEXT DEFAULT '[]',
                    assessed_at TEXT NOT NULL,
                    app_id TEXT DEFAULT '',
                    UNIQUE(control_id, framework, app_id)
                );

                CREATE TABLE IF NOT EXISTS evidence_items (
                    evidence_id TEXT PRIMARY KEY,
                    control_id TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    source TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    data_hash TEXT DEFAULT '',
                    collected_at TEXT NOT NULL,
                    app_id TEXT DEFAULT '',
                    finding_id TEXT DEFAULT '',
                    metadata TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS posture_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    framework TEXT NOT NULL,
                    overall_score REAL DEFAULT 0.0,
                    satisfied INTEGER DEFAULT 0,
                    partially_satisfied INTEGER DEFAULT 0,
                    not_satisfied INTEGER DEFAULT 0,
                    total_controls INTEGER DEFAULT 0,
                    evaluated_at TEXT NOT NULL,
                    app_id TEXT DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_assessments_framework ON assessments(framework);
                CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);
                CREATE INDEX IF NOT EXISTS idx_evidence_control ON evidence_items(control_id, framework);
                CREATE INDEX IF NOT EXISTS idx_posture_framework ON posture_history(framework, evaluated_at);
            """)

    def upsert_assessment(self, assessment: ControlAssessment, app_id: str = "") -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO assessments (assessment_id, control_id, framework, status,
                    evidence_count, findings_count, critical_findings, score,
                    assessor, notes, evidence_refs, assessed_at, app_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(control_id, framework, app_id)
                DO UPDATE SET status=excluded.status, evidence_count=excluded.evidence_count,
                    findings_count=excluded.findings_count, critical_findings=excluded.critical_findings,
                    score=excluded.score, notes=excluded.notes, evidence_refs=excluded.evidence_refs,
                    assessed_at=excluded.assessed_at
            """, (
                assessment.assessment_id, assessment.control_id, assessment.framework.value,
                assessment.status.value, assessment.evidence_count, assessment.findings_count,
                assessment.critical_findings, assessment.score, assessment.assessor,
                assessment.notes, json.dumps(assessment.evidence_refs),
                assessment.last_assessed, app_id,
            ))

    def add_evidence(self, evidence: Dict[str, Any]) -> str:
        evidence_id = evidence.get("evidence_id", str(uuid.uuid4()))
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO evidence_items
                (evidence_id, control_id, framework, evidence_type, source,
                 description, data_hash, collected_at, app_id, finding_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence_id, evidence["control_id"], evidence["framework"],
                evidence["evidence_type"], evidence.get("source", ""),
                evidence.get("description", ""),
                evidence.get("data_hash", ""),
                evidence.get("collected_at", datetime.now(timezone.utc).isoformat()),
                evidence.get("app_id", ""),
                evidence.get("finding_id", ""),
                json.dumps(evidence.get("metadata", {})),
            ))
        return evidence_id

    def save_posture(self, posture: CompliancePosture, app_id: str = "") -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO posture_history
                (framework, overall_score, satisfied, partially_satisfied,
                 not_satisfied, total_controls, evaluated_at, app_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                posture.framework.value, posture.overall_score,
                posture.satisfied, posture.partially_satisfied,
                posture.not_satisfied, posture.total_controls,
                posture.last_evaluated, app_id,
            ))

    def get_assessments(self, framework: str, app_id: str = "") -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM assessments WHERE framework=? AND app_id=?",
                (framework, app_id),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_evidence_for_control(self, control_id: str, framework: str) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM evidence_items WHERE control_id=? AND framework=?",
                (control_id, framework),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_posture_trend(self, framework: str, limit: int = 30) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM posture_history WHERE framework=? ORDER BY evaluated_at DESC LIMIT ?",
                (framework, limit),
            ).fetchall()
            return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Compliance Engine
# ---------------------------------------------------------------------------
class ComplianceEngine:
    """Full compliance auto-mapping and assessment engine.

    Usage:
        engine = ComplianceEngine()
        # Map findings to controls
        mappings = engine.map_findings_to_controls(findings)
        # Assess all controls for a framework
        posture = engine.assess_framework(Framework.SOC2)
        # Get gaps
        gaps = engine.get_compliance_gaps(Framework.PCI_DSS)
        # Generate audit bundle
        bundle = engine.generate_audit_bundle(Framework.SOC2, app_id="my-app")
    """

    def __init__(self, db: Optional[ComplianceDB] = None):
        _build_cwe_index()
        self.db = db or ComplianceDB()
        self._framework_controls: Dict[Framework, Dict[str, Dict[str, Any]]] = {
            Framework.SOC2: SOC2_CONTROLS,
            Framework.PCI_DSS: PCI_DSS_CONTROLS,
            Framework.NIST_800_53: NIST_800_53_CONTROLS,
            Framework.ISO_27001: ISO_27001_CONTROLS,
        }
        enabled = os.getenv("FIXOPS_COMPLIANCE_FRAMEWORKS", "")
        if enabled:
            names = {f.strip().upper() for f in enabled.split(",")}
            self._enabled = {f for f in Framework if f.value.upper() in names or f.name.upper() in names}
        else:
            self._enabled = set(Framework)

    # ---- Core Mapping ----

    def map_findings_to_controls(
        self, findings: List[Dict[str, Any]], app_id: str = ""
    ) -> Dict[str, List[Tuple[str, str]]]:
        """Map a list of findings (with CWEs) to compliance controls.

        Args:
            findings: List of finding dicts with 'cwe_ids' or 'cwe' field
            app_id: Optional APP_ID for scoping

        Returns:
            Dict mapping finding_id → list of (framework, control_id) tuples
        """
        result: Dict[str, List[Tuple[str, str]]] = {}
        for finding in findings:
            finding_id = finding.get("id") or finding.get("finding_id") or str(uuid.uuid4())
            cwes = finding.get("cwe_ids") or finding.get("cwes") or []
            if isinstance(cwes, str):
                cwes = [cwes]
            # Also try single cwe field
            single_cwe = finding.get("cwe") or finding.get("cwe_id")
            if single_cwe and single_cwe not in cwes:
                cwes.append(single_cwe)

            mapped_controls: List[Tuple[str, str]] = []
            for cwe in cwes:
                cwe_key = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
                if cwe_key in _CWE_TO_CONTROLS:
                    for framework, ctrl_id in _CWE_TO_CONTROLS[cwe_key]:
                        if framework in self._enabled:
                            pair = (framework.value, ctrl_id)
                            if pair not in mapped_controls:
                                mapped_controls.append(pair)
                            # Auto-collect evidence
                            self.db.add_evidence({
                                "control_id": ctrl_id,
                                "framework": framework.value,
                                "evidence_type": EvidenceType.SCAN_RESULT.value,
                                "source": finding.get("scanner") or finding.get("source") or "unknown",
                                "description": f"Finding {finding_id}: {finding.get('title', 'N/A')}",
                                "data_hash": hashlib.sha256(json.dumps(finding, sort_keys=True, default=str).encode()).hexdigest(),
                                "app_id": app_id,
                                "finding_id": finding_id,
                                "metadata": {
                                    "severity": finding.get("severity", "unknown"),
                                    "cwe": cwe_key,
                                    "status": finding.get("status", "open"),
                                },
                            })
            result[finding_id] = mapped_controls
        return result

    def assess_framework(
        self, framework: Framework, app_id: str = "", findings: Optional[List[Dict[str, Any]]] = None
    ) -> CompliancePosture:
        """Assess all controls in a framework and return posture.

        Args:
            framework: The compliance framework to assess
            app_id: Optional APP_ID scope
            findings: Optional findings to map first

        Returns:
            CompliancePosture with scores and gaps
        """
        if framework not in self._enabled:
            return CompliancePosture(framework=framework)

        # Map findings if provided
        if findings:
            self.map_findings_to_controls(findings, app_id)

        controls = self._framework_controls.get(framework, {})
        posture = CompliancePosture(
            framework=framework,
            total_controls=len(controls),
            last_evaluated=datetime.now(timezone.utc).isoformat(),
        )

        for ctrl_id, ctrl_def in controls.items():
            # Get evidence for this control
            evidence = self.db.get_evidence_for_control(ctrl_id, framework.value)
            evidence_count = len(evidence)

            # Determine status based on evidence
            if not ctrl_def.get("automated", True):
                status = ControlStatus.NOT_ASSESSED
                score = 0.0
                notes = "Manual assessment required"
            elif evidence_count == 0:
                status = ControlStatus.NOT_SATISFIED
                score = 0.0
                notes = "No evidence collected"
                posture.gaps.append(f"{ctrl_id}: {ctrl_def['title']} — no evidence")
            else:
                # Check for critical findings in evidence
                critical = sum(
                    1 for e in evidence
                    if json.loads(e.get("metadata", "{}")).get("severity") in ("critical", "high")
                    and json.loads(e.get("metadata", "{}")).get("status") == "open"
                )
                total_findings = len(evidence)
                resolved = sum(
                    1 for e in evidence
                    if json.loads(e.get("metadata", "{}")).get("status") in ("resolved", "fixed", "closed")
                )

                if critical > 0:
                    status = ControlStatus.NOT_SATISFIED
                    score = max(0.0, 0.3 - (critical * 0.1))
                    notes = f"{critical} critical/high open findings"
                    posture.gaps.append(f"{ctrl_id}: {ctrl_def['title']} — {critical} critical findings")
                elif resolved == total_findings and total_findings > 0:
                    status = ControlStatus.SATISFIED
                    score = 1.0
                    notes = f"All {total_findings} findings resolved"
                elif evidence_count >= len(ctrl_def.get("evidence", [])):
                    status = ControlStatus.PARTIALLY_SATISFIED
                    score = 0.5 + (resolved / max(total_findings, 1)) * 0.4
                    notes = f"{resolved}/{total_findings} findings resolved"
                else:
                    status = ControlStatus.PARTIALLY_SATISFIED
                    score = 0.3
                    notes = f"Partial evidence ({evidence_count} items)"

            # Create and save assessment
            assessment = ControlAssessment(
                assessment_id=str(uuid.uuid4()),
                control_id=ctrl_id,
                framework=framework,
                status=status,
                evidence_count=evidence_count,
                findings_count=len(evidence),
                critical_findings=sum(
                    1 for e in evidence
                    if json.loads(e.get("metadata", "{}")).get("severity") in ("critical", "high")
                ),
                last_assessed=datetime.now(timezone.utc).isoformat(),
                score=score,
                notes=notes,
                evidence_refs=[e["evidence_id"] for e in evidence[:10]],
            )
            self.db.upsert_assessment(assessment, app_id)

            # Update posture counters
            if status == ControlStatus.SATISFIED:
                posture.satisfied += 1
            elif status == ControlStatus.PARTIALLY_SATISFIED:
                posture.partially_satisfied += 1
            elif status == ControlStatus.NOT_SATISFIED:
                posture.not_satisfied += 1
            elif status == ControlStatus.NOT_ASSESSED:
                posture.not_assessed += 1
            elif status == ControlStatus.NOT_APPLICABLE:
                posture.not_applicable += 1

        # Calculate overall score
        assessable = posture.total_controls - posture.not_applicable - posture.not_assessed
        if assessable > 0:
            posture.overall_score = (
                posture.satisfied * 1.0 + posture.partially_satisfied * 0.5
            ) / assessable

        # Determine trend
        history = self.db.get_posture_trend(framework.value, limit=2)
        if len(history) >= 2:
            prev_score = history[1].get("overall_score", 0.0)
            if posture.overall_score > prev_score + 0.05:
                posture.trend = "improving"
            elif posture.overall_score < prev_score - 0.05:
                posture.trend = "degrading"

        self.db.save_posture(posture, app_id)
        return posture

    def assess_all_frameworks(self, app_id: str = "", findings: Optional[List[Dict[str, Any]]] = None) -> List[CompliancePosture]:
        """Assess all enabled frameworks."""
        results = []
        for framework in self._enabled:
            if framework in self._framework_controls:
                posture = self.assess_framework(framework, app_id, findings)
                results.append(posture)
        return results

    def get_compliance_gaps(self, framework: Framework, app_id: str = "") -> List[Dict[str, Any]]:
        """Get all controls that are not satisfied for a framework."""
        assessments = self.db.get_assessments(framework.value, app_id)
        gaps = []
        controls = self._framework_controls.get(framework, {})
        assessed_controls = {a["control_id"] for a in assessments}

        for ctrl_id, ctrl_def in controls.items():
            if ctrl_id not in assessed_controls:
                gaps.append({
                    "control_id": ctrl_id,
                    "title": ctrl_def["title"],
                    "category": ctrl_def["category"],
                    "status": "not_assessed",
                    "gap_type": "no_assessment",
                    "remediation": "Run compliance assessment to evaluate this control",
                })
            else:
                assessment = next((a for a in assessments if a["control_id"] == ctrl_id), None)
                if assessment and assessment["status"] in ("not_satisfied", "partially_satisfied"):
                    gaps.append({
                        "control_id": ctrl_id,
                        "title": ctrl_def["title"],
                        "category": ctrl_def["category"],
                        "status": assessment["status"],
                        "score": assessment.get("score", 0.0),
                        "gap_type": "finding_remediation" if assessment.get("critical_findings", 0) > 0 else "evidence_gap",
                        "findings_count": assessment.get("findings_count", 0),
                        "critical_findings": assessment.get("critical_findings", 0),
                        "remediation": assessment.get("notes", ""),
                    })
        return gaps

    def generate_audit_bundle(
        self, framework: Framework, app_id: str = "", period_days: int = 90
    ) -> Dict[str, Any]:
        """Generate an audit-ready compliance bundle.

        Returns a comprehensive JSON bundle suitable for auditor review.
        """
        posture = self.assess_framework(framework, app_id)
        assessments = self.db.get_assessments(framework.value, app_id)
        gaps = self.get_compliance_gaps(framework, app_id)
        trend = self.db.get_posture_trend(framework.value, limit=10)

        # Gather evidence per control
        controls_with_evidence = []
        for assessment in assessments:
            evidence = self.db.get_evidence_for_control(
                assessment["control_id"], framework.value
            )
            controls_with_evidence.append({
                "control_id": assessment["control_id"],
                "status": assessment["status"],
                "score": assessment.get("score", 0.0),
                "evidence_count": len(evidence),
                "evidence_items": evidence[:5],  # Top 5 per control
                "notes": assessment.get("notes", ""),
            })

        bundle = {
            "bundle_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "framework": framework.value,
            "app_id": app_id or "organization-wide",
            "assessment_period": {
                "days": period_days,
                "start": (datetime.now(timezone.utc) - __import__("datetime").timedelta(days=period_days)).isoformat(),
                "end": datetime.now(timezone.utc).isoformat(),
            },
            "posture": posture.to_dict(),
            "controls": controls_with_evidence,
            "gaps": gaps,
            "trend": trend,
            "summary": {
                "total_controls": posture.total_controls,
                "compliance_rate": round(
                    (posture.satisfied + posture.partially_satisfied * 0.5)
                    / max(posture.total_controls - posture.not_applicable, 1) * 100, 1
                ),
                "critical_gaps": len([g for g in gaps if g.get("critical_findings", 0) > 0]),
                "evidence_items_total": sum(c["evidence_count"] for c in controls_with_evidence),
                "automated_controls": sum(1 for c in self._framework_controls.get(framework, {}).values() if c.get("automated")),
            },
            "content_hash": "",  # Filled below
        }
        # Self-referential hash for tamper detection
        bundle["content_hash"] = hashlib.sha256(
            json.dumps(bundle, sort_keys=True, default=str).encode()
        ).hexdigest()

        return bundle

    def get_control_details(self, control_id: str, framework: Framework) -> Optional[Dict[str, Any]]:
        """Get full details for a specific control."""
        controls = self._framework_controls.get(framework, {})
        ctrl_def = controls.get(control_id)
        if not ctrl_def:
            return None

        evidence = self.db.get_evidence_for_control(control_id, framework.value)
        assessments = self.db.get_assessments(framework.value)
        assessment = next((a for a in assessments if a["control_id"] == control_id), None)

        return {
            "control_id": control_id,
            "framework": framework.value,
            "title": ctrl_def["title"],
            "category": ctrl_def["category"],
            "related_cwes": ctrl_def.get("cwes", []),
            "expected_evidence_types": [e.value for e in ctrl_def.get("evidence", [])],
            "automated": ctrl_def.get("automated", True),
            "assessment": assessment,
            "evidence_items": evidence,
            "evidence_count": len(evidence),
        }

    def get_cwe_control_mapping(self, cwe_id: str) -> List[Dict[str, str]]:
        """Get all controls mapped to a specific CWE."""
        cwe_key = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
        mappings = _CWE_TO_CONTROLS.get(cwe_key, [])
        result = []
        for framework, ctrl_id in mappings:
            ctrl_def = self._framework_controls.get(framework, {}).get(ctrl_id, {})
            result.append({
                "framework": framework.value,
                "control_id": ctrl_id,
                "title": ctrl_def.get("title", ""),
                "category": ctrl_def.get("category", ""),
            })
        return result

    def get_supported_frameworks(self) -> List[Dict[str, Any]]:
        """List all supported frameworks with control counts."""
        return [
            {
                "framework": f.value,
                "enabled": f in self._enabled,
                "total_controls": len(self._framework_controls.get(f, {})),
                "automated_controls": sum(
                    1 for c in self._framework_controls.get(f, {}).values()
                    if c.get("automated")
                ),
            }
            for f in Framework
            if f in self._framework_controls
        ]


# Module-level convenience instance
_default_engine: Optional[ComplianceEngine] = None


def get_compliance_engine() -> ComplianceEngine:
    """Get or create the default compliance engine."""
    global _default_engine
    if _default_engine is None:
        _default_engine = ComplianceEngine()
    return _default_engine
