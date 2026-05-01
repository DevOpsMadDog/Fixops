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
from datetime import datetime, timedelta, timezone
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
    CMMC_V2 = "CMMC_V2"
    FEDRAMP = "FedRAMP"
    HIPAA = "HIPAA"
    DFARS = "DFARS_252.204-7012"


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

# ---------------------------------------------------------------------------
# CMMC V2 Level 2 Controls (NIST SP 800-171 mapped practices)
# 14 domains, 110 practices — Level 2 subset (required for CUI handling)
# ---------------------------------------------------------------------------
CMMC_V2_CONTROLS: Dict[str, Dict[str, Any]] = {
    # AC — Access Control
    "AC.L2-3.1.1": {"title": "Authorized Access Control", "category": "AC", "cwes": ["CWE-862", "CWE-863"], "evidence": [EvidenceType.ACCESS_REVIEW, EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC.L2-3.1.2": {"title": "Transaction & Function Control", "category": "AC", "cwes": ["CWE-862"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC.L2-3.1.3": {"title": "CUI Flow Enforcement", "category": "AC", "cwes": ["CWE-284"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC.L2-3.1.5": {"title": "Least Privilege", "category": "AC", "cwes": ["CWE-269", "CWE-250"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "AC.L2-3.1.7": {"title": "Privileged Functions", "category": "AC", "cwes": ["CWE-269"], "evidence": [EvidenceType.ACCESS_REVIEW, EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC.L2-3.1.8": {"title": "Unsuccessful Logon Attempts", "category": "AC", "cwes": ["CWE-307"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC.L2-3.1.12": {"title": "Remote Access Control", "category": "AC", "cwes": ["CWE-284"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC.L2-3.1.13": {"title": "Remote Access Confidentiality", "category": "AC", "cwes": ["CWE-319"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC.L2-3.1.14": {"title": "Remote Access Routing", "category": "AC", "cwes": ["CWE-284"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC.L2-3.1.20": {"title": "External System Connections", "category": "AC", "cwes": ["CWE-918"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # AT — Awareness & Training
    "AT.L2-3.2.1": {"title": "Role-Based Risk Awareness", "category": "AT", "cwes": [], "evidence": [EvidenceType.TRAINING_RECORD], "automated": False},
    "AT.L2-3.2.2": {"title": "Insider Threat Awareness", "category": "AT", "cwes": [], "evidence": [EvidenceType.TRAINING_RECORD], "automated": False},
    # AU — Audit & Accountability
    "AU.L2-3.3.1": {"title": "System Auditing", "category": "AU", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AU.L2-3.3.2": {"title": "User Accountability", "category": "AU", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AU.L2-3.3.4": {"title": "Audit Failure Alerting", "category": "AU", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AU.L2-3.3.5": {"title": "Audit Record Correlation", "category": "AU", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "AU.L2-3.3.8": {"title": "Audit Protection", "category": "AU", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # CM — Configuration Management
    "CM.L2-3.4.1": {"title": "System Baselining", "category": "CM", "cwes": ["CWE-16", "CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "CM.L2-3.4.2": {"title": "Security Configuration Enforcement", "category": "CM", "cwes": ["CWE-16"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "CM.L2-3.4.5": {"title": "Access Restrictions for Change", "category": "CM", "cwes": ["CWE-1104"], "evidence": [EvidenceType.CHANGE_RECORD], "automated": True},
    "CM.L2-3.4.6": {"title": "Least Functionality", "category": "CM", "cwes": ["CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # IA — Identification & Authentication
    "IA.L2-3.5.1": {"title": "Identification", "category": "IA", "cwes": ["CWE-287"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "IA.L2-3.5.2": {"title": "Authentication", "category": "IA", "cwes": ["CWE-287", "CWE-306"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "IA.L2-3.5.3": {"title": "Multi-Factor Authentication", "category": "IA", "cwes": ["CWE-287", "CWE-306"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "IA.L2-3.5.7": {"title": "Password Complexity", "category": "IA", "cwes": ["CWE-521"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "IA.L2-3.5.10": {"title": "Cryptographic Authentication", "category": "IA", "cwes": ["CWE-327", "CWE-798"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # IR — Incident Response
    "IR.L2-3.6.1": {"title": "Incident Handling", "category": "IR", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "IR.L2-3.6.2": {"title": "Incident Reporting", "category": "IR", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    # MA — Maintenance
    "MA.L2-3.7.5": {"title": "Nonlocal Maintenance", "category": "MA", "cwes": ["CWE-284"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # MP — Media Protection
    "MP.L2-3.8.1": {"title": "Media Protection", "category": "MP", "cwes": ["CWE-312"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "MP.L2-3.8.3": {"title": "Media Sanitization", "category": "MP", "cwes": ["CWE-312"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": False},
    # PE — Physical Protection
    "PE.L2-3.10.1": {"title": "Physical Access Limitation", "category": "PE", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": False},
    # PS — Personnel Security
    "PS.L2-3.9.2": {"title": "Personnel Actions During Transfer/Termination", "category": "PS", "cwes": ["CWE-269"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    # RA — Risk Assessment
    "RA.L2-3.11.1": {"title": "Risk Assessments", "category": "RA", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    "RA.L2-3.11.2": {"title": "Vulnerability Scanning", "category": "RA", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "RA.L2-3.11.3": {"title": "Vulnerability Remediation", "category": "RA", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CHANGE_RECORD], "automated": True},
    # SC — System & Communications Protection
    "SC.L2-3.13.1": {"title": "Boundary Protection", "category": "SC", "cwes": ["CWE-284", "CWE-918"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC.L2-3.13.2": {"title": "Security Engineering", "category": "SC", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC.L2-3.13.5": {"title": "Public Access System Separation", "category": "SC", "cwes": ["CWE-284"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC.L2-3.13.8": {"title": "CUI Transmission Cryptography", "category": "SC", "cwes": ["CWE-319", "CWE-327"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC.L2-3.13.11": {"title": "CUI Encryption at Rest", "category": "SC", "cwes": ["CWE-312", "CWE-311"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC.L2-3.13.16": {"title": "Data at Rest Protection", "category": "SC", "cwes": ["CWE-312"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # SI — System & Information Integrity
    "SI.L2-3.14.1": {"title": "Flaw Remediation", "category": "SI", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CHANGE_RECORD], "automated": True},
    "SI.L2-3.14.2": {"title": "Malicious Code Protection", "category": "SI", "cwes": ["CWE-506"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SI.L2-3.14.3": {"title": "Security Alerts & Advisories", "category": "SI", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SI.L2-3.14.6": {"title": "System Monitoring — Attacks", "category": "SI", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SI.L2-3.14.7": {"title": "System Monitoring — Unauthorized Use", "category": "SI", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
}

# ---------------------------------------------------------------------------
# FedRAMP Controls (NIST 800-53 Moderate baseline — 325 controls, key subset)
# FedRAMP extends NIST 800-53 with additional FedRAMP-specific requirements.
# Core subset covers the most automated/scanned control families.
# ---------------------------------------------------------------------------
FEDRAMP_CONTROLS: Dict[str, Dict[str, Any]] = {
    # Access Control
    "AC-1": {"title": "Access Control Policy & Procedures", "category": "AC", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "AC-2": {"title": "Account Management", "category": "AC", "cwes": ["CWE-269", "CWE-732"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "AC-3": {"title": "Access Enforcement", "category": "AC", "cwes": ["CWE-862", "CWE-863"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-4": {"title": "Information Flow Enforcement", "category": "AC", "cwes": ["CWE-284"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-5": {"title": "Separation of Duties", "category": "AC", "cwes": ["CWE-269"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "AC-6": {"title": "Least Privilege", "category": "AC", "cwes": ["CWE-269", "CWE-250"], "evidence": [EvidenceType.ACCESS_REVIEW, EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-7": {"title": "Unsuccessful Logon Attempts", "category": "AC", "cwes": ["CWE-307"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-8": {"title": "System Use Notification", "category": "AC", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-11": {"title": "Session Lock", "category": "AC", "cwes": ["CWE-613"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-12": {"title": "Session Termination", "category": "AC", "cwes": ["CWE-613"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-14": {"title": "Actions Without Identification", "category": "AC", "cwes": ["CWE-306"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-17": {"title": "Remote Access", "category": "AC", "cwes": ["CWE-284", "CWE-319"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-18": {"title": "Wireless Access", "category": "AC", "cwes": ["CWE-284"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AC-20": {"title": "External Information Systems", "category": "AC", "cwes": ["CWE-918"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # Audit
    "AU-2": {"title": "Event Logging", "category": "AU", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AU-3": {"title": "Content of Audit Records", "category": "AU", "cwes": ["CWE-778", "CWE-117"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AU-6": {"title": "Audit Review & Analysis", "category": "AU", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "AU-8": {"title": "Time Stamps", "category": "AU", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AU-9": {"title": "Protection of Audit Information", "category": "AU", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AU-11": {"title": "Audit Record Retention", "category": "AU", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "AU-12": {"title": "Audit Generation", "category": "AU", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # Config Management
    "CM-2": {"title": "Baseline Configuration", "category": "CM", "cwes": ["CWE-16", "CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "CM-3": {"title": "Configuration Change Control", "category": "CM", "cwes": ["CWE-1104"], "evidence": [EvidenceType.CHANGE_RECORD], "automated": True},
    "CM-6": {"title": "Configuration Settings", "category": "CM", "cwes": ["CWE-16"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "CM-7": {"title": "Least Functionality", "category": "CM", "cwes": ["CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "CM-8": {"title": "Information System Component Inventory", "category": "CM", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # Identification
    "IA-2": {"title": "Identification & Authentication (Org Users)", "category": "IA", "cwes": ["CWE-287", "CWE-306"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "IA-4": {"title": "Identifier Management", "category": "IA", "cwes": ["CWE-287"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "IA-5": {"title": "Authenticator Management", "category": "IA", "cwes": ["CWE-798", "CWE-521"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.SCAN_RESULT], "automated": True},
    "IA-6": {"title": "Authenticator Feedback", "category": "IA", "cwes": ["CWE-200"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "IA-8": {"title": "Identification (Non-Org Users)", "category": "IA", "cwes": ["CWE-287"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # Incident Response
    "IR-4": {"title": "Incident Handling", "category": "IR", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "IR-5": {"title": "Incident Monitoring", "category": "IR", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE, EvidenceType.SCAN_RESULT], "automated": True},
    "IR-6": {"title": "Incident Reporting", "category": "IR", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "IR-8": {"title": "Incident Response Plan", "category": "IR", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    # Risk Assessment
    "RA-3": {"title": "Risk Assessment", "category": "RA", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    "RA-5": {"title": "Vulnerability Scanning", "category": "RA", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    # System & Services Acquisition
    "SA-3": {"title": "System Development Life Cycle", "category": "SA", "cwes": [], "evidence": [EvidenceType.CODE_REVIEW], "automated": True},
    "SA-4": {"title": "Acquisition Process", "category": "SA", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "SA-8": {"title": "Security Engineering Principles", "category": "SA", "cwes": [], "evidence": [EvidenceType.CODE_REVIEW], "automated": True},
    "SA-11": {"title": "Developer Security Testing", "category": "SA", "cwes": ["CWE-89", "CWE-79", "CWE-78"], "evidence": [EvidenceType.CODE_REVIEW, EvidenceType.SCAN_RESULT], "automated": True},
    # System & Communications Protection
    "SC-5": {"title": "Denial of Service Protection", "category": "SC", "cwes": ["CWE-400"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC-7": {"title": "Boundary Protection", "category": "SC", "cwes": ["CWE-284", "CWE-918"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC-8": {"title": "Transmission Confidentiality & Integrity", "category": "SC", "cwes": ["CWE-319"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC-12": {"title": "Cryptographic Key Establishment", "category": "SC", "cwes": ["CWE-320", "CWE-327"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "SC-13": {"title": "Cryptographic Protection", "category": "SC", "cwes": ["CWE-327", "CWE-326"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SC-28": {"title": "Protection of Information at Rest", "category": "SC", "cwes": ["CWE-312", "CWE-311"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # System & Information Integrity
    "SI-2": {"title": "Flaw Remediation", "category": "SI", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CHANGE_RECORD], "automated": True},
    "SI-3": {"title": "Malicious Code Protection", "category": "SI", "cwes": ["CWE-506"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SI-4": {"title": "Information System Monitoring", "category": "SI", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SI-5": {"title": "Security Alerts & Advisories", "category": "SI", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "SI-10": {"title": "Information Input Validation", "category": "SI", "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-22"], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CODE_REVIEW], "automated": True},
}

# ---------------------------------------------------------------------------
# HIPAA Security Rule Controls (45 CFR 164.3xx)
# Administrative (164.308), Physical (164.310), Technical (164.312)
# ---------------------------------------------------------------------------
HIPAA_CONTROLS: Dict[str, Dict[str, Any]] = {
    # Administrative Safeguards — 164.308
    "164.308(a)(1)": {"title": "Security Management Process", "category": "Administrative", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT, EvidenceType.POLICY_CHECK], "automated": True},
    "164.308(a)(1)(ii)(A)": {"title": "Risk Analysis", "category": "Administrative", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    "164.308(a)(1)(ii)(B)": {"title": "Risk Management", "category": "Administrative", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    "164.308(a)(1)(ii)(D)": {"title": "Information System Activity Review", "category": "Administrative", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.SCAN_RESULT], "automated": True},
    "164.308(a)(3)": {"title": "Workforce Security", "category": "Administrative", "cwes": ["CWE-269"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "164.308(a)(4)": {"title": "Information Access Management", "category": "Administrative", "cwes": ["CWE-862", "CWE-863"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "164.308(a)(5)": {"title": "Security Awareness & Training", "category": "Administrative", "cwes": [], "evidence": [EvidenceType.TRAINING_RECORD], "automated": False},
    "164.308(a)(6)": {"title": "Security Incident Procedures", "category": "Administrative", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "164.308(a)(7)": {"title": "Contingency Plan", "category": "Administrative", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "164.308(a)(8)": {"title": "Evaluation", "category": "Administrative", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    # Physical Safeguards — 164.310
    "164.310(a)(1)": {"title": "Facility Access Controls", "category": "Physical", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": False},
    "164.310(b)": {"title": "Workstation Use", "category": "Physical", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "164.310(c)": {"title": "Workstation Security", "category": "Physical", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": False},
    "164.310(d)(1)": {"title": "Device & Media Controls", "category": "Physical", "cwes": ["CWE-312"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    # Technical Safeguards — 164.312
    "164.312(a)(1)": {"title": "Access Control", "category": "Technical", "cwes": ["CWE-862", "CWE-287"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.ACCESS_REVIEW], "automated": True},
    "164.312(a)(2)(i)": {"title": "Unique User Identification", "category": "Technical", "cwes": ["CWE-287"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "164.312(a)(2)(ii)": {"title": "Emergency Access Procedure", "category": "Technical", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "164.312(a)(2)(iii)": {"title": "Automatic Logoff", "category": "Technical", "cwes": ["CWE-613"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "164.312(a)(2)(iv)": {"title": "Encryption & Decryption", "category": "Technical", "cwes": ["CWE-311", "CWE-312"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "164.312(b)": {"title": "Audit Controls", "category": "Technical", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "164.312(c)(1)": {"title": "Integrity", "category": "Technical", "cwes": ["CWE-345", "CWE-354"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "164.312(d)": {"title": "Person or Entity Authentication", "category": "Technical", "cwes": ["CWE-287", "CWE-306"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "164.312(e)(1)": {"title": "Transmission Security", "category": "Technical", "cwes": ["CWE-319", "CWE-327"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "164.312(e)(2)(i)": {"title": "Integrity Controls (Transmission)", "category": "Technical", "cwes": ["CWE-345"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "164.312(e)(2)(ii)": {"title": "Encryption (Transmission)", "category": "Technical", "cwes": ["CWE-319", "CWE-327"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
}

# ---------------------------------------------------------------------------
# DFARS 252.204-7012 — Safeguarding Covered Defense Information
# 14 security requirements mapped from NIST SP 800-171
# ---------------------------------------------------------------------------
DFARS_CONTROLS: Dict[str, Dict[str, Any]] = {
    "DFARS-3.1": {"title": "Access Control — Limit system access", "category": "Access", "cwes": ["CWE-862", "CWE-863", "CWE-269"], "evidence": [EvidenceType.ACCESS_REVIEW, EvidenceType.CONFIG_AUDIT], "automated": True},
    "DFARS-3.2": {"title": "Awareness & Training — Ensure personnel trained", "category": "Training", "cwes": [], "evidence": [EvidenceType.TRAINING_RECORD], "automated": False},
    "DFARS-3.3": {"title": "Audit & Accountability — Create & retain logs", "category": "Audit", "cwes": ["CWE-778"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "DFARS-3.4": {"title": "Configuration Management — Establish baselines", "category": "Configuration", "cwes": ["CWE-16", "CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "DFARS-3.5": {"title": "Identification & Authentication — Identify & verify users", "category": "Identity", "cwes": ["CWE-287", "CWE-306"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "DFARS-3.6": {"title": "Incident Response — Establish IR capability", "category": "Incident", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "DFARS-3.7": {"title": "Maintenance — Perform system maintenance", "category": "Maintenance", "cwes": [], "evidence": [EvidenceType.CHANGE_RECORD], "automated": True},
    "DFARS-3.8": {"title": "Media Protection — Protect system media", "category": "Media", "cwes": ["CWE-312"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "DFARS-3.9": {"title": "Personnel Security — Screen & protect during termination", "category": "Personnel", "cwes": ["CWE-269"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "DFARS-3.10": {"title": "Physical Protection — Limit physical access", "category": "Physical", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": False},
    "DFARS-3.11": {"title": "Risk Assessment — Assess and scan vulnerabilities", "category": "Risk", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT, EvidenceType.SCAN_RESULT], "automated": True},
    "DFARS-3.12": {"title": "Security Assessment — Assess effectiveness", "category": "Assessment", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT, EvidenceType.PENETRATION_TEST], "automated": True},
    "DFARS-3.13": {"title": "System & Communications Protection — Monitor & protect boundaries", "category": "Communications", "cwes": ["CWE-284", "CWE-319", "CWE-918"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "DFARS-3.14": {"title": "System & Information Integrity — Identify & manage flaws", "category": "Integrity", "cwes": ["CWE-506"], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CHANGE_RECORD], "automated": True},
}

# ---------------------------------------------------------------------------
# NIST CSF 2.0 — Cybersecurity Framework Core Functions
# ---------------------------------------------------------------------------
NIST_CSF_CONTROLS: Dict[str, Dict[str, Any]] = {
    # Govern
    "GV.OC-01": {"title": "Organizational Context", "category": "Govern", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "GV.RM-01": {"title": "Risk Management Strategy", "category": "Govern", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    "GV.SC-01": {"title": "Supply Chain Risk Management", "category": "Govern", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    # Identify
    "ID.AM-01": {"title": "Asset Inventory", "category": "Identify", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "ID.AM-02": {"title": "Software Inventory", "category": "Identify", "cwes": [], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.SCAN_RESULT], "automated": True},
    "ID.RA-01": {"title": "Vulnerability Identification", "category": "Identify", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "ID.RA-02": {"title": "Threat Intelligence", "category": "Identify", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "ID.RA-03": {"title": "Risk Identification", "category": "Identify", "cwes": [], "evidence": [EvidenceType.RISK_ASSESSMENT], "automated": True},
    # Protect
    "PR.AA-01": {"title": "Identity Management", "category": "Protect", "cwes": ["CWE-287"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "PR.AA-03": {"title": "Access Control", "category": "Protect", "cwes": ["CWE-862", "CWE-863"], "evidence": [EvidenceType.ACCESS_REVIEW], "automated": True},
    "PR.AT-01": {"title": "Security Awareness Training", "category": "Protect", "cwes": [], "evidence": [EvidenceType.TRAINING_RECORD], "automated": False},
    "PR.DS-01": {"title": "Data-at-Rest Protection", "category": "Protect", "cwes": ["CWE-312", "CWE-311"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "PR.DS-02": {"title": "Data-in-Transit Protection", "category": "Protect", "cwes": ["CWE-319"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "PR.PS-01": {"title": "Configuration Management", "category": "Protect", "cwes": ["CWE-16", "CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "PR.PS-02": {"title": "Software Maintenance", "category": "Protect", "cwes": [], "evidence": [EvidenceType.CHANGE_RECORD], "automated": True},
    # Detect
    "DE.CM-01": {"title": "Network Monitoring", "category": "Detect", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "DE.CM-06": {"title": "External Service Provider Monitoring", "category": "Detect", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "DE.CM-09": {"title": "Computing Resource Monitoring", "category": "Detect", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "DE.AE-02": {"title": "Anomaly Detection", "category": "Detect", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "DE.AE-06": {"title": "Event Correlation", "category": "Detect", "cwes": [], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    # Respond
    "RS.MA-01": {"title": "Incident Management", "category": "Respond", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "RS.AN-03": {"title": "Incident Analysis", "category": "Respond", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
    "RS.MI-01": {"title": "Incident Mitigation", "category": "Respond", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE, EvidenceType.CHANGE_RECORD], "automated": True},
    # Recover
    "RC.RP-01": {"title": "Recovery Plan Execution", "category": "Recover", "cwes": [], "evidence": [EvidenceType.POLICY_CHECK], "automated": False},
    "RC.CO-03": {"title": "Recovery Communication", "category": "Recover", "cwes": [], "evidence": [EvidenceType.INCIDENT_RESPONSE], "automated": True},
}

# ---------------------------------------------------------------------------
# OWASP ASVS 4.0 — Application Security Verification Standard
# 14 chapters covering application-specific security requirements
# ---------------------------------------------------------------------------
OWASP_ASVS_CONTROLS: Dict[str, Dict[str, Any]] = {
    "V1": {"title": "Architecture, Design & Threat Modeling", "category": "Architecture", "cwes": [], "evidence": [EvidenceType.CODE_REVIEW, EvidenceType.RISK_ASSESSMENT], "automated": True},
    "V2": {"title": "Authentication Verification", "category": "Authentication", "cwes": ["CWE-287", "CWE-306", "CWE-521", "CWE-798"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.SCAN_RESULT], "automated": True},
    "V3": {"title": "Session Management Verification", "category": "Session", "cwes": ["CWE-613", "CWE-384"], "evidence": [EvidenceType.CONFIG_AUDIT, EvidenceType.SCAN_RESULT], "automated": True},
    "V4": {"title": "Access Control Verification", "category": "Access", "cwes": ["CWE-862", "CWE-863", "CWE-269"], "evidence": [EvidenceType.ACCESS_REVIEW, EvidenceType.SCAN_RESULT], "automated": True},
    "V5": {"title": "Input Validation Verification", "category": "Input", "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-502"], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CODE_REVIEW], "automated": True},
    "V6": {"title": "Output Encoding Verification", "category": "Output", "cwes": ["CWE-79", "CWE-116"], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CODE_REVIEW], "automated": True},
    "V7": {"title": "Cryptography Verification", "category": "Cryptography", "cwes": ["CWE-327", "CWE-326", "CWE-320"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "V8": {"title": "Data Protection Verification", "category": "Data", "cwes": ["CWE-312", "CWE-311", "CWE-200", "CWE-209"], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.CONFIG_AUDIT], "automated": True},
    "V9": {"title": "Communication Verification", "category": "Communications", "cwes": ["CWE-319"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
    "V10": {"title": "Malicious Code Verification", "category": "Malicious", "cwes": ["CWE-506", "CWE-829"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "V11": {"title": "Business Logic Verification", "category": "Logic", "cwes": [], "evidence": [EvidenceType.CODE_REVIEW, EvidenceType.PENETRATION_TEST], "automated": True},
    "V12": {"title": "File & Resource Verification", "category": "Files", "cwes": ["CWE-22", "CWE-434"], "evidence": [EvidenceType.SCAN_RESULT], "automated": True},
    "V13": {"title": "API & Web Service Verification", "category": "API", "cwes": ["CWE-918", "CWE-284"], "evidence": [EvidenceType.SCAN_RESULT, EvidenceType.PENETRATION_TEST], "automated": True},
    "V14": {"title": "Configuration Verification", "category": "Configuration", "cwes": ["CWE-16", "CWE-1188"], "evidence": [EvidenceType.CONFIG_AUDIT], "automated": True},
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
        (Framework.CMMC_V2, CMMC_V2_CONTROLS),
        (Framework.FEDRAMP, FEDRAMP_CONTROLS),
        (Framework.HIPAA, HIPAA_CONTROLS),
        (Framework.DFARS, DFARS_CONTROLS),
        (Framework.NIST_CSF, NIST_CSF_CONTROLS),
        (Framework.OWASP_ASVS, OWASP_ASVS_CONTROLS),
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

    def _ensure_schema(self) -> None:
        """Defensive idempotent schema guard — call before any read.

        Hardens BUG-1: prevents HTTP 500 on /api/v1/compliance-engine/audit-bundle
        if the SQLite DB is deleted/corrupted between process start and first request.
        CREATE TABLE IF NOT EXISTS is a no-op when tables already exist.
        """
        try:
            self._init_db()
        except (sqlite3.OperationalError, sqlite3.DatabaseError, OSError):
            pass

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
        self._ensure_schema()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM assessments WHERE framework=? AND app_id=?",
                (framework, app_id),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_evidence_for_control(self, control_id: str, framework: str) -> List[Dict[str, Any]]:
        self._ensure_schema()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM evidence_items WHERE control_id=? AND framework=?",
                (control_id, framework),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_posture_trend(self, framework: str, limit: int = 30) -> List[Dict[str, Any]]:
        self._ensure_schema()
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
            Framework.CMMC_V2: CMMC_V2_CONTROLS,
            Framework.FEDRAMP: FEDRAMP_CONTROLS,
            Framework.HIPAA: HIPAA_CONTROLS,
            Framework.DFARS: DFARS_CONTROLS,
            Framework.NIST_CSF: NIST_CSF_CONTROLS,
            Framework.OWASP_ASVS: OWASP_ASVS_CONTROLS,
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

    def get_compliance_gaps(self, framework, app_id: str = "") -> List[Dict[str, Any]]:
        """Get all controls that are not satisfied for a framework.

        Args:
            framework: Framework enum, Framework string value, or None (returns all frameworks).
            app_id: Optional application scope.
        """
        # Resolve string or None to Framework enum
        if framework is None:
            # Return gaps across all enabled frameworks
            all_gaps: List[Dict[str, Any]] = []
            for fw in self._enabled:
                try:
                    fw_gaps = self.get_compliance_gaps(fw, app_id)
                    for g in fw_gaps:
                        g.setdefault("framework", fw.value)
                    all_gaps.extend(fw_gaps)
                except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                    pass
            return all_gaps
        if isinstance(framework, str):
            fw_map = {f.value.lower(): f for f in Framework}
            fw_key = framework.lower().replace("-", "_").replace(" ", "_")
            resolved = fw_map.get(fw_key) or fw_map.get(framework.lower())
            if resolved is None:
                raise ValueError(f"Unknown framework string: {framework!r}")
            framework = resolved
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
                "start": (datetime.now(timezone.utc) - timedelta(days=period_days)).isoformat(),
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


# ---------------------------------------------------------------------------
# COMPLIANCE AUTO-MAPPER
# ---------------------------------------------------------------------------


@dataclass
class ControlMapping:
    """A single finding-to-control mapping result."""

    framework: str
    control_id: str
    control_title: str
    relevance_score: float        # 0.0-1.0 confidence of mapping
    mapping_reason: str
    evidence_required: List[str]
    automated: bool = True


@dataclass
class FrameworkCoverage:
    """Coverage report for a single compliance framework."""

    framework: str
    total_controls: int
    covered_controls: int
    coverage_pct: float
    uncovered_controls: List[str]
    partial_controls: List[str]
    as_of: str


class ComplianceAutoMapper:
    """Automatically map security findings to compliance controls.

    Supports mapping across 7 major frameworks:
    - SOC 2 Type II (47 trust service criteria)
    - PCI-DSS v4.0 (12 requirements, 264 sub-requirements)
    - ISO 27001:2022 (93 controls across 4 themes)
    - HIPAA (45 safeguards)
    - NIST 800-53 Rev 5 (20 control families)
    - CMMC v2 (14 domains)
    - FedRAMP (325 controls, NIST 800-53 subset)

    Mapping is keyword-driven from CWE IDs, finding categories, and
    vulnerability types. Each mapping includes a relevance score so
    downstream evidence generation can be prioritised.

    Usage::

        mapper = ComplianceAutoMapper()
        mappings = mapper.map_finding_to_controls(finding_dict)
        coverage = mapper.get_coverage_report("SOC2")
        gaps = mapper.identify_gaps("PCI_DSS_4.0")
    """

    # CWE → frameworks → controls mapping table
    # Format: {cwe_id: {framework: [control_ids]}}
    _CWE_CONTROL_MAP: Dict[str, Dict[str, List[str]]] = {
        "CWE-89":   {  # SQLi
            "SOC2": ["CC6.1", "CC6.6", "CC7.1"],
            "PCI_DSS_4.0": ["6.2", "6.3", "6.4"],
            "ISO_27001_2022": ["A.8.28", "A.8.29", "A.8.25"],
            "NIST_800_53_R5": ["SI-10", "SA-11", "SA-15"],
            "CMMC_V2": ["SI.L1-3.14.1", "SA.L2-3.12.3"],
            "HIPAA": ["§164.312(a)(1)", "§164.312(c)(1)"],
            "FedRAMP": ["SI-10", "SA-11"],
        },
        "CWE-79":   {  # XSS
            "SOC2": ["CC6.1", "CC6.6"],
            "PCI_DSS_4.0": ["6.2", "6.4"],
            "ISO_27001_2022": ["A.8.28", "A.8.29"],
            "NIST_800_53_R5": ["SI-10", "SC-18"],
            "CMMC_V2": ["SI.L1-3.14.1"],
            "HIPAA": ["§164.312(a)(1)"],
            "FedRAMP": ["SI-10", "SC-18"],
        },
        "CWE-22":   {  # Path Traversal
            "SOC2": ["CC6.1", "CC6.3"],
            "PCI_DSS_4.0": ["6.2", "7.2"],
            "ISO_27001_2022": ["A.8.28", "A.8.3"],
            "NIST_800_53_R5": ["AC-3", "SI-10"],
            "CMMC_V2": ["AC.L1-3.1.1", "SI.L1-3.14.1"],
            "HIPAA": ["§164.312(a)(1)", "§164.312(c)(1)"],
            "FedRAMP": ["AC-3", "SI-10"],
        },
        "CWE-78":   {  # Command Injection
            "SOC2": ["CC6.1", "CC6.6", "CC7.1"],
            "PCI_DSS_4.0": ["6.2", "6.3"],
            "ISO_27001_2022": ["A.8.28", "A.8.29"],
            "NIST_800_53_R5": ["SI-10", "CM-7"],
            "CMMC_V2": ["SI.L1-3.14.1", "CM.L2-3.4.6"],
            "HIPAA": ["§164.312(a)(1)"],
            "FedRAMP": ["SI-10", "CM-7"],
        },
        "CWE-798":  {  # Hardcoded Credentials
            "SOC2": ["CC6.1", "CC6.2"],
            "PCI_DSS_4.0": ["8.2", "8.3", "8.6"],
            "ISO_27001_2022": ["A.8.13", "A.5.17", "A.8.5"],
            "NIST_800_53_R5": ["IA-5", "SA-15"],
            "CMMC_V2": ["IA.L1-3.5.1", "IA.L2-3.5.3"],
            "HIPAA": ["§164.312(d)"],
            "FedRAMP": ["IA-5", "IA-6"],
        },
        "CWE-327":  {  # Weak Crypto
            "SOC2": ["CC6.1", "CC6.7"],
            "PCI_DSS_4.0": ["4.2", "6.2"],
            "ISO_27001_2022": ["A.8.24", "A.8.28"],
            "NIST_800_53_R5": ["SC-13", "SC-28"],
            "CMMC_V2": ["SC.L2-3.13.10", "SC.L2-3.13.8"],
            "HIPAA": ["§164.312(a)(2)(iv)", "§164.312(e)(2)(ii)"],
            "FedRAMP": ["SC-13", "SC-28"],
        },
        "CWE-502":  {  # Insecure Deserialization
            "SOC2": ["CC6.1", "CC6.6"],
            "PCI_DSS_4.0": ["6.2", "6.3"],
            "ISO_27001_2022": ["A.8.28", "A.8.29"],
            "NIST_800_53_R5": ["SI-10", "SA-11"],
            "CMMC_V2": ["SI.L1-3.14.1"],
            "HIPAA": ["§164.312(a)(1)"],
            "FedRAMP": ["SI-10"],
        },
        "CWE-918":  {  # SSRF
            "SOC2": ["CC6.1", "CC6.6", "CC7.1"],
            "PCI_DSS_4.0": ["6.2", "6.3", "1.3"],
            "ISO_27001_2022": ["A.8.28", "A.8.20"],
            "NIST_800_53_R5": ["SC-7", "SI-10"],
            "CMMC_V2": ["SC.L2-3.13.5", "SI.L1-3.14.1"],
            "HIPAA": ["§164.312(a)(1)"],
            "FedRAMP": ["SC-7", "SI-10"],
        },
        "CWE-611":  {  # XXE
            "SOC2": ["CC6.1", "CC6.6"],
            "PCI_DSS_4.0": ["6.2", "6.3"],
            "ISO_27001_2022": ["A.8.28"],
            "NIST_800_53_R5": ["SI-10"],
            "CMMC_V2": ["SI.L1-3.14.1"],
            "HIPAA": ["§164.312(a)(1)"],
            "FedRAMP": ["SI-10"],
        },
        "CWE-284":  {  # Broken Access Control
            "SOC2": ["CC6.2", "CC6.3"],
            "PCI_DSS_4.0": ["7.1", "7.2", "7.3"],
            "ISO_27001_2022": ["A.8.3", "A.5.15", "A.8.4"],
            "NIST_800_53_R5": ["AC-2", "AC-3", "AC-6"],
            "CMMC_V2": ["AC.L1-3.1.1", "AC.L1-3.1.2"],
            "HIPAA": ["§164.312(a)(1)", "§164.312(a)(2)(i)"],
            "FedRAMP": ["AC-2", "AC-3"],
        },
        "CWE-269":  {  # Privilege Escalation
            "SOC2": ["CC6.3"],
            "PCI_DSS_4.0": ["7.2", "7.3"],
            "ISO_27001_2022": ["A.8.2", "A.5.15"],
            "NIST_800_53_R5": ["AC-6", "CM-7"],
            "CMMC_V2": ["AC.L1-3.1.1", "AC.L2-3.1.6"],
            "HIPAA": ["§164.312(a)(2)(i)"],
            "FedRAMP": ["AC-6"],
        },
        "CWE-362":  {  # Race Condition
            "SOC2": ["CC7.1"],
            "PCI_DSS_4.0": ["6.2"],
            "ISO_27001_2022": ["A.8.28"],
            "NIST_800_53_R5": ["SI-16", "SA-11"],
            "CMMC_V2": ["SI.L1-3.14.1"],
            "HIPAA": ["§164.312(c)(1)"],
            "FedRAMP": ["SA-11"],
        },
        "CWE-506":  {  # Supply Chain / Embedded Malicious Code
            "SOC2": ["CC6.1", "CC9.2"],
            "PCI_DSS_4.0": ["6.3", "12.8"],
            "ISO_27001_2022": ["A.8.30", "A.5.19", "A.5.20"],
            "NIST_800_53_R5": ["SA-12", "SA-15", "SR-3"],
            "CMMC_V2": ["SR.L2-3.17.2", "SR.L2-3.17.3"],
            "HIPAA": ["§164.308(a)(1)"],
            "FedRAMP": ["SA-12", "SR-3"],
        },
        "CWE-639":  {  # IDOR
            "SOC2": ["CC6.2", "CC6.3"],
            "PCI_DSS_4.0": ["7.1", "7.2"],
            "ISO_27001_2022": ["A.8.3", "A.5.15"],
            "NIST_800_53_R5": ["AC-3", "AC-4"],
            "CMMC_V2": ["AC.L1-3.1.1"],
            "HIPAA": ["§164.312(a)(1)"],
            "FedRAMP": ["AC-3"],
        },
        "CWE-120":  {  # Buffer Overflow
            "SOC2": ["CC7.1"],
            "PCI_DSS_4.0": ["6.2"],
            "ISO_27001_2022": ["A.8.28", "A.8.8"],
            "NIST_800_53_R5": ["SI-16", "SA-11"],
            "CMMC_V2": ["SI.L1-3.14.1"],
            "HIPAA": ["§164.312(c)(1)"],
            "FedRAMP": ["SA-11", "SI-16"],
        },
    }

    # Framework control catalogs (title mappings for key controls)
    _CONTROL_TITLES: Dict[str, Dict[str, str]] = {
        "SOC2": {
            "CC6.1": "Logical and Physical Access Controls — Access Provisioning",
            "CC6.2": "Logical and Physical Access Controls — Passwords and Authentication",
            "CC6.3": "Logical and Physical Access Controls — Removal of Access",
            "CC6.6": "Logical and Physical Access Controls — Boundary Protection",
            "CC6.7": "Logical and Physical Access Controls — Transmission Controls",
            "CC7.1": "System Operations — Change Management",
            "CC9.2": "Risk Mitigation — Vendor and Business Partner Management",
        },
        "PCI_DSS_4.0": {
            "1.3": "Network Access Controls",
            "4.2": "Protection of Cardholder Data in Transit",
            "6.2": "Secure Development Practices",
            "6.3": "Vulnerability Management",
            "6.4": "Web-Facing Application Security",
            "7.1": "Access Control Policy",
            "7.2": "Access Control System",
            "7.3": "All Access Reviewed",
            "8.2": "User Identification and Authentication",
            "8.3": "Strong Authentication for Non-Consumer Users",
            "8.6": "Management of Service Provider Accounts",
            "12.8": "Third-Party Service Providers",
        },
        "ISO_27001_2022": {
            "A.5.15": "Access control",
            "A.5.17": "Authentication information",
            "A.5.19": "Information security in supplier relationships",
            "A.5.20": "Addressing information security within supplier agreements",
            "A.8.2": "Privileged access rights",
            "A.8.3": "Information access restriction",
            "A.8.4": "Access to source code",
            "A.8.5": "Secure authentication",
            "A.8.8": "Management of technical vulnerabilities",
            "A.8.13": "Information backup",
            "A.8.20": "Networks security",
            "A.8.24": "Use of cryptography",
            "A.8.25": "Secure development life cycle",
            "A.8.28": "Secure coding",
            "A.8.29": "Security testing in development and acceptance",
            "A.8.30": "Outsourced development",
        },
        "NIST_800_53_R5": {
            "AC-2": "Account Management",
            "AC-3": "Access Enforcement",
            "AC-4": "Information Flow Enforcement",
            "AC-6": "Least Privilege",
            "CM-7": "Least Functionality",
            "IA-5": "Authenticator Management",
            "IA-6": "Authentication Feedback",
            "SA-11": "Developer Testing and Evaluation",
            "SA-12": "Supply Chain Protection",
            "SA-15": "Development Process, Standards, and Tools",
            "SC-7": "Boundary Protection",
            "SC-13": "Cryptographic Protection",
            "SC-18": "Mobile Code",
            "SC-28": "Protection of Information at Rest",
            "SI-10": "Information Input Validation",
            "SI-16": "Memory Protection",
            "SR-3": "Supply Chain Controls and Processes",
        },
        "CMMC_V2": {
            "AC.L1-3.1.1": "Authorized Access Control",
            "AC.L1-3.1.2": "Transaction & Function Control",
            "AC.L2-3.1.6": "Non-Privileged Account Use",
            "CM.L2-3.4.6": "Least Functionality",
            "IA.L1-3.5.1": "Identification",
            "IA.L2-3.5.3": "Multi-factor Authentication",
            "SA.L2-3.12.3": "Security Control Testing",
            "SC.L2-3.13.5": "Public-Access System Separation",
            "SC.L2-3.13.8": "Data in Transit",
            "SC.L2-3.13.10": "Key Management",
            "SI.L1-3.14.1": "Flaw Remediation",
            "SR.L2-3.17.2": "Supply Chain Risk Assessment",
            "SR.L2-3.17.3": "Supplier Agreements",
        },
        "HIPAA": {
            "§164.308(a)(1)": "Risk Analysis and Management",
            "§164.312(a)(1)": "Access Control",
            "§164.312(a)(2)(i)": "Unique User Identification",
            "§164.312(a)(2)(iv)": "Encryption and Decryption",
            "§164.312(c)(1)": "Integrity Controls",
            "§164.312(d)": "Person or Entity Authentication",
            "§164.312(e)(2)(ii)": "Encryption of Data in Transit",
        },
        "FedRAMP": {
            "AC-2": "Account Management",
            "AC-3": "Access Enforcement",
            "AC-6": "Least Privilege",
            "IA-5": "Authenticator Management",
            "IA-6": "Authentication Feedback",
            "SA-11": "Developer Security Testing",
            "SA-12": "Supply Chain Protection",
            "SC-7": "Boundary Protection",
            "SC-13": "Cryptographic Protection",
            "SC-28": "Protection of Information at Rest",
            "SI-10": "Information Input Validation",
            "SI-16": "Memory Protection",
            "SR-3": "Supply Chain Controls",
        },
    }

    def __init__(self) -> None:
        # Build reverse index: framework → set of all control_ids
        self._all_controls: Dict[str, set] = {}
        for _, fw_map in self._CWE_CONTROL_MAP.items():
            for fw, controls in fw_map.items():
                if fw not in self._all_controls:
                    self._all_controls[fw] = set()
                self._all_controls[fw].update(controls)

    def map_finding_to_controls(
        self, finding: Dict[str, Any]
    ) -> List[ControlMapping]:
        """Map a finding to compliance controls across all frameworks.

        Args:
            finding: Dict with at least one of:
                - cwe_id (str): CWE identifier (e.g. "CWE-89")
                - category (str): Finding category
                - title (str): Finding title
                - severity (str): Severity level

        Returns:
            Sorted list of ControlMapping objects (highest relevance first).
        """
        mappings: List[ControlMapping] = []
        seen: set = set()  # Avoid duplicates

        cwe_id = finding.get("cwe_id", "")
        title = (finding.get("title", "") + " " + finding.get("category", "")).lower()

        # Direct CWE match
        if cwe_id in self._CWE_CONTROL_MAP:
            for framework, control_ids in self._CWE_CONTROL_MAP[cwe_id].items():
                fw_titles = self._CONTROL_TITLES.get(framework, {})
                for ctrl_id in control_ids:
                    key = f"{framework}:{ctrl_id}"
                    if key not in seen:
                        seen.add(key)
                        mappings.append(ControlMapping(
                            framework=framework,
                            control_id=ctrl_id,
                            control_title=fw_titles.get(ctrl_id, ctrl_id),
                            relevance_score=0.95,
                            mapping_reason=f"Direct CWE match: {cwe_id}",
                            evidence_required=self._get_evidence_requirements(
                                framework, ctrl_id
                            ),
                        ))

        # Keyword-based matching for findings without CWE
        if not cwe_id or len(mappings) < 3:
            keyword_map = {
                "sql": "CWE-89",
                "injection": "CWE-78",
                "command": "CWE-78",
                "path traversal": "CWE-22",
                "directory": "CWE-22",
                "ssrf": "CWE-918",
                "deserializ": "CWE-502",
                "xxe": "CWE-611",
                "access control": "CWE-284",
                "privilege": "CWE-269",
                "crypto": "CWE-327",
                "encrypt": "CWE-327",
                "credential": "CWE-798",
                "secret": "CWE-798",
                "supply chain": "CWE-506",
                "buffer": "CWE-120",
                "idor": "CWE-639",
                "xss": "CWE-79",
            }
            for keyword, fallback_cwe in keyword_map.items():
                if keyword in title and fallback_cwe != cwe_id:
                    for fw, ctrl_ids in self._CWE_CONTROL_MAP.get(fallback_cwe, {}).items():
                        fw_titles = self._CONTROL_TITLES.get(fw, {})
                        for ctrl_id in ctrl_ids:
                            key = f"{fw}:{ctrl_id}"
                            if key not in seen:
                                seen.add(key)
                                mappings.append(ControlMapping(
                                    framework=fw,
                                    control_id=ctrl_id,
                                    control_title=fw_titles.get(ctrl_id, ctrl_id),
                                    relevance_score=0.75,
                                    mapping_reason=f"Keyword match: '{keyword}' → {fallback_cwe}",
                                    evidence_required=self._get_evidence_requirements(fw, ctrl_id),
                                ))
                    break

        mappings.sort(key=lambda m: m.relevance_score, reverse=True)
        return mappings

    def get_coverage_report(
        self, framework: str, covered_control_ids: Optional[List[str]] = None
    ) -> FrameworkCoverage:
        """Compute coverage percentage for a framework.

        Args:
            framework: Framework identifier string.
            covered_control_ids: List of control IDs with evidence. If None,
                uses all controls seen in mappings.

        Returns:
            FrameworkCoverage with percentage and gap details.
        """
        all_controls = self._all_controls.get(framework, set())
        covered = set(covered_control_ids or [])
        covered_in_fw = covered.intersection(all_controls)
        uncovered = sorted(all_controls - covered_in_fw)
        partial = []  # Could be populated with richer evidence tracking

        coverage_pct = (
            len(covered_in_fw) / len(all_controls) * 100.0
            if all_controls else 0.0
        )

        return FrameworkCoverage(
            framework=framework,
            total_controls=len(all_controls),
            covered_controls=len(covered_in_fw),
            coverage_pct=round(coverage_pct, 1),
            uncovered_controls=uncovered,
            partial_controls=partial,
            as_of=datetime.now(timezone.utc).isoformat(),
        )

    def identify_gaps(
        self,
        framework: str,
        evidence_map: Optional[Dict[str, List[str]]] = None,
    ) -> List[Dict[str, Any]]:
        """Identify controls with missing or insufficient evidence.

        Args:
            framework: Framework identifier.
            evidence_map: Dict of control_id → [evidence_bundle_ids]. If None,
                assumes no evidence for any control.

        Returns:
            Sorted list of gap dicts with priority and remediation suggestions.
        """
        all_controls = self._all_controls.get(framework, set())
        ev_map = evidence_map or {}
        fw_titles = self._CONTROL_TITLES.get(framework, {})
        gaps: List[Dict[str, Any]] = []

        for ctrl_id in sorted(all_controls):
            ev_count = len(ev_map.get(ctrl_id, []))
            if ev_count == 0:
                priority = "critical"
                status = "no_evidence"
            elif ev_count == 1:
                priority = "high"
                status = "insufficient_evidence"
            else:
                continue  # Adequately covered

            gaps.append({
                "framework": framework,
                "control_id": ctrl_id,
                "control_title": fw_titles.get(ctrl_id, ctrl_id),
                "status": status,
                "priority": priority,
                "evidence_count": ev_count,
                "remediation": self._get_gap_remediation(framework, ctrl_id, status),
                "estimated_days_to_close": 5 if ev_count == 0 else 2,
            })

        gaps.sort(key=lambda g: (0 if g["priority"] == "critical" else 1, g["control_id"]))
        return gaps

    def get_all_framework_names(self) -> List[str]:
        """Return list of all supported framework names."""
        return sorted(self._all_controls.keys())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_evidence_requirements(framework: str, control_id: str) -> List[str]:
        """Return standard evidence types required for a control."""
        base = ["scan_result", "policy_check"]
        if framework in ("SOC2", "ISO_27001_2022"):
            base.append("access_review")
        if framework in ("PCI_DSS_4.0", "FedRAMP"):
            base.append("penetration_test")
        if "SA" in control_id or "8.28" in control_id or "8.29" in control_id:
            base.append("code_review")
        return base

    @staticmethod
    def _get_gap_remediation(framework: str, control_id: str, status: str) -> str:
        """Build a remediation suggestion for a coverage gap."""
        if status == "no_evidence":
            return (
                f"Run a scan targeting {control_id} and generate evidence bundle. "
                f"At minimum 2 evidence items required for {framework} compliance."
            )
        return (
            f"Supplement existing evidence for {control_id} with a second "
            f"independent source (e.g., penetration test or access review)."
        )


# ---------------------------------------------------------------------------
# AUTO EVIDENCE GENERATOR
# ---------------------------------------------------------------------------


class AutoEvidenceGenerator:
    """Generate compliance evidence bundles from real scan data.

    Creates structured, audit-ready evidence bundles for specific framework
    controls using actual FixOps scan results. Each bundle includes:
    - Control reference and framework
    - Evidence timestamp and expiry
    - Relevant scan findings
    - Compliance statement
    - Audit-ready metadata

    Usage::

        gen = AutoEvidenceGenerator()
        bundle = gen.generate_soc2_evidence("auth-service", "CC6.1")
        bundles = gen.bulk_generate("payment-api", "PCI_DSS_4.0")
    """

    # Evidence validity periods (days) per framework
    _VALIDITY_DAYS: Dict[str, int] = {
        "SOC2": 365,
        "PCI_DSS_4.0": 365,
        "ISO_27001_2022": 365,
        "HIPAA": 365,
        "NIST_800_53_R5": 365,
        "CMMC_V2": 365,
        "FedRAMP": 365,
    }

    def __init__(
        self,
        auto_mapper: Optional[ComplianceAutoMapper] = None,
    ) -> None:
        self._mapper = auto_mapper or ComplianceAutoMapper()

    def generate_soc2_evidence(
        self,
        app_id: str,
        control_id: str,
        scan_findings: Optional[List[Dict[str, Any]]] = None,
        auditor_notes: str = "",
    ) -> Dict[str, Any]:
        """Generate a SOC 2 evidence bundle for a specific trust service criterion.

        Args:
            app_id: Application or service identifier.
            control_id: SOC 2 criterion ID (e.g. "CC6.1").
            scan_findings: List of relevant findings from scan results.
            auditor_notes: Optional notes from auditor or security team.

        Returns:
            Structured evidence bundle dict ready for SOC 2 audit submission.
        """
        return self._generate_bundle(
            framework="SOC2",
            app_id=app_id,
            control_id=control_id,
            scan_findings=scan_findings or [],
            auditor_notes=auditor_notes,
        )

    def generate_pci_evidence(
        self,
        app_id: str,
        requirement: str,
        scan_findings: Optional[List[Dict[str, Any]]] = None,
        auditor_notes: str = "",
    ) -> Dict[str, Any]:
        """Generate a PCI-DSS v4.0 evidence bundle.

        Args:
            app_id: Application or service identifier.
            requirement: PCI DSS requirement ID (e.g. "6.2").
            scan_findings: Relevant scan findings.
            auditor_notes: Optional auditor notes.

        Returns:
            Structured evidence bundle dict for PCI-DSS submission.
        """
        return self._generate_bundle(
            framework="PCI_DSS_4.0",
            app_id=app_id,
            control_id=requirement,
            scan_findings=scan_findings or [],
            auditor_notes=auditor_notes,
        )

    def generate_hipaa_evidence(
        self,
        app_id: str,
        safeguard_id: str,
        scan_findings: Optional[List[Dict[str, Any]]] = None,
        auditor_notes: str = "",
    ) -> Dict[str, Any]:
        """Generate a HIPAA evidence bundle for a specific safeguard.

        Args:
            app_id: Application identifier.
            safeguard_id: HIPAA safeguard (e.g. "§164.312(a)(1)").
            scan_findings: Relevant scan findings.
            auditor_notes: Optional auditor notes.

        Returns:
            Structured evidence bundle dict.
        """
        return self._generate_bundle(
            framework="HIPAA",
            app_id=app_id,
            control_id=safeguard_id,
            scan_findings=scan_findings or [],
            auditor_notes=auditor_notes,
        )

    def generate_cmmc_evidence(
        self,
        app_id: str,
        practice_id: str,
        scan_findings: Optional[List[Dict[str, Any]]] = None,
        auditor_notes: str = "",
    ) -> Dict[str, Any]:
        """Generate a CMMC v2 evidence bundle.

        Args:
            app_id: Application identifier.
            practice_id: CMMC practice ID (e.g. "SI.L1-3.14.1").
            scan_findings: Relevant findings.
            auditor_notes: Optional notes.

        Returns:
            Structured evidence bundle dict for CMMC assessment.
        """
        return self._generate_bundle(
            framework="CMMC_V2",
            app_id=app_id,
            control_id=practice_id,
            scan_findings=scan_findings or [],
            auditor_notes=auditor_notes,
        )

    def bulk_generate(
        self,
        app_id: str,
        framework: str,
        scan_findings: Optional[List[Dict[str, Any]]] = None,
        max_controls: int = 50,
    ) -> Dict[str, Any]:
        """Generate evidence bundles for all controls in a framework.

        Args:
            app_id: Application identifier.
            framework: Framework name (e.g. "SOC2").
            scan_findings: All available scan findings for the application.
            max_controls: Cap on number of controls to generate (avoids runaway).

        Returns:
            Dict with framework, total_generated, bundles list.
        """
        all_controls = list(
            self._mapper._all_controls.get(framework, set())
        )[:max_controls]

        bundles: List[Dict[str, Any]] = []
        findings = scan_findings or []

        for ctrl_id in sorted(all_controls):
            # Filter findings relevant to this control
            relevant = [
                f for f in findings
                if any(
                    m.control_id == ctrl_id
                    for m in self._mapper.map_finding_to_controls(f)
                    if m.framework == framework
                )
            ]
            bundle = self._generate_bundle(
                framework=framework,
                app_id=app_id,
                control_id=ctrl_id,
                scan_findings=relevant,
                auditor_notes="",
            )
            bundles.append(bundle)

        return {
            "framework": framework,
            "app_id": app_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_generated": len(bundles),
            "controls_covered": sorted(all_controls),
            "bundles": bundles,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _generate_bundle(
        self,
        framework: str,
        app_id: str,
        control_id: str,
        scan_findings: List[Dict[str, Any]],
        auditor_notes: str,
    ) -> Dict[str, Any]:
        """Core evidence bundle generator."""
        now = datetime.now(timezone.utc)
        validity_days = self._VALIDITY_DAYS.get(framework, 365)
        expires_at = (now + timedelta(days=validity_days)).isoformat()

        fw_titles = ComplianceAutoMapper._CONTROL_TITLES.get(framework, {})
        control_title = fw_titles.get(control_id, control_id)

        # Compute compliance status from findings
        critical_findings = [
            f for f in scan_findings
            if f.get("severity", "").lower() in ("critical", "high")
        ]
        status = "satisfied" if not critical_findings else "partially_satisfied"

        # Build evidence hash for integrity
        bundle_content = json.dumps({
            "app_id": app_id,
            "control_id": control_id,
            "framework": framework,
            "findings_count": len(scan_findings),
            "generated_at": now.isoformat(),
        }, sort_keys=True)
        evidence_hash = hashlib.sha256(bundle_content.encode()).hexdigest()

        return {
            "evidence_id": str(uuid.uuid4()),
            "framework": framework,
            "control_id": control_id,
            "control_title": control_title,
            "app_id": app_id,
            "generated_at": now.isoformat(),
            "expires_at": expires_at,
            "validity_days": validity_days,
            "status": status,
            "finding_count": len(scan_findings),
            "critical_finding_count": len(critical_findings),
            "findings_summary": [
                {
                    "id": f.get("id", ""),
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "cwe_id": f.get("cwe_id", ""),
                }
                for f in scan_findings[:10]  # Cap at 10 for bundle size
            ],
            "compliance_statement": self._build_compliance_statement(
                framework, control_id, control_title, app_id, status, scan_findings
            ),
            "auditor_notes": auditor_notes,
            "evidence_hash": evidence_hash,
            "evidence_type": "automated_scan",
            "generated_by": "FixOps AutoEvidenceGenerator",
            "schema_version": "1.0",
        }

    @staticmethod
    def _build_compliance_statement(
        framework: str,
        control_id: str,
        control_title: str,
        app_id: str,
        status: str,
        findings: List[Dict[str, Any]],
    ) -> str:
        """Build a human-readable compliance statement for auditors."""
        finding_str = (
            f"No findings relevant to this control."
            if not findings
            else f"{len(findings)} finding(s) reviewed; "
            f"{sum(1 for f in findings if f.get('severity','').lower() in ('critical','high'))} "
            f"are high/critical severity."
        )
        return (
            f"FixOps automated scan of application '{app_id}' was conducted on "
            f"{datetime.now(timezone.utc).date().isoformat()}. "
            f"Evidence collected for {framework} control {control_id} "
            f"({control_title}). {finding_str} "
            f"Control status assessed as '{status}' based on automated evidence analysis."
        )


# ---------------------------------------------------------------------------
# COMPLIANCE GAP ANALYZER
# ---------------------------------------------------------------------------


@dataclass
class ComplianceGap:
    """A single compliance gap with remediation detail."""

    framework: str
    control_id: str
    control_title: str
    gap_type: str                     # missing_evidence / insufficient_evidence / expired_evidence
    priority: str                     # critical / high / medium / low
    current_evidence_count: int
    required_evidence_count: int
    remediation_steps: List[str]
    estimated_days_to_close: int
    last_evidence_date: Optional[str] = None
    days_since_evidence: Optional[int] = None


@dataclass
class GapTrend:
    """Gap reduction trend over time."""

    framework: str
    measurement_date: str
    total_gaps: int
    critical_gaps: int
    high_gaps: int
    coverage_pct: float


class ComplianceGapAnalyzer:
    """Compliance gap analysis with trend tracking and remediation planning.

    Identifies and prioritizes compliance control gaps across frameworks,
    providing remediation timeline estimates and tracking improvement
    over successive assessments.

    Usage::

        analyzer = ComplianceGapAnalyzer()
        gaps = analyzer.analyze_gaps("SOC2", evidence_map)
        timeline = analyzer.estimate_closure_timeline(gaps)
        analyzer.record_trend("SOC2", gaps)
        trend = analyzer.get_trend("SOC2")
    """

    # Minimum evidence items required per control tier
    _MIN_EVIDENCE = {
        "SOC2": 2,
        "PCI_DSS_4.0": 3,
        "ISO_27001_2022": 2,
        "HIPAA": 2,
        "NIST_800_53_R5": 2,
        "CMMC_V2": 3,
        "FedRAMP": 4,
    }

    # Evidence expiry periods (days)
    _EVIDENCE_EXPIRY_DAYS = {
        "SOC2": 365,
        "PCI_DSS_4.0": 365,
        "ISO_27001_2022": 365,
        "HIPAA": 365,
        "NIST_800_53_R5": 365,
        "CMMC_V2": 365,
        "FedRAMP": 365,
    }

    def __init__(
        self,
        mapper: Optional[ComplianceAutoMapper] = None,
    ) -> None:
        self._mapper = mapper or ComplianceAutoMapper()
        self._trend_history: Dict[str, List[GapTrend]] = {}

    def analyze_gaps(
        self,
        framework: str,
        evidence_map: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> List[ComplianceGap]:
        """Identify compliance gaps for a framework.

        Args:
            framework: Framework identifier.
            evidence_map: Dict of control_id → list of evidence bundle dicts.
                Each bundle should have: evidence_id, generated_at, status.

        Returns:
            Priority-sorted list of ComplianceGap objects.
        """
        all_controls = self._mapper._all_controls.get(framework, set())
        fw_titles = ComplianceAutoMapper._CONTROL_TITLES.get(framework, {})
        ev_map = evidence_map or {}
        min_ev = self._MIN_EVIDENCE.get(framework, 2)
        expiry_days = self._EVIDENCE_EXPIRY_DAYS.get(framework, 365)
        gaps: List[ComplianceGap] = []

        for ctrl_id in sorted(all_controls):
            bundles = ev_map.get(ctrl_id, [])
            now = datetime.now(timezone.utc)

            # Filter out expired evidence
            valid_bundles = []
            for b in bundles:
                gen_at_str = b.get("generated_at", "")
                try:
                    gen_at = datetime.fromisoformat(gen_at_str)
                    if gen_at.tzinfo is None:
                        gen_at = gen_at.replace(tzinfo=timezone.utc)
                    if (now - gen_at).days <= expiry_days:
                        valid_bundles.append(b)
                except (ValueError, TypeError):
                    valid_bundles.append(b)  # Include if can't parse date

            ev_count = len(valid_bundles)
            last_ev_date = None
            days_since = None

            if valid_bundles:
                try:
                    dates = [
                        datetime.fromisoformat(b.get("generated_at", ""))
                        for b in valid_bundles
                        if b.get("generated_at")
                    ]
                    if dates:
                        latest = max(dates)
                        if latest.tzinfo is None:
                            latest = latest.replace(tzinfo=timezone.utc)
                        last_ev_date = latest.isoformat()
                        days_since = (now - latest).days
                except (ValueError, TypeError):
                    pass

            if ev_count == 0:
                gap_type = "missing_evidence"
                priority = "critical"
                est_days = 7
                steps = self._missing_evidence_steps(framework, ctrl_id)
            elif ev_count < min_ev:
                gap_type = "insufficient_evidence"
                priority = "high"
                est_days = 3
                steps = [
                    f"Generate {min_ev - ev_count} additional evidence bundle(s) for {ctrl_id}",
                    "Run targeted scan against this control area",
                    "Consider independent audit validation",
                ]
            else:
                # Check for stale evidence (>75% of expiry window)
                if days_since and days_since > int(expiry_days * 0.75):
                    gap_type = "stale_evidence"
                    priority = "medium"
                    est_days = 5
                    steps = [
                        f"Evidence for {ctrl_id} is {days_since} days old",
                        "Re-run scan to refresh evidence",
                        f"Target refresh before day {expiry_days} of evidence age",
                    ]
                else:
                    continue  # No gap

            gaps.append(ComplianceGap(
                framework=framework,
                control_id=ctrl_id,
                control_title=fw_titles.get(ctrl_id, ctrl_id),
                gap_type=gap_type,
                priority=priority,
                current_evidence_count=ev_count,
                required_evidence_count=min_ev,
                remediation_steps=steps,
                estimated_days_to_close=est_days,
                last_evidence_date=last_ev_date,
                days_since_evidence=days_since,
            ))

        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        gaps.sort(key=lambda g: (priority_order.get(g.priority, 4), g.control_id))
        return gaps

    def estimate_closure_timeline(
        self,
        gaps: List[ComplianceGap],
        team_capacity_days_per_week: float = 5.0,
    ) -> Dict[str, Any]:
        """Estimate how long it will take to close all identified gaps.

        Args:
            gaps: Output from analyze_gaps().
            team_capacity_days_per_week: Effective team capacity for remediation.

        Returns:
            Dict with estimated_days, target_date, gap_summary, critical_path.
        """
        if not gaps:
            return {
                "estimated_days": 0,
                "target_date": datetime.now(timezone.utc).date().isoformat(),
                "gap_count": 0,
                "message": "No gaps identified — framework is fully covered",
            }

        total_effort_days = sum(g.estimated_days_to_close for g in gaps)
        # Parallelise: assume team can work on 2 gaps simultaneously
        effective_days = total_effort_days / min(2.0, team_capacity_days_per_week)
        # Add overhead for review/approval cycles (20%)
        effective_days = int(effective_days * 1.2)

        target_date = (
            datetime.now(timezone.utc) + timedelta(days=effective_days)
        ).date().isoformat()

        critical_gaps = [g for g in gaps if g.priority == "critical"]
        high_gaps = [g for g in gaps if g.priority == "high"]

        critical_path = []
        if critical_gaps:
            critical_path = [
                {
                    "control_id": g.control_id,
                    "framework": g.framework,
                    "gap_type": g.gap_type,
                    "days_to_close": g.estimated_days_to_close,
                }
                for g in critical_gaps[:5]
            ]

        return {
            "estimated_days": effective_days,
            "target_date": target_date,
            "gap_count": len(gaps),
            "critical_gaps": len(critical_gaps),
            "high_gaps": len(high_gaps),
            "total_effort_days": total_effort_days,
            "team_capacity_days_per_week": team_capacity_days_per_week,
            "critical_path": critical_path,
        }

    def record_trend(
        self,
        framework: str,
        gaps: List[ComplianceGap],
        evidence_map: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> GapTrend:
        """Record a gap snapshot for trend tracking.

        Args:
            framework: Framework identifier.
            gaps: Current gap list from analyze_gaps().
            evidence_map: Optional evidence map for coverage calculation.

        Returns:
            GapTrend snapshot.
        """
        all_controls = len(self._mapper._all_controls.get(framework, set()))
        coverage_pct = (
            (all_controls - len(gaps)) / all_controls * 100.0
            if all_controls > 0 else 0.0
        )

        trend = GapTrend(
            framework=framework,
            measurement_date=datetime.now(timezone.utc).isoformat(),
            total_gaps=len(gaps),
            critical_gaps=sum(1 for g in gaps if g.priority == "critical"),
            high_gaps=sum(1 for g in gaps if g.priority == "high"),
            coverage_pct=round(coverage_pct, 1),
        )

        if framework not in self._trend_history:
            self._trend_history[framework] = []
        self._trend_history[framework].append(trend)
        return trend

    def get_trend(
        self,
        framework: str,
        lookback_days: int = 90,
    ) -> Dict[str, Any]:
        """Return gap trend analysis for a framework.

        Args:
            framework: Framework identifier.
            lookback_days: Number of days of history to include.

        Returns:
            Dict with trend direction, measurements, and delta.
        """
        history = self._trend_history.get(framework, [])
        if not history:
            return {
                "framework": framework,
                "trend": "no_data",
                "measurements": 0,
            }

        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(days=lookback_days)).isoformat()
        recent = [t for t in history if t.measurement_date >= cutoff]

        if len(recent) < 2:
            latest = history[-1]
            return {
                "framework": framework,
                "trend": "insufficient_data",
                "measurements": len(recent),
                "latest_total_gaps": latest.total_gaps,
                "latest_coverage_pct": latest.coverage_pct,
            }

        first = recent[0]
        last = recent[-1]
        delta_gaps = last.total_gaps - first.total_gaps
        direction = (
            "improving" if delta_gaps < 0
            else "declining" if delta_gaps > 0
            else "stable"
        )

        return {
            "framework": framework,
            "trend": direction,
            "measurements": len(recent),
            "lookback_days": lookback_days,
            "gap_delta": delta_gaps,
            "start_gaps": first.total_gaps,
            "current_gaps": last.total_gaps,
            "start_coverage_pct": first.coverage_pct,
            "current_coverage_pct": last.coverage_pct,
            "coverage_improvement_pct": round(
                last.coverage_pct - first.coverage_pct, 1
            ),
            "history": [
                {
                    "date": t.measurement_date[:10],
                    "total_gaps": t.total_gaps,
                    "critical_gaps": t.critical_gaps,
                    "coverage_pct": t.coverage_pct,
                }
                for t in recent
            ],
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _missing_evidence_steps(framework: str, control_id: str) -> List[str]:
        """Build remediation steps for a control with no evidence."""
        return [
            f"Run automated scan targeting {control_id} ({framework})",
            f"Generate evidence bundle using AutoEvidenceGenerator.generate_{framework.lower().split('_')[0]}_evidence()",
            "Validate evidence quality with auditor review",
            "Store evidence in WORM storage with 7-year retention",
        ]


# ---------------------------------------------------------------------------
# Module-level singleton helpers
# ---------------------------------------------------------------------------

_auto_mapper_instance: Optional[ComplianceAutoMapper] = None
_evidence_generator_instance: Optional[AutoEvidenceGenerator] = None
_gap_analyzer_instance: Optional[ComplianceGapAnalyzer] = None


def get_auto_mapper() -> ComplianceAutoMapper:
    """Return the module-level ComplianceAutoMapper singleton."""
    global _auto_mapper_instance
    if _auto_mapper_instance is None:
        _auto_mapper_instance = ComplianceAutoMapper()
    return _auto_mapper_instance


def get_evidence_generator() -> AutoEvidenceGenerator:
    """Return the module-level AutoEvidenceGenerator singleton."""
    global _evidence_generator_instance
    if _evidence_generator_instance is None:
        _evidence_generator_instance = AutoEvidenceGenerator()
    return _evidence_generator_instance


def get_gap_analyzer() -> ComplianceGapAnalyzer:
    """Return the module-level ComplianceGapAnalyzer singleton."""
    global _gap_analyzer_instance
    if _gap_analyzer_instance is None:
        _gap_analyzer_instance = ComplianceGapAnalyzer()
    return _gap_analyzer_instance
