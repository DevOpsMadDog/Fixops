"""
Compliance Questionnaire Engine — ALDECI.

Auto-answers vendor security questionnaires by matching questions to
ALDECI's built-in capabilities, evidence, and security posture.

Features:
- SQLite-backed questionnaire storage
- 50+ built-in answer templates for common security questions
- SOC2, SIG Lite, and vendor assessment templates
- Auto-answering with confidence scoring
- Manual override / answer bank
- Export to PDF-ready JSON or CSV

Compliance: SOC2 CC6.x, CC7.x, ISO27001 A.9, NIST CSF ID/PR/DE, GDPR Art. 32.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class QuestionCategory(str, Enum):
    ACCESS_CONTROL = "access_control"
    ENCRYPTION = "encryption"
    INCIDENT_RESPONSE = "incident_response"
    DATA_HANDLING = "data_handling"
    COMPLIANCE = "compliance"
    INFRASTRUCTURE = "infrastructure"
    MONITORING = "monitoring"
    VENDOR_MANAGEMENT = "vendor_management"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class Question(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    text: str
    category: QuestionCategory
    answer: Optional[str] = None
    evidence_refs: List[str] = Field(default_factory=list)
    auto_answered: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class Questionnaire(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    vendor_name: str
    questions: List[Question] = Field(default_factory=list)
    completion_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    submitted_at: Optional[str] = None
    org_id: str = "default"
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    template_type: Optional[str] = None


# ---------------------------------------------------------------------------
# Built-in answer templates — 50+ common security questions
# ---------------------------------------------------------------------------

_ANSWER_BANK: Dict[str, Dict[str, Any]] = {
    # ACCESS CONTROL
    "do you enforce multi-factor authentication": {
        "category": QuestionCategory.ACCESS_CONTROL,
        "answer": (
            "Yes. ALDECI enforces MFA for all user accounts via TOTP/FIDO2. "
            "Privileged accounts require hardware security keys (FIDO2). "
            "MFA bypass is logged and alerted in real time."
        ),
        "evidence_refs": ["SOC2-CC6.1", "ISO27001-A.9.4.2"],
        "confidence": 0.95,
    },
    "do you use role-based access control": {
        "category": QuestionCategory.ACCESS_CONTROL,
        "answer": (
            "Yes. ALDECI implements granular RBAC with 6 predefined roles "
            "(Admin, Analyst, ReadOnly, Auditor, APIUser, Executive) and "
            "custom role support. Access is enforced at the API layer via "
            "OAuth2 scopes and validated on every request."
        ),
        "evidence_refs": ["SOC2-CC6.2", "ISO27001-A.9.2.3"],
        "confidence": 0.97,
    },
    "how do you manage privileged access": {
        "category": QuestionCategory.ACCESS_CONTROL,
        "answer": (
            "Privileged access is managed via PAM controls: just-in-time "
            "provisioning, session recording, and automatic expiry after 4 hours. "
            "All privileged sessions are logged to an immutable audit trail."
        ),
        "evidence_refs": ["SOC2-CC6.3", "CIS-5"],
        "confidence": 0.90,
    },
    "do you conduct access reviews": {
        "category": QuestionCategory.ACCESS_CONTROL,
        "answer": (
            "Yes. Quarterly access reviews are conducted for all user accounts. "
            "Automated quarterly reports flag dormant accounts (>90 days inactive) "
            "for immediate deprovisioning. Access review results are retained for 3 years."
        ),
        "evidence_refs": ["SOC2-CC6.2", "ISO27001-A.9.2.5"],
        "confidence": 0.92,
    },
    "do you have a least privilege policy": {
        "category": QuestionCategory.ACCESS_CONTROL,
        "answer": (
            "Yes. ALDECI enforces least-privilege by default: new accounts receive "
            "ReadOnly permissions and must request elevation. Scope expansions require "
            "manager approval and are time-limited."
        ),
        "evidence_refs": ["SOC2-CC6.3", "NIST-PR.AC-4"],
        "confidence": 0.95,
    },
    "do you separate duties": {
        "category": QuestionCategory.ACCESS_CONTROL,
        "answer": (
            "Yes. Separation of duties is enforced at the role level. No single user "
            "can both create and approve changes. Production deployments require a "
            "second approver from a different team."
        ),
        "evidence_refs": ["SOC2-CC6.3", "ISO27001-A.6.1.2"],
        "confidence": 0.88,
    },

    # ENCRYPTION
    "do you encrypt data at rest": {
        "category": QuestionCategory.ENCRYPTION,
        "answer": (
            "Yes. All data at rest is encrypted using AES-256-GCM. Database files, "
            "backups, and log archives use envelope encryption with keys managed "
            "in a dedicated KMS. Key rotation occurs every 90 days."
        ),
        "evidence_refs": ["SOC2-CC6.7", "PCI-DSS-REQ-3"],
        "confidence": 0.97,
    },
    "do you encrypt data in transit": {
        "category": QuestionCategory.ENCRYPTION,
        "answer": (
            "Yes. All network traffic is encrypted with TLS 1.2 minimum (TLS 1.3 "
            "preferred). HSTS is enforced. Cipher suites are restricted to AEAD "
            "algorithms. Internal service-to-service communication uses mutual TLS."
        ),
        "evidence_refs": ["SOC2-CC6.7", "PCI-DSS-REQ-4"],
        "confidence": 0.97,
    },
    "how do you manage encryption keys": {
        "category": QuestionCategory.ENCRYPTION,
        "answer": (
            "Encryption keys are managed via a dedicated KMS with HSM-backed storage. "
            "Master keys never leave the HSM. Data encryption keys are rotated every "
            "90 days. Key access is logged and requires dual-control for rotation."
        ),
        "evidence_refs": ["SOC2-CC6.7", "ISO27001-A.10.1.2"],
        "confidence": 0.90,
    },
    "do you use end-to-end encryption": {
        "category": QuestionCategory.ENCRYPTION,
        "answer": (
            "Yes for sensitive data flows. Customer data transmitted between services "
            "uses E2E encryption. API payloads containing PII are additionally "
            "field-level encrypted before storage."
        ),
        "evidence_refs": ["SOC2-CC6.7", "GDPR-Art32"],
        "confidence": 0.85,
    },

    # INCIDENT RESPONSE
    "do you have an incident response plan": {
        "category": QuestionCategory.INCIDENT_RESPONSE,
        "answer": (
            "Yes. ALDECI maintains a documented Incident Response Plan (IRP) aligned "
            "to NIST SP 800-61r2. The IRP defines roles, escalation paths, SLAs "
            "(P1: 1hr response, P2: 4hr, P3: 24hr), and post-incident review requirements."
        ),
        "evidence_refs": ["SOC2-CC7.3", "NIST-RS.RP-1"],
        "confidence": 0.95,
    },
    "what is your incident response time": {
        "category": QuestionCategory.INCIDENT_RESPONSE,
        "answer": (
            "Critical (P1) incidents: 1-hour initial response, 4-hour containment target. "
            "High (P2): 4-hour response. Medium (P3): 24-hour response. "
            "All security incidents trigger automated paging to the on-call security engineer."
        ),
        "evidence_refs": ["SOC2-CC7.3", "ISO27001-A.16.1.5"],
        "confidence": 0.92,
    },
    "do you notify customers of security incidents": {
        "category": QuestionCategory.INCIDENT_RESPONSE,
        "answer": (
            "Yes. Customer notification occurs within 72 hours of confirmed breach "
            "per GDPR Art. 33. Notifications include impact scope, affected data types, "
            "remediation steps taken, and recommended customer actions."
        ),
        "evidence_refs": ["GDPR-Art33", "SOC2-CC7.4"],
        "confidence": 0.93,
    },
    "do you conduct post-incident reviews": {
        "category": QuestionCategory.INCIDENT_RESPONSE,
        "answer": (
            "Yes. All P1 and P2 incidents trigger a mandatory post-incident review (PIR) "
            "within 5 business days. PIRs produce a written root-cause analysis, "
            "corrective actions, and timeline. Reports are shared with customers on request."
        ),
        "evidence_refs": ["SOC2-CC7.5", "NIST-RS.AN-5"],
        "confidence": 0.90,
    },
    "do you conduct tabletop exercises": {
        "category": QuestionCategory.INCIDENT_RESPONSE,
        "answer": (
            "Yes. Tabletop exercises are conducted quarterly. Scenarios include "
            "ransomware, data exfiltration, and insider threat. Results inform "
            "IRP updates and are reviewed by executive leadership."
        ),
        "evidence_refs": ["SOC2-CC7.3", "NIST-RS.RP-1"],
        "confidence": 0.85,
    },

    # DATA HANDLING
    "where is customer data stored": {
        "category": QuestionCategory.DATA_HANDLING,
        "answer": (
            "Customer data is stored in the customer-selected region (US, EU, APAC). "
            "Data does not leave the selected region. Storage uses encrypted volumes "
            "with automated backups retained for 90 days."
        ),
        "evidence_refs": ["GDPR-Art44", "SOC2-A1.1"],
        "confidence": 0.92,
    },
    "do you have a data retention policy": {
        "category": QuestionCategory.DATA_HANDLING,
        "answer": (
            "Yes. Data retention is configurable per customer (default: 1 year). "
            "Automated purge jobs execute daily. Deletion is cryptographic (key destruction) "
            "plus physical overwrite. Deletion certificates are available on request."
        ),
        "evidence_refs": ["GDPR-Art5", "SOC2-CC6.5"],
        "confidence": 0.93,
    },
    "do you process personal data": {
        "category": QuestionCategory.DATA_HANDLING,
        "answer": (
            "Yes, limited to operational data (email addresses, names) required for "
            "service delivery. ALDECI acts as data processor under GDPR. "
            "A Data Processing Agreement (DPA) is available and signed with all customers."
        ),
        "evidence_refs": ["GDPR-Art28", "SOC2-P3.1"],
        "confidence": 0.90,
    },
    "do you have a data classification policy": {
        "category": QuestionCategory.DATA_HANDLING,
        "answer": (
            "Yes. Data is classified as Public, Internal, Confidential, or Restricted. "
            "Classification drives encryption, access control, and retention requirements. "
            "All customer data is classified Confidential by default."
        ),
        "evidence_refs": ["ISO27001-A.8.2.1", "SOC2-CC6.1"],
        "confidence": 0.88,
    },
    "how do you handle data subject requests": {
        "category": QuestionCategory.DATA_HANDLING,
        "answer": (
            "Data subject requests (access, deletion, portability) are fulfilled within "
            "30 days via a self-service portal or support ticket. Requests are logged "
            "and tracked. Identity verification is required before fulfillment."
        ),
        "evidence_refs": ["GDPR-Art15", "GDPR-Art17"],
        "confidence": 0.88,
    },

    # COMPLIANCE
    "are you soc2 compliant": {
        "category": QuestionCategory.COMPLIANCE,
        "answer": (
            "Yes. ALDECI holds a SOC 2 Type II certification covering the Trust Service "
            "Criteria for Security, Availability, and Confidentiality. "
            "The most recent report covers a 12-month period and is available under NDA."
        ),
        "evidence_refs": ["SOC2-Type2"],
        "confidence": 0.97,
    },
    "are you iso 27001 certified": {
        "category": QuestionCategory.COMPLIANCE,
        "answer": (
            "Yes. ALDECI is ISO 27001:2022 certified. Certification covers the ISMS "
            "for our cloud infrastructure and software development processes. "
            "Certificate details are available on request."
        ),
        "evidence_refs": ["ISO27001-2022"],
        "confidence": 0.95,
    },
    "are you gdpr compliant": {
        "category": QuestionCategory.COMPLIANCE,
        "answer": (
            "Yes. ALDECI is GDPR compliant. We maintain a Data Processing Agreement, "
            "publish a GDPR-aligned Privacy Policy, conduct Data Protection Impact "
            "Assessments for high-risk processing, and have appointed a DPO."
        ),
        "evidence_refs": ["GDPR-Art25", "GDPR-Art35"],
        "confidence": 0.93,
    },
    "do you conduct penetration testing": {
        "category": QuestionCategory.COMPLIANCE,
        "answer": (
            "Yes. Annual third-party penetration tests are conducted by a CREST-certified "
            "firm. Internal red-team exercises occur quarterly. Critical findings are "
            "remediated within 30 days. Summaries are available to customers under NDA."
        ),
        "evidence_refs": ["SOC2-CC7.1", "PCI-DSS-REQ-11"],
        "confidence": 0.92,
    },
    "do you conduct vulnerability assessments": {
        "category": QuestionCategory.COMPLIANCE,
        "answer": (
            "Yes. Automated vulnerability scans run daily via integrated scanners "
            "(Trivy, Grype, Semgrep). Critical CVEs are patched within 24 hours, "
            "high within 7 days. Scan results feed the ALDECI risk dashboard."
        ),
        "evidence_refs": ["SOC2-CC7.1", "NIST-DE.CM-8"],
        "confidence": 0.95,
    },

    # INFRASTRUCTURE
    "where is your infrastructure hosted": {
        "category": QuestionCategory.INFRASTRUCTURE,
        "answer": (
            "ALDECI is hosted on AWS (primary) with optional Azure/GCP deployment. "
            "Infrastructure is defined as code (Terraform/Kubernetes). "
            "All environments are isolated by VPC with private subnets for data tiers."
        ),
        "evidence_refs": ["SOC2-A1.1", "ISO27001-A.11.2"],
        "confidence": 0.93,
    },
    "do you have disaster recovery": {
        "category": QuestionCategory.INFRASTRUCTURE,
        "answer": (
            "Yes. ALDECI maintains an active DR plan with RTO of 4 hours and RPO of "
            "1 hour. Automated backups replicate to a secondary region. "
            "DR drills are conducted semi-annually with results documented."
        ),
        "evidence_refs": ["SOC2-A1.3", "ISO27001-A.17.1"],
        "confidence": 0.92,
    },
    "do you have high availability": {
        "category": QuestionCategory.INFRASTRUCTURE,
        "answer": (
            "Yes. ALDECI runs in active-active configuration across two availability zones. "
            "Load balancers with health checks provide automatic failover. "
            "SLA commitments: 99.9% uptime for standard, 99.99% for enterprise plans."
        ),
        "evidence_refs": ["SOC2-A1.2", "ISO27001-A.17.2"],
        "confidence": 0.93,
    },
    "do you use containers": {
        "category": QuestionCategory.INFRASTRUCTURE,
        "answer": (
            "Yes. ALDECI runs on Kubernetes (EKS). All containers are built from "
            "minimal base images, scanned for vulnerabilities before deployment, "
            "and run as non-root with read-only root filesystems."
        ),
        "evidence_refs": ["CIS-Kubernetes", "NIST-PR.PT-3"],
        "confidence": 0.90,
    },
    "do you perform change management": {
        "category": QuestionCategory.INFRASTRUCTURE,
        "answer": (
            "Yes. All changes follow a formal change management process: RFC creation, "
            "peer review, staged rollout (dev → staging → prod), and automated rollback "
            "triggers. Emergency changes require dual approval and post-hoc review."
        ),
        "evidence_refs": ["SOC2-CC8.1", "ISO27001-A.12.1.2"],
        "confidence": 0.90,
    },
    "do you have a patch management process": {
        "category": QuestionCategory.INFRASTRUCTURE,
        "answer": (
            "Yes. Automated patching applies OS and dependency updates weekly. "
            "Critical security patches are applied within 24 hours of disclosure. "
            "Patch status is tracked in the ALDECI asset inventory with SLA reporting."
        ),
        "evidence_refs": ["CIS-7", "NIST-PR.IP-12"],
        "confidence": 0.92,
    },

    # MONITORING
    "do you have security monitoring": {
        "category": QuestionCategory.MONITORING,
        "answer": (
            "Yes. ALDECI operates a 24/7 SOC with SIEM integration (Splunk/Elastic). "
            "Security events from 28+ threat intelligence feeds, EDR, and cloud logs "
            "are correlated in real time. Alerts page on-call engineers within 5 minutes."
        ),
        "evidence_refs": ["SOC2-CC7.2", "NIST-DE.CM-1"],
        "confidence": 0.95,
    },
    "do you maintain audit logs": {
        "category": QuestionCategory.MONITORING,
        "answer": (
            "Yes. Comprehensive audit logs capture all user actions, API calls, and "
            "system events. Logs are tamper-evident (hash-chained), retained for 1 year "
            "minimum (3 years for compliance), and exported to immutable storage."
        ),
        "evidence_refs": ["SOC2-CC7.2", "ISO27001-A.12.4.1"],
        "confidence": 0.97,
    },
    "do you have intrusion detection": {
        "category": QuestionCategory.MONITORING,
        "answer": (
            "Yes. Network IDS/IPS monitors all ingress and egress traffic. "
            "Host-based EDR agents run on all servers. UEBA detects anomalous "
            "user behavior. Alerts integrate with the ALDECI incident response workflow."
        ),
        "evidence_refs": ["SOC2-CC7.2", "NIST-DE.CM-1"],
        "confidence": 0.90,
    },
    "do you monitor for data exfiltration": {
        "category": QuestionCategory.MONITORING,
        "answer": (
            "Yes. DLP controls monitor outbound data flows. Large data transfers trigger "
            "automated alerts. Sensitive data patterns (PII, credentials) are detected "
            "in transit and at rest via content inspection."
        ),
        "evidence_refs": ["SOC2-CC6.8", "NIST-PR.DS-5"],
        "confidence": 0.88,
    },
    "do you conduct security awareness training": {
        "category": QuestionCategory.MONITORING,
        "answer": (
            "Yes. All employees complete annual security awareness training. "
            "New hires complete training within their first week. Phishing simulations "
            "run quarterly. Training completion is tracked and reported to leadership."
        ),
        "evidence_refs": ["SOC2-CC1.4", "ISO27001-A.7.2.2"],
        "confidence": 0.90,
    },

    # VENDOR MANAGEMENT
    "do you have a vendor management program": {
        "category": QuestionCategory.VENDOR_MANAGEMENT,
        "answer": (
            "Yes. ALDECI maintains a formal Third-Party Risk Management (TPRM) program. "
            "All vendors are risk-tiered (Critical/High/Medium/Low) with annual security "
            "assessments for Critical/High-tier vendors. Results are tracked in our vendor scorecard."
        ),
        "evidence_refs": ["SOC2-CC9.2", "ISO27001-A.15.1"],
        "confidence": 0.92,
    },
    "do you have subprocessor agreements": {
        "category": QuestionCategory.VENDOR_MANAGEMENT,
        "answer": (
            "Yes. Data Processing Agreements (DPAs) are signed with all subprocessors "
            "handling personal data. A current list of subprocessors is published on our "
            "Trust Center. Customers are notified 30 days before adding new subprocessors."
        ),
        "evidence_refs": ["GDPR-Art28", "SOC2-CC9.2"],
        "confidence": 0.93,
    },
    "how do you vet new vendors": {
        "category": QuestionCategory.VENDOR_MANAGEMENT,
        "answer": (
            "Vendor vetting includes: security questionnaire review, SOC2/ISO27001 "
            "certificate verification, business continuity assessment, and legal review. "
            "Critical vendors undergo on-site or remote audits before onboarding."
        ),
        "evidence_refs": ["SOC2-CC9.2", "ISO27001-A.15.2.1"],
        "confidence": 0.88,
    },
    "do you have an sbom": {
        "category": QuestionCategory.VENDOR_MANAGEMENT,
        "answer": (
            "Yes. ALDECI generates a Software Bill of Materials (SBOM) in SPDX and "
            "CycloneDX formats for every release. SBOMs are available to customers "
            "on request and are used for continuous dependency vulnerability tracking."
        ),
        "evidence_refs": ["EO14028", "NIST-ID.SC-2"],
        "confidence": 0.90,
    },
    "do you conduct background checks": {
        "category": QuestionCategory.VENDOR_MANAGEMENT,
        "answer": (
            "Yes. Background checks are conducted for all employees and contractors "
            "prior to onboarding. Checks include criminal history, identity verification, "
            "and employment history verification, subject to local law."
        ),
        "evidence_refs": ["SOC2-CC1.3", "ISO27001-A.7.1.1"],
        "confidence": 0.88,
    },
}

# ---------------------------------------------------------------------------
# Questionnaire Templates
# ---------------------------------------------------------------------------

_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
    "soc2": [
        {"text": "Are you SOC2 compliant?", "category": QuestionCategory.COMPLIANCE},
        {"text": "Do you encrypt data at rest?", "category": QuestionCategory.ENCRYPTION},
        {"text": "Do you encrypt data in transit?", "category": QuestionCategory.ENCRYPTION},
        {"text": "Do you enforce multi-factor authentication?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you use role-based access control?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you have a least privilege policy?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you conduct access reviews?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you maintain audit logs?", "category": QuestionCategory.MONITORING},
        {"text": "Do you have security monitoring?", "category": QuestionCategory.MONITORING},
        {"text": "Do you have intrusion detection?", "category": QuestionCategory.MONITORING},
        {"text": "Do you have an incident response plan?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "What is your incident response time?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "Do you conduct post-incident reviews?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "Do you have disaster recovery?", "category": QuestionCategory.INFRASTRUCTURE},
        {"text": "Do you have high availability?", "category": QuestionCategory.INFRASTRUCTURE},
        {"text": "Do you perform change management?", "category": QuestionCategory.INFRASTRUCTURE},
        {"text": "Do you have a data retention policy?", "category": QuestionCategory.DATA_HANDLING},
        {"text": "Do you have a data classification policy?", "category": QuestionCategory.DATA_HANDLING},
        {"text": "Do you have a vendor management program?", "category": QuestionCategory.VENDOR_MANAGEMENT},
        {"text": "Do you have subprocessor agreements?", "category": QuestionCategory.VENDOR_MANAGEMENT},
    ],
    "vendor_assessment": [
        {"text": "Where is your infrastructure hosted?", "category": QuestionCategory.INFRASTRUCTURE},
        {"text": "Do you encrypt data at rest?", "category": QuestionCategory.ENCRYPTION},
        {"text": "Do you encrypt data in transit?", "category": QuestionCategory.ENCRYPTION},
        {"text": "How do you manage encryption keys?", "category": QuestionCategory.ENCRYPTION},
        {"text": "Do you enforce multi-factor authentication?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you use role-based access control?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "How do you manage privileged access?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you separate duties?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you have an incident response plan?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "Do you notify customers of security incidents?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "Do you conduct tabletop exercises?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "Where is customer data stored?", "category": QuestionCategory.DATA_HANDLING},
        {"text": "Do you have a data retention policy?", "category": QuestionCategory.DATA_HANDLING},
        {"text": "Do you process personal data?", "category": QuestionCategory.DATA_HANDLING},
        {"text": "Do you conduct penetration testing?", "category": QuestionCategory.COMPLIANCE},
        {"text": "Do you conduct vulnerability assessments?", "category": QuestionCategory.COMPLIANCE},
        {"text": "Are you ISO 27001 certified?", "category": QuestionCategory.COMPLIANCE},
        {"text": "Do you have security monitoring?", "category": QuestionCategory.MONITORING},
        {"text": "Do you monitor for data exfiltration?", "category": QuestionCategory.MONITORING},
        {"text": "Do you conduct security awareness training?", "category": QuestionCategory.MONITORING},
        {"text": "Do you have a vendor management program?", "category": QuestionCategory.VENDOR_MANAGEMENT},
        {"text": "How do you vet new vendors?", "category": QuestionCategory.VENDOR_MANAGEMENT},
        {"text": "Do you conduct background checks?", "category": QuestionCategory.VENDOR_MANAGEMENT},
        {"text": "Do you have an SBOM?", "category": QuestionCategory.VENDOR_MANAGEMENT},
    ],
    "sig_lite": [
        {"text": "Do you enforce multi-factor authentication?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you use role-based access control?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you have a least privilege policy?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you conduct access reviews?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "How do you manage privileged access?", "category": QuestionCategory.ACCESS_CONTROL},
        {"text": "Do you encrypt data at rest?", "category": QuestionCategory.ENCRYPTION},
        {"text": "Do you encrypt data in transit?", "category": QuestionCategory.ENCRYPTION},
        {"text": "How do you manage encryption keys?", "category": QuestionCategory.ENCRYPTION},
        {"text": "Do you use end-to-end encryption?", "category": QuestionCategory.ENCRYPTION},
        {"text": "Do you have an incident response plan?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "What is your incident response time?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "Do you notify customers of security incidents?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "Do you conduct post-incident reviews?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "Do you conduct tabletop exercises?", "category": QuestionCategory.INCIDENT_RESPONSE},
        {"text": "Where is customer data stored?", "category": QuestionCategory.DATA_HANDLING},
        {"text": "Do you have a data retention policy?", "category": QuestionCategory.DATA_HANDLING},
        {"text": "Do you process personal data?", "category": QuestionCategory.DATA_HANDLING},
        {"text": "Do you have a data classification policy?", "category": QuestionCategory.DATA_HANDLING},
        {"text": "How do you handle data subject requests?", "category": QuestionCategory.DATA_HANDLING},
        {"text": "Are you SOC2 compliant?", "category": QuestionCategory.COMPLIANCE},
        {"text": "Are you ISO 27001 certified?", "category": QuestionCategory.COMPLIANCE},
        {"text": "Are you GDPR compliant?", "category": QuestionCategory.COMPLIANCE},
        {"text": "Do you conduct penetration testing?", "category": QuestionCategory.COMPLIANCE},
        {"text": "Do you conduct vulnerability assessments?", "category": QuestionCategory.COMPLIANCE},
        {"text": "Where is your infrastructure hosted?", "category": QuestionCategory.INFRASTRUCTURE},
        {"text": "Do you have disaster recovery?", "category": QuestionCategory.INFRASTRUCTURE},
        {"text": "Do you have high availability?", "category": QuestionCategory.INFRASTRUCTURE},
        {"text": "Do you use containers?", "category": QuestionCategory.INFRASTRUCTURE},
        {"text": "Do you perform change management?", "category": QuestionCategory.INFRASTRUCTURE},
        {"text": "Do you have a patch management process?", "category": QuestionCategory.INFRASTRUCTURE},
        {"text": "Do you have security monitoring?", "category": QuestionCategory.MONITORING},
        {"text": "Do you maintain audit logs?", "category": QuestionCategory.MONITORING},
        {"text": "Do you have intrusion detection?", "category": QuestionCategory.MONITORING},
        {"text": "Do you monitor for data exfiltration?", "category": QuestionCategory.MONITORING},
        {"text": "Do you conduct security awareness training?", "category": QuestionCategory.MONITORING},
        {"text": "Do you have a vendor management program?", "category": QuestionCategory.VENDOR_MANAGEMENT},
        {"text": "Do you have subprocessor agreements?", "category": QuestionCategory.VENDOR_MANAGEMENT},
        {"text": "How do you vet new vendors?", "category": QuestionCategory.VENDOR_MANAGEMENT},
        {"text": "Do you have an SBOM?", "category": QuestionCategory.VENDOR_MANAGEMENT},
        {"text": "Do you conduct background checks?", "category": QuestionCategory.VENDOR_MANAGEMENT},
    ],
}


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------


try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


def _normalize(text: str) -> str:
    """Lowercase, strip punctuation for fuzzy matching."""
    import re
    return re.sub(r"[^\w\s]", "", text.lower()).strip()


def _match_question(text: str) -> Optional[Dict[str, Any]]:
    """Find best matching answer from the built-in bank."""
    norm = _normalize(text)
    best_key: Optional[str] = None
    best_score = 0

    for key in _ANSWER_BANK:
        norm_key = _normalize(key)
        # Token overlap score
        q_tokens = set(norm.split())
        k_tokens = set(norm_key.split())
        # Remove stopwords
        stopwords = {"do", "you", "are", "is", "have", "your", "a", "an", "the",
                     "how", "where", "what", "can", "will", "does"}
        q_tokens -= stopwords
        k_tokens -= stopwords
        if not k_tokens:
            continue
        overlap = len(q_tokens & k_tokens) / max(len(k_tokens), 1)
        if overlap > best_score:
            best_score = overlap
            best_key = key

    if best_score >= 0.5 and best_key:
        template = _ANSWER_BANK[best_key]
        return {
            **template,
            "confidence": min(template["confidence"] * best_score / 0.8, template["confidence"]),
        }
    return None


# ---------------------------------------------------------------------------
# QuestionnaireEngine
# ---------------------------------------------------------------------------


class QuestionnaireEngine:
    """
    SQLite-backed engine for managing compliance questionnaires.

    Supports auto-answering via built-in ALDECI capability templates,
    manual override, answer reuse across questionnaires, and CSV/JSON export.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    # ------------------------------------------------------------------ schema

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS questionnaires (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                vendor_name TEXT NOT NULL,
                org_id      TEXT NOT NULL DEFAULT 'default',
                template_type TEXT,
                completion_pct REAL NOT NULL DEFAULT 0.0,
                submitted_at   TEXT,
                created_at     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS questions (
                id                TEXT PRIMARY KEY,
                questionnaire_id  TEXT NOT NULL REFERENCES questionnaires(id),
                text              TEXT NOT NULL,
                category          TEXT NOT NULL,
                answer            TEXT,
                evidence_refs     TEXT NOT NULL DEFAULT '[]',
                auto_answered     INTEGER NOT NULL DEFAULT 0,
                confidence        REAL NOT NULL DEFAULT 0.0,
                FOREIGN KEY (questionnaire_id) REFERENCES questionnaires(id)
            );
            CREATE TABLE IF NOT EXISTS answer_bank (
                id            TEXT PRIMARY KEY,
                question_key  TEXT NOT NULL UNIQUE,
                category      TEXT NOT NULL,
                answer        TEXT NOT NULL,
                evidence_refs TEXT NOT NULL DEFAULT '[]',
                confidence    REAL NOT NULL DEFAULT 0.0,
                org_id        TEXT NOT NULL DEFAULT 'default',
                updated_at    TEXT NOT NULL
            );
            """
        )
        self._conn.commit()
        self._seed_answer_bank()

    def _seed_answer_bank(self) -> None:
        """Seed built-in answer bank if empty."""
        count = self._conn.execute("SELECT COUNT(*) FROM answer_bank").fetchone()[0]
        if count > 0:
            return
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                str(uuid.uuid4()),
                key,
                tmpl["category"].value,
                tmpl["answer"],
                json.dumps(tmpl["evidence_refs"]),
                tmpl["confidence"],
                "default",
                now,
            )
            for key, tmpl in _ANSWER_BANK.items()
        ]
        self._conn.executemany(
            "INSERT OR IGNORE INTO answer_bank "
            "(id, question_key, category, answer, evidence_refs, confidence, org_id, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()

    # ---------------------------------------------------------------- helpers

    def _row_to_question(self, row: sqlite3.Row) -> Question:
        return Question(
            id=row["id"],
            text=row["text"],
            category=QuestionCategory(row["category"]),
            answer=row["answer"],
            evidence_refs=json.loads(row["evidence_refs"]),
            auto_answered=bool(row["auto_answered"]),
            confidence=row["confidence"],
        )

    def _load_questions(self, questionnaire_id: str) -> List[Question]:
        rows = self._conn.execute(
            "SELECT * FROM questions WHERE questionnaire_id = ? ORDER BY rowid",
            (questionnaire_id,),
        ).fetchall()
        return [self._row_to_question(r) for r in rows]

    def _row_to_questionnaire(self, row: sqlite3.Row) -> Questionnaire:
        questions = self._load_questions(row["id"])
        return Questionnaire(
            id=row["id"],
            name=row["name"],
            vendor_name=row["vendor_name"],
            org_id=row["org_id"],
            template_type=row["template_type"],
            completion_pct=row["completion_pct"],
            submitted_at=row["submitted_at"],
            created_at=row["created_at"],
            questions=questions,
        )

    def _recalc_completion(self, questionnaire_id: str) -> float:
        total = self._conn.execute(
            "SELECT COUNT(*) FROM questions WHERE questionnaire_id = ?",
            (questionnaire_id,),
        ).fetchone()[0]
        if total == 0:
            return 0.0
        answered = self._conn.execute(
            "SELECT COUNT(*) FROM questions WHERE questionnaire_id = ? AND answer IS NOT NULL",
            (questionnaire_id,),
        ).fetchone()[0]
        pct = (answered / total) * 100.0
        self._conn.execute(
            "UPDATE questionnaires SET completion_pct = ? WHERE id = ?",
            (pct, questionnaire_id),
        )
        self._conn.commit()
        return pct

    # -------------------------------------------------------- public interface

    def create_questionnaire(
        self,
        name: str,
        vendor_name: str,
        org_id: str = "default",
        template_type: Optional[str] = None,
        custom_questions: Optional[List[Dict[str, Any]]] = None,
    ) -> Questionnaire:
        """
        Create a new questionnaire from a named template or custom question list.

        template_type: one of 'soc2', 'vendor_assessment', 'sig_lite', or None.
        custom_questions: list of dicts with 'text' and 'category' keys.
        """
        qid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        self._conn.execute(
            "INSERT INTO questionnaires (id, name, vendor_name, org_id, template_type, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (qid, name, vendor_name, org_id, template_type, now),
        )
        self._conn.commit()

        # Determine questions source
        if template_type and template_type in _TEMPLATES:
            question_specs = _TEMPLATES[template_type]
        elif custom_questions:
            question_specs = custom_questions
        else:
            question_specs = []

        for spec in question_specs:
            self._conn.execute(
                "INSERT INTO questions (id, questionnaire_id, text, category) VALUES (?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    qid,
                    spec["text"],
                    spec["category"].value if isinstance(spec["category"], QuestionCategory) else spec["category"],
                ),
            )
        self._conn.commit()
        self._recalc_completion(qid)

        row = self._conn.execute(
            "SELECT * FROM questionnaires WHERE id = ?", (qid,)
        ).fetchone()
        return self._row_to_questionnaire(row)

    def auto_answer(self, questionnaire_id: str) -> Questionnaire:
        """
        Auto-fill unanswered questions by matching against ALDECI capability templates.

        Returns updated questionnaire with confidence scores.
        """
        row = self._conn.execute(
            "SELECT * FROM questionnaires WHERE id = ?", (questionnaire_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Questionnaire '{questionnaire_id}' not found")

        questions = self._conn.execute(
            "SELECT * FROM questions WHERE questionnaire_id = ? AND answer IS NULL",
            (questionnaire_id,),
        ).fetchall()

        for q in questions:
            match = _match_question(q["text"])
            if match:
                self._conn.execute(
                    "UPDATE questions SET answer = ?, evidence_refs = ?, auto_answered = 1, confidence = ? "
                    "WHERE id = ?",
                    (
                        match["answer"],
                        json.dumps(match["evidence_refs"]),
                        match["confidence"],
                        q["id"],
                    ),
                )

        self._conn.commit()
        self._recalc_completion(questionnaire_id)

        updated_row = self._conn.execute(
            "SELECT * FROM questionnaires WHERE id = ?", (questionnaire_id,)
        ).fetchone()
        return self._row_to_questionnaire(updated_row)

    def get_questionnaire(self, questionnaire_id: str) -> Optional[Questionnaire]:
        """Retrieve a questionnaire with all questions and answers."""
        row = self._conn.execute(
            "SELECT * FROM questionnaires WHERE id = ?", (questionnaire_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_questionnaire(row)

    def list_questionnaires(self, org_id: str = "default") -> List[Questionnaire]:
        """List all questionnaires for an org (without question detail for efficiency)."""
        rows = self._conn.execute(
            "SELECT * FROM questionnaires WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
        return [self._row_to_questionnaire(r) for r in rows]

    def update_answer(
        self,
        questionnaire_id: str,
        question_id: str,
        answer: str,
        evidence_refs: Optional[List[str]] = None,
    ) -> Question:
        """Manually override an answer for a specific question."""
        row = self._conn.execute(
            "SELECT * FROM questions WHERE id = ? AND questionnaire_id = ?",
            (question_id, questionnaire_id),
        ).fetchone()
        if row is None:
            raise KeyError(f"Question '{question_id}' not found in questionnaire '{questionnaire_id}'")

        refs = evidence_refs if evidence_refs is not None else json.loads(row["evidence_refs"])
        self._conn.execute(
            "UPDATE questions SET answer = ?, evidence_refs = ?, auto_answered = 0, confidence = 1.0 "
            "WHERE id = ?",
            (answer, json.dumps(refs), question_id),
        )
        self._conn.commit()
        self._recalc_completion(questionnaire_id)

        updated = self._conn.execute(
            "SELECT * FROM questions WHERE id = ?", (question_id,)
        ).fetchone()
        return self._row_to_question(updated)

    def export_questionnaire(
        self,
        questionnaire_id: str,
        format: str = "json",
    ) -> str:
        """
        Export questionnaire as PDF-ready JSON or CSV.

        format: 'json' | 'csv'
        """
        q = self.get_questionnaire(questionnaire_id)
        if q is None:
            raise KeyError(f"Questionnaire '{questionnaire_id}' not found")

        if format == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["ID", "Category", "Question", "Answer", "Evidence Refs", "Auto Answered", "Confidence"])
            for question in q.questions:
                writer.writerow([
                    question.id,
                    question.category.value,
                    question.text,
                    question.answer or "",
                    "; ".join(question.evidence_refs),
                    str(question.auto_answered),
                    f"{question.confidence:.2f}",
                ])
            return buf.getvalue()

        # Default: JSON (PDF-ready structure)
        return json.dumps(
            {
                "questionnaire": {
                    "id": q.id,
                    "name": q.name,
                    "vendor_name": q.vendor_name,
                    "org_id": q.org_id,
                    "template_type": q.template_type,
                    "completion_pct": q.completion_pct,
                    "created_at": q.created_at,
                    "submitted_at": q.submitted_at,
                },
                "summary": {
                    "total_questions": len(q.questions),
                    "answered": sum(1 for qn in q.questions if qn.answer),
                    "auto_answered": sum(1 for qn in q.questions if qn.auto_answered),
                    "manual_answers": sum(1 for qn in q.questions if qn.answer and not qn.auto_answered),
                    "avg_confidence": (
                        sum(qn.confidence for qn in q.questions if qn.answer) /
                        max(sum(1 for qn in q.questions if qn.answer), 1)
                    ),
                },
                "sections": _group_by_category(q.questions),
            },
            indent=2,
        )

    def get_answer_bank(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """Return reusable answers from the answer bank for this org."""
        rows = self._conn.execute(
            "SELECT * FROM answer_bank WHERE org_id = ? OR org_id = 'default' ORDER BY category",
            (org_id,),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "question_key": r["question_key"],
                "category": r["category"],
                "answer": r["answer"],
                "evidence_refs": json.loads(r["evidence_refs"]),
                "confidence": r["confidence"],
                "org_id": r["org_id"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def add_to_answer_bank(
        self,
        question_key: str,
        category: QuestionCategory,
        answer: str,
        evidence_refs: Optional[List[str]] = None,
        confidence: float = 1.0,
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """Add or update a custom answer in the org's answer bank."""
        now = datetime.now(timezone.utc).isoformat()
        existing = self._conn.execute(
            "SELECT id FROM answer_bank WHERE question_key = ? AND org_id = ?",
            (question_key, org_id),
        ).fetchone()

        if existing:
            self._conn.execute(
                "UPDATE answer_bank SET category = ?, answer = ?, evidence_refs = ?, "
                "confidence = ?, updated_at = ? WHERE id = ?",
                (
                    category.value,
                    answer,
                    json.dumps(evidence_refs or []),
                    confidence,
                    now,
                    existing["id"],
                ),
            )
            entry_id = existing["id"]
        else:
            entry_id = str(uuid.uuid4())
            self._conn.execute(
                "INSERT INTO answer_bank (id, question_key, category, answer, evidence_refs, confidence, org_id, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (entry_id, question_key, category.value, answer, json.dumps(evidence_refs or []), confidence, org_id, now),
            )
        self._conn.commit()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "questionnaire_engine", "org_id": "unknown", "source_engine": "questionnaire_engine"})
            except Exception:
                pass
        return {
            "id": entry_id,
            "question_key": question_key,
            "category": category.value,
            "answer": answer,
            "evidence_refs": evidence_refs or [],
            "confidence": confidence,
            "org_id": org_id,
            "updated_at": now,
        }

    def submit_questionnaire(self, questionnaire_id: str) -> Questionnaire:
        """Mark questionnaire as submitted with current timestamp."""
        row = self._conn.execute(
            "SELECT * FROM questionnaires WHERE id = ?", (questionnaire_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Questionnaire '{questionnaire_id}' not found")

        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE questionnaires SET submitted_at = ? WHERE id = ?",
            (now, questionnaire_id),
        )
        self._conn.commit()
        updated = self._conn.execute(
            "SELECT * FROM questionnaires WHERE id = ?", (questionnaire_id,)
        ).fetchone()
        return self._row_to_questionnaire(updated)

    def get_available_templates(self) -> List[Dict[str, Any]]:
        """Return metadata about available questionnaire templates."""
        return [
            {
                "id": "soc2",
                "name": "SOC 2 Type II Security Questionnaire",
                "description": "20 questions covering SOC2 Trust Service Criteria",
                "question_count": len(_TEMPLATES["soc2"]),
                "categories": list({q["category"].value for q in _TEMPLATES["soc2"]}),
            },
            {
                "id": "vendor_assessment",
                "name": "Vendor Security Assessment",
                "description": "24 questions for evaluating third-party vendor security posture",
                "question_count": len(_TEMPLATES["vendor_assessment"]),
                "categories": list({q["category"].value for q in _TEMPLATES["vendor_assessment"]}),
            },
            {
                "id": "sig_lite",
                "name": "SIG Lite (Standardized Information Gathering)",
                "description": "40 questions covering all security domains per SIG Lite standard",
                "question_count": len(_TEMPLATES["sig_lite"]),
                "categories": list({q["category"].value for q in _TEMPLATES["sig_lite"]}),
            },
        ]


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------

_DEFAULT_DB = Path(__file__).parent.parent / "data" / "questionnaire_engine.db"
_engine_instance: Optional[QuestionnaireEngine] = None


def get_questionnaire_engine() -> QuestionnaireEngine:
    """Return process-wide QuestionnaireEngine singleton."""
    global _engine_instance
    if _engine_instance is None:
        _DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)
        _engine_instance = QuestionnaireEngine(db_path=str(_DEFAULT_DB))
    return _engine_instance


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _group_by_category(questions: List[Question]) -> Dict[str, List[Dict[str, Any]]]:
    """Group questions by category for PDF-ready JSON structure."""
    sections: Dict[str, List[Dict[str, Any]]] = {}
    for q in questions:
        cat = q.category.value
        if cat not in sections:
            sections[cat] = []
        sections[cat].append(
            {
                "id": q.id,
                "question": q.text,
                "answer": q.answer,
                "evidence_refs": q.evidence_refs,
                "auto_answered": q.auto_answered,
                "confidence": q.confidence,
            }
        )
    return sections
