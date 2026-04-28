"""
Vendor Risk Management (VRM) Engine — ALDECI.

Provides a unified, self-hosted vendor risk management platform covering:
- Vendor Registry: third-party vendor tracking with data access, SLA, compliance certs
- Risk Assessment Questionnaire: SIG/SIG Lite-based 100+ question auto-scoring
- Continuous Monitoring: security ratings, breach history, compliance drift
- Vendor Tiering: Critical / High / Medium / Low auto-classification
- Fourth-Party Risk: transitive dependency mapping and breach propagation
- Contract Risk: clause gap detection (breach notification, audit rights, liability)
- Vendor Scorecard: composite 0-100 score with trend tracking

Compliance: SOC2 CC9.2, ISO27001 A.15, PCI-DSS 12.8, NIST CSF ID.SC
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

_logger = structlog.get_logger(__name__)

# TrustGraph event bus — optional, never blocks on failure
try:  # pragma: no cover - bus is optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
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
            import asyncio
            import inspect
            if inspect.iscoroutine(result):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


_DEFAULT_DB_PATH = "data/vendor_risk.db"


# ============================================================================
# ENUMS
# ============================================================================


class ServiceCategory(str, Enum):
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    SAAS_APPLICATION = "saas_application"
    SECURITY_TOOLING = "security_tooling"
    PROFESSIONAL_SERVICES = "professional_services"
    DATA_PROCESSING = "data_processing"
    PAYMENT_PROCESSING = "payment_processing"
    HR_PAYROLL = "hr_payroll"
    COMMUNICATION = "communication"
    DEVELOPMENT_TOOLS = "development_tools"
    NETWORKING = "networking"
    OTHER = "other"


class DataAccessLevel(str, Enum):
    NONE = "none"                     # No data access
    PUBLIC = "public"                 # Public data only
    INTERNAL = "internal"             # Internal non-sensitive data
    CONFIDENTIAL = "confidential"     # Confidential business data
    RESTRICTED = "restricted"         # PII / regulated data
    SECRET = "secret"                 # Crown jewels / trade secrets


class VendorTier(str, Enum):
    CRITICAL = "critical"    # Sensitive data + core operations
    HIGH = "high"            # Sensitive data OR core operations
    MEDIUM = "medium"        # Limited data access
    LOW = "low"              # No data access


class ComplianceCert(str, Enum):
    SOC2_TYPE1 = "soc2_type1"
    SOC2_TYPE2 = "soc2_type2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    FEDRAMP = "fedramp"
    CSA_STAR = "csa_star"
    NIST_CSF = "nist_csf"


class QuestionCategory(str, Enum):
    ACCESS_CONTROL = "access_control"
    ENCRYPTION = "encryption"
    INCIDENT_RESPONSE = "incident_response"
    BUSINESS_CONTINUITY = "business_continuity"
    DATA_HANDLING = "data_handling"
    NETWORK_SECURITY = "network_security"
    PHYSICAL_SECURITY = "physical_security"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    THIRD_PARTY_MANAGEMENT = "third_party_management"
    COMPLIANCE = "compliance"


class RiskSignalType(str, Enum):
    SECURITY_RATING = "security_rating"
    BREACH_HISTORY = "breach_history"
    COMPLIANCE_CHANGE = "compliance_change"
    FINANCIAL_STABILITY = "financial_stability"
    NEWS_ALERT = "news_alert"
    VULNERABILITY_DISCLOSURE = "vulnerability_disclosure"
    CERT_EXPIRY = "cert_expiry"


class RiskSignalSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ContractRiskType(str, Enum):
    MISSING_BREACH_NOTIFICATION = "missing_breach_notification"
    MISSING_AUDIT_RIGHTS = "missing_audit_rights"
    UNLIMITED_LIABILITY_GAP = "unlimited_liability_gap"
    MISSING_DATA_RETURN = "missing_data_return"
    MISSING_SECURITY_STANDARDS = "missing_security_standards"
    EXPIRED_CERT = "expired_cert"
    NO_SUBPROCESSOR_CLAUSE = "no_subprocessor_clause"
    MISSING_INCIDENT_RESPONSE_SLA = "missing_incident_response_sla"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class VendorContact(BaseModel):
    """Primary contact for a vendor."""

    name: str = Field(..., description="Contact full name")
    email: str = Field(..., description="Contact email")
    phone: Optional[str] = Field(None, description="Contact phone")
    role: str = Field("Security Contact", description="Contact role or title")


class SLATerms(BaseModel):
    """Service Level Agreement terms."""

    uptime_percent: float = Field(99.9, ge=0.0, le=100.0, description="Uptime SLA %")
    incident_response_hours: int = Field(4, ge=0, description="Hours to acknowledge incident")
    breach_notification_hours: int = Field(72, ge=0, description="Hours to notify of breach")
    data_return_days: int = Field(30, ge=0, description="Days to return data on termination")
    review_frequency_months: int = Field(12, ge=1, description="SLA review frequency in months")


class CertificationRecord(BaseModel):
    """A compliance certification with validity dates."""

    cert: ComplianceCert
    issued_date: str = Field(..., description="ISO-8601 date certification issued")
    expiry_date: str = Field(..., description="ISO-8601 date certification expires")
    issuing_body: Optional[str] = Field(None, description="Auditor or certification body")
    report_url: Optional[str] = Field(None, description="Link to certification report")

    @property
    def is_expired(self) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expiry_date).replace(tzinfo=timezone.utc)
            return expiry < datetime.now(timezone.utc)
        except ValueError:
            return False


class Vendor(BaseModel):
    """Full vendor record in the registry."""

    id: str = Field(default_factory=lambda: f"vnd-{uuid.uuid4().hex[:12]}")
    name: str = Field(..., min_length=1, description="Vendor name")
    service_category: ServiceCategory = Field(..., description="Primary service category")
    data_access_level: DataAccessLevel = Field(..., description="Level of data access granted")
    is_core_operations: bool = Field(False, description="True if vendor supports core operations")
    contract_start: str = Field(..., description="ISO-8601 contract start date")
    contract_end: str = Field(..., description="ISO-8601 contract expiry date")
    sla_terms: SLATerms = Field(default_factory=SLATerms)
    certifications: List[CertificationRecord] = Field(default_factory=list)
    primary_contact: Optional[VendorContact] = None
    description: str = Field("", description="Brief description of the vendor relationship")
    fourth_party_vendors: List[str] = Field(
        default_factory=list,
        description="Vendor IDs used by this vendor (fourth-party dependencies)",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Computed fields — populated by VRM engine
    tier: Optional[VendorTier] = None
    current_score: Optional[float] = None


class AssessmentQuestion(BaseModel):
    """A single question in the SIG-based questionnaire."""

    id: str
    category: QuestionCategory
    text: str
    weight: float = Field(1.0, gt=0.0, description="Score weight for this question")
    expected_answer: bool = Field(True, description="True = 'Yes' is the secure answer")
    control_reference: str = Field("", description="SOC2/ISO27001/PCI control reference")


class QuestionnaireResponse(BaseModel):
    """Vendor's response to a single assessment question."""

    question_id: str
    answer: bool = Field(..., description="True = Yes, False = No")
    evidence_url: Optional[str] = Field(None, description="URL to supporting evidence")
    notes: Optional[str] = Field(None, description="Vendor-provided notes")


class VendorAssessment(BaseModel):
    """Complete assessment result for a vendor."""

    id: str = Field(default_factory=lambda: f"asm-{uuid.uuid4().hex[:12]}")
    vendor_id: str
    responses: List[QuestionnaireResponse] = Field(default_factory=list)
    questionnaire_score: float = Field(0.0, ge=0.0, le=100.0)
    category_scores: Dict[str, float] = Field(default_factory=dict)
    submitted_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    next_review_date: Optional[str] = None
    assessed_by: str = Field("system", description="User or system that triggered assessment")


class RiskSignal(BaseModel):
    """A monitoring event that affects vendor risk posture."""

    id: str = Field(default_factory=lambda: f"sig-{uuid.uuid4().hex[:12]}")
    vendor_id: str
    signal_type: RiskSignalType
    severity: RiskSignalSeverity
    title: str
    description: str
    source: str = Field("manual", description="Data source (e.g. 'bitsight', 'nvd', 'news')")
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    resolved_at: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        return self.resolved_at is None


class SecurityRating(BaseModel):
    """BitSight-style security rating for a vendor."""

    vendor_id: str
    score: int = Field(..., ge=0, le=900, description="Security rating 0-900 (BitSight scale)")
    grade: str = Field(..., description="Letter grade: A-F")
    factors: Dict[str, Any] = Field(default_factory=dict)
    recorded_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ContractRisk(BaseModel):
    """A contractual risk gap identified for a vendor."""

    id: str = Field(default_factory=lambda: f"ctr-{uuid.uuid4().hex[:12]}")
    vendor_id: str
    risk_type: ContractRiskType
    severity: RiskSignalSeverity
    description: str
    recommendation: str
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    remediated_at: Optional[str] = None


class FourthPartyRisk(BaseModel):
    """Transitive risk from a vendor's vendor."""

    id: str = Field(default_factory=lambda: f"4pr-{uuid.uuid4().hex[:12]}")
    first_party_vendor_id: str = Field(..., description="Your direct vendor")
    fourth_party_vendor_id: str = Field(..., description="Your vendor's vendor")
    fourth_party_name: str
    transitive_risk_level: RiskSignalSeverity
    trigger_signal_id: Optional[str] = Field(None, description="Signal that triggered this risk")
    description: str
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class VendorScorecard(BaseModel):
    """Composite 0-100 scorecard for a vendor with trend tracking."""

    vendor_id: str
    vendor_name: str
    tier: VendorTier
    overall_score: float = Field(..., ge=0.0, le=100.0)
    grade: str
    questionnaire_score: float = Field(0.0, ge=0.0, le=100.0)
    monitoring_score: float = Field(0.0, ge=0.0, le=100.0)
    contract_score: float = Field(0.0, ge=0.0, le=100.0)
    incident_score: float = Field(0.0, ge=0.0, le=100.0)
    score_trend: List[Dict[str, Any]] = Field(default_factory=list)
    active_risks: int = 0
    contract_gaps: int = 0
    calculated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class TieringOverview(BaseModel):
    """Summary of vendor tiering across the registry."""

    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    untiered_count: int = 0
    tier_breakdown: Dict[str, List[str]] = Field(default_factory=dict)
    assessment_requirements: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


class FourthPartyMap(BaseModel):
    """Complete fourth-party risk map."""

    direct_vendor_count: int = 0
    fourth_party_count: int = 0
    active_transitive_risks: int = 0
    dependency_chains: List[Dict[str, Any]] = Field(default_factory=list)
    high_risk_fourth_parties: List[Dict[str, Any]] = Field(default_factory=list)


# ============================================================================
# SIG-BASED QUESTIONNAIRE (100+ questions)
# ============================================================================


def _build_questionnaire() -> List[AssessmentQuestion]:
    """Return the standard SIG/SIG Lite security assessment questionnaire."""
    questions: List[AssessmentQuestion] = []

    # Access Control (15 questions)
    ac_questions = [
        ("AC-01", "Does the vendor enforce multi-factor authentication for all privileged accounts?", 2.0, "SOC2 CC6.1 / ISO A.9.4"),
        ("AC-02", "Is access to customer data restricted to need-to-know personnel?", 2.0, "SOC2 CC6.3 / PCI 7.1"),
        ("AC-03", "Does the vendor maintain a formal access control policy reviewed annually?", 1.0, "ISO A.9.1"),
        ("AC-04", "Are privileged access sessions logged and monitored?", 1.5, "SOC2 CC6.2 / PCI 10.2"),
        ("AC-05", "Is access revoked within 24 hours of employee termination?", 2.0, "SOC2 CC6.3"),
        ("AC-06", "Does the vendor conduct quarterly access reviews?", 1.5, "PCI 7.1.2"),
        ("AC-07", "Is vendor remote access protected by VPN and MFA?", 1.5, "ISO A.6.2 / PCI 8.3"),
        ("AC-08", "Are service accounts subject to the same access controls as human accounts?", 1.0, "ISO A.9.4"),
        ("AC-09", "Does the vendor enforce password complexity requirements?", 1.0, "PCI 8.6"),
        ("AC-10", "Is access to production environments separated from development?", 1.5, "SOC2 CC8.1"),
        ("AC-11", "Does the vendor maintain a privileged access management (PAM) solution?", 1.0, "ISO A.9.2"),
        ("AC-12", "Are all API keys and secrets stored in a secrets management system?", 1.5, "ISO A.9.4"),
        ("AC-13", "Does the vendor enforce the principle of least privilege?", 2.0, "SOC2 CC6.3"),
        ("AC-14", "Is cross-tenant data access technically prevented?", 2.0, "SOC2 CC6.1"),
        ("AC-15", "Does the vendor perform background checks before granting privileged access?", 1.0, "ISO A.7.1"),
    ]
    for qid, text, weight, ref in ac_questions:
        questions.append(AssessmentQuestion(
            id=qid, category=QuestionCategory.ACCESS_CONTROL,
            text=text, weight=weight, control_reference=ref,
        ))

    # Encryption (10 questions)
    enc_questions = [
        ("EN-01", "Is data encrypted in transit using TLS 1.2 or higher?", 2.0, "PCI 4.2 / ISO A.10.1"),
        ("EN-02", "Is customer data encrypted at rest using AES-256 or equivalent?", 2.0, "PCI 3.4 / SOC2 CC6.7"),
        ("EN-03", "Does the vendor maintain a formal encryption key management policy?", 1.5, "ISO A.10.1 / PCI 3.5"),
        ("EN-04", "Are encryption keys rotated at least annually?", 1.5, "PCI 3.6"),
        ("EN-05", "Is encryption applied to backups of customer data?", 1.5, "ISO A.12.3"),
        ("EN-06", "Does the vendor use Hardware Security Modules (HSMs) for key storage?", 1.0, "PCI 3.5.3"),
        ("EN-07", "Is end-to-end encryption implemented for sensitive data flows?", 1.0, "SOC2 CC6.7"),
        ("EN-08", "Are deprecated cryptographic algorithms (MD5, SHA-1, DES) prohibited?", 1.5, "PCI 4.1"),
        ("EN-09", "Does the vendor have a certificate management process to prevent expiry?", 1.0, "ISO A.10.1"),
        ("EN-10", "Are database fields containing PII encrypted at the field level?", 1.0, "GDPR Art.32 / PCI 3.4"),
    ]
    for qid, text, weight, ref in enc_questions:
        questions.append(AssessmentQuestion(
            id=qid, category=QuestionCategory.ENCRYPTION,
            text=text, weight=weight, control_reference=ref,
        ))

    # Incident Response (10 questions)
    ir_questions = [
        ("IR-01", "Does the vendor have a documented incident response plan?", 2.0, "SOC2 CC7.3 / ISO A.16.1"),
        ("IR-02", "Is the incident response plan tested at least annually?", 1.5, "ISO A.16.1.5"),
        ("IR-03", "Does the vendor have a dedicated security incident response team?", 1.5, "SOC2 CC7.3"),
        ("IR-04", "Can the vendor notify customers of a breach within 72 hours?", 2.0, "GDPR Art.33 / SOC2 CC7.3"),
        ("IR-05", "Does the vendor maintain an incident response runbook?", 1.0, "ISO A.16.1"),
        ("IR-06", "Are post-incident reviews conducted after significant events?", 1.0, "ISO A.16.1.6"),
        ("IR-07", "Does the vendor have cyber insurance coverage?", 1.0, "SOC2 CC9.1"),
        ("IR-08", "Is there a 24/7 security operations capability?", 1.5, "SOC2 CC7.2"),
        ("IR-09", "Does the vendor maintain forensic investigation capabilities?", 1.0, "ISO A.16.1.7"),
        ("IR-10", "Are incident severity levels defined with escalation procedures?", 1.0, "ISO A.16.1.5"),
    ]
    for qid, text, weight, ref in ir_questions:
        questions.append(AssessmentQuestion(
            id=qid, category=QuestionCategory.INCIDENT_RESPONSE,
            text=text, weight=weight, control_reference=ref,
        ))

    # Business Continuity (10 questions)
    bc_questions = [
        ("BC-01", "Does the vendor have a Business Continuity Plan (BCP)?", 2.0, "ISO A.17.1 / SOC2 A1"),
        ("BC-02", "Is the BCP tested at least annually?", 1.5, "ISO A.17.1.3"),
        ("BC-03", "Does the vendor have a Disaster Recovery Plan (DRP)?", 2.0, "ISO A.17.2"),
        ("BC-04", "Is the Recovery Time Objective (RTO) documented and tested?", 1.5, "SOC2 A1.2"),
        ("BC-05", "Is the Recovery Point Objective (RPO) documented and tested?", 1.5, "SOC2 A1.2"),
        ("BC-06", "Are backups stored in a geographically separate location?", 1.5, "ISO A.12.3"),
        ("BC-07", "Are backup restoration procedures tested quarterly?", 1.0, "ISO A.12.3.1"),
        ("BC-08", "Does the vendor operate from multiple data centers?", 1.0, "SOC2 A1.1"),
        ("BC-09", "Is there a documented communication plan for outages?", 1.0, "ISO A.17.1.2"),
        ("BC-10", "Does the vendor have a vendor/supplier continuity plan?", 1.0, "ISO A.17.2"),
    ]
    for qid, text, weight, ref in bc_questions:
        questions.append(AssessmentQuestion(
            id=qid, category=QuestionCategory.BUSINESS_CONTINUITY,
            text=text, weight=weight, control_reference=ref,
        ))

    # Data Handling (15 questions)
    dh_questions = [
        ("DH-01", "Does the vendor have a documented data classification policy?", 1.5, "ISO A.8.2"),
        ("DH-02", "Is customer data logically isolated from other customers' data?", 2.0, "SOC2 CC6.1"),
        ("DH-03", "Does the vendor have a data retention and deletion policy?", 1.5, "GDPR Art.5 / SOC2 CC6.5"),
        ("DH-04", "Can the vendor securely delete customer data upon contract termination?", 2.0, "GDPR Art.17"),
        ("DH-05", "Does the vendor disclose all sub-processors handling customer data?", 1.5, "GDPR Art.28"),
        ("DH-06", "Is a Data Processing Agreement (DPA) in place?", 2.0, "GDPR Art.28"),
        ("DH-07", "Does the vendor conduct annual privacy impact assessments?", 1.0, "GDPR Art.35"),
        ("DH-08", "Are data transfers to third countries covered by appropriate safeguards?", 1.5, "GDPR Art.44-49"),
        ("DH-09", "Does the vendor maintain a Record of Processing Activities (ROPA)?", 1.0, "GDPR Art.30"),
        ("DH-10", "Is data minimization practiced — only necessary data collected?", 1.0, "GDPR Art.5"),
        ("DH-11", "Does the vendor provide data portability upon request?", 1.0, "GDPR Art.20"),
        ("DH-12", "Are data access logs retained for at least 12 months?", 1.5, "SOC2 CC7.2 / PCI 10.7"),
        ("DH-13", "Is production data prohibited from use in development/test environments?", 1.5, "PCI 6.4.3 / SOC2 CC6.6"),
        ("DH-14", "Does the vendor have a data breach notification procedure?", 2.0, "GDPR Art.33 / SOC2 CC7.3"),
        ("DH-15", "Are data disposal methods (e.g. DoD 5220.22-M) documented?", 1.0, "ISO A.11.2.7"),
    ]
    for qid, text, weight, ref in dh_questions:
        questions.append(AssessmentQuestion(
            id=qid, category=QuestionCategory.DATA_HANDLING,
            text=text, weight=weight, control_reference=ref,
        ))

    # Network Security (10 questions)
    ns_questions = [
        ("NS-01", "Does the vendor employ network segmentation between environments?", 2.0, "PCI 1.3 / ISO A.13.1"),
        ("NS-02", "Are firewalls deployed and rule sets reviewed quarterly?", 1.5, "PCI 1.1"),
        ("NS-03", "Is intrusion detection/prevention (IDS/IPS) deployed?", 1.5, "SOC2 CC7.2 / ISO A.13.1"),
        ("NS-04", "Is web application firewall (WAF) protection in place?", 1.5, "PCI 6.6"),
        ("NS-05", "Does the vendor perform DDoS mitigation?", 1.0, "ISO A.13.1"),
        ("NS-06", "Is network traffic monitored and logged centrally?", 1.5, "SOC2 CC7.2 / PCI 10.6"),
        ("NS-07", "Are external-facing services subject to annual penetration testing?", 2.0, "PCI 11.3 / SOC2 CC4.1"),
        ("NS-08", "Is DNS security (DNSSEC) implemented?", 0.5, "ISO A.13.1"),
        ("NS-09", "Does the vendor have an asset inventory for network devices?", 1.0, "ISO A.8.1"),
        ("NS-10", "Are network access controls reviewed when personnel change roles?", 1.0, "SOC2 CC6.3"),
    ]
    for qid, text, weight, ref in ns_questions:
        questions.append(AssessmentQuestion(
            id=qid, category=QuestionCategory.NETWORK_SECURITY,
            text=text, weight=weight, control_reference=ref,
        ))

    # Physical Security (5 questions)
    ps_questions = [
        ("PS-01", "Are data centers where customer data is hosted SOC2 or ISO27001 certified?", 2.0, "ISO A.11.1"),
        ("PS-02", "Is physical access to data centers logged and reviewed?", 1.5, "PCI 9.1 / ISO A.11.1"),
        ("PS-03", "Are data center facilities subject to annual physical security audits?", 1.0, "ISO A.11.1.2"),
        ("PS-04", "Is CCTV and environmental monitoring (fire, flood, temperature) deployed?", 1.0, "ISO A.11.1.4"),
        ("PS-05", "Are media containing customer data physically secured and tracked?", 1.0, "PCI 9.6 / ISO A.11.2"),
    ]
    for qid, text, weight, ref in ps_questions:
        questions.append(AssessmentQuestion(
            id=qid, category=QuestionCategory.PHYSICAL_SECURITY,
            text=text, weight=weight, control_reference=ref,
        ))

    # Vulnerability Management (10 questions)
    vm_questions = [
        ("VM-01", "Does the vendor run authenticated vulnerability scans at least monthly?", 2.0, "PCI 11.2 / SOC2 CC7.1"),
        ("VM-02", "Are critical vulnerabilities remediated within 30 days?", 2.0, "PCI 6.3.3"),
        ("VM-03", "Is a Software Composition Analysis (SCA) tool used for open-source dependencies?", 1.5, "NIST CSF DE.CM"),
        ("VM-04", "Does the vendor have a responsible disclosure / bug bounty program?", 1.0, "ISO A.6.1"),
        ("VM-05", "Is static application security testing (SAST) integrated into the CI/CD pipeline?", 1.5, "SOC2 CC8.1"),
        ("VM-06", "Are container images scanned for vulnerabilities before deployment?", 1.5, "ISO A.12.6"),
        ("VM-07", "Does the vendor track CVE feeds and apply patches promptly?", 1.5, "PCI 6.3.3 / NIST ID.RA"),
        ("VM-08", "Are pentest findings tracked to remediation with SLAs?", 1.5, "SOC2 CC4.1"),
        ("VM-09", "Is dynamic application security testing (DAST) performed in staging?", 1.0, "OWASP ASVS"),
        ("VM-10", "Does the vendor maintain a security-aware SDLC (training, code review)?", 1.0, "SOC2 CC8.1"),
    ]
    for qid, text, weight, ref in vm_questions:
        questions.append(AssessmentQuestion(
            id=qid, category=QuestionCategory.VULNERABILITY_MANAGEMENT,
            text=text, weight=weight, control_reference=ref,
        ))

    # Third-Party Management (10 questions)
    tp_questions = [
        ("TP-01", "Does the vendor assess the security posture of its own sub-processors?", 2.0, "ISO A.15.2 / GDPR Art.28"),
        ("TP-02", "Are security requirements included in sub-processor contracts?", 1.5, "ISO A.15.1"),
        ("TP-03", "Does the vendor maintain a register of all sub-processors?", 1.5, "GDPR Art.28"),
        ("TP-04", "Are sub-processor security assessments conducted annually?", 1.5, "ISO A.15.2"),
        ("TP-05", "Does the vendor notify customers before changing sub-processors?", 2.0, "GDPR Art.28"),
        ("TP-06", "Is vendor risk tiering used to prioritize assessment depth?", 1.0, "ISO A.15.1"),
        ("TP-07", "Does the vendor have the right to audit sub-processors?", 1.5, "ISO A.15.2"),
        ("TP-08", "Are sub-processors required to maintain equivalent security standards?", 1.5, "ISO A.15.1.2"),
        ("TP-09", "Is there a process to offboard sub-processors securely?", 1.0, "ISO A.15.2"),
        ("TP-10", "Does the vendor monitor sub-processor compliance continuously?", 1.0, "ISO A.15.2.2"),
    ]
    for qid, text, weight, ref in tp_questions:
        questions.append(AssessmentQuestion(
            id=qid, category=QuestionCategory.THIRD_PARTY_MANAGEMENT,
            text=text, weight=weight, control_reference=ref,
        ))

    # Compliance (10 questions)
    comp_questions = [
        ("CL-01", "Is the vendor certified to SOC2 Type II or equivalent?", 2.0, "SOC2"),
        ("CL-02", "Are compliance certifications renewed before expiry?", 1.5, "ISO A.18.1"),
        ("CL-03", "Does the vendor conduct annual internal compliance audits?", 1.5, "ISO A.18.2"),
        ("CL-04", "Are employees trained on compliance requirements annually?", 1.0, "SOC2 CC1.4"),
        ("CL-05", "Does the vendor have a compliance officer or equivalent role?", 1.0, "ISO A.18.1"),
        ("CL-06", "Is the vendor subject to regulatory oversight (e.g. FCA, SEC)?", 1.0, "ISO A.18.1.1"),
        ("CL-07", "Are compliance violations tracked and remediated with root cause analysis?", 1.5, "SOC2 CC4.2"),
        ("CL-08", "Does the vendor support customer compliance audits and requests?", 1.5, "SOC2 CC2.3"),
        ("CL-09", "Are changes to compliance posture communicated to customers proactively?", 1.0, "SOC2 CC2.3"),
        ("CL-10", "Does the vendor maintain evidence of compliance for at least 3 years?", 1.0, "SOC2 / ISO A.18.1"),
    ]
    for qid, text, weight, ref in comp_questions:
        questions.append(AssessmentQuestion(
            id=qid, category=QuestionCategory.COMPLIANCE,
            text=text, weight=weight, control_reference=ref,
        ))

    return questions


_QUESTIONNAIRE: List[AssessmentQuestion] = _build_questionnaire()
_QUESTION_MAP: Dict[str, AssessmentQuestion] = {q.id: q for q in _QUESTIONNAIRE}


# ============================================================================
# TIERING LOGIC
# ============================================================================


_SENSITIVE_ACCESS_LEVELS = {
    DataAccessLevel.RESTRICTED,
    DataAccessLevel.SECRET,
    DataAccessLevel.CONFIDENTIAL,
}


def _compute_tier(vendor: Vendor) -> VendorTier:
    """Auto-tier a vendor based on data access and operational criticality."""
    is_sensitive = vendor.data_access_level in _SENSITIVE_ACCESS_LEVELS
    is_core = vendor.is_core_operations

    if is_sensitive and is_core:
        return VendorTier.CRITICAL
    if is_sensitive or is_core:
        return VendorTier.HIGH
    if vendor.data_access_level in (DataAccessLevel.INTERNAL, DataAccessLevel.PUBLIC):
        return VendorTier.MEDIUM
    return VendorTier.LOW


_TIER_ASSESSMENT_REQUIREMENTS: Dict[str, Dict[str, Any]] = {
    VendorTier.CRITICAL.value: {
        "full_questionnaire": True,
        "questionnaire_frequency_months": 6,
        "onsite_audit_required": True,
        "continuous_monitoring": True,
        "contract_review_months": 12,
        "categories_required": [c.value for c in QuestionCategory],
    },
    VendorTier.HIGH.value: {
        "full_questionnaire": True,
        "questionnaire_frequency_months": 12,
        "onsite_audit_required": False,
        "continuous_monitoring": True,
        "contract_review_months": 24,
        "categories_required": [
            QuestionCategory.ACCESS_CONTROL.value,
            QuestionCategory.ENCRYPTION.value,
            QuestionCategory.INCIDENT_RESPONSE.value,
            QuestionCategory.DATA_HANDLING.value,
            QuestionCategory.VULNERABILITY_MANAGEMENT.value,
        ],
    },
    VendorTier.MEDIUM.value: {
        "full_questionnaire": False,
        "questionnaire_frequency_months": 24,
        "onsite_audit_required": False,
        "continuous_monitoring": False,
        "contract_review_months": 36,
        "categories_required": [
            QuestionCategory.ACCESS_CONTROL.value,
            QuestionCategory.DATA_HANDLING.value,
            QuestionCategory.COMPLIANCE.value,
        ],
    },
    VendorTier.LOW.value: {
        "full_questionnaire": False,
        "questionnaire_frequency_months": 36,
        "onsite_audit_required": False,
        "continuous_monitoring": False,
        "contract_review_months": 48,
        "categories_required": [QuestionCategory.COMPLIANCE.value],
    },
}


# ============================================================================
# CONTRACT RISK ANALYSIS
# ============================================================================


def _analyze_contract_risks(vendor: Vendor) -> List[ContractRisk]:
    """Detect contract risk gaps for a vendor."""
    risks: List[ContractRisk] = []
    sla = vendor.sla_terms

    # Missing breach notification requirement (>72h is risky)
    if sla.breach_notification_hours > 72:
        risks.append(ContractRisk(
            vendor_id=vendor.id,
            risk_type=ContractRiskType.MISSING_BREACH_NOTIFICATION,
            severity=RiskSignalSeverity.HIGH,
            description=f"Breach notification SLA is {sla.breach_notification_hours}h — exceeds the 72h GDPR/industry standard.",
            recommendation="Negotiate breach notification to ≤72 hours in the contract.",
        ))

    # Missing audit rights (data_return_days=0 treated as no audit clause awareness)
    if sla.data_return_days > 90:
        risks.append(ContractRisk(
            vendor_id=vendor.id,
            risk_type=ContractRiskType.MISSING_DATA_RETURN,
            severity=RiskSignalSeverity.MEDIUM,
            description=f"Data return SLA is {sla.data_return_days} days — exceeds 90-day best practice.",
            recommendation="Negotiate data return to ≤30 days on contract termination.",
        ))

    # Low uptime SLA
    if sla.uptime_percent < 99.5:
        risks.append(ContractRisk(
            vendor_id=vendor.id,
            risk_type=ContractRiskType.UNLIMITED_LIABILITY_GAP,
            severity=RiskSignalSeverity.MEDIUM,
            description=f"Uptime SLA of {sla.uptime_percent}% is below 99.5% industry standard for critical services.",
            recommendation="Negotiate higher uptime SLA with financial penalties for non-compliance.",
        ))

    # Expired or missing certifications
    for cert_record in vendor.certifications:
        if cert_record.is_expired:
            risks.append(ContractRisk(
                vendor_id=vendor.id,
                risk_type=ContractRiskType.EXPIRED_CERT,
                severity=RiskSignalSeverity.HIGH,
                description=f"Certification {cert_record.cert.value} expired on {cert_record.expiry_date}.",
                recommendation=f"Request updated {cert_record.cert.value} report from vendor.",
            ))

    # Critical vendors must have SOC2 Type II
    if vendor.tier == VendorTier.CRITICAL:
        has_soc2 = any(
            c.cert == ComplianceCert.SOC2_TYPE2 and not c.is_expired
            for c in vendor.certifications
        )
        if not has_soc2:
            risks.append(ContractRisk(
                vendor_id=vendor.id,
                risk_type=ContractRiskType.MISSING_SECURITY_STANDARDS,
                severity=RiskSignalSeverity.CRITICAL,
                description="Critical vendor lacks a current SOC2 Type II certification.",
                recommendation="Require SOC2 Type II as a contractual obligation with audit rights.",
            ))

    return risks


# ============================================================================
# SCORECARD CALCULATION
# ============================================================================

_SCORECARD_WEIGHTS: Dict[str, float] = {
    "questionnaire": 0.40,
    "monitoring": 0.30,
    "contract": 0.20,
    "incident": 0.10,
}

_SEVERITY_PENALTY: Dict[str, float] = {
    RiskSignalSeverity.CRITICAL.value: 25.0,
    RiskSignalSeverity.HIGH.value: 15.0,
    RiskSignalSeverity.MEDIUM.value: 8.0,
    RiskSignalSeverity.LOW.value: 3.0,
    RiskSignalSeverity.INFO.value: 0.5,
}


def _score_to_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _compute_monitoring_score(signals: List[RiskSignal]) -> float:
    """Compute a 0-100 monitoring score based on active risk signals."""
    active = [s for s in signals if s.is_active]
    if not active:
        return 100.0
    penalty = sum(_SEVERITY_PENALTY.get(s.severity.value, 5.0) for s in active)
    return max(0.0, 100.0 - penalty)


def _compute_contract_score(risks: List[ContractRisk]) -> float:
    """Compute a 0-100 contract score based on unresolved contract gaps."""
    open_risks = [r for r in risks if r.remediated_at is None]
    if not open_risks:
        return 100.0
    penalty = sum(_SEVERITY_PENALTY.get(r.severity.value, 5.0) for r in open_risks)
    return max(0.0, 100.0 - penalty)


# ============================================================================
# SQLITE PERSISTENCE
# ============================================================================


class _VendorDB:
    """Thin SQLite wrapper for the VRM engine."""

    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS vendors (
                        id              TEXT PRIMARY KEY,
                        data            TEXT NOT NULL,
                        created_at      TEXT NOT NULL,
                        updated_at      TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS assessments (
                        id          TEXT PRIMARY KEY,
                        vendor_id   TEXT NOT NULL,
                        data        TEXT NOT NULL,
                        submitted_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_asm_vendor
                        ON assessments (vendor_id, submitted_at);

                    CREATE TABLE IF NOT EXISTS risk_signals (
                        id          TEXT PRIMARY KEY,
                        vendor_id   TEXT NOT NULL,
                        data        TEXT NOT NULL,
                        detected_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_sig_vendor
                        ON risk_signals (vendor_id, detected_at);

                    CREATE TABLE IF NOT EXISTS contract_risks (
                        id          TEXT PRIMARY KEY,
                        vendor_id   TEXT NOT NULL,
                        data        TEXT NOT NULL,
                        detected_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_ctr_vendor
                        ON contract_risks (vendor_id, detected_at);

                    CREATE TABLE IF NOT EXISTS fourth_party_risks (
                        id                      TEXT PRIMARY KEY,
                        first_party_vendor_id   TEXT NOT NULL,
                        fourth_party_vendor_id  TEXT NOT NULL,
                        data                    TEXT NOT NULL,
                        detected_at             TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_4pr_first
                        ON fourth_party_risks (first_party_vendor_id);

                    CREATE TABLE IF NOT EXISTS scorecard_history (
                        id          TEXT PRIMARY KEY,
                        vendor_id   TEXT NOT NULL,
                        score       REAL NOT NULL,
                        grade       TEXT NOT NULL,
                        calculated_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_sc_vendor_ts
                        ON scorecard_history (vendor_id, calculated_at);
                """)
                conn.commit()
            finally:
                conn.close()

    # --- Vendors ---

    def upsert_vendor(self, vendor: Vendor) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO vendors (id, data, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (vendor.id, vendor.model_dump_json(), vendor.created_at, now),
                )
                conn.commit()
            finally:
                conn.close()

    def get_vendor(self, vendor_id: str) -> Optional[Vendor]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT data FROM vendors WHERE id = ?", (vendor_id,)).fetchone()
                return Vendor.model_validate_json(row["data"]) if row else None
            finally:
                conn.close()

    def list_vendors(self) -> List[Vendor]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT data FROM vendors ORDER BY updated_at DESC").fetchall()
                return [Vendor.model_validate_json(r["data"]) for r in rows]
            finally:
                conn.close()

    # --- Assessments ---

    def upsert_assessment(self, assessment: VendorAssessment) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO assessments (id, vendor_id, data, submitted_at) VALUES (?, ?, ?, ?)",
                    (assessment.id, assessment.vendor_id, assessment.model_dump_json(), assessment.submitted_at),
                )
                conn.commit()
            finally:
                conn.close()

    def get_latest_assessment(self, vendor_id: str) -> Optional[VendorAssessment]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT data FROM assessments WHERE vendor_id = ? ORDER BY submitted_at DESC LIMIT 1",
                    (vendor_id,),
                ).fetchone()
                return VendorAssessment.model_validate_json(row["data"]) if row else None
            finally:
                conn.close()

    # --- Risk Signals ---

    def insert_signal(self, signal: RiskSignal) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO risk_signals (id, vendor_id, data, detected_at) VALUES (?, ?, ?, ?)",
                    (signal.id, signal.vendor_id, signal.model_dump_json(), signal.detected_at),
                )
                conn.commit()
            finally:
                conn.close()

    def get_signals(self, vendor_id: str) -> List[RiskSignal]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT data FROM risk_signals WHERE vendor_id = ? ORDER BY detected_at DESC",
                    (vendor_id,),
                ).fetchall()
                return [RiskSignal.model_validate_json(r["data"]) for r in rows]
            finally:
                conn.close()

    # --- Contract Risks ---

    def upsert_contract_risks(self, risks: List[ContractRisk]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                for r in risks:
                    conn.execute(
                        "INSERT OR REPLACE INTO contract_risks (id, vendor_id, data, detected_at) VALUES (?, ?, ?, ?)",
                        (r.id, r.vendor_id, r.model_dump_json(), r.detected_at),
                    )
                conn.commit()
            finally:
                conn.close()

    def get_contract_risks(self, vendor_id: str) -> List[ContractRisk]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT data FROM contract_risks WHERE vendor_id = ? ORDER BY detected_at DESC",
                    (vendor_id,),
                ).fetchall()
                return [ContractRisk.model_validate_json(r["data"]) for r in rows]
            finally:
                conn.close()

    # --- Fourth-Party Risks ---

    def upsert_fourth_party_risk(self, risk: FourthPartyRisk) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO fourth_party_risks "
                    "(id, first_party_vendor_id, fourth_party_vendor_id, data, detected_at) VALUES (?, ?, ?, ?, ?)",
                    (risk.id, risk.first_party_vendor_id, risk.fourth_party_vendor_id,
                     risk.model_dump_json(), risk.detected_at),
                )
                conn.commit()
            finally:
                conn.close()

    def get_fourth_party_risks(self, first_party_vendor_id: str) -> List[FourthPartyRisk]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT data FROM fourth_party_risks WHERE first_party_vendor_id = ?",
                    (first_party_vendor_id,),
                ).fetchall()
                return [FourthPartyRisk.model_validate_json(r["data"]) for r in rows]
            finally:
                conn.close()

    def get_all_fourth_party_risks(self) -> List[FourthPartyRisk]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT data FROM fourth_party_risks").fetchall()
                return [FourthPartyRisk.model_validate_json(r["data"]) for r in rows]
            finally:
                conn.close()

    # --- Scorecard History ---

    def insert_scorecard_snapshot(self, vendor_id: str, score: float, grade: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        snapshot_id = f"sc-{uuid.uuid4().hex[:12]}"
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO scorecard_history (id, vendor_id, score, grade, calculated_at) VALUES (?, ?, ?, ?, ?)",
                    (snapshot_id, vendor_id, score, grade, now),
                )
                conn.commit()
            finally:
                conn.close()

    def get_scorecard_trend(self, vendor_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT score, grade, calculated_at FROM scorecard_history "
                    "WHERE vendor_id = ? ORDER BY calculated_at DESC LIMIT ?",
                    (vendor_id, limit),
                ).fetchall()
                return [{"score": r["score"], "grade": r["grade"], "calculated_at": r["calculated_at"]} for r in rows]
            finally:
                conn.close()


# ============================================================================
# VRM ENGINE
# ============================================================================


class VendorRiskEngine:
    """
    Vendor Risk Management engine — central coordinator for all VRM operations.

    Thread-safe. Backed by SQLite. Supports multi-tenant usage via db_path
    namespacing.
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self._db = _VendorDB(db_path)
        _logger.info("VendorRiskEngine initialised", db_path=db_path)

    # ------------------------------------------------------------------
    # Vendor Registry
    # ------------------------------------------------------------------

    def register_vendor(self, vendor: Vendor) -> Vendor:
        """Add or update a vendor in the registry. Auto-computes tier."""
        vendor.tier = _compute_tier(vendor)
        self._db.upsert_vendor(vendor)

        # Auto-analyze contract risks on registration/update
        contract_risks = _analyze_contract_risks(vendor)
        if contract_risks:
            self._db.upsert_contract_risks(contract_risks)
            _logger.warning(
                "Contract risks detected on vendor registration",
                vendor_id=vendor.id,
                risk_count=len(contract_risks),
            )

        _logger.info("Vendor registered", vendor_id=vendor.id, tier=vendor.tier.value)
        _emit_event(
            "vendor.registered",
            {
                "vendor_id": vendor.id,
                "tier": vendor.tier.value,
                "contract_risk_count": len(contract_risks) if contract_risks else 0,
            },
        )
        return vendor

    def get_vendor(self, vendor_id: str) -> Optional[Vendor]:
        """Retrieve a vendor by ID with current score populated."""
        vendor = self._db.get_vendor(vendor_id)
        if vendor:
            scorecard = self.compute_scorecard(vendor_id)
            if scorecard:
                vendor.current_score = scorecard.overall_score
        return vendor

    def list_vendors(self) -> List[Vendor]:
        """List all vendors with current scores."""
        vendors = self._db.list_vendors()
        result: List[Vendor] = []
        for vendor in vendors:
            scorecard = self.compute_scorecard(vendor.id)
            if scorecard:
                vendor.current_score = scorecard.overall_score
            result.append(vendor)
        return result

    # ------------------------------------------------------------------
    # Questionnaire
    # ------------------------------------------------------------------

    def get_questionnaire(self) -> List[AssessmentQuestion]:
        """Return the full SIG-based assessment questionnaire."""
        return _QUESTIONNAIRE

    def submit_questionnaire(
        self,
        vendor_id: str,
        responses: List[QuestionnaireResponse],
        assessed_by: str = "system",
    ) -> VendorAssessment:
        """Score questionnaire responses and persist the assessment."""
        total_weight = 0.0
        earned_weight = 0.0
        category_earned: Dict[str, float] = {}
        category_total: Dict[str, float] = {}

        for resp in responses:
            question = _QUESTION_MAP.get(resp.question_id)
            if not question:
                continue

            cat = question.category.value
            category_total[cat] = category_total.get(cat, 0.0) + question.weight
            category_earned.setdefault(cat, 0.0)

            total_weight += question.weight
            if resp.answer == question.expected_answer:
                earned_weight += question.weight
                category_earned[cat] += question.weight

        questionnaire_score = (earned_weight / total_weight * 100.0) if total_weight > 0 else 0.0
        category_scores = {
            cat: (category_earned.get(cat, 0.0) / category_total[cat] * 100.0)
            for cat in category_total
        }

        assessment = VendorAssessment(
            vendor_id=vendor_id,
            responses=responses,
            questionnaire_score=round(questionnaire_score, 2),
            category_scores={k: round(v, 2) for k, v in category_scores.items()},
            assessed_by=assessed_by,
        )
        self._db.upsert_assessment(assessment)
        _logger.info(
            "Questionnaire submitted",
            vendor_id=vendor_id,
            score=assessment.questionnaire_score,
            question_count=len(responses),
        )
        _emit_event(
            "vendor.assessed",
            {
                "vendor_id": vendor_id,
                "score": assessment.questionnaire_score,
                "question_count": len(responses),
                "assessed_by": assessed_by,
            },
        )
        return assessment

    def get_assessment(self, vendor_id: str) -> Optional[VendorAssessment]:
        """Return the latest assessment for a vendor."""
        return self._db.get_latest_assessment(vendor_id)

    # ------------------------------------------------------------------
    # Continuous Monitoring
    # ------------------------------------------------------------------

    def record_risk_signal(self, signal: RiskSignal) -> RiskSignal:
        """Record a monitoring risk signal for a vendor."""
        self._db.insert_signal(signal)

        # Propagate transitive risk to all vendors that depend on this one
        if signal.severity in (RiskSignalSeverity.HIGH, RiskSignalSeverity.CRITICAL):
            self._propagate_fourth_party_risk(signal)

        _logger.info(
            "Risk signal recorded",
            vendor_id=signal.vendor_id,
            signal_type=signal.signal_type.value,
            severity=signal.severity.value,
        )
        _emit_event(
            "vendor.risk_signal",
            {
                "vendor_id": signal.vendor_id,
                "signal_type": signal.signal_type.value,
                "severity": signal.severity.value,
            },
        )
        return signal

    def get_monitoring_data(self, vendor_id: str) -> Dict[str, Any]:
        """Return monitoring signals, latest security rating, and active risk summary."""
        signals = self._db.get_signals(vendor_id)

        # Latest security rating
        rating_signals = [s for s in signals if s.signal_type == RiskSignalType.SECURITY_RATING]
        latest_rating: Optional[Dict[str, Any]] = None
        if rating_signals:
            latest = rating_signals[0]
            latest_rating = {
                "score": latest.metadata.get("score", 0),
                "grade": latest.metadata.get("grade", "F"),
                "recorded_at": latest.detected_at,
            }

        active = [s for s in signals if s.is_active]
        severity_counts: Dict[str, int] = {}
        for s in active:
            severity_counts[s.severity.value] = severity_counts.get(s.severity.value, 0) + 1

        return {
            "vendor_id": vendor_id,
            "total_signals": len(signals),
            "active_signals": len(active),
            "severity_breakdown": severity_counts,
            "latest_security_rating": latest_rating,
            "signals": [s.model_dump() for s in signals[:20]],  # Most recent 20
        }

    # ------------------------------------------------------------------
    # Tiering
    # ------------------------------------------------------------------

    def get_tiering_overview(self) -> TieringOverview:
        """Build tiering overview across the vendor registry."""
        vendors = self._db.list_vendors()
        tier_map: Dict[str, List[str]] = {t.value: [] for t in VendorTier}
        untiered: List[str] = []

        for vendor in vendors:
            if vendor.tier:
                tier_map[vendor.tier.value].append(vendor.name)
            else:
                untiered.append(vendor.name)

        return TieringOverview(
            critical_count=len(tier_map[VendorTier.CRITICAL.value]),
            high_count=len(tier_map[VendorTier.HIGH.value]),
            medium_count=len(tier_map[VendorTier.MEDIUM.value]),
            low_count=len(tier_map[VendorTier.LOW.value]),
            untiered_count=len(untiered),
            tier_breakdown=tier_map,
            assessment_requirements=_TIER_ASSESSMENT_REQUIREMENTS,
        )

    # ------------------------------------------------------------------
    # Fourth-Party Risk
    # ------------------------------------------------------------------

    def _propagate_fourth_party_risk(self, signal: RiskSignal) -> None:
        """Propagate a high/critical signal as transitive risk to dependent vendors."""
        all_vendors = self._db.list_vendors()
        affected_vendors = [
            v for v in all_vendors
            if signal.vendor_id in v.fourth_party_vendors
        ]

        for affected in affected_vendors:
            fp_risk = FourthPartyRisk(
                first_party_vendor_id=affected.id,
                fourth_party_vendor_id=signal.vendor_id,
                fourth_party_name=affected.name,
                transitive_risk_level=signal.severity,
                trigger_signal_id=signal.id,
                description=(
                    f"Fourth-party risk: your vendor dependency '{signal.vendor_id}' "
                    f"triggered a {signal.severity.value} signal: {signal.title}"
                ),
            )
            self._db.upsert_fourth_party_risk(fp_risk)
            _logger.warning(
                "Fourth-party risk propagated",
                first_party_vendor_id=affected.id,
                fourth_party_vendor_id=signal.vendor_id,
                severity=signal.severity.value,
            )

    def get_fourth_party_map(self) -> FourthPartyMap:
        """Build the complete fourth-party dependency and risk map."""
        vendors = self._db.list_vendors()
        all_risks = self._db.get_all_fourth_party_risks()

        # Build dependency chains
        dependency_chains: List[Dict[str, Any]] = []
        for vendor in vendors:
            if vendor.fourth_party_vendors:
                dependency_chains.append({
                    "vendor_id": vendor.id,
                    "vendor_name": vendor.name,
                    "fourth_parties": vendor.fourth_party_vendors,
                    "dependency_count": len(vendor.fourth_party_vendors),
                })

        # High-risk fourth parties
        high_risk_fp: List[Dict[str, Any]] = [
            r.model_dump() for r in all_risks
            if r.transitive_risk_level in (RiskSignalSeverity.HIGH, RiskSignalSeverity.CRITICAL)
        ]

        fourth_party_ids: set = set()
        for vendor in vendors:
            fourth_party_ids.update(vendor.fourth_party_vendors)

        return FourthPartyMap(
            direct_vendor_count=len(vendors),
            fourth_party_count=len(fourth_party_ids),
            active_transitive_risks=len(all_risks),
            dependency_chains=dependency_chains,
            high_risk_fourth_parties=high_risk_fp,
        )

    # ------------------------------------------------------------------
    # Scorecard
    # ------------------------------------------------------------------

    def compute_scorecard(self, vendor_id: str) -> Optional[VendorScorecard]:
        """Compute and persist the composite vendor scorecard."""
        vendor = self._db.get_vendor(vendor_id)
        if not vendor:
            return None

        tier = vendor.tier or _compute_tier(vendor)
        assessment = self._db.get_latest_assessment(vendor_id)
        signals = self._db.get_signals(vendor_id)
        contract_risks = self._db.get_contract_risks(vendor_id)
        trend = self._db.get_scorecard_trend(vendor_id)

        questionnaire_score = assessment.questionnaire_score if assessment else 0.0
        monitoring_score = _compute_monitoring_score(signals)
        contract_score = _compute_contract_score(contract_risks)
        # Incident score: 100 if no breach signals, else reduce
        breach_signals = [
            s for s in signals
            if s.signal_type == RiskSignalType.BREACH_HISTORY and s.is_active
        ]
        incident_score = max(0.0, 100.0 - (len(breach_signals) * 30.0))

        overall = (
            questionnaire_score * _SCORECARD_WEIGHTS["questionnaire"]
            + monitoring_score * _SCORECARD_WEIGHTS["monitoring"]
            + contract_score * _SCORECARD_WEIGHTS["contract"]
            + incident_score * _SCORECARD_WEIGHTS["incident"]
        )
        overall = round(overall, 2)
        grade = _score_to_grade(overall)

        # Persist snapshot for trend tracking
        self._db.insert_scorecard_snapshot(vendor_id, overall, grade)

        return VendorScorecard(
            vendor_id=vendor_id,
            vendor_name=vendor.name,
            tier=tier,
            overall_score=overall,
            grade=grade,
            questionnaire_score=round(questionnaire_score, 2),
            monitoring_score=round(monitoring_score, 2),
            contract_score=round(contract_score, 2),
            incident_score=round(incident_score, 2),
            score_trend=trend,
            active_risks=sum(1 for s in signals if s.is_active),
            contract_gaps=sum(1 for r in contract_risks if r.remediated_at is None),
        )

    def get_contract_risks(self, vendor_id: str) -> List[ContractRisk]:
        """Return all contract risks for a vendor."""
        return self._db.get_contract_risks(vendor_id)


# ============================================================================
# MODULE-LEVEL SINGLETON
# ============================================================================

_engine: Optional[VendorRiskEngine] = None


def get_engine(db_path: str = _DEFAULT_DB_PATH) -> VendorRiskEngine:
    """Return the module-level VendorRiskEngine singleton."""
    global _engine
    if _engine is None:
        _engine = VendorRiskEngine(db_path=db_path)
    return _engine
