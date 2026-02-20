"""
Security-related models for FixOps Enterprise
Findings, Vulnerabilities, Incidents, Services, Policies
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from core.models.enterprise.base import AuditMixin, BaseModel, SoftDeleteMixin
from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScannerType(str, Enum):
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    IAST = "iast"
    RASP = "rasp"
    IAC = "iac"
    CONTAINER = "container"
    VM = "vm"
    CNAPP = "cnapp"
    SECRETS = "secrets"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    WAIVED = "waived"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"
    PCI = "pci"
    PHI = "phi"


class Environment(str, Enum):
    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"


class PolicyDecision(str, Enum):
    BLOCK = "block"
    ALLOW = "allow"
    DEFER = "defer"
    FIX = "fix"
    MITIGATE = "mitigate"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Service(BaseModel, AuditMixin, SoftDeleteMixin):
    """Service registry with business context and security metadata"""

    __tablename__ = "services"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    business_capability: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )

    # Data and environment context
    data_classification: Mapped[List[str]] = mapped_column(
        ARRAY(String(50)), nullable=False
    )
    environment: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Ownership and responsibility
    owner_team: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_email: Mapped[str] = mapped_column(String(255), nullable=False)
    technical_lead: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Technical metadata
    repository_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    deployment_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    documentation_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Risk and exposure
    internet_facing: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    pci_scope: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Service dependencies
    dependencies: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String(255)), nullable=True
    )

    # Technology stack
    tech_stack: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # SLA and criticality
    sla_tier: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    business_criticality: Mapped[str] = mapped_column(
        String(50), default="medium", nullable=False
    )

    # Relationships
    findings: Mapped[List["SecurityFinding"]] = relationship(
        "SecurityFinding", back_populates="service"
    )
    incidents: Mapped[List["SecurityIncident"]] = relationship(
        "SecurityIncident", back_populates="service"
    )


class SecurityFinding(BaseModel, AuditMixin, SoftDeleteMixin):
    """Security findings from various scanners with enriched context"""

    __tablename__ = "security_findings"

    # Service relationship
    service_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("services.id"), nullable=False, index=True
    )

    # Scanner metadata
    scanner_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    scanner_name: Mapped[str] = mapped_column(String(255), nullable=False)
    scanner_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    scan_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True
    )

    # Finding identification
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    external_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True
    )
    fingerprint: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True
    )

    # Core finding data
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    category: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Vulnerability details
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Location and context
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    function_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Web application specific
    url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)

    # Code and evidence
    code_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Status and lifecycle
    status: Mapped[str] = mapped_column(
        String(50), default="open", nullable=False, index=True
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # Business impact and context
    business_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exploitability_grade: Mapped[Optional[str]] = mapped_column(
        String(10), nullable=True
    )

    # Remediation
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_effort: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Assignment and tracking
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    service: Mapped["Service"] = relationship("Service", back_populates="findings")
    correlations: Mapped[List["FindingCorrelation"]] = relationship(
        "FindingCorrelation",
        foreign_keys="FindingCorrelation.finding_id",
        back_populates="finding",
    )


class FindingCorrelation(BaseModel):
    """Correlation between multiple findings to reduce noise"""

    __tablename__ = "finding_correlations"

    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_findings.id"), nullable=False
    )
    correlated_finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_findings.id"), nullable=False
    )
    correlation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    correlation_reason: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationships
    finding: Mapped["SecurityFinding"] = relationship(
        "SecurityFinding", foreign_keys=[finding_id]
    )


class KevFindingWaiver(BaseModel, AuditMixin, SoftDeleteMixin):
    """Auditable waiver record for Known Exploited Vulnerabilities"""

    __tablename__ = "kev_waivers"

    cve_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    service_name: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True
    )
    finding_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True, index=True
    )
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    change_ticket: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    def is_active_for(
        self, *, service_name: Optional[str], now: Optional[datetime] = None
    ) -> bool:
        """Return True when the waiver is active for the requested scope."""

        if not self.is_active:
            return False

        if now is None:
            now = datetime.utcnow()

        # Normalize timezone aware timestamps to naive UTC for comparison
        expiry = self.expires_at
        if expiry.tzinfo is not None:
            expiry = expiry.astimezone(timezone.utc).replace(tzinfo=None)

        if expiry < now:
            return False

        if self.service_name and service_name:
            return self.service_name.lower() == service_name.lower()

        return self.service_name is None or service_name is None


class SecurityIncident(BaseModel, AuditMixin, SoftDeleteMixin):
    """Security incidents created from findings or external sources"""

    __tablename__ = "security_incidents"

    # Service relationship
    service_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("services.id"), nullable=True, index=True
    )

    # Incident identification
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(50), default="open", nullable=False, index=True
    )

    # Classification and impact
    incident_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    business_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_users: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Assignment and workflow
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    reporter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Timeline
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # External tracking
    external_ticket_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    external_ticket_url: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True
    )

    # Related findings
    related_findings: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String(36)), nullable=True
    )

    # Resolution and lessons learned
    resolution_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    service: Mapped[Optional["Service"]] = relationship(
        "Service", back_populates="incidents"
    )


class PolicyRule(BaseModel, AuditMixin, SoftDeleteMixin):
    """Security policy rules for automated decision making"""

    __tablename__ = "policy_rules"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Policy definition
    rule_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # rego, python, json
    rule_content: Mapped[str] = mapped_column(Text, nullable=False)

    # Scope and applicability
    environments: Mapped[List[str]] = mapped_column(ARRAY(String(50)), nullable=False)
    data_classifications: Mapped[List[str]] = mapped_column(
        ARRAY(String(50)), nullable=False
    )
    scanner_types: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String(50)), nullable=True
    )

    # NIST SSDF compliance
    nist_ssdf_controls: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String(20)), nullable=True
    )

    # Priority and execution
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Decision outcomes
    default_decision: Mapped[str] = mapped_column(String(50), nullable=False)
    escalation_threshold: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)


class PolicyDecisionLog(BaseModel):
    """Log of policy decisions for audit and compliance"""

    __tablename__ = "policy_decision_logs"

    # Context
    finding_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True, index=True
    )
    service_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True, index=True
    )

    # Policy execution
    policy_rule_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("policy_rules.id"), nullable=False
    )
    decision: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    # Context data used for decision
    input_context: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    decision_rationale: Mapped[str] = mapped_column(Text, nullable=False)

    # Execution metadata
    execution_time_ms: Mapped[float] = mapped_column(Float, nullable=False)
    policy_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)


class VulnerabilityIntelligence(BaseModel):
    """Vulnerability intelligence and threat data"""

    __tablename__ = "vulnerability_intelligence"

    # Vulnerability identification
    cve_id: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True, unique=True, index=True
    )
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)

    # Scoring and assessment
    cvss_v3_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Threat intelligence
    known_exploits: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exploit_maturity: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    threat_actor_activity: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    # Vendor and disclosure
    vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    disclosure_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Patches and fixes
    patch_available: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    patch_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    workaround_available: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    # Intelligence metadata
    intelligence_sources: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String(255)), nullable=True
    )
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ComplianceEvidence(BaseModel, AuditMixin):
    """Compliance evidence and attestations"""

    __tablename__ = "compliance_evidence"

    service_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("services.id"), nullable=False, index=True
    )

    # Compliance framework
    framework: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # NIST_SSDF, SOC2, etc.
    control_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    control_description: Mapped[str] = mapped_column(Text, nullable=False)

    # Evidence
    evidence_type: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    artifact_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )  # SHA-256 hash

    # Attestation
    attestation_status: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # compliant, non_compliant, partial
    attestor: Mapped[str] = mapped_column(String(255), nullable=False)
    attestation_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Validity and review
    valid_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    review_required: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    # Digital signature for integrity
    digital_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
