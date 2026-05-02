"""
TrustGraph Knowledge Core Schemas for ALDECI.

This module defines the 5 Knowledge Core schemas that TrustGraph uses to organize ALDECI's
security data. Each Core defines:
  - Entity types (nodes in the graph)
  - Relationship types (edges)
  - Property schemas (attributes on nodes/edges)

The Knowledge Cores are:
  1. Customer Environment (per-tenant) - assets, findings, deployment info
  2. Threat Intelligence (shared) - CVEs, attackers, exploits
  3. Compliance & Regulatory (versioned) - frameworks, controls, evidence
  4. Decision Memory (append-only) - triage, verdicts, remediation
  5. Competitive Intelligence - competitors, products, market segments

This is the data contract between connectors and TrustGraph.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ============================================================================
# Core 1: Customer Environment (per-tenant)
# ============================================================================

class Organization(BaseModel):
    """Organization entity - top-level tenant container."""
    id: str = Field(..., description="Unique organization identifier")
    name: str = Field(..., description="Organization name")
    industry: Optional[str] = Field(default=None, description="Industry classification")
    size: Optional[str] = Field(default=None, description="Organization size (startup, SMB, enterprise)")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Team(BaseModel):
    """Team entity - group within organization."""
    id: str
    name: str
    org_id: str = Field(..., description="Parent organization ID")
    function: Optional[str] = Field(default=None, description="Team function (security, devops, platform, etc.)")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Service(BaseModel):
    """Service entity - application or microservice."""
    id: str
    name: str
    org_id: str
    team_id: Optional[str] = None
    service_type: str = Field(..., description="Type: api, webapp, worker, library, etc.")
    criticality: Optional[str] = Field(default=None, description="Criticality level: critical, high, medium, low")
    owner: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Repository(BaseModel):
    """Repository entity - source code repository."""
    id: str
    name: str
    org_id: str
    url: str
    service_id: Optional[str] = None
    language: Optional[str] = None
    visibility: str = Field(default="private", description="public or private")
    default_branch: str = Field(default="main")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Artifact(BaseModel):
    """Artifact entity - built artifact (binary, library, image)."""
    id: str
    name: str
    org_id: str
    artifact_type: str = Field(..., description="Type: docker_image, jar, wheel, gem, npm_package, etc.")
    version: str
    registry: Optional[str] = None
    checksum: Optional[str] = None
    size_bytes: Optional[int] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Container(BaseModel):
    """Container entity - running container instance."""
    id: str
    name: str
    org_id: str
    artifact_id: Optional[str] = None
    image_digest: Optional[str] = None
    status: str = Field(default="running", description="running, stopped, failed, etc.")
    environment: str = Field(..., description="dev, staging, prod, etc.")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class CloudAccount(BaseModel):
    """CloudAccount entity - cloud platform account (AWS, GCP, Azure)."""
    id: str
    name: str
    org_id: str
    provider: str = Field(..., description="aws, gcp, azure, etc.")
    account_id: str
    environment: str = Field(..., description="dev, staging, prod")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Endpoint(BaseModel):
    """Endpoint entity - network endpoint (server, device)."""
    id: str
    hostname: Optional[str] = None
    ip_address: str
    org_id: str
    endpoint_type: str = Field(..., description="server, workstation, iot, etc.")
    os: Optional[str] = None
    status: str = Field(default="active")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class APIEndpoint(BaseModel):
    """APIEndpoint entity - API exposure."""
    id: str
    name: str
    org_id: str
    service_id: Optional[str] = None
    url: str
    method: str = Field(..., description="GET, POST, PUT, DELETE, etc.")
    authentication_required: bool = Field(default=False)
    public: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class User(BaseModel):
    """User entity - person in organization."""
    id: str
    org_id: str
    email: str
    name: Optional[str] = None
    team_id: Optional[str] = None
    role: Optional[str] = Field(default=None, description="admin, developer, security, etc.")
    active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Finding(BaseModel):
    """Finding entity - security finding/issue."""
    id: str
    org_id: str
    title: str
    description: Optional[str] = None
    severity: str = Field(..., description="critical, high, medium, low, info")
    status: str = Field(default="open", description="open, resolved, false_positive, accepted_risk")
    source: str = Field(..., description="sast, dast, sca, manual, etc.")
    found_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {'critical', 'high', 'medium', 'low', 'info'}
        if v.lower() not in valid:
            raise ValueError(f'Severity must be one of {valid}')
        return v.lower()

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Vulnerability(BaseModel):
    """Vulnerability entity - known vulnerability."""
    id: str
    org_id: str
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    affected_versions: List[str] = Field(default_factory=list)
    fixed_versions: List[str] = Field(default_factory=list)
    severity: str = Field(..., description="critical, high, medium, low")
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class SBOM(BaseModel):
    """SBOM entity - Software Bill of Materials."""
    id: str
    org_id: str
    artifact_id: Optional[str] = None
    service_id: Optional[str] = None
    components: List[Dict[str, Any]] = Field(default_factory=list, description="List of component entries")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    format: str = Field(default="spdx", description="spdx, cyclonedx, etc.")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Pipeline(BaseModel):
    """Pipeline entity - CI/CD pipeline."""
    id: str
    org_id: str
    name: str
    service_id: Optional[str] = None
    repository_id: Optional[str] = None
    platform: str = Field(..., description="github_actions, gitlab_ci, jenkins, etc.")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class PullRequest(BaseModel):
    """PullRequest entity - source code review."""
    id: str
    org_id: str
    repository_id: str
    number: int
    title: str
    status: str = Field(default="open", description="open, merged, closed")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    merged_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Commit(BaseModel):
    """Commit entity - source code commit."""
    id: str
    org_id: str
    repository_id: str
    sha: str
    message: str
    author: Optional[str] = None
    committed_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Branch(BaseModel):
    """Branch entity - source code branch."""
    id: str
    org_id: str
    repository_id: str
    name: str
    protected: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class K8sCluster(BaseModel):
    """K8sCluster entity - Kubernetes cluster."""
    id: str
    org_id: str
    name: str
    cloud_account_id: Optional[str] = None
    version: Optional[str] = None
    environment: str = Field(..., description="dev, staging, prod")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class K8sNamespace(BaseModel):
    """K8sNamespace entity - Kubernetes namespace."""
    id: str
    org_id: str
    cluster_id: str
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Pod(BaseModel):
    """Pod entity - Kubernetes pod."""
    id: str
    org_id: str
    namespace_id: str
    name: str
    status: str = Field(default="running")
    restart_count: int = Field(default=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class NetworkPolicy(BaseModel):
    """NetworkPolicy entity - network access policy."""
    id: str
    org_id: str
    name: str
    policy_type: str = Field(..., description="ingress, egress, etc.")
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class IAMRole(BaseModel):
    """IAMRole entity - IAM role for access control."""
    id: str
    org_id: str
    name: str
    cloud_account_id: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class DataStore(BaseModel):
    """DataStore entity - data storage location."""
    id: str
    org_id: str
    name: str
    cloud_account_id: Optional[str] = None
    store_type: str = Field(..., description="s3, rds, firestore, etc.")
    encryption_enabled: bool = Field(default=False)
    public_access: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 1})


class Core1RelationshipType(str, Enum):
    """Relationship types for Core 1: Customer Environment."""
    OWNS = "owns"
    MAINTAINS = "maintains"
    DEPENDS_ON = "depends_on"
    AFFECTS = "affects"
    DEPLOYED_TO = "deployed_to"
    RUNS_IN = "runs_in"
    HAS_PERMISSION = "has_permission"
    PROCESSES_DATA = "processes_data"
    EXPOSES = "exposes"
    TRIGGERS = "triggers"
    PRODUCES = "produces"
    CONSUMES = "consumes"
    AUTHORED_BY = "authored_by"
    REVIEWED_BY = "reviewed_by"
    CONTAINS = "contains"


CORE1_ENTITY_TYPES = {
    'Organization': Organization,
    'Team': Team,
    'Service': Service,
    'Repository': Repository,
    'Artifact': Artifact,
    'Container': Container,
    'CloudAccount': CloudAccount,
    'Endpoint': Endpoint,
    'APIEndpoint': APIEndpoint,
    'User': User,
    'Finding': Finding,
    'Vulnerability': Vulnerability,
    'SBOM': SBOM,
    'Pipeline': Pipeline,
    'PullRequest': PullRequest,
    'Commit': Commit,
    'Branch': Branch,
    'K8sCluster': K8sCluster,
    'K8sNamespace': K8sNamespace,
    'Pod': Pod,
    'NetworkPolicy': NetworkPolicy,
    'IAMRole': IAMRole,
    'DataStore': DataStore,
}


# ============================================================================
# Core 2: Threat Intelligence (shared)
# ============================================================================

class CVE(BaseModel):
    """CVE entity - Common Vulnerabilities and Exposures."""
    id: str
    cve_id: str = Field(..., description="e.g., CVE-2024-1234")
    title: str
    description: Optional[str] = None
    severity: str = Field(..., description="critical, high, medium, low")
    cvss_v3_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    published_date: datetime
    modified_date: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class CWE(BaseModel):
    """CWE entity - Common Weakness Enumeration."""
    id: str
    cwe_id: str = Field(..., description="e.g., CWE-79")
    title: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class ATTACKTechnique(BaseModel):
    """ATTACKTechnique entity - MITRE ATT&CK technique."""
    id: str
    technique_id: str = Field(..., description="e.g., T1055")
    name: str
    description: Optional[str] = None
    platforms: List[str] = Field(default_factory=list, description="windows, linux, macos, etc.")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class ATTACKTactic(BaseModel):
    """ATTACKTactic entity - MITRE ATT&CK tactic."""
    id: str
    tactic_id: str
    name: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class CAPEC(BaseModel):
    """CAPEC entity - Common Attack Pattern Expression and Enumeration."""
    id: str
    capec_id: str = Field(..., description="e.g., CAPEC-1")
    name: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class Exploit(BaseModel):
    """Exploit entity - known exploit code/PoC."""
    id: str
    name: str
    description: Optional[str] = None
    cve_id: Optional[str] = None
    source: Optional[str] = Field(default=None, description="Exploit-DB, GitHub, etc.")
    source_url: Optional[str] = None
    published_date: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class ThreatActor(BaseModel):
    """ThreatActor entity - known threat group/attacker."""
    id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    actor_type: str = Field(..., description="nation_state, criminal, hacktivist, insider, etc.")
    regions: List[str] = Field(default_factory=list)
    known_since: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class Campaign(BaseModel):
    """Campaign entity - threat campaign."""
    id: str
    name: str
    description: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    targets: List[str] = Field(default_factory=list, description="Industries, sectors")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class Indicator(BaseModel):
    """Indicator entity - IoC (Indicator of Compromise)."""
    id: str
    ioc_type: str = Field(..., description="ip, domain, hash, url, email, file, process, etc.")
    value: str
    description: Optional[str] = None
    severity: str = Field(default="medium", description="critical, high, medium, low")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class EPSSScore(BaseModel):
    """EPSSScore entity - Exploit Prediction Scoring System."""
    id: str
    cve_id: str
    epss_score: float = Field(..., ge=0.0, le=1.0, description="EPSS probability 0-1")
    percentile: float = Field(..., ge=0.0, le=100.0, description="Percentile rank")
    date: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class KEVEntry(BaseModel):
    """KEVEntry entity - CISA Known Exploited Vulnerabilities."""
    id: str
    cve_id: str
    vendor_product: str
    vulnerability_name: str
    date_added: datetime
    due_date: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class Advisory(BaseModel):
    """Advisory entity - security advisory."""
    id: str
    title: str
    description: Optional[str] = None
    source: str = Field(..., description="vendor, CISA, NVD, etc.")
    published_date: datetime = Field(default_factory=datetime.utcnow)
    affected_cves: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 2})


class Core2RelationshipType(str, Enum):
    """Relationship types for Core 2: Threat Intelligence."""
    EXPLOITS = "exploits"
    MITIGATES = "mitigates"
    RELATED_TO = "related_to"
    ATTRIBUTED_TO = "attributed_to"
    USES_TECHNIQUE = "uses_technique"
    TARGETS = "targets"
    INDICATES = "indicates"
    HAS_SCORE = "has_score"


CORE2_ENTITY_TYPES = {
    'CVE': CVE,
    'CWE': CWE,
    'ATTACKTechnique': ATTACKTechnique,
    'ATTACKTactic': ATTACKTactic,
    'CAPEC': CAPEC,
    'Exploit': Exploit,
    'ThreatActor': ThreatActor,
    'Campaign': Campaign,
    'Indicator': Indicator,
    'EPSSScore': EPSSScore,
    'KEVEntry': KEVEntry,
    'Advisory': Advisory,
}


# ============================================================================
# Core 3: Compliance & Regulatory (versioned)
# ============================================================================

class Framework(BaseModel):
    """Framework entity - compliance framework."""
    id: str
    name: str
    description: Optional[str] = None
    framework_type: str = Field(..., description="nist, pci-dss, hipaa, gdpr, sox, cis, iso27001, etc.")
    version: str = Field(default="1.0")
    published_date: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 3})


class Control(BaseModel):
    """Control entity - compliance control."""
    id: str
    framework_id: str
    control_id: str = Field(..., description="e.g., AC-2, PCI-DSS-1.1")
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    version: str = Field(default="1.0")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 3})


class Requirement(BaseModel):
    """Requirement entity - specific requirement for compliance."""
    id: str
    control_id: str
    title: str
    description: Optional[str] = None
    mandatory: bool = Field(default=True)
    version: str = Field(default="1.0")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 3})


class Evidence(BaseModel):
    """Evidence entity - compliance evidence."""
    id: str
    requirement_id: str
    evidence_type: str = Field(..., description="document, screenshot, log, test_result, audit_report, etc.")
    content: str = Field(..., description="Evidence content or reference")
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 3})


class Assessment(BaseModel):
    """Assessment entity - compliance assessment."""
    id: str
    framework_id: str
    org_id: str
    assessor: Optional[str] = None
    assessment_date: datetime = Field(default_factory=datetime.utcnow)
    status: str = Field(default="in_progress", description="in_progress, completed, failed")
    overall_compliance_percentage: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 3})


class Gap(BaseModel):
    """Gap entity - compliance gap."""
    id: str
    control_id: str
    assessment_id: str
    description: str
    severity: str = Field(..., description="critical, high, medium, low")
    remediation_plan: Optional[str] = None
    due_date: Optional[datetime] = None
    status: str = Field(default="open", description="open, in_progress, resolved")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 3})


class Policy(BaseModel):
    """Policy entity - organizational policy."""
    id: str
    org_id: str
    name: str
    description: Optional[str] = None
    policy_category: str = Field(..., description="access_control, data_protection, incident_response, etc.")
    version: str = Field(default="1.0")
    effective_date: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 3})


class DataClassification(BaseModel):
    """DataClassification entity - data sensitivity classification."""
    id: str
    org_id: str
    level: str = Field(..., description="public, internal, confidential, restricted")
    description: Optional[str] = None
    handling_requirements: List[str] = Field(default_factory=list)
    retention_days: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 3})


class ConsentRecord(BaseModel):
    """ConsentRecord entity - user consent for data processing."""
    id: str
    org_id: str
    user_id: Optional[str] = None
    consent_type: str = Field(..., description="marketing, analytics, third_party, etc.")
    given: bool
    given_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 3})


class RetentionPolicy(BaseModel):
    """RetentionPolicy entity - data retention policy."""
    id: str
    org_id: str
    data_type: str
    retention_period_days: int
    deletion_method: Optional[str] = None
    effective_date: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 3})


class Core3RelationshipType(str, Enum):
    """Relationship types for Core 3: Compliance & Regulatory."""
    SATISFIES = "satisfies"
    REQUIRES = "requires"
    EVIDENCED_BY = "evidenced_by"
    ASSESSED_AGAINST = "assessed_against"
    VIOLATES = "violates"
    APPLIES_TO = "applies_to"
    GOVERNS = "governs"


CORE3_ENTITY_TYPES = {
    'Framework': Framework,
    'Control': Control,
    'Requirement': Requirement,
    'Evidence': Evidence,
    'Assessment': Assessment,
    'Gap': Gap,
    'Policy': Policy,
    'DataClassification': DataClassification,
    'ConsentRecord': ConsentRecord,
    'RetentionPolicy': RetentionPolicy,
}


# ============================================================================
# Core 4: Decision Memory (append-only)
# ============================================================================

class Decision(BaseModel):
    """Decision entity - security decision."""
    id: str
    org_id: str
    title: str
    description: Optional[str] = None
    decision_type: str = Field(..., description="finding_triage, remediation, waiver, escalation, etc.")
    made_at: datetime = Field(default_factory=datetime.utcnow)
    made_by: Optional[str] = None
    rationale: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 4})


class Verdict(BaseModel):
    """Verdict entity - judgment on a security issue."""
    id: str
    org_id: str
    issue_id: str
    verdict: str = Field(..., description="confirmed, false_positive, accepted_risk, needs_review")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    verdict_date: datetime = Field(default_factory=datetime.utcnow)
    justification: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 4})


class CouncilSession(BaseModel):
    """CouncilSession entity - security council meeting/session."""
    id: str
    org_id: str
    session_date: datetime = Field(default_factory=datetime.utcnow)
    attendees: List[str] = Field(default_factory=list)
    topics: List[str] = Field(default_factory=list)
    minutes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 4})


class Vote(BaseModel):
    """Vote entity - vote on a decision."""
    id: str
    session_id: str
    decision_id: str
    voter: str
    vote: str = Field(..., description="for, against, abstain")
    comment: Optional[str] = None
    voted_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 4})


class Escalation(BaseModel):
    """Escalation entity - issue escalation."""
    id: str
    org_id: str
    issue_id: str
    escalated_to: str = Field(..., description="exec_leadership, legal, customer, etc.")
    reason: str
    escalated_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 4})


class Triage(BaseModel):
    """Triage entity - security finding triage decision."""
    id: str
    org_id: str
    finding_id: str
    triaged_by: Optional[str] = None
    priority: str = Field(..., description="critical, high, medium, low")
    category: Optional[str] = None
    owner: Optional[str] = None
    triaged_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 4})


class Remediation(BaseModel):
    """Remediation entity - fix/remediation action."""
    id: str
    org_id: str
    issue_id: str
    title: str
    description: Optional[str] = None
    status: str = Field(default="planned", description="planned, in_progress, completed, failed")
    planned_date: Optional[datetime] = None
    completed_date: Optional[datetime] = None
    owner: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 4})


class Playbook(BaseModel):
    """Playbook entity - response playbook/runbook."""
    id: str
    org_id: str
    name: str
    description: Optional[str] = None
    incident_type: str = Field(..., description="ransomware, data_breach, ddos, etc.")
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    version: str = Field(default="1.0")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 4})


class Incident(BaseModel):
    """Incident entity - security incident."""
    id: str
    org_id: str
    title: str
    description: Optional[str] = None
    incident_type: str = Field(..., description="breach, malware, ddos, insider, etc.")
    severity: str = Field(..., description="critical, high, medium, low")
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    affected_assets: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 4})


class ROIMetric(BaseModel):
    """ROIMetric entity - return on investment metric for security."""
    id: str
    org_id: str
    metric_name: str
    metric_value: float
    unit: str = Field(..., description="dollars, incidents_prevented, hours_saved, etc.")
    measured_at: datetime = Field(default_factory=datetime.utcnow)
    period: str = Field(..., description="daily, weekly, monthly, quarterly, annual")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 4})


class Core4RelationshipType(str, Enum):
    """Relationship types for Core 4: Decision Memory."""
    DECIDED_BY = "decided_by"
    VOTED_ON = "voted_on"
    ESCALATED_TO = "escalated_to"
    TRIGGERED = "triggered"
    RESOLVED_BY = "resolved_by"
    MEASURED_BY = "measured_by"
    CORRELATED_WITH = "correlated_with"


CORE4_ENTITY_TYPES = {
    'Decision': Decision,
    'Verdict': Verdict,
    'CouncilSession': CouncilSession,
    'Vote': Vote,
    'Escalation': Escalation,
    'Triage': Triage,
    'Remediation': Remediation,
    'Playbook': Playbook,
    'Incident': Incident,
    'ROIMetric': ROIMetric,
}


# ============================================================================
# Core 5: Competitive Intelligence
# ============================================================================

class Competitor(BaseModel):
    """Competitor entity - competing vendor/company."""
    id: str
    name: str
    description: Optional[str] = None
    industry: Optional[str] = None
    founded_year: Optional[int] = None
    headquarters: Optional[str] = None
    website: Optional[str] = None
    employee_count: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 5})


class Product(BaseModel):
    """Product entity - competitor product/offering."""
    id: str
    name: str
    competitor_id: str
    description: Optional[str] = None
    product_category: str = Field(..., description="siem, sast, dast, soar, etc.")
    launch_date: Optional[datetime] = None
    version: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 5})


class Feature(BaseModel):
    """Feature entity - product feature."""
    id: str
    product_id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    release_date: Optional[datetime] = None
    maturity: str = Field(default="stable", description="beta, stable, deprecated")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 5})


class Integration(BaseModel):
    """Integration entity - product integration."""
    id: str
    product_id: str
    integrated_product: str
    integration_type: str = Field(..., description="api, plugin, webhook, native, etc.")
    availability: str = Field(default="available", description="available, planned, deprecated")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 5})


class PricingTier(BaseModel):
    """PricingTier entity - pricing model."""
    id: str
    product_id: str
    tier_name: str
    price: Optional[float] = None
    currency: str = Field(default="USD")
    billing_period: str = Field(..., description="monthly, annual, per_incident, etc.")
    features_included: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 5})


class MarketSegment(BaseModel):
    """MarketSegment entity - market segment."""
    id: str
    name: str
    description: Optional[str] = None
    vertical: str = Field(..., description="financial, healthcare, tech, government, etc.")
    size_estimate: Optional[str] = None
    growth_rate: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(json_schema_extra={"core": 5})


class Core5RelationshipType(str, Enum):
    """Relationship types for Core 5: Competitive Intelligence."""
    OFFERS = "offers"
    COMPETES_WITH = "competes_with"
    INTEGRATES_WITH = "integrates_with"
    TARGETS_SEGMENT = "targets_segment"


CORE5_ENTITY_TYPES = {
    'Competitor': Competitor,
    'Product': Product,
    'Feature': Feature,
    'Integration': Integration,
    'PricingTier': PricingTier,
    'MarketSegment': MarketSegment,
}


# ============================================================================
# Core Schema Definition
# ============================================================================

@dataclass
class CoreSchema:
    """
    Schema definition for a Knowledge Core.

    Attributes:
        core_id: Unique identifier for this core (1-5)
        name: Display name
        description: Core description
        entity_types: Dict mapping entity type names to Pydantic models
        relationship_types: Enum class defining valid relationships
        scope: One of 'per_tenant', 'shared', 'versioned', 'append_only'
        metadata: Additional schema metadata
    """
    core_id: int
    name: str
    description: str
    entity_types: Dict[str, type]
    relationship_types: type  # Enum class
    scope: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_entity_type_model(self, entity_type_name: str) -> Optional[type]:
        """Get Pydantic model for an entity type."""
        return self.entity_types.get(entity_type_name)

    def get_relationship_members(self) -> Set[str]:
        """Get all valid relationship type values."""
        return {r.value for r in self.relationship_types}


# ============================================================================
# Knowledge Core Manager
# ============================================================================

class KnowledgeCoreManager:
    """
    Manager for Knowledge Core schemas and validation.

    Provides core schema lookups, entity/relationship validation, and finding routing.
    """

    # Core schema definitions
    _CORES = {
        1: CoreSchema(
            core_id=1,
            name="Customer Environment",
            description="Per-tenant assets, findings, deployment info",
            entity_types=CORE1_ENTITY_TYPES,
            relationship_types=Core1RelationshipType,
            scope="per_tenant",
            metadata={
                "tenant_scoped": True,
                "temporal": True,
                "entity_count": len(CORE1_ENTITY_TYPES),
            },
        ),
        2: CoreSchema(
            core_id=2,
            name="Threat Intelligence",
            description="CVEs, attackers, exploits (shared across tenants)",
            entity_types=CORE2_ENTITY_TYPES,
            relationship_types=Core2RelationshipType,
            scope="shared",
            metadata={
                "tenant_scoped": False,
                "curated": True,
                "entity_count": len(CORE2_ENTITY_TYPES),
            },
        ),
        3: CoreSchema(
            core_id=3,
            name="Compliance & Regulatory",
            description="Frameworks, controls, evidence (versioned)",
            entity_types=CORE3_ENTITY_TYPES,
            relationship_types=Core3RelationshipType,
            scope="versioned",
            metadata={
                "tenant_scoped": True,
                "versioned": True,
                "entity_count": len(CORE3_ENTITY_TYPES),
            },
        ),
        4: CoreSchema(
            core_id=4,
            name="Decision Memory",
            description="Triage, verdicts, remediation (append-only)",
            entity_types=CORE4_ENTITY_TYPES,
            relationship_types=Core4RelationshipType,
            scope="append_only",
            metadata={
                "tenant_scoped": True,
                "append_only": True,
                "audit_trail": True,
                "entity_count": len(CORE4_ENTITY_TYPES),
            },
        ),
        5: CoreSchema(
            core_id=5,
            name="Competitive Intelligence",
            description="Competitors, products, market segments",
            entity_types=CORE5_ENTITY_TYPES,
            relationship_types=Core5RelationshipType,
            scope="shared",
            metadata={
                "tenant_scoped": False,
                "entity_count": len(CORE5_ENTITY_TYPES),
            },
        ),
    }

    # Valid source relationships per core
    _VALID_RELATIONSHIPS: Dict[int, Dict[str, Set[str]]] = {
        1: {
            'Organization': {'Team', 'Service', 'User', 'CloudAccount', 'Policy'},
            'Team': {'Service', 'User'},
            'Service': {'Repository', 'Pipeline', 'Artifact', 'APIEndpoint', 'Finding', 'Vulnerability', 'SBOM'},
            'Repository': {'Commit', 'Branch', 'PullRequest'},
            'CloudAccount': {'K8sCluster', 'IAMRole', 'DataStore', 'Endpoint'},
            'K8sCluster': {'K8sNamespace', 'Pod', 'NetworkPolicy'},
            'K8sNamespace': {'Pod'},
            'Container': {'Artifact'},
            'Artifact': {'SBOM'},
            'DataStore': {'Finding'},
            'Endpoint': {'Finding'},
            'APIEndpoint': {'Finding'},
        },
        2: {
            'CVE': {'CWE', 'Exploit', 'Advisory', 'ATTACKTechnique', 'EPSSScore', 'KEVEntry'},
            'Exploit': {'CVE', 'ATTACKTechnique'},
            'ThreatActor': {'Campaign', 'ATTACKTechnique', 'Indicator'},
            'Campaign': {'ThreatActor', 'Indicator', 'Advisory'},
            'Indicator': {'ThreatActor', 'Campaign', 'CVE'},
            'ATTACKTechnique': {'ATTACKTactic', 'CWE', 'CAPEC'},
            'ATTACKTactic': {'ATTACKTechnique'},
            'Advisory': {'CVE', 'CWE'},
        },
        3: {
            'Framework': {'Control', 'Assessment'},
            'Control': {'Requirement', 'Evidence', 'Gap'},
            'Requirement': {'Evidence'},
            'Assessment': {'Framework', 'Gap'},
            'Policy': {'Framework', 'DataClassification'},
            'DataClassification': {'RetentionPolicy'},
        },
        4: {
            'Decision': {'Vote', 'Escalation', 'Verdict'},
            'CouncilSession': {'Vote', 'Decision'},
            'Verdict': {'Decision'},
            'Incident': {'Triage', 'Escalation', 'Remediation'},
            'Playbook': {'Remediation'},
            'Triage': {'Remediation', 'Verdict'},
            'Remediation': {'ROIMetric'},
        },
        5: {
            'Competitor': {'Product'},
            'Product': {'Feature', 'Integration', 'PricingTier', 'MarketSegment'},
            'Feature': {},
            'Integration': {},
            'PricingTier': {},
            'MarketSegment': {},
        },
    }

    @classmethod
    def get_core(cls, core_id: int) -> Optional[CoreSchema]:
        """
        Get schema for a Knowledge Core.

        Args:
            core_id: Core ID (1-5)

        Returns:
            CoreSchema or None if not found
        """
        return cls._CORES.get(core_id)

    @classmethod
    def validate_entity(cls, core_id: int, entity_type: str, data: Dict[str, Any]) -> bool:
        """
        Validate entity data against core schema.

        Args:
            core_id: Core ID (1-5)
            entity_type: Entity type name
            data: Entity data dict

        Returns:
            True if valid, raises ValidationError otherwise
        """
        core = cls.get_core(core_id)
        if not core:
            raise ValueError(f"Unknown core ID: {core_id}")

        model_class = core.get_entity_type_model(entity_type)
        if not model_class:
            raise ValueError(f"Unknown entity type '{entity_type}' in core {core_id}")

        # Validate using Pydantic
        model_class.model_validate(data)
        return True

    @classmethod
    def validate_relationship(
        cls, core_id: int, rel_type: str, source_type: str, target_type: str
    ) -> bool:
        """
        Validate that a relationship is allowed between entity types.

        Args:
            core_id: Core ID (1-5)
            rel_type: Relationship type name
            source_type: Source entity type
            target_type: Target entity type

        Returns:
            True if valid relationship, raises ValueError otherwise
        """
        core = cls.get_core(core_id)
        if not core:
            raise ValueError(f"Unknown core ID: {core_id}")

        # Check relationship type exists in core
        valid_rels = {r.value for r in core.relationship_types}
        if rel_type not in valid_rels:
            raise ValueError(f"Unknown relationship type '{rel_type}' in core {core_id}")

        # Check entity types exist
        if source_type not in core.entity_types:
            raise ValueError(f"Unknown source entity type '{source_type}' in core {core_id}")
        if target_type not in core.entity_types:
            raise ValueError(f"Unknown target entity type '{target_type}' in core {core_id}")

        # Check if relationship is valid (if we have explicit mapping)
        valid_targets = cls._VALID_RELATIONSHIPS.get(core_id, {}).get(source_type, set())
        if valid_targets and target_type not in valid_targets:
            raise ValueError(
                f"Relationship not valid: {source_type} -[{rel_type}]-> {target_type}"
            )

        return True

    @classmethod
    def get_entity_types(cls, core_id: int) -> List[str]:
        """
        Get list of entity types for a core.

        Args:
            core_id: Core ID (1-5)

        Returns:
            List of entity type names, or empty list if core not found
        """
        core = cls.get_core(core_id)
        if not core:
            return []
        return sorted(core.entity_types.keys())

    @classmethod
    def get_relationship_types(cls, core_id: int) -> List[str]:
        """
        Get list of relationship types for a core.

        Args:
            core_id: Core ID (1-5)

        Returns:
            List of relationship type names, or empty list if core not found
        """
        core = cls.get_core(core_id)
        if not core:
            return []
        return sorted([r.value for r in core.relationship_types])

    @classmethod
    def route_finding(cls, finding: Dict[str, Any]) -> List[int]:
        """
        Route a normalized finding to appropriate Knowledge Cores.

        A finding typically goes to:
          - Core 1 (Customer Environment) - always, for the finding itself
          - Core 2 (Threat Intelligence) - if CVE/CWE IDs present
          - Core 3 (Compliance) - if compliance relevance identified
          - Core 4 (Decision) - after triage/verdict

        Args:
            finding: Normalized finding dict with keys like:
              - finding_id, title, severity
              - cve_id, cwe_id (optional)
              - framework_id, control_id (optional)
              - service_id, artifact_id (optional)

        Returns:
            List of core IDs (1-5) where this finding should be ingested
        """
        cores = [1]  # Always Core 1 (Customer Environment)

        # Route to Core 2 if threat intelligence refs present
        if finding.get('cve_id') or finding.get('cwe_id') or finding.get('exploit_id'):
            cores.append(2)

        # Route to Core 3 if compliance relevance
        if finding.get('framework_id') or finding.get('control_id') or finding.get('compliance_relevant'):
            cores.append(3)

        # Core 4 added after triage/decision is made
        # (not typically on initial finding ingestion)

        return sorted(list(set(cores)))

    @classmethod
    def get_all_cores(cls) -> Dict[int, CoreSchema]:
        """Get all core schemas."""
        return cls._CORES.copy()

    @classmethod
    def list_cores(cls) -> List[Dict[str, Any]]:
        """
        List all cores with metadata.

        Returns:
            List of dicts with core_id, name, description, scope, entity_count
        """
        return [
            {
                "core_id": core.core_id,
                "name": core.name,
                "description": core.description,
                "scope": core.scope,
                "entity_count": len(core.entity_types),
                "relationship_count": len(list(core.relationship_types)),
            }
            for core in cls._CORES.values()
        ]
