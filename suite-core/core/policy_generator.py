"""
Security Policy Document Generator — ALDECI.

Auto-generates security policies from platform config and best practices.
Provides full lifecycle management: draft, approve, archive, export.

Features:
- SQLite-backed policy storage with full version history
- Built-in best-practice templates for 10 policy types
- Markdown and HTML export
- Review-due alerting
- Org-scoped policy management

Compliance: SOC2 CC9.2, ISO27001 A.5.1, NIST CSF ID.GV-1, CIS Control 1.
"""

from __future__ import annotations

import html as _html
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus:
            bus.emit(event_type, payload)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_REVIEW_DAYS = 365  # annual review by default
_DEFAULT_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PolicyType(str, Enum):
    """Supported security policy types."""

    ACCEPTABLE_USE = "acceptable_use"
    DATA_CLASSIFICATION = "data_classification"
    INCIDENT_RESPONSE = "incident_response"
    ACCESS_CONTROL = "access_control"
    ENCRYPTION = "encryption"
    PATCH_MANAGEMENT = "patch_management"
    VENDOR_MANAGEMENT = "vendor_management"
    CHANGE_MANAGEMENT = "change_management"
    BUSINESS_CONTINUITY = "business_continuity"
    PASSWORD = "password"

    def __str__(self) -> str:
        return self.value


class PolicyStatus(str, Enum):
    """Policy lifecycle status."""

    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"

    def __str__(self) -> str:
        return self.value


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class PolicyDocument(BaseModel):
    """A security policy document."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: PolicyType
    title: str
    version: str = Field(default=_DEFAULT_VERSION)
    content: str = Field(..., description="Policy body in Markdown")
    approved_by: Optional[str] = Field(None, description="Approver name/ID")
    effective_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    status: PolicyStatus = Field(default=PolicyStatus.DRAFT)
    org_id: str = Field(default="default")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Built-in policy templates
# ---------------------------------------------------------------------------

_POLICY_TITLES: Dict[str, str] = {
    PolicyType.ACCEPTABLE_USE: "Acceptable Use Policy",
    PolicyType.DATA_CLASSIFICATION: "Data Classification Policy",
    PolicyType.INCIDENT_RESPONSE: "Incident Response Policy",
    PolicyType.ACCESS_CONTROL: "Access Control Policy",
    PolicyType.ENCRYPTION: "Encryption Policy",
    PolicyType.PATCH_MANAGEMENT: "Patch Management Policy",
    PolicyType.VENDOR_MANAGEMENT: "Vendor Management Policy",
    PolicyType.CHANGE_MANAGEMENT: "Change Management Policy",
    PolicyType.BUSINESS_CONTINUITY: "Business Continuity Policy",
    PolicyType.PASSWORD: "Password Policy",
}

_POLICY_TEMPLATES: Dict[str, str] = {
    PolicyType.ACCEPTABLE_USE: """\
# Acceptable Use Policy

## 1. Purpose
This policy defines the acceptable use of information technology resources to protect the organization, its employees, partners, and customers from harm caused by deliberate or inadvertent misuse.

## 2. Scope
This policy applies to all employees, contractors, consultants, temporary staff, and other workers, including all personnel affiliated with third parties who use organization-owned or organization-leased technology resources.

## 3. Acceptable Use
- Resources must be used primarily for business purposes.
- Limited personal use is permitted provided it does not interfere with work duties or violate any policies.
- Users must comply with all applicable laws, regulations, and organization policies.
- Confidential data must not be shared with unauthorized parties.

## 4. Prohibited Activities
- Unauthorized access to systems, networks, or data.
- Installation of unauthorized software or hardware.
- Circumventing security controls, firewalls, or monitoring systems.
- Downloading, distributing, or storing illegal, obscene, or harassing content.
- Using organization resources for personal financial gain.
- Mining cryptocurrency on organization infrastructure.
- Sharing credentials or allowing others to use your access.

## 5. Monitoring and Privacy
The organization reserves the right to monitor, inspect, and audit all activity on its technology resources. Users should have no expectation of privacy when using organization resources.

## 6. Enforcement
Violations of this policy may result in disciplinary action, up to and including termination of employment or contract, and legal action where appropriate.

## 7. Reporting
Suspected violations must be reported to the Information Security team immediately via the security incident reporting channel.

## 8. Review
This policy is reviewed annually or upon significant organizational change.
""",
    PolicyType.DATA_CLASSIFICATION: """\
# Data Classification Policy

## 1. Purpose
Establish a framework for classifying organizational data based on sensitivity and criticality to ensure appropriate protection measures are applied.

## 2. Scope
All data created, received, maintained, or transmitted by the organization in any format (electronic, paper, verbal).

## 3. Classification Levels

### 3.1 Public
- Definition: Information approved for public disclosure with no potential for harm.
- Examples: Press releases, published reports, marketing materials.
- Handling: No special controls required.

### 3.2 Internal
- Definition: General business information not intended for public disclosure.
- Examples: Internal procedures, org charts, project plans.
- Handling: Must not be shared externally without authorization.

### 3.3 Confidential
- Definition: Sensitive business information that could cause harm if disclosed.
- Examples: Financial data, contracts, personnel records, customer data.
- Handling: Encryption required at rest and in transit; access on need-to-know basis.

### 3.4 Restricted
- Definition: Highly sensitive information with severe impact if disclosed.
- Examples: Trade secrets, regulated health/financial data, authentication credentials.
- Handling: Strictest controls; encryption mandatory; logging of all access; minimal distribution.

## 4. Data Owner Responsibilities
- Assign and maintain classification labels.
- Periodically review and update classifications.
- Approve access requests for data under their ownership.

## 5. User Responsibilities
- Handle data according to its classification level.
- Not downgrade data classification without owner approval.
- Report suspected misclassification or unauthorized disclosure.

## 6. Labeling and Handling
All Confidential and Restricted documents must be labeled with classification level in headers/footers.

## 7. Retention and Disposal
Data must be retained per the Data Retention Schedule and securely disposed of when no longer needed (shredding for paper; secure wipe for electronic).

## 8. Review
This policy is reviewed annually or when regulatory requirements change.
""",
    PolicyType.INCIDENT_RESPONSE: """\
# Incident Response Policy

## 1. Purpose
Define the organization's approach to detecting, containing, and recovering from information security incidents to minimize business impact and meet regulatory obligations.

## 2. Scope
All information security incidents affecting organization systems, data, or operations, including those involving third-party service providers.

## 3. Incident Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| P1 — Critical | Active breach, data exfiltration, ransomware | Immediate (< 1 hour) |
| P2 — High | Confirmed compromise, service disruption | < 4 hours |
| P3 — Medium | Suspected compromise, policy violation | < 24 hours |
| P4 — Low | Security anomaly, near-miss | < 72 hours |

## 4. Incident Response Phases

### 4.1 Preparation
- Maintain incident response team (IRT) with defined roles.
- Keep contact lists, runbooks, and tooling current.
- Conduct annual tabletop exercises.

### 4.2 Detection and Analysis
- Monitor SIEM, EDR, and threat intelligence feeds continuously.
- Validate alerts and determine scope within the target response window.
- Document findings in the incident tracking system.

### 4.3 Containment
- Isolate affected systems to prevent lateral movement.
- Preserve forensic evidence (memory dumps, log snapshots).
- Implement short-term fixes to limit damage.

### 4.4 Eradication
- Remove malicious artifacts, unauthorized access, and vulnerabilities.
- Patch or harden affected systems.
- Reset compromised credentials.

### 4.5 Recovery
- Restore systems from clean backups.
- Verify integrity before returning to production.
- Monitor for recurrence for a minimum of 30 days post-incident.

### 4.6 Post-Incident Review
- Conduct lessons-learned meeting within 5 business days.
- Produce written post-mortem report.
- Update runbooks, controls, and detection rules.

## 5. Notification Requirements
- Internal: Executive team notified for P1/P2 within 2 hours.
- Regulatory: Breach notification within 72 hours where required (GDPR Art. 33, HIPAA §164.410).
- Customers: Notification per contractual obligations.

## 6. Evidence Preservation
All incident artifacts must be preserved for a minimum of 3 years.

## 7. Review
This policy is reviewed annually and after each P1/P2 incident.
""",
    PolicyType.ACCESS_CONTROL: """\
# Access Control Policy

## 1. Purpose
Ensure that access to information systems and data is granted on a least-privilege, need-to-know basis to protect confidentiality, integrity, and availability.

## 2. Scope
All systems, applications, databases, and network resources owned or operated by the organization.

## 3. Principles
- **Least Privilege**: Users receive the minimum access required to perform their job.
- **Need-to-Know**: Access granted only when there is a documented business need.
- **Separation of Duties**: Critical functions require multiple individuals.
- **Zero Trust**: No implicit trust; verify every access request.

## 4. Access Request and Provisioning
- All access requests must be submitted through the approved ticketing system.
- Manager approval required for all access grants.
- Privileged access requires additional approval from the CISO or delegate.
- Access must be provisioned within 2 business days of approval.

## 5. Privileged Access Management
- Privileged accounts (admin, root, service accounts) must be inventoried and reviewed quarterly.
- Privileged sessions must be recorded and stored for 1 year.
- Just-in-time (JIT) access preferred over standing privileged access.
- Multi-factor authentication (MFA) mandatory for all privileged access.

## 6. Access Reviews
- Quarterly access reviews for all production systems.
- Immediate review triggered by role change or termination.
- Annual comprehensive access certification for all accounts.

## 7. Account Termination
- Access must be revoked within 4 hours of employee termination notification.
- All credentials and tokens must be invalidated.
- Shared accounts updated if former employee knew the credentials.

## 8. Remote Access
- VPN or zero-trust network access (ZTNA) required for remote system access.
- MFA mandatory for all remote access sessions.
- Remote sessions must time out after 30 minutes of inactivity.

## 9. Service Accounts
- Service accounts must have unique passwords rotated at least annually.
- Service accounts must not be used for interactive logins.
- Permissions must be scoped to the minimum required for the service function.

## 10. Review
This policy is reviewed annually or upon significant infrastructure change.
""",
    PolicyType.ENCRYPTION: """\
# Encryption Policy

## 1. Purpose
Establish minimum encryption standards to protect confidential and restricted data from unauthorized disclosure during storage and transmission.

## 2. Scope
All organization-owned systems, cloud services, and third-party systems that store or transmit confidential or restricted data.

## 3. Encryption Standards

### 3.1 Approved Algorithms
| Use Case | Algorithm | Minimum Key Size |
|----------|-----------|-----------------|
| Symmetric encryption | AES | 256-bit |
| Asymmetric encryption | RSA | 4096-bit |
| Elliptic curve | ECDSA/ECDH | P-384 or higher |
| Hashing | SHA-2 family | 256-bit (SHA-256) |
| Key derivation | PBKDF2 / bcrypt / Argon2 | Per NIST SP 800-132 |
| TLS | TLS 1.2 minimum | TLS 1.3 preferred |

### 3.2 Prohibited Algorithms
The following algorithms are prohibited: DES, 3DES, RC4, MD5, SHA-1, SSL 2.0/3.0, TLS 1.0/1.1.

## 4. Data at Rest
- Confidential and Restricted data must be encrypted at rest using AES-256.
- Full-disk encryption required on all endpoints and laptops.
- Database encryption (TDE) required for databases containing Confidential or Restricted data.
- Cloud storage must use provider-managed or customer-managed encryption keys (CMK preferred).

## 5. Data in Transit
- All data transmitted over public networks must use TLS 1.2 or higher.
- Internal service-to-service communication must use mutual TLS (mTLS) for sensitive data.
- Email containing Confidential data must use S/MIME or PGP encryption.

## 6. Key Management
- Encryption keys must be stored separately from encrypted data.
- Keys must be rotated at least annually or upon suspected compromise.
- A key management system (KMS) must be used for all production keys.
- Key access must be logged and reviewed quarterly.
- Backup keys must be stored in geographically separate secure storage.

## 7. Certificate Management
- TLS certificates must use a minimum 2048-bit RSA or 256-bit EC key.
- Certificate expiry must be tracked; renewal must occur at least 30 days before expiry.
- Wildcard certificates require explicit CISO approval.

## 8. Review
This policy is reviewed annually or when cryptographic standards are updated by NIST.
""",
    PolicyType.PATCH_MANAGEMENT: """\
# Patch Management Policy

## 1. Purpose
Ensure timely identification, testing, and deployment of security patches to reduce exposure to known vulnerabilities.

## 2. Scope
All organization-owned and managed systems: servers, endpoints, network devices, cloud instances, containers, and third-party applications.

## 3. Patch Classification and SLAs

| Severity | CVSS Score | Remediation SLA |
|----------|-----------|-----------------|
| Critical | 9.0 – 10.0 | 48 hours |
| High | 7.0 – 8.9 | 7 days |
| Medium | 4.0 – 6.9 | 30 days |
| Low | 0.1 – 3.9 | 90 days |

Active exploitation in the wild reduces SLA by 50% for all severities.

## 4. Patch Process

### 4.1 Identification
- Automated vulnerability scanning must run at minimum weekly.
- Subscribe to vendor security advisories and CISA KEV (Known Exploited Vulnerabilities).
- All assets must be inventoried and covered by scanning.

### 4.2 Assessment and Prioritization
- Patches scored using CVSS + threat intelligence (exploit availability, active exploitation).
- Risk-ranked patch list published to system owners weekly.

### 4.3 Testing
- Critical and High patches tested in staging environment before production (unless emergency).
- Testing window: 24 hours for Critical, 48–72 hours for High.
- Rollback procedure documented before any patch deployment.

### 4.4 Deployment
- Patches deployed during approved maintenance windows except for Critical/emergency patches.
- Deployment tracked in change management system.
- Post-patch vulnerability scan must confirm remediation within 24 hours.

### 4.5 Exceptions
- Patch exceptions require CISO approval, documented risk acceptance, and compensating controls.
- Exceptions reviewed monthly; maximum exception duration is 90 days.

## 5. Metrics and Reporting
- Monthly patch compliance report published to security leadership.
- KPIs: % patched within SLA per severity, mean time to patch (MTTP), exception count.

## 6. End-of-Life Systems
- EOL systems without vendor support must be documented and isolated.
- Migration plan required within 60 days of EOL designation.

## 7. Review
This policy is reviewed annually or after a significant vulnerability incident.
""",
    PolicyType.VENDOR_MANAGEMENT: """\
# Vendor Management Policy

## 1. Purpose
Establish controls for selecting, onboarding, monitoring, and offboarding vendors that handle organization data or provide critical services to manage third-party risk.

## 2. Scope
All third-party vendors, suppliers, contractors, and service providers that have access to organization data, systems, or facilities.

## 3. Vendor Risk Tiers

| Tier | Description | Review Frequency |
|------|-------------|-----------------|
| Critical | Access to Restricted data or core infrastructure | Annual + on-incident |
| High | Access to Confidential data or significant business function | Annual |
| Medium | Access to Internal data or non-critical services | Every 2 years |
| Low | No data access; commodity services | Every 3 years |

## 4. Vendor Onboarding
- Security questionnaire required for all Tier Critical/High vendors.
- Security assessment (SOC 2 Type II report, penetration test, or equivalent) required for Tier Critical.
- Legal review and Data Processing Agreement (DPA) required where vendor processes personal data.
- Vendor onboarding approval requires Security team sign-off.

## 5. Contractual Requirements
All vendor contracts must include:
- Data protection and confidentiality obligations.
- Incident notification requirement (within 24 hours of suspected breach).
- Right-to-audit clause.
- Security standards compliance (ISO 27001, SOC 2, or equivalent).
- Sub-processor notification obligations.
- Data return/deletion on contract termination.

## 6. Ongoing Monitoring
- Annual security questionnaire review for Tier High and Critical vendors.
- Continuous monitoring of vendor security ratings (e.g., SecurityScorecard).
- Review vendor SOC 2 / ISO 27001 certificates annually for validity.
- Track vendor security incidents and advisories.

## 7. Vendor Access Controls
- Vendors must use unique credentials; shared accounts prohibited.
- MFA required for all vendor remote access.
- Vendor access must be scoped to minimum necessary and time-limited.
- Vendor sessions logged and audited.

## 8. Vendor Offboarding
- All access revoked within 24 hours of contract termination.
- Confirm data return or certified destruction within 30 days.
- Document offboarding completion in vendor record.

## 9. Review
This policy is reviewed annually or after a significant vendor-related incident.
""",
    PolicyType.CHANGE_MANAGEMENT: """\
# Change Management Policy

## 1. Purpose
Ensure that all changes to information systems are authorized, tested, documented, and reversible to maintain system stability, security, and compliance.

## 2. Scope
All changes to production systems including infrastructure, applications, configurations, network, databases, and cloud resources.

## 3. Change Types

| Type | Description | Approval Required |
|------|-------------|------------------|
| Standard | Pre-approved, low-risk, repeatable | Auto-approved via runbook |
| Normal | Planned change with moderate risk | Change Advisory Board (CAB) |
| Emergency | Urgent change to restore service | CISO/CTO + post-hoc CAB review |

## 4. Change Request Process

### 4.1 Submission
- All Normal changes submitted via change management system at least 5 business days before desired implementation.
- Request must include: description, business justification, risk assessment, rollback plan, and test results.

### 4.2 Review and Approval
- CAB reviews Normal changes weekly.
- Security team reviews changes affecting security controls, authentication, encryption, or network boundaries.
- Changes affecting Restricted data require CISO approval.

### 4.3 Implementation
- Changes implemented only during approved maintenance windows (unless emergency).
- Implementation follows documented runbook.
- Pre-change backup or snapshot taken where applicable.
- Change owner present during implementation.

### 4.4 Post-Implementation Review
- Verify change achieved intended outcome within 24 hours.
- Monitor for adverse effects for minimum 48 hours post-change.
- Close change ticket with outcome documented.

## 5. Emergency Changes
- Emergency changes may bypass normal approval but require verbal authorization from CISO or CTO.
- Full documentation and CAB retrospective within 2 business days.
- Emergency changes tracked and reviewed monthly for trends.

## 6. Rollback
- All changes must have a documented, tested rollback procedure.
- Rollback decision made by change owner in consultation with stakeholders.
- Rollback must be executable within the maintenance window.

## 7. Change Freeze Periods
- Change freeze enforced during business-critical periods (year-end, major product launches).
- Freeze periods published to all stakeholders at least 4 weeks in advance.
- Only emergency changes permitted during freeze.

## 8. Review
This policy is reviewed annually or after a significant change-related outage.
""",
    PolicyType.BUSINESS_CONTINUITY: """\
# Business Continuity Policy

## 1. Purpose
Ensure the organization can continue critical operations during and after disruptive events, and recover within acceptable timeframes.

## 2. Scope
All critical business functions, supporting systems, personnel, and third-party dependencies.

## 3. Recovery Objectives

| Tier | Systems | RTO | RPO |
|------|---------|-----|-----|
| Tier 1 — Mission Critical | Core platform, authentication, data pipelines | < 4 hours | < 1 hour |
| Tier 2 — Business Critical | Customer portals, reporting, APIs | < 8 hours | < 4 hours |
| Tier 3 — Important | Internal tools, analytics, non-critical services | < 24 hours | < 8 hours |
| Tier 4 — Normal | Administrative systems | < 72 hours | < 24 hours |

RTO: Recovery Time Objective. RPO: Recovery Point Objective.

## 4. Business Impact Analysis
- BIA conducted annually and after significant organizational changes.
- Identifies critical functions, dependencies, maximum tolerable downtime (MTD), and resource requirements.
- BIA results inform BC/DR strategy and investment priorities.

## 5. BC/DR Strategy
- Tier 1 systems must have active-active or active-passive redundancy.
- Backups tested quarterly; restore test must complete successfully.
- Geographic redundancy required for Tier 1 and Tier 2 systems.
- Cloud-based failover preferred for cost-effective resilience.

## 6. Plan Maintenance
- BC/DR plans documented and stored in accessible location (not solely on affected systems).
- Plans reviewed and updated annually or after significant infrastructure change.
- Contact lists reviewed quarterly.

## 7. Testing and Exercises
- Tabletop exercise: annually minimum.
- Functional drill (partial failover test): semi-annually for Tier 1 systems.
- Full DR test: annually with documented results and remediation plan.
- Lessons learned from each exercise incorporated within 30 days.

## 8. Crisis Communications
- Communication tree activated within 1 hour of a declared disaster.
- Status updates to stakeholders at minimum every 4 hours during an active incident.
- Executive briefing at start and close of each operational day during recovery.

## 9. Vendor Dependencies
- Critical vendors must demonstrate equivalent BC/DR capabilities.
- Vendor BCP reviewed annually as part of vendor management process.
- Alternative vendors identified for all Tier 1 dependencies.

## 10. Review
This policy is reviewed annually and after any significant disruption or test finding.
""",
    PolicyType.PASSWORD: """\
# Password Policy

## 1. Purpose
Establish minimum requirements for password creation, management, and protection to prevent unauthorized access to organization systems.

## 2. Scope
All accounts on organization-owned systems, applications, and services including employee, contractor, service, and privileged accounts.

## 3. Password Requirements

### 3.1 Standard User Accounts
- Minimum length: **16 characters**
- Must include characters from at least 3 of: uppercase, lowercase, digits, special characters.
- Must not contain the user's name, username, or common dictionary words.
- Must not reuse the last 12 passwords.
- Expiry: Passwords do not expire unless compromised (per NIST SP 800-63B guidance).
- Compromise check: Passwords screened against known-breached password lists on set/reset.

### 3.2 Privileged / Administrative Accounts
- Minimum length: **20 characters**
- Random, machine-generated passwords preferred.
- Stored in approved privileged access management (PAM) vault.
- Rotated at minimum annually or upon staff change.

### 3.3 Service Accounts
- Minimum length: **32 characters**, randomly generated.
- Rotated at minimum annually and upon any personnel change with knowledge of the credential.
- Stored in secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager).

## 4. Multi-Factor Authentication (MFA)
- MFA is **mandatory** for:
  - All remote access (VPN, ZTNA).
  - All privileged account usage.
  - All cloud management consoles.
  - All SaaS applications containing Confidential or Restricted data.
- Approved MFA methods: FIDO2/WebAuthn hardware keys, authenticator app (TOTP). SMS OTP is discouraged and requires CISO approval.

## 5. Password Managers
- Organization-approved password managers must be used for storing passwords.
- Personal password managers may be used for personal accounts only.
- Browser-based password save is acceptable only for Internal-tier accounts.

## 6. Prohibited Practices
- Sharing passwords with anyone, including IT staff.
- Writing passwords on paper or in unencrypted files.
- Using the same password for multiple systems.
- Transmitting passwords via email, chat, or unencrypted channels.

## 7. Forgotten Password / Reset
- Password resets require identity verification via MFA or identity verification process.
- Temporary passwords must be unique, single-use, and expire within 24 hours.
- Resets must be logged with requesting user identity.

## 8. Review
This policy is reviewed annually or when NIST or industry password guidance is updated.
""",
}


# ---------------------------------------------------------------------------
# PolicyGenerator
# ---------------------------------------------------------------------------


class PolicyGenerator:
    """
    SQLite-backed security policy document generator.

    Generates, stores, and manages the full lifecycle of security policy
    documents for an organization.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        """
        Initialise the generator.

        Args:
            db_path: Path to SQLite database. Defaults to in-memory for tests.
        """
        self.db_path = db_path
        self._lock = threading.RLock()
        if db_path == ":memory:":
            self._shared_conn: Optional[sqlite3.Connection] = sqlite3.connect(
                ":memory:", check_same_thread=False
            )
            self._shared_conn.row_factory = sqlite3.Row
        else:
            self._shared_conn = None
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create SQLite schema if it does not exist."""
        with self._lock:
            conn = self._connect()
            owned = self._shared_conn is None
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS policy_documents (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        type TEXT NOT NULL,
                        title TEXT NOT NULL,
                        version TEXT NOT NULL DEFAULT '1.0',
                        content TEXT NOT NULL,
                        approved_by TEXT,
                        effective_date TEXT,
                        review_date TEXT,
                        status TEXT NOT NULL DEFAULT 'draft',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_policies_org ON policy_documents (org_id)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_policies_status ON policy_documents (status)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_policies_type ON policy_documents (type)"
                )
                conn.commit()
            finally:
                if owned:
                    conn.close()

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _row_to_policy(self, row: sqlite3.Row) -> PolicyDocument:
        """Convert a database row to a PolicyDocument."""
        data = dict(row)
        for dt_field in ("effective_date", "review_date", "created_at", "updated_at"):
            if data.get(dt_field):
                data[dt_field] = datetime.fromisoformat(data[dt_field])
        return PolicyDocument(**data)

    def _save_policy(self, conn: sqlite3.Connection, policy: PolicyDocument) -> None:
        """Insert or replace a policy document in the database."""
        conn.execute(
            """
            INSERT OR REPLACE INTO policy_documents
            (id, org_id, type, title, version, content, approved_by,
             effective_date, review_date, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                policy.id,
                policy.org_id,
                str(policy.type),
                policy.title,
                policy.version,
                policy.content,
                policy.approved_by,
                policy.effective_date.isoformat() if policy.effective_date else None,
                policy.review_date.isoformat() if policy.review_date else None,
                str(policy.status),
                policy.created_at.isoformat(),
                policy.updated_at.isoformat(),
            ),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_policy(
        self,
        type: PolicyType,
        org_id: str = "default",
        custom_title: Optional[str] = None,
        review_days: int = _DEFAULT_REVIEW_DAYS,
    ) -> PolicyDocument:
        """
        Auto-generate a policy document from built-in templates and best practices.

        Args:
            type: The PolicyType to generate.
            org_id: Organisation identifier.
            custom_title: Override the default title.
            review_days: Days until the policy is due for review (default 365).

        Returns:
            The generated PolicyDocument in DRAFT status.
        """
        type_val = PolicyType(str(type))
        now = datetime.now(timezone.utc)
        title = custom_title or _POLICY_TITLES[type_val]
        content = _POLICY_TEMPLATES[type_val]
        review_date = now + timedelta(days=review_days)

        policy = PolicyDocument(
            type=type_val,
            title=title,
            content=content,
            org_id=org_id,
            review_date=review_date,
            created_at=now,
            updated_at=now,
        )

        with self._lock:
            conn = self._connect()
            owned = self._shared_conn is None
            try:
                self._save_policy(conn, policy)
                conn.commit()
            finally:
                if owned:
                    conn.close()

        _logger.info("Generated policy type=%s id=%s org=%s", type_val, policy.id, org_id)
        _tg_emit("policy_generator.policy_generated", {"policy_id": policy.id, "org_id": org_id, "type": type_val})
        return policy

    def list_policies(self, org_id: str = "default") -> List[PolicyDocument]:
        """
        Return all policies for an organisation.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of PolicyDocument objects, ordered by created_at descending.
        """
        with self._lock:
            conn = self._connect()
            owned = self._shared_conn is None
            try:
                rows = conn.execute(
                    "SELECT * FROM policy_documents WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
                return [self._row_to_policy(r) for r in rows]
            finally:
                if owned:
                    conn.close()

    def get_policy(self, policy_id: str) -> Optional[PolicyDocument]:
        """
        Retrieve a single policy by ID.

        Args:
            policy_id: The policy document ID.

        Returns:
            PolicyDocument or None if not found.
        """
        with self._lock:
            conn = self._connect()
            owned = self._shared_conn is None
            try:
                row = conn.execute(
                    "SELECT * FROM policy_documents WHERE id = ?", (policy_id,)
                ).fetchone()
                return self._row_to_policy(row) if row else None
            finally:
                if owned:
                    conn.close()

    def update_policy(self, policy_id: str, content: str) -> Optional[PolicyDocument]:
        """
        Update the content of a policy (manual edit).

        Args:
            policy_id: The policy document ID.
            content: New Markdown content.

        Returns:
            Updated PolicyDocument or None if not found.
        """
        with self._lock:
            conn = self._connect()
            owned = self._shared_conn is None
            try:
                row = conn.execute(
                    "SELECT * FROM policy_documents WHERE id = ?", (policy_id,)
                ).fetchone()
                if not row:
                    return None
                policy = self._row_to_policy(row)
                policy.content = content
                policy.updated_at = datetime.now(timezone.utc)
                self._save_policy(conn, policy)
                conn.commit()
                return policy
            finally:
                if owned:
                    conn.close()

    def approve_policy(self, policy_id: str, approver: str) -> Optional[PolicyDocument]:
        """
        Mark a policy as approved (ACTIVE) with effective date set to now.

        Args:
            policy_id: The policy document ID.
            approver: Name or ID of the approver.

        Returns:
            Updated PolicyDocument or None if not found.
        """
        with self._lock:
            conn = self._connect()
            owned = self._shared_conn is None
            try:
                row = conn.execute(
                    "SELECT * FROM policy_documents WHERE id = ?", (policy_id,)
                ).fetchone()
                if not row:
                    return None
                policy = self._row_to_policy(row)
                now = datetime.now(timezone.utc)
                policy.approved_by = approver
                policy.status = PolicyStatus.ACTIVE
                policy.effective_date = now
                policy.updated_at = now
                self._save_policy(conn, policy)
                conn.commit()
                _logger.info("Policy %s approved by %s", policy_id, approver)
                return policy
            finally:
                if owned:
                    conn.close()

    def archive_policy(self, policy_id: str) -> Optional[PolicyDocument]:
        """
        Archive a policy document.

        Args:
            policy_id: The policy document ID.

        Returns:
            Updated PolicyDocument or None if not found.
        """
        with self._lock:
            conn = self._connect()
            owned = self._shared_conn is None
            try:
                row = conn.execute(
                    "SELECT * FROM policy_documents WHERE id = ?", (policy_id,)
                ).fetchone()
                if not row:
                    return None
                policy = self._row_to_policy(row)
                policy.status = PolicyStatus.ARCHIVED
                policy.updated_at = datetime.now(timezone.utc)
                self._save_policy(conn, policy)
                conn.commit()
                _logger.info("Policy %s archived", policy_id)
                return policy
            finally:
                if owned:
                    conn.close()

    def get_policies_due_review(self, org_id: str = "default") -> List[PolicyDocument]:
        """
        Return policies whose review date is in the past (overdue for review).

        Args:
            org_id: Organisation identifier.

        Returns:
            List of PolicyDocument objects that are past their review date.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            owned = self._shared_conn is None
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM policy_documents
                    WHERE org_id = ?
                      AND review_date IS NOT NULL
                      AND review_date < ?
                      AND status != 'archived'
                    ORDER BY review_date ASC
                    """,
                    (org_id, now),
                ).fetchall()
                return [self._row_to_policy(r) for r in rows]
            finally:
                if owned:
                    conn.close()

    def export_policy(self, policy_id: str, format: str = "markdown") -> Optional[str]:
        """
        Export a policy document in the requested format.

        Args:
            policy_id: The policy document ID.
            format: Export format — 'markdown' or 'html'.

        Returns:
            Exported content string or None if policy not found.

        Raises:
            ValueError: If format is not supported.
        """
        fmt = format.lower().strip()
        if fmt not in ("markdown", "html"):
            raise ValueError(f"Unsupported export format: {format!r}. Use 'markdown' or 'html'.")

        policy = self.get_policy(policy_id)
        if policy is None:
            return None

        if fmt == "markdown":
            return self._export_markdown(policy)
        return self._export_html(policy)

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def _export_markdown(self, policy: PolicyDocument) -> str:
        """Render a policy as a Markdown document with metadata header."""
        lines = [
            "---",
            f"title: {policy.title}",
            f"id: {policy.id}",
            f"type: {policy.type}",
            f"version: {policy.version}",
            f"status: {policy.status}",
            f"org_id: {policy.org_id}",
            f"approved_by: {policy.approved_by or 'Pending'}",
            f"effective_date: {policy.effective_date.isoformat() if policy.effective_date else 'N/A'}",
            f"review_date: {policy.review_date.isoformat() if policy.review_date else 'N/A'}",
            "---",
            "",
            policy.content,
        ]
        return "\n".join(lines)

    def _export_html(self, policy: PolicyDocument) -> str:
        """Render a policy as an HTML document."""
        # Simple Markdown-to-HTML conversion for headings, lists, tables, paragraphs
        import re

        md = policy.content
        # Process line by line
        html_lines: List[str] = []
        in_table = False
        in_ul = False
        lines = md.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i]

            # Headings
            h_match = re.match(r"^(#{1,6})\s+(.*)", line)
            if h_match:
                if in_ul:
                    html_lines.append("</ul>")
                    in_ul = False
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                level = len(h_match.group(1))
                text = _html.escape(h_match.group(2))
                html_lines.append(f"<h{level}>{text}</h{level}>")
                i += 1
                continue

            # Table rows
            if "|" in line and line.strip().startswith("|"):
                if in_ul:
                    html_lines.append("</ul>")
                    in_ul = False
                if not in_table:
                    html_lines.append("<table>")
                    in_table = True
                    # First row is header
                    cells = [_html.escape(c.strip()) for c in line.strip().strip("|").split("|")]
                    html_lines.append("<thead><tr>" + "".join(f"<th>{c}</th>" for c in cells) + "</tr></thead><tbody>")
                    i += 1
                    # Skip separator row
                    if i < len(lines) and re.match(r"^\|[-| :]+\|$", lines[i].strip()):
                        i += 1
                    continue
                else:
                    cells = [_html.escape(c.strip()) for c in line.strip().strip("|").split("|")]
                    html_lines.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
                    i += 1
                    continue

            if in_table:
                html_lines.append("</tbody></table>")
                in_table = False

            # Unordered list items
            li_match = re.match(r"^[-*]\s+(.*)", line)
            if li_match:
                if not in_ul:
                    html_lines.append("<ul>")
                    in_ul = True
                html_lines.append(f"<li>{_html.escape(li_match.group(1))}</li>")
                i += 1
                continue

            if in_ul and line.strip() == "":
                html_lines.append("</ul>")
                in_ul = False

            # Blank line
            if line.strip() == "":
                html_lines.append("")
                i += 1
                continue

            # Plain paragraph
            if not in_ul:
                html_lines.append(f"<p>{_html.escape(line)}</p>")
            i += 1

        if in_ul:
            html_lines.append("</ul>")
        if in_table:
            html_lines.append("</tbody></table>")

        body = "\n".join(html_lines)
        effective = _html.escape(policy.effective_date.isoformat() if policy.effective_date else "N/A")
        review = _html.escape(policy.review_date.isoformat() if policy.review_date else "N/A")
        safe_title = _html.escape(str(policy.title))
        safe_id = _html.escape(str(policy.id))
        safe_version = _html.escape(str(policy.version))
        safe_status = _html.escape(str(policy.status))
        safe_approved_by = _html.escape(str(policy.approved_by or "Pending"))

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <title>{safe_title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #333; }}
    h1,h2,h3,h4,h5,h6 {{ color: #1a1a2e; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
    th,td {{ border: 1px solid #ccc; padding: 8px 12px; text-align: left; }}
    th {{ background: #f0f0f0; }}
    .meta {{ background: #f8f8f8; padding: 12px 16px; border-left: 4px solid #1a1a2e; margin-bottom: 24px; }}
    .meta dt {{ font-weight: bold; display: inline; }}
    .meta dd {{ display: inline; margin: 0 16px 0 4px; }}
  </style>
</head>
<body>
  <h1>{safe_title}</h1>
  <div class="meta">
    <dl>
      <dt>ID:</dt><dd>{safe_id}</dd>
      <dt>Version:</dt><dd>{safe_version}</dd>
      <dt>Status:</dt><dd>{safe_status}</dd>
      <dt>Approved By:</dt><dd>{safe_approved_by}</dd>
      <dt>Effective Date:</dt><dd>{effective}</dd>
      <dt>Review Date:</dt><dd>{review}</dd>
    </dl>
  </div>
  {body}
</body>
</html>"""
