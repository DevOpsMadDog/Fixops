"""
Compliance Gap Remediation Planner — generates specific remediation steps for
compliance gaps with effort estimates and progress tracking.

Supports 7 compliance frameworks: SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF,
CIS, GDPR.  Plans and remediations are persisted in SQLite.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EffortLevel(str, Enum):
    MINIMAL = "minimal"   # 1-2 hours
    LOW = "low"           # half-day
    MEDIUM = "medium"     # 1-2 days
    HIGH = "high"         # 3-5 days
    MAJOR = "major"       # 1-2 weeks


class RemediationPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ImplementationStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    BLOCKED = "blocked"


# ---------------------------------------------------------------------------
# Effort hours mapping
# ---------------------------------------------------------------------------

_EFFORT_HOURS: Dict[EffortLevel, float] = {
    EffortLevel.MINIMAL: 1.5,
    EffortLevel.LOW: 4.0,
    EffortLevel.MEDIUM: 12.0,
    EffortLevel.HIGH: 32.0,
    EffortLevel.MAJOR: 80.0,
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class GapRemediation(BaseModel):
    """A single remediation item for a compliance gap."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str
    control_id: str
    control_name: str
    gap_description: str
    remediation_steps: List[str]
    effort: EffortLevel
    priority: RemediationPriority
    status: ImplementationStatus = ImplementationStatus.NOT_STARTED
    assigned_to: Optional[str] = None
    target_date: Optional[datetime] = None
    findings_that_fix: List[str] = Field(default_factory=list)
    notes: str = ""
    org_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RemediationPlan(BaseModel):
    """An aggregated remediation plan for one framework and org."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str
    org_id: str
    total_gaps: int
    remediated: int
    in_progress: int
    blocked: int
    completion_pct: float
    estimated_total_effort_hours: float
    remediations: List[GapRemediation]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Built-in remediation templates keyed by (framework, control_id)
# ---------------------------------------------------------------------------

_REMEDIATION_TEMPLATES: Dict[str, Dict[str, Any]] = {
    # SOC2
    "SOC2:CC6.1": {
        "steps": [
            "Audit all user accounts and remove orphaned/inactive accounts.",
            "Implement role-based access control (RBAC) aligned to least-privilege.",
            "Deploy MFA for all privileged access paths.",
            "Document physical access controls and review badge logs quarterly.",
            "Generate and store access control policy document.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.CRITICAL,
    },
    "SOC2:CC6.2": {
        "steps": [
            "Enforce multi-factor authentication for all user logins.",
            "Configure password complexity and rotation policies.",
            "Integrate with SSO/IdP (Okta, Azure AD) for centralised authentication.",
            "Log all authentication events and ship to SIEM.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "SOC2:CC7.1": {
        "steps": [
            "Deploy centralised logging with retention ≥ 90 days.",
            "Configure anomaly detection alerts for failed logins and privilege escalation.",
            "Integrate with SIEM and set up dashboards.",
            "Schedule monthly review of system anomaly reports.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "SOC2:CC8.1": {
        "steps": [
            "Establish a formal change management process with approval workflow.",
            "Require peer-reviewed pull requests for all production changes.",
            "Maintain a change log and link changes to tickets.",
            "Conduct post-implementation reviews for significant changes.",
        ],
        "effort": EffortLevel.LOW,
        "priority": RemediationPriority.MEDIUM,
    },
    "SOC2:CC9.1": {
        "steps": [
            "Conduct a formal risk assessment covering business disruption scenarios.",
            "Document risk register with likelihood and impact ratings.",
            "Assign owners to each identified risk.",
            "Review and update the risk register semi-annually.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.MEDIUM,
    },
    "SOC2:A1.2": {
        "steps": [
            "Instrument application and infrastructure with performance metrics.",
            "Set up uptime monitoring with alerting below SLA thresholds.",
            "Document capacity planning process and review quarterly.",
            "Configure auto-scaling policies for peak loads.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.MEDIUM,
    },
    # PCI-DSS
    "PCI-DSS:1.1": {
        "steps": [
            "Install and configure a stateful firewall on all CDE boundaries.",
            "Document network topology including all data flows.",
            "Review and restrict ingress/egress rules to minimum required.",
            "Run quarterly firewall rule review and document results.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.CRITICAL,
    },
    "PCI-DSS:2.2": {
        "steps": [
            "Create hardening baseline for each system type (OS, DB, web server).",
            "Remove default credentials and disable unused services.",
            "Apply configuration baseline via configuration management tool (Ansible/Chef).",
            "Scan configurations quarterly with a CIS benchmark tool.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.HIGH,
    },
    "PCI-DSS:6.3": {
        "steps": [
            "Schedule monthly internal vulnerability scans using an ASV-approved scanner.",
            "Integrate vulnerability scanning into CI/CD pipeline.",
            "Establish SLA for remediation by severity (Critical: 24h, High: 7 days).",
            "Maintain vulnerability tracking in ticketing system.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "PCI-DSS:8.2": {
        "steps": [
            "Assign unique IDs to each user; prohibit shared accounts.",
            "Enforce MFA for all access into the CDE.",
            "Implement password complexity: minimum 12 chars, mixed case, numbers, symbols.",
            "Lock accounts after 6 failed attempts; require manual unlock.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.CRITICAL,
    },
    "PCI-DSS:10.2": {
        "steps": [
            "Enable audit logging on all CDE system components.",
            "Centralise logs to a secure, write-once log management system.",
            "Retain audit logs for at least 12 months (3 months immediately available).",
            "Generate daily summary reports and review for anomalies.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "PCI-DSS:11.3": {
        "steps": [
            "Engage a qualified security assessor for annual external penetration test.",
            "Conduct internal network penetration test annually and after major changes.",
            "Document scope, methodology, and findings for each test.",
            "Remediate critical/high findings within 30 days and verify remediation.",
        ],
        "effort": EffortLevel.MAJOR,
        "priority": RemediationPriority.HIGH,
    },
    "PCI-DSS:12.3": {
        "steps": [
            "Conduct a formal risk assessment of the cardholder data environment.",
            "Document risk assessment results and present to management.",
            "Obtain formal sign-off from executive stakeholders.",
            "Review risk assessment at least annually and after significant changes.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.MEDIUM,
    },
    # HIPAA
    "HIPAA:164.308(a)(1)": {
        "steps": [
            "Conduct a thorough risk analysis covering all ePHI assets.",
            "Document threats, vulnerabilities, and risk levels.",
            "Implement a risk management plan to reduce risks to an acceptable level.",
            "Review and update risk analysis annually and after environmental changes.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.CRITICAL,
    },
    "HIPAA:164.308(a)(3)": {
        "steps": [
            "Implement procedures for granting access to ePHI based on job role.",
            "Establish a workforce clearance procedure and background check policy.",
            "Revoke access within 24 hours of workforce member termination.",
            "Document and review access authorisation logs quarterly.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "HIPAA:164.308(a)(5)": {
        "steps": [
            "Develop a security awareness training curriculum covering phishing, malware, and PHI handling.",
            "Deliver training to all workforce members within 30 days of hire.",
            "Track training completion rates and follow up with non-compliant staff.",
            "Refresh training annually with updated threat scenarios.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.MEDIUM,
    },
    "HIPAA:164.312(a)(1)": {
        "steps": [
            "Implement unique user identification for all ePHI system access.",
            "Enforce automatic logoff after 15 minutes of inactivity.",
            "Deploy encryption for ePHI data at rest and in transit.",
            "Review and document access control configurations quarterly.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.CRITICAL,
    },
    "HIPAA:164.312(b)": {
        "steps": [
            "Enable audit controls on all systems that access ePHI.",
            "Centralise audit log collection with tamper-evident storage.",
            "Review audit logs weekly for anomalous access patterns.",
            "Retain audit logs for a minimum of 6 years.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "HIPAA:164.312(e)(1)": {
        "steps": [
            "Enforce TLS 1.2+ for all ePHI transmissions.",
            "Disable legacy protocols (TLS 1.0, SSL 3.0, SSLv2).",
            "Obtain and renew TLS certificates from a trusted CA.",
            "Perform quarterly TLS configuration scans using SSL Labs or equivalent.",
        ],
        "effort": EffortLevel.LOW,
        "priority": RemediationPriority.HIGH,
    },
    # ISO27001
    "ISO27001:A.5.1": {
        "steps": [
            "Draft an information security policy covering all key domains.",
            "Obtain management sign-off and publish the policy organisation-wide.",
            "Schedule annual policy review with documented sign-off.",
            "Communicate policy updates to all staff within 5 business days.",
        ],
        "effort": EffortLevel.LOW,
        "priority": RemediationPriority.HIGH,
    },
    "ISO27001:A.6.1": {
        "steps": [
            "Define and document information security roles and responsibilities.",
            "Appoint an Information Security Manager or equivalent.",
            "Establish an information security steering committee.",
            "Hold quarterly security governance meetings and document minutes.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.MEDIUM,
    },
    "ISO27001:A.8.1": {
        "steps": [
            "Create and maintain a complete inventory of information assets.",
            "Classify assets by sensitivity (public, internal, confidential, restricted).",
            "Assign an owner to each asset.",
            "Review and update the asset inventory annually.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.MEDIUM,
    },
    "ISO27001:A.9.1": {
        "steps": [
            "Define an access control policy based on business and security requirements.",
            "Implement need-to-know and least-privilege principles.",
            "Review user access rights at least every 6 months.",
            "Maintain a formal user registration and de-registration procedure.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "ISO27001:A.12.1": {
        "steps": [
            "Document operating procedures for all critical information processing activities.",
            "Implement change management process for operational changes.",
            "Separate development, testing, and production environments.",
            "Maintain capacity management plan with quarterly reviews.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.MEDIUM,
    },
    "ISO27001:A.18.1": {
        "steps": [
            "Identify all relevant legal, statutory, and regulatory requirements.",
            "Map requirements to existing controls and identify gaps.",
            "Engage legal counsel to review compliance posture annually.",
            "Document evidence of compliance for each applicable requirement.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.HIGH,
    },
    # NIST-CSF
    "NIST-CSF:ID.AM-1": {
        "steps": [
            "Deploy an automated asset discovery tool across all network segments.",
            "Maintain a hardware inventory including serial numbers and network addresses.",
            "Integrate asset inventory with vulnerability management system.",
            "Reconcile inventory monthly and investigate discrepancies.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "NIST-CSF:PR.AC-1": {
        "steps": [
            "Implement centralised identity management (IdP/SSO).",
            "Establish lifecycle management: provisioning, review, revocation.",
            "Enforce MFA for all privileged and remote access.",
            "Conduct quarterly access certification campaigns.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.HIGH,
    },
    "NIST-CSF:PR.DS-1": {
        "steps": [
            "Enable encryption at rest for all datastores containing sensitive data.",
            "Use AES-256 or equivalent for encryption keys.",
            "Implement key management solution with rotation policy.",
            "Scan storage systems for unencrypted sensitive data quarterly.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.CRITICAL,
    },
    "NIST-CSF:DE.CM-1": {
        "steps": [
            "Deploy network intrusion detection/prevention system (IDS/IPS).",
            "Configure network flow logging (NetFlow/IPFIX) for all segments.",
            "Integrate network monitoring data into SIEM.",
            "Define and tune alert thresholds to reduce false positives.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.HIGH,
    },
    "NIST-CSF:RS.RP-1": {
        "steps": [
            "Develop an Incident Response Plan (IRP) covering detection, containment, eradication, recovery.",
            "Assign roles and responsibilities for incident response.",
            "Conduct tabletop exercises at least annually.",
            "Review and update the IRP after each incident and annually.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "NIST-CSF:RC.RP-1": {
        "steps": [
            "Develop and document a disaster recovery and business continuity plan.",
            "Define Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO).",
            "Test recovery procedures at least annually via full DR drill.",
            "Update the plan after significant infrastructure changes.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.MEDIUM,
    },
    # CIS
    "CIS:CIS-1": {
        "steps": [
            "Deploy an active discovery tool to identify authorised and unauthorised devices.",
            "Maintain detailed hardware asset inventory with owner and classification.",
            "Implement network access control (NAC) to prevent unauthorised devices.",
            "Review and update asset inventory monthly.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "CIS:CIS-3": {
        "steps": [
            "Classify all data by sensitivity and apply appropriate handling procedures.",
            "Implement DLP (Data Loss Prevention) controls for sensitive data.",
            "Encrypt sensitive data at rest and in transit.",
            "Document data retention and disposal procedures and apply them.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.HIGH,
    },
    "CIS:CIS-5": {
        "steps": [
            "Maintain inventory of all accounts including service accounts.",
            "Disable or remove accounts inactive for more than 45 days.",
            "Enforce unique credentials for each account; prohibit sharing.",
            "Implement privileged account management (PAM) solution.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "CIS:CIS-7": {
        "steps": [
            "Establish a continuous vulnerability management programme.",
            "Run authenticated scans at least weekly on all systems.",
            "Prioritise remediation using CVSS scores and asset criticality.",
            "Track remediation progress and report metrics to management monthly.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "CIS:CIS-8": {
        "steps": [
            "Enable audit logging on all enterprise assets.",
            "Standardise log formats and centralise to a SIEM.",
            "Retain logs for at least 90 days (1 year recommended).",
            "Set up automated alerting for high-severity log events.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "CIS:CIS-12": {
        "steps": [
            "Maintain an up-to-date network infrastructure diagram.",
            "Apply security configuration baselines to all network devices.",
            "Restrict administrative access to network devices to authorised IPs only.",
            "Perform quarterly network device configuration audits.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.MEDIUM,
    },
    # GDPR
    "GDPR:Art.5": {
        "steps": [
            "Document the lawful basis for each data processing activity.",
            "Create or update the Record of Processing Activities (RoPA).",
            "Implement data minimisation practices across all collection points.",
            "Conduct annual review of processing activities for continued necessity.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.CRITICAL,
    },
    "GDPR:Art.13": {
        "steps": [
            "Create clear, plain-language privacy notices for all data collection points.",
            "Include all required GDPR Art.13 elements: controller identity, purposes, legal basis, rights.",
            "Deploy privacy notices at point of collection (forms, apps, websites).",
            "Review and update privacy notices annually or on process changes.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.HIGH,
    },
    "GDPR:Art.25": {
        "steps": [
            "Conduct Privacy Impact Assessments (PIAs) for new processing activities.",
            "Implement privacy-by-design principles in system architecture.",
            "Enable privacy settings by default (data minimisation, purpose limitation).",
            "Document technical and organisational measures for each processing activity.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.HIGH,
    },
    "GDPR:Art.32": {
        "steps": [
            "Implement encryption for personal data at rest and in transit.",
            "Deploy pseudonymisation where technically feasible.",
            "Establish procedures to ensure ongoing confidentiality, integrity, and availability.",
            "Test and evaluate effectiveness of security measures annually.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.CRITICAL,
    },
    "GDPR:Art.33": {
        "steps": [
            "Establish a data breach detection and notification process.",
            "Define a 72-hour notification procedure to the supervisory authority.",
            "Maintain a breach register with all incidents, even those not reported.",
            "Train staff on breach recognition and internal reporting obligations.",
        ],
        "effort": EffortLevel.MEDIUM,
        "priority": RemediationPriority.CRITICAL,
    },
    "GDPR:Art.17": {
        "steps": [
            "Implement automated mechanisms to action data erasure requests.",
            "Define retention schedules and automated deletion workflows.",
            "Ensure erasure propagates to all downstream processors and backups.",
            "Log and acknowledge erasure requests within 30 days.",
        ],
        "effort": EffortLevel.HIGH,
        "priority": RemediationPriority.HIGH,
    },
}

# Default template for unmapped controls
_DEFAULT_TEMPLATE: Dict[str, Any] = {
    "steps": [
        "Review control requirements and assess current state.",
        "Document the gap between current state and required state.",
        "Assign an owner responsible for closing the gap.",
        "Implement technical or procedural controls to satisfy the requirement.",
        "Collect evidence demonstrating control effectiveness.",
        "Schedule a review date to verify the control remains effective.",
    ],
    "effort": EffortLevel.MEDIUM,
    "priority": RemediationPriority.MEDIUM,
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _remediation_from_row(row: sqlite3.Row) -> GapRemediation:
    return GapRemediation(
        id=row["id"],
        framework=row["framework"],
        control_id=row["control_id"],
        control_name=row["control_name"],
        gap_description=row["gap_description"],
        remediation_steps=json.loads(row["remediation_steps"] or "[]"),
        effort=EffortLevel(row["effort"]),
        priority=RemediationPriority(row["priority"]),
        status=ImplementationStatus(row["status"]),
        assigned_to=row["assigned_to"],
        target_date=_parse_dt(row["target_date"]),
        findings_that_fix=json.loads(row["findings_that_fix"] or "[]"),
        notes=row["notes"] or "",
        org_id=row["org_id"],
        created_at=_parse_dt(row["created_at"]) or datetime.now(timezone.utc),
        updated_at=_parse_dt(row["updated_at"]) or datetime.now(timezone.utc),
    )


def _plan_from_row(row: sqlite3.Row, remediations: List[GapRemediation]) -> RemediationPlan:
    remediated = sum(
        1 for r in remediations
        if r.status in (ImplementationStatus.IMPLEMENTED, ImplementationStatus.VERIFIED)
    )
    in_progress = sum(1 for r in remediations if r.status == ImplementationStatus.IN_PROGRESS)
    blocked = sum(1 for r in remediations if r.status == ImplementationStatus.BLOCKED)
    total = len(remediations)
    completion_pct = (remediated / total * 100.0) if total > 0 else 0.0
    total_hours = sum(_EFFORT_HOURS.get(r.effort, 12.0) for r in remediations)

    return RemediationPlan(
        id=row["id"],
        framework=row["framework"],
        org_id=row["org_id"],
        total_gaps=total,
        remediated=remediated,
        in_progress=in_progress,
        blocked=blocked,
        completion_pct=round(completion_pct, 1),
        estimated_total_effort_hours=total_hours,
        remediations=remediations,
        created_at=_parse_dt(row["created_at"]) or datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# CompliancePlanner
# ---------------------------------------------------------------------------

class CompliancePlanner:
    """SQLite-backed compliance gap remediation planner."""

    def __init__(self, db_path: str = "data/compliance_planner.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS remediation_plans (
                    id TEXT PRIMARY KEY,
                    framework TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(framework, org_id)
                );

                CREATE INDEX IF NOT EXISTS idx_plans_org_id ON remediation_plans(org_id);
                CREATE INDEX IF NOT EXISTS idx_plans_framework ON remediation_plans(framework);

                CREATE TABLE IF NOT EXISTS gap_remediations (
                    id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    control_name TEXT NOT NULL,
                    gap_description TEXT NOT NULL,
                    remediation_steps TEXT NOT NULL DEFAULT '[]',
                    effort TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'not_started',
                    assigned_to TEXT,
                    target_date TEXT,
                    findings_that_fix TEXT NOT NULL DEFAULT '[]',
                    notes TEXT NOT NULL DEFAULT '',
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(plan_id) REFERENCES remediation_plans(id)
                );

                CREATE INDEX IF NOT EXISTS idx_rem_plan_id ON gap_remediations(plan_id);
                CREATE INDEX IF NOT EXISTS idx_rem_org_id ON gap_remediations(org_id);
                CREATE INDEX IF NOT EXISTS idx_rem_framework ON gap_remediations(framework);
                CREATE INDEX IF NOT EXISTS idx_rem_status ON gap_remediations(status);
                CREATE INDEX IF NOT EXISTS idx_rem_priority ON gap_remediations(priority);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_template(self, framework: str, control_id: str) -> Dict[str, Any]:
        key = f"{framework}:{control_id}"
        return _REMEDIATION_TEMPLATES.get(key, _DEFAULT_TEMPLATE)

    def _get_or_create_plan_id(
        self, conn: sqlite3.Connection, framework: str, org_id: str
    ) -> str:
        row = conn.execute(
            "SELECT id FROM remediation_plans WHERE framework = ? AND org_id = ?",
            (framework, org_id),
        ).fetchone()
        if row:
            return row["id"]
        plan_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO remediation_plans (id, framework, org_id, created_at) VALUES (?, ?, ?, ?)",
            (plan_id, framework, org_id, _now_iso()),
        )
        return plan_id

    def _load_remediations_for_plan(
        self, conn: sqlite3.Connection, plan_id: str
    ) -> List[GapRemediation]:
        rows = conn.execute(
            "SELECT * FROM gap_remediations WHERE plan_id = ? ORDER BY created_at",
            (plan_id,),
        ).fetchall()
        return [_remediation_from_row(r) for r in rows]

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def generate_plan(
        self,
        framework: str,
        gaps: List[Dict[str, Any]],
        org_id: str,
    ) -> RemediationPlan:
        """Auto-generate a remediation plan for a list of compliance gaps.

        Each gap dict should contain at minimum:
            control_id (str), control_name (str), gap_description (str).
        Optional: findings_that_fix (List[str]).
        """
        conn = self._get_connection()
        try:
            plan_id = self._get_or_create_plan_id(conn, framework, org_id)
            now = _now_iso()

            # Delete existing remediations for this plan so we can regenerate
            conn.execute(
                "DELETE FROM gap_remediations WHERE plan_id = ?", (plan_id,)
            )

            remediations: List[GapRemediation] = []
            for gap in gaps:
                control_id = gap.get("control_id", "UNKNOWN")
                control_name = gap.get("control_name", control_id)
                gap_description = gap.get("gap_description", f"Gap identified for control {control_id}")
                findings = gap.get("findings_that_fix", [])

                tmpl = self._get_template(framework, control_id)
                rem = GapRemediation(
                    framework=framework,
                    control_id=control_id,
                    control_name=control_name,
                    gap_description=gap_description,
                    remediation_steps=list(tmpl["steps"]),
                    effort=tmpl["effort"],
                    priority=tmpl["priority"],
                    findings_that_fix=findings,
                    org_id=org_id,
                )
                conn.execute(
                    """
                    INSERT INTO gap_remediations
                        (id, plan_id, framework, control_id, control_name, gap_description,
                         remediation_steps, effort, priority, status, assigned_to, target_date,
                         findings_that_fix, notes, org_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rem.id, plan_id, rem.framework, rem.control_id, rem.control_name,
                        rem.gap_description, json.dumps(rem.remediation_steps),
                        rem.effort.value, rem.priority.value, rem.status.value,
                        rem.assigned_to,
                        rem.target_date.isoformat() if rem.target_date else None,
                        json.dumps(rem.findings_that_fix), rem.notes, rem.org_id,
                        now, now,
                    ),
                )
                remediations.append(rem)

            conn.commit()

            plan_row = conn.execute(
                "SELECT * FROM remediation_plans WHERE id = ?", (plan_id,)
            ).fetchone()
            return _plan_from_row(plan_row, remediations)
        finally:
            conn.close()

    def get_plan(self, framework: str, org_id: str) -> Optional[RemediationPlan]:
        """Retrieve an existing remediation plan."""
        conn = self._get_connection()
        try:
            plan_row = conn.execute(
                "SELECT * FROM remediation_plans WHERE framework = ? AND org_id = ?",
                (framework, org_id),
            ).fetchone()
            if not plan_row:
                return None
            remediations = self._load_remediations_for_plan(conn, plan_row["id"])
            return _plan_from_row(plan_row, remediations)
        finally:
            conn.close()

    def list_plans(self, org_id: str) -> List[RemediationPlan]:
        """List all remediation plans for an org."""
        conn = self._get_connection()
        try:
            plan_rows = conn.execute(
                "SELECT * FROM remediation_plans WHERE org_id = ? ORDER BY created_at",
                (org_id,),
            ).fetchall()
            plans = []
            for plan_row in plan_rows:
                remediations = self._load_remediations_for_plan(conn, plan_row["id"])
                plans.append(_plan_from_row(plan_row, remediations))
            return plans
        finally:
            conn.close()

    def get_remediation(self, remediation_id: str) -> Optional[GapRemediation]:
        """Get a single remediation by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM gap_remediations WHERE id = ?", (remediation_id,)
            ).fetchone()
            return _remediation_from_row(row) if row else None
        finally:
            conn.close()

    def list_remediations(
        self,
        org_id: str,
        framework: Optional[str] = None,
        status_filter: Optional[ImplementationStatus] = None,
        priority_filter: Optional[RemediationPriority] = None,
    ) -> List[GapRemediation]:
        """List remediations with optional filters."""
        query = "SELECT * FROM gap_remediations WHERE org_id = ?"
        params: list = [org_id]
        if framework:
            query += " AND framework = ?"
            params.append(framework)
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter.value)
        if priority_filter:
            query += " AND priority = ?"
            params.append(priority_filter.value)
        query += " ORDER BY created_at"

        conn = self._get_connection()
        try:
            rows = conn.execute(query, params).fetchall()
            return [_remediation_from_row(r) for r in rows]
        finally:
            conn.close()

    def update_remediation_status(
        self,
        remediation_id: str,
        status: ImplementationStatus,
        notes: str = "",
    ) -> Optional[GapRemediation]:
        """Update the implementation status of a remediation item."""
        conn = self._get_connection()
        try:
            existing = conn.execute(
                "SELECT * FROM gap_remediations WHERE id = ?", (remediation_id,)
            ).fetchone()
            if not existing:
                return None

            current_notes = existing["notes"] or ""
            new_notes = notes if notes else current_notes

            conn.execute(
                "UPDATE gap_remediations SET status = ?, notes = ?, updated_at = ? WHERE id = ?",
                (status.value, new_notes, _now_iso(), remediation_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM gap_remediations WHERE id = ?", (remediation_id,)
            ).fetchone()
            return _remediation_from_row(row)
        finally:
            conn.close()

    def assign_remediation(
        self,
        remediation_id: str,
        assigned_to: str,
        target_date: Optional[datetime] = None,
    ) -> Optional[GapRemediation]:
        """Assign a remediation item to a person with an optional target date."""
        conn = self._get_connection()
        try:
            existing = conn.execute(
                "SELECT id FROM gap_remediations WHERE id = ?", (remediation_id,)
            ).fetchone()
            if not existing:
                return None

            conn.execute(
                "UPDATE gap_remediations SET assigned_to = ?, target_date = ?, updated_at = ? WHERE id = ?",
                (
                    assigned_to,
                    target_date.isoformat() if target_date else None,
                    _now_iso(),
                    remediation_id,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM gap_remediations WHERE id = ?", (remediation_id,)
            ).fetchone()
            return _remediation_from_row(row)
        finally:
            conn.close()

    def map_findings_to_controls(
        self, findings: List[str], framework: str
    ) -> Dict[str, List[str]]:
        """Return a mapping of control_id → list of findings that would satisfy it when fixed.

        This is a heuristic: findings are matched against control keywords.
        """
        control_keywords: Dict[str, List[str]] = {
            # SOC2
            "CC6.1": ["access", "permission", "privilege", "authentication", "mfa", "role"],
            "CC6.2": ["login", "auth", "password", "credential", "mfa", "sso"],
            "CC7.1": ["monitor", "alert", "anomaly", "log", "siem", "detection"],
            "CC8.1": ["change", "deploy", "release", "patch", "approval"],
            "CC9.1": ["risk", "threat", "vulnerability", "assessment"],
            "A1.2": ["availability", "uptime", "capacity", "performance", "sla"],
            # PCI-DSS
            "1.1": ["firewall", "network", "boundary", "ingress", "egress"],
            "2.2": ["config", "hardening", "baseline", "default", "credential"],
            "6.3": ["vulnerability", "patch", "cve", "scan"],
            "8.2": ["user", "account", "identity", "mfa", "password"],
            "10.2": ["log", "audit", "event", "siem"],
            "11.3": ["pentest", "penetration", "scan", "assessment"],
            "12.3": ["risk", "assessment", "cardholder"],
            # HIPAA
            "164.308(a)(1)": ["risk", "ephi", "phi", "assessment"],
            "164.308(a)(3)": ["workforce", "access", "employee", "termination"],
            "164.308(a)(5)": ["training", "awareness", "phishing"],
            "164.312(a)(1)": ["access", "encryption", "logoff", "ephi"],
            "164.312(b)": ["audit", "log", "access", "ephi"],
            "164.312(e)(1)": ["tls", "ssl", "encryption", "transit"],
            # ISO27001
            "A.5.1": ["policy", "information security", "governance"],
            "A.6.1": ["role", "responsibility", "governance", "committee"],
            "A.8.1": ["asset", "inventory", "classification"],
            "A.9.1": ["access", "control", "privilege"],
            "A.12.1": ["operations", "change", "procedure", "environment"],
            "A.18.1": ["compliance", "legal", "regulatory", "gdpr"],
            # NIST-CSF
            "ID.AM-1": ["asset", "inventory", "discovery"],
            "PR.AC-1": ["identity", "credential", "mfa", "access"],
            "PR.DS-1": ["encryption", "rest", "data", "storage"],
            "DE.CM-1": ["network", "monitor", "ids", "ips", "detection"],
            "RS.RP-1": ["incident", "response", "plan", "playbook"],
            "RC.RP-1": ["recovery", "disaster", "backup", "rto", "rpo"],
            # CIS
            "CIS-1": ["asset", "inventory", "device", "discovery"],
            "CIS-3": ["data", "classification", "dlp", "encryption"],
            "CIS-5": ["account", "user", "identity", "privilege"],
            "CIS-7": ["vulnerability", "scan", "patch", "cve"],
            "CIS-8": ["log", "audit", "siem", "retention"],
            "CIS-12": ["network", "infrastructure", "firewall", "router"],
            # GDPR
            "Art.5": ["processing", "lawful", "basis", "ropa"],
            "Art.13": ["privacy", "notice", "information", "data subject"],
            "Art.25": ["privacy by design", "pia", "dpia", "minimisation"],
            "Art.32": ["encryption", "security", "pseudonymisation"],
            "Art.33": ["breach", "notification", "incident"],
            "Art.17": ["erasure", "deletion", "right to be forgotten"],
        }

        result: Dict[str, List[str]] = {}
        framework_keywords = {
            k: v for k, v in control_keywords.items()
            if self._control_belongs_to_framework(k, framework)
        }

        for control_id, keywords in framework_keywords.items():
            matched = [
                f for f in findings
                if any(kw.lower() in f.lower() for kw in keywords)
            ]
            if matched:
                result[control_id] = matched

        return result

    def _control_belongs_to_framework(self, control_id: str, framework: str) -> bool:
        framework_prefixes: Dict[str, List[str]] = {
            "SOC2": ["CC", "A1"],
            "PCI-DSS": ["1.", "2.", "6.", "8.", "10.", "11.", "12."],
            "HIPAA": ["164."],
            "ISO27001": ["A."],
            "NIST-CSF": ["ID.", "PR.", "DE.", "RS.", "RC."],
            "CIS": ["CIS-"],
            "GDPR": ["Art."],
        }
        prefixes = framework_prefixes.get(framework, [])
        return any(control_id.startswith(p) for p in prefixes)

    def get_effort_summary(self, org_id: str) -> Dict[str, Any]:
        """Return total estimated effort hours by framework and by priority."""
        remediations = self.list_remediations(org_id)

        by_framework: Dict[str, float] = {}
        by_priority: Dict[str, float] = {}

        for rem in remediations:
            hours = _EFFORT_HOURS.get(rem.effort, 12.0)
            by_framework[rem.framework] = by_framework.get(rem.framework, 0.0) + hours
            by_priority[rem.priority.value] = by_priority.get(rem.priority.value, 0.0) + hours

        return {
            "total_hours": sum(by_framework.values()),
            "by_framework": by_framework,
            "by_priority": by_priority,
            "total_remediations": len(remediations),
        }

    def get_blocked_items(self, org_id: str) -> List[GapRemediation]:
        """Return all remediations currently in BLOCKED status."""
        return self.list_remediations(org_id, status_filter=ImplementationStatus.BLOCKED)

    def get_overdue_items(self, org_id: str) -> List[GapRemediation]:
        """Return remediations past their target date and not yet completed."""
        now = datetime.now(timezone.utc)
        remediations = self.list_remediations(org_id)
        return [
            r for r in remediations
            if r.target_date is not None
            and r.target_date < now
            and r.status not in (ImplementationStatus.IMPLEMENTED, ImplementationStatus.VERIFIED)
        ]

    def get_planner_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate statistics: by framework, by status, completion rates."""
        remediations = self.list_remediations(org_id)

        by_framework: Dict[str, Dict[str, int]] = {}
        by_status: Dict[str, int] = {}

        for rem in remediations:
            fw = rem.framework
            if fw not in by_framework:
                by_framework[fw] = {
                    "total": 0,
                    "not_started": 0,
                    "in_progress": 0,
                    "implemented": 0,
                    "verified": 0,
                    "blocked": 0,
                }
            by_framework[fw]["total"] += 1
            by_framework[fw][rem.status.value] += 1

            by_status[rem.status.value] = by_status.get(rem.status.value, 0) + 1

        # Completion rates per framework
        completion_rates: Dict[str, float] = {}
        for fw, counts in by_framework.items():
            done = counts["implemented"] + counts["verified"]
            total = counts["total"]
            completion_rates[fw] = round(done / total * 100.0, 1) if total > 0 else 0.0

        total = len(remediations)
        done_total = by_status.get("implemented", 0) + by_status.get("verified", 0)
        overall_completion = round(done_total / total * 100.0, 1) if total > 0 else 0.0

        return {
            "total_remediations": total,
            "by_framework": by_framework,
            "by_status": by_status,
            "completion_rates": completion_rates,
            "overall_completion_pct": overall_completion,
        }
