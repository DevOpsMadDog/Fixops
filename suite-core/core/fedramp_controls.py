"""
FedRAMP Compliance Controls Manager.

Provides FedRAMP baseline tracking (Low/Moderate/High), control family management,
gap analysis, System Security Plan (SSP) generation, and ALDECI feature mapping.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FedRAMPBaseline(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"


class ControlFamily(str, Enum):
    AC = "AC"  # Access Control
    AU = "AU"  # Audit and Accountability
    CA = "CA"  # Assessment, Authorization and Monitoring
    CM = "CM"  # Configuration Management
    CP = "CP"  # Contingency Planning
    IA = "IA"  # Identification and Authentication
    IR = "IR"  # Incident Response
    MA = "MA"  # Maintenance
    MP = "MP"  # Media Protection
    PE = "PE"  # Physical and Environmental Protection
    PL = "PL"  # Planning
    PS = "PS"  # Personnel Security
    RA = "RA"  # Risk Assessment
    SA = "SA"  # System and Services Acquisition
    SC = "SC"  # System and Communications Protection
    SI = "SI"  # System and Information Integrity


class ControlStatus(str, Enum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    PLANNED = "planned"
    NOT_APPLICABLE = "not_applicable"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class FedRAMPControl(BaseModel):
    """Represents a single FedRAMP security control."""

    id: str = Field(..., description="Control identifier, e.g. AC-1")
    family: ControlFamily
    title: str
    description: str
    baseline: List[FedRAMPBaseline] = Field(default_factory=list)
    status: ControlStatus = ControlStatus.PLANNED
    evidence_ids: List[str] = Field(default_factory=list)
    implementation_notes: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class POAMItem(BaseModel):
    """Plan of Action and Milestones item."""

    control_id: str
    weakness: str
    detection_date: str
    planned_completion_date: str
    responsible_party: str
    resources_required: str
    milestones: List[str] = Field(default_factory=list)
    status: str = "open"


class ComplianceScore(BaseModel):
    """Compliance score breakdown."""

    baseline: FedRAMPBaseline
    total_controls: int
    implemented: int
    partial: int
    planned: int
    not_applicable: int
    score_percent: float
    readiness_level: str


class GapAnalysis(BaseModel):
    """Gap analysis result."""

    baseline: FedRAMPBaseline
    total_required: int
    gaps: List[Dict[str, Any]]
    gap_count: int
    critical_gaps: List[str]


class SSPData(BaseModel):
    """System Security Plan data structure."""

    system_name: str
    system_owner: str
    baseline: FedRAMPBaseline
    generated_at: str
    controls: List[Dict[str, Any]]
    summary: Dict[str, int]
    feature_coverage: Dict[str, List[str]]


class FedRAMPStats(BaseModel):
    """Overall FedRAMP statistics."""

    total_controls: int
    by_status: Dict[str, int]
    by_family: Dict[str, int]
    by_baseline: Dict[str, int]
    scores: Dict[str, float]


# ---------------------------------------------------------------------------
# Built-in control catalogue (representative subset for all families)
# ---------------------------------------------------------------------------

_CONTROL_CATALOGUE: List[Dict[str, Any]] = [
    # Access Control
    {"id": "AC-1", "family": "AC", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate access control policy and procedures.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "AC-2", "family": "AC", "title": "Account Management",
     "description": "Manage information system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "AC-3", "family": "AC", "title": "Access Enforcement",
     "description": "Enforce approved authorizations for logical access to information and system resources.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "AC-4", "family": "AC", "title": "Information Flow Enforcement",
     "description": "Enforce approved authorizations for controlling the flow of information within and between systems.",
     "baseline": ["MODERATE", "HIGH"]},
    {"id": "AC-6", "family": "AC", "title": "Least Privilege",
     "description": "Employ the principle of least privilege, allowing only authorized accesses for users.",
     "baseline": ["MODERATE", "HIGH"]},
    {"id": "AC-17", "family": "AC", "title": "Remote Access",
     "description": "Establish and document usage restrictions and implementation guidance for remote access.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Audit and Accountability
    {"id": "AU-1", "family": "AU", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate an audit and accountability policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "AU-2", "family": "AU", "title": "Event Logging",
     "description": "Identify the types of events that the system is capable of logging.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "AU-3", "family": "AU", "title": "Content of Audit Records",
     "description": "Ensure audit records contain information to establish what type of event occurred.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "AU-6", "family": "AU", "title": "Audit Record Review, Analysis, and Reporting",
     "description": "Review and analyze system audit records for indications of inappropriate or unusual activity.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "AU-9", "family": "AU", "title": "Protection of Audit Information",
     "description": "Protect audit information and audit tools from unauthorized access, modification, and deletion.",
     "baseline": ["MODERATE", "HIGH"]},
    {"id": "AU-12", "family": "AU", "title": "Audit Record Generation",
     "description": "Provide audit record generation capability for auditable events.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Assessment, Authorization and Monitoring
    {"id": "CA-1", "family": "CA", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a security assessment and authorization policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "CA-2", "family": "CA", "title": "Control Assessments",
     "description": "Select the appropriate assessor or assessment team and assess the security controls.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "CA-3", "family": "CA", "title": "Information Exchange",
     "description": "Approve and manage the exchange of information between the system and other systems.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "CA-7", "family": "CA", "title": "Continuous Monitoring",
     "description": "Develop a continuous monitoring strategy and implement a continuous monitoring program.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Configuration Management
    {"id": "CM-1", "family": "CM", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a configuration management policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "CM-2", "family": "CM", "title": "Baseline Configuration",
     "description": "Develop, document, and maintain a current baseline configuration of the information system.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "CM-6", "family": "CM", "title": "Configuration Settings",
     "description": "Establish and document configuration settings for information technology products.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "CM-8", "family": "CM", "title": "System Component Inventory",
     "description": "Develop and document an inventory of system components.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Contingency Planning
    {"id": "CP-1", "family": "CP", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a contingency planning policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "CP-2", "family": "CP", "title": "Contingency Plan",
     "description": "Develop a contingency plan for the information system.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "CP-9", "family": "CP", "title": "System Backup",
     "description": "Conduct backups of user-level, system-level, and security-related documentation.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Identification and Authentication
    {"id": "IA-1", "family": "IA", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate an identification and authentication policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "IA-2", "family": "IA", "title": "Identification and Authentication (Organizational Users)",
     "description": "Uniquely identify and authenticate organizational users.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "IA-4", "family": "IA", "title": "Identifier Management",
     "description": "Manage information system identifiers for users and devices.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "IA-5", "family": "IA", "title": "Authenticator Management",
     "description": "Manage information system authenticators by verifying identity of user before distributing authenticator.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "IA-8", "family": "IA", "title": "Identification and Authentication (Non-Organizational Users)",
     "description": "Uniquely identify and authenticate non-organizational users.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Incident Response
    {"id": "IR-1", "family": "IR", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate an incident response policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "IR-2", "family": "IR", "title": "Incident Response Training",
     "description": "Provide incident response training to information system users.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "IR-4", "family": "IR", "title": "Incident Handling",
     "description": "Implement an incident handling capability for security incidents.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "IR-6", "family": "IR", "title": "Incident Reporting",
     "description": "Require personnel to report suspected security incidents to the organizational incident response capability.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Maintenance
    {"id": "MA-1", "family": "MA", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a system maintenance policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "MA-2", "family": "MA", "title": "Controlled Maintenance",
     "description": "Schedule, perform, document, and review records of maintenance and repairs on information system components.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Media Protection
    {"id": "MP-1", "family": "MP", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a media protection policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "MP-2", "family": "MP", "title": "Media Access",
     "description": "Restrict access to digital and non-digital media to authorized individuals.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "MP-6", "family": "MP", "title": "Media Sanitization",
     "description": "Sanitize digital and non-digital media prior to disposal or reuse.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Physical and Environmental Protection
    {"id": "PE-1", "family": "PE", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a physical and environmental protection policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "PE-2", "family": "PE", "title": "Physical Access Authorizations",
     "description": "Develop, approve, and maintain a list of individuals with authorized access to the facility.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Planning
    {"id": "PL-1", "family": "PL", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a security planning policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "PL-2", "family": "PL", "title": "System Security Plans",
     "description": "Develop a security plan for the system that is consistent with the organization's enterprise architecture.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Personnel Security
    {"id": "PS-1", "family": "PS", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a personnel security policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "PS-3", "family": "PS", "title": "Personnel Screening",
     "description": "Screen individuals prior to authorizing access to the information system.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # Risk Assessment
    {"id": "RA-1", "family": "RA", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a risk assessment policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "RA-2", "family": "RA", "title": "Security Categorization",
     "description": "Categorize the information system and information it processes, stores, and transmits.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "RA-3", "family": "RA", "title": "Risk Assessment",
     "description": "Conduct assessments of the risk and magnitude of harm that could result from unauthorized access.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "RA-5", "family": "RA", "title": "Vulnerability Monitoring and Scanning",
     "description": "Monitor and scan for vulnerabilities in the information system and hosted applications.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    # System and Services Acquisition
    {"id": "SA-1", "family": "SA", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a system and services acquisition policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "SA-3", "family": "SA", "title": "System Development Life Cycle",
     "description": "Manage the system using a system development life cycle that incorporates information security considerations.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "SA-11", "family": "SA", "title": "Developer Testing and Evaluation",
     "description": "Require the developer to implement a security assessment plan.",
     "baseline": ["MODERATE", "HIGH"]},
    # System and Communications Protection
    {"id": "SC-1", "family": "SC", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a system and communications protection policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "SC-7", "family": "SC", "title": "Boundary Protection",
     "description": "Monitor and control communications at the external boundary of the system.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "SC-8", "family": "SC", "title": "Transmission Confidentiality and Integrity",
     "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure of information during transmission.",
     "baseline": ["MODERATE", "HIGH"]},
    {"id": "SC-28", "family": "SC", "title": "Protection of Information at Rest",
     "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure of information at rest.",
     "baseline": ["MODERATE", "HIGH"]},
    # System and Information Integrity
    {"id": "SI-1", "family": "SI", "title": "Policy and Procedures",
     "description": "Develop, document, and disseminate a system and information integrity policy.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "SI-2", "family": "SI", "title": "Flaw Remediation",
     "description": "Identify, report, and correct information system flaws.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "SI-3", "family": "SI", "title": "Malicious Code Protection",
     "description": "Implement malicious code protection mechanisms at appropriate locations.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "SI-4", "family": "SI", "title": "System Monitoring",
     "description": "Monitor the information system to detect attacks and indicators of potential attacks.",
     "baseline": ["LOW", "MODERATE", "HIGH"]},
    {"id": "SI-10", "family": "SI", "title": "Information Input Validation",
     "description": "Check the validity of information inputs to detect attacks.",
     "baseline": ["MODERATE", "HIGH"]},
]

# ---------------------------------------------------------------------------
# ALDECI feature → FedRAMP control mapping
# ---------------------------------------------------------------------------

_ALDECI_FEATURE_CONTROL_MAP: Dict[str, List[str]] = {
    "RBAC": ["AC-1", "AC-2", "AC-3", "AC-6", "IA-2", "IA-4"],
    "MFA": ["IA-2", "IA-5", "IA-8"],
    "API_Key_Management": ["AC-2", "IA-4", "IA-5"],
    "Audit_Logging": ["AU-1", "AU-2", "AU-3", "AU-6", "AU-12"],
    "Audit_Tamper_Protection": ["AU-9"],
    "Encryption_In_Transit": ["SC-7", "SC-8"],
    "Encryption_At_Rest": ["SC-28"],
    "Vulnerability_Scanning": ["RA-5", "SI-2", "SI-3"],
    "Threat_Intelligence": ["SI-4", "RA-3", "IR-4"],
    "Incident_Response": ["IR-1", "IR-2", "IR-4", "IR-6"],
    "Asset_Inventory": ["CM-8", "CA-7"],
    "Compliance_Frameworks": ["CA-2", "RA-2", "PL-2"],
    "Continuous_Monitoring": ["CA-7", "SI-4", "AU-6"],
    "LLM_Council": ["SA-11", "CA-2"],
    "SSP_Generation": ["PL-2", "CA-1"],
    "Backup_Recovery": ["CP-2", "CP-9"],
    "Configuration_Management": ["CM-2", "CM-6"],
    "Risk_Scoring": ["RA-3", "RA-5"],
    "Connector_Framework": ["CA-3", "SC-7"],
    "TrustGraph": ["SI-4", "CA-7", "RA-3"],
}

# Readiness levels by score range
def _readiness_level(score: float) -> str:
    if score >= 90:
        return "Authorization Ready"
    elif score >= 75:
        return "Significant Progress"
    elif score >= 50:
        return "Moderate Progress"
    elif score >= 25:
        return "Early Stage"
    else:
        return "Initial"


# ---------------------------------------------------------------------------
# FedRAMPManager
# ---------------------------------------------------------------------------


class FedRAMPManager:
    """SQLite-backed FedRAMP control manager.

    Manages the full lifecycle of FedRAMP controls: tracking implementation
    status, generating gap analyses, producing SSP data, and mapping ALDECI
    platform features to specific controls.
    """

    def __init__(self, db_path: str = "data/fedramp.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_catalogue()

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS fedramp_controls (
                    id TEXT PRIMARY KEY,
                    family TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    baseline TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'planned',
                    evidence_ids TEXT NOT NULL DEFAULT '[]',
                    implementation_notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fedramp_family ON fedramp_controls(family);
                CREATE INDEX IF NOT EXISTS idx_fedramp_status ON fedramp_controls(status);

                CREATE TABLE IF NOT EXISTS fedramp_poam (
                    id TEXT PRIMARY KEY,
                    control_id TEXT NOT NULL,
                    weakness TEXT NOT NULL,
                    detection_date TEXT NOT NULL,
                    planned_completion_date TEXT NOT NULL,
                    responsible_party TEXT NOT NULL,
                    resources_required TEXT NOT NULL,
                    milestones TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (control_id) REFERENCES fedramp_controls(id)
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _seed_catalogue(self) -> None:
        """Insert catalogue controls if the table is empty."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT COUNT(*) as cnt FROM fedramp_controls").fetchone()
            if row["cnt"] > 0:
                return
            now = datetime.now(timezone.utc).isoformat()
            for ctrl in _CONTROL_CATALOGUE:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO fedramp_controls
                        (id, family, title, description, baseline, status,
                         evidence_ids, implementation_notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 'planned', '[]', '', ?, ?)
                    """,
                    (
                        ctrl["id"],
                        ctrl["family"],
                        ctrl["title"],
                        ctrl["description"],
                        json.dumps(ctrl["baseline"]),
                        now,
                        now,
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _row_to_control(self, row: sqlite3.Row) -> FedRAMPControl:
        return FedRAMPControl(
            id=row["id"],
            family=ControlFamily(row["family"]),
            title=row["title"],
            description=row["description"],
            baseline=[FedRAMPBaseline(b) for b in json.loads(row["baseline"])],
            status=ControlStatus(row["status"]),
            evidence_ids=json.loads(row["evidence_ids"]),
            implementation_notes=row["implementation_notes"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_control(self, control: FedRAMPControl) -> FedRAMPControl:
        """Insert or replace a control record."""
        now = datetime.now(timezone.utc).isoformat()
        control.updated_at = now
        if not control.created_at:
            control.created_at = now
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO fedramp_controls
                    (id, family, title, description, baseline, status,
                     evidence_ids, implementation_notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    control.id,
                    control.family.value,
                    control.title,
                    control.description,
                    json.dumps([b.value for b in control.baseline]),
                    control.status.value,
                    json.dumps(control.evidence_ids),
                    control.implementation_notes,
                    control.created_at,
                    control.updated_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return control

    def list_controls(
        self,
        family: Optional[ControlFamily] = None,
        baseline: Optional[FedRAMPBaseline] = None,
        status: Optional[ControlStatus] = None,
    ) -> List[FedRAMPControl]:
        """List controls with optional filters."""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM fedramp_controls WHERE 1=1"
            params: List[Any] = []
            if family:
                query += " AND family = ?"
                params.append(family.value)
            if status:
                query += " AND status = ?"
                params.append(status.value)
            rows = conn.execute(query, params).fetchall()
        finally:
            conn.close()

        controls = [self._row_to_control(r) for r in rows]

        if baseline:
            controls = [c for c in controls if baseline in c.baseline]

        return controls

    def get_control(self, control_id: str) -> Optional[FedRAMPControl]:
        """Retrieve a single control by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM fedramp_controls WHERE id = ?", (control_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return self._row_to_control(row)

    def update_status(
        self,
        control_id: str,
        status: ControlStatus,
        implementation_notes: str = "",
        evidence_ids: Optional[List[str]] = None,
    ) -> Optional[FedRAMPControl]:
        """Update the implementation status of a control."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_conn()
        try:
            existing = conn.execute(
                "SELECT * FROM fedramp_controls WHERE id = ?", (control_id,)
            ).fetchone()
            if existing is None:
                return None

            new_evidence = evidence_ids if evidence_ids is not None else json.loads(existing["evidence_ids"])
            new_notes = implementation_notes if implementation_notes else existing["implementation_notes"]

            conn.execute(
                """
                UPDATE fedramp_controls
                SET status = ?, implementation_notes = ?, evidence_ids = ?, updated_at = ?
                WHERE id = ?
                """,
                (status.value, new_notes, json.dumps(new_evidence), now, control_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM fedramp_controls WHERE id = ?", (control_id,)
            ).fetchone()
        finally:
            conn.close()
        return self._row_to_control(row)

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_compliance_score(self, baseline: FedRAMPBaseline) -> ComplianceScore:
        """Calculate compliance score for a given baseline."""
        controls = self.list_controls(baseline=baseline)
        total = len(controls)
        if total == 0:
            return ComplianceScore(
                baseline=baseline,
                total_controls=0,
                implemented=0,
                partial=0,
                planned=0,
                not_applicable=0,
                score_percent=0.0,
                readiness_level=_readiness_level(0.0),
            )

        implemented = sum(1 for c in controls if c.status == ControlStatus.IMPLEMENTED)
        partial = sum(1 for c in controls if c.status == ControlStatus.PARTIAL)
        planned = sum(1 for c in controls if c.status == ControlStatus.PLANNED)
        not_applicable = sum(1 for c in controls if c.status == ControlStatus.NOT_APPLICABLE)

        # NA controls don't count against the score
        scoreable = total - not_applicable
        if scoreable == 0:
            score = 100.0
        else:
            score = round(((implemented + partial * 0.5) / scoreable) * 100, 2)

        return ComplianceScore(
            baseline=baseline,
            total_controls=total,
            implemented=implemented,
            partial=partial,
            planned=planned,
            not_applicable=not_applicable,
            score_percent=score,
            readiness_level=_readiness_level(score),
        )

    def get_gap_analysis(self, baseline: FedRAMPBaseline) -> GapAnalysis:
        """Return controls that are not yet fully implemented for a baseline."""
        controls = self.list_controls(baseline=baseline)
        gaps = [
            {
                "control_id": c.id,
                "family": c.family.value,
                "title": c.title,
                "status": c.status.value,
                "implementation_notes": c.implementation_notes,
            }
            for c in controls
            if c.status in (ControlStatus.PLANNED, ControlStatus.PARTIAL)
        ]
        critical_families = {ControlFamily.AC, ControlFamily.IA, ControlFamily.AU, ControlFamily.SC}
        critical_gaps = [
            g["control_id"]
            for g in gaps
            if ControlFamily(g["family"]) in critical_families and g["status"] == ControlStatus.PLANNED.value
        ]
        return GapAnalysis(
            baseline=baseline,
            total_required=len(controls),
            gaps=gaps,
            gap_count=len(gaps),
            critical_gaps=critical_gaps,
        )

    # ------------------------------------------------------------------
    # SSP generation
    # ------------------------------------------------------------------

    def generate_ssp_data(
        self,
        baseline: FedRAMPBaseline,
        system_name: str = "ALDECI",
        system_owner: str = "DevOpsMadDog",
    ) -> SSPData:
        """Generate System Security Plan (SSP) data for the given baseline."""
        controls = self.list_controls(baseline=baseline)
        score = self.get_compliance_score(baseline)
        feature_coverage = self.map_aldeci_features_to_controls()

        controls_data = [
            {
                "control_id": c.id,
                "family": c.family.value,
                "title": c.title,
                "description": c.description,
                "status": c.status.value,
                "implementation_notes": c.implementation_notes,
                "evidence_ids": c.evidence_ids,
            }
            for c in controls
        ]

        return SSPData(
            system_name=system_name,
            system_owner=system_owner,
            baseline=baseline,
            generated_at=datetime.now(timezone.utc).isoformat(),
            controls=controls_data,
            summary={
                "total": score.total_controls,
                "implemented": score.implemented,
                "partial": score.partial,
                "planned": score.planned,
                "not_applicable": score.not_applicable,
            },
            feature_coverage=feature_coverage,
        )

    # ------------------------------------------------------------------
    # Feature mapping
    # ------------------------------------------------------------------

    def map_aldeci_features_to_controls(self) -> Dict[str, List[str]]:
        """Return mapping of ALDECI features to FedRAMP control IDs."""
        return dict(_ALDECI_FEATURE_CONTROL_MAP)

    def get_controls_for_feature(self, feature_name: str) -> List[FedRAMPControl]:
        """Return FedRAMP controls associated with a given ALDECI feature."""
        control_ids = _ALDECI_FEATURE_CONTROL_MAP.get(feature_name, [])
        controls = []
        for cid in control_ids:
            ctrl = self.get_control(cid)
            if ctrl:
                controls.append(ctrl)
        return controls

    # ------------------------------------------------------------------
    # POA&M
    # ------------------------------------------------------------------

    def get_poam(self, baseline: Optional[FedRAMPBaseline] = None) -> List[POAMItem]:
        """Generate Plan of Action & Milestones for unimplemented controls."""
        if baseline:
            controls = self.list_controls(baseline=baseline)
        else:
            controls = self.list_controls()

        poam_items = []
        detection_date = datetime.now(timezone.utc).isoformat()
        for ctrl in controls:
            if ctrl.status in (ControlStatus.PLANNED, ControlStatus.PARTIAL):
                poam_items.append(
                    POAMItem(
                        control_id=ctrl.id,
                        weakness=f"Control {ctrl.id} ({ctrl.title}) is {ctrl.status.value}.",
                        detection_date=detection_date,
                        planned_completion_date="",
                        responsible_party="Security Team",
                        resources_required="Engineering time",
                        milestones=[
                            f"Define implementation plan for {ctrl.id}",
                            f"Implement {ctrl.id} controls",
                            f"Test and validate {ctrl.id} implementation",
                            f"Document evidence for {ctrl.id}",
                        ],
                        status="open" if ctrl.status == ControlStatus.PLANNED else "in_progress",
                    )
                )
        return poam_items

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_fedramp_stats(self) -> FedRAMPStats:
        """Return aggregate statistics across all controls."""
        all_controls = self.list_controls()

        by_status: Dict[str, int] = {}
        by_family: Dict[str, int] = {}
        by_baseline: Dict[str, int] = {}

        for ctrl in all_controls:
            by_status[ctrl.status.value] = by_status.get(ctrl.status.value, 0) + 1
            by_family[ctrl.family.value] = by_family.get(ctrl.family.value, 0) + 1
            for b in ctrl.baseline:
                by_baseline[b.value] = by_baseline.get(b.value, 0) + 1

        scores = {
            bl.value: self.get_compliance_score(bl).score_percent
            for bl in FedRAMPBaseline
        }

        return FedRAMPStats(
            total_controls=len(all_controls),
            by_status=by_status,
            by_family=by_family,
            by_baseline=by_baseline,
            scores=scores,
        )
