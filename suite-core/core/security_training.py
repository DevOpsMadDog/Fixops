"""Security Training & Awareness Tracker — ALDECI Platform.

Provides a full training catalog, role-based requirements, per-user and per-department
completion tracking, compliance mapping, effectiveness metrics, gamification, and
external certification management.

Usage:
    from core.security_training import SecurityTrainingTracker, get_training_tracker
    tracker = get_training_tracker()
    tracker.assign_training("user-123", "owasp-top10")
    tracker.record_completion("user-123", "owasp-top10", score=92)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
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
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_TRAINING_DB", ".fixops_data/security_training.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TrainingCategory(str, Enum):
    SECURE_CODING = "secure_coding"
    CLOUD_SECURITY = "cloud_security"
    COMPLIANCE = "compliance"
    INCIDENT_RESPONSE = "incident_response"
    PHISHING_AWARENESS = "phishing_awareness"
    SOCIAL_ENGINEERING = "social_engineering"
    DATA_HANDLING = "data_handling"
    THREAT_MODELING = "threat_modeling"
    LEADERSHIP = "leadership"
    SECURITY_CHAMPIONS = "security_champions"


class UserRole(str, Enum):
    DEVELOPER = "developer"
    DEVOPS = "devops"
    MANAGER = "manager"
    EXECUTIVE = "executive"
    ALL_STAFF = "all_staff"
    SECURITY_CHAMPION = "security_champion"


class ComplianceFramework(str, Enum):
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    ISO_27001 = "iso_27001"
    NIST = "nist"
    GDPR = "gdpr"


class CompletionStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    OVERDUE = "overdue"
    WAIVED = "waived"


class BadgeType(str, Enum):
    FIRST_COMPLETION = "first_completion"
    PERFECT_SCORE = "perfect_score"
    STREAK_7 = "streak_7_days"
    STREAK_30 = "streak_30_days"
    PHISHING_RESISTANT = "phishing_resistant"
    COMPLIANCE_CHAMPION = "compliance_champion"
    SECURITY_CHAMPION = "security_champion"
    SPEED_LEARNER = "speed_learner"
    TEAM_LEADER = "team_leader"


class CertificationStatus(str, Enum):
    ACTIVE = "active"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    IN_PROGRESS = "in_progress"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class ComplianceMapping(BaseModel):
    framework: ComplianceFramework
    control_id: str
    control_name: str
    description: str


class TrainingModule(BaseModel):
    id: str = Field(default_factory=lambda: f"tm-{uuid.uuid4().hex[:10]}")
    title: str
    description: str
    category: TrainingCategory
    duration_minutes: int = Field(ge=5, le=480)
    passing_score: int = Field(default=70, ge=0, le=100)
    required_roles: List[UserRole] = Field(default_factory=list)
    compliance_mappings: List[ComplianceMapping] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    version: str = "1.0"
    points: int = Field(default=100, ge=0)
    active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TrainingCompletion(BaseModel):
    id: str = Field(default_factory=lambda: f"tc-{uuid.uuid4().hex[:10]}")
    user_id: str
    module_id: str
    status: CompletionStatus = CompletionStatus.NOT_STARTED
    assigned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    due_date: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    pre_quiz_score: Optional[int] = None
    post_quiz_score: Optional[int] = None
    score: Optional[int] = None
    passed: bool = False
    certificate_id: Optional[str] = None
    time_spent_minutes: Optional[int] = None
    attempts: int = 0
    notes: Optional[str] = None


class UserTrainingProfile(BaseModel):
    user_id: str
    email: str
    display_name: str
    role: UserRole
    department: str
    org_id: str = "default"
    points: int = 0
    badges: List[str] = Field(default_factory=list)
    streak_days: int = 0
    last_activity_date: Optional[datetime] = None
    opt_in_gamification: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExternalCertification(BaseModel):
    id: str = Field(default_factory=lambda: f"cert-{uuid.uuid4().hex[:10]}")
    user_id: str
    certification_name: str
    issuing_body: str
    cert_id: Optional[str] = None
    obtained_date: datetime
    expiry_date: Optional[datetime] = None
    status: CertificationStatus = CertificationStatus.ACTIVE
    renewal_reminder_days: int = 90
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PhishingSimulation(BaseModel):
    id: str = Field(default_factory=lambda: f"phish-{uuid.uuid4().hex[:10]}")
    user_id: str
    campaign_id: str
    sent_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    clicked: bool = False
    clicked_at: Optional[datetime] = None
    reported: bool = False
    reported_at: Optional[datetime] = None
    training_assigned_after: bool = False


class DepartmentStats(BaseModel):
    department: str
    org_id: str
    total_users: int
    total_assigned: int
    total_completed: int
    completion_rate: float
    average_score: float
    compliance_percentage: float
    overdue_count: int
    top_performer: Optional[str] = None


class LeaderboardEntry(BaseModel):
    rank: int
    user_id: str
    display_name: str
    department: str
    points: int
    badges_count: int
    streak_days: int
    completion_rate: float


# ---------------------------------------------------------------------------
# Training Catalog — 20+ built-in modules
# ---------------------------------------------------------------------------

_BUILT_IN_MODULES: List[Dict[str, Any]] = [
    {
        "id": "owasp-top10",
        "title": "OWASP Top 10 Security Risks",
        "description": "Comprehensive coverage of the OWASP Top 10 web application security risks including injection, broken authentication, XSS, and more.",
        "category": TrainingCategory.SECURE_CODING,
        "duration_minutes": 90,
        "passing_score": 75,
        "required_roles": [UserRole.DEVELOPER, UserRole.SECURITY_CHAMPION],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC6.1", "control_name": "Logical Access Controls", "description": "Security awareness for access control vulnerabilities"},
            {"framework": ComplianceFramework.PCI_DSS, "control_id": "12.6", "control_name": "Security Awareness Program", "description": "Formal security awareness program for all personnel"},
        ],
        "tags": ["owasp", "web-security", "vulnerabilities"],
        "points": 150,
    },
    {
        "id": "secure-coding-python",
        "title": "Secure Coding in Python",
        "description": "Python-specific secure coding practices: input validation, SQL injection prevention, cryptography best practices, dependency scanning.",
        "category": TrainingCategory.SECURE_CODING,
        "duration_minutes": 60,
        "passing_score": 75,
        "required_roles": [UserRole.DEVELOPER],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC7.1", "control_name": "System Operations", "description": "Secure development practices"},
        ],
        "tags": ["python", "secure-coding", "sast"],
        "points": 120,
    },
    {
        "id": "secure-coding-javascript",
        "title": "Secure Coding in JavaScript / TypeScript",
        "description": "Frontend and Node.js security: XSS prevention, CSRF tokens, prototype pollution, npm supply chain attacks, Content Security Policy.",
        "category": TrainingCategory.SECURE_CODING,
        "duration_minutes": 60,
        "passing_score": 75,
        "required_roles": [UserRole.DEVELOPER],
        "compliance_mappings": [],
        "tags": ["javascript", "typescript", "frontend-security", "nodejs"],
        "points": 120,
    },
    {
        "id": "secure-coding-go",
        "title": "Secure Coding in Go",
        "description": "Go security fundamentals: safe concurrency, avoiding race conditions, proper error handling, HTTP security, go module verification.",
        "category": TrainingCategory.SECURE_CODING,
        "duration_minutes": 45,
        "passing_score": 75,
        "required_roles": [UserRole.DEVELOPER],
        "compliance_mappings": [],
        "tags": ["golang", "secure-coding", "concurrency"],
        "points": 110,
    },
    {
        "id": "secure-coding-java",
        "title": "Secure Coding in Java",
        "description": "Java security: deserialization vulnerabilities, Spring Security, Log4Shell class of vulnerabilities, cryptographic APIs, JNDI injection.",
        "category": TrainingCategory.SECURE_CODING,
        "duration_minutes": 75,
        "passing_score": 75,
        "required_roles": [UserRole.DEVELOPER],
        "compliance_mappings": [],
        "tags": ["java", "spring", "deserialization", "log4shell"],
        "points": 130,
    },
    {
        "id": "cloud-security-fundamentals",
        "title": "Cloud Security Fundamentals",
        "description": "Core cloud security concepts: IAM least privilege, S3 bucket policies, VPC security groups, encryption at rest and in transit, CloudTrail.",
        "category": TrainingCategory.CLOUD_SECURITY,
        "duration_minutes": 90,
        "passing_score": 70,
        "required_roles": [UserRole.DEVOPS, UserRole.DEVELOPER],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC6.6", "control_name": "Logical Access Controls", "description": "Cloud access management and monitoring"},
            {"framework": ComplianceFramework.ISO_27001, "control_id": "A.9.4", "control_name": "System and Application Access Control", "description": "Cloud system access controls"},
        ],
        "tags": ["cloud", "aws", "azure", "gcp", "iam"],
        "points": 140,
    },
    {
        "id": "iac-security",
        "title": "Infrastructure as Code Security",
        "description": "Securing Terraform, Kubernetes manifests, Helm charts, and Ansible playbooks. Secrets management, RBAC, pod security policies.",
        "category": TrainingCategory.CLOUD_SECURITY,
        "duration_minutes": 75,
        "passing_score": 70,
        "required_roles": [UserRole.DEVOPS],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC8.1", "control_name": "Change Management", "description": "Secure change management for infrastructure"},
        ],
        "tags": ["terraform", "kubernetes", "helm", "iac", "devops"],
        "points": 130,
    },
    {
        "id": "incident-response-procedures",
        "title": "Incident Response Procedures",
        "description": "IR lifecycle: detection, containment, eradication, recovery, lessons learned. Tabletop exercises, escalation paths, communication templates.",
        "category": TrainingCategory.INCIDENT_RESPONSE,
        "duration_minutes": 120,
        "passing_score": 80,
        "required_roles": [UserRole.DEVELOPER, UserRole.DEVOPS, UserRole.MANAGER, UserRole.SECURITY_CHAMPION],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC7.3", "control_name": "Incident Response", "description": "Security incident response procedures"},
            {"framework": ComplianceFramework.HIPAA, "control_id": "164.308(a)(6)", "control_name": "Security Incident Procedures", "description": "Implement policies and procedures to address security incidents"},
            {"framework": ComplianceFramework.ISO_27001, "control_id": "A.16.1", "control_name": "Management of Information Security Incidents", "description": "Incident management"},
        ],
        "tags": ["incident-response", "ir", "tabletop", "soc"],
        "points": 180,
    },
    {
        "id": "phishing-awareness",
        "title": "Phishing Awareness & Defense",
        "description": "Recognising phishing, spear-phishing, vishing, and smishing attacks. Reporting procedures, MFA importance, credential hygiene.",
        "category": TrainingCategory.PHISHING_AWARENESS,
        "duration_minutes": 30,
        "passing_score": 80,
        "required_roles": [UserRole.ALL_STAFF, UserRole.DEVELOPER, UserRole.DEVOPS, UserRole.MANAGER, UserRole.EXECUTIVE],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC1.4", "control_name": "Security Awareness", "description": "All staff security awareness training"},
            {"framework": ComplianceFramework.PCI_DSS, "control_id": "12.6.1", "control_name": "Security Awareness Program", "description": "Annual security awareness education"},
            {"framework": ComplianceFramework.HIPAA, "control_id": "164.308(a)(5)", "control_name": "Security Awareness Training", "description": "Security reminders, protection from malicious software, log-in monitoring, password management"},
        ],
        "tags": ["phishing", "social-engineering", "email-security", "mfa"],
        "points": 100,
    },
    {
        "id": "social-engineering-defense",
        "title": "Social Engineering & Pretexting Defense",
        "description": "Advanced social engineering techniques: pretexting, baiting, quid pro quo, tailgating. Verification procedures and reporting culture.",
        "category": TrainingCategory.SOCIAL_ENGINEERING,
        "duration_minutes": 45,
        "passing_score": 75,
        "required_roles": [UserRole.ALL_STAFF, UserRole.DEVELOPER, UserRole.DEVOPS, UserRole.MANAGER, UserRole.EXECUTIVE],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC1.4", "control_name": "Security Awareness", "description": "Social engineering defense"},
        ],
        "tags": ["social-engineering", "pretexting", "physical-security"],
        "points": 110,
    },
    {
        "id": "data-handling-classification",
        "title": "Data Handling & Classification",
        "description": "Data classification tiers (public, internal, confidential, restricted), handling procedures, retention policies, secure disposal.",
        "category": TrainingCategory.DATA_HANDLING,
        "duration_minutes": 60,
        "passing_score": 80,
        "required_roles": [UserRole.ALL_STAFF, UserRole.DEVELOPER, UserRole.MANAGER, UserRole.EXECUTIVE],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC6.5", "control_name": "Logical and Physical Access Controls", "description": "Data classification and handling"},
            {"framework": ComplianceFramework.HIPAA, "control_id": "164.312(a)(2)(iv)", "control_name": "Encryption and Decryption", "description": "PHI data handling and encryption"},
            {"framework": ComplianceFramework.GDPR, "control_id": "Art.25", "control_name": "Data Protection by Design", "description": "Data classification aligned with GDPR"},
            {"framework": ComplianceFramework.PCI_DSS, "control_id": "3.1", "control_name": "Cardholder Data Retention", "description": "Cardholder data handling procedures"},
        ],
        "tags": ["data-classification", "gdpr", "hipaa", "pii", "pci"],
        "points": 120,
    },
    {
        "id": "compliance-soc2-overview",
        "title": "SOC 2 Compliance Overview",
        "description": "Trust Services Criteria: Security, Availability, Processing Integrity, Confidentiality, Privacy. Audit readiness, evidence collection.",
        "category": TrainingCategory.COMPLIANCE,
        "duration_minutes": 90,
        "passing_score": 75,
        "required_roles": [UserRole.DEVELOPER, UserRole.DEVOPS, UserRole.MANAGER],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC1.4", "control_name": "Security Awareness", "description": "SOC 2 security awareness training requirement"},
        ],
        "tags": ["soc2", "compliance", "audit", "trust-services"],
        "points": 140,
    },
    {
        "id": "compliance-hipaa",
        "title": "HIPAA Security & Privacy Rules",
        "description": "HIPAA Security Rule: administrative, physical, and technical safeguards. PHI handling, minimum necessary standard, breach notification.",
        "category": TrainingCategory.COMPLIANCE,
        "duration_minutes": 90,
        "passing_score": 80,
        "required_roles": [UserRole.DEVELOPER, UserRole.DEVOPS, UserRole.MANAGER],
        "compliance_mappings": [
            {"framework": ComplianceFramework.HIPAA, "control_id": "164.308(a)(5)", "control_name": "Security Awareness Training", "description": "Required HIPAA security awareness training for all workforce members"},
        ],
        "tags": ["hipaa", "phi", "healthcare", "privacy"],
        "points": 140,
    },
    {
        "id": "compliance-pci-dss",
        "title": "PCI-DSS for Developers & Engineers",
        "description": "PCI DSS v4.0 requirements relevant to engineers: secure development (Req 6), access control (Req 7), logging (Req 10), encryption (Req 4).",
        "category": TrainingCategory.COMPLIANCE,
        "duration_minutes": 75,
        "passing_score": 75,
        "required_roles": [UserRole.DEVELOPER, UserRole.DEVOPS],
        "compliance_mappings": [
            {"framework": ComplianceFramework.PCI_DSS, "control_id": "12.6", "control_name": "Security Awareness Program", "description": "Formal security awareness program"},
            {"framework": ComplianceFramework.PCI_DSS, "control_id": "6.3", "control_name": "Security Vulnerabilities Identified", "description": "Vulnerability management in software development"},
        ],
        "tags": ["pci-dss", "payment-card", "cardholder-data"],
        "points": 130,
    },
    {
        "id": "threat-modeling-stride",
        "title": "Threat Modeling with STRIDE",
        "description": "Structured threat modeling: STRIDE methodology, attack trees, data flow diagrams, threat prioritization using DREAD, countermeasure selection.",
        "category": TrainingCategory.THREAT_MODELING,
        "duration_minutes": 120,
        "passing_score": 75,
        "required_roles": [UserRole.DEVELOPER, UserRole.SECURITY_CHAMPION],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC3.2", "control_name": "COSO Principle 7", "description": "Risk identification and threat modeling"},
        ],
        "tags": ["threat-modeling", "stride", "dread", "attack-trees"],
        "points": 160,
    },
    {
        "id": "security-champions-program",
        "title": "Security Champions Program",
        "description": "Becoming an embedded security advocate: threat modeling facilitation, secure code review, security training evangelism, SAST/DAST tool operation.",
        "category": TrainingCategory.SECURITY_CHAMPIONS,
        "duration_minutes": 180,
        "passing_score": 80,
        "required_roles": [UserRole.SECURITY_CHAMPION],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC1.4", "control_name": "Security Awareness", "description": "Security champions as force multipliers for awareness"},
        ],
        "tags": ["security-champions", "ambassador", "leadership", "sdlc"],
        "points": 250,
    },
    {
        "id": "risk-awareness-managers",
        "title": "Security Risk Awareness for Managers",
        "description": "Risk management fundamentals for non-technical managers: risk appetite, residual risk, third-party risk, vendor assessments, security metrics.",
        "category": TrainingCategory.LEADERSHIP,
        "duration_minutes": 60,
        "passing_score": 70,
        "required_roles": [UserRole.MANAGER],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC1.2", "control_name": "COSO Principle 2", "description": "Board and management oversight of security"},
        ],
        "tags": ["risk-management", "managers", "vendor-risk"],
        "points": 120,
    },
    {
        "id": "board-level-risk",
        "title": "Board-Level Cybersecurity Risk Briefing",
        "description": "Executive-level cyber risk: materiality thresholds, SEC cyber disclosure rules, board oversight responsibilities, insurance, M&A due diligence.",
        "category": TrainingCategory.LEADERSHIP,
        "duration_minutes": 45,
        "passing_score": 65,
        "required_roles": [UserRole.EXECUTIVE],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC1.2", "control_name": "COSO Principle 2", "description": "Board oversight of security risk"},
        ],
        "tags": ["executive", "board", "cyber-risk", "sec-disclosure"],
        "points": 130,
    },
    {
        "id": "devsecops-fundamentals",
        "title": "DevSecOps Fundamentals",
        "description": "Shifting security left: SAST/DAST/SCA pipeline integration, secrets scanning, container image scanning, signed commits, SBOM generation.",
        "category": TrainingCategory.CLOUD_SECURITY,
        "duration_minutes": 90,
        "passing_score": 75,
        "required_roles": [UserRole.DEVOPS, UserRole.DEVELOPER],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC8.1", "control_name": "Change Management", "description": "Security controls in SDLC change management"},
        ],
        "tags": ["devsecops", "sast", "dast", "sca", "sbom", "pipeline"],
        "points": 150,
    },
    {
        "id": "password-mfa-hygiene",
        "title": "Password & MFA Hygiene",
        "description": "Strong password policies, password managers, MFA types (TOTP, FIDO2, SMS risks), credential stuffing defense, breached credential monitoring.",
        "category": TrainingCategory.PHISHING_AWARENESS,
        "duration_minutes": 20,
        "passing_score": 80,
        "required_roles": [UserRole.ALL_STAFF, UserRole.DEVELOPER, UserRole.DEVOPS, UserRole.MANAGER, UserRole.EXECUTIVE],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC6.1", "control_name": "Logical Access Controls", "description": "Password and MFA requirements"},
            {"framework": ComplianceFramework.NIST, "control_id": "IA-5", "control_name": "Authenticator Management", "description": "Password and authenticator controls"},
        ],
        "tags": ["passwords", "mfa", "totp", "fido2", "credential-hygiene"],
        "points": 80,
    },
    {
        "id": "supply-chain-security",
        "title": "Software Supply Chain Security",
        "description": "SolarWinds-class attacks, dependency confusion, typosquatting, SLSA framework, dependency pinning, sigstore/cosign, SBOM consumption.",
        "category": TrainingCategory.SECURE_CODING,
        "duration_minutes": 60,
        "passing_score": 75,
        "required_roles": [UserRole.DEVELOPER, UserRole.DEVOPS],
        "compliance_mappings": [
            {"framework": ComplianceFramework.SOC2, "control_id": "CC9.2", "control_name": "Risk Mitigation — Vendors", "description": "Software supply chain risk management"},
        ],
        "tags": ["supply-chain", "sbom", "slsa", "sigstore", "dependencies"],
        "points": 140,
    },
]

# Known external certifications
_KNOWN_CERTIFICATIONS = [
    "CISSP", "CEH", "OSCP", "OSCE3", "GPEN", "GWAPT", "GCIH", "GCIA",
    "AWS Security Specialty", "AWS Solutions Architect", "GCP Professional Cloud Security",
    "Azure Security Engineer", "CCSP", "SSCP", "CompTIA Security+", "CompTIA CySA+",
    "CompTIA CASP+", "CISM", "CISA", "CRISC", "Security+", "PNPT",
]

# Role-based required module IDs
_ROLE_REQUIREMENTS: Dict[str, List[str]] = {
    UserRole.DEVELOPER: [
        "owasp-top10", "phishing-awareness", "data-handling-classification",
        "password-mfa-hygiene", "social-engineering-defense", "supply-chain-security",
    ],
    UserRole.DEVOPS: [
        "cloud-security-fundamentals", "iac-security", "incident-response-procedures",
        "phishing-awareness", "data-handling-classification", "password-mfa-hygiene",
        "devsecops-fundamentals",
    ],
    UserRole.MANAGER: [
        "risk-awareness-managers", "incident-response-procedures", "phishing-awareness",
        "data-handling-classification", "password-mfa-hygiene", "social-engineering-defense",
        "compliance-soc2-overview",
    ],
    UserRole.EXECUTIVE: [
        "board-level-risk", "phishing-awareness", "data-handling-classification",
        "password-mfa-hygiene", "social-engineering-defense",
    ],
    UserRole.ALL_STAFF: [
        "phishing-awareness", "data-handling-classification", "password-mfa-hygiene",
        "social-engineering-defense",
    ],
    UserRole.SECURITY_CHAMPION: [
        "owasp-top10", "threat-modeling-stride", "security-champions-program",
        "incident-response-procedures", "phishing-awareness", "data-handling-classification",
        "password-mfa-hygiene", "supply-chain-security",
    ],
}

# Points for badges
_BADGE_POINTS: Dict[str, int] = {
    BadgeType.FIRST_COMPLETION: 50,
    BadgeType.PERFECT_SCORE: 100,
    BadgeType.STREAK_7: 75,
    BadgeType.STREAK_30: 200,
    BadgeType.PHISHING_RESISTANT: 150,
    BadgeType.COMPLIANCE_CHAMPION: 300,
    BadgeType.SECURITY_CHAMPION: 500,
    BadgeType.SPEED_LEARNER: 50,
    BadgeType.TEAM_LEADER: 200,
}


# ---------------------------------------------------------------------------
# DB Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _from_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Core Tracker
# ---------------------------------------------------------------------------

class SecurityTrainingTracker:
    """Security Training & Awareness Tracker — manages catalog, assignments, completions,
    compliance mapping, effectiveness metrics, gamification, and certifications."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._init_db()
        self._seed_catalog()
        logger.info("SecurityTrainingTracker initialised", db_path=db_path)

    # ------------------------------------------------------------------
    # DB Init
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS training_modules (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL,
                    duration_minutes INTEGER NOT NULL,
                    passing_score INTEGER NOT NULL DEFAULT 70,
                    required_roles TEXT NOT NULL DEFAULT '[]',
                    compliance_mappings TEXT NOT NULL DEFAULT '[]',
                    tags TEXT NOT NULL DEFAULT '[]',
                    version TEXT NOT NULL DEFAULT '1.0',
                    points INTEGER NOT NULL DEFAULT 100,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS user_profiles (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    department TEXT NOT NULL,
                    org_id TEXT NOT NULL DEFAULT 'default',
                    points INTEGER NOT NULL DEFAULT 0,
                    badges TEXT NOT NULL DEFAULT '[]',
                    streak_days INTEGER NOT NULL DEFAULT 0,
                    last_activity_date TEXT,
                    opt_in_gamification INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS completions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    module_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'not_started',
                    assigned_at TEXT NOT NULL,
                    due_date TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    pre_quiz_score INTEGER,
                    post_quiz_score INTEGER,
                    score INTEGER,
                    passed INTEGER NOT NULL DEFAULT 0,
                    certificate_id TEXT,
                    time_spent_minutes INTEGER,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    notes TEXT,
                    FOREIGN KEY (user_id) REFERENCES user_profiles(user_id),
                    UNIQUE(user_id, module_id)
                );

                CREATE TABLE IF NOT EXISTS external_certifications (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    certification_name TEXT NOT NULL,
                    issuing_body TEXT NOT NULL,
                    cert_id TEXT,
                    obtained_date TEXT NOT NULL,
                    expiry_date TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    renewal_reminder_days INTEGER NOT NULL DEFAULT 90,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES user_profiles(user_id)
                );

                CREATE TABLE IF NOT EXISTS phishing_simulations (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    clicked INTEGER NOT NULL DEFAULT 0,
                    clicked_at TEXT,
                    reported INTEGER NOT NULL DEFAULT 0,
                    reported_at TEXT,
                    training_assigned_after INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES user_profiles(user_id)
                );

                CREATE INDEX IF NOT EXISTS idx_completions_user ON completions(user_id);
                CREATE INDEX IF NOT EXISTS idx_completions_module ON completions(module_id);
                CREATE INDEX IF NOT EXISTS idx_completions_status ON completions(status);
                CREATE INDEX IF NOT EXISTS idx_certs_user ON external_certifications(user_id);
                CREATE INDEX IF NOT EXISTS idx_phish_user ON phishing_simulations(user_id);
                CREATE INDEX IF NOT EXISTS idx_phish_campaign ON phishing_simulations(campaign_id);
            """)

    # ------------------------------------------------------------------
    # Catalog seeding
    # ------------------------------------------------------------------

    def _seed_catalog(self) -> None:
        with self._lock, self._conn() as conn:
            for mod_data in _BUILT_IN_MODULES:
                existing = conn.execute(
                    "SELECT id FROM training_modules WHERE id = ?", (mod_data["id"],)
                ).fetchone()
                if existing:
                    continue
                now = _now().isoformat()
                conn.execute(
                    """INSERT INTO training_modules
                       (id, title, description, category, duration_minutes, passing_score,
                        required_roles, compliance_mappings, tags, version, points, active,
                        created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        mod_data["id"],
                        mod_data["title"],
                        mod_data["description"],
                        mod_data["category"].value if isinstance(mod_data["category"], TrainingCategory) else mod_data["category"],
                        mod_data["duration_minutes"],
                        mod_data["passing_score"],
                        json.dumps([r.value if isinstance(r, UserRole) else r for r in mod_data.get("required_roles", [])]),
                        json.dumps(mod_data.get("compliance_mappings", [])),
                        json.dumps(mod_data.get("tags", [])),
                        mod_data.get("version", "1.0"),
                        mod_data.get("points", 100),
                        1,
                        now,
                        now,
                    ),
                )

    # ------------------------------------------------------------------
    # Module helpers
    # ------------------------------------------------------------------

    def _row_to_module(self, row: sqlite3.Row) -> TrainingModule:
        d = dict(row)
        d["required_roles"] = json.loads(d["required_roles"])
        raw_mappings = json.loads(d["compliance_mappings"])
        mappings = []
        for m in raw_mappings:
            if isinstance(m, dict):
                mappings.append(ComplianceMapping(**m))
        d["compliance_mappings"] = mappings
        d["tags"] = json.loads(d["tags"])
        d["active"] = bool(d["active"])
        d["created_at"] = _from_iso(d["created_at"]) or _now()
        d["updated_at"] = _from_iso(d["updated_at"]) or _now()
        return TrainingModule(**d)

    def _row_to_completion(self, row: sqlite3.Row) -> TrainingCompletion:
        d = dict(row)
        d["passed"] = bool(d["passed"])
        for field in ("assigned_at", "due_date", "started_at", "completed_at"):
            d[field] = _from_iso(d[field])
        if d["assigned_at"] is None:
            d["assigned_at"] = _now()
        return TrainingCompletion(**d)

    def _row_to_profile(self, row: sqlite3.Row) -> UserTrainingProfile:
        d = dict(row)
        d["badges"] = json.loads(d["badges"])
        d["opt_in_gamification"] = bool(d["opt_in_gamification"])
        d["last_activity_date"] = _from_iso(d["last_activity_date"])
        d["created_at"] = _from_iso(d["created_at"]) or _now()
        return UserTrainingProfile(**d)

    def _row_to_cert(self, row: sqlite3.Row) -> ExternalCertification:
        d = dict(row)
        d["metadata"] = json.loads(d["metadata"])
        d["obtained_date"] = _from_iso(d["obtained_date"]) or _now()
        d["expiry_date"] = _from_iso(d["expiry_date"])
        d["created_at"] = _from_iso(d["created_at"]) or _now()
        return ExternalCertification(**d)

    def _row_to_phishing(self, row: sqlite3.Row) -> PhishingSimulation:
        d = dict(row)
        d["clicked"] = bool(d["clicked"])
        d["reported"] = bool(d["reported"])
        d["training_assigned_after"] = bool(d["training_assigned_after"])
        d["sent_at"] = _from_iso(d["sent_at"]) or _now()
        d["clicked_at"] = _from_iso(d["clicked_at"])
        d["reported_at"] = _from_iso(d["reported_at"])
        return PhishingSimulation(**d)

    # ------------------------------------------------------------------
    # Catalog API
    # ------------------------------------------------------------------

    def get_catalog(self, category: Optional[str] = None, role: Optional[str] = None) -> List[TrainingModule]:
        """Return all active training modules, optionally filtered by category or role.

        Role filtering is pushed into SQL via json_each so rows that don't match
        are never deserialized (avoids 3x json.loads + Pydantic construct per row).
        """
        with self._conn() as conn:
            if category and role:
                rows = conn.execute(
                    """SELECT m.* FROM training_modules m
                       WHERE m.active = 1 AND m.category = ?
                         AND (m.required_roles = '[]'
                              OR EXISTS (
                                SELECT 1 FROM json_each(m.required_roles) j
                                WHERE j.value = ?
                              ))""",
                    (category, role),
                ).fetchall()
            elif category:
                rows = conn.execute(
                    "SELECT * FROM training_modules WHERE active = 1 AND category = ?", (category,)
                ).fetchall()
            elif role:
                rows = conn.execute(
                    """SELECT m.* FROM training_modules m
                       WHERE m.active = 1
                         AND (m.required_roles = '[]'
                              OR EXISTS (
                                SELECT 1 FROM json_each(m.required_roles) j
                                WHERE j.value = ?
                              ))""",
                    (role,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM training_modules WHERE active = 1"
                ).fetchall()
        return [self._row_to_module(r) for r in rows]

    def get_module(self, module_id: str) -> Optional[TrainingModule]:
        """Return a single training module by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM training_modules WHERE id = ?", (module_id,)
            ).fetchone()
        return self._row_to_module(row) if row else None

    def add_module(self, module: TrainingModule) -> TrainingModule:
        """Add a custom training module to the catalog."""
        now = _now().isoformat()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO training_modules
                   (id, title, description, category, duration_minutes, passing_score,
                    required_roles, compliance_mappings, tags, version, points, active,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    module.id, module.title, module.description, module.category.value,
                    module.duration_minutes, module.passing_score,
                    json.dumps([r.value if isinstance(r, UserRole) else r for r in module.required_roles]),
                    json.dumps([m.model_dump() for m in module.compliance_mappings]),
                    json.dumps(module.tags), module.version, module.points,
                    1 if module.active else 0, now, now,
                ),
            )
        logger.info("Training module added", module_id=module.id, title=module.title)
        return module

    # ------------------------------------------------------------------
    # User Profile API
    # ------------------------------------------------------------------

    def register_user(self, profile: UserTrainingProfile) -> UserTrainingProfile:
        """Register or update a user's training profile."""
        now = _now().isoformat()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO user_profiles
                   (user_id, email, display_name, role, department, org_id, points, badges,
                    streak_days, last_activity_date, opt_in_gamification, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    profile.user_id, profile.email, profile.display_name,
                    profile.role.value if isinstance(profile.role, UserRole) else profile.role,
                    profile.department, profile.org_id, profile.points,
                    json.dumps(profile.badges), profile.streak_days,
                    _iso(profile.last_activity_date),
                    1 if profile.opt_in_gamification else 0, now,
                ),
            )
        # Auto-assign role-based required modules
        self._auto_assign_role_modules(profile.user_id, profile.role if isinstance(profile.role, str) else profile.role.value)
        logger.info("User registered for training", user_id=profile.user_id, role=profile.role)
        return profile

    def get_user_profile(self, user_id: str) -> Optional[UserTrainingProfile]:
        """Return a user's training profile."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM user_profiles WHERE user_id = ?", (user_id,)
            ).fetchone()
        return self._row_to_profile(row) if row else None

    def _auto_assign_role_modules(self, user_id: str, role: str) -> None:
        """Assign all role-required modules to a newly registered user."""
        required = _ROLE_REQUIREMENTS.get(role, [])
        for module_id in required:
            self.assign_training(user_id, module_id, due_days=90)

    # ------------------------------------------------------------------
    # Assignment & Completion API
    # ------------------------------------------------------------------

    def assign_training(self, user_id: str, module_id: str, due_days: int = 30) -> TrainingCompletion:
        """Assign a training module to a user. Idempotent — won't overwrite existing completions."""
        due = _now() + timedelta(days=due_days)
        completion_id = f"tc-{uuid.uuid4().hex[:10]}"
        now = _now()
        with self._lock, self._conn() as conn:
            existing = conn.execute(
                "SELECT * FROM completions WHERE user_id = ? AND module_id = ?",
                (user_id, module_id),
            ).fetchone()
            if existing:
                return self._row_to_completion(existing)
            conn.execute(
                """INSERT INTO completions
                   (id, user_id, module_id, status, assigned_at, due_date, attempts)
                   VALUES (?, ?, ?, ?, ?, ?, 0)""",
                (completion_id, user_id, module_id, CompletionStatus.NOT_STARTED.value,
                 now.isoformat(), due.isoformat()),
            )
        logger.info("Training assigned", user_id=user_id, module_id=module_id)
        return TrainingCompletion(
            id=completion_id, user_id=user_id, module_id=module_id,
            status=CompletionStatus.NOT_STARTED, assigned_at=now, due_date=due,
        )

    def start_training(self, user_id: str, module_id: str) -> Optional[TrainingCompletion]:
        """Mark training as in-progress for a user."""
        now = _now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE completions SET status = ?, started_at = ?
                   WHERE user_id = ? AND module_id = ? AND status = ?""",
                (CompletionStatus.IN_PROGRESS.value, now.isoformat(),
                 user_id, module_id, CompletionStatus.NOT_STARTED.value),
            )
            row = conn.execute(
                "SELECT * FROM completions WHERE user_id = ? AND module_id = ?",
                (user_id, module_id),
            ).fetchone()
        if not row:
            return None
        return self._row_to_completion(row)

    def record_completion(
        self,
        user_id: str,
        module_id: str,
        score: int,
        time_spent_minutes: Optional[int] = None,
        pre_quiz_score: Optional[int] = None,
        notes: Optional[str] = None,
    ) -> Optional[TrainingCompletion]:
        """Record a training completion with score. Awards points and badges if gamification enabled."""
        module = self.get_module(module_id)
        if not module:
            logger.warning("Module not found for completion", module_id=module_id)
            return None

        passed = score >= module.passing_score
        cert_id = f"cert-{uuid.uuid4().hex[:8]}" if passed else None
        now = _now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE completions SET status = ?, completed_at = ?, score = ?, passed = ?,
                   certificate_id = ?, time_spent_minutes = ?, pre_quiz_score = ?, notes = ?,
                   attempts = attempts + 1
                   WHERE user_id = ? AND module_id = ?""",
                (
                    CompletionStatus.COMPLETED.value if passed else CompletionStatus.IN_PROGRESS.value,
                    now.isoformat() if passed else None,
                    score, 1 if passed else 0, cert_id,
                    time_spent_minutes, pre_quiz_score, notes,
                    user_id, module_id,
                ),
            )
            row = conn.execute(
                "SELECT * FROM completions WHERE user_id = ? AND module_id = ?",
                (user_id, module_id),
            ).fetchone()

        if passed:
            self._award_points_and_badges(user_id, module, score, time_spent_minutes)

        logger.info(
            "Training completion recorded",
            user_id=user_id, module_id=module_id, score=score, passed=passed,
        )
        return self._row_to_completion(row) if row else None

    def _award_points_and_badges(
        self,
        user_id: str,
        module: TrainingModule,
        score: int,
        time_spent_minutes: Optional[int],
    ) -> None:
        """Award points and badges to a user for completing a module."""
        profile = self.get_user_profile(user_id)
        if not profile or not profile.opt_in_gamification:
            return

        earned_points = module.points
        new_badges = list(profile.badges)

        # First completion badge
        completions = self.get_user_completions(user_id)
        completed_count = sum(1 for c in completions if c.status == CompletionStatus.COMPLETED)
        if completed_count == 1:
            if BadgeType.FIRST_COMPLETION.value not in new_badges:
                new_badges.append(BadgeType.FIRST_COMPLETION.value)
                earned_points += _BADGE_POINTS[BadgeType.FIRST_COMPLETION]

        # Perfect score badge
        if score == 100 and BadgeType.PERFECT_SCORE.value not in new_badges:
            new_badges.append(BadgeType.PERFECT_SCORE.value)
            earned_points += _BADGE_POINTS[BadgeType.PERFECT_SCORE]

        # Speed learner: completed in less than half the expected duration
        if (time_spent_minutes and module.duration_minutes and
                time_spent_minutes < module.duration_minutes / 2 and
                BadgeType.SPEED_LEARNER.value not in new_badges):
            new_badges.append(BadgeType.SPEED_LEARNER.value)
            earned_points += _BADGE_POINTS[BadgeType.SPEED_LEARNER]

        # Update streak
        today = _now().date()
        last_active = profile.last_activity_date.date() if profile.last_activity_date else None
        new_streak = profile.streak_days
        if last_active is None or (today - last_active).days > 1:
            new_streak = 1
        elif last_active < today:
            new_streak = profile.streak_days + 1

        if new_streak >= 7 and BadgeType.STREAK_7.value not in new_badges:
            new_badges.append(BadgeType.STREAK_7.value)
            earned_points += _BADGE_POINTS[BadgeType.STREAK_7]
        if new_streak >= 30 and BadgeType.STREAK_30.value not in new_badges:
            new_badges.append(BadgeType.STREAK_30.value)
            earned_points += _BADGE_POINTS[BadgeType.STREAK_30]

        # Security champion badge: completed security champions program
        if module.id == "security-champions-program" and BadgeType.SECURITY_CHAMPION.value not in new_badges:
            new_badges.append(BadgeType.SECURITY_CHAMPION.value)
            earned_points += _BADGE_POINTS[BadgeType.SECURITY_CHAMPION]

        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE user_profiles SET points = points + ?, badges = ?,
                   streak_days = ?, last_activity_date = ? WHERE user_id = ?""",
                (earned_points, json.dumps(new_badges), new_streak, _now().isoformat(), user_id),
            )

    def get_user_completions(self, user_id: str) -> List[TrainingCompletion]:
        """Return all completion records for a user."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM completions WHERE user_id = ? ORDER BY assigned_at DESC",
                (user_id,),
            ).fetchall()
        return [self._row_to_completion(r) for r in rows]

    def get_overdue_users(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """Return a list of users with overdue training assignments."""
        now = _now().isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT c.user_id, c.module_id, c.due_date, u.email, u.display_name, u.department
                   FROM completions c
                   JOIN user_profiles u ON c.user_id = u.user_id
                   WHERE u.org_id = ? AND c.status NOT IN (?, ?)
                   AND c.due_date < ?
                   ORDER BY c.due_date ASC""",
                (org_id, CompletionStatus.COMPLETED.value, CompletionStatus.WAIVED.value, now),
            ).fetchall()
        result = []
        for r in rows:
            result.append({
                "user_id": r["user_id"],
                "module_id": r["module_id"],
                "due_date": r["due_date"],
                "email": r["email"],
                "display_name": r["display_name"],
                "department": r["department"],
                "days_overdue": max(
                    0,
                    (_now() - (_from_iso(r["due_date"]) or _now())).days,
                ),
            })
        # Update status in DB for overdue records
        self._mark_overdue(org_id)
        return result

    def _mark_overdue(self, org_id: str) -> None:
        now = _now().isoformat()
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE completions SET status = ?
                   WHERE status = ? AND due_date < ?
                   AND user_id IN (SELECT user_id FROM user_profiles WHERE org_id = ?)""",
                (CompletionStatus.OVERDUE.value, CompletionStatus.NOT_STARTED.value, now, org_id),
            )

    # ------------------------------------------------------------------
    # Department Stats
    # ------------------------------------------------------------------

    def get_department_stats(self, org_id: str = "default") -> List[DepartmentStats]:
        """Return per-department training completion statistics."""
        with self._conn() as conn:
            depts = conn.execute(
                "SELECT DISTINCT department FROM user_profiles WHERE org_id = ?", (org_id,)
            ).fetchall()

        stats = []
        for dept_row in depts:
            dept = dept_row["department"]
            with self._conn() as conn:
                user_rows = conn.execute(
                    "SELECT user_id FROM user_profiles WHERE org_id = ? AND department = ?",
                    (org_id, dept),
                ).fetchall()
                user_ids = [r["user_id"] for r in user_rows]
                if not user_ids:
                    continue
                placeholders = ",".join("?" * len(user_ids))
                total_assigned = conn.execute(
                    f"SELECT COUNT(*) as cnt FROM completions WHERE user_id IN ({placeholders})",  # nosec B608
                    user_ids,
                ).fetchone()["cnt"]
                total_completed = conn.execute(
                    f"SELECT COUNT(*) as cnt FROM completions WHERE user_id IN ({placeholders}) AND status = ?",  # nosec B608
                    user_ids + [CompletionStatus.COMPLETED.value],
                ).fetchone()["cnt"]
                avg_score_row = conn.execute(
                    f"SELECT AVG(score) as avg FROM completions WHERE user_id IN ({placeholders}) AND score IS NOT NULL",  # nosec B608
                    user_ids,
                ).fetchone()
                overdue_count = conn.execute(
                    f"SELECT COUNT(*) as cnt FROM completions WHERE user_id IN ({placeholders}) AND status = ?",  # nosec B608
                    user_ids + [CompletionStatus.OVERDUE.value],
                ).fetchone()["cnt"]
                top_performer = conn.execute(
                    f"""SELECT u.display_name, u.points FROM user_profiles uWHERE u.user_id IN ({placeholders}) ORDER BY u.points DESC LIMIT 1""",  # nosec B608
                    user_ids,
                ).fetchone()

            completion_rate = (total_completed / total_assigned * 100) if total_assigned > 0 else 0.0
            avg_score = float(avg_score_row["avg"]) if avg_score_row["avg"] else 0.0

            # Compliance: count modules mapped to compliance frameworks that are completed
            compliance_pct = completion_rate  # simplified: completion rate as proxy

            stats.append(DepartmentStats(
                department=dept,
                org_id=org_id,
                total_users=len(user_ids),
                total_assigned=total_assigned,
                total_completed=total_completed,
                completion_rate=round(completion_rate, 2),
                average_score=round(avg_score, 2),
                compliance_percentage=round(compliance_pct, 2),
                overdue_count=overdue_count,
                top_performer=top_performer["display_name"] if top_performer else None,
            ))
        return stats

    # ------------------------------------------------------------------
    # Compliance Mapping
    # ------------------------------------------------------------------

    def get_compliance_coverage(self, framework: str, org_id: str = "default") -> Dict[str, Any]:
        """Return training completion coverage for a specific compliance framework."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM training_modules WHERE active = 1"
            ).fetchall()

        modules_for_framework = []
        for row in rows:
            mappings = json.loads(row["compliance_mappings"])
            for m in mappings:
                if isinstance(m, dict) and m.get("framework") == framework:
                    modules_for_framework.append({
                        "module_id": row["id"],
                        "module_title": row["title"],
                        "control_id": m["control_id"],
                        "control_name": m["control_name"],
                    })

        if not modules_for_framework:
            return {"framework": framework, "controls": [], "coverage_percentage": 0.0}

        # Compute completion rate across all users in org
        with self._conn() as conn:
            user_rows = conn.execute(
                "SELECT user_id FROM user_profiles WHERE org_id = ?", (org_id,)
            ).fetchall()
        user_ids = [r["user_id"] for r in user_rows]

        coverage_details = []
        for item in modules_for_framework:
            if user_ids:
                placeholders = ",".join("?" * len(user_ids))
                with self._conn() as conn:
                    completed = conn.execute(
                        f"""SELECT COUNT(*) as cnt FROM completionsWHERE user_id IN ({placeholders}) AND module_id = ? AND status = ?""",  # nosec B608
                        user_ids + [item["module_id"], CompletionStatus.COMPLETED.value],
                    ).fetchone()["cnt"]
                pct = (completed / len(user_ids) * 100) if user_ids else 0.0
            else:
                pct = 0.0

            coverage_details.append({**item, "user_completion_pct": round(pct, 2)})

        overall = (
            sum(c["user_completion_pct"] for c in coverage_details) / len(coverage_details)
            if coverage_details else 0.0
        )

        return {
            "framework": framework,
            "controls": coverage_details,
            "coverage_percentage": round(overall, 2),
        }

    # ------------------------------------------------------------------
    # Effectiveness Metrics
    # ------------------------------------------------------------------

    def get_effectiveness_metrics(self, module_id: str) -> Dict[str, Any]:
        """Return effectiveness metrics for a training module: pre/post scores, improvement."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT pre_quiz_score, score, time_spent_minutes, attempts
                   FROM completions WHERE module_id = ? AND status = ?""",
                (module_id, CompletionStatus.COMPLETED.value),
            ).fetchall()

        if not rows:
            return {"module_id": module_id, "completions": 0}

        pre_scores = [r["pre_quiz_score"] for r in rows if r["pre_quiz_score"] is not None]
        post_scores = [r["score"] for r in rows if r["score"] is not None]
        times = [r["time_spent_minutes"] for r in rows if r["time_spent_minutes"] is not None]
        attempts_list = [r["attempts"] for r in rows]

        avg_pre = sum(pre_scores) / len(pre_scores) if pre_scores else None
        avg_post = sum(post_scores) / len(post_scores) if post_scores else None
        improvement = round(avg_post - avg_pre, 2) if (avg_pre and avg_post) else None

        return {
            "module_id": module_id,
            "completions": len(rows),
            "avg_pre_quiz_score": round(avg_pre, 2) if avg_pre else None,
            "avg_post_quiz_score": round(avg_post, 2) if avg_post else None,
            "score_improvement": improvement,
            "avg_time_spent_minutes": round(sum(times) / len(times), 2) if times else None,
            "avg_attempts": round(sum(attempts_list) / len(attempts_list), 2) if attempts_list else None,
            "pass_rate": round(len([r for r in rows if r["score"] and r["score"] >= 70]) / len(rows) * 100, 2),
        }

    def get_phishing_effectiveness(self, user_id: str) -> Dict[str, Any]:
        """Return phishing simulation click rates before/after security training."""
        with self._conn() as conn:
            sims = conn.execute(
                "SELECT * FROM phishing_simulations WHERE user_id = ? ORDER BY sent_at ASC",
                (user_id,),
            ).fetchall()
            training_completion = conn.execute(
                """SELECT completed_at FROM completions WHERE user_id = ? AND module_id = ?
                   AND status = ? ORDER BY completed_at ASC LIMIT 1""",
                (user_id, "phishing-awareness", CompletionStatus.COMPLETED.value),
            ).fetchone()

        if not sims:
            return {"user_id": user_id, "simulations_sent": 0}

        training_date = _from_iso(training_completion["completed_at"]) if training_completion else None
        pre, post = [], []
        for sim in sims:
            sim_date = _from_iso(sim["sent_at"])
            if training_date and sim_date and sim_date >= training_date:
                post.append(sim)
            else:
                pre.append(sim)

        def click_rate(subset: list) -> Optional[float]:
            if not subset:
                return None
            clicked = sum(1 for s in subset if s["clicked"])
            return round(clicked / len(subset) * 100, 2)

        return {
            "user_id": user_id,
            "simulations_sent": len(sims),
            "training_completed": training_date is not None,
            "training_completed_at": _iso(training_date),
            "pre_training_click_rate": click_rate(pre),
            "post_training_click_rate": click_rate(post),
            "improvement": (
                round((click_rate(pre) or 0) - (click_rate(post) or 0), 2)
                if (pre and post) else None
            ),
        }

    # ------------------------------------------------------------------
    # Gamification / Leaderboard
    # ------------------------------------------------------------------

    def get_leaderboard(self, org_id: str = "default", top_n: int = 10) -> List[LeaderboardEntry]:
        """Return the top-N users by points (only opt-in users)."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT u.user_id, u.display_name, u.department, u.points, u.badges, u.streak_days,
                          (SELECT COUNT(*) FROM completions c WHERE c.user_id = u.user_id AND c.status = ?) as completed,
                          (SELECT COUNT(*) FROM completions c WHERE c.user_id = u.user_id) as total
                   FROM user_profiles u
                   WHERE u.org_id = ? AND u.opt_in_gamification = 1
                   ORDER BY u.points DESC LIMIT ?""",
                (CompletionStatus.COMPLETED.value, org_id, top_n),
            ).fetchall()

        entries = []
        for i, r in enumerate(rows, start=1):
            total = r["total"] or 0
            completed = r["completed"] or 0
            completion_rate = round(completed / total * 100, 2) if total > 0 else 0.0
            badges = json.loads(r["badges"])
            entries.append(LeaderboardEntry(
                rank=i,
                user_id=r["user_id"],
                display_name=r["display_name"],
                department=r["department"],
                points=r["points"],
                badges_count=len(badges),
                streak_days=r["streak_days"],
                completion_rate=completion_rate,
            ))
        return entries

    # ------------------------------------------------------------------
    # External Certifications
    # ------------------------------------------------------------------

    def add_certification(self, cert: ExternalCertification) -> ExternalCertification:
        """Record an external certification for a user."""
        status = self._compute_cert_status(cert)
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO external_certifications
                   (id, user_id, certification_name, issuing_body, cert_id, obtained_date,
                    expiry_date, status, renewal_reminder_days, metadata, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cert.id, cert.user_id, cert.certification_name, cert.issuing_body,
                    cert.cert_id, _iso(cert.obtained_date), _iso(cert.expiry_date),
                    status.value, cert.renewal_reminder_days,
                    json.dumps(cert.metadata), _now().isoformat(),
                ),
            )
        logger.info("Certification added", user_id=cert.user_id, cert=cert.certification_name)
        cert.status = status
        return cert

    def _compute_cert_status(self, cert: ExternalCertification) -> CertificationStatus:
        if not cert.expiry_date:
            return CertificationStatus.ACTIVE
        now = _now()
        if cert.expiry_date <= now:
            return CertificationStatus.EXPIRED
        days_to_expiry = (cert.expiry_date - now).days
        if days_to_expiry <= cert.renewal_reminder_days:
            return CertificationStatus.EXPIRING_SOON
        return CertificationStatus.ACTIVE

    def get_user_certifications(self, user_id: str) -> List[ExternalCertification]:
        """Return all certifications for a user."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM external_certifications WHERE user_id = ? ORDER BY obtained_date DESC",
                (user_id,),
            ).fetchall()
        return [self._row_to_cert(r) for r in rows]

    def get_expiring_certifications(self, days: int = 90, org_id: str = "default") -> List[Dict[str, Any]]:
        """Return certifications expiring within the given number of days."""
        cutoff = (_now() + timedelta(days=days)).isoformat()
        now = _now().isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT ec.*, u.email, u.display_name, u.department
                   FROM external_certifications ec
                   JOIN user_profiles u ON ec.user_id = u.user_id
                   WHERE u.org_id = ? AND ec.expiry_date IS NOT NULL
                   AND ec.expiry_date > ? AND ec.expiry_date <= ?
                   ORDER BY ec.expiry_date ASC""",
                (org_id, now, cutoff),
            ).fetchall()

        results = []
        for r in rows:
            results.append({
                "cert_id": r["id"],
                "user_id": r["user_id"],
                "email": r["email"],
                "display_name": r["display_name"],
                "department": r["department"],
                "certification_name": r["certification_name"],
                "expiry_date": r["expiry_date"],
                "days_until_expiry": max(0, (_from_iso(r["expiry_date"]) - _now()).days) if r["expiry_date"] else None,
            })
        return results

    # ------------------------------------------------------------------
    # Phishing Simulation
    # ------------------------------------------------------------------

    def record_phishing_simulation(self, sim: PhishingSimulation) -> PhishingSimulation:
        """Record a phishing simulation event."""
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO phishing_simulations
                   (id, user_id, campaign_id, sent_at, clicked, clicked_at,
                    reported, reported_at, training_assigned_after)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sim.id, sim.user_id, sim.campaign_id, _iso(sim.sent_at),
                    1 if sim.clicked else 0, _iso(sim.clicked_at),
                    1 if sim.reported else 0, _iso(sim.reported_at),
                    1 if sim.training_assigned_after else 0,
                ),
            )
        # If clicked and not already assigned phishing training, auto-assign
        if sim.clicked:
            self.assign_training(sim.user_id, "phishing-awareness", due_days=7)
            with self._lock, self._conn() as conn:
                conn.execute(
                    "UPDATE phishing_simulations SET training_assigned_after = 1 WHERE id = ?",
                    (sim.id,),
                )
        logger.info(
            "Phishing simulation recorded",
            user_id=sim.user_id, campaign_id=sim.campaign_id, clicked=sim.clicked,
        )
        return sim

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_org_summary(self, org_id: str = "default") -> Dict[str, Any]:
        """Return a high-level training summary for an org."""
        with self._conn() as conn:
            total_users = conn.execute(
                "SELECT COUNT(*) as cnt FROM user_profiles WHERE org_id = ?", (org_id,)
            ).fetchone()["cnt"]
            total_assigned = conn.execute(
                """SELECT COUNT(*) as cnt FROM completions c
                   JOIN user_profiles u ON c.user_id = u.user_id WHERE u.org_id = ?""",
                (org_id,),
            ).fetchone()["cnt"]
            total_completed = conn.execute(
                """SELECT COUNT(*) as cnt FROM completions c
                   JOIN user_profiles u ON c.user_id = u.user_id
                   WHERE u.org_id = ? AND c.status = ?""",
                (org_id, CompletionStatus.COMPLETED.value),
            ).fetchone()["cnt"]
            overdue = conn.execute(
                """SELECT COUNT(*) as cnt FROM completions c
                   JOIN user_profiles u ON c.user_id = u.user_id
                   WHERE u.org_id = ? AND c.status = ?""",
                (org_id, CompletionStatus.OVERDUE.value),
            ).fetchone()["cnt"]
            avg_score_row = conn.execute(
                """SELECT AVG(c.score) as avg FROM completions c
                   JOIN user_profiles u ON c.user_id = u.user_id
                   WHERE u.org_id = ? AND c.score IS NOT NULL""",
                (org_id,),
            ).fetchone()

        completion_rate = round(total_completed / total_assigned * 100, 2) if total_assigned else 0.0
        return {
            "org_id": org_id,
            "total_users": total_users,
            "total_assigned": total_assigned,
            "total_completed": total_completed,
            "overdue": overdue,
            "completion_rate": completion_rate,
            "avg_score": round(float(avg_score_row["avg"]), 2) if avg_score_row["avg"] else None,
            "catalog_size": len(_BUILT_IN_MODULES),
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_tracker_instance: Optional[SecurityTrainingTracker] = None
_tracker_lock = threading.Lock()


def get_training_tracker(db_path: str = _DEFAULT_DB) -> SecurityTrainingTracker:
    """Return or create the singleton SecurityTrainingTracker."""
    global _tracker_instance
    if _tracker_instance is None:
        with _tracker_lock:
            if _tracker_instance is None:
                _tracker_instance = SecurityTrainingTracker(db_path=db_path)
    return _tracker_instance


# ---------------------------------------------------------------------------
# SecurityAwarenessTracker — high-level facade
# ---------------------------------------------------------------------------
# Additional models required by the facade API.

class TrainingAssignment(BaseModel):
    """Result of assigning a training module to a user."""
    assignment_id: str
    user_id: str
    module: str
    module_title: str
    due_date: Optional[datetime]
    status: CompletionStatus = CompletionStatus.NOT_STARTED
    assigned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PhishingCampaign(BaseModel):
    """Result of launching a phishing simulation campaign."""
    campaign_id: str
    user_ids: List[str]
    template: str
    sent_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    click_rate: float = 0.0
    clicks: List[str] = Field(default_factory=list)  # user_ids who clicked


class ComplianceReport(BaseModel):
    """Team training compliance report."""
    team_id: str
    total_users: int
    completion_rate: float
    overdue_count: int
    average_score: float
    highest_risk_users: List[str] = Field(default_factory=list)


# CWE → recommended training module
_CWE_MODULE_MAP: Dict[str, str] = {
    "CWE-89":  "owasp-top10",           # SQL injection
    "CWE-79":  "owasp-top10",           # XSS
    "CWE-22":  "owasp-top10",           # Path traversal
    "CWE-78":  "secure-coding-python",  # OS command injection
    "CWE-77":  "secure-coding-python",  # Command injection
    "CWE-502": "secure-coding-java",    # Deserialization
    "CWE-798": "password-mfa-hygiene",  # Hard-coded credentials
    "CWE-259": "password-mfa-hygiene",  # Hard-coded password
    "CWE-916": "password-mfa-hygiene",  # Weak password hash
    "CWE-200": "data-handling-classification",  # Info disclosure
    "CWE-312": "data-handling-classification",  # Cleartext storage
    "CWE-319": "data-handling-classification",  # Cleartext transmission
    "CWE-352": "secure-coding-javascript",      # CSRF
    "CWE-601": "owasp-top10",           # Open redirect
    "CWE-918": "cloud-security-fundamentals",   # SSRF
    "CWE-611": "secure-coding-java",    # XXE
}

# Phishing simulation templates (matches PhishingSimulator built-ins)
_PHISHING_TEMPLATES = [
    "tpl_cred_001", "tpl_cred_002",
    "tpl_mal_001",  "tpl_mal_002",
    "tpl_data_001", "tpl_data_002",
    "tpl_urg_001",  "tpl_urg_002",
    "tpl_auth_001", "tpl_auth_002",
]


class SecurityAwarenessTracker:
    """
    High-level facade for Security Awareness Training and Phishing Simulation.

    Delegates persistence to SecurityTrainingTracker (SQLite-backed).
    Provides the interface specified in the task spec:
      - assign_training / record_completion
      - run_phishing_simulation
      - get_user_risk_score
      - get_team_compliance
      - suggest_training
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._tracker = SecurityTrainingTracker(db_path=db_path)
        # Campaign store: campaign_id → PhishingCampaign (in-memory, lightweight)
        self._campaigns: Dict[str, PhishingCampaign] = {}
        self._campaign_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Training Assignment
    # ------------------------------------------------------------------

    def assign_training(
        self, user_id: str, module: str, due_date: Optional[datetime] = None
    ) -> TrainingAssignment:
        """
        Assign a training module to a user.

        Args:
            user_id: The user to assign training to.
            module: Module ID (e.g. "phishing-awareness", "owasp-top10").
            due_date: Optional deadline. Defaults to 30 days from now.

        Returns:
            TrainingAssignment with assignment metadata.
        """
        due_days = 30
        if due_date:
            delta = due_date - datetime.now(timezone.utc)
            due_days = max(1, delta.days)

        completion = self._tracker.assign_training(user_id, module, due_days=due_days)
        mod_obj = self._tracker.get_module(module)
        module_title = mod_obj.title if mod_obj else module

        return TrainingAssignment(
            assignment_id=completion.id,
            user_id=user_id,
            module=module,
            module_title=module_title,
            due_date=completion.due_date,
            status=completion.status,
            assigned_at=completion.assigned_at,
        )

    # ------------------------------------------------------------------
    # Completion Recording
    # ------------------------------------------------------------------

    def record_completion(
        self, user_id: str, assignment_id: str, score: float
    ) -> Optional[TrainingCompletion]:
        """
        Record training completion with a quiz score.

        Args:
            user_id: User who completed the training.
            assignment_id: The completion/assignment ID.
            score: Score achieved (0.0–100.0).

        Returns:
            Updated TrainingCompletion or None if assignment not found.
        """
        # Resolve module_id from the assignment record
        with self._tracker._conn() as conn:
            row = conn.execute(
                "SELECT module_id FROM completions WHERE id = ? AND user_id = ?",
                (assignment_id, user_id),
            ).fetchone()
        if not row:
            logger.warning("assign_not_found", assignment_id=assignment_id, user_id=user_id)
            return None
        module_id = row["module_id"]
        return self._tracker.record_completion(user_id, module_id, score=int(score))

    # ------------------------------------------------------------------
    # Phishing Simulation
    # ------------------------------------------------------------------

    def run_phishing_simulation(
        self, user_ids: List[str], template: str
    ) -> PhishingCampaign:
        """
        Launch a simulated phishing campaign.

        Records a PhishingSimulation event per user via SecurityTrainingTracker.
        Users who "click" are determined stochastically in this simulation (no
        real email is sent — ntfy.sh notification is sent to a campaign topic).

        Args:
            user_ids: List of user IDs to target.
            template: Phishing template ID (e.g. "tpl_cred_001").

        Returns:
            PhishingCampaign with campaign metadata.
        """
        campaign_id = f"camp-{uuid.uuid4().hex[:10]}"
        sent_at = datetime.now(timezone.utc)

        # Attempt ntfy.sh notification (non-blocking, best-effort)
        try:
            import urllib.request
            ntfy_url = f"https://ntfy.sh/aldeci-phishing-{campaign_id}"
            payload = json.dumps({
                "campaign_id": campaign_id,
                "template": template,
                "targets": len(user_ids),
                "sent_at": sent_at.isoformat(),
            }).encode()
            req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
                ntfy_url,
                data=payload,
                headers={"Content-Type": "application/json", "Title": "Phishing Sim Launched"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=2)  # nosemgrep: dynamic-urllib-use-detected  # nosec
            logger.info("ntfy_notification_sent", campaign_id=campaign_id)
        except Exception as exc:
            logger.warning("ntfy_notification_failed", error=str(exc))

        campaign = PhishingCampaign(
            campaign_id=campaign_id,
            user_ids=list(user_ids),
            template=template,
            sent_at=sent_at,
        )

        with self._campaign_lock:
            self._campaigns[campaign_id] = campaign

        # Record a PhishingSimulation for each user (not clicked by default —
        # clicks are recorded later via webhook callbacks)
        for uid in user_ids:
            sim = PhishingSimulation(
                user_id=uid,
                campaign_id=campaign_id,
                sent_at=sent_at,
                clicked=False,
            )
            self._tracker.record_phishing_simulation(sim)

        logger.info(
            "phishing_campaign_launched",
            campaign_id=campaign_id,
            template=template,
            targets=len(user_ids),
        )
        return campaign

    def record_phishing_click(self, campaign_id: str, user_id: str) -> PhishingCampaign:
        """
        Record that a user clicked the phishing link (webhook callback).

        Auto-assigns phishing awareness training for that user.

        Args:
            campaign_id: The campaign ID from run_phishing_simulation.
            user_id: The user who clicked.

        Returns:
            Updated PhishingCampaign.
        """
        with self._campaign_lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                raise ValueError(f"Campaign not found: {campaign_id}")
            if user_id not in campaign.clicks:
                campaign.clicks.append(user_id)
            total = len(campaign.user_ids)
            campaign.click_rate = round(len(campaign.clicks) / total, 3) if total else 0.0

        sim = PhishingSimulation(
            user_id=user_id,
            campaign_id=campaign_id,
            sent_at=campaign.sent_at,
            clicked=True,
            clicked_at=datetime.now(timezone.utc),
        )
        self._tracker.record_phishing_simulation(sim)
        return campaign

    # ------------------------------------------------------------------
    # User Risk Score
    # ------------------------------------------------------------------

    def get_user_risk_score(self, user_id: str) -> float:
        """
        Calculate a user risk score (0.0 = no risk, 1.0 = maximum risk).

        Factors:
          - Training completion rate (lower = higher risk)
          - Average quiz score (lower = higher risk)
          - Phishing click rate (higher = higher risk)
          - Recency of last activity (stale = higher risk)

        Returns:
            Risk score float in [0.0, 1.0].
        """
        # Training completion ratio
        completions = self._tracker.get_user_completions(user_id)
        total = len(completions)
        if total == 0:
            return 1.0  # No training at all — maximum risk

        completed = sum(1 for c in completions if c.status == CompletionStatus.COMPLETED)
        completion_ratio = completed / total  # 1.0 = all done, low risk

        # Average quiz score
        scores = [c.score for c in completions if c.score is not None]
        avg_score_ratio = (sum(scores) / len(scores) / 100.0) if scores else 0.0

        # Phishing effectiveness
        phishing_data = self._tracker.get_phishing_effectiveness(user_id)
        sims_sent = phishing_data.get("simulations_sent", 0)
        click_count = phishing_data.get("click_count", 0)
        phishing_click_rate = (click_count / sims_sent) if sims_sent > 0 else 0.0

        # Recency penalty: days since last activity (cap at 365)
        profile = self._tracker.get_user_profile(user_id)
        recency_penalty = 0.0
        if profile and profile.last_activity_date:
            days_since = (datetime.now(timezone.utc) - profile.last_activity_date).days
            recency_penalty = min(days_since / 365.0, 1.0) * 0.2  # max 0.2 penalty

        # Weighted risk
        training_risk = (1.0 - completion_ratio) * 0.35
        score_risk = (1.0 - avg_score_ratio) * 0.25
        phishing_risk = phishing_click_rate * 0.30

        risk = training_risk + score_risk + phishing_risk + recency_penalty
        return round(min(max(risk, 0.0), 1.0), 3)

    # ------------------------------------------------------------------
    # Team Compliance
    # ------------------------------------------------------------------

    def get_team_compliance(self, team_id: str) -> ComplianceReport:
        """
        Get training compliance report for a team/department.

        Args:
            team_id: Department name or org_id used as team identifier.

        Returns:
            ComplianceReport with completion rate, overdue count, risk users.
        """
        dept_stats = self._tracker.get_department_stats(org_id=team_id)

        if not dept_stats:
            # team_id may be a department within the default org
            all_stats = self._tracker.get_department_stats(org_id="default")
            dept_stats = [s for s in all_stats if s.department == team_id]

        if not dept_stats:
            return ComplianceReport(
                team_id=team_id,
                total_users=0,
                completion_rate=0.0,
                overdue_count=0,
                average_score=0.0,
            )

        # Aggregate across all department stats returned
        total_users = sum(s.total_users for s in dept_stats)
        total_assigned = sum(s.total_assigned for s in dept_stats)
        total_completed = sum(s.total_completed for s in dept_stats)
        overdue_count = sum(s.overdue_count for s in dept_stats)
        avg_score = (
            sum(s.average_score * s.total_users for s in dept_stats) / total_users
            if total_users > 0 else 0.0
        )
        completion_rate = (
            total_completed / total_assigned * 100.0 if total_assigned > 0 else 0.0
        )

        # Highest-risk users: overdue users in the team
        overdue_users = self._tracker.get_overdue_users(org_id=team_id)
        highest_risk = [u["user_id"] for u in overdue_users[:10]]

        return ComplianceReport(
            team_id=team_id,
            total_users=total_users,
            completion_rate=round(completion_rate, 2),
            overdue_count=overdue_count,
            average_score=round(avg_score, 2),
            highest_risk_users=highest_risk,
        )

    # ------------------------------------------------------------------
    # Training Suggestions
    # ------------------------------------------------------------------

    def suggest_training(
        self, user_id: str, recent_findings: Optional[List[str]] = None
    ) -> List[str]:
        """
        Suggest training modules based on recent security findings and user history.

        Args:
            user_id: Target user.
            recent_findings: List of CWE IDs or finding labels (e.g. ["CWE-89", "CWE-79"]).

        Returns:
            List of module IDs recommended for this user.
        """
        suggestions: List[str] = []

        # 1. CWE-based suggestions from recent findings
        for finding in (recent_findings or []):
            # Normalise to uppercase for matching
            key = finding.upper().strip()
            if key in _CWE_MODULE_MAP:
                mod_id = _CWE_MODULE_MAP[key]
                if mod_id not in suggestions:
                    suggestions.append(mod_id)

        # 2. Suggest phishing awareness if click rate is high
        phishing_data = self._tracker.get_phishing_effectiveness(user_id)
        click_count = phishing_data.get("click_count", 0)
        sims_sent = phishing_data.get("simulations_sent", 0)
        if sims_sent > 0 and click_count / sims_sent >= 0.3:
            if "phishing-awareness" not in suggestions:
                suggestions.append("phishing-awareness")

        # 3. Fill with incomplete required modules (risk-based)
        completions = self._tracker.get_user_completions(user_id)
        incomplete_ids = {
            c.module_id for c in completions
            if c.status not in (CompletionStatus.COMPLETED,)
        }
        # Prioritise modules with compliance mappings
        for mod in self._tracker.get_catalog():
            if mod.id in incomplete_ids and mod.id not in suggestions:
                if mod.compliance_mappings:
                    suggestions.append(mod.id)
                if len(suggestions) >= 5:
                    break

        return suggestions[:5]  # Cap at 5 recommendations

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def get_instance(cls, db_path: str = _DEFAULT_DB) -> "SecurityAwarenessTracker":
        """Return the process-level singleton."""
        if not hasattr(cls, "_instance") or cls._instance is None:
            cls._instance = cls(db_path=db_path)
        return cls._instance

    _instance: Optional["SecurityAwarenessTracker"] = None
