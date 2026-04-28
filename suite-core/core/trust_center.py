"""
ALDECI Trust Center — public-facing security/compliance page management.

Provides:
- TrustPageConfig, ComplianceBadge, SecurityControl, SubprocessorEntry, TrustCenterData models
- TrustCenterManager class (SQLite-backed, thread-safe)

Replaces what Vanta charges $10K+/yr for with a self-hosted equivalent.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore[assignment]


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus is not None:
            bus.emit(event_type, payload)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class TrustPageConfig(BaseModel):
    """Configuration for a public-facing trust page."""

    org_id: str
    org_name: str
    logo_url: Optional[str] = None
    brand_color: str = "#0066CC"
    enabled_sections: List[str] = Field(
        default_factory=lambda: ["compliance", "controls", "subprocessors"]
    )
    custom_message: Optional[str] = None
    contact_email: Optional[str] = None


class ComplianceBadge(BaseModel):
    """A compliance certification or attestation badge."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str  # SOC2, ISO27001, GDPR, HIPAA, PCI-DSS, etc.
    status: str  # certified | in_progress | planned
    certified_date: Optional[str] = None
    auditor: Optional[str] = None
    report_url: Optional[str] = None
    org_id: str = ""


class SecurityControl(BaseModel):
    """A security control with implementation status."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str  # Access Control, Encryption, Monitoring, etc.
    title: str
    description: str
    status: str  # implemented | planned
    org_id: str = ""


class SubprocessorEntry(BaseModel):
    """A sub-processor (third-party vendor) used by the organization."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    purpose: str
    location: str  # Country / region
    data_types: List[str] = Field(default_factory=list)
    org_id: str = ""


class TrustCenterData(BaseModel):
    """Aggregated public trust center page data — NO SECRETS."""

    config: TrustPageConfig
    badges: List[ComplianceBadge] = Field(default_factory=list)
    controls: List[SecurityControl] = Field(default_factory=list)
    subprocessors: List[SubprocessorEntry] = Field(default_factory=list)
    last_updated: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_configs (
    org_id          TEXT PRIMARY KEY,
    org_name        TEXT NOT NULL,
    logo_url        TEXT,
    brand_color     TEXT NOT NULL DEFAULT '#0066CC',
    enabled_sections TEXT NOT NULL DEFAULT '["compliance","controls","subprocessors"]',
    custom_message  TEXT,
    contact_email   TEXT
);

CREATE TABLE IF NOT EXISTS trust_badges (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    framework       TEXT NOT NULL,
    status          TEXT NOT NULL,
    certified_date  TEXT,
    auditor         TEXT,
    report_url      TEXT
);
CREATE INDEX IF NOT EXISTS idx_badges_org ON trust_badges (org_id);

CREATE TABLE IF NOT EXISTS trust_controls (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    status      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_controls_org ON trust_controls (org_id);

CREATE TABLE IF NOT EXISTS trust_subprocessors (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    name        TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    location    TEXT NOT NULL,
    data_types  TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_sub_org ON trust_subprocessors (org_id);
"""


# ---------------------------------------------------------------------------
# TrustCenterManager
# ---------------------------------------------------------------------------


class TrustCenterManager:
    """Thread-safe, SQLite-backed manager for public trust center pages.

    Usage::

        mgr = TrustCenterManager()
        mgr.configure(TrustPageConfig(org_id="acme", org_name="Acme Corp"))
        mgr.add_badge(ComplianceBadge(framework="SOC2", status="certified", org_id="acme"))
        page = mgr.get_public_page("acme")
    """

    _instance: Optional[TrustCenterManager] = None
    _instance_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def get_instance(cls, db_path: str | Path = ":memory:") -> TrustCenterManager:
        """Return the process-wide singleton, creating it if needed."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton (useful for tests)."""
        with cls._instance_lock:
            cls._instance = None

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = db_path if isinstance(db_path, Path) else Path(str(db_path))
        self._lock = threading.RLock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if str(self._db_path) == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem_conn.row_factory = sqlite3.Row
            return self._mem_conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript(_SCHEMA)
            conn.commit()

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def configure(self, config: TrustPageConfig) -> TrustPageConfig:
        """Upsert trust page configuration for an org."""
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO trust_configs
                    (org_id, org_name, logo_url, brand_color, enabled_sections,
                     custom_message, contact_email)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(org_id) DO UPDATE SET
                    org_name        = excluded.org_name,
                    logo_url        = excluded.logo_url,
                    brand_color     = excluded.brand_color,
                    enabled_sections = excluded.enabled_sections,
                    custom_message  = excluded.custom_message,
                    contact_email   = excluded.contact_email
                """,
                (
                    config.org_id,
                    config.org_name,
                    config.logo_url,
                    config.brand_color,
                    json.dumps(config.enabled_sections),
                    config.custom_message,
                    config.contact_email,
                ),
            )
            conn.commit()
        _logger.info("trust_center: configured org=%s", config.org_id)
        _tg_emit("trust_center.configure", {"org_id": config.org_id, "org_name": config.org_name})
        return config

    def get_config(self, org_id: str) -> Optional[TrustPageConfig]:
        """Return trust page config for org, or None if not found."""
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT * FROM trust_configs WHERE org_id = ?", (org_id,)
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["enabled_sections"] = json.loads(d.get("enabled_sections") or "[]")
        return TrustPageConfig(**d)

    # ------------------------------------------------------------------
    # Badges
    # ------------------------------------------------------------------

    def add_badge(self, badge: ComplianceBadge, org_id: str) -> ComplianceBadge:
        """Add or upsert a compliance badge for an org."""
        badge = badge.model_copy(update={"org_id": org_id})
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO trust_badges
                    (id, org_id, framework, status, certified_date, auditor, report_url)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    framework      = excluded.framework,
                    status         = excluded.status,
                    certified_date = excluded.certified_date,
                    auditor        = excluded.auditor,
                    report_url     = excluded.report_url
                """,
                (
                    badge.id,
                    badge.org_id,
                    badge.framework,
                    badge.status,
                    badge.certified_date,
                    badge.auditor,
                    badge.report_url,
                ),
            )
            conn.commit()
        _tg_emit("trust_center.add_badge", {"org_id": org_id, "framework": badge.framework, "status": badge.status})
        return badge

    def list_badges(self, org_id: str) -> List[ComplianceBadge]:
        """List all compliance badges for an org."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM trust_badges WHERE org_id = ? ORDER BY framework",
                (org_id,),
            ).fetchall()
        return [ComplianceBadge(**dict(r)) for r in rows]

    def delete_badge(self, badge_id: str, org_id: str) -> bool:
        """Delete a badge. Returns True if deleted, False if not found."""
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "DELETE FROM trust_badges WHERE id = ? AND org_id = ?",
                (badge_id, org_id),
            )
            conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def add_control(self, control: SecurityControl, org_id: str) -> SecurityControl:
        """Add or upsert a security control for an org."""
        control = control.model_copy(update={"org_id": org_id})
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO trust_controls
                    (id, org_id, category, title, description, status)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    category    = excluded.category,
                    title       = excluded.title,
                    description = excluded.description,
                    status      = excluded.status
                """,
                (
                    control.id,
                    control.org_id,
                    control.category,
                    control.title,
                    control.description,
                    control.status,
                ),
            )
            conn.commit()
        return control

    def list_controls(self, org_id: str) -> List[SecurityControl]:
        """List all security controls for an org."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM trust_controls WHERE org_id = ? ORDER BY category, title",
                (org_id,),
            ).fetchall()
        return [SecurityControl(**dict(r)) for r in rows]

    def delete_control(self, control_id: str, org_id: str) -> bool:
        """Delete a control. Returns True if deleted, False if not found."""
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "DELETE FROM trust_controls WHERE id = ? AND org_id = ?",
                (control_id, org_id),
            )
            conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Subprocessors
    # ------------------------------------------------------------------

    def add_subprocessor(self, entry: SubprocessorEntry, org_id: str) -> SubprocessorEntry:
        """Add or upsert a sub-processor entry for an org."""
        entry = entry.model_copy(update={"org_id": org_id})
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO trust_subprocessors
                    (id, org_id, name, purpose, location, data_types)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name       = excluded.name,
                    purpose    = excluded.purpose,
                    location   = excluded.location,
                    data_types = excluded.data_types
                """,
                (
                    entry.id,
                    entry.org_id,
                    entry.name,
                    entry.purpose,
                    entry.location,
                    json.dumps(entry.data_types),
                ),
            )
            conn.commit()
        return entry

    def list_subprocessors(self, org_id: str) -> List[SubprocessorEntry]:
        """List all sub-processor entries for an org."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM trust_subprocessors WHERE org_id = ? ORDER BY name",
                (org_id,),
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["data_types"] = json.loads(d.get("data_types") or "[]")
            result.append(SubprocessorEntry(**d))
        return result

    def delete_subprocessor(self, entry_id: str, org_id: str) -> bool:
        """Delete a sub-processor entry. Returns True if deleted."""
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "DELETE FROM trust_subprocessors WHERE id = ? AND org_id = ?",
                (entry_id, org_id),
            )
            conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Public page aggregation
    # ------------------------------------------------------------------

    def get_public_page(self, org_id: str) -> Optional[TrustCenterData]:
        """Return full public trust page data for an org — NO SECRETS.

        Returns None if the org has no trust page configured.
        """
        config = self.get_config(org_id)
        if config is None:
            return None
        return TrustCenterData(
            config=config,
            badges=self.list_badges(org_id),
            controls=self.list_controls(org_id),
            subprocessors=self.list_subprocessors(org_id),
            last_updated=datetime.now(timezone.utc).isoformat(),
        )

    # ------------------------------------------------------------------
    # Reports & stats
    # ------------------------------------------------------------------

    def generate_security_report(self, org_id: str) -> Dict[str, Any]:
        """Generate a downloadable security overview report dict."""
        config = self.get_config(org_id)
        badges = self.list_badges(org_id)
        controls = self.list_controls(org_id)
        subprocessors = self.list_subprocessors(org_id)

        certified = [b for b in badges if b.status == "certified"]
        in_progress = [b for b in badges if b.status == "in_progress"]
        implemented = [c for c in controls if c.status == "implemented"]
        planned = [c for c in controls if c.status == "planned"]

        # Group controls by category
        categories: Dict[str, List[str]] = {}
        for ctrl in controls:
            categories.setdefault(ctrl.category, []).append(ctrl.title)

        return {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "organization": config.org_name if config else org_id,
            "org_id": org_id,
            "compliance_summary": {
                "total_frameworks": len(badges),
                "certified": len(certified),
                "in_progress": len(in_progress),
                "planned": len(badges) - len(certified) - len(in_progress),
                "certifications": [
                    {
                        "framework": b.framework,
                        "status": b.status,
                        "certified_date": b.certified_date,
                        "auditor": b.auditor,
                    }
                    for b in badges
                ],
            },
            "security_controls": {
                "total": len(controls),
                "implemented": len(implemented),
                "planned": len(planned),
                "implementation_rate": (
                    round(len(implemented) / len(controls) * 100, 1) if controls else 0.0
                ),
                "by_category": categories,
            },
            "subprocessors": {
                "total": len(subprocessors),
                "list": [
                    {
                        "name": s.name,
                        "purpose": s.purpose,
                        "location": s.location,
                        "data_types": s.data_types,
                    }
                    for s in subprocessors
                ],
            },
        }

    def get_trust_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate statistics for an org's trust center."""
        badges = self.list_badges(org_id)
        controls = self.list_controls(org_id)
        subprocessors = self.list_subprocessors(org_id)

        implemented = sum(1 for c in controls if c.status == "implemented")
        certified = sum(1 for b in badges if b.status == "certified")

        return {
            "org_id": org_id,
            "badges": {
                "total": len(badges),
                "certified": certified,
                "in_progress": sum(1 for b in badges if b.status == "in_progress"),
                "planned": sum(1 for b in badges if b.status == "planned"),
            },
            "controls": {
                "total": len(controls),
                "implemented": implemented,
                "planned": sum(1 for c in controls if c.status == "planned"),
                "implementation_rate": (
                    round(implemented / len(controls) * 100, 1) if controls else 0.0
                ),
            },
            "subprocessors": {
                "total": len(subprocessors),
            },
            "trust_score": _compute_trust_score(badges, controls),
        }


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _compute_trust_score(
    badges: List[ComplianceBadge], controls: List[SecurityControl]
) -> float:
    """Compute a 0-100 trust score based on certifications and controls."""
    score = 0.0
    # Certifications worth up to 50 points
    if badges:
        cert_ratio = sum(1 for b in badges if b.status == "certified") / len(badges)
        score += cert_ratio * 50
    # Control implementation worth up to 50 points
    if controls:
        impl_ratio = sum(1 for c in controls if c.status == "implemented") / len(controls)
        score += impl_ratio * 50
    return round(score, 1)


# ===========================================================================
# EXTENDED FEATURES — Security Practices, Documents, NDA/DPA, FAQ, Requests
# ===========================================================================

# ---------------------------------------------------------------------------
# Pydantic models for extended features
# ---------------------------------------------------------------------------


class SecurityPractice(BaseModel):
    """A documented security practice area."""

    area: str  # e.g. Encryption, Access Control, Incident Response
    title: str
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)
    last_reviewed: Optional[str] = None  # ISO date string


class TrustDocument(BaseModel):
    """A trust/compliance document in the repository."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    doc_type: str  # security_whitepaper | pentest_summary | soc2_report | privacy_policy | dpa_template | acceptable_use | nda_template
    title: str
    description: str
    version: str = "1.0"
    published_date: Optional[str] = None  # ISO date
    last_updated: Optional[str] = None   # ISO date
    requires_nda: bool = False
    requires_auth: bool = False
    file_size_kb: Optional[int] = None
    page_count: Optional[int] = None


class SignedAgreement(BaseModel):
    """A generated NDA or DPA and its signature status."""

    agreement_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agreement_type: str  # NDA | DPA
    prospect_name: str
    prospect_email: str
    prospect_company: str
    document_version: str = "1.0"
    signed_at: Optional[str] = None       # ISO datetime
    ip_address: Optional[str] = None
    is_countersigned: bool = False
    countersigned_at: Optional[str] = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class FAQItem(BaseModel):
    """A security FAQ question and approved answer."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str  # data_handling | compliance | incident_response | infrastructure | access_control | encryption | vendor_management
    question: str
    answer: str
    order: int = 0
    is_public: bool = True
    last_reviewed: Optional[str] = None  # ISO date
    reviewed_by: Optional[str] = None


class DocumentRequest(BaseModel):
    """A prospect request for additional trust documentation."""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_type: str  # additional_docs | security_questionnaire | architecture_diagram | proof_of_compliance | custom_dpa | custom_nda
    requester_name: str
    requester_email: str
    requester_company: str
    requester_title: Optional[str] = None
    message: Optional[str] = None
    status: str = "pending"  # pending | in_review | fulfilled | declined
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    fulfilled_at: Optional[str] = None
    fulfilled_by: Optional[str] = None
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Extended SQLite schema (additive — appended to _SCHEMA)
# ---------------------------------------------------------------------------

_EXTENDED_SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_documents (
    id           TEXT PRIMARY KEY,
    doc_type     TEXT NOT NULL,
    data         TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signed_agreements (
    agreement_id TEXT PRIMARY KEY,
    agreement_type TEXT NOT NULL,
    prospect_email TEXT NOT NULL,
    data         TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS faq_items (
    id         TEXT PRIMARY KEY,
    category   TEXT NOT NULL,
    is_public  INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    data       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS document_requests (
    request_id TEXT PRIMARY KEY,
    status     TEXT NOT NULL DEFAULT 'pending',
    data       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

# ---------------------------------------------------------------------------
# Static default data
# ---------------------------------------------------------------------------

_DEFAULT_SECURITY_PRACTICES: List[SecurityPractice] = [
    SecurityPractice(
        area="Encryption",
        title="Data Encryption",
        description="All customer data is encrypted at rest and in transit.",
        details={
            "at_rest": "AES-256-GCM with per-tenant key isolation. Database-level encryption via SQLCipher. Filesystem encryption via LUKS.",
            "in_transit": "TLS 1.3 enforced on all endpoints. HSTS with preload. Mutual TLS for service-to-service.",
            "key_management": "HashiCorp Vault Enterprise. Keys rotated every 90 days (symmetric), 1 year (asymmetric).",
            "certificate_authority": "Let's Encrypt (public) + internal Vault PKI (service mesh)",
        },
        last_reviewed="2024-10-01",
    ),
    SecurityPractice(
        area="Access Control",
        title="Identity and Access Management",
        description="Strict RBAC with MFA enforcement and privileged access management.",
        details={
            "mfa_required": True,
            "sso_supported": True,
            "rbac_tiers": ["Owner", "Admin", "Security Engineer", "Developer", "Auditor", "Read-Only"],
            "privileged_access": "Just-in-time (JIT) access via PIM. Break-glass requires dual approval. All sessions recorded.",
            "access_review_frequency": "Quarterly automated access reviews",
            "least_privilege": True,
        },
        last_reviewed="2024-09-15",
    ),
    SecurityPractice(
        area="Incident Response",
        title="Incident Response Program",
        description="Documented IR plan with SLA-bound response and customer notification.",
        details={
            "response_sla_hours": 1,
            "customer_notification_sla_hours": 72,
            "runbook_maintained": True,
            "tabletop_exercises": "Quarterly tabletop + annual full-scale simulation",
            "post_incident_reviews": True,
            "disclosure_policy_url": "https://aldeci.io/security/disclosure",
        },
        last_reviewed="2024-08-01",
    ),
    SecurityPractice(
        area="Vulnerability Management",
        title="Vulnerability Management Program",
        description="Continuous scanning, annual pentests, and SLA-bound patching.",
        details={
            "sast_tools": ["Semgrep", "Bandit", "CodeQL"],
            "dast_tools": ["OWASP ZAP", "Burp Suite Enterprise"],
            "dependency_scanning": True,
            "pentest_frequency": "Annual third-party (CREST-certified) + quarterly internal",
            "critical_patch_sla_hours": 24,
            "high_patch_sla_days": 7,
            "cvss_scoring": True,
        },
        last_reviewed="2024-11-01",
    ),
    SecurityPractice(
        area="Business Continuity",
        title="Business Continuity and Disaster Recovery",
        description="Multi-region DR with tested RPO/RTO targets.",
        details={
            "rpo_hours": 4,
            "rto_hours": 2,
            "backup_frequency": "Continuous WAL shipping + hourly snapshots",
            "backup_encryption": "AES-256 with separate key from production",
            "backup_retention_days": 90,
            "dr_site": "Active-passive multi-region (us-east-1 primary, eu-west-1 DR)",
            "last_dr_test": "2024-Q4",
            "uptime_sla_percent": 99.9,
        },
        last_reviewed="2024-12-01",
    ),
    SecurityPractice(
        area="Employee Security",
        title="Employee Security Training",
        description="Security awareness program with annual training and phishing simulations.",
        details={
            "background_checks": True,
            "security_training_frequency": "Annual mandatory + role-based supplemental",
            "phishing_simulations": "Monthly simulated campaigns",
            "acceptable_use_policy": True,
            "nda_at_onboarding": True,
            "offboarding_access_revocation_hours": 2,
            "security_champions_program": True,
        },
        last_reviewed="2024-07-01",
    ),
    SecurityPractice(
        area="Physical Security",
        title="Physical Security Controls",
        description="Data center and office physical security controls.",
        details={
            "data_center_provider": "AWS (SOC2/ISO27001 certified facilities)",
            "office_access": "Badge + PIN + biometric in server areas",
            "visitor_policy": "All visitors escorted; logged entry/exit",
            "clean_desk_policy": True,
            "media_destruction": "DoD 5220.22-M shredding for physical media",
        },
        last_reviewed="2024-06-01",
    ),
    SecurityPractice(
        area="SDLC Security",
        title="Secure Software Development Lifecycle",
        description="Security integrated throughout the development lifecycle.",
        details={
            "threat_modeling": "STRIDE threat modeling for all new features",
            "secure_code_review": "Security-focused PR review required",
            "dependency_pinning": True,
            "supply_chain_security": "SBOM per release; Sigstore signing",
            "secrets_scanning": "TruffleHog + GitLeaks in CI/CD",
            "container_scanning": "Trivy + Snyk",
            "isolated_build_environments": True,
        },
        last_reviewed="2024-10-15",
    ),
]

_DEFAULT_TRUST_DOCUMENTS: List[TrustDocument] = [
    TrustDocument(
        doc_type="security_whitepaper",
        title="ALDECI Security Architecture Whitepaper",
        description="Overview of security architecture, controls, and design decisions.",
        version="2.1",
        published_date="2024-01-15",
        last_updated="2024-10-01",
        requires_nda=False,
        requires_auth=False,
        file_size_kb=842,
        page_count=38,
    ),
    TrustDocument(
        doc_type="pentest_summary",
        title="Annual Penetration Test Executive Summary (2024)",
        description="Redacted executive summary from CREST-certified third-party pentest. Includes scope, methodology, finding counts by severity, and remediation status.",
        version="1.0",
        published_date="2024-08-01",
        requires_nda=True,
        requires_auth=True,
        file_size_kb=215,
        page_count=12,
    ),
    TrustDocument(
        doc_type="soc2_report",
        title="SOC 2 Type II — Cover Page & Opinion Letter (2024)",
        description="Auditor opinion letter and management assertion. Full report available under NDA.",
        version="1.0",
        published_date="2024-03-15",
        requires_nda=True,
        requires_auth=True,
        file_size_kb=180,
        page_count=6,
    ),
    TrustDocument(
        doc_type="privacy_policy",
        title="Privacy Policy",
        description="Governs collection, use, and sharing of personal data.",
        version="3.2",
        published_date="2023-05-25",
        last_updated="2024-09-01",
        requires_nda=False,
        requires_auth=False,
        file_size_kb=95,
        page_count=18,
    ),
    TrustDocument(
        doc_type="dpa_template",
        title="Data Processing Agreement (DPA) Template",
        description="Standard DPA with SCCs for GDPR compliance. Countersigned by our DPO.",
        version="2.0",
        published_date="2024-01-01",
        requires_nda=False,
        requires_auth=False,
        file_size_kb=145,
        page_count=22,
    ),
    TrustDocument(
        doc_type="acceptable_use",
        title="Acceptable Use Policy",
        description="Policy governing acceptable use of the ALDECI platform.",
        version="1.5",
        published_date="2023-03-01",
        last_updated="2024-06-15",
        requires_nda=False,
        requires_auth=False,
        file_size_kb=62,
        page_count=8,
    ),
    TrustDocument(
        doc_type="nda_template",
        title="Mutual Non-Disclosure Agreement Template",
        description="Standard mutual NDA for prospects requesting restricted trust documents.",
        version="1.2",
        published_date="2023-01-01",
        requires_nda=False,
        requires_auth=False,
        file_size_kb=55,
        page_count=6,
    ),
]

_DEFAULT_FAQ_ITEMS: List[FAQItem] = [
    FAQItem(category="data_handling", question="Where is my data stored?",
            answer="AWS us-east-1 (primary). EU customers can select eu-west-1 Frankfurt. Data never crosses regions without consent.",
            order=10),
    FAQItem(category="data_handling", question="How long is data retained?",
            answer="Findings: 2 years (configurable). Audit logs: 7 years. Raw scan data: 90 days. Purged within 30 days of termination.",
            order=20),
    FAQItem(category="data_handling", question="Do you sell customer data?",
            answer="No. We never sell, trade, or rent customer data. Sub-processors receive minimum required data only.",
            order=30),
    FAQItem(category="data_handling", question="Can I export my data?",
            answer="Yes. All data exportable via API or dashboard. Formats: JSON, CSV, STIX 2.1.",
            order=40),
    FAQItem(category="compliance", question="Are you SOC 2 Type II certified?",
            answer="Yes. Annual SOC 2 Type II audit covering Security, Availability, Confidentiality. Latest: March 2024 (A-LIGN).",
            order=10),
    FAQItem(category="compliance", question="Are you GDPR compliant?",
            answer="Yes. We offer DPAs with SCCs. EU data residency available. DPO reachable at privacy@aldeci.io.",
            order=20),
    FAQItem(category="compliance", question="Do you support HIPAA?",
            answer="Yes. BAAs available for HIPAA-covered workloads. §164.312 technical safeguards implemented.",
            order=30),
    FAQItem(category="incident_response", question="How do you handle security incidents?",
            answer="1-hour initial response SLA. Customer notification within 72 hours of confirmed breach. Post-incident reviews published.",
            order=10),
    FAQItem(category="incident_response", question="How do I report a vulnerability?",
            answer="Email security@aldeci.io (PGP available at https://aldeci.io/pgp). 24-hour acknowledgment. 90-day coordinated disclosure.",
            order=20),
    FAQItem(category="infrastructure", question="What cloud provider do you use?",
            answer="AWS (EC2, EKS, RDS, S3, CloudFront). All infra defined as code via Terraform.",
            order=10),
    FAQItem(category="infrastructure", question="What is your uptime SLA?",
            answer="99.9% uptime guarantee. Status and incident history: https://status.aldeci.io",
            order=20),
    FAQItem(category="infrastructure", question="Do you perform penetration testing?",
            answer="Annual third-party pentest (CREST-certified). Quarterly internal assessments. Executive summaries available under NDA.",
            order=30),
    FAQItem(category="access_control", question="Is MFA supported?",
            answer="Yes, MFA is required (TOTP, WebAuthn/FIDO2). SSO via SAML 2.0 and OIDC (Okta, Azure AD, Google Workspace).",
            order=10),
    FAQItem(category="access_control", question="Do ALDECI employees access my data?",
            answer="Only with consent or for support (audit-logged). Production DB access requires JIT approval and session recording.",
            order=20),
    FAQItem(category="encryption", question="How is data encrypted?",
            answer="At rest: AES-256-GCM with per-tenant keys. In transit: TLS 1.3. Keys in HashiCorp Vault, rotated every 90 days.",
            order=10),
    FAQItem(category="vendor_management", question="How do you manage sub-processors?",
            answer="All sub-processors require SOC2 or ISO27001. DPAs executed for personal-data handling. Public sub-processor list updated within 30 days of changes.",
            order=10),
]

_NDA_TEMPLATE = """\
MUTUAL NON-DISCLOSURE AGREEMENT

This Mutual NDA is entered into as of {date} between:
  ALDECI Security Intelligence, Inc. ("Company"), and
  {prospect_company} ("{prospect_name}") ("Recipient").

1. CONFIDENTIAL INFORMATION: Each Party may disclose non-public proprietary information
   ("Confidential Information") solely for evaluating a potential business relationship.

2. OBLIGATIONS: Each Party agrees to hold Confidential Information in strict confidence,
   not disclose to third parties without consent, and use solely for evaluation.

3. TERM: Two (2) years from the date of execution.

4. GOVERNING LAW: State of Delaware, USA.

ALDECI Security Intelligence, Inc.        {prospect_company}
By: ________________________              By: ________________________
Name: General Counsel                     Name: {prospect_name}
Date: {date}                              Date: {date}
Agreement ID: {agreement_id}
"""

_DPA_TEMPLATE = """\
DATA PROCESSING AGREEMENT

This DPA is entered into as of {date} between:
  ALDECI Security Intelligence, Inc. ("Processor"), and
  {prospect_company} ("{prospect_name}") ("Controller").

1. PROCESSING INSTRUCTIONS: Processor processes Personal Data only on Controller instructions.

2. SECURITY MEASURES: AES-256-GCM encryption, TLS 1.3, RBAC+MFA, annual pentests, SOC 2 Type II.

3. SUB-PROCESSORS: Sub-processor list at https://trust.aldeci.io/sub-processors.
   30-day notice for new sub-processors.

4. DATA SUBJECT RIGHTS: Assistance within 72 hours of DSR receipt.

5. BREACH NOTIFICATION: Controller notified within 72 hours of confirmed breach.

6. RETURN & DELETION: All Personal Data deleted within 30 days of termination.
   Written deletion certificate provided.

7. GOVERNING LAW: EU GDPR with Standard Contractual Clauses as applicable.

ALDECI Security Intelligence, Inc.        {prospect_company}
By: ________________________              By: ________________________
Name: DPO                                 Name: {prospect_name}
Date: {date}                              Date: {date}
DPA ID: {agreement_id}
"""


# ---------------------------------------------------------------------------
# ExtendedTrustCenterManager — adds practices, docs, NDA/DPA, FAQ, requests
# ---------------------------------------------------------------------------


class ExtendedTrustCenterManager(TrustCenterManager):
    """
    TrustCenterManager extended with security practices, document repository,
    NDA/DPA generation, FAQ management, and prospect request portal.

    Fully backwards-compatible — all existing TrustCenterManager methods
    remain available.
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        super().__init__(db_path=db_path)
        self._init_extended_schema()
        self._seed_defaults_once()

    def _init_extended_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript(_EXTENDED_SCHEMA)
            conn.commit()

    def _seed_defaults_once(self) -> None:
        """Seed default documents and FAQ on first run."""
        with self._lock:
            conn = self._connect()
            count = conn.execute("SELECT COUNT(*) FROM trust_documents").fetchone()[0]
        if count == 0:
            now = datetime.now(timezone.utc).isoformat()
            with self._lock:
                conn = self._connect()
                for doc in _DEFAULT_TRUST_DOCUMENTS:
                    conn.execute(
                        "INSERT OR IGNORE INTO trust_documents (id, doc_type, data, created_at, updated_at) VALUES (?,?,?,?,?)",
                        (doc.id, doc.doc_type, doc.model_dump_json(), now, now),
                    )
                conn.commit()

        with self._lock:
            conn = self._connect()
            count = conn.execute("SELECT COUNT(*) FROM faq_items").fetchone()[0]
        if count == 0:
            now = datetime.now(timezone.utc).isoformat()
            with self._lock:
                conn = self._connect()
                for item in _DEFAULT_FAQ_ITEMS:
                    conn.execute(
                        "INSERT OR IGNORE INTO faq_items (id, category, is_public, sort_order, data, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                        (item.id, item.category, int(item.is_public), item.order, item.model_dump_json(), now, now),
                    )
                conn.commit()

    # -----------------------------------------------------------------------
    # Security practices (static — loaded from defaults)
    # -----------------------------------------------------------------------

    def get_security_practices(self) -> List[SecurityPractice]:
        """Return the full list of documented security practices."""
        return list(_DEFAULT_SECURITY_PRACTICES)

    def get_practices_by_area(self, area: str) -> Optional[SecurityPractice]:
        """Return a single practice by area name (case-insensitive)."""
        lower = area.lower()
        for p in _DEFAULT_SECURITY_PRACTICES:
            if p.area.lower() == lower:
                return p
        return None

    def get_practices_summary(self) -> Dict[str, Any]:
        """Return a summary of all security practice areas."""
        return {
            "areas": [p.area for p in _DEFAULT_SECURITY_PRACTICES],
            "total_areas": len(_DEFAULT_SECURITY_PRACTICES),
            "highlights": {
                "encryption_at_rest": "AES-256-GCM",
                "encryption_in_transit": "TLS 1.3",
                "mfa_required": True,
                "annual_pentest": True,
                "uptime_sla": "99.9%",
                "rpo_hours": 4,
                "rto_hours": 2,
            },
        }

    # -----------------------------------------------------------------------
    # Document repository
    # -----------------------------------------------------------------------

    def list_documents(self, public_only: bool = True) -> List[TrustDocument]:
        """Return trust documents. If public_only, excludes NDA/auth-gated docs."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute("SELECT data FROM trust_documents").fetchall()
        docs = [TrustDocument.model_validate_json(r[0]) for r in rows]
        if public_only:
            docs = [d for d in docs if not d.requires_auth]
        return docs

    def get_document(self, doc_id: str) -> Optional[TrustDocument]:
        """Return a specific document by ID."""
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT data FROM trust_documents WHERE id = ?", (doc_id,)
            ).fetchone()
        if row is None:
            return None
        return TrustDocument.model_validate_json(row[0])

    def add_document(self, doc: TrustDocument) -> TrustDocument:
        """Add or update a trust document."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO trust_documents (id, doc_type, data, created_at, updated_at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET doc_type=excluded.doc_type, data=excluded.data, updated_at=excluded.updated_at",
                (doc.id, doc.doc_type, doc.model_dump_json(), now, now),
            )
            conn.commit()
        return doc

    # -----------------------------------------------------------------------
    # NDA / DPA generation
    # -----------------------------------------------------------------------

    def generate_nda(
        self,
        prospect_name: str,
        prospect_email: str,
        prospect_company: str,
    ) -> Dict[str, Any]:
        """Generate a pre-filled NDA and record it."""
        from datetime import date as _date
        agreement_id = str(uuid.uuid4())
        today = _date.today().isoformat()
        rendered = _NDA_TEMPLATE.format(
            date=today,
            prospect_name=prospect_name,
            prospect_company=prospect_company,
            agreement_id=agreement_id,
        )
        agreement = SignedAgreement(
            agreement_id=agreement_id,
            agreement_type="NDA",
            prospect_name=prospect_name,
            prospect_email=prospect_email,
            prospect_company=prospect_company,
            document_version="1.2",
        )
        self._save_agreement(agreement)
        _logger.info("Generated NDA for %s (%s) id=%s", prospect_name, prospect_company, agreement_id)
        return {
            "agreement_id": agreement_id,
            "agreement_type": "NDA",
            "document_text": rendered,
            "generated_at": today,
            "instructions": "Sign and return to legal@aldeci.io. Restricted documents shared within 1 business day of countersignature.",
        }

    def generate_dpa(
        self,
        prospect_name: str,
        prospect_email: str,
        prospect_company: str,
    ) -> Dict[str, Any]:
        """Generate a pre-filled DPA and record it."""
        from datetime import date as _date
        agreement_id = str(uuid.uuid4())
        today = _date.today().isoformat()
        rendered = _DPA_TEMPLATE.format(
            date=today,
            prospect_name=prospect_name,
            prospect_company=prospect_company,
            agreement_id=agreement_id,
        )
        agreement = SignedAgreement(
            agreement_id=agreement_id,
            agreement_type="DPA",
            prospect_name=prospect_name,
            prospect_email=prospect_email,
            prospect_company=prospect_company,
            document_version="2.0",
        )
        self._save_agreement(agreement)
        _logger.info("Generated DPA for %s (%s) id=%s", prospect_name, prospect_company, agreement_id)
        return {
            "agreement_id": agreement_id,
            "agreement_type": "DPA",
            "document_text": rendered,
            "generated_at": today,
            "instructions": "Sign and return to legal@aldeci.io. DPA countersigned by our DPO within 2 business days.",
        }

    def record_signature(
        self, agreement_id: str, ip_address: Optional[str] = None
    ) -> Optional[SignedAgreement]:
        """Mark an agreement as signed by the prospect."""
        agreements = self.list_agreements()
        for a in agreements:
            if a.agreement_id == agreement_id:
                a.signed_at = datetime.now(timezone.utc).isoformat()
                a.ip_address = ip_address
                self._save_agreement(a)
                return a
        return None

    def check_agreement_status(
        self, prospect_email: str, agreement_type: str
    ) -> Optional[SignedAgreement]:
        """Return an agreement for a prospect email + type, if it exists."""
        for a in self.list_agreements():
            if a.prospect_email.lower() == prospect_email.lower() and a.agreement_type == agreement_type:
                return a
        return None

    def list_agreements(self) -> List[SignedAgreement]:
        """Return all generated agreements."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute("SELECT data FROM signed_agreements").fetchall()
        return [SignedAgreement.model_validate_json(r[0]) for r in rows]

    def _save_agreement(self, agreement: SignedAgreement) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO signed_agreements (agreement_id, agreement_type, prospect_email, data, created_at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(agreement_id) DO UPDATE SET data=excluded.data",
                (agreement.agreement_id, agreement.agreement_type, agreement.prospect_email,
                 agreement.model_dump_json(), now),
            )
            conn.commit()

    # -----------------------------------------------------------------------
    # FAQ management
    # -----------------------------------------------------------------------

    def get_faq(
        self,
        category: Optional[str] = None,
        public_only: bool = True,
    ) -> List[FAQItem]:
        """Return FAQ items, optionally filtered by category."""
        with self._lock:
            conn = self._connect()
            if public_only:
                rows = conn.execute(
                    "SELECT data FROM faq_items WHERE is_public=1 ORDER BY sort_order ASC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM faq_items ORDER BY sort_order ASC"
                ).fetchall()
        items = [FAQItem.model_validate_json(r[0]) for r in rows]
        if category:
            items = [i for i in items if i.category == category]
        return items

    def get_faq_by_category(self) -> Dict[str, List[FAQItem]]:
        """Return FAQ grouped by category."""
        grouped: Dict[str, List[FAQItem]] = {}
        for item in self.get_faq(public_only=True):
            grouped.setdefault(item.category, []).append(item)
        return grouped

    def add_faq_item(self, item: FAQItem) -> FAQItem:
        """Add or update a FAQ item."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO faq_items (id, category, is_public, sort_order, data, created_at, updated_at) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET category=excluded.category, is_public=excluded.is_public, sort_order=excluded.sort_order, data=excluded.data, updated_at=excluded.updated_at",
                (item.id, item.category, int(item.is_public), item.order, item.model_dump_json(), now, now),
            )
            conn.commit()
        return item

    # -----------------------------------------------------------------------
    # Request portal
    # -----------------------------------------------------------------------

    def submit_request(self, req: DocumentRequest) -> DocumentRequest:
        """Submit a prospect documentation request."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO document_requests (request_id, status, data, created_at, updated_at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(request_id) DO UPDATE SET status=excluded.status, data=excluded.data, updated_at=excluded.updated_at",
                (req.request_id, req.status, req.model_dump_json(), now, now),
            )
            conn.commit()
        _logger.info("Trust center request submitted: type=%s from=%s", req.request_type, req.requester_email)
        return req

    def list_requests(self, status: Optional[str] = None) -> List[DocumentRequest]:
        """List documentation requests, optionally filtered by status."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT data FROM document_requests ORDER BY created_at DESC"
            ).fetchall()
        reqs = [DocumentRequest.model_validate_json(r[0]) for r in rows]
        if status:
            reqs = [r for r in reqs if r.status == status]
        return reqs

    def update_request_status(
        self,
        request_id: str,
        status: str,
        fulfilled_by: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Optional[DocumentRequest]:
        """Update status of a documentation request."""
        all_reqs = self.list_requests()
        for req in all_reqs:
            if req.request_id == request_id:
                req.status = status
                if fulfilled_by:
                    req.fulfilled_by = fulfilled_by
                if notes:
                    req.notes = notes
                if status == "fulfilled":
                    req.fulfilled_at = datetime.now(timezone.utc).isoformat()
                now = datetime.now(timezone.utc).isoformat()
                with self._lock:
                    conn = self._connect()
                    conn.execute(
                        "UPDATE document_requests SET status=?, data=?, updated_at=? WHERE request_id=?",
                        (req.status, req.model_dump_json(), now, request_id),
                    )
                    conn.commit()
                return req
        return None

    # -----------------------------------------------------------------------
    # Extended singleton
    # -----------------------------------------------------------------------

    _ext_instance: Optional["ExtendedTrustCenterManager"] = None
    _ext_lock = threading.Lock()

    @classmethod
    def get_extended_instance(
        cls, db_path: str | Path = ":memory:"
    ) -> "ExtendedTrustCenterManager":
        """Return the process-wide ExtendedTrustCenterManager singleton."""
        with cls._ext_lock:
            if cls._ext_instance is None:
                cls._ext_instance = cls(db_path)
            return cls._ext_instance

    @classmethod
    def reset_extended_instance(cls) -> None:
        """Reset extended singleton (useful for tests)."""
        with cls._ext_lock:
            cls._ext_instance = None
