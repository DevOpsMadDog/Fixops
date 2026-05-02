"""
FixOps Phishing Simulation Engine — Employee Security Awareness Testing.

Provides end-to-end phishing simulation capabilities:
- 10 built-in templates across 5 attack categories
- Campaign lifecycle management (create, send, track, report)
- Per-user susceptibility scoring
- Org-wide risk aggregation
- SQLite-backed persistent storage with thread safety

Compliance: NIST SP 800-50 (Security Awareness Training), ISO 27001 A.7.2.2
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================


class PhishingCategory(str, Enum):
    """Categories of phishing attacks simulated."""

    CREDENTIAL_HARVEST = "credential_harvest"
    MALWARE_LINK = "malware_link"
    DATA_REQUEST = "data_request"
    URGENCY = "urgency"
    AUTHORITY = "authority"


class PhishingDifficulty(str, Enum):
    """Difficulty level of the phishing template."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class PhishingTemplate(BaseModel):
    """
    A reusable phishing email template.

    Attributes:
        id: Unique identifier for the template
        name: Human-readable template name
        subject: Email subject line
        body_html: HTML body of the phishing email
        category: Attack category (credential_harvest, malware_link, etc.)
        difficulty: How obvious the phish is (easy/medium/hard)
        indicators: List of clues that reveal this is a phish
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    subject: str
    body_html: str
    category: PhishingCategory
    difficulty: PhishingDifficulty
    indicators: List[str] = Field(default_factory=list)


class PhishingCampaign(BaseModel):
    """
    A phishing simulation campaign targeting a set of employees.

    Attributes:
        id: Unique campaign identifier
        name: Campaign display name
        template_id: ID of the PhishingTemplate used
        target_emails: List of employee email addresses targeted
        sent_count: Number of emails sent
        opened_count: Number of emails opened
        clicked_count: Number of employees who clicked the link (failed)
        reported_count: Number of employees who reported the phish (passed)
        started_at: Campaign start timestamp (ISO 8601)
        ended_at: Campaign end timestamp (ISO 8601, None if active)
        org_id: Organisation identifier
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    template_id: str
    target_emails: List[str] = Field(default_factory=list)
    sent_count: int = 0
    opened_count: int = 0
    clicked_count: int = 0
    reported_count: int = 0
    started_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    ended_at: Optional[str] = None
    org_id: str


# ============================================================================
# BUILT-IN TEMPLATES
# ============================================================================

BUILTIN_TEMPLATES: List[PhishingTemplate] = [
    # ---- CREDENTIAL HARVEST (2) ----
    PhishingTemplate(
        id="tpl_cred_001",
        name="IT Password Reset",
        subject="[ACTION REQUIRED] Your password expires in 24 hours",
        body_html=(
            "<p>Dear Employee,</p>"
            "<p>Your corporate password will expire in <strong>24 hours</strong>. "
            "Click the link below to reset it immediately:</p>"
            "<p><a href='http://corp-password-reset.support/reset?token=abc123'>"
            "Reset My Password Now</a></p>"
            "<p>IT Security Team</p>"
        ),
        category=PhishingCategory.CREDENTIAL_HARVEST,
        difficulty=PhishingDifficulty.EASY,
        indicators=[
            "Suspicious domain (corp-password-reset.support)",
            "Artificial urgency (24-hour deadline)",
            "Generic greeting (Dear Employee)",
            "HTTP not HTTPS link",
        ],
    ),
    PhishingTemplate(
        id="tpl_cred_002",
        name="Microsoft 365 Sign-In Alert",
        subject="Unusual sign-in activity detected on your account",
        body_html=(
            "<p>We noticed a sign-in to your Microsoft 365 account from an unrecognized device.</p>"
            "<p>Location: Bucharest, Romania | Time: 03:14 AM UTC</p>"
            "<p>If this wasn't you, <a href='https://microsoft-security-alerts.com/verify'>verify your identity</a>.</p>"
            "<p>Microsoft Account Team</p>"
        ),
        category=PhishingCategory.CREDENTIAL_HARVEST,
        difficulty=PhishingDifficulty.MEDIUM,
        indicators=[
            "Domain mismatch (microsoft-security-alerts.com vs microsoft.com)",
            "Fear-based social engineering",
            "Sender address not @microsoft.com",
        ],
    ),
    # ---- MALWARE LINK (2) ----
    PhishingTemplate(
        id="tpl_mal_001",
        name="Shared Document Notification",
        subject="John shared a document with you",
        body_html=(
            "<p>John Smith has shared a document with you: <strong>Q4_Salary_Review_2024.xlsx</strong></p>"
            "<p><a href='https://docs-viewer.net/share/abc?download=1'>Open Document</a></p>"
            "<p>This link will expire in 48 hours.</p>"
        ),
        category=PhishingCategory.MALWARE_LINK,
        difficulty=PhishingDifficulty.EASY,
        indicators=[
            "Unsolicited file share from unknown sender",
            "Third-party domain (docs-viewer.net)",
            "Enticing filename (salary data)",
        ],
    ),
    PhishingTemplate(
        id="tpl_mal_002",
        name="FedEx Delivery Failure",
        subject="Your package could not be delivered — action required",
        body_html=(
            "<p>Dear Customer,</p>"
            "<p>We attempted to deliver your package (Tracking: FX928374651) but failed.</p>"
            "<p>Download your shipping label to reschedule: "
            "<a href='https://fedex-delivery.re/label.exe'>Download Label</a></p>"
            "<p>FedEx Customer Service</p>"
        ),
        category=PhishingCategory.MALWARE_LINK,
        difficulty=PhishingDifficulty.MEDIUM,
        indicators=[
            "Executable file (.exe) disguised as a shipping label",
            "Non-official domain (fedex-delivery.re)",
            "Delivery pretext creates urgency",
        ],
    ),
    # ---- DATA REQUEST (2) ----
    PhishingTemplate(
        id="tpl_data_001",
        name="HR Benefits Survey",
        subject="Complete your 2024 benefits enrollment — deadline today",
        body_html=(
            "<p>HR requires you to confirm your benefits enrollment for 2025.</p>"
            "<p>Please complete the form including your SSN and banking details for direct deposit:</p>"
            "<p><a href='https://hr-benefits-portal.xyz/enroll'>Complete Enrollment</a></p>"
        ),
        category=PhishingCategory.DATA_REQUEST,
        difficulty=PhishingDifficulty.EASY,
        indicators=[
            "Requests SSN and banking info via web form",
            "Unofficial domain (hr-benefits-portal.xyz)",
            "Deadline pressure",
        ],
    ),
    PhishingTemplate(
        id="tpl_data_002",
        name="Expense Report Verification",
        subject="Finance: please verify your expense report",
        body_html=(
            "<p>Hi,</p>"
            "<p>Our audit system flagged your recent expense report for manual review.</p>"
            "<p>Please reply with your employee ID, department code, and manager name so we can resolve this.</p>"
            "<p>Finance Operations</p>"
        ),
        category=PhishingCategory.DATA_REQUEST,
        difficulty=PhishingDifficulty.MEDIUM,
        indicators=[
            "Requests PII via email reply",
            "Vague audit pretext",
            "No official ticket or reference number",
        ],
    ),
    # ---- URGENCY (2) ----
    PhishingTemplate(
        id="tpl_urg_001",
        name="VPN Access Suspended",
        subject="URGENT: Your VPN access has been suspended",
        body_html=(
            "<p><strong>ALERT:</strong> Your VPN access was suspended due to a policy violation.</p>"
            "<p>You have <strong>2 hours</strong> to appeal or your account will be permanently disabled.</p>"
            "<p><a href='https://vpn-appeal.internal-it.co/appeal?id=usr4892'>Submit Appeal Now</a></p>"
        ),
        category=PhishingCategory.URGENCY,
        difficulty=PhishingDifficulty.EASY,
        indicators=[
            "Extreme time pressure (2 hours)",
            "Threat of permanent account loss",
            "Suspicious domain (internal-it.co not company domain)",
        ],
    ),
    PhishingTemplate(
        id="tpl_urg_002",
        name="CEO Urgent Wire Transfer",
        subject="Urgent — need your help with a wire transfer",
        body_html=(
            "<p>Hi,</p>"
            "<p>I'm in a board meeting and need you to process a wire transfer of $47,500 to a new vendor urgently.</p>"
            "<p>Details: Account 8847261930, Routing 021000021, Beneficiary: Nexus Consulting Ltd.</p>"
            "<p>Please confirm once done. Don't call me — I'll explain later.</p>"
            "<p>Best, Michael (CEO)</p>"
        ),
        category=PhishingCategory.URGENCY,
        difficulty=PhishingDifficulty.HARD,
        indicators=[
            "Request to bypass normal approval process",
            "Instruction not to call for verification",
            "Email sender address differs from real CEO",
            "Unusual financial request via email",
        ],
    ),
    # ---- AUTHORITY (2) ----
    PhishingTemplate(
        id="tpl_auth_001",
        name="IT Security Compliance Audit",
        subject="Mandatory security compliance check — respond within 1 business day",
        body_html=(
            "<p>Dear Employee,</p>"
            "<p>As part of our annual ISO 27001 audit, the IT Security team requires you to install "
            "our compliance agent on your workstation.</p>"
            "<p><a href='https://compliance-agent-download.net/agent-v3.2.msi'>Download Compliance Agent</a></p>"
            "<p>Failure to comply within 24 hours may result in disciplinary action.</p>"
            "<p>IT Security Compliance Team</p>"
        ),
        category=PhishingCategory.AUTHORITY,
        difficulty=PhishingDifficulty.MEDIUM,
        indicators=[
            "Requests software installation from external domain",
            "Threat of disciplinary action",
            "ISO 27001 mentioned for legitimacy veneer",
        ],
    ),
    PhishingTemplate(
        id="tpl_auth_002",
        name="Legal Department NDA Signature",
        subject="DocuSign: Please sign the updated NDA — Legal Dept",
        body_html=(
            "<p>Our legal team requires your signature on an updated NDA before end of day.</p>"
            "<p>Please review and sign here: "
            "<a href='https://docusign-esign.co/sign?doc=nda_2024&user=you@company.com'>Sign NDA</a></p>"
            "<p>This is time-sensitive. Non-signers will be flagged for HR review.</p>"
            "<p>Legal & Compliance</p>"
        ),
        category=PhishingCategory.AUTHORITY,
        difficulty=PhishingDifficulty.HARD,
        indicators=[
            "Fake DocuSign domain (docusign-esign.co vs docusign.com)",
            "HR threat creates compliance pressure",
            "User email pre-filled in URL (data harvesting)",
            "Typosquatted brand domain",
        ],
    ),
]

# Fast lookup by template ID
_TEMPLATE_INDEX: Dict[str, PhishingTemplate] = {t.id: t for t in BUILTIN_TEMPLATES}


# ============================================================================
# SIMULATOR
# ============================================================================


class PhishingSimulator:
    """
    SQLite-backed phishing simulation engine.

    Thread-safe via RLock. Stores campaigns and per-user interaction events.
    Built-in templates are stored in memory; custom templates can be added
    and persist to the database.

    Args:
        db_path: Path to SQLite file (created if absent).
    """

    def __init__(self, db_path: str = "/tmp/phishing_simulator.db") -> None:  # nosec B108
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()
        _logger.info("PhishingSimulator initialized with db_path=%s", db_path)

    # ------------------------------------------------------------------ #
    # Database bootstrap
    # ------------------------------------------------------------------ #

    def _init_db(self) -> None:
        """Create tables if they do not exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    template_id TEXT NOT NULL,
                    target_emails TEXT NOT NULL,
                    sent_count INTEGER DEFAULT 0,
                    opened_count INTEGER DEFAULT 0,
                    clicked_count INTEGER DEFAULT 0,
                    reported_count INTEGER DEFAULT 0,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    org_id TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                );

                CREATE TABLE IF NOT EXISTS custom_templates (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                );
                """
            )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _get_campaign(self, conn: sqlite3.Connection, campaign_id: str) -> Optional[Dict[str, Any]]:
        row = conn.execute(
            "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        if row is None:
            return None
        [d[0] for d in conn.execute("SELECT * FROM campaigns LIMIT 0").description]
        # Re-fetch with column names
        row = conn.execute(
            "SELECT id, name, template_id, target_emails, sent_count, opened_count, "
            "clicked_count, reported_count, started_at, ended_at, org_id "
            "FROM campaigns WHERE id = ?",
            (campaign_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0],
            "name": row[1],
            "template_id": row[2],
            "target_emails": json.loads(row[3]),
            "sent_count": row[4],
            "opened_count": row[5],
            "clicked_count": row[6],
            "reported_count": row[7],
            "started_at": row[8],
            "ended_at": row[9],
            "org_id": row[10],
        }

    def _record_event(self, campaign_id: str, email: str, event_type: str) -> None:
        """Insert an interaction event and increment the campaign counter."""
        now = datetime.now(timezone.utc).isoformat()
        counter_col = {
            "open": "opened_count",
            "click": "clicked_count",
            "report": "reported_count",
        }.get(event_type)

        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                # Validate campaign exists
                row = conn.execute(
                    "SELECT id FROM campaigns WHERE id = ?", (campaign_id,)
                ).fetchone()
                if row is None:
                    raise ValueError(f"Campaign not found: {campaign_id}")

                conn.execute(
                    "INSERT OR IGNORE INTO events (id, campaign_id, email, event_type, recorded_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), campaign_id, email, event_type, now),
                )
                if counter_col:
                    conn.execute(
                        f"UPDATE campaigns SET {counter_col} = {counter_col} + 1 WHERE id = ?",  # nosec B608
                        (campaign_id,),
                    )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def create_campaign(
        self,
        name: str,
        template_id: str,
        targets: List[str],
        org_id: str,
    ) -> PhishingCampaign:
        """
        Create and launch a phishing campaign.

        Args:
            name: Display name for the campaign.
            template_id: ID of a built-in or custom template.
            targets: List of employee email addresses.
            org_id: Organisation identifier.

        Returns:
            PhishingCampaign with sent_count set to len(targets).

        Raises:
            ValueError: If template_id does not exist.
        """
        if not self.get_template(template_id):
            raise ValueError(f"Template not found: {template_id}")

        campaign = PhishingCampaign(
            id=str(uuid.uuid4()),
            name=name,
            template_id=template_id,
            target_emails=targets,
            sent_count=len(targets),
            org_id=org_id,
        )

        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO campaigns (id, name, template_id, target_emails, sent_count, "
                    "opened_count, clicked_count, reported_count, started_at, ended_at, org_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        campaign.id,
                        campaign.name,
                        campaign.template_id,
                        json.dumps(campaign.target_emails),
                        campaign.sent_count,
                        campaign.opened_count,
                        campaign.clicked_count,
                        campaign.reported_count,
                        campaign.started_at,
                        campaign.ended_at,
                        campaign.org_id,
                    ),
                )

        _logger.info("Campaign %s created for org %s (%d targets)", campaign.id, org_id, len(targets))
        return campaign

    def record_open(self, campaign_id: str, email: str) -> None:
        """Record that an employee opened the phishing email."""
        self._record_event(campaign_id, email, "open")

    def record_click(self, campaign_id: str, email: str) -> None:
        """Record that an employee clicked the phishing link (failed test)."""
        self._record_event(campaign_id, email, "click")

    def record_report(self, campaign_id: str, email: str) -> None:
        """Record that an employee reported the email as phishing (passed test)."""
        self._record_event(campaign_id, email, "report")

    def get_campaign_results(self, campaign_id: str) -> Dict[str, Any]:
        """
        Return full campaign results including per-user event breakdown.

        Returns:
            Dict with campaign metadata, counts, and per_user events list.

        Raises:
            ValueError: If campaign_id does not exist.
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                campaign = self._get_campaign(conn, campaign_id)
                if campaign is None:
                    raise ValueError(f"Campaign not found: {campaign_id}")

                events = conn.execute(
                    "SELECT email, event_type, recorded_at FROM events "
                    "WHERE campaign_id = ? ORDER BY recorded_at",
                    (campaign_id,),
                ).fetchall()

        per_user: Dict[str, List[str]] = {}
        for email, event_type, _ in events:
            per_user.setdefault(email, []).append(event_type)

        sent = campaign["sent_count"]
        clicked = campaign["clicked_count"]
        reported = campaign["reported_count"]
        click_rate = round(clicked / sent * 100, 1) if sent else 0.0
        report_rate = round(reported / sent * 100, 1) if sent else 0.0

        return {
            **campaign,
            "per_user": per_user,
            "click_rate_pct": click_rate,
            "report_rate_pct": report_rate,
        }

    def get_user_susceptibility(self, email: str, org_id: str) -> Dict[str, Any]:
        """
        Compute an individual risk score (0.0–1.0) for one employee.

        Score = clicks / (campaigns they were targeted in). Higher = riskier.

        Returns:
            Dict with email, org_id, campaigns_targeted, click_count,
            report_count, susceptibility_score, risk_level.
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                # Campaigns in this org that included this email
                rows = conn.execute(
                    "SELECT id, target_emails FROM campaigns WHERE org_id = ?",
                    (org_id,),
                ).fetchall()

                targeted_ids: List[str] = []
                for cid, targets_json in rows:
                    targets = json.loads(targets_json)
                    if email in targets:
                        targeted_ids.append(cid)

                if not targeted_ids:
                    return {
                        "email": email,
                        "org_id": org_id,
                        "campaigns_targeted": 0,
                        "click_count": 0,
                        "report_count": 0,
                        "susceptibility_score": 0.0,
                        "risk_level": "unknown",
                    }

                placeholders = ",".join("?" * len(targeted_ids))
                click_count = conn.execute(
                    f"SELECT COUNT(*) FROM events WHERE campaign_id IN ({placeholders}) "  # nosec B608
                    "AND email = ? AND event_type = 'click'",
                    (*targeted_ids, email),
                ).fetchone()[0]

                report_count = conn.execute(
                    f"SELECT COUNT(*) FROM events WHERE campaign_id IN ({placeholders}) "  # nosec B608
                    "AND email = ? AND event_type = 'report'",
                    (*targeted_ids, email),
                ).fetchone()[0]

        total = len(targeted_ids)
        score = round(click_count / total, 3) if total else 0.0
        risk_level = (
            "critical" if score >= 0.75
            else "high" if score >= 0.5
            else "medium" if score >= 0.25
            else "low"
        )

        return {
            "email": email,
            "org_id": org_id,
            "campaigns_targeted": total,
            "click_count": click_count,
            "report_count": report_count,
            "susceptibility_score": score,
            "risk_level": risk_level,
        }

    def get_org_phishing_risk(self, org_id: str) -> Dict[str, Any]:
        """
        Compute organisation-wide phishing susceptibility.

        Returns:
            Dict with org_id, total_campaigns, total_sent, total_clicked,
            total_reported, susceptibility_rate_pct, report_rate_pct, risk_level.
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT COUNT(*), SUM(sent_count), SUM(clicked_count), SUM(reported_count) "
                    "FROM campaigns WHERE org_id = ?",
                    (org_id,),
                ).fetchone()

        total_campaigns, total_sent, total_clicked, total_reported = row
        total_campaigns = total_campaigns or 0
        total_sent = total_sent or 0
        total_clicked = total_clicked or 0
        total_reported = total_reported or 0

        susceptibility_rate = round(total_clicked / total_sent * 100, 1) if total_sent else 0.0
        report_rate = round(total_reported / total_sent * 100, 1) if total_sent else 0.0

        risk_level = (
            "critical" if susceptibility_rate >= 40
            else "high" if susceptibility_rate >= 25
            else "medium" if susceptibility_rate >= 10
            else "low"
        )

        return {
            "org_id": org_id,
            "total_campaigns": total_campaigns,
            "total_sent": total_sent,
            "total_clicked": total_clicked,
            "total_reported": total_reported,
            "susceptibility_rate_pct": susceptibility_rate,
            "report_rate_pct": report_rate,
            "risk_level": risk_level,
        }

    def get_campaign_history(self, org_id: str) -> List[Dict[str, Any]]:
        """
        Return all campaigns for an organisation, ordered by start date descending.

        Returns:
            List of campaign dicts (without per-user event breakdown).
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT id, name, template_id, target_emails, sent_count, opened_count, "
                    "clicked_count, reported_count, started_at, ended_at, org_id "
                    "FROM campaigns WHERE org_id = ? ORDER BY started_at DESC",
                    (org_id,),
                ).fetchall()

        result = []
        for row in rows:
            result.append(
                {
                    "id": row[0],
                    "name": row[1],
                    "template_id": row[2],
                    "target_emails": json.loads(row[3]),
                    "sent_count": row[4],
                    "opened_count": row[5],
                    "clicked_count": row[6],
                    "reported_count": row[7],
                    "started_at": row[8],
                    "ended_at": row[9],
                    "org_id": row[10],
                }
            )
        return result

    # ------------------------------------------------------------------ #
    # Template management
    # ------------------------------------------------------------------ #

    def get_template(self, template_id: str) -> Optional[PhishingTemplate]:
        """Look up a template by ID (built-in first, then custom)."""
        if template_id in _TEMPLATE_INDEX:
            return _TEMPLATE_INDEX[template_id]
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT data FROM custom_templates WHERE id = ?", (template_id,)
                ).fetchone()
        if row:
            return PhishingTemplate.model_validate_json(row[0])
        return None

    def list_templates(self) -> List[PhishingTemplate]:
        """Return all built-in templates plus any custom ones."""
        templates = list(BUILTIN_TEMPLATES)
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("SELECT data FROM custom_templates").fetchall()
        for (data,) in rows:
            templates.append(PhishingTemplate.model_validate_json(data))
        return templates

    def add_custom_template(self, template: PhishingTemplate) -> PhishingTemplate:
        """Persist a custom template to the database."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO custom_templates (id, data) VALUES (?, ?)",
                    (template.id, template.model_dump_json()),
                )
        _TEMPLATE_INDEX[template.id] = template
        _logger.info("Custom template %s added", template.id)
        return template

    # ------------------------------------------------------------------ #
    # Singleton accessor
    # ------------------------------------------------------------------ #

    @classmethod
    def get_instance(cls) -> "PhishingSimulator":
        """Return the process-level singleton."""
        if not hasattr(cls, "_instance") or cls._instance is None:
            cls._instance = cls()
        return cls._instance

    _instance: Optional["PhishingSimulator"] = None
